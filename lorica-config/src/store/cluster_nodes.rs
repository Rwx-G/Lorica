//! The control plane's node registry and revocation source on
//! `ConfigStore` (Story 9.3 AC #7/#9).
//!
//! `cluster_nodes` is keyed by the server-assigned `node_id`; identity
//! lookups run by certificate fingerprint (current OR the superseded
//! one a renewal left in `prev_cert_fingerprint`). `cluster_revoked_serials`
//! is what the CRL is minted from: an operator revocation adds the
//! node's serials, a completed renewal adds the superseded one.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};

use super::row_helpers::{parse_datetime, parse_optional_datetime};
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::{ClusterNode, NodeStatus, RevokedSerial};

const NODE_COLUMNS: &str = "node_id, name, cert_fingerprint, cert_serial, prev_cert_fingerprint, \
     prev_cert_serial, address, version, schema_version, status, enrolled_at, last_seen_at, \
     applied_config_generation, applied_config_hash, cert_not_after, revoked_at";

/// The routes bound to one certificate, for
/// [`ConfigStore::cert_key_recipients`].
const ROUTE_SELECTORS_BY_CERTIFICATE: &str =
    "SELECT id, node_selector FROM routes WHERE certificate_id = ?1";

/// Every route that names a certificate, with its selector, for
/// [`ConfigStore::certificates_entitling_node`].
///
/// The whole table rather than a per-certificate query, because that
/// resolver answers for one NODE across every certificate and the
/// per-certificate shape would mean one statement per certificate.
const ROUTE_CERTIFICATES_AND_SELECTORS: &str =
    "SELECT certificate_id, id, node_selector FROM routes WHERE certificate_id IS NOT NULL";

/// Every route's host keys and selector, for
/// [`ConfigStore::challenge_recipients`].
///
/// No `WHERE` clause: a route answers on its `hostname` AND on every
/// entry of `hostname_aliases`, and any of those keys may be a `*.`
/// wildcard, so the match is [`route_serves_hostname`] rather than a
/// SQL predicate. Expressing it in SQL would mean a `LIKE` whose
/// pattern comes from the data, which is case-insensitive by default in
/// SQLite and would treat a `%` or `_` in a stored hostname as a
/// wildcard of its own. That is the wrong place to be clever about a
/// predicate that decides who receives a challenge token. The route
/// table is small and this runs once per ACME authorization, never per
/// request.
const ROUTE_HOSTS_AND_SELECTORS: &str =
    "SELECT id, hostname, hostname_aliases, node_selector FROM routes";

/// Whether a route answering on `route_hostname` plus `aliases` serves
/// `hostname`.
///
/// Mirrors `ProxyConfig::find_route`
/// (`lorica/src/proxy_wiring/config.rs:670-700`), which is the
/// authoritative matcher: `from_store` indexes the route hostname and
/// every alias into the same map, then moves every key starting with
/// `*.` into the wildcard list. So both are host keys of equal standing
/// and either may be a wildcard.
///
/// The catch-all key `_` is deliberately NOT honoured here even though
/// `find_route` falls back to it: it would make every route in the
/// fleet a recipient of every hostname's token, which is a fan-out
/// decision an operator should make explicitly rather than inherit from
/// a routing fallback.
fn route_serves_hostname(route_hostname: &str, aliases: &[String], hostname: &str) -> bool {
    std::iter::once(route_hostname)
        .chain(aliases.iter().map(String::as_str))
        .any(|pattern| host_pattern_matches(pattern, hostname))
}

/// One host key against one hostname, byte-for-byte as
/// `ProxyConfig::find_route` does it.
///
/// A `*.` pattern matches any host ending in the pattern's dot-suffix
/// and strictly longer than it. That is an ANY-DEPTH match, not a
/// single-label one: the proxy accepts `deep.a.example.com` for
/// `*.example.com`, so this accepts it too. Narrowing it here would
/// deny a token to a node that really would answer the CA, which is the
/// under-match this predicate exists to fix. The length test is what
/// keeps the parent domain out: `example.com` does not end with
/// `.example.com`, and even a host equal to the suffix is refused.
///
/// A pattern that starts with `*` but not `*.` is an exact key to the
/// proxy (`from_store` filters on `starts_with("*.")`), so it is one
/// here too. Comparison is case-sensitive, matching both the proxy,
/// which compares the raw request host, and the lowercase-hostname
/// invariant the route model documents.
fn host_pattern_matches(pattern: &str, hostname: &str) -> bool {
    if pattern.starts_with("*.") {
        // "*.example.com" -> ".example.com", exactly `&pattern[1..]`
        // in the proxy.
        let suffix = &pattern[1..];
        hostname.ends_with(suffix) && hostname.len() > suffix.len()
    } else {
        pattern == hostname
    }
}

/// The running union of `node_selector` across a set of routes, plus
/// whether any of them was fleet-wide.
///
/// Its own type so that both resolvers fold selectors through the same
/// code: this is the need-to-know predicate, and two copies drifting is
/// a confidentiality bug rather than a cosmetic one.
#[derive(Default)]
struct SelectorUnion {
    /// Node NAMES named by at least one scoped route.
    names: BTreeSet<String>,
    /// At least one matched route had an empty selector.
    fleet_wide: bool,
}

impl SelectorUnion {
    /// Fold one route's stored selector in.
    ///
    /// Fails closed on a selector that will not parse. `row_to_route`
    /// degrades an unreadable selector to `[]`, i.e. fleet-wide, so a
    /// corrupt row still serves traffic; doing that here would hand key
    /// material or a challenge token to every node in the fleet.
    fn add(&mut self, route_id: &str, raw_selector: &str) -> Result<()> {
        let names: Vec<String> = serde_json::from_str(raw_selector).map_err(|e| {
            ConfigError::Validation(format!(
                "node_selector of route {route_id} is not a JSON array of node names: {e}"
            ))
        })?;
        if names.is_empty() {
            self.fleet_wide = true;
        } else {
            self.names.extend(names);
        }
        Ok(())
    }
}

/// Record one serial on the revocation list (idempotent).
fn insert_revoked_serial(
    conn: &Connection,
    serial: &str,
    reason: &str,
    revoked_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO cluster_revoked_serials (serial, revoked_at, reason, expires_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            serial,
            revoked_at.to_rfc3339(),
            reason,
            expires_at.to_rfc3339()
        ],
    )?;
    Ok(())
}

fn row_to_node(row: &rusqlite::Row<'_>) -> Result<ClusterNode> {
    let status: String = row.get(9)?;
    Ok(ClusterNode {
        node_id: row.get(0)?,
        name: row.get(1)?,
        cert_fingerprint: row.get(2)?,
        cert_serial: row.get(3)?,
        prev_cert_fingerprint: row.get(4)?,
        prev_cert_serial: row.get(5)?,
        address: row.get(6)?,
        version: row.get(7)?,
        schema_version: row.get(8)?,
        status: status
            .parse()
            .map_err(|e: String| ConfigError::Validation(e))?,
        enrolled_at: parse_datetime(&row.get::<_, String>(10)?)?,
        last_seen_at: parse_optional_datetime(row.get(11)?)?,
        applied_config_generation: row.get(12)?,
        applied_config_hash: row.get(13)?,
        cert_not_after: parse_datetime(&row.get::<_, String>(14)?)?,
        revoked_at: parse_optional_datetime(row.get(15)?)?,
    })
}

impl ConfigStore {
    /// Insert a freshly enrolled node (status as given, normally
    /// `Pending`).
    pub fn create_cluster_node(&self, node: &ClusterNode) -> Result<()> {
        // The INSERT list IS the SELECT list, so the three places that
        // must agree on column order (this, NODE_COLUMNS, row_to_node)
        // are two.
        self.conn.execute(
            &format!(
                "INSERT INTO cluster_nodes ({NODE_COLUMNS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"
            ),
            params![
                node.node_id,
                node.name,
                node.cert_fingerprint,
                node.cert_serial,
                node.prev_cert_fingerprint,
                node.prev_cert_serial,
                node.address,
                node.version,
                node.schema_version,
                node.status.as_str(),
                node.enrolled_at.to_rfc3339(),
                node.last_seen_at.map(|t| t.to_rfc3339()),
                node.applied_config_generation,
                node.applied_config_hash,
                node.cert_not_after.to_rfc3339(),
                node.revoked_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Fetch a node by id.
    pub fn get_cluster_node(&self, node_id: &str) -> Result<Option<ClusterNode>> {
        self.conn
            .query_row(
                &format!("SELECT {NODE_COLUMNS} FROM cluster_nodes WHERE node_id = ?1"),
                params![node_id],
                |row| Ok(row_to_node(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch a node by certificate fingerprint: the current one or the
    /// superseded one a renewal left behind (AC #8 identity lookup).
    pub fn get_cluster_node_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<ClusterNode>> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {NODE_COLUMNS} FROM cluster_nodes \
                     WHERE cert_fingerprint = ?1 OR prev_cert_fingerprint = ?1"
                ),
                params![fingerprint],
                |row| Ok(row_to_node(row)),
            )
            .optional()?
            .transpose()
    }

    /// Every node, oldest enrollment first.
    pub fn list_cluster_nodes(&self) -> Result<Vec<ClusterNode>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {NODE_COLUMNS} FROM cluster_nodes ORDER BY enrolled_at, node_id"
        ))?;
        let rows = stmt.query_map([], |row| Ok(row_to_node(row)))?;
        let mut nodes = Vec::new();
        for r in rows {
            nodes.push(r??);
        }
        Ok(nodes)
    }

    /// Nodes in `status`.
    pub fn count_cluster_nodes_with_status(&self, status: NodeStatus) -> Result<i64> {
        let n = self.conn.query_row(
            "SELECT COUNT(*) FROM cluster_nodes WHERE status = ?1",
            params![status.as_str()],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// `Pending` -> `Active` (AC #5). Returns `false` when the node is
    /// not pending (already active, revoked, or absent).
    pub fn activate_cluster_node(&self, node_id: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE cluster_nodes SET status = 'active' WHERE node_id = ?1 AND status = 'pending'",
            params![node_id],
        )?;
        Ok(changed == 1)
    }

    /// Revoke a node (AC #7): marks it `Revoked`, records both of its
    /// serials on the revocation list, and returns the row as it was
    /// so the caller can tear its session down. `None` when the node
    /// is absent or already revoked.
    pub fn revoke_cluster_node(
        &self,
        node_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ClusterNode>> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(None);
        };
        if node.status == NodeStatus::Revoked {
            return Ok(None);
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE cluster_nodes SET status = 'revoked', revoked_at = ?2 WHERE node_id = ?1",
            params![node_id, now.to_rfc3339()],
        )?;
        insert_revoked_serial(&tx, &node.cert_serial, "revoked", now, node.cert_not_after)?;
        if let Some(prev) = &node.prev_cert_serial {
            // The superseded certificate was issued before the current
            // one, so the current expiry bounds its lifetime.
            insert_revoked_serial(&tx, prev, "revoked", now, node.cert_not_after)?;
        }
        tx.commit()?;
        Ok(Some(node))
    }

    /// Persist live facts the session layer observed (address, build
    /// version, schema version, last seen, and the configuration
    /// generation / hash the node reports having applied). Absent
    /// nodes are ignored.
    ///
    /// The facts travel as a struct rather than as a parameter list:
    /// Story 9.4 added the applied generation and hash, and seven
    /// positional arguments of mostly-string type is exactly how a
    /// caller ends up swapping two of them silently.
    pub fn touch_cluster_node(&self, facts: &LiveNodeFacts) -> Result<()> {
        self.touch_cluster_nodes(std::slice::from_ref(facts))
    }

    /// [`ConfigStore::touch_cluster_node`] for a whole snapshot in one
    /// transaction (the periodic flush: one commit per flush, not one
    /// per node).
    pub fn touch_cluster_nodes(&self, facts: &[LiveNodeFacts]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut update = tx.prepare(
                "UPDATE cluster_nodes SET address = ?2, version = ?3, schema_version = ?4, \
                 last_seen_at = ?5, applied_config_generation = ?6, applied_config_hash = ?7 \
                 WHERE node_id = ?1",
            )?;
            for f in facts {
                update.execute(params![
                    f.node_id,
                    f.address,
                    f.version,
                    f.schema_version,
                    f.last_seen_at.to_rfc3339(),
                    f.applied_config_generation,
                    f.applied_config_hash
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// A renewal issued a new certificate (AC #12): the current one
    /// becomes `prev_*` (still accepted until the node's first session
    /// on the new one), the new one becomes current. A still-pending
    /// previous certificate (two renewals without a session in
    /// between) is retired to the revocation list first. Only an
    /// `Active` node renews (AC #5: a pending node receives no
    /// certificates); `false` otherwise.
    pub fn record_cluster_node_renewal(
        &self,
        node_id: &str,
        new_fingerprint: &str,
        new_serial: &str,
        new_not_after: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(false);
        };
        if node.status != NodeStatus::Active {
            return Ok(false);
        }
        let tx = self.conn.unchecked_transaction()?;
        if let Some(stale) = &node.prev_cert_serial {
            insert_revoked_serial(&tx, stale, "superseded", now, node.cert_not_after)?;
        }
        let changed = tx.execute(
            "UPDATE cluster_nodes SET prev_cert_fingerprint = cert_fingerprint, \
             prev_cert_serial = cert_serial, cert_fingerprint = ?2, cert_serial = ?3, \
             cert_not_after = ?4 WHERE node_id = ?1 AND status = 'active'",
            params![node_id, new_fingerprint, new_serial, new_not_after.to_rfc3339()],
        )?;
        tx.commit()?;
        Ok(changed == 1)
    }

    /// The node's first session on its renewed certificate: retire the
    /// superseded one (revocation list, reason `superseded`) and clear
    /// the `prev_*` columns. Returns the retired serial, `None` when
    /// there was nothing to retire.
    pub fn retire_previous_cluster_certificate(
        &self,
        node_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(None);
        };
        let Some(prev_serial) = node.prev_cert_serial else {
            return Ok(None);
        };
        let tx = self.conn.unchecked_transaction()?;
        insert_revoked_serial(&tx, &prev_serial, "superseded", now, node.cert_not_after)?;
        tx.execute(
            "UPDATE cluster_nodes SET prev_cert_fingerprint = NULL, prev_cert_serial = NULL \
             WHERE node_id = ?1",
            params![node_id],
        )?;
        tx.commit()?;
        Ok(Some(prev_serial))
    }

    /// Every revoked serial whose certificate is still within its
    /// validity at `now`, oldest first: the CRL input. Expired
    /// certificates fail TLS on their own and never need a CRL entry.
    pub fn list_cluster_revoked_serials(&self, now: DateTime<Utc>) -> Result<Vec<RevokedSerial>> {
        let mut stmt = self.conn.prepare(
            "SELECT serial, revoked_at, reason, expires_at FROM cluster_revoked_serials \
             WHERE expires_at > ?1 ORDER BY revoked_at, serial",
        )?;
        let rows = stmt.query_map(params![now.to_rfc3339()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (serial, revoked_at, reason, expires_at) = r?;
            out.push(RevokedSerial {
                serial,
                revoked_at: parse_datetime(&revoked_at)?,
                reason,
                expires_at: parse_datetime(&expires_at)?,
            });
        }
        Ok(out)
    }

    /// The node ids entitled to the private key of `cert_id` (Story 9.5
    /// AC #1, decision D3).
    ///
    /// Resolved control-plane side and never by the recipient: the chain
    /// is certificate, then the routes whose `certificate_id` names it,
    /// then the union of those routes' `node_selector`, then those node
    /// NAMES resolved against `cluster_nodes` to node IDS, which is the
    /// identity the mutual-TLS certificate actually proves. A selector
    /// that is empty means the route is fleet-wide, so every Active node
    /// is entitled.
    ///
    /// Only `Active` nodes are ever returned: a node awaiting operator
    /// activation receives no key material.
    ///
    /// `Route::certificate_id` is a soft reference, so a certificate no
    /// route names simply entitles nobody, and a selector entry that
    /// matches no node is skipped rather than raising. The result is
    /// sorted and deduplicated.
    ///
    /// A disabled route still entitles its selected nodes, matching
    /// `Route::applies_to_node`, which the replica apply uses and
    /// which ignores `enabled` too. Narrowing on `enabled` here would
    /// make re-enabling a route race key delivery, and the route row
    /// itself already replicates to the same nodes.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure, and
    /// [`ConfigError::Validation`] when a stored `node_selector` is not
    /// a JSON array of strings. That case fails closed on purpose:
    /// `row_to_route` degrades an unreadable selector to "fleet-wide"
    /// so a corrupt row still serves traffic, but doing the same here
    /// would hand a private key to every node in the fleet.
    pub fn cert_key_recipients(&self, cert_id: &str) -> Result<Vec<String>> {
        let mut union = SelectorUnion::default();
        {
            let mut stmt = self.conn.prepare(ROUTE_SELECTORS_BY_CERTIFICATE)?;
            let rows = stmt.query_map(params![cert_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (route_id, raw_selector) = row?;
                union.add(&route_id, &raw_selector)?;
            }
        }
        self.resolve_selector_union(&union)
    }

    /// The certificate ids whose private key `node_id` receives.
    ///
    /// The inverse of [`ConfigStore::cert_key_recipients`], and it has
    /// to stay the inverse: the dashboard's node drawer answers "what
    /// key material does this node hold" with it, and an answer that
    /// disagrees with the push path is worse than no answer.
    ///
    /// So it applies exactly the same two rules. An empty
    /// `node_selector` means the route is fleet-wide and entitles every
    /// Active node, which is why this cannot be derived from
    /// [`ConfigStore::hostnames_selecting_node_name`]: that one
    /// deliberately EXCLUDES fleet-wide routes, because it answers the
    /// different question of what approving a pending node would hand
    /// over that is specific to its name. Deriving one from the other
    /// silently omits every fleet-wide certificate.
    ///
    /// A node that is not `Active` receives nothing, matching
    /// [`ConfigStore::resolve_selector_union`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure, and
    /// [`ConfigError::Validation`] when a stored `node_selector` is not
    /// a JSON array of strings, failing closed for the same reason
    /// [`ConfigStore::cert_key_recipients`] does.
    pub fn certificates_entitling_node(&self, node_id: &str) -> Result<Vec<String>> {
        Ok(self
            .certificates_by_node()?
            .remove(node_id)
            .unwrap_or_default())
    }

    /// Every Active node's certificate entitlement, in one pass.
    ///
    /// The roster endpoint answers for the whole fleet at once, so this
    /// reads the route table once rather than once per node, the same
    /// reason [`ConfigStore::hostnames_selecting_node_name`] is folded
    /// into a single pass by its caller.
    ///
    /// This is the one place the entitlement rule is written;
    /// [`ConfigStore::certificates_entitling_node`] delegates to it so
    /// the single-node and fleet views cannot drift apart.
    ///
    /// Nodes that are not `Active` are absent from the map rather than
    /// present with an empty list: they receive nothing at all, which
    /// is a different statement from "nothing is bound to them".
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure, and
    /// [`ConfigError::Validation`] when a stored `node_selector` is not
    /// a JSON array of strings, failing closed for the same reason
    /// [`ConfigStore::cert_key_recipients`] does.
    pub fn certificates_by_node(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let mut names: Vec<(String, String)> = Vec::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT node_id, name FROM cluster_nodes WHERE status = ?1")?;
            let rows = stmt.query_map(params![NodeStatus::Active.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                names.push(row?);
            }
        }
        if names.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut fleet_wide: BTreeSet<String> = BTreeSet::new();
        let mut scoped: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        {
            let mut stmt = self.conn.prepare(ROUTE_CERTIFICATES_AND_SELECTORS)?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (cert_id, route_id, raw_selector) = row?;
                let mut union = SelectorUnion::default();
                union.add(&route_id, &raw_selector)?;
                if union.fleet_wide {
                    fleet_wide.insert(cert_id);
                } else {
                    for name in union.names {
                        scoped.entry(name).or_default().insert(cert_id.clone());
                    }
                }
            }
        }

        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (node_id, name) in names {
            let mut certs = fleet_wide.clone();
            if let Some(named) = scoped.get(&name) {
                certs.extend(named.iter().cloned());
            }
            out.insert(node_id, certs.into_iter().collect());
        }
        Ok(out)
    }

    /// The node ids that plausibly serve `hostname`, for HTTP-01
    /// challenge distribution (Story 9.5 AC #6).
    ///
    /// Same control-plane-side resolution as
    /// [`ConfigStore::cert_key_recipients`] and for the same reason:
    /// routes that answer for the hostname, then the union of their
    /// `node_selector`, then names resolved to node ids against
    /// `cluster_nodes`, Active only. An empty selector means
    /// fleet-wide.
    ///
    /// "Plausibly" is the honest word: the CA picks which node it
    /// validates against, so the token has to be present on every node
    /// that could answer for that hostname.
    ///
    /// A route answers for the hostname when its `hostname` OR any
    /// entry of its `hostname_aliases` matches, exactly or as a `*.`
    /// wildcard, per [`route_serves_hostname`], which mirrors the
    /// proxy's own matcher. Matching the primary hostname alone would
    /// under-match: a node whose route answers on `www.example.com` as
    /// an alias really does serve that hostname, and refusing it a
    /// token aborts a legitimate issuance. The same holds for a
    /// wildcard alias.
    ///
    /// A hostname no route serves resolves to nobody. **An empty
    /// result is not a satisfied all-or-nothing**: distributing to zero
    /// nodes and then calling `set_ready()` tells the CA to validate a
    /// token nothing serves. The caller must treat the empty case as a
    /// refusal, not as a vacuous success.
    ///
    /// Matching is case-sensitive, as the proxy's is. Route hostnames
    /// are stored lowercase and ACME identifiers are lowercase, so the
    /// two agree; a row that broke that invariant resolves to nobody,
    /// which the paragraph above turns into a refusal rather than a
    /// silent mis-issuance.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure, and
    /// [`ConfigError::Validation`] when a stored `node_selector` is not
    /// a JSON array of strings, failing closed for the same reason
    /// [`ConfigStore::cert_key_recipients`] does.
    pub fn challenge_recipients(&self, hostname: &str) -> Result<Vec<String>> {
        let mut union = SelectorUnion::default();
        {
            let mut stmt = self.conn.prepare(ROUTE_HOSTS_AND_SELECTORS)?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (route_id, route_hostname, raw_aliases, raw_selector) = row?;
                let aliases: Vec<String> = serde_json::from_str(&raw_aliases).map_err(|e| {
                    ConfigError::Validation(format!(
                        "hostname_aliases of route {route_id} is not a JSON array of \
                         hostnames: {e}"
                    ))
                })?;
                if route_serves_hostname(&route_hostname, &aliases, hostname) {
                    union.add(&route_id, &raw_selector)?;
                }
            }
        }
        self.resolve_selector_union(&union)
    }

    /// The hostnames a node bearing `name` would serve, and therefore
    /// the certificate private keys it would become entitled to, if it
    /// were activated right now (Story 9.5 QA, decision D15).
    ///
    /// This is the INVERSE of the entitlement resolvers: they answer
    /// "who may hold this key", and an operator reviewing a node that
    /// is waiting for approval needs the other direction, "what would
    /// approving this name hand over". Without it, activation is a
    /// button rather than a decision: a route selector may have been
    /// written long before the node it names was provisioned, and
    /// activating is the moment that selector starts handing out keys.
    ///
    /// Empty selectors are deliberately NOT counted. A fleet-wide route
    /// entitles every active node, so listing them here would bury the
    /// entries an operator actually has to think about under the ones
    /// that apply to everyone.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure. A route
    /// whose selector does not parse is skipped rather than failing the
    /// review: this is an advisory surface, and refusing to render it
    /// would be worse than rendering it incompletely.
    pub fn hostnames_selecting_node_name(&self, name: &str) -> Result<Vec<String>> {
        Ok(self
            .hostnames_by_selected_name()?
            .remove(name)
            .unwrap_or_default())
    }

    /// The same answer as [`ConfigStore::hostnames_selecting_node_name`]
    /// for EVERY name any route selector mentions, from one pass over
    /// the route table.
    ///
    /// The roster endpoint asks for the whole fleet at once. Answering
    /// it name by name meant one full route walk, with one JSON parse
    /// per selector, per distinct node name, all under the store lock
    /// (Epic 9 close, performance audit): O(nodes x routes) where
    /// O(routes) was available, and the comment at the call site
    /// claimed the single pass this function now actually is.
    ///
    /// Names that appear only in fleet-wide (empty) selectors are
    /// absent from the map, for the reason the per-name resolver
    /// gives: this is the "what would approving this name hand over"
    /// view, and a fleet-wide route hands the same thing to everyone.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure. A selector
    /// that does not parse is skipped, as in the per-name resolver.
    pub fn hostnames_by_selected_name(&self) -> Result<BTreeMap<String, Vec<String>>> {
        let mut stmt = self.conn.prepare(ROUTE_HOSTS_AND_SELECTORS)?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, String>(3)?))
        })?;
        let mut by_name: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for row in rows {
            let (hostname, raw_selector) = row?;
            let Ok(selector) = serde_json::from_str::<Vec<String>>(&raw_selector) else {
                continue;
            };
            for name in selector {
                by_name.entry(name).or_default().insert(hostname.clone());
            }
        }
        Ok(by_name
            .into_iter()
            .map(|(name, hosts)| (name, hosts.into_iter().collect()))
            .collect())
    }

    /// Turn a folded [`SelectorUnion`] into the Active node ids it
    /// names. The single place a selector becomes a set of recipients,
    /// shared by both public resolvers.
    fn resolve_selector_union(&self, union: &SelectorUnion) -> Result<Vec<String>> {
        // One fleet-wide route in the match makes the union
        // fleet-wide: every Active node serves that route, so every
        // Active node needs what the route implies.
        if union.fleet_wide {
            return self.active_cluster_node_ids();
        }
        if union.names.is_empty() {
            return Ok(Vec::new());
        }

        let mut by_name: BTreeMap<String, String> = BTreeMap::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT name, node_id FROM cluster_nodes WHERE status = ?1")?;
            let rows = stmt.query_map(params![NodeStatus::Active.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            for row in rows {
                let (name, node_id) = row?;
                by_name.insert(name, node_id);
            }
        }

        let recipients: BTreeSet<String> = union
            .names
            .iter()
            .filter_map(|name| by_name.get(name).cloned())
            .collect();
        Ok(recipients.into_iter().collect())
    }

    /// Every Active node id, for the fleet-wide opt-in override.
    ///
    /// Sorted, so a caller comparing two resolutions compares two
    /// stable lists.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure.
    pub fn active_cluster_node_ids(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT node_id FROM cluster_nodes WHERE status = ?1 ORDER BY node_id")?;
        let rows = stmt.query_map(params![NodeStatus::Active.as_str()], |row| {
            row.get::<_, String>(0)
        })?;
        let mut ids = Vec::new();
        for row in rows {
            ids.push(row?);
        }
        Ok(ids)
    }

    /// Drop revoked serials whose certificate expired before `now`
    /// (the CRL stays bounded by the number of live certificates).
    /// Returns how many were pruned.
    pub fn prune_cluster_revoked_serials(&self, now: DateTime<Utc>) -> Result<u32> {
        let pruned = self.conn.execute(
            "DELETE FROM cluster_revoked_serials WHERE expires_at <= ?1",
            params![now.to_rfc3339()],
        )?;
        Ok(u32::try_from(pruned).unwrap_or(u32::MAX))
    }
}

/// Live facts the session layer persists for one node.
#[derive(Debug, Clone)]
pub struct LiveNodeFacts {
    /// The node.
    pub node_id: String,
    /// Last observed transport address.
    pub address: String,
    /// Reported build version.
    pub version: String,
    /// Reported schema version.
    pub schema_version: i64,
    /// Last activity.
    pub last_seen_at: DateTime<Utc>,
    /// Configuration generation the node reports having applied
    /// (Story 9.4 AC #12). Persisted so drift survives a control-plane
    /// restart instead of resetting the whole fleet to "unknown".
    pub applied_config_generation: i64,
    /// Canonical hash the node reports for that generation. Empty
    /// until the node applies its first replica.
    pub applied_config_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Certificate;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    fn enrol(store: &ConfigStore, node_id: &str, name: &str, status: NodeStatus) {
        let node = ClusterNode {
            node_id: node_id.to_string(),
            name: name.to_string(),
            cert_fingerprint: format!("fp-{node_id}"),
            cert_serial: format!("sn-{node_id}"),
            prev_cert_fingerprint: None,
            prev_cert_serial: None,
            address: "192.0.2.10:5001".to_string(),
            version: "1.7.0".to_string(),
            schema_version: 54,
            status,
            enrolled_at: at("2026-09-08T00:00:00Z"),
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: at("2027-09-08T00:00:00Z"),
            revoked_at: None,
        };
        store
            .create_cluster_node(&node)
            .expect("test setup: node enrols");
    }

    fn issue_certificate(store: &ConfigStore, cert_id: &str, domain: &str) {
        let cert = Certificate {
            id: cert_id.to_string(),
            domain: domain.to_string(),
            san_domains: Vec::new(),
            fingerprint: format!("fp-{cert_id}"),
            cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----".to_string(),
            issuer: "Test CA".to_string(),
            not_before: at("2026-09-01T00:00:00Z"),
            not_after: at("2026-12-01T00:00:00Z"),
            is_acme: true,
            acme_auto_renew: true,
            created_at: at("2026-09-01T00:00:00Z"),
            acme_method: Some("http01".to_string()),
            acme_dns_provider_id: None,
        };
        store
            .create_certificate(&cert)
            .expect("test setup: certificate issues");
    }

    /// Bind a route to a certificate with the given selector. Written
    /// through SQL rather than `create_route`: the predicate under test
    /// reads two columns, and a seventy-field `Route` literal would
    /// bury them.
    fn bind_route(
        store: &ConfigStore,
        route_id: &str,
        hostname: &str,
        cert_id: &str,
        selector: &[&str],
    ) {
        bind_route_under(store, route_id, hostname, "/", cert_id, selector);
    }

    /// [`bind_route`] with an explicit path prefix, so two routes can
    /// legitimately share a hostname.
    fn bind_route_under(
        store: &ConfigStore,
        route_id: &str,
        hostname: &str,
        path_prefix: &str,
        cert_id: &str,
        selector: &[&str],
    ) {
        bind_route_with_aliases(store, route_id, hostname, &[], path_prefix, cert_id, selector);
    }

    /// [`bind_route`] with `hostname_aliases`, the extra host keys the
    /// route also answers on.
    fn bind_route_with_aliases(
        store: &ConfigStore,
        route_id: &str,
        hostname: &str,
        aliases: &[&str],
        path_prefix: &str,
        cert_id: &str,
        selector: &[&str],
    ) {
        let aliases_json = serde_json::to_string(aliases).expect("test setup: aliases serialize");
        let selector_json =
            serde_json::to_string(selector).expect("test setup: selector serializes");
        store
            .conn
            .execute(
                "INSERT INTO routes \
                 (id, hostname, hostname_aliases, path_prefix, certificate_id, node_selector) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    route_id,
                    hostname,
                    aliases_json,
                    path_prefix,
                    cert_id,
                    selector_json
                ],
            )
            .expect("test setup: route binds");
    }

    fn fleet_of_three() -> ConfigStore {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        enrol(&store, "node-a", "edge-a", NodeStatus::Active);
        enrol(&store, "node-b", "edge-b", NodeStatus::Active);
        enrol(&store, "node-c", "edge-c", NodeStatus::Active);
        issue_certificate(&store, "cert-1", "shop.example.com");
        store
    }

    #[test]
    fn a_fleet_wide_route_entitles_every_active_node() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("recipients resolve"),
            vec![
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string()
            ]
        );
    }

    #[test]
    fn a_scoped_route_entitles_only_the_named_nodes() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-b"]);

        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("recipients resolve"),
            vec!["node-b".to_string()],
            "a node that never serves the hostname gets no private key"
        );
    }

    #[test]
    fn a_pending_node_is_never_a_recipient_even_when_named() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        enrol(&store, "node-a", "edge-a", NodeStatus::Active);
        enrol(&store, "node-p", "edge-p", NodeStatus::Pending);
        enrol(&store, "node-r", "edge-r", NodeStatus::Revoked);
        issue_certificate(&store, "cert-1", "shop.example.com");
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-a", "edge-p", "edge-r"]);

        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("recipients resolve"),
            vec!["node-a".to_string()],
            "operator activation gates key material, not the selector"
        );

        // The fleet-wide path applies the same gate.
        bind_route(&store, "r2", "www.example.com", "cert-1", &[]);
        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("recipients resolve"),
            vec!["node-a".to_string()]
        );
    }

    #[test]
    fn the_node_view_of_entitlement_agrees_with_the_certificate_view() {
        // The two resolvers answer the same question from opposite
        // ends. The dashboard's node drawer reads one and the push path
        // reads the other, so a disagreement is a false statement to an
        // operator about who holds which private key.
        let store = fleet_of_three();
        issue_certificate(&store, "cert-2", "api.example.com");
        // Fleet-wide: nobody is named, everybody is entitled.
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);
        // Scoped to one node.
        bind_route(&store, "r2", "api.example.com", "cert-2", &["edge-b"]);

        for (node_id, expected) in [
            ("node-a", vec!["cert-1".to_string()]),
            ("node-b", vec!["cert-1".to_string(), "cert-2".to_string()]),
            ("node-c", vec!["cert-1".to_string()]),
        ] {
            assert_eq!(
                store
                    .certificates_entitling_node(node_id)
                    .expect("entitlement resolves"),
                expected,
                "{node_id} sees the certificates it actually receives"
            );
        }

        for cert_id in ["cert-1", "cert-2"] {
            for node_id in ["node-a", "node-b", "node-c"] {
                let from_cert = store
                    .cert_key_recipients(cert_id)
                    .expect("recipients resolve")
                    .contains(&node_id.to_string());
                let from_node = store
                    .certificates_entitling_node(node_id)
                    .expect("entitlement resolves")
                    .contains(&cert_id.to_string());
                assert_eq!(
                    from_cert, from_node,
                    "the two resolvers disagree on {node_id} and {cert_id}"
                );
            }
        }
    }

    #[test]
    fn a_fleet_wide_certificate_is_not_lost_by_the_node_view() {
        // The bug this test exists for: the drawer used to derive its
        // certificate list from `hostnames_selecting_node_name`, which
        // deliberately excludes fleet-wide routes, and so told an
        // operator a node held no keys while it held every fleet-wide
        // one.
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        assert!(
            store
                .hostnames_selecting_node_name("edge-a")
                .expect("review list resolves")
                .is_empty(),
            "the approval review deliberately says nothing about fleet-wide routes"
        );
        assert_eq!(
            store
                .certificates_entitling_node("node-a")
                .expect("entitlement resolves"),
            vec!["cert-1".to_string()],
            "but the node really does receive that certificate's key"
        );
    }

    #[test]
    fn a_node_that_is_not_active_is_entitled_to_nothing() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        enrol(&store, "node-p", "edge-p", NodeStatus::Pending);
        enrol(&store, "node-r", "edge-r", NodeStatus::Revoked);
        issue_certificate(&store, "cert-1", "shop.example.com");
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        for node_id in ["node-p", "node-r", "node-absent"] {
            assert!(
                store
                    .certificates_entitling_node(node_id)
                    .expect("entitlement resolves")
                    .is_empty(),
                "{node_id} holds no key material"
            );
        }
    }

    #[test]
    fn an_unparseable_selector_fails_closed_in_the_node_view_too() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-a"]);
        store
            .conn
            .execute(
                "UPDATE routes SET node_selector = 'not json' WHERE id = 'r1'",
                [],
            )
            .expect("test setup: corrupt the selector");

        assert!(
            store.certificates_entitling_node("node-a").is_err(),
            "a selector that will not parse must not degrade to fleet-wide here either"
        );
    }

    #[test]
    fn a_selector_name_matching_no_node_is_skipped() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-a", "edge-gone"]);

        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("a stale selector entry is not an error"),
            vec!["node-a".to_string()]
        );
    }

    #[test]
    fn two_routes_on_one_certificate_take_the_union() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-c"]);
        bind_route(&store, "r2", "www.example.com", "cert-1", &["edge-a"]);

        assert_eq!(
            store
                .cert_key_recipients("cert-1")
                .expect("recipients resolve"),
            vec!["node-a".to_string(), "node-c".to_string()],
            "sorted and deduplicated, so two resolutions compare"
        );
    }

    #[test]
    fn a_certificate_no_route_references_entitles_nobody() {
        let store = fleet_of_three();
        issue_certificate(&store, "cert-orphan", "old.example.com");
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        assert!(
            store
                .cert_key_recipients("cert-orphan")
                .expect("recipients resolve")
                .is_empty(),
            "an unbound certificate is distributed to no one"
        );
        assert!(
            store
                .cert_key_recipients("cert-never-issued")
                .expect("an unknown certificate id is not an error")
                .is_empty(),
            "certificate_id is a soft reference on both sides"
        );
    }

    #[test]
    fn active_node_ids_are_sorted_and_exclude_every_other_state() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        enrol(&store, "node-c", "edge-c", NodeStatus::Active);
        enrol(&store, "node-a", "edge-a", NodeStatus::Active);
        enrol(&store, "node-p", "edge-p", NodeStatus::Pending);
        enrol(&store, "node-r", "edge-r", NodeStatus::Revoked);

        assert_eq!(
            store.active_cluster_node_ids().expect("active ids resolve"),
            vec!["node-a".to_string(), "node-c".to_string()]
        );
    }

    #[test]
    fn a_fleet_wide_route_puts_the_challenge_on_every_active_node() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        assert_eq!(
            store
                .challenge_recipients("shop.example.com")
                .expect("recipients resolve"),
            vec![
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string()
            ]
        );
    }

    #[test]
    fn a_scoped_route_puts_the_challenge_only_on_the_named_nodes() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-b"]);
        // A different hostname on the same certificate must not widen
        // the challenge fan-out: the CA validates one identifier.
        bind_route(&store, "r2", "www.example.com", "cert-1", &["edge-c"]);

        assert_eq!(
            store
                .challenge_recipients("shop.example.com")
                .expect("recipients resolve"),
            vec!["node-b".to_string()]
        );
    }

    #[test]
    fn a_pending_node_never_receives_a_challenge() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        enrol(&store, "node-a", "edge-a", NodeStatus::Active);
        enrol(&store, "node-p", "edge-p", NodeStatus::Pending);
        issue_certificate(&store, "cert-1", "shop.example.com");
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-a", "edge-p"]);

        assert_eq!(
            store
                .challenge_recipients("shop.example.com")
                .expect("recipients resolve"),
            vec!["node-a".to_string()],
            "a node that receives no configuration cannot serve a token"
        );
    }

    #[test]
    fn a_hostname_no_route_serves_resolves_to_nobody() {
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &[]);

        assert!(
            store
                .challenge_recipients("unknown.example.com")
                .expect("an unserved hostname is not an error")
                .is_empty()
        );
        assert!(
            store
                .challenge_recipients("SHOP.EXAMPLE.COM")
                .expect("recipients resolve")
                .is_empty(),
            "hostname is matched exactly, as stored"
        );
    }

    #[test]
    fn two_routes_on_one_hostname_take_the_union() {
        let store = fleet_of_three();
        bind_route_under(&store, "r1", "shop.example.com", "/", "cert-1", &["edge-c"]);
        bind_route_under(&store, "r2", "shop.example.com", "/api", "cert-1", &["edge-a"]);

        assert_eq!(
            store
                .challenge_recipients("shop.example.com")
                .expect("recipients resolve"),
            vec!["node-a".to_string(), "node-c".to_string()],
            "every node that could answer for the hostname gets the token"
        );
    }

    #[test]
    fn an_exact_alias_entitles_the_node_serving_it() {
        let store = fleet_of_three();
        bind_route_with_aliases(
            &store,
            "r1",
            "shop.example.com",
            &["www.example.com"],
            "/",
            "cert-1",
            &["edge-b"],
        );

        assert_eq!(
            store
                .challenge_recipients("www.example.com")
                .expect("recipients resolve"),
            vec!["node-b".to_string()],
            "a node whose route answers on the alias does serve that hostname"
        );
    }

    #[test]
    fn a_wildcard_alias_entitles_for_a_subdomain() {
        let store = fleet_of_three();
        bind_route_with_aliases(
            &store,
            "r1",
            "shop.example.com",
            &["*.example.com"],
            "/",
            "cert-1",
            &["edge-c"],
        );

        assert_eq!(
            store
                .challenge_recipients("a.example.com")
                .expect("recipients resolve"),
            vec!["node-c".to_string()]
        );
    }

    #[test]
    fn a_wildcard_alias_does_not_entitle_for_the_parent_domain() {
        let store = fleet_of_three();
        bind_route_with_aliases(
            &store,
            "r1",
            "shop.example.com",
            &["*.example.com"],
            "/",
            "cert-1",
            &["edge-c"],
        );

        assert!(
            store
                .challenge_recipients("example.com")
                .expect("recipients resolve")
                .is_empty(),
            "`example.com` does not end with `.example.com`, so the proxy \
             would not route it here either"
        );
    }

    #[test]
    fn a_wildcard_alias_entitles_at_any_depth_because_the_proxy_does() {
        // Not a single-label match: `ProxyConfig::find_route` tests
        // `host.ends_with(\".example.com\")` with no label counting, so
        // the proxy really would answer `deep.a.example.com` here.
        // Narrowing this would deny a token to a node that serves the
        // CA's request.
        let store = fleet_of_three();
        bind_route_with_aliases(
            &store,
            "r1",
            "shop.example.com",
            &["*.example.com"],
            "/",
            "cert-1",
            &["edge-c"],
        );

        assert_eq!(
            store
                .challenge_recipients("deep.a.example.com")
                .expect("recipients resolve"),
            vec!["node-c".to_string()]
        );
    }

    #[test]
    fn a_wildcard_primary_hostname_matches_like_a_wildcard_alias() {
        // `from_store` indexes `route.hostname` and every alias into
        // the same map before splitting the `*.` keys out, so a
        // wildcard in the primary hostname is a wildcard to the proxy.
        let store = fleet_of_three();
        bind_route(&store, "r1", "*.example.com", "cert-1", &["edge-a"]);

        assert_eq!(
            store
                .challenge_recipients("a.example.com")
                .expect("recipients resolve"),
            vec!["node-a".to_string()]
        );
        assert!(
            store
                .challenge_recipients("example.com")
                .expect("recipients resolve")
                .is_empty()
        );
    }

    #[test]
    fn the_host_pattern_matcher_mirrors_the_proxy() {
        // The table the proxy's own matcher satisfies
        // (`lorica/src/proxy_wiring/config.rs:670-700`). Kept as a
        // direct unit test so a change to either side shows up as a
        // failing assertion rather than as a silent divergence in who
        // receives a token.
        assert!(host_pattern_matches("shop.example.com", "shop.example.com"));
        assert!(!host_pattern_matches("shop.example.com", "other.example.com"));
        assert!(host_pattern_matches("*.example.com", "a.example.com"));
        assert!(host_pattern_matches("*.example.com", "deep.a.example.com"));
        assert!(!host_pattern_matches("*.example.com", "example.com"));
        assert!(!host_pattern_matches("*.example.com", ".example.com"));
        assert!(!host_pattern_matches("*.example.com", "notexample.com"));
        // A `*` that is not followed by a dot is an exact key to the
        // proxy, which filters on `starts_with("*.")`.
        assert!(host_pattern_matches("*example.com", "*example.com"));
        assert!(!host_pattern_matches("*example.com", "a.example.com"));
        // The catch-all routing key is not a challenge fan-out rule.
        assert!(!host_pattern_matches("_", "shop.example.com"));
    }

    #[test]
    fn a_malformed_alias_list_fails_closed() {
        let store = fleet_of_three();
        store
            .conn
            .execute(
                "INSERT INTO routes \
                 (id, hostname, hostname_aliases, certificate_id, node_selector) \
                 VALUES ('r1', 'shop.example.com', 'not json', 'cert-1', '[\"edge-a\"]')",
                [],
            )
            .expect("test setup: corrupt route inserts");

        assert!(
            store.challenge_recipients("shop.example.com").is_err(),
            "an unreadable alias list must not silently under-match"
        );
    }

    #[test]
    fn a_malformed_selector_fails_closed_rather_than_going_fleet_wide() {
        let store = fleet_of_three();
        store
            .conn
            .execute(
                "INSERT INTO routes (id, hostname, certificate_id, node_selector) \
                 VALUES ('r1', 'shop.example.com', 'cert-1', 'not json')",
                [],
            )
            .expect("test setup: corrupt route inserts");

        assert!(
            store.cert_key_recipients("cert-1").is_err(),
            "an unreadable selector must not be read as fleet-wide"
        );
    }

    #[test]
    fn the_review_surface_shows_what_a_name_is_already_selected_for() {
        // Story 9.5 D15: an operator approving a pending node must be
        // able to see what that NAME is entitled to before clicking
        // activate, because the selector may well have been written
        // before the node was provisioned.
        let store = fleet_of_three();
        bind_route(&store, "r1", "shop.example.com", "cert-1", &["edge-b"]);
        bind_route(&store, "r2", "api.example.com", "cert-1", &["edge-b", "edge-c"]);
        bind_route(&store, "r3", "www.example.com", "cert-1", &["edge-c"]);

        assert_eq!(
            store
                .hostnames_selecting_node_name("edge-b")
                .expect("selection resolves"),
            vec!["api.example.com".to_string(), "shop.example.com".to_string()],
            "sorted and deduplicated, so the review column is stable"
        );
        assert!(
            store
                .hostnames_selecting_node_name("edge-never-provisioned")
                .expect("an unknown name is not an error")
                .is_empty()
        );
    }

    #[test]
    fn a_fleet_wide_route_is_not_reported_as_selecting_a_name() {
        // A fleet-wide route entitles every active node, which is not
        // information about THIS name and would drown the entries the
        // operator actually has to think about.
        let store = fleet_of_three();
        bind_route(&store, "r1", "everything.example.com", "cert-1", &[]);
        bind_route(&store, "r2", "shop.example.com", "cert-1", &["edge-a"]);

        assert_eq!(
            store
                .hostnames_selecting_node_name("edge-a")
                .expect("selection resolves"),
            vec!["shop.example.com".to_string()]
        );
    }
}
