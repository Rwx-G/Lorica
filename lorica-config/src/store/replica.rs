//! Replica apply: the follower half of Story 9.4 (AC #2, D2/D3).
//!
//! Two phases mirroring the wire protocol. [`ConfigStore::prepare_replica`]
//! decodes and validates a canonical blob without touching the store,
//! so a semantic rejection costs nothing and never leaves a partial
//! state. [`ConfigStore::apply_replica`] writes the decoded snapshot in
//! ONE transaction.
//!
//! # Why not `import_to_store`
//!
//! The TOML import path calls `clear_all`, which deletes `users` and
//! `global_settings` (the follower's own operators and machine
//! configuration) while NOT deleting `waf_custom_rules`,
//! `cert_export_acls`, `ai_crawlers_custom`, `probe_configs` or
//! `sla_configs`, so those would go stale on the follower forever.
//! Destructive where it must not be, incomplete where it must be.
//!
//! # The table list is explicit (D2)
//!
//! Applied: global fleet policy (the [`CanonicalGlobalSettings`]
//! subset, node-local fields untouched by construction), routes,
//! backends, route_backends, certificates (metadata only, see D3),
//! waf_custom_rules, waf_disabled_rules, cert_export_acls,
//! ai_crawlers_custom (keyed on its UNIQUE `name`, not its
//! autoincrement id), probe_configs and sla_configs. Rows absent from
//! the blob are deleted in exactly those tables.
//!
//! Never written: `users`, `user_preferences`, `sessions`,
//! `notification_configs`, `dns_providers`, every `cluster_*` table,
//! load tests and all telemetry (`sla_buckets`, `probe_results`,
//! access and WAF logs).
//!
//! Not written is not the same as not affected. `sla_buckets.route_id`
//! is `REFERENCES routes(id) ON DELETE CASCADE` and `PRAGMA
//! foreign_keys` is ON, so every route this path deletes takes that
//! route's local SLA history with it. On a standalone install that is
//! an operator deleting their own route; on a follower it also fires
//! when a `node_selector` change de-selects the node, which destroys
//! up to `sla_purge_retention_days` of that node's history without
//! anyone touching that node, and re-selecting it later does not bring
//! the history back. Tracked as backlog #67. `probe_results` carries
//! no foreign key and is genuinely untouched. Notification channels and DNS providers DO
//! ride the blob (their secret payload as a digest) because fleet
//! drift detection must notice a changed credential, but they are
//! control-plane concerns and are not applied here: a fleet that
//! configures them centrally therefore reports drift until each node
//! carries its own, which is the documented trade-off.
//!
//! # Certificates are metadata in this story (D3)
//!
//! The blob carries `sha256:<hex>` in `key_pem`, never the key. A
//! follower that already holds a matching key keeps it; anything else
//! gets the row with an EMPTY `key_pem` and is counted in
//! [`ReplicaOutcome::certificates_without_key`]. Story 9.5 delivers
//! keys over its own node-scoped path.
//!
//! [`CanonicalGlobalSettings`]: crate::canonical::CanonicalGlobalSettings

use std::collections::{HashMap, HashSet};

use rusqlite::params;

use super::ConfigStore;
use crate::canonical::{decode_canonical, secret_digest, sha256_hex, CanonicalConfig};
use crate::error::{ConfigError, Result};
use crate::models::{Certificate, Route};

/// Why a replica could not be applied.
///
/// `Refused` is the semantic rejection the control plane aborts on
/// fleet-wide (Story 9.4 AC #1 / AC #5): the blob itself is
/// unacceptable to this node, and retrying it changes nothing.
/// `Store` is a local failure (disk, constraint, corrupt row); the
/// transaction rolled back and the node stays on its previous
/// configuration.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaError {
    /// The blob was rejected on its merits. The message names the
    /// reason without embedding blob values.
    #[error("replica refused: {0}")]
    Refused(String),
    /// A local store failure during prepare or apply.
    #[error(transparent)]
    Store(#[from] ConfigError),
}

/// What one apply changed, for the log line and the audit row. Every
/// count is rows written, not rows examined.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicaOutcome {
    /// Routes written (created or updated) on this node.
    pub routes: usize,
    /// Routes in the blob whose `node_selector` does not name this
    /// node. They are not written, and any local copy is deleted.
    pub routes_skipped_by_selector: usize,
    /// Backends written.
    pub backends: usize,
    /// Route-to-backend links written.
    pub route_backends: usize,
    /// Certificate rows written.
    pub certificates: usize,
    /// Certificate rows written with an empty `key_pem` because this
    /// node does not hold the matching private key (D3). The cert
    /// resolver skips those with a WARN until Story 9.5 delivers the
    /// key.
    pub certificates_without_key: usize,
    /// Operator WAF custom rules written.
    pub waf_custom_rules: usize,
    /// Disabled built-in WAF rule ids written.
    pub waf_disabled_rules: usize,
    /// Certificate-export ACL rows written.
    pub cert_export_acls: usize,
    /// Operator AI crawler rows written.
    pub ai_crawlers_custom: usize,
    /// Active-probe definitions written.
    pub probe_configs: usize,
    /// SLA target definitions written.
    pub sla_configs: usize,
    /// Whether any fleet-policy global setting differed from the
    /// local value and was overwritten.
    pub global_fields_changed: bool,
}

impl ConfigStore {
    /// Decode (strictly) and validate a canonical blob without
    /// touching the store: the Prepare phase.
    ///
    /// `expected_hash` is the lowercase-hex SHA-256 of `blob` the
    /// control plane announced; a mismatch is a refusal, so a
    /// truncated or tampered payload never reaches the decoder. The
    /// comparison is case-insensitive because the hash travels as
    /// text; it guards integrity, not secrecy.
    ///
    /// # Errors
    ///
    /// [`ReplicaError::Refused`] on a hash mismatch, on any
    /// [`decode_canonical`] failure (unknown field, wrong format
    /// version, malformed shape), and on a route whose
    /// `node_selector` breaks [`Route::validate_node_selector`].
    pub fn prepare_replica(
        &self,
        blob: &[u8],
        expected_hash: &str,
    ) -> std::result::Result<CanonicalConfig, ReplicaError> {
        if !sha256_hex(blob).eq_ignore_ascii_case(expected_hash) {
            return Err(ReplicaError::Refused("hash mismatch".to_string()));
        }
        let config =
            decode_canonical(blob).map_err(|e| ReplicaError::Refused(e.to_string()))?;
        for route in &config.routes {
            route.validate_node_selector().map_err(|reason| {
                ReplicaError::Refused(format!("route {}: {reason}", route.id))
            })?;
        }
        Ok(config)
    }

    /// Apply a decoded replica in ONE transaction: the Commit phase.
    ///
    /// `local_node_name` is this node's Story 9.3 `cluster_nodes.name`;
    /// it selects which routes apply here (D11). Any error rolls the
    /// whole apply back, so the node either serves the new generation
    /// whole or keeps the previous one whole.
    ///
    /// `generation` and `hash` are the applied-configuration marker,
    /// written INSIDE the same transaction. It used to be a second
    /// write after the commit, with a comment promising that a failed
    /// marker would "re-apply on the next pull"; it did not, because
    /// the pull compared against the in-memory copy that had already
    /// moved on (Epic 9 close, architecture review). Now the tables
    /// and the marker move together or not at all, and there is no
    /// second state to reconcile.
    ///
    /// # Errors
    ///
    /// [`ReplicaError::Store`] on any store failure. The blob was
    /// already accepted by [`ConfigStore::prepare_replica`], so this
    /// phase raises no `Refused`.
    pub fn apply_replica(
        &self,
        config: &CanonicalConfig,
        local_node_name: &str,
        generation: u64,
        hash: &str,
    ) -> std::result::Result<ReplicaOutcome, ReplicaError> {
        let tx = self.conn.unchecked_transaction().map_err(ConfigError::from)?;
        // Every helper below writes through `self.conn`, the same
        // connection the transaction was opened on, so all of it is
        // inside this transaction. Returning early drops `tx`, which
        // rolls back.
        let outcome = self.apply_replica_tables(config, local_node_name)?;
        self.record_applied_config(generation, hash)?;
        tx.commit().map_err(ConfigError::from)?;
        Ok(outcome)
    }

    /// The body of [`ConfigStore::apply_replica`], run inside its
    /// caller's transaction. Split out so every `?` return path drops
    /// the transaction and rolls back.
    fn apply_replica_tables(
        &self,
        config: &CanonicalConfig,
        local_node_name: &str,
    ) -> Result<ReplicaOutcome> {
        let mut outcome = ReplicaOutcome::default();

        // 1. Fleet-policy globals. Node-local fields have no field in
        //    `CanonicalGlobalSettings`, so they cannot be reached from
        //    here even by a compromised control plane (AC #1).
        let mut settings = self.get_global_settings()?;
        outcome.global_fields_changed = config.global.apply_to(&mut settings);
        if outcome.global_fields_changed {
            self.update_global_settings(&settings)?;
        }

        // 2. Certificates before routes: `routes.certificate_id` has a
        //    foreign key onto them.
        outcome.certificates = config.certificates.len();
        outcome.certificates_without_key = self.apply_replica_certificates(config)?;

        // 3. Backends before the links that reference them.
        self.apply_replica_backends(config)?;
        outcome.backends = config.backends.len();

        // 4. Routes, scoped by `node_selector`.
        let kept: Vec<&Route> = config
            .routes
            .iter()
            .filter(|r| Route::route_applies_to_node(r, local_node_name))
            .collect();
        outcome.routes = kept.len();
        outcome.routes_skipped_by_selector = config.routes.len() - kept.len();
        self.apply_replica_routes(&kept)?;

        // 5. Links, restricted to the routes this node keeps.
        let kept_ids: HashSet<&str> = kept.iter().map(|r| r.id.as_str()).collect();
        outcome.route_backends = self.apply_replica_route_backends(config, &kept_ids)?;

        // 6. WAF: both sets are wholesale replacements.
        self.conn.execute("DELETE FROM waf_custom_rules", [])?;
        for rule in &config.waf_custom_rules {
            self.save_waf_custom_rule(
                rule.id,
                &rule.description,
                &rule.category,
                &rule.pattern,
                rule.severity,
                rule.enabled,
            )?;
        }
        outcome.waf_custom_rules = config.waf_custom_rules.len();
        self.save_waf_disabled_rules(&config.waf_disabled_rules)?;
        outcome.waf_disabled_rules = config.waf_disabled_rules.len();

        // 7. Certificate-export ACLs: the pattern policy is fleet
        //    policy; the export directory and its ownership stay
        //    node-local and are not in the blob at all.
        let acl_ids: HashSet<&str> = config
            .cert_export_acls
            .iter()
            .map(|a| a.id.as_str())
            .collect();
        for local in self.list_cert_export_acls()? {
            if !acl_ids.contains(local.id.as_str()) {
                self.delete_cert_export_acl(&local.id)?;
            }
        }
        for acl in &config.cert_export_acls {
            // Delete-then-insert rather than an UPDATE: it restores
            // every column including `created_at`, so a re-encode on
            // this node reproduces the control plane's bytes.
            self.delete_cert_export_acl(&acl.id)?;
            self.create_cert_export_acl(acl)?;
        }
        outcome.cert_export_acls = config.cert_export_acls.len();

        // 8. AI crawlers, keyed on the UNIQUE `name` (D2).
        outcome.ai_crawlers_custom = self.apply_replica_crawlers(config)?;

        // 9. Probes and SLA targets. Both reference `routes(id)`, so
        //    an entry whose route this node does not serve is skipped:
        //    the row has nowhere to attach and the cascade would have
        //    removed it anyway.
        outcome.probe_configs = self.apply_replica_probes(config, &kept_ids)?;
        outcome.sla_configs = self.apply_replica_sla(config, &kept_ids)?;

        Ok(outcome)
    }

    /// Certificates (D3). Returns how many rows landed without a key.
    fn apply_replica_certificates(&self, config: &CanonicalConfig) -> Result<usize> {
        let local: HashMap<String, Certificate> = self
            .list_certificates()?
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        let blob_ids: HashSet<&str> = config.certificates.iter().map(|c| c.id.as_str()).collect();

        let mut without_key = 0usize;
        for cert in &config.certificates {
            let mut row = cert.clone();
            let existing = local.get(&cert.id);
            match existing {
                // The digest in the blob matches the key this node
                // already holds: keep the key, refresh the metadata.
                Some(held) if secret_digest(&held.key_pem) == cert.key_pem => {
                    row.key_pem = held.key_pem.clone();
                }
                // The blob announces a DIFFERENT key and this node
                // holds a working pair for that row. Leave the row
                // completely alone rather than writing the new chain
                // with an empty key.
                //
                // Writing it would take the node from "serving the
                // previous certificate, which is still valid" to
                // "serving nothing for that hostname", because a chain
                // without its key is skipped by the TLS resolver. The
                // node would then be BETTER off having ignored the
                // generation entirely. So the old pair keeps serving
                // until the key channel delivers the new one, which is
                // what turns a renewal from a self-inflicted outage
                // into a no-op that resolves itself.
                Some(held) if !held.key_pem.is_empty() => {
                    without_key += 1;
                    continue;
                }
                // No local row, or a local row that never had a key:
                // there is nothing to preserve, so write the metadata
                // and wait for the key.
                _ => {
                    row.key_pem = String::new();
                    without_key += 1;
                }
            }
            if existing.is_some() {
                self.update_certificate(&row)?;
            } else {
                self.create_certificate(&row)?;
            }
        }
        for id in local.keys() {
            if !blob_ids.contains(id.as_str()) {
                self.delete_certificate(id)?;
            }
        }
        Ok(without_key)
    }

    /// Backends: upsert by id, then delete the ones the blob dropped.
    /// Deleting a backend cascades its `route_backends` rows, which the
    /// link pass rewrites anyway.
    fn apply_replica_backends(&self, config: &CanonicalConfig) -> Result<()> {
        let local_ids: HashSet<String> = self
            .list_backends()?
            .into_iter()
            .map(|b| b.id)
            .collect();
        let blob_ids: HashSet<&str> = config.backends.iter().map(|b| b.id.as_str()).collect();
        for backend in &config.backends {
            if local_ids.contains(&backend.id) {
                self.update_backend(backend)?;
            } else {
                self.create_backend(backend)?;
            }
        }
        for id in &local_ids {
            if !blob_ids.contains(id.as_str()) {
                self.delete_backend(id)?;
            }
        }
        Ok(())
    }

    /// Routes: delete what this node no longer serves, then upsert the
    /// rest. The uniqueness check is deliberately skipped (see
    /// `ConfigStore::insert_route_row`): the blob is one consistent
    /// snapshot, and checking row by row would reject a generation
    /// that merely swaps two hostnames.
    fn apply_replica_routes(&self, kept: &[&Route]) -> Result<()> {
        let kept_ids: HashSet<&str> = kept.iter().map(|r| r.id.as_str()).collect();
        let local_ids: HashSet<String> = self.local_route_ids()?;
        for id in &local_ids {
            if !kept_ids.contains(id.as_str()) {
                self.delete_route(id)?;
            }
        }
        for route in kept {
            if local_ids.contains(route.id.as_str()) {
                self.update_route_row(route)?;
            } else {
                self.insert_route_row(route)?;
            }
        }
        Ok(())
    }

    /// Every route id currently on this node. A bare id read: the full
    /// row decode `list_routes` performs is wasted work here.
    fn local_route_ids(&self) -> Result<HashSet<String>> {
        let mut stmt = self.conn.prepare("SELECT id FROM routes")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut ids = HashSet::new();
        for row in rows {
            ids.insert(row?);
        }
        Ok(ids)
    }

    /// Route-to-backend links for the kept routes, replaced wholesale.
    /// Returns how many links were written.
    fn apply_replica_route_backends(
        &self,
        config: &CanonicalConfig,
        kept_ids: &HashSet<&str>,
    ) -> Result<usize> {
        for route_id in kept_ids {
            self.conn.execute(
                "DELETE FROM route_backends WHERE route_id = ?1",
                params![*route_id],
            )?;
        }
        let mut written = 0usize;
        for link in &config.route_backends {
            if kept_ids.contains(link.route_id.as_str()) {
                self.link_route_backend(&link.route_id, &link.backend_id)?;
                written += 1;
            }
        }
        Ok(written)
    }

    /// AI crawlers, keyed on `name` (D2: nothing references the
    /// autoincrement id). Returns how many rows were written.
    ///
    /// `INSERT OR REPLACE` carries the blob's id and timestamps
    /// verbatim, so this node re-encodes the control plane's bytes
    /// instead of drifting forever on a locally assigned rowid. It
    /// also resolves a row that collides on `name` OR on `id` in a
    /// single statement.
    fn apply_replica_crawlers(&self, config: &CanonicalConfig) -> Result<usize> {
        let names: HashSet<&str> = config
            .ai_crawlers_custom
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        for local in self.list_custom_crawlers()? {
            if !names.contains(local.name.as_str()) {
                self.delete_custom_crawler_by_name(&local.name)?;
            }
        }
        for crawler in &config.ai_crawlers_custom {
            self.replace_custom_crawler(crawler)?;
        }
        Ok(config.ai_crawlers_custom.len())
    }

    /// Probe definitions for the kept routes. Returns how many were
    /// written.
    fn apply_replica_probes(
        &self,
        config: &CanonicalConfig,
        kept_ids: &HashSet<&str>,
    ) -> Result<usize> {
        let blob_ids: HashSet<&str> = config
            .probe_configs
            .iter()
            .filter(|p| kept_ids.contains(p.route_id.as_str()))
            .map(|p| p.id.as_str())
            .collect();
        for local in self.list_probe_configs()? {
            if !blob_ids.contains(local.id.as_str()) {
                self.delete_probe_config(&local.id)?;
            }
        }
        let mut written = 0usize;
        for probe in &config.probe_configs {
            if !kept_ids.contains(probe.route_id.as_str()) {
                continue;
            }
            // Delete-then-insert restores `route_id` and `created_at`
            // too, which `update_probe_config` leaves alone.
            self.conn.execute(
                "DELETE FROM probe_configs WHERE id = ?1",
                params![probe.id],
            )?;
            self.create_probe_config(probe)?;
            written += 1;
        }
        Ok(written)
    }

    /// SLA targets for the kept routes. Returns how many were written.
    fn apply_replica_sla(
        &self,
        config: &CanonicalConfig,
        kept_ids: &HashSet<&str>,
    ) -> Result<usize> {
        let blob_routes: HashSet<&str> = config
            .sla_configs
            .iter()
            .filter(|s| kept_ids.contains(s.route_id.as_str()))
            .map(|s| s.route_id.as_str())
            .collect();
        for local in self.list_sla_configs()? {
            if !blob_routes.contains(local.route_id.as_str()) {
                self.conn.execute(
                    "DELETE FROM sla_configs WHERE route_id = ?1",
                    params![local.route_id],
                )?;
            }
        }
        let mut written = 0usize;
        for sla in &config.sla_configs {
            if !kept_ids.contains(sla.route_id.as_str()) {
                continue;
            }
            // `upsert_sla_config` keeps the local `created_at` on
            // conflict; the replica must restore the blob's, so the
            // row is replaced outright.
            self.conn.execute(
                "DELETE FROM sla_configs WHERE route_id = ?1",
                params![sla.route_id],
            )?;
            self.upsert_sla_config(sla)?;
            written += 1;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::canonical::{canonical_bytes, canonical_hash};
    use crate::models::{
        Backend, CertExportAcl, CustomCrawler, CustomVerification, GlobalSettings, HealthStatus,
        LifecycleState, LoadBalancing, ProbeConfig, SlaConfig, WafMode,
    };
    use crate::store::new_id;

    /// Fixed timestamp: the same logical entity written to two stores
    /// must serialise to identical bytes.
    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-02-02T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    const CERT_KEY: &str = "-----BEGIN PRIVATE KEY-----\nreplica-key\n-----END PRIVATE KEY-----";

    fn make_route(id: &str, hostname: &str, selector: &[&str]) -> Route {
        let now = fixed_now();
        Route {
            id: id.to_string(),
            hostname: hostname.to_string(),
            path_prefix: "/".into(),
            certificate_id: Some("cert-1".into()),
            load_balancing: LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: WafMode::Detection,
            enabled: true,
            force_https: false,
            redirect_hostname: None,
            redirect_to: None,
            hostname_aliases: Vec::new(),
            proxy_headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            security_headers: "moderate".to_string(),
            connect_timeout_s: 5,
            read_timeout_s: 60,
            send_timeout_s: 60,
            strip_path_prefix: None,
            add_path_prefix: None,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            access_log_enabled: true,
            proxy_headers_remove: Vec::new(),
            response_headers_remove: Vec::new(),
            max_request_body_bytes: None,
            websocket_enabled: true,
            rate_limit_rps: None,
            rate_limit_burst: None,
            ip_allowlist: Vec::new(),
            ip_denylist: Vec::new(),
            cors_allowed_origins: Vec::new(),
            cors_allowed_methods: Vec::new(),
            cors_max_age_s: None,
            compression_enabled: false,
            retry_attempts: None,
            cache_enabled: false,
            cache_ttl_s: 300,
            cache_max_bytes: 52_428_800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: Vec::new(),
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: Vec::new(),
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: Vec::new(),
            header_rules: Vec::new(),
            traffic_splits: Vec::new(),
            forward_auth: None,
            mirror: None,
            response_rewrite: None,
            mtls: None,
            rate_limit: None,
            geoip: None,
            bot_protection: None,
            group_name: String::new(),
            node_selector: selector.iter().map(|s| (*s).to_string()).collect(),
            ai_bot_policy: None,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_backend(id: &str, address: &str) -> Backend {
        let now = fixed_now();
        Backend {
            id: id.to_string(),
            address: address.to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 100,
            health_status: HealthStatus::Healthy,
            health_check_enabled: true,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            created_at: now,
            updated_at: now,
        }
    }

    fn make_certificate(id: &str, key_pem: &str) -> Certificate {
        let now = fixed_now();
        Certificate {
            id: id.to_string(),
            domain: "replica.example.com".into(),
            san_domains: Vec::new(),
            fingerprint: "sha256:replica".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nreplica\n-----END CERTIFICATE-----".into(),
            key_pem: key_pem.to_string(),
            issuer: "Test CA".into(),
            not_before: now,
            not_after: now,
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
        }
    }

    /// The control plane's configuration: two routes (one of them
    /// pinned to `edge-1`), two backends and every table the replica
    /// apply owns. Deliberately no notification channel and no DNS
    /// provider: those ride the blob for drift detection but are never
    /// applied (D2), so a fixture carrying them could not converge.
    fn seed_source(store: &ConfigStore) {
        let now = fixed_now();
        store
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("test setup: certificate");
        for backend in [
            make_backend("backend-1", "10.0.0.10:8080"),
            make_backend("backend-2", "10.0.0.11:8080"),
        ] {
            store
                .create_backend(&backend)
                .expect("test setup: backend");
        }
        for route in [
            make_route("route-fleet", "fleet.example.com", &[]),
            make_route("route-edge", "edge.example.com", &["edge-1"]),
        ] {
            store.create_route(&route).expect("test setup: route");
        }
        for (route_id, backend_id) in [
            ("route-fleet", "backend-1"),
            ("route-fleet", "backend-2"),
            ("route-edge", "backend-1"),
        ] {
            store
                .link_route_backend(route_id, backend_id)
                .expect("test setup: link");
        }
        store
            .save_waf_custom_rule(9001, "block", "custom", "evil", 5, true)
            .expect("test setup: waf rule");
        store
            .save_waf_disabled_rules(&[1001, 1002])
            .expect("test setup: waf disabled");
        store
            .create_cert_export_acl(&CertExportAcl {
                id: "acl-1".into(),
                hostname_pattern: "*.example.com".into(),
                allowed_uid: Some(1000),
                allowed_gid: None,
                created_at: now,
            })
            .expect("test setup: acl");
        store
            .create_custom_crawler(&CustomCrawler {
                id: 0,
                name: "acme-bot".into(),
                user_agent_pattern: "AcmeBot/1".into(),
                verification: CustomVerification::UaOnly,
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .expect("test setup: crawler");
        store
            .create_probe_config(&ProbeConfig {
                id: "probe-1".into(),
                route_id: "route-fleet".into(),
                method: "GET".into(),
                path: "/health".into(),
                expected_status: 200,
                interval_s: 30,
                timeout_ms: 5000,
                enabled: true,
                created_at: now,
                updated_at: now,
            })
            .expect("test setup: probe");
        store
            .upsert_sla_config(&SlaConfig {
                route_id: "route-fleet".into(),
                target_pct: 99.5,
                max_latency_ms: 400,
                success_status_min: 200,
                success_status_max: 399,
                created_at: now,
                updated_at: now,
            })
            .expect("test setup: sla");
        let mut settings = store
            .get_global_settings()
            .expect("test setup: settings read");
        settings.waf_ban_threshold = 11;
        settings.cert_export_dir = Some("/var/lib/lorica/control-plane".into());
        store
            .update_global_settings(&settings)
            .expect("test setup: settings write");
    }

    /// A follower with its own machine configuration and its own
    /// operator account, neither of which replication may disturb.
    fn seed_target_node_local(store: &ConfigStore) {
        let mut settings = store
            .get_global_settings()
            .expect("test setup: settings read");
        settings.management_port = 9999;
        settings.cert_export_dir = Some("/srv/edge-1/certs".into());
        settings.bot_hmac_secret_hex = "feedfacefeedfacefeedfacefeedface".into();
        store
            .update_global_settings(&settings)
            .expect("test setup: settings write");
        store
            .create_user(&crate::models::User {
                id: new_id(),
                username: "edge-operator".into(),
                password_hash: "argon2-hash".into(),
                role: crate::models::Role::SuperAdmin,
                must_change_password: false,
                created_at: fixed_now(),
                last_login_at: None,
                disabled_at: None,
                created_by: None,
            })
            .expect("test setup: user");
    }

    fn prepared(
        source: &ConfigStore,
        target: &ConfigStore,
    ) -> std::result::Result<CanonicalConfig, ReplicaError> {
        let blob = canonical_bytes(source).expect("encode");
        let hash = canonical_hash(source).expect("hash");
        target.prepare_replica(&blob, &hash)
    }

    #[test]
    fn apply_converges_the_replicated_tables_and_leaves_node_local_state_alone() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        seed_target_node_local(&target);
        // The follower already holds the private key, so the digest in
        // the blob matches and the key survives the apply.
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");

        let config = prepared(&source, &target).expect("prepare");
        let outcome = target.apply_replica(&config, "edge-1", 1, "h1").expect("apply");

        assert_eq!(outcome.routes, 2);
        assert_eq!(outcome.routes_skipped_by_selector, 0);
        assert_eq!(outcome.backends, 2);
        assert_eq!(outcome.route_backends, 3);
        assert_eq!(outcome.certificates, 1);
        assert_eq!(outcome.certificates_without_key, 0);
        assert_eq!(outcome.waf_custom_rules, 1);
        assert_eq!(outcome.waf_disabled_rules, 2);
        assert_eq!(outcome.cert_export_acls, 1);
        assert_eq!(outcome.ai_crawlers_custom, 1);
        assert_eq!(outcome.probe_configs, 1);
        assert_eq!(outcome.sla_configs, 1);
        assert!(outcome.global_fields_changed);

        // Every replicated table matches, which the canonical hash
        // states in one assertion.
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash"),
            "a fully applied replica must re-encode to the control plane's bytes"
        );
        assert_eq!(
            target.list_routes().expect("routes").len(),
            2,
            "both routes apply on edge-1"
        );
        assert_eq!(
            target
                .get_certificate("cert-1")
                .expect("cert")
                .expect("row")
                .key_pem,
            CERT_KEY,
            "a matching key digest keeps the local key"
        );

        // Node-local settings and the follower's own operator survive.
        let settings = target.get_global_settings().expect("settings");
        assert_eq!(settings.management_port, 9999);
        assert_eq!(settings.cert_export_dir.as_deref(), Some("/srv/edge-1/certs"));
        assert_eq!(settings.bot_hmac_secret_hex, "feedfacefeedfacefeedfacefeedface");
        assert_eq!(settings.waf_ban_threshold, 11, "fleet policy did replicate");
        let users = target.list_users().expect("users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "edge-operator");
    }

    #[test]
    fn a_certificate_whose_key_is_absent_lands_without_one() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let config = prepared(&source, &target).expect("prepare");
        let outcome = target.apply_replica(&config, "edge-1", 1, "h1").expect("apply");

        assert_eq!(outcome.certificates, 1);
        assert_eq!(outcome.certificates_without_key, 1);
        let cert = target
            .get_certificate("cert-1")
            .expect("cert")
            .expect("row");
        assert!(
            cert.key_pem.is_empty(),
            "Story 9.5 delivers the key on its own path; 9.4 must not invent one"
        );
        assert_eq!(cert.fingerprint, "sha256:replica", "metadata still applies");
    }

    #[test]
    fn node_selector_scopes_routes_to_the_named_nodes() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let config = prepared(&source, &target).expect("prepare");
        let outcome = target.apply_replica(&config, "edge-2", 1, "h1").expect("apply");

        assert_eq!(outcome.routes, 1);
        assert_eq!(outcome.routes_skipped_by_selector, 1);
        let hostnames: Vec<String> = target
            .list_routes()
            .expect("routes")
            .into_iter()
            .map(|r| r.hostname)
            .collect();
        assert_eq!(hostnames, vec!["fleet.example.com".to_string()]);
        assert!(
            target.get_route("route-edge").expect("route").is_none(),
            "a route pinned to edge-1 must not exist on edge-2"
        );
        // Only the fleet route's two links survive.
        assert_eq!(outcome.route_backends, 2);
    }

    #[test]
    fn a_wrong_hash_or_a_tampered_blob_is_refused() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        let blob = canonical_bytes(&source).expect("encode");
        let hash = canonical_hash(&source).expect("hash");

        let err = target
            .prepare_replica(&blob, &"0".repeat(64))
            .expect_err("a wrong hash must be refused");
        assert!(matches!(err, ReplicaError::Refused(ref m) if m.contains("hash")));

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] = b' ';
        assert!(
            matches!(
                target.prepare_replica(&tampered, &hash),
                Err(ReplicaError::Refused(_))
            ),
            "a payload that does not hash to the announced value is refused"
        );

        // A blob carrying a field this node does not know is refused
        // by the strict decoder, hash and all.
        let mut root: serde_json::Value = serde_json::from_slice(&blob).expect("json");
        root.as_object_mut()
            .expect("object")
            .insert("added_in_a_newer_schema".into(), serde_json::Value::Bool(true));
        let newer = serde_json::to_vec(&root).expect("re-encode");
        let newer_hash = sha256_hex(&newer);
        assert!(matches!(
            target.prepare_replica(&newer, &newer_hash),
            Err(ReplicaError::Refused(_))
        ));
    }

    #[test]
    fn a_route_with_an_invalid_node_selector_is_refused() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        let blob = canonical_bytes(&source).expect("encode");
        let mut root: serde_json::Value = serde_json::from_slice(&blob).expect("json");
        for route in root["routes"].as_array_mut().expect("routes array") {
            route["node_selector"] = serde_json::json!(["Not A Node Name"]);
        }
        let edited = serde_json::to_vec(&root).expect("re-encode");
        let hash = sha256_hex(&edited);

        let err = target
            .prepare_replica(&edited, &hash)
            .expect_err("an invalid selector must be refused");
        assert!(matches!(err, ReplicaError::Refused(_)));
    }

    #[test]
    fn a_failed_apply_leaves_the_target_untouched() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        seed_target_node_local(&target);
        let config = prepared(&source, &target).expect("prepare");
        target.apply_replica(&config, "edge-1", 1, "h1").expect("first apply");
        let baseline = canonical_hash(&target).expect("baseline hash");

        // A second generation that drops every certificate while a
        // route still references one: the route INSERT trips the
        // `routes.certificate_id` foreign key half way through the
        // apply, which must roll the whole thing back.
        let mut broken = config.clone();
        broken.certificates.clear();
        broken.routes.push(make_route("route-broken", "broken.example.com", &[]));
        let err = target
            .apply_replica(&broken, "edge-1", 2, "h2")
            .expect_err("a foreign-key violation must fail the apply");
        assert!(matches!(err, ReplicaError::Store(_)));

        assert_eq!(
            baseline,
            canonical_hash(&target).expect("post-failure hash"),
            "a rolled-back apply must leave every table as it was"
        );
        assert!(target.get_route("route-broken").expect("route").is_none());
        assert_eq!(
            target.get_global_settings().expect("settings").management_port,
            9999
        );
    }

    #[test]
    fn applying_the_same_replica_twice_is_idempotent() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");

        let config = prepared(&source, &target).expect("prepare");
        let first = target.apply_replica(&config, "edge-1", 1, "h1").expect("first apply");
        let after_first = canonical_hash(&target).expect("hash");
        let second = target.apply_replica(&config, "edge-1", 1, "h1").expect("second apply");

        assert_eq!(after_first, canonical_hash(&target).expect("hash"));
        assert_eq!(first.routes, second.routes);
        assert_eq!(first.backends, second.backends);
        assert_eq!(first.route_backends, second.route_backends);
        assert_eq!(first.ai_crawlers_custom, second.ai_crawlers_custom);
        assert!(
            !second.global_fields_changed,
            "the second apply finds every fleet-policy field already in place"
        );
    }

    #[test]
    fn rows_the_blob_dropped_are_deleted_on_the_follower() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");
        let config = prepared(&source, &target).expect("prepare");
        target.apply_replica(&config, "edge-1", 1, "h1").expect("first apply");

        // The control plane deletes a route, a backend, the ACL and the
        // crawler, then republishes.
        source.delete_route("route-edge").expect("delete route");
        source.delete_backend("backend-2").expect("delete backend");
        source.delete_cert_export_acl("acl-1").expect("delete acl");
        let crawler_id = source
            .list_custom_crawlers()
            .expect("crawlers")
            .first()
            .map(|c| c.id)
            .expect("one crawler");
        source
            .delete_custom_crawler(crawler_id)
            .expect("delete crawler");

        let config = prepared(&source, &target).expect("prepare");
        target.apply_replica(&config, "edge-1", 1, "h1").expect("second apply");

        assert!(target.get_route("route-edge").expect("route").is_none());
        assert!(target.get_backend("backend-2").expect("backend").is_none());
        assert!(target
            .list_cert_export_acls()
            .expect("acls")
            .is_empty());
        assert!(target
            .list_custom_crawlers()
            .expect("crawlers")
            .is_empty());
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash")
        );
    }

    #[test]
    fn global_settings_apply_to_is_the_inverse_of_the_encoder() {
        // A round trip through the canonical subset must be identity on
        // the fleet-policy fields and leave node-local ones alone.
        let mut node_local = GlobalSettings {
            management_port: 8443,
            bot_hmac_secret_hex: "0123456789abcdef0123456789abcdef".into(),
            ..GlobalSettings::default()
        };
        let fleet = GlobalSettings {
            waf_ban_threshold: 42,
            sla_purge_schedule: "0 4 * * *".into(),
            ..GlobalSettings::default()
        };
        let canonical = crate::canonical::CanonicalGlobalSettings::from(&fleet);

        assert!(canonical.apply_to(&mut node_local));
        assert_eq!(node_local.waf_ban_threshold, 42);
        assert_eq!(node_local.sla_purge_schedule, "0 4 * * *");
        assert_eq!(node_local.management_port, 8443);
        assert_eq!(
            node_local.bot_hmac_secret_hex,
            "0123456789abcdef0123456789abcdef"
        );
        assert!(
            !canonical.apply_to(&mut node_local),
            "a second application changes nothing"
        );
    }
}
