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
//! autoincrement id), probe_configs, sla_configs, capture_rules,
//! automation_environments, streams and stream_backends. Rows absent
//! from the blob are deleted in exactly those tables.
//!
//! # One check on the snapshot, unchecked writes (Story 12.1, D-6)
//!
//! The stream attachment rule (`check_backend_attachments`) runs once,
//! on the whole decoded blob, in [`ConfigStore::prepare_replica`], as a
//! semantic refusal. The apply then writes backends, route links,
//! streams and stream links through the store's unchecked writers: a
//! consistent snapshot applied row by row can pass through a transient
//! violation (a backend moving from a UDP stream to a route), which the
//! checked management writers would refuse half way through a valid
//! generation. Same argument as the hostname uniqueness the route pass
//! skips.
//!
//! A capture rule's two counters are the one thing the blob does not
//! carry (Story 10.1): they count what THIS node recorded and dropped,
//! so an apply refreshes every other column and leaves them where the
//! local process put them.
//!
//! Never written: `users`, `user_preferences`, `sessions`,
//! `notification_configs`, `dns_providers`, every `cluster_*` table,
//! load tests and all telemetry (`sla_buckets`, `probe_results`,
//! access and WAF logs).
//!
//! Telemetry is genuinely untouched since 1.7.1. It was not before:
//! `sla_buckets.route_id` was `REFERENCES routes(id) ON DELETE CASCADE`
//! with `PRAGMA foreign_keys` ON, so a `node_selector` change that
//! de-selected a node destroyed up to `sla_purge_retention_days` of
//! that node's SLA history with nobody touching that node, and
//! re-selecting it did not bring the history back. Schema migration 55
//! rebuilt the table without the constraint, so SLA history now follows
//! the rule `probe_results` always did: retained by time, removed by
//! `prune_sla_buckets` and by nothing else (backlog #67).
//! Notification channels and DNS providers DO
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
use crate::canonical::{
    decode_canonical, key_material_digest, secret_digest, sha256_hex, CanonicalConfig,
};
use crate::error::{ConfigError, Result};
use crate::models::{check_backend_attachments, AttachmentSnapshot, Certificate, Route, Stream};
use crate::route_selection::{self, RouteNames};

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
    /// Traffic-capture rules written.
    pub capture_rules: usize,
    /// Capture rules in the blob naming a route this node does not
    /// serve. They are dropped rather than inserted: the foreign key
    /// would refuse them and abort the whole apply.
    pub capture_rules_dropped: usize,
    /// Automation environments written (Story 10.4).
    pub automation_environments: usize,
    /// Environments in the blob naming a route this node does not
    /// serve, dropped for the same reason as `capture_rules_dropped`.
    pub automation_environments_dropped: usize,
    /// Streams written (Story 12.1), enabled or not.
    pub streams: usize,
    /// Streams in the blob whose `node_selector` does not name this
    /// node. They are not written, and any local copy is deleted.
    pub streams_skipped_by_selector: usize,
    /// Stream-to-backend links written.
    pub stream_backends: usize,
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
    /// version, malformed shape), on a global setting carrying a
    /// malformed CIDR entry, on a route whose `node_selector` breaks
    /// [`Route::validate_node_selector`], on a stream that breaks
    /// [`Stream::validate`] (selector included), and on a snapshot whose
    /// backends break the stream attachment rule
    /// ([`check_backend_attachments`]). A stream refusal names the
    /// stream's id.
    pub fn prepare_replica(
        blob: &[u8],
        expected_hash: &str,
    ) -> std::result::Result<CanonicalConfig, ReplicaError> {
        if !sha256_hex(blob).eq_ignore_ascii_case(expected_hash) {
            return Err(ReplicaError::Refused("hash mismatch".to_string()));
        }
        let config = decode_canonical(blob).map_err(|e| ReplicaError::Refused(e.to_string()))?;
        // A malformed address entry is refused here rather than dropped
        // at parse time on the data plane: an allow list whose only
        // entry is a typo parses to an EMPTY allow list, which the
        // connection filter reads as default-allow, so applying the
        // blob would silently take the node's TCP allowlist off
        // (backlog #88). The round aborts fleet-wide, which is what a
        // blob this node will not accept is supposed to do.
        config
            .global
            .validate_cidr_lists()
            .map_err(|reason| ReplicaError::Refused(format!("global settings: {reason}")))?;
        for route in &config.routes {
            route
                .validate_node_selector()
                .map_err(|reason| ReplicaError::Refused(format!("route {}: {reason}", route.id)))?;
        }
        for stream in &config.streams {
            stream.validate().map_err(|reason| {
                ReplicaError::Refused(format!("stream {}: {reason}", stream.id))
            })?;
        }
        // Once, on the whole snapshot (D-6): the apply below writes row
        // by row through the unchecked writers, which is only sound
        // because the set it converges to was checked here.
        check_backend_attachments(&AttachmentSnapshot {
            backends: &config.backends,
            streams: &config.streams,
            stream_backends: &config.stream_backends,
            route_backends: &config.route_backends,
        })
        .map_err(|conflict| {
            let subject = conflict
                .stream
                .as_deref()
                .and_then(|name| config.streams.iter().find(|s| s.name == name))
                .map_or_else(
                    || format!("backend {}", conflict.backend_id),
                    |stream| format!("stream {}", stream.id),
                );
            ReplicaError::Refused(format!("{subject}: {conflict}"))
        })?;
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
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(ConfigError::from)?;
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
        //
        // Since Story 10.0 this is no longer where targeting happens:
        // the control plane cuts the payload per recipient, so a route
        // this node is not selected for never arrives. The filter stays
        // for two reasons. It is what makes a 1.8.0 follower work under
        // a 1.7.x control plane, which still sends the fleet-wide blob.
        // And on a current fleet it is the assertion that the cut was
        // correct: if it ever removes a row, the control plane sent
        // this node something it was not entitled to.
        let kept: Vec<&Route> = config
            .routes
            .iter()
            .filter(|r| r.applies_to_node(local_node_name))
            .collect();
        outcome.routes = kept.len();
        outcome.routes_skipped_by_selector = config.routes.len() - kept.len();
        self.apply_replica_routes(&kept)?;

        // 5. Links, restricted to the routes this node keeps.
        let kept_ids: HashSet<&str> = kept.iter().map(|r| r.id.as_str()).collect();
        outcome.route_backends = self.apply_replica_route_backends(config, &kept_ids)?;

        // 6. Streams and their links, after the backends they reference,
        //    scoped by `node_selector` exactly as routes are. The control
        //    plane already cut the payload (Story 12.1), so this filter
        //    is the assertion that the cut was right, not the targeting.
        //    A disabled stream is applied like an enabled one: only the
        //    bind reads `enabled`.
        let kept_streams: Vec<&Stream> = config
            .streams
            .iter()
            .filter(|s| s.applies_to_node(local_node_name))
            .collect();
        outcome.streams = kept_streams.len();
        outcome.streams_skipped_by_selector = config.streams.len() - kept_streams.len();
        outcome.stream_backends = self.apply_replica_streams(config, &kept_streams)?;

        // 7. WAF: both sets are wholesale replacements.
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

        // 8. Certificate-export ACLs: the pattern policy is fleet
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

        // 9. AI crawlers, keyed on the UNIQUE `name` (D2).
        outcome.ai_crawlers_custom = self.apply_replica_crawlers(config)?;

        // 10. Probes and SLA targets. Both reference `routes(id)`, so
        //     an entry whose route this node does not serve is skipped:
        //     the row has nowhere to attach and the cascade would have
        //     removed it anyway.
        outcome.probe_configs = self.apply_replica_probes(config, &kept_ids)?;
        outcome.sla_configs = self.apply_replica_sla(config, &kept_ids)?;

        // 11. Capture rules, after the routes they cascade from.
        let (written, dropped) = self.apply_replica_capture_rules(config, &kept_ids)?;
        outcome.capture_rules = written;
        outcome.capture_rules_dropped = dropped;

        // 12. Automation environments, after the routes they cascade
        //     from (Story 10.4).
        let (written, dropped) = self.apply_replica_automation_environments(config, &kept_ids)?;
        outcome.automation_environments = written;
        outcome.automation_environments_dropped = dropped;

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
                //
                // By material first (backlog #60), because the two sides
                // hold their own PEM text and a line ending must not read
                // as a different key. The raw-text form is still accepted:
                // a 1.7.0 control plane announces that one, and a
                // followers-first upgrade would otherwise see every
                // certificate as changed for the length of the rollout.
                Some(held)
                    if key_material_digest(&held.key_pem) == cert.key_pem
                        || secret_digest(&held.key_pem) == cert.key_pem =>
                {
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
    /// Deleting a backend cascades its `route_backends` and
    /// `stream_backends` rows, which the link passes rewrite anyway.
    /// Unchecked writers: the attachment rule was checked on the whole
    /// snapshot in [`ConfigStore::prepare_replica`], and the links still
    /// on this node are the previous generation's.
    fn apply_replica_backends(&self, config: &CanonicalConfig) -> Result<()> {
        let local_ids: HashSet<String> = self.list_backends()?.into_iter().map(|b| b.id).collect();
        let blob_ids: HashSet<&str> = config.backends.iter().map(|b| b.id.as_str()).collect();
        for backend in &config.backends {
            if local_ids.contains(&backend.id) {
                self.update_backend_unchecked(backend)?;
            } else {
                self.create_backend_unchecked(backend)?;
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
    ///
    /// The names land canonical, the set rewritten as one
    /// ([`route_selection::canonicalise_route_names`]): a control plane
    /// older than this rule ships each name as its client sent it, and
    /// this node's proxy looks requests up in canonical form. A twin of
    /// a name another row serves keeps its spelling, as the upgrade
    /// leaves it, and the reload reports it. The applied-generation hash
    /// is the control plane's, recorded as sent, so the rewrite is no
    /// drift.
    fn apply_replica_routes(&self, kept: &[&Route]) -> Result<()> {
        let kept_ids: HashSet<&str> = kept.iter().map(|r| r.id.as_str()).collect();
        let local_ids: HashSet<String> = self.local_route_ids()?;
        for id in &local_ids {
            if !kept_ids.contains(id.as_str()) {
                self.delete_route(id)?;
            }
        }
        let mut names: Vec<RouteNames> = kept.iter().map(|route| RouteNames::of(route)).collect();
        route_selection::canonicalise_route_names(&mut names);
        for (route, names) in kept.iter().zip(names) {
            let mut route = (*route).clone();
            route.hostname = names.hostname;
            route.hostname_aliases = names.aliases;
            if local_ids.contains(route.id.as_str()) {
                self.update_route_row(&route)?;
            } else {
                self.insert_route_row(&route)?;
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

    /// Route-to-backend links for the kept routes, replaced wholesale,
    /// through the unchecked writer (the snapshot was checked whole).
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
                self.link_route_backend_unchecked(&link.route_id, &link.backend_id)?;
                written += 1;
            }
        }
        Ok(written)
    }

    /// Streams and their links: every local stream deleted, then every
    /// kept stream inserted and its links written. Returns how many links
    /// were written.
    ///
    /// Delete-then-insert rather than an upsert: `streams.name` is
    /// UNIQUE, and a generation that swaps two names would trip it on
    /// the first row of a row-by-row update. Deleting cascades every
    /// stream link, which this pass rewrites for the kept streams. The
    /// rows carry the blob's timestamps, so a re-encode on this node
    /// reproduces the control plane's bytes. Unchecked writers, for the
    /// reason [`ConfigStore::apply_replica_backends`] gives.
    fn apply_replica_streams(&self, config: &CanonicalConfig, kept: &[&Stream]) -> Result<usize> {
        self.conn.execute("DELETE FROM streams", [])?;
        for stream in kept {
            self.create_stream_unchecked(stream)?;
        }
        let kept_ids: HashSet<&str> = kept.iter().map(|s| s.id.as_str()).collect();
        let mut written = 0usize;
        for link in &config.stream_backends {
            if kept_ids.contains(link.stream_id.as_str()) {
                self.link_stream_backend_unchecked(link)?;
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
            self.conn
                .execute("DELETE FROM probe_configs WHERE id = ?1", params![probe.id])?;
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

    /// Capture rules for the kept routes. Returns `(written, dropped)`.
    ///
    /// A rule naming a route this node does not serve is DROPPED, not
    /// inserted. `capture_rules.route_id` is `REFERENCES routes(id)`,
    /// so inserting it would raise a constraint error and roll the
    /// whole generation back: a follower would stop applying any
    /// configuration at all because of one rule it was never meant to
    /// run. Counting the drop makes it visible; failing the apply makes
    /// it an outage. Since Story 10.0 the control plane cuts these per
    /// recipient, so a non-zero count here means the cut was wrong or
    /// the control plane predates it.
    fn apply_replica_capture_rules(
        &self,
        config: &CanonicalConfig,
        kept_ids: &HashSet<&str>,
    ) -> Result<(usize, usize)> {
        let blob_ids: HashSet<&str> = config
            .capture_rules
            .iter()
            .filter(|rule| kept_ids.contains(rule.route_id.as_str()))
            .map(|rule| rule.id.as_str())
            .collect();
        let local_ids: HashSet<String> = self
            .list_capture_rules()?
            .into_iter()
            .map(|rule| rule.id)
            .collect();
        for id in &local_ids {
            if !blob_ids.contains(id.as_str()) {
                self.delete_capture_rule(id)?;
            }
        }

        let mut written = 0usize;
        let mut dropped = 0usize;
        for canonical in &config.capture_rules {
            if !kept_ids.contains(canonical.route_id.as_str()) {
                dropped += 1;
                continue;
            }
            let rule = canonical.to_rule();
            // Update rather than delete-then-insert, unlike probes and
            // SLA targets: it restores every replicated column including
            // `created_at`, so a re-encode on this node reproduces the
            // control plane's bytes, AND it leaves this node's two
            // counters alone. A delete would zero them on every
            // generation that touches the rule.
            if local_ids.contains(&rule.id) {
                self.update_capture_rule(&rule)?;
            } else {
                self.create_capture_rule(&rule)?;
            }
            written += 1;
        }
        Ok((written, dropped))
    }

    /// Automation environments for the kept routes. Returns
    /// `(written, dropped)`.
    ///
    /// Same shape as [`ConfigStore::apply_replica_capture_rules`], for
    /// the same reason: `automation_environments.route_id` is
    /// `REFERENCES routes(id)`, so a row naming a route this node does
    /// not serve would fail the insert and roll the whole generation
    /// back. It is dropped and counted instead. The upsert writes every
    /// column from the blob, `created_at` included, so a re-encode on
    /// this node reproduces the control plane's bytes.
    fn apply_replica_automation_environments(
        &self,
        config: &CanonicalConfig,
        kept_ids: &HashSet<&str>,
    ) -> Result<(usize, usize)> {
        let blob_names: HashSet<&str> = config
            .automation_environments
            .iter()
            .filter(|environment| kept_ids.contains(environment.route_id.as_str()))
            .map(|environment| environment.name.as_str())
            .collect();
        for local in self.list_automation_environments()? {
            if !blob_names.contains(local.name.as_str()) {
                self.delete_automation_environment(&local.name)?;
            }
        }

        let mut written = 0usize;
        let mut dropped = 0usize;
        for environment in &config.automation_environments {
            if !kept_ids.contains(environment.route_id.as_str()) {
                dropped += 1;
                continue;
            }
            self.upsert_automation_environment(environment)?;
            written += 1;
        }
        Ok((written, dropped))
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::*;
    use crate::canonical::{canonical_bytes, canonical_hash, CanonicalCaptureRule};
    use crate::models::{
        binds_here, sample_stream, sample_stream_backend, sample_stream_id as sid, NodeRole,
    };
    use crate::models::{
        AutomationEnvironment, Backend, CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput,
        CaptureRedaction, CaptureRule, CaptureScope, CertExportAcl, CertificateMode, CustomCrawler,
        CustomVerification, EnvironmentOwner, GlobalSettings, HealthStatus, LifecycleState,
        LoadBalancing, ManagedBy, OwnerKind, ProbeConfig, SlaConfig, StatusMatch, StreamProtocol,
        WafMode,
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
            waf_body_scan_max_bytes: None,
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
            case_insensitive_paths: false,
            managed_by: None,
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
            health_check: crate::models::HealthCheck::TcpConnect,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
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
            adcs_authority_id: None,
            adcs_template: None,
            adcs_template_oid: None,
            adcs_request_id: None,
        }
    }

    fn make_capture_rule(id: &str, route_id: &str) -> CaptureRule {
        let now = fixed_now();
        CaptureRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            route_id: route_id.to_string(),
            enabled: true,
            match_: CaptureMatch {
                source_cidrs: vec!["10.0.0.0/8".to_string()],
                methods: vec!["POST".to_string()],
                path_prefix: Some("/api".to_string()),
                path_regex: None,
                headers: Vec::new(),
            },
            emit: CaptureEmit {
                always: false,
                status: vec![StatusMatch::ServerError],
                min_latency_ms: None,
                upstream_error: false,
            },
            capture: CaptureScope::default(),
            limits: CaptureLimits::default(),
            output: CaptureOutput::default(),
            redact: CaptureRedaction::default(),
            created_by: "admin".to_string(),
            created_at: now,
            expires_at: now,
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    fn automation_mark(environment: &str) -> Option<ManagedBy> {
        Some(ManagedBy::Automation {
            environment: environment.to_string(),
        })
    }

    fn make_environment(name: &str, route_id: &str) -> AutomationEnvironment {
        let now = fixed_now();
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("team".to_string(), "acme".to_string());
        AutomationEnvironment {
            name: name.to_string(),
            route_id: route_id.to_string(),
            owner: EnvironmentOwner {
                kind: OwnerKind::StaticToken,
                principal: "acme-ci".to_string(),
            },
            certificate_mode: CertificateMode::Auto,
            labels,
            expires_at: now,
            created_at: now,
            updated_at: now,
            last_pipeline: Some("pipeline-7".to_string()),
            pipeline: None,
        }
    }

    /// The control plane's configuration: two routes (one of them
    /// pinned to `edge-1`), three backends and every table the replica
    /// apply owns, a TCP stream pinned to `edge-1` included: it reaches
    /// `backend-2`, which a route shares, and `backend-3`, which only
    /// the stream references. The fleet route and its first backend are
    /// automation-managed by `env-1`. Deliberately no notification
    /// channel and no DNS provider: those ride the blob for drift
    /// detection but are never applied (D2), so a fixture carrying them
    /// could not converge.
    fn seed_source(store: &ConfigStore) {
        let now = fixed_now();
        store
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("test setup: certificate");
        let mut managed_backend = make_backend("backend-1", "10.0.0.10:8080");
        managed_backend.managed_by = automation_mark("env-1");
        for backend in [
            managed_backend,
            make_backend("backend-2", "10.0.0.11:8080"),
            make_backend("backend-3", "192.0.2.30:5432"),
        ] {
            store.create_backend(&backend).expect("test setup: backend");
        }
        let mut managed_route = make_route("route-fleet", "fleet.example.com", &[]);
        managed_route.managed_by = automation_mark("env-1");
        for route in [
            managed_route,
            make_route("route-edge", "edge.example.com", &["edge-1"]),
        ] {
            store.create_route(&route).expect("test setup: route");
        }
        store
            .upsert_automation_environment(&make_environment("env-1", "route-fleet"))
            .expect("test setup: environment");
        for (route_id, backend_id) in [
            ("route-fleet", "backend-1"),
            ("route-fleet", "backend-2"),
            ("route-edge", "backend-1"),
        ] {
            store
                .link_route_backend(route_id, backend_id)
                .expect("test setup: link");
        }
        let mut stream = sample_stream("stream-edge", "edge-postgres", StreamProtocol::Tcp, 5432);
        stream.node_selector = vec!["edge-1".to_string()];
        stream.created_at = now;
        stream.updated_at = now;
        store.create_stream(&stream).expect("test setup: stream");
        store
            .set_stream_backends(
                &sid("stream-edge"),
                &["backend-2".to_string(), "backend-3".to_string()],
            )
            .expect("test setup: stream links");
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
        store
            .create_capture_rule(&make_capture_rule("cap-1", "route-fleet"))
            .expect("test setup: capture rule");
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

    fn prepared(source: &ConfigStore) -> std::result::Result<CanonicalConfig, ReplicaError> {
        let blob = canonical_bytes(source).expect("encode");
        let hash = canonical_hash(source).expect("hash");
        ConfigStore::prepare_replica(&blob, &hash)
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

        let config = prepared(&source).expect("prepare");
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");

        assert_eq!(outcome.routes, 2);
        assert_eq!(outcome.routes_skipped_by_selector, 0);
        assert_eq!(outcome.backends, 3);
        assert_eq!(outcome.route_backends, 3);
        assert_eq!(outcome.streams, 1);
        assert_eq!(outcome.streams_skipped_by_selector, 0);
        assert_eq!(outcome.stream_backends, 2);
        assert_eq!(outcome.certificates, 1);
        assert_eq!(outcome.certificates_without_key, 0);
        assert_eq!(outcome.waf_custom_rules, 1);
        assert_eq!(outcome.waf_disabled_rules, 2);
        assert_eq!(outcome.cert_export_acls, 1);
        assert_eq!(outcome.ai_crawlers_custom, 1);
        assert_eq!(outcome.probe_configs, 1);
        assert_eq!(outcome.sla_configs, 1);
        assert_eq!(outcome.capture_rules, 1);
        assert_eq!(outcome.capture_rules_dropped, 0);
        assert_eq!(outcome.automation_environments, 1);
        assert_eq!(outcome.automation_environments_dropped, 0);
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
        assert_eq!(
            settings.cert_export_dir.as_deref(),
            Some("/srv/edge-1/certs")
        );
        assert_eq!(
            settings.bot_hmac_secret_hex,
            "feedfacefeedfacefeedfacefeedface"
        );
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

        let config = prepared(&source).expect("prepare");
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");

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
    fn an_adcs_certificate_replicates_and_its_authority_never_does() {
        // Epic 13 PRD D13: the authority, its failed state and its
        // issuing CA certificate stay on the control plane; the
        // certificates it issued reach followers with their `adcs_*`
        // columns, and no foreign key refuses them there.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        source
            .upsert_adcs_authority(&crate::models::sample_adcs_authority("adcs-1"))
            .expect("test setup: authority");
        source
            .set_adcs_failed("ticket_acquisition", Some(24))
            .expect("test setup: failed state");
        let mut cert = source
            .get_certificate("cert-1")
            .expect("test setup: cert read")
            .expect("test setup: cert exists");
        cert.adcs_authority_id = Some("adcs-1".to_string());
        cert.adcs_template = Some("LoricaWebServer".to_string());
        cert.adcs_request_id = Some("4242".to_string());
        source
            .update_certificate(&cert)
            .expect("test setup: cert update");

        let fleet = crate::canonical::canonical_config(&source).expect("canonical config");
        let resolution = crate::canonical::SelectorResolution::from_rows([(
            "edge-1".to_string(),
            "id-1".to_string(),
        )]);
        let cut = crate::canonical::restrict_for_recipient(&fleet, "id-1", &resolution);
        assert!(
            cut.certificates.iter().any(|c| c.id == "cert-1"),
            "test setup: the follower payload carries the AD CS certificate"
        );
        for (payload, label) in [(&fleet, "canonical blob"), (&cut, "follower payload")] {
            let bytes = crate::canonical::encode_canonical(payload).expect("encode");
            let text = String::from_utf8(bytes).expect("the blob is UTF-8");
            assert!(
                !text
                    .to_ascii_lowercase()
                    .contains(crate::models::ADCS_FIXTURE_SENTINEL),
                "{label} carries authority data: {text}"
            );
            assert!(!text.contains("ticket_acquisition"), "{label}: {text}");
            assert!(!text.contains("\"adcs_authority\""), "{label}: {text}");
        }

        // The follower already holds the key, so the hash comparison
        // below is about the authority and nothing else.
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("test setup: target holds the key");
        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply without the authority row");
        assert!(target
            .get_adcs_authority()
            .expect("follower authority read")
            .is_none());
        let applied = target
            .get_certificate("cert-1")
            .expect("cert")
            .expect("row");
        assert_eq!(applied.adcs_authority_id.as_deref(), Some("adcs-1"));
        assert_eq!(applied.adcs_request_id.as_deref(), Some("4242"));
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash"),
            "the authority is not part of what the fleet hashes"
        );
    }

    #[test]
    fn node_selector_scopes_routes_to_the_named_nodes() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let config = prepared(&source).expect("prepare");
        let outcome = target
            .apply_replica(&config, "edge-2", 1, "h1")
            .expect("apply");

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
        // The stream pinned to edge-1 is scoped the same way.
        assert_eq!(outcome.streams, 0);
        assert_eq!(outcome.streams_skipped_by_selector, 1);
        assert_eq!(outcome.stream_backends, 0);
        assert!(target.list_streams().expect("streams").is_empty());
    }

    #[test]
    fn a_wrong_hash_or_a_tampered_blob_is_refused() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        seed_source(&source);
        let blob = canonical_bytes(&source).expect("encode");
        let hash = canonical_hash(&source).expect("hash");

        let err = ConfigStore::prepare_replica(&blob, &"0".repeat(64))
            .expect_err("a wrong hash must be refused");
        assert!(matches!(err, ReplicaError::Refused(ref m) if m.contains("hash")));

        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] = b' ';
        assert!(
            matches!(
                ConfigStore::prepare_replica(&tampered, &hash),
                Err(ReplicaError::Refused(_))
            ),
            "a payload that does not hash to the announced value is refused"
        );

        // A blob carrying a field this node does not know is refused
        // by the strict decoder, hash and all.
        let mut root: serde_json::Value = serde_json::from_slice(&blob).expect("json");
        root.as_object_mut().expect("object").insert(
            "added_in_a_newer_schema".into(),
            serde_json::Value::Bool(true),
        );
        let newer = serde_json::to_vec(&root).expect("re-encode");
        let newer_hash = sha256_hex(&newer);
        assert!(matches!(
            ConfigStore::prepare_replica(&newer, &newer_hash),
            Err(ReplicaError::Refused(_))
        ));
    }

    #[test]
    fn a_route_with_an_invalid_node_selector_is_refused() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        seed_source(&source);
        let blob = canonical_bytes(&source).expect("encode");
        let mut root: serde_json::Value = serde_json::from_slice(&blob).expect("json");
        for route in root["routes"].as_array_mut().expect("routes array") {
            route["node_selector"] = serde_json::json!(["Not A Node Name"]);
        }
        let edited = serde_json::to_vec(&root).expect("re-encode");
        let hash = sha256_hex(&edited);

        let err = ConfigStore::prepare_replica(&edited, &hash)
            .expect_err("an invalid selector must be refused");
        assert!(matches!(err, ReplicaError::Refused(_)));
    }

    #[test]
    fn a_malformed_cidr_in_any_replicated_setting_is_refused_and_the_store_is_untouched() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        seed_target_node_local(&target);
        let baseline = canonical_hash(&target).expect("baseline hash");
        let blob = canonical_bytes(&source).expect("encode");

        // Every address list the blob carries, edited in turn: a new
        // one that `CanonicalGlobalSettings::cidr_lists` does not name
        // fails `every_replicated_cidr_setting_is_validated` over in
        // `canonical.rs`, so this loop cannot go stale silently.
        let fields: Vec<&str> = crate::canonical::CanonicalGlobalSettings::from(
            &crate::models::GlobalSettings::default(),
        )
        .cidr_lists()
        .iter()
        .map(|(field, _)| *field)
        .collect();
        assert!(!fields.is_empty(), "the blob carries at least one list");

        for field in fields {
            let mut root: serde_json::Value = serde_json::from_slice(&blob).expect("json");
            root["global"][field] = serde_json::json!(["10.0.0.0/33"]);
            let edited = serde_json::to_vec(&root).expect("re-encode");
            let hash = sha256_hex(&edited);

            let err = ConfigStore::prepare_replica(&edited, &hash)
                .expect_err("a /33 is not a v4 network");
            match err {
                ReplicaError::Refused(ref message) => {
                    assert!(
                        message.contains(field),
                        "the refusal does not name {field}: {message}"
                    );
                    assert!(message.contains("10.0.0.0/33"), "{message}");
                }
                ReplicaError::Store(e) => panic!("a bad CIDR is a semantic refusal, not {e}"),
            }
            assert_eq!(
                canonical_hash(&target).expect("post-refusal hash"),
                baseline,
                "prepare must not touch the store"
            );
        }
    }

    #[test]
    fn a_failed_apply_leaves_the_target_untouched() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        seed_target_node_local(&target);
        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("first apply");
        let baseline = canonical_hash(&target).expect("baseline hash");

        // A second generation that drops every certificate while a
        // route still references one: the route INSERT trips the
        // `routes.certificate_id` foreign key half way through the
        // apply, which must roll the whole thing back.
        let mut broken = config.clone();
        broken.certificates.clear();
        broken
            .routes
            .push(make_route("route-broken", "broken.example.com", &[]));
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
            target
                .get_global_settings()
                .expect("settings")
                .management_port,
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

        let config = prepared(&source).expect("prepare");
        let first = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("first apply");
        let after_first = canonical_hash(&target).expect("hash");
        let second = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("second apply");

        assert_eq!(after_first, canonical_hash(&target).expect("hash"));
        // Every count matches; only `global_fields_changed` may differ.
        assert_eq!(
            first,
            ReplicaOutcome {
                global_fields_changed: first.global_fields_changed,
                ..second.clone()
            }
        );
        assert_eq!(first.streams, 1, "the fixture carries a stream");
        assert_eq!(first.stream_backends, 2, "and its two links");
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
    fn a_replica_from_a_control_plane_storing_names_as_sent_lands_them_canonical() {
        // A control plane older than 1.10.2 stores and ships each name
        // as its client sent it; the follower applies the form its proxy
        // looks requests up by, and leaves a twin of a name another row
        // already spells canonically as it came.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        let mut mixed = make_route("r-mixed", "App.Example.COM.", &[]);
        mixed.certificate_id = None;
        mixed.hostname_aliases = vec!["WWW.Example.com".into(), "www.example.com.".into()];
        let mut canonical = make_route("r-canonical", "shop.example.com", &[]);
        canonical.certificate_id = None;
        let mut twin = make_route("r-twin", "Shop.Example.com", &[]);
        twin.certificate_id = None;
        for route in [&mixed, &canonical, &twin] {
            source
                .insert_route_row(route)
                .expect("test setup: a row as an older control plane stored it");
        }

        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");
        let names = |id: &str| {
            let route = target.get_route(id).expect("reads").expect("applied");
            (route.hostname, route.hostname_aliases)
        };
        assert_eq!(
            names("r-mixed"),
            (
                "app.example.com".to_string(),
                vec!["www.example.com".to_string()]
            )
        );
        assert_eq!(names("r-canonical").0, "shop.example.com");
        assert_eq!(names("r-twin").0, "Shop.Example.com");
    }

    #[test]
    fn case_insensitive_paths_lands_on_the_follower_both_ways() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        let mut route = make_route("r-iis", "iis.example.com", &[]);
        route.certificate_id = None;
        route.case_insensitive_paths = true;
        source.create_route(&route).expect("test setup: route");
        let applied = || {
            target
                .get_route("r-iis")
                .expect("reads")
                .expect("applied")
                .case_insensitive_paths
        };

        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");
        assert!(applied());

        route.case_insensitive_paths = false;
        source
            .update_route(&route)
            .expect("test setup: switched off");
        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 2, "h2")
            .expect("apply");
        assert!(!applied());
    }

    #[test]
    fn rows_the_blob_dropped_are_deleted_on_the_follower() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");
        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("first apply");

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

        let config = prepared(&source).expect("prepare");
        target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("second apply");

        assert!(target.get_route("route-edge").expect("route").is_none());
        assert!(target.get_backend("backend-2").expect("backend").is_none());
        assert!(target.list_cert_export_acls().expect("acls").is_empty());
        assert!(target.list_custom_crawlers().expect("crawlers").is_empty());
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash")
        );
    }

    #[test]
    fn a_capture_rule_in_the_blob_lands_on_the_follower() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let config = prepared(&source).expect("prepare");
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");

        assert_eq!(outcome.capture_rules, 1);
        let stored = target
            .get_capture_rule("cap-1")
            .expect("capture rule read")
            .expect("the rule landed");
        assert_eq!(stored.route_id, "route-fleet");
        assert_eq!(stored.emit.status, vec![StatusMatch::ServerError]);
        assert_eq!(stored.created_at, fixed_now());
    }

    #[test]
    fn a_capture_rule_that_disappears_from_the_blob_is_deleted() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");

        source
            .delete_capture_rule("cap-1")
            .expect("test setup: rule removed on the control plane");
        let outcome = target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 2, "h2")
            .expect("second apply");

        assert_eq!(outcome.capture_rules, 0);
        assert!(target
            .list_capture_rules()
            .expect("capture rules")
            .is_empty());
    }

    #[test]
    fn an_apply_refreshes_a_capture_rule_without_resetting_this_nodes_counters() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");
        target
            .bump_capture_counters("cap-1", 12, 4)
            .expect("this node recorded something");

        let mut edited = make_capture_rule("cap-1", "route-fleet");
        edited.name = "renamed on the control plane".into();
        source
            .update_capture_rule(&edited)
            .expect("test setup: rule edited");
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 2, "h2")
            .expect("second apply");

        let stored = target
            .get_capture_rule("cap-1")
            .expect("capture rule read")
            .expect("the rule is still there");
        assert_eq!(stored.name, "renamed on the control plane");
        assert_eq!(stored.captures_emitted, 12, "the counters are this node's");
        assert_eq!(stored.captures_dropped, 4);
    }

    #[test]
    fn a_capture_rule_naming_a_route_absent_from_the_payload_is_dropped_not_fatal() {
        // Defence in depth behind the Story 10.0 cut: the foreign key
        // would refuse the insert and roll back the whole generation,
        // so one rule this node was never meant to run would stop it
        // applying any configuration at all.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let mut config = prepared(&source).expect("prepare");
        config
            .capture_rules
            .push(CanonicalCaptureRule::from(&make_capture_rule(
                "cap-ghost",
                "route-nobody-here-serves",
            )));
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("the apply survives the stray rule");

        assert_eq!(outcome.capture_rules, 1);
        assert_eq!(outcome.capture_rules_dropped, 1);
        assert!(target
            .get_capture_rule("cap-ghost")
            .expect("capture rule read")
            .is_none());
        assert!(target
            .get_capture_rule("cap-1")
            .expect("capture rule read")
            .is_some());
    }

    // -----------------------------------------------------------------
    // Story 10.4: the environment row and the managed_by mark
    // -----------------------------------------------------------------

    #[test]
    fn an_automation_environment_in_the_blob_lands_on_the_follower() {
        // Applied AFTER routes: the row cascades from its route, so it
        // cannot exist before the route does.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let config = prepared(&source).expect("prepare");
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("apply");

        assert_eq!(outcome.automation_environments, 1);
        assert_eq!(outcome.automation_environments_dropped, 0);
        let stored = target
            .get_automation_environment("env-1")
            .expect("environment read")
            .expect("the environment landed");
        assert_eq!(stored, make_environment("env-1", "route-fleet"));
    }

    #[test]
    fn a_managed_by_mark_lands_on_the_follower_byte_for_byte() {
        // The follower's own dashboard must show the badge and refuse
        // the in-place edit, so the mark has to arrive intact on both
        // the route and the backend.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");

        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("apply");

        let route = target
            .get_route("route-fleet")
            .expect("route read")
            .expect("the route landed");
        assert_eq!(route.managed_by, automation_mark("env-1"));
        let backend = target
            .get_backend("backend-1")
            .expect("backend read")
            .expect("the backend landed");
        assert_eq!(backend.managed_by, automation_mark("env-1"));
        let unmarked = target
            .get_route("route-edge")
            .expect("route read")
            .expect("the route landed");
        assert_eq!(
            unmarked.managed_by, None,
            "an operator route stays unmarked"
        );
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash"),
            "the marks re-encode to the control plane's bytes"
        );
    }

    #[test]
    fn an_environment_that_disappears_from_the_blob_is_deleted() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");

        source
            .delete_automation_environment("env-1")
            .expect("test setup: environment removed on the control plane");
        let outcome = target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 2, "h2")
            .expect("second apply");

        assert_eq!(outcome.automation_environments, 0);
        assert!(target
            .list_automation_environments()
            .expect("environments")
            .is_empty());
    }

    #[test]
    fn an_environment_naming_a_route_absent_from_the_payload_is_dropped_not_fatal() {
        // Same defence as the capture rule: the foreign key would refuse
        // the insert and roll back the whole generation over one row
        // this node was never meant to hold.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);

        let mut config = prepared(&source).expect("prepare");
        config
            .automation_environments
            .push(make_environment("env-ghost", "route-nobody-here-serves"));
        let outcome = target
            .apply_replica(&config, "edge-1", 1, "h1")
            .expect("the apply survives the stray environment");

        assert_eq!(outcome.automation_environments, 1);
        assert_eq!(outcome.automation_environments_dropped, 1);
        assert!(target
            .get_automation_environment("env-ghost")
            .expect("environment read")
            .is_none());
        assert!(target
            .get_automation_environment("env-1")
            .expect("environment read")
            .is_some());
    }

    // -----------------------------------------------------------------
    // Story 12.1: streams, cut per recipient and applied
    // -----------------------------------------------------------------

    /// The e2e `cluster` profile's shape: a control plane holding a TCP
    /// stream targeted at `edge-1` and a UDP stream with an empty
    /// selector, each reaching a backend no route references.
    fn seed_stream_fleet(control_plane: &ConfigStore, targeted_enabled: bool) {
        control_plane
            .create_backend(&sample_stream_backend("b-pg", "192.0.2.10:5432"))
            .expect("test setup: backend");
        control_plane
            .create_backend(&sample_stream_backend("b-dns", "192.0.2.20:53"))
            .expect("test setup: backend");
        let mut targeted = sample_stream("s-targeted", "postgres", StreamProtocol::Tcp, 5432);
        targeted.node_selector = vec!["edge-1".to_string()];
        targeted.enabled = targeted_enabled;
        let fleet_wide = sample_stream("s-fleet", "dns", StreamProtocol::Udp, 53);
        for (stream, backend) in [(&targeted, "b-pg"), (&fleet_wide, "b-dns")] {
            control_plane
                .create_stream(stream)
                .expect("test setup: stream");
            control_plane
                .set_stream_backends(&stream.id, &[backend.to_string()])
                .expect("test setup: stream link");
        }
    }

    /// The two followers' roster rows, as the control plane resolves
    /// selectors against them.
    const FOLLOWERS: [(&str, &str); 2] = [("edge-1", "id-1"), ("edge-2", "id-2")];

    /// Cut the control plane's configuration for each follower, send it
    /// through prepare and apply on that follower's own store, and
    /// return each follower's store with the payload it received.
    fn replicate_to_followers(
        control_plane: &ConfigStore,
    ) -> Vec<(&'static str, ConfigStore, CanonicalConfig)> {
        let fleet = crate::canonical::canonical_config(control_plane).expect("canonical config");
        let resolution = crate::canonical::SelectorResolution::from_rows(
            FOLLOWERS.map(|(name, id)| (name.to_string(), id.to_string())),
        );
        FOLLOWERS
            .iter()
            .map(|(name, id)| {
                let cut = crate::canonical::restrict_for_recipient(&fleet, id, &resolution);
                let blob = crate::canonical::encode_canonical(&cut).expect("encode");
                let hash = sha256_hex(&blob);
                let config = ConfigStore::prepare_replica(&blob, &hash).expect("prepare");
                let follower = ConfigStore::open_in_memory().expect("follower opens");
                follower
                    .apply_replica(&config, name, 1, &hash)
                    .expect("apply");
                assert_eq!(
                    canonical_bytes(&follower).expect("re-encode"),
                    blob,
                    "{name} re-encodes the payload it was sent"
                );
                (*name, follower, cut)
            })
            .collect()
    }

    /// The names of the streams `store` holds that a node in `role`
    /// binds, sorted.
    fn bound(store: &ConfigStore, role: NodeRole<'_>) -> Vec<String> {
        store
            .list_streams()
            .expect("streams")
            .iter()
            .filter(|s| binds_here(s, role))
            .map(|s| s.name.clone())
            .collect()
    }

    #[test]
    fn iv1_a_targeted_stream_reaches_and_binds_on_its_follower_only() {
        let control_plane = ConfigStore::open_in_memory().expect("control plane opens");
        seed_stream_fleet(&control_plane, true);
        let followers = replicate_to_followers(&control_plane);

        let (_, edge_1, edge_1_payload) = &followers[0];
        let (_, edge_2, edge_2_payload) = &followers[1];
        let ids = |cut: &CanonicalConfig| -> Vec<String> {
            let mut ids: Vec<String> = cut.streams.iter().map(|s| s.id.clone()).collect();
            ids.sort();
            ids
        };
        assert_eq!(ids(edge_1_payload), vec![sid("s-fleet"), sid("s-targeted")]);
        assert_eq!(ids(edge_2_payload), vec![sid("s-fleet")]);
        assert!(
            !edge_2_payload.backends.iter().any(|b| b.id == "b-pg"),
            "edge-2 never receives the targeted stream's upstream"
        );
        assert!(
            !edge_2_payload
                .stream_backends
                .iter()
                .any(|l| l.stream_id == sid("s-targeted")),
            "nor its link"
        );
        // A follower serving only streams still receives their backends,
        // and keeps them after the apply.
        assert!(edge_1.get_backend("b-pg").expect("read").is_some());
        assert_eq!(
            edge_1
                .list_backends_for_stream(&sid("s-targeted"))
                .expect("links"),
            vec!["b-pg"]
        );

        // Where each node binds, through the one predicate 12.2 binds by.
        assert_eq!(
            bound(&control_plane, NodeRole::ControlPlane),
            vec!["dns"],
            "the control plane holds the targeted stream to replicate it and does not bind it"
        );
        assert_eq!(
            bound(
                edge_1,
                NodeRole::Follower {
                    node_name: "edge-1"
                }
            ),
            vec!["dns", "postgres"]
        );
        assert_eq!(
            bound(
                edge_2,
                NodeRole::Follower {
                    node_name: "edge-2"
                }
            ),
            vec!["dns"]
        );
        assert!(
            edge_2
                .get_stream(&sid("s-targeted"))
                .expect("read")
                .is_none(),
            "edge-2 does not hold it either"
        );
    }

    #[test]
    fn a_disabled_stream_is_cut_and_applied_like_an_enabled_one() {
        let enabled_plane = ConfigStore::open_in_memory().expect("control plane opens");
        seed_stream_fleet(&enabled_plane, true);
        let disabled_plane = ConfigStore::open_in_memory().expect("control plane opens");
        seed_stream_fleet(&disabled_plane, false);

        let enabled = replicate_to_followers(&enabled_plane);
        let disabled = replicate_to_followers(&disabled_plane);
        for ((name, _, on), (_, follower, off)) in enabled.iter().zip(&disabled) {
            let shape = |cut: &CanonicalConfig| {
                let mut streams = cut.streams.clone();
                for stream in &mut streams {
                    stream.enabled = true;
                }
                // The canonical sort key includes `enabled`, so the
                // flag may reorder the list; the set is what must match.
                streams.sort_by(|a, b| a.id.cmp(&b.id));
                let backend_ids: Vec<String> = cut.backends.iter().map(|b| b.id.clone()).collect();
                (streams, cut.stream_backends.clone(), backend_ids)
            };
            assert_eq!(shape(on), shape(off), "{name}: only the flag differs");
            assert_eq!(
                follower.list_streams().expect("streams").len(),
                off.streams.len(),
                "{name}: a disabled stream is stored like an enabled one"
            );
        }
        let (_, edge_1, _) = &disabled[0];
        let held = edge_1
            .get_stream(&sid("s-targeted"))
            .expect("read")
            .expect("edge-1 holds the disabled stream");
        assert!(!held.enabled);
        assert_eq!(
            bound(
                edge_1,
                NodeRole::Follower {
                    node_name: "edge-1"
                }
            ),
            vec!["dns"],
            "and binds it nowhere"
        );
    }

    /// Prepare `blob` after `edit`, expecting a refusal; returns its
    /// message.
    fn refusal_after(blob: &[u8], edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut root: serde_json::Value = serde_json::from_slice(blob).expect("json");
        edit(&mut root);
        let edited = serde_json::to_vec(&root).expect("re-encode");
        match ConfigStore::prepare_replica(&edited, &sha256_hex(&edited)) {
            Err(ReplicaError::Refused(message)) => message,
            Err(ReplicaError::Store(e)) => panic!("a refusal on the blob's merits, not {e}"),
            Ok(_) => panic!("the edited blob was accepted"),
        }
    }

    #[test]
    fn a_blob_breaking_a_stream_rule_is_refused_naming_the_stream_and_the_store_is_untouched() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        source
            .create_backend(&sample_stream_backend("b-dns", "192.0.2.20:53"))
            .expect("test setup: backend");
        source
            .create_stream(&sample_stream("s-dns", "dns", StreamProtocol::Udp, 53))
            .expect("test setup: stream");
        source
            .set_stream_backends(&sid("s-dns"), &["b-dns".to_string()])
            .expect("test setup: link");
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");
        let baseline = canonical_hash(&target).expect("baseline hash");
        let blob = canonical_bytes(&source).expect("encode");
        let index = |root: &serde_json::Value| -> usize {
            root["streams"]
                .as_array()
                .expect("streams array")
                .iter()
                .position(|s| s["id"] == sid("s-dns").as_str())
                .expect("the UDP stream is in the blob")
        };

        // A backend of the UDP stream also linked to a route.
        let message = refusal_after(&blob, |root| {
            root["route_backends"]
                .as_array_mut()
                .expect("links array")
                .push(serde_json::json!({"route_id": "route-fleet", "backend_id": "b-dns"}));
        });
        assert!(
            message.contains(&format!("stream {}", sid("s-dns"))),
            "{message}"
        );

        // A stream whose selector breaks the route rule.
        let message = refusal_after(&blob, |root| {
            let i = index(root);
            root["streams"][i]["node_selector"] = serde_json::json!(["Not A Node Name"]);
        });
        assert!(
            message.contains(&format!("stream {}", sid("s-dns"))),
            "{message}"
        );

        // A range one port wider than the cap.
        let message = refusal_after(&blob, |root| {
            let i = index(root);
            root["streams"][i]["port_last"] =
                serde_json::json!(53 + u32::from(crate::models::STREAM_PORT_RANGE_MAX));
        });
        assert!(
            message.contains(&format!("stream {}", sid("s-dns"))),
            "{message}"
        );

        // An id that is not a UUID in its canonical form, its link
        // following it so only the id rule is broken.
        let message = refusal_after(&blob, |root| {
            let i = index(root);
            let upper = sid("s-dns").to_uppercase();
            root["streams"][i]["id"] = serde_json::json!(upper);
            for link in root["stream_backends"].as_array_mut().expect("links") {
                if link["stream_id"] == sid("s-dns").as_str() {
                    link["stream_id"] = serde_json::json!(upper);
                }
            }
        });
        assert!(message.contains("stream id"), "{message}");

        assert_eq!(
            canonical_hash(&target).expect("post-refusal hash"),
            baseline,
            "prepare must not touch the store"
        );
    }

    #[test]
    fn a_generation_moving_a_backend_from_a_udp_stream_to_a_route_applies() {
        // The transient violation the checked writers would refuse: the
        // new links are written while the old stream link is still on
        // this node. The snapshot itself is sound.
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        seed_source(&source);
        source
            .create_backend(&sample_stream_backend("b-moving", "192.0.2.50:53"))
            .expect("test setup: backend");
        source
            .create_stream(&sample_stream("s-dns", "dns", StreamProtocol::Udp, 53))
            .expect("test setup: stream");
        source
            .set_stream_backends(&sid("s-dns"), &["b-moving".to_string()])
            .expect("test setup: link");
        target
            .create_certificate(&make_certificate("cert-1", CERT_KEY))
            .expect("target holds the key");
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");

        source
            .set_stream_backends(&sid("s-dns"), &[])
            .expect("test setup: unlinked");
        source
            .link_route_backend("route-fleet", "b-moving")
            .expect("test setup: now a route backend");
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 2, "h2")
            .expect("the second generation applies");
        assert_eq!(
            canonical_hash(&source).expect("source hash"),
            canonical_hash(&target).expect("target hash")
        );
    }

    #[test]
    fn a_generation_swapping_two_stream_names_applies() {
        let source = ConfigStore::open_in_memory().expect("source opens");
        let target = ConfigStore::open_in_memory().expect("target opens");
        let mut alpha = sample_stream("s-1", "alpha", StreamProtocol::Tcp, 7001);
        let mut beta = sample_stream("s-2", "beta", StreamProtocol::Tcp, 7002);
        source.create_stream(&alpha).expect("test setup: stream");
        source.create_stream(&beta).expect("test setup: stream");
        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 1, "h1")
            .expect("first apply");

        alpha.name = "swap-tmp".to_string();
        source.update_stream(&alpha).expect("test setup: rename");
        beta.name = "alpha".to_string();
        source.update_stream(&beta).expect("test setup: rename");
        alpha.name = "beta".to_string();
        source.update_stream(&alpha).expect("test setup: rename");

        target
            .apply_replica(&prepared(&source).expect("prepare"), "edge-1", 2, "h2")
            .expect("a swap of two UNIQUE names applies");
        assert_eq!(
            target
                .get_stream(&sid("s-1"))
                .expect("read")
                .expect("held")
                .name,
            "beta"
        );
        assert_eq!(
            target
                .get_stream(&sid("s-2"))
                .expect("read")
                .expect("held")
                .name,
            "alpha"
        );
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
