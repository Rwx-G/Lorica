//! Traffic-capture rule persistence on `ConfigStore` (Story 10.1).
//!
//! The nested blocks (`match`, `emit`, `capture`, `limits`, `output`,
//! `redact`) live in JSON columns, the way `routes` already stores
//! `path_rules`, `header_rules` and `mtls`. Flat columns would mean a
//! migration per dial on a model whose whole purpose is to grow dials,
//! and nothing queries inside these blocks: every read is by rule id or
//! by route id, both of which are real columns.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{json_column, parse_datetime};
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::CaptureRule;

/// The column list every capture-rule read binds, in the order
/// [`row_to_capture_rule`] expects.
const CAPTURE_COLUMNS: &str = "id, name, route_id, enabled, match_json, emit_json, \
     capture_json, limits_json, output_json, redact_json, created_by, created_at, \
     expires_at, captures_emitted, captures_dropped";

/// Decode one `capture_rules` row.
///
/// A malformed JSON block is an error rather than a silent default: the
/// blocks carry the redaction list and the size ceilings, so degrading
/// to a default would widen what a rule records on a node whose row got
/// corrupted. Same stance as [`super::row_helpers::parse_optional_json_field`].
fn row_to_capture_rule(row: &rusqlite::Row<'_>) -> Result<CaptureRule> {
    let created_at: String = row.get(11)?;
    let expires_at: String = row.get(12)?;
    Ok(CaptureRule {
        id: row.get(0)?,
        name: row.get(1)?,
        route_id: row.get(2)?,
        enabled: row.get(3)?,
        match_: json_column(row, 4, "capture", "match")?,
        emit: json_column(row, 5, "capture", "emit")?,
        capture: json_column(row, 6, "capture", "capture")?,
        limits: json_column(row, 7, "capture", "limits")?,
        output: json_column(row, 8, "capture", "output")?,
        redact: json_column(row, 9, "capture", "redact")?,
        created_by: row.get(10)?,
        created_at: parse_datetime(&created_at)?,
        expires_at: parse_datetime(&expires_at)?,
        captures_emitted: row.get(13)?,
        captures_dropped: row.get(14)?,
    })
}

impl ConfigStore {
    /// Every capture rule, ordered by id so the listing is stable.
    pub fn list_capture_rules(&self) -> Result<Vec<CaptureRule>> {
        let sql = format!("SELECT {CAPTURE_COLUMNS} FROM capture_rules ORDER BY id ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_capture_rule(row)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// Every ARMED capture rule whose `expires_at` is at or before
    /// `instant`: exactly the set the self-disable sweep disarms.
    ///
    /// The sweep runs every five seconds on every standalone node and
    /// control plane, and on almost every tick the answer is "none".
    /// Reading the whole table and filtering in Rust made that tick cost
    /// one full scan plus a JSON decode per rule; `idx_capture_rules_expires_at`
    /// exists for this query and was going unused.
    pub fn list_capture_rules_expiring_before(
        &self,
        instant: DateTime<Utc>,
    ) -> Result<Vec<CaptureRule>> {
        let sql = format!(
            "SELECT {CAPTURE_COLUMNS} FROM capture_rules \
             WHERE enabled = 1 AND expires_at <= ?1 ORDER BY id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![instant.to_rfc3339()], |row| {
            Ok(row_to_capture_rule(row))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// One capture rule by id, or `None` when no such row exists.
    pub fn get_capture_rule(&self, id: &str) -> Result<Option<CaptureRule>> {
        let sql = format!("SELECT {CAPTURE_COLUMNS} FROM capture_rules WHERE id = ?1");
        let found = self
            .conn
            .query_row(&sql, params![id], |row| Ok(row_to_capture_rule(row)))
            .optional()?;
        match found {
            Some(rule) => Ok(Some(rule?)),
            None => Ok(None),
        }
    }

    /// Insert a capture rule. The counters are written from the model,
    /// which is zero on a fresh rule and the applied value on a restore.
    pub fn create_capture_rule(&self, rule: &CaptureRule) -> Result<()> {
        self.conn.execute(
            "INSERT INTO capture_rules (id, name, route_id, enabled, match_json, emit_json,
             capture_json, limits_json, output_json, redact_json, created_by, created_at,
             expires_at, captures_emitted, captures_dropped)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                rule.id,
                rule.name,
                rule.route_id,
                rule.enabled,
                serialize_field("capture match", &rule.match_)?,
                serialize_field("capture emit", &rule.emit)?,
                serialize_field("capture scope", &rule.capture)?,
                serialize_field("capture limits", &rule.limits)?,
                serialize_field("capture output", &rule.output)?,
                serialize_field("capture redact", &rule.redact)?,
                rule.created_by,
                rule.created_at.to_rfc3339(),
                rule.expires_at.to_rfc3339(),
                rule.captures_emitted,
                rule.captures_dropped,
            ],
        )?;
        Ok(())
    }

    /// Update every configured column of a capture rule.
    ///
    /// The two counters are deliberately NOT written here. They are
    /// per-node, per-process facts owned by
    /// [`ConfigStore::bump_capture_counters`]; an edit to the rule's
    /// name or its ceilings must not reset what this node has already
    /// recorded.
    pub fn update_capture_rule(&self, rule: &CaptureRule) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE capture_rules SET name = ?1, route_id = ?2, enabled = ?3, match_json = ?4,
             emit_json = ?5, capture_json = ?6, limits_json = ?7, output_json = ?8,
             redact_json = ?9, created_by = ?10, created_at = ?11, expires_at = ?12
             WHERE id = ?13",
            params![
                rule.name,
                rule.route_id,
                rule.enabled,
                serialize_field("capture match", &rule.match_)?,
                serialize_field("capture emit", &rule.emit)?,
                serialize_field("capture scope", &rule.capture)?,
                serialize_field("capture limits", &rule.limits)?,
                serialize_field("capture output", &rule.output)?,
                serialize_field("capture redact", &rule.redact)?,
                rule.created_by,
                rule.created_at.to_rfc3339(),
                rule.expires_at.to_rfc3339(),
                rule.id,
            ],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("capture rule {}", rule.id)));
        }
        Ok(())
    }

    /// Delete one capture rule by id.
    pub fn delete_capture_rule(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM capture_rules WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("capture rule {id}")));
        }
        Ok(())
    }

    /// Toggle one capture rule without rewriting the rest of the row.
    pub fn set_capture_rule_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE capture_rules SET enabled = ?1 WHERE id = ?2",
            params![enabled, id],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("capture rule {id}")));
        }
        Ok(())
    }

    /// Add to this node's emitted / dropped counters for one rule.
    ///
    /// A relative bump rather than an absolute write, because the proxy
    /// reports what it did since the last flush and two writers on the
    /// same rule must not overwrite each other. A rule that is gone is
    /// not an error: the counter flush races a delete by construction,
    /// and failing it would turn a routine race into a logged fault.
    pub fn bump_capture_counters(
        &self,
        id: &str,
        emitted_delta: i64,
        dropped_delta: i64,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE capture_rules
             SET captures_emitted = captures_emitted + ?1,
                 captures_dropped = captures_dropped + ?2
             WHERE id = ?3",
            params![emitted_delta, dropped_delta, id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use crate::models::{
        CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
        CaptureScope, LoadBalancing, Route, StatusMatch, WafMode,
    };
    use crate::store::ConfigStore;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    /// A minimal route to hang a capture rule on. The full literal is
    /// what the model requires; `store/replica.rs` keeps its own for the
    /// same reason.
    fn make_route(id: &str) -> Route {
        let now = fixed_now();
        Route {
            id: id.to_string(),
            hostname: format!("{id}.example"),
            path_prefix: "/".into(),
            certificate_id: None,
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
            node_selector: Vec::new(),
            ai_bot_policy: None,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            managed_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn seed_route(store: &ConfigStore, id: &str) {
        store
            .create_route(&make_route(id))
            .expect("test setup: route insert");
    }

    fn rule(id: &str, route_id: &str) -> CaptureRule {
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
                status: vec![StatusMatch::ServerError, StatusMatch::Exact(404)],
                min_latency_ms: Some(250),
                upstream_error: true,
            },
            capture: CaptureScope::default(),
            limits: CaptureLimits::default(),
            output: CaptureOutput {
                dir: Some("/var/lib/lorica/captures".to_string()),
                max_dir_bytes: Some(1_048_576),
            },
            redact: CaptureRedaction {
                headers: vec!["X-Api-Key".to_string()],
                query: vec!["token".to_string()],
            },
            created_by: "admin".to_string(),
            created_at: fixed_now(),
            expires_at: fixed_now(),
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    #[test]
    fn a_capture_rule_round_trips_through_the_store() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        let written = rule("cap-1", "route-1");
        store
            .create_capture_rule(&written)
            .expect("test setup: rule insert");

        let read = store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .expect("the rule exists");
        assert_eq!(read, written);
        assert_eq!(
            store
                .list_capture_rules()
                .expect("test setup: listing")
                .len(),
            1
        );
    }

    #[test]
    fn the_expiry_query_returns_only_the_armed_rules_already_past_their_expiry() {
        use chrono::Duration;

        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");

        let mut due = rule("cap-due", "route-1");
        due.expires_at = fixed_now() - Duration::minutes(1);
        let mut exactly_now = rule("cap-now", "route-1");
        exactly_now.expires_at = fixed_now();
        let mut later = rule("cap-later", "route-1");
        later.expires_at = fixed_now() + Duration::hours(1);
        let mut already_off = rule("cap-off", "route-1");
        already_off.expires_at = fixed_now() - Duration::hours(1);
        already_off.enabled = false;
        for rule in [&due, &exactly_now, &later, &already_off] {
            store
                .create_capture_rule(rule)
                .expect("test setup: rule insert");
        }

        let swept: Vec<String> = store
            .list_capture_rules_expiring_before(fixed_now())
            .expect("the expiry query runs")
            .into_iter()
            .map(|rule| rule.id)
            .collect();
        assert_eq!(
            swept,
            vec!["cap-due".to_string(), "cap-now".to_string()],
            "the boundary is inclusive, a rule already disarmed is not swept again"
        );
    }

    #[test]
    fn an_update_rewrites_the_nested_blocks() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");

        let mut edited = rule("cap-1", "route-1");
        edited.name = "renamed".to_string();
        edited.limits.max_captures = 42;
        edited.redact.headers = vec!["X-Other".to_string()];
        store
            .update_capture_rule(&edited)
            .expect("test setup: rule update");

        let read = store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .expect("the rule exists");
        assert_eq!(read.name, "renamed");
        assert_eq!(read.limits.max_captures, 42);
        assert_eq!(read.redact.headers, vec!["X-Other".to_string()]);
    }

    #[test]
    fn an_update_leaves_this_nodes_counters_alone() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");
        store
            .bump_capture_counters("cap-1", 7, 3)
            .expect("test setup: counter bump");

        let mut edited = rule("cap-1", "route-1");
        edited.name = "renamed".to_string();
        store
            .update_capture_rule(&edited)
            .expect("test setup: rule update");

        let read = store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .expect("the rule exists");
        assert_eq!(read.captures_emitted, 7);
        assert_eq!(read.captures_dropped, 3);
    }

    #[test]
    fn counters_accumulate_across_bumps() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");
        store
            .bump_capture_counters("cap-1", 2, 1)
            .expect("test setup: counter bump");
        store
            .bump_capture_counters("cap-1", 5, 0)
            .expect("test setup: counter bump");

        let read = store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .expect("the rule exists");
        assert_eq!(read.captures_emitted, 7);
        assert_eq!(read.captures_dropped, 1);
    }

    #[test]
    fn toggling_a_rule_touches_nothing_else() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");
        store
            .set_capture_rule_enabled("cap-1", false)
            .expect("test setup: toggle");

        let read = store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .expect("the rule exists");
        assert!(!read.enabled);
        assert_eq!(read.name, "rule cap-1");
    }

    #[test]
    fn deleting_a_rule_removes_it() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");
        store
            .delete_capture_rule("cap-1")
            .expect("test setup: rule delete");
        assert!(store
            .get_capture_rule("cap-1")
            .expect("test setup: rule read")
            .is_none());
    }

    #[test]
    fn an_unknown_id_is_not_found_rather_than_silently_ignored() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store.delete_capture_rule("nope").is_err());
        assert!(store.set_capture_rule_enabled("nope", true).is_err());
    }

    #[test]
    fn deleting_a_route_cascades_its_capture_rules_away() {
        // A capture rule for a deleted route is a recorder pointed at
        // nothing, so the foreign key takes it with the route.
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        seed_route(&store, "route-2");
        store
            .create_capture_rule(&rule("cap-1", "route-1"))
            .expect("test setup: rule insert");
        store
            .create_capture_rule(&rule("cap-2", "route-2"))
            .expect("test setup: rule insert");

        store
            .delete_route("route-1")
            .expect("test setup: route delete");

        let remaining = store.list_capture_rules().expect("test setup: listing");
        let ids: Vec<&str> = remaining.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["cap-2"]);
    }

    #[test]
    fn a_rule_naming_no_route_is_refused_by_the_foreign_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store.create_capture_rule(&rule("cap-1", "ghost")).is_err());
    }
}
