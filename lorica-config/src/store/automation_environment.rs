//! Automation environment persistence on `ConfigStore` (Story 10.4).
//!
//! The owner, the certificate mode and the labels live in JSON columns,
//! the way `capture_rules` stores its blocks: nothing queries inside
//! them. The two filtered reads are by name (the primary key) and by
//! expiry (the reaper and the `expiring_before` list filter), and
//! `expires_at` is a real column with an index for that reason.
//!
//! Timestamps are compared as text. Every writer in this crate emits
//! `DateTime::to_rfc3339()` on a UTC value, which is a fixed-layout
//! string with a `+00:00` suffix, so lexical order is chronological
//! order, including between a value with fractional seconds and one
//! without (`+` sorts before `.`).

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{json_column, parse_datetime};
use super::{serialize_field, serialize_optional_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::AutomationEnvironment;

/// The column list every environment read binds, in the order
/// [`row_to_environment`] expects.
const ENVIRONMENT_COLUMNS: &str = "name, route_id, owner_json, certificate_mode_json, \
     labels_json, expires_at, created_at, updated_at, last_pipeline, pipeline_json";

/// Decode one `automation_environments` row.
///
/// A malformed JSON column is an error rather than a default: the owner
/// column is an authorization input, and a row whose owner silently
/// read as "nobody" or "anybody" would either strand a review app or
/// hand it to the wrong project.
fn row_to_environment(row: &rusqlite::Row<'_>) -> Result<AutomationEnvironment> {
    let expires_at: String = row.get(5)?;
    let created_at: String = row.get(6)?;
    let updated_at: String = row.get(7)?;
    let pipeline_json: Option<String> = row.get(9)?;
    let pipeline = pipeline_json
        .map(|raw| {
            serde_json::from_str(&raw).map_err(|e| {
                ConfigError::Corrupt(format!("invalid environment pipeline JSON: {e}"))
            })
        })
        .transpose()?;
    Ok(AutomationEnvironment {
        name: row.get(0)?,
        route_id: row.get(1)?,
        owner: json_column(row, 2, "environment", "owner")?,
        certificate_mode: json_column(row, 3, "environment", "certificate_mode")?,
        labels: json_column(row, 4, "environment", "labels")?,
        expires_at: parse_datetime(&expires_at)?,
        created_at: parse_datetime(&created_at)?,
        updated_at: parse_datetime(&updated_at)?,
        last_pipeline: row.get(8)?,
        pipeline,
    })
}

impl ConfigStore {
    /// Every environment, ordered by name so the listing is stable.
    pub fn list_automation_environments(&self) -> Result<Vec<AutomationEnvironment>> {
        let sql =
            format!("SELECT {ENVIRONMENT_COLUMNS} FROM automation_environments ORDER BY name ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_environment(row)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// One environment by name, or `None` when no such row exists.
    pub fn get_automation_environment(&self, name: &str) -> Result<Option<AutomationEnvironment>> {
        let sql =
            format!("SELECT {ENVIRONMENT_COLUMNS} FROM automation_environments WHERE name = ?1");
        let found = self
            .conn
            .query_row(&sql, params![name], |row| Ok(row_to_environment(row)))
            .optional()?;
        match found {
            Some(environment) => Ok(Some(environment?)),
            None => Ok(None),
        }
    }

    /// Insert or replace an environment by name.
    ///
    /// Every column is written from the model, `created_at` included.
    /// The replica apply restores the control plane's row through this
    /// same call, so the row must not keep a local value the blob does
    /// not carry, or the follower would never re-encode the control
    /// plane's bytes. A caller updating an existing environment carries
    /// the stored `created_at` forward; it already holds the row for
    /// the ownership check.
    ///
    /// # Errors
    ///
    /// Returns a database error when `route_id` names no route, or
    /// names a route another environment already owns.
    pub fn upsert_automation_environment(&self, environment: &AutomationEnvironment) -> Result<()> {
        self.conn.execute(
            "INSERT INTO automation_environments (name, route_id, owner_json,
             certificate_mode_json, labels_json, expires_at, created_at, updated_at,
             last_pipeline, pipeline_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(name) DO UPDATE SET
                 route_id = excluded.route_id,
                 owner_json = excluded.owner_json,
                 certificate_mode_json = excluded.certificate_mode_json,
                 labels_json = excluded.labels_json,
                 expires_at = excluded.expires_at,
                 created_at = excluded.created_at,
                 updated_at = excluded.updated_at,
                 last_pipeline = excluded.last_pipeline,
                 pipeline_json = excluded.pipeline_json",
            params![
                environment.name,
                environment.route_id,
                serialize_field("environment owner", &environment.owner)?,
                serialize_field(
                    "environment certificate_mode",
                    &environment.certificate_mode
                )?,
                serialize_field("environment labels", &environment.labels)?,
                environment.expires_at.to_rfc3339(),
                environment.created_at.to_rfc3339(),
                environment.updated_at.to_rfc3339(),
                environment.last_pipeline,
                serialize_optional_field("environment pipeline", environment.pipeline.as_ref())?,
            ],
        )?;
        Ok(())
    }

    /// Delete one environment by name.
    ///
    /// Only the environment row: the route it owns, and through the
    /// route's cascade everything attached to it, is the caller's
    /// transaction to remove. `NotFound` on an unknown name so the
    /// handler can tell "never existed" from "already gone".
    pub fn delete_automation_environment(&self, name: &str) -> Result<()> {
        let affected = self.conn.execute(
            "DELETE FROM automation_environments WHERE name = ?1",
            params![name],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("environment {name}")));
        }
        Ok(())
    }

    /// Environments whose `expires_at` is at or before `now`: what the
    /// reaper collects on a sweep.
    pub fn list_expired_automation_environments(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<AutomationEnvironment>> {
        self.environments_with_expiry("<=", now)
    }

    /// Environments whose `expires_at` is strictly before `instant`:
    /// the `expiring_before` filter of the listing endpoint.
    pub fn list_automation_environments_expiring_before(
        &self,
        instant: DateTime<Utc>,
    ) -> Result<Vec<AutomationEnvironment>> {
        self.environments_with_expiry("<", instant)
    }

    /// The two expiry reads share one query; `comparison` is a
    /// compile-time constant from this module, never caller-supplied.
    fn environments_with_expiry(
        &self,
        comparison: &'static str,
        bound: DateTime<Utc>,
    ) -> Result<Vec<AutomationEnvironment>> {
        let sql = format!(
            "SELECT {ENVIRONMENT_COLUMNS} FROM automation_environments \
             WHERE expires_at {comparison} ?1 ORDER BY expires_at ASC, name ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![bound.to_rfc3339()], |row| {
            Ok(row_to_environment(row))
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Duration, Utc};

    use crate::models::{
        AutomationEnvironment, CertificateMode, EnvironmentOwner, LoadBalancing, OwnerKind,
        PipelineIdentity, Route, WafMode,
    };
    use crate::store::ConfigStore;

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    /// A minimal route to hang an environment on. The full literal is
    /// what the model requires; `store/capture.rs` keeps its own for the
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

    fn environment(name: &str, route_id: &str) -> AutomationEnvironment {
        let mut labels = BTreeMap::new();
        labels.insert("team".to_string(), "acme".to_string());
        labels.insert("shared".to_string(), "true".to_string());
        AutomationEnvironment {
            name: name.to_string(),
            route_id: route_id.to_string(),
            owner: EnvironmentOwner {
                kind: OwnerKind::StaticToken,
                principal: "acme-ci".to_string(),
            },
            certificate_mode: CertificateMode::Explicit("cert-1".to_string()),
            labels,
            expires_at: fixed_now() + Duration::hours(1),
            created_at: fixed_now(),
            updated_at: fixed_now(),
            last_pipeline: Some("pipeline-1234".to_string()),
            pipeline: Some(PipelineIdentity {
                project_path: "acme/web".to_string(),
                git_ref: Some("main".to_string()),
                pipeline_id: Some("1234".to_string()),
                job_id: Some("5678".to_string()),
                user_login: Some("dev".to_string()),
            }),
        }
    }

    #[test]
    fn an_environment_round_trips_through_the_store() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        let written = environment("pr-42", "route-1");
        store
            .upsert_automation_environment(&written)
            .expect("test setup: environment insert");

        let read = store
            .get_automation_environment("pr-42")
            .expect("test setup: environment read")
            .expect("the environment exists");
        assert_eq!(read, written);
        assert_eq!(
            store
                .list_automation_environments()
                .expect("test setup: listing")
                .len(),
            1
        );
    }

    #[test]
    fn an_upsert_on_an_existing_name_replaces_every_column() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .upsert_automation_environment(&environment("pr-42", "route-1"))
            .expect("test setup: environment insert");

        let mut edited = environment("pr-42", "route-1");
        edited.certificate_mode = CertificateMode::Auto;
        edited.labels.clear();
        edited.expires_at = fixed_now() + Duration::hours(6);
        edited.updated_at = fixed_now() + Duration::minutes(1);
        edited.last_pipeline = None;
        edited.pipeline = None;
        store
            .upsert_automation_environment(&edited)
            .expect("test setup: environment update");

        let read = store
            .get_automation_environment("pr-42")
            .expect("test setup: environment read")
            .expect("the environment exists");
        assert_eq!(read, edited);
        assert_eq!(
            store
                .list_automation_environments()
                .expect("test setup: listing")
                .len(),
            1,
            "an upsert by name must not create a second row"
        );
    }

    #[test]
    fn deleting_an_environment_removes_only_its_row() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .upsert_automation_environment(&environment("pr-42", "route-1"))
            .expect("test setup: environment insert");

        store
            .delete_automation_environment("pr-42")
            .expect("test setup: environment delete");

        assert!(store
            .get_automation_environment("pr-42")
            .expect("test setup: environment read")
            .is_none());
        assert!(
            store.get_route("route-1").expect("route read").is_some(),
            "the route is the caller's transaction to remove"
        );
    }

    #[test]
    fn an_unknown_name_is_not_found_rather_than_silently_ignored() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store.delete_automation_environment("nope").is_err());
    }

    #[test]
    fn deleting_a_route_cascades_its_environment_away() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        seed_route(&store, "route-2");
        store
            .upsert_automation_environment(&environment("pr-1", "route-1"))
            .expect("test setup: environment insert");
        store
            .upsert_automation_environment(&environment("pr-2", "route-2"))
            .expect("test setup: environment insert");

        store
            .delete_route("route-1")
            .expect("test setup: route delete");

        let names: Vec<String> = store
            .list_automation_environments()
            .expect("test setup: listing")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["pr-2".to_string()]);
    }

    #[test]
    fn an_environment_naming_no_route_is_refused_by_the_foreign_key() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        assert!(store
            .upsert_automation_environment(&environment("pr-42", "ghost"))
            .is_err());
    }

    #[test]
    fn one_route_is_owned_by_at_most_one_environment() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        store
            .upsert_automation_environment(&environment("pr-1", "route-1"))
            .expect("test setup: environment insert");
        assert!(
            store
                .upsert_automation_environment(&environment("pr-2", "route-1"))
                .is_err(),
            "two environments on one route would each believe the other's PUT was theirs"
        );
    }

    #[test]
    fn a_failed_transaction_leaves_nothing_behind_and_a_successful_one_commits() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");

        let aborted: Result<(), crate::error::ConfigError> = store.in_transaction(|store| {
            store.upsert_automation_environment(&environment("pr-42", "route-1"))?;
            store.delete_route("route-1")?;
            Err(crate::error::ConfigError::Validation(
                "abort after two writes".to_string(),
            ))
        });
        assert!(aborted.is_err());
        assert!(
            store
                .get_automation_environment("pr-42")
                .expect("environment read")
                .is_none(),
            "the environment insert must roll back"
        );
        assert!(
            store.get_route("route-1").expect("route read").is_some(),
            "the route delete must roll back"
        );

        let committed: Result<(), crate::error::ConfigError> = store.in_transaction(|store| {
            store.upsert_automation_environment(&environment("pr-42", "route-1"))
        });
        assert!(committed.is_ok());
        assert!(store
            .get_automation_environment("pr-42")
            .expect("environment read")
            .is_some());
    }

    #[test]
    fn expiry_reads_honour_their_boundaries() {
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        for id in ["route-1", "route-2", "route-3"] {
            seed_route(&store, id);
        }
        let now = fixed_now();
        let mut past = environment("pr-past", "route-1");
        past.expires_at = now - Duration::minutes(1);
        let mut exact = environment("pr-exact", "route-2");
        exact.expires_at = now;
        let mut future = environment("pr-future", "route-3");
        future.expires_at = now + Duration::minutes(1);
        for environment in [&past, &exact, &future] {
            store
                .upsert_automation_environment(environment)
                .expect("test setup: environment insert");
        }

        let expired: Vec<String> = store
            .list_expired_automation_environments(now)
            .expect("expired read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            expired,
            vec!["pr-past".to_string(), "pr-exact".to_string()],
            "expired at `now` includes a row expiring exactly now"
        );

        let before: Vec<String> = store
            .list_automation_environments_expiring_before(now)
            .expect("expiring-before read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(
            before,
            vec!["pr-past".to_string()],
            "expiring before `now` is strict"
        );
    }

    #[test]
    fn fractional_seconds_do_not_break_the_expiry_order() {
        // `to_rfc3339` prints fractional seconds only when they are
        // non-zero, so a row with them and a row without must still
        // sort chronologically as text.
        let store = ConfigStore::open_in_memory().expect("test setup: store opens");
        seed_route(&store, "route-1");
        seed_route(&store, "route-2");
        let base = fixed_now();
        let mut whole = environment("pr-whole", "route-1");
        whole.expires_at = base + Duration::seconds(1);
        let mut fractional = environment("pr-fractional", "route-2");
        fractional.expires_at = base + Duration::milliseconds(500);
        store
            .upsert_automation_environment(&whole)
            .expect("test setup: environment insert");
        store
            .upsert_automation_environment(&fractional)
            .expect("test setup: environment insert");

        let expired: Vec<String> = store
            .list_expired_automation_environments(base + Duration::milliseconds(750))
            .expect("expired read")
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(expired, vec!["pr-fractional".to_string()]);
    }
}
