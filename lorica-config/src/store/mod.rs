//! SQLite-backed configuration store.
//!
//! **Validation split:** type-shape validation (enum parsing, range
//! checks, regex compilability, `host:port` format) happens at the API
//! boundary in `lorica-api::routes`. This module owns *business-rule*
//! validation: hostname uniqueness across routes, invariants that
//! need a DB read to evaluate, and any rule that must stay consistent
//! with the existing persisted state. JSON (de)serialization of the
//! column-typed fields lives here too (see `serialize_field` below).
//!
//! The store is split into per-entity submodules (routes, backends,
//! certs, sessions, sla, ...). Each submodule defines additional
//! methods on `ConfigStore` via `impl ConfigStore { ... }`. This file
//! hosts the struct, the lifecycle entry points (`open`,
//! `open_in_memory`), the migration runner and the encryption helpers
//! shared by every submodule.

use std::collections::HashSet;
use std::path::Path;

use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::EncryptionKey;
use crate::error::{ConfigError, Result};

mod acme_challenges;
mod ai_crawlers;
mod backends;
pub mod bot_stash;
mod cert_export_acls;
mod certs;
mod cluster_ca;
mod cluster_identity;
mod cluster_nodes;
mod cluster_replica;
mod cluster_tokens;
pub use cluster_nodes::LiveNodeFacts;
mod dns_providers;
mod loadtest;
mod notifications;
mod preferences;
mod probes;
mod replica;
pub use replica::{ReplicaError, ReplicaOutcome};
mod routes;
mod row_helpers;
mod sessions;
mod settings;
mod sla;
mod users;
mod waf;

/// Serialize a route/config field to JSON, mapping any error to a
/// `ConfigError::Validation` that names the offending field. Used by
/// `create_route` / `update_route` to dedupe ~60 lines of repeated
/// `map_err` closures and to give operators a clear "which field"
/// rather than a generic serde error.
pub(super) fn serialize_field<T: serde::Serialize + ?Sized>(name: &str, val: &T) -> Result<String> {
    serde_json::to_string(val).map_err(|e| ConfigError::Validation(format!("invalid {name}: {e}")))
}

/// Optional variant: `None` passes through unchanged, `Some(_)` is
/// serialized via `serialize_field`.
pub(super) fn serialize_optional_field<T: serde::Serialize>(
    name: &str,
    val: Option<&T>,
) -> Result<Option<String>> {
    match val {
        Some(v) => serialize_field(name, v).map(Some),
        None => Ok(None),
    }
}

const MIGRATION_V1: &str = include_str!("../migrations/001_initial.sql");
const MIGRATION_V2: &str = include_str!("../migrations/002_add_health_check_path.sql");
const MIGRATION_V3: &str = include_str!("../migrations/003_sla_metrics.sql");
const MIGRATION_V4: &str = include_str!("../migrations/004_probe_configs.sql");
const MIGRATION_V5: &str = include_str!("../migrations/005_load_tests.sql");
const MIGRATION_V6: &str = include_str!("../migrations/006_sla_bucket_config_snapshot.sql");
const MIGRATION_V7: &str = include_str!("../migrations/007_route_config.sql");
const MIGRATION_V8: &str = include_str!("../migrations/008_backend_name_group.sql");
const MIGRATION_V9: &str = include_str!("../migrations/009_cache_and_protection.sql");
const MIGRATION_V10: &str = include_str!("../migrations/010_sla_default_range.sql");
const MIGRATION_V11: &str = include_str!("../migrations/011_backend_h2_upstream.sql");
const MIGRATION_V12: &str = include_str!("../migrations/012_route_regex_rewrite.sql");
const MIGRATION_V13: &str = include_str!("../migrations/013_waf_persistence.sql");
const MIGRATION_V14: &str = include_str!("../migrations/014_backend_tls_sni.sql");
const MIGRATION_V15: &str = include_str!("../migrations/015_probe_results.sql");
const MIGRATION_V16: &str = include_str!("../migrations/016_backend_tls_skip_verify.sql");
const MIGRATION_V17: &str = include_str!("../migrations/017_acme_method.sql");
const MIGRATION_V19: &str = include_str!("../migrations/019_sessions.sql");

/// A single tracked schema migration: its version and the function
/// that applies it. Entries live in [`MIGRATIONS`], ascending.
type Migration = (i64, fn(&Connection) -> rusqlite::Result<()>);

/// Every schema migration, in ascending version order.
/// [`ConfigStore::run_migrations`] applies each entry whose version is
/// greater than the highest recorded in `schema_migrations`, then
/// records that version.
///
/// Versions 1-22 map to the historical gates: the numbered `.sql`
/// batches, a few inline column additions, and the RBAC backfill at
/// 22. Versions 23+ were previously *unconditional* idempotent
/// `ALTER TABLE ... ADD COLUMN` statements re-run on every open. They
/// now each carry a distinct version and an idempotent body.
///
/// This split matters for databases already deployed in the field. An
/// installation that ran the old code sits at recorded version 22 yet
/// already has every post-22 column, because those unconditional
/// ALTERs added them on every startup regardless of the recorded
/// version. Re-issuing a bare `ALTER TABLE ADD COLUMN` for such a
/// column raises "duplicate column name" and aborts the upgrade;
/// [`add_column_if_absent`] makes each body skip the column it already
/// finds and merely advance the version. The `.sql` batch migrations
/// (1-16, 19, 21) keep their exact original version gating: the
/// columns they add were only ever created by that gated path, so a
/// database below their version never has the column and the bare DDL
/// inside them stays safe.
const MIGRATIONS: &[Migration] = &[
    (1, migrate_initial),
    (2, migrate_health_check_path),
    (3, migrate_sla_metrics),
    (4, migrate_probe_configs),
    (5, migrate_load_tests),
    (6, migrate_sla_bucket_snapshot),
    (7, migrate_route_config),
    (8, migrate_backend_name_group),
    (9, migrate_cache_and_protection),
    (10, migrate_sla_default_range),
    (11, migrate_backend_h2_upstream),
    (12, migrate_route_regex_rewrite),
    (13, migrate_waf_persistence),
    (14, migrate_backend_tls_sni),
    (15, migrate_probe_results),
    (16, migrate_backend_tls_skip_verify),
    (17, migrate_route_redirect_to),
    (18, migrate_route_path_rules),
    (19, migrate_acme_method),
    (20, migrate_dns_providers),
    (21, migrate_sessions),
    (22, migrate_users_rbac),
    (23, migrate_route_sticky_session),
    (24, migrate_route_basic_auth),
    (25, migrate_route_stale_cache),
    (26, migrate_route_retry_on_methods),
    (27, migrate_route_maintenance),
    (28, migrate_route_cache_vary_headers),
    (29, migrate_route_header_rules),
    (30, migrate_route_traffic_splits),
    (31, migrate_route_forward_auth),
    (32, migrate_route_mirror),
    (33, migrate_route_response_rewrite),
    (34, migrate_route_mtls),
    (35, migrate_session_indexes),
    (36, migrate_route_rate_limit),
    (37, migrate_route_geoip),
    (38, migrate_route_bot_protection),
    (39, migrate_bot_pending_challenges),
    (40, migrate_route_group_name),
    (41, migrate_cert_export_acls),
    (42, migrate_route_ai_bot_policy),
    (43, migrate_ai_crawlers_custom),
    (44, migrate_route_serve_robots_txt),
    (45, migrate_bot_pending_prefix_index),
    (46, migrate_session_role),
    (47, migrate_acme_challenges),
    (48, migrate_cluster_state),
    (49, migrate_cluster_ca),
    (50, migrate_cluster_registry),
    (51, migrate_cluster_revoked_serial_expiry),
    (52, migrate_cluster_replication),
    (53, migrate_cluster_node_name_unique),
    (54, migrate_acme_challenge_expiry),
];

/// Which telemetry fan-in cursor a follower is reading or advancing
/// (Story 9.6 AC #5).
///
/// An enum rather than a string because the value is a key in
/// `cluster_state`: a typo in a caller-supplied key would silently
/// create a second cursor that always reads 0, and the node would
/// re-send its whole retained log on every drain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryCursor {
    /// Progress through the local `access_logs` table.
    Access,
    /// Progress through the local `waf_events` table.
    Waf,
    /// Progress through this node's OWN `audit_log` rows
    /// (Story 9.9 AC #2).
    Audit,
}

impl TelemetryCursor {
    /// The `cluster_state` key, a compile-time constant of this module.
    pub fn as_key(self) -> &'static str {
        match self {
            Self::Access => "telemetry_access_cursor",
            Self::Waf => "telemetry_waf_cursor",
            Self::Audit => "telemetry_audit_cursor",
        }
    }
}

/// Whether `column` already exists on `table`, via `pragma_table_info`.
/// Returns `false` when the table itself is absent (the pragma yields
/// no rows), matching the pre-refactor behaviour of the inline guards.
fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Add `column` to `table` with the given column definition, but only
/// when it is absent. Field databases upgraded from the pre-tracked
/// runner already carry these columns (the old code added them
/// unconditionally on every open), so a bare `ALTER TABLE ADD COLUMN`
/// would fail with "duplicate column name". Guarding on
/// `pragma_table_info` keeps each migration idempotent. `table` and
/// `column` are compile-time constants from this module, never
/// caller-supplied, so interpolating them into the DDL is safe.
fn add_column_if_absent(
    conn: &Connection,
    table: &str,
    column: &str,
    coldef_ddl: &str,
) -> rusqlite::Result<()> {
    if !column_exists(conn, table, column)? {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {coldef_ddl}"),
            [],
        )?;
    }
    Ok(())
}

fn migrate_initial(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V1)
}

fn migrate_health_check_path(conn: &Connection) -> rusqlite::Result<()> {
    if !column_exists(conn, "backends", "health_check_path")? {
        conn.execute_batch(MIGRATION_V2)?;
    }
    Ok(())
}

fn migrate_sla_metrics(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V3)
}

fn migrate_probe_configs(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V4)
}

fn migrate_load_tests(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V5)
}

fn migrate_sla_bucket_snapshot(conn: &Connection) -> rusqlite::Result<()> {
    if !column_exists(conn, "sla_buckets", "cfg_max_latency_ms")? {
        conn.execute_batch(MIGRATION_V6)?;
    }
    Ok(())
}

fn migrate_route_config(conn: &Connection) -> rusqlite::Result<()> {
    if !column_exists(conn, "routes", "force_https")? {
        conn.execute_batch(MIGRATION_V7)?;
    }
    Ok(())
}

fn migrate_backend_name_group(conn: &Connection) -> rusqlite::Result<()> {
    if !column_exists(conn, "backends", "name")? {
        conn.execute_batch(MIGRATION_V8)?;
    }
    Ok(())
}

fn migrate_cache_and_protection(conn: &Connection) -> rusqlite::Result<()> {
    if !column_exists(conn, "routes", "cache_enabled")? {
        conn.execute_batch(MIGRATION_V9)?;
    }
    Ok(())
}

fn migrate_sla_default_range(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V10)
}

fn migrate_backend_h2_upstream(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V11)
}

fn migrate_route_regex_rewrite(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V12)
}

fn migrate_waf_persistence(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V13)
}

fn migrate_backend_tls_sni(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V14)
}

fn migrate_probe_results(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V15)
}

fn migrate_backend_tls_skip_verify(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V16)
}

fn migrate_route_redirect_to(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "redirect_to", "TEXT DEFAULT NULL")
}

/// Version 18: the `path_rules` / `return_status` columns were
/// historically added inline (no `.sql` file numbered 018 exists);
/// they are slotted here as a tracked, idempotent entry so the version
/// sequence has no gap.
fn migrate_route_path_rules(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "path_rules", "TEXT DEFAULT '[]'")?;
    add_column_if_absent(conn, "routes", "return_status", "INTEGER DEFAULT NULL")
}

fn migrate_acme_method(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V17)
}

fn migrate_dns_providers(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS dns_providers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            provider_type TEXT NOT NULL,
            config TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;
    add_column_if_absent(
        conn,
        "certificates",
        "acme_dns_provider_id",
        "TEXT DEFAULT NULL",
    )
}

fn migrate_sessions(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(MIGRATION_V19)
}

/// Version 22: the `users` table replaces `admin_users` (Story 8.3
/// RBAC). This carries a one-time data backfill (the single pre-RBAC
/// admin row migrates as role `super_admin`), which is why it cannot
/// be an idempotent ALTER: the backfill must run exactly once. The
/// backfill and drop only run while `admin_users` still exists, so a
/// process that loses the concurrent-open race skips them cleanly.
fn migrate_users_rbac(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'super_admin',
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            last_login_at TEXT,
            disabled_at TEXT,
            created_by TEXT
        );",
    )?;
    let has_admin_users: bool = conn
        .prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_users'")?
        .query_row([], |row| row.get::<_, i64>(0))
        .map(|c| c > 0)?;
    if has_admin_users {
        conn.execute_batch(
            "INSERT OR IGNORE INTO users
                (id, username, password_hash, role, must_change_password,
                 created_at, last_login_at)
             SELECT id, username, password_hash, 'super_admin',
                    must_change_password, created_at, last_login
             FROM admin_users;
             DROP TABLE admin_users;",
        )?;
    }
    Ok(())
}

fn migrate_route_sticky_session(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "sticky_session",
        "INTEGER NOT NULL DEFAULT 0",
    )
}

fn migrate_route_basic_auth(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "basic_auth_username", "TEXT DEFAULT NULL")?;
    add_column_if_absent(
        conn,
        "routes",
        "basic_auth_password_hash",
        "TEXT DEFAULT NULL",
    )
}

fn migrate_route_stale_cache(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "stale_while_revalidate_s",
        "INTEGER NOT NULL DEFAULT 10",
    )?;
    add_column_if_absent(
        conn,
        "routes",
        "stale_if_error_s",
        "INTEGER NOT NULL DEFAULT 60",
    )
}

fn migrate_route_retry_on_methods(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "retry_on_methods",
        "TEXT NOT NULL DEFAULT '[]'",
    )
}

fn migrate_route_maintenance(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "maintenance_mode",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    add_column_if_absent(conn, "routes", "error_page_html", "TEXT DEFAULT NULL")
}

fn migrate_route_cache_vary_headers(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "cache_vary_headers",
        "TEXT NOT NULL DEFAULT '[]'",
    )
}

fn migrate_route_header_rules(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "header_rules", "TEXT NOT NULL DEFAULT '[]'")
}

fn migrate_route_traffic_splits(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "traffic_splits",
        "TEXT NOT NULL DEFAULT '[]'",
    )
}

fn migrate_route_forward_auth(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "forward_auth", "TEXT DEFAULT NULL")
}

fn migrate_route_mirror(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "mirror", "TEXT DEFAULT NULL")
}

fn migrate_route_response_rewrite(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "response_rewrite", "TEXT DEFAULT NULL")
}

fn migrate_route_mtls(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "mtls", "TEXT DEFAULT NULL")
}

fn migrate_session_indexes(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
         CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);",
    )
}

fn migrate_route_rate_limit(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "rate_limit", "TEXT DEFAULT NULL")
}

fn migrate_route_geoip(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "geoip", "TEXT DEFAULT NULL")
}

fn migrate_route_bot_protection(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "bot_protection", "TEXT DEFAULT NULL")
}

fn migrate_bot_pending_challenges(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS bot_pending_challenges (
            nonce TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            mode INTEGER NOT NULL,
            route_id TEXT NOT NULL,
            ip_prefix_disc INTEGER NOT NULL,
            ip_prefix_bytes BLOB NOT NULL,
            return_url TEXT NOT NULL,
            cookie_ttl_s INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            png_bytes BLOB
        );
         CREATE INDEX IF NOT EXISTS idx_bot_pending_expires_at
            ON bot_pending_challenges(expires_at);",
    )
}

fn migrate_route_group_name(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "group_name", "TEXT NOT NULL DEFAULT ''")
}

fn migrate_cert_export_acls(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cert_export_acls (
            id TEXT PRIMARY KEY,
            hostname_pattern TEXT NOT NULL,
            allowed_uid INTEGER,
            allowed_gid INTEGER,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )
}

fn migrate_route_ai_bot_policy(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "ai_bot_policy", "TEXT DEFAULT NULL")?;
    add_column_if_absent(
        conn,
        "routes",
        "ai_bot_spoofed_fallback",
        "TEXT DEFAULT NULL",
    )
}

fn migrate_ai_crawlers_custom(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ai_crawlers_custom (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            user_agent_pattern TEXT NOT NULL,
            verification_kind TEXT NOT NULL,
            verification_data TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
    )
}

fn migrate_route_serve_robots_txt(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "routes",
        "serve_robots_txt",
        "INTEGER NOT NULL DEFAULT 0",
    )
}

fn migrate_bot_pending_prefix_index(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_bot_pending_prefix
         ON bot_pending_challenges(ip_prefix_disc, ip_prefix_bytes);",
    )
}

fn migrate_session_role(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(
        conn,
        "sessions",
        "role",
        "TEXT NOT NULL DEFAULT 'super_admin'",
    )
}

fn migrate_acme_challenges(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.1 AC #10: schema ownership of `acme_challenges` moves
    // here from the ad-hoc CREATE in lorica-api's AcmeChallengeStore
    // (which opened a second connection on the same file and issued
    // its own DDL). IF NOT EXISTS because every deployed database
    // already carries the table from that ad-hoc path; from now on
    // any schema change to it (Story 9.5 adds a network writer)
    // flows through MIGRATIONS.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS acme_challenges (
            token TEXT PRIMARY KEY,
            key_auth TEXT NOT NULL
        );",
    )
}

fn migrate_cluster_state(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.1 AC #6: the persisted cluster configuration generation,
    // distinct from the supervisor's in-memory `reload_generation`
    // (which resets to 0 on every start). Without persistence a
    // control-plane restart would put the whole fleet in permanent
    // false drift and every follower GenerationGate would reject the
    // first post-restart Prepare.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cluster_state (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO cluster_state (key, value) VALUES ('config_generation', 0);
        INSERT OR IGNORE INTO cluster_state (key, value) VALUES ('takeover_epoch', 0);",
    )
}

fn migrate_cluster_ca(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.2 AC #8: the cluster CA generated by `lorica cluster
    // init`. Single row (id = 'ca'); `key_pem` is AES-256-GCM
    // ciphertext under the node's master key (the CA thereby inherits
    // the master-key trust model - docs/cluster.md spells out that
    // this file is now the identity root of the fleet).
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cluster_ca (
            id TEXT PRIMARY KEY,
            cert_pem TEXT NOT NULL,
            key_pem BLOB NOT NULL,
            created_at TEXT NOT NULL
        );",
    )
}

fn migrate_cluster_registry(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.3: the control plane's node registry (AC #9), join
    // tokens (AC #1/#4, only the HMAC of the secret is stored), the
    // revocation list source (AC #7), a follower's own identity
    // (leaf key encrypted at rest) and the control plane's token HMAC
    // key (encrypted at rest). Both encrypted columns are registered
    // in ENCRYPTED_COLUMNS so key rotation covers them.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cluster_nodes (
            node_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            cert_fingerprint TEXT NOT NULL UNIQUE,
            cert_serial TEXT NOT NULL,
            prev_cert_fingerprint TEXT,
            prev_cert_serial TEXT,
            address TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            schema_version INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            enrolled_at TEXT NOT NULL,
            last_seen_at TEXT,
            applied_config_generation INTEGER NOT NULL DEFAULT 0,
            applied_config_hash TEXT NOT NULL DEFAULT '',
            cert_not_after TEXT NOT NULL,
            revoked_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cluster_nodes_prev_fp
            ON cluster_nodes(prev_cert_fingerprint);
        CREATE TABLE IF NOT EXISTS cluster_join_tokens (
            public_id TEXT PRIMARY KEY,
            secret_hmac TEXT NOT NULL,
            state TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            bound_node_name TEXT,
            bound_source_cidr TEXT,
            burned_at TEXT,
            burned_by_node_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cluster_join_tokens_live
            ON cluster_join_tokens(state, expires_at);
        CREATE TABLE IF NOT EXISTS cluster_revoked_serials (
            serial TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            reason TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cluster_identity (
            id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            node_name TEXT NOT NULL,
            cert_pem TEXT NOT NULL,
            key_pem BLOB NOT NULL,
            ca_pem TEXT NOT NULL,
            control_plane TEXT NOT NULL,
            server_name TEXT NOT NULL,
            enrolled_at TEXT NOT NULL,
            cert_not_after TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cluster_secrets (
            id TEXT PRIMARY KEY,
            value BLOB NOT NULL,
            created_at TEXT NOT NULL
        );",
    )
}

fn migrate_cluster_revoked_serial_expiry(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.3 QA: a revoked serial carries its certificate's expiry
    // so the CRL stays bounded by the live certificates (expired ones
    // are pruned). Its own migration, not a column slipped into
    // migration 50: databases created earlier in the v1.7.0 cycle are
    // already at 50 and would never see the column otherwise. The
    // epoch default only ever applies to rows written before this
    // migration on such a database; they are pruned at the next flush,
    // which is the right outcome for serials whose expiry is unknown.
    add_column_if_absent(
        conn,
        "cluster_revoked_serials",
        "expires_at",
        "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'",
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_cluster_revoked_serials_expiry
            ON cluster_revoked_serials(expires_at);",
    )
}

fn migrate_cluster_replication(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.4: the follower's applied-replica state and the
    // break-glass window, plus the route-level `node_selector`
    // (D11 / AC #13).
    //
    // Its own migration rather than an edit of 50 or 51: a database
    // created earlier in the v1.7.0 cycle already records 50 and 51 and
    // would never re-run them, so a column or a row added there would
    // silently never appear on those installations.
    //
    // The state does NOT live in `cluster_state`: migration 48 typed
    // that table's `value` column as INTEGER, and the applied hash and
    // the break-glass deadline are text. `cluster_replica` is the text
    // sibling; both are single-row-per-key and read through
    // `store/cluster_replica.rs`.
    add_column_if_absent(
        conn,
        "routes",
        "node_selector",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS cluster_replica (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT OR IGNORE INTO cluster_replica (key, value) VALUES ('applied_config_generation', '0');
        INSERT OR IGNORE INTO cluster_replica (key, value) VALUES ('applied_config_hash', '');
        INSERT OR IGNORE INTO cluster_replica (key, value) VALUES ('break_glass_until', '');",
    )
}

/// `base` truncated so that `base` followed by `suffix` still fits the
/// 64-character node-name rule enforced by
/// [`crate::models::validate_node_selector_names`], so a renamed node
/// stays nameable in a selector. Truncation counts characters, never
/// bytes: a name written before any validation existed is not
/// guaranteed to be ASCII.
fn name_with_suffix(base: &str, suffix: &str) -> String {
    const MAX_NAME_CHARS: usize = 64;
    let keep = MAX_NAME_CHARS.saturating_sub(suffix.chars().count());
    let mut out: String = base.chars().take(keep).collect();
    out.push_str(suffix);
    out
}

/// Give every `cluster_nodes.name` a distinct value, so migration 53
/// can put a UNIQUE index on the column.
///
/// The name has been proposed by the joining node since Story 9.3 with
/// no constraint at all, so a fleet already in the field can hold
/// duplicates. Creating the index on such a database would abort the
/// migration and take the control plane's boot down with it, which is a
/// far worse outcome than a renamed node.
///
/// The oldest enrollment keeps the name; ties break on `node_id` so the
/// outcome does not depend on SQLite's row order. Every later holder
/// becomes `<name>-<first 8 of node_id>`, with a numeric disambiguator
/// on the vanishingly unlikely event that the result is itself taken.
///
/// Each rename is logged at WARN because it is operator-visible: a
/// route's `node_selector` matches on the name, so a renamed node stops
/// serving its selected routes until one side or the other is fixed.
fn rename_duplicate_cluster_node_names(conn: &Connection) -> rusqlite::Result<()> {
    let mut nodes: Vec<(String, String)> = Vec::new();
    {
        let mut stmt = conn.prepare(
            "SELECT node_id, name FROM cluster_nodes ORDER BY name, enrolled_at, node_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            nodes.push(row?);
        }
    }

    let mut taken: HashSet<String> = nodes.iter().map(|(_, name)| name.clone()).collect();
    let mut previous_name: Option<String> = None;
    let mut renamed: Vec<String> = Vec::new();
    for (node_id, name) in &nodes {
        if previous_name.as_ref() != Some(name) {
            previous_name = Some(name.clone());
            continue;
        }
        let short_id: String = node_id.chars().take(8).collect();
        let mut candidate = name_with_suffix(name, &format!("-{short_id}"));
        let mut disambiguator: u32 = 1;
        while taken.contains(&candidate) {
            candidate = name_with_suffix(name, &format!("-{short_id}-{disambiguator}"));
            disambiguator += 1;
        }
        conn.execute(
            "UPDATE cluster_nodes SET name = ?2 WHERE node_id = ?1",
            params![node_id, candidate],
        )?;
        tracing::warn!(
            node_id = %node_id,
            previous_name = %name,
            new_name = %candidate,
            "duplicate cluster node name renamed by migration 53; \
             update any route node_selector that named it"
        );
        renamed.push(candidate.clone());
        taken.insert(candidate);
    }
    // One summary at ERROR beside the per-node warnings. A rename here
    // silently changes what a route `node_selector` matches, which
    // changes which node is entitled to which private key: the
    // operator has to reconcile the selectors by hand, and a line
    // buried among per-node warnings at boot is not how they will find
    // out.
    if !renamed.is_empty() {
        tracing::error!(
            renamed = renamed.len(),
            names = ?renamed,
            "migration 53 renamed cluster nodes that shared a name; every route \
             node_selector naming one of them now selects a DIFFERENT set of \
             nodes, which changes certificate key entitlement. Review the \
             selectors before trusting the fleet's key distribution."
        );
    }
    Ok(())
}

fn migrate_cluster_node_name_unique(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.5 D3: certificate recipients are resolved by matching a
    // route's `node_selector` against `cluster_nodes.name`, then
    // translating the name to the `node_id` the mutual-TLS certificate
    // proves. Two nodes sharing a name would each be entitled to the
    // other's private keys, so the name must designate exactly one
    // node. The index also lets enrollment refuse a taken name instead
    // of silently creating the ambiguity.
    //
    // Duplicates are renamed first: without that pass, a database
    // enrolled before this migration fails the CREATE UNIQUE INDEX and
    // the control plane never boots.
    rename_duplicate_cluster_node_names(conn)?;
    conn.execute_batch(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cluster_nodes_name ON cluster_nodes(name);",
    )
}

fn migrate_acme_challenge_expiry(conn: &Connection) -> rusqlite::Result<()> {
    // Story 9.5 AC #6 / D11: `acme_challenges` carried no timestamp, no
    // index and no purge, so an order that died between the write and
    // the driver's cleanup left the node serving a key authorization
    // forever (lorica-api's store already warns about that case on a
    // failed DELETE). The column turns expiry into a read-time
    // predicate instead of a hope, and the index keeps the purge from
    // scanning the table.
    //
    // The epoch default deliberately expires every row a pre-migration
    // database still holds. A challenge is valid for minutes, so a row
    // that survived the upgrade is a leaked token by definition:
    // nothing legitimate is lost by refusing to serve it.
    add_column_if_absent(
        conn,
        "acme_challenges",
        "expires_at",
        "TEXT NOT NULL DEFAULT '1970-01-01T00:00:00+00:00'",
    )?;
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_acme_challenges_expiry
            ON acme_challenges(expires_at);",
    )
}

/// One encrypted-at-rest storage location the key rotation walks
/// (Story 9.1 AC #8). Adding at-rest encryption anywhere in the store
/// REQUIRES a matching entry here; the source-scan test
/// `rotation_registry_covers_every_encrypting_store_module` fails the
/// build's test run when a store module encrypts into a table this
/// registry does not name.
#[derive(Debug, Clone, Copy)]
enum EncryptedColumn {
    /// A BLOB column holding raw AES-256-GCM ciphertext.
    Blob {
        table: &'static str,
        id_col: &'static str,
        col: &'static str,
    },
    /// A TEXT column holding base64-wrapped ciphertext.
    Text {
        table: &'static str,
        id_col: &'static str,
        col: &'static str,
    },
    /// One row of a key-value table (TEXT, base64-wrapped
    /// ciphertext; the empty string means "absent").
    KvText {
        table: &'static str,
        key_col: &'static str,
        val_col: &'static str,
        row_key: &'static str,
    },
}

/// Every encrypted-at-rest storage location, the single registry the
/// rotation iterates.
const ENCRYPTED_COLUMNS: &[EncryptedColumn] = &[
    EncryptedColumn::Blob {
        table: "certificates",
        id_col: "id",
        col: "key_pem",
    },
    // The fleet identity root (Story 9.2 AC #8): losing rotation
    // coverage here would brick every cluster session at the next
    // key rotation.
    EncryptedColumn::Blob {
        table: "cluster_ca",
        id_col: "id",
        col: "key_pem",
    },
    // A follower's own fleet identity key (Story 9.3).
    EncryptedColumn::Blob {
        table: "cluster_identity",
        id_col: "id",
        col: "key_pem",
    },
    // The control plane's join-token HMAC key (Story 9.3): rotating
    // the master key rotates it, invalidating outstanding tokens.
    EncryptedColumn::Blob {
        table: "cluster_secrets",
        id_col: "id",
        col: "value",
    },
    EncryptedColumn::Text {
        table: "notification_configs",
        id_col: "id",
        col: "config",
    },
    // Missing from the pre-9.1 hardcoded loop: a key rotation left
    // every DNS provider credential undecryptable while reporting
    // success (Story 9.1 AC #8's motivating bug class, found live).
    EncryptedColumn::Text {
        table: "dns_providers",
        id_col: "id",
        col: "config",
    },
    // Log-export sink secrets (Story 9.8).
    EncryptedColumn::KvText {
        table: "global_settings",
        key_col: "key",
        val_col: "value",
        row_key: "syslog_tls_client_key_pem",
    },
    EncryptedColumn::KvText {
        table: "global_settings",
        key_col: "key",
        val_col: "value",
        row_key: "otlp_logs_auth_header",
    },
];

/// Table names covered by [`ENCRYPTED_COLUMNS`], for the coverage
/// test in `tests.rs`.
#[cfg(test)]
pub(crate) fn rotation_covered_tables() -> Vec<&'static str> {
    ENCRYPTED_COLUMNS
        .iter()
        .map(|c| match c {
            EncryptedColumn::Blob { table, .. }
            | EncryptedColumn::Text { table, .. }
            | EncryptedColumn::KvText { table, .. } => *table,
        })
        .collect()
}

/// Row keys of the [`EncryptedColumn::KvText`] entries, for the
/// coverage test in `tests.rs`: table-level coverage is too coarse
/// for a key/value table where dozens of plaintext settings and a
/// few encrypted secrets share the same INSERT.
#[cfg(test)]
pub(crate) fn rotation_covered_kv_row_keys() -> Vec<&'static str> {
    ENCRYPTED_COLUMNS
        .iter()
        .filter_map(|c| match c {
            EncryptedColumn::KvText { row_key, .. } => Some(*row_key),
            _ => None,
        })
        .collect()
}

/// Sole database access point for all Lorica configuration.
pub struct ConfigStore {
    pub(crate) conn: Connection,
    encryption_key: Option<EncryptionKey>,
}

impl ConfigStore {
    /// Open (or create) the configuration database at the given path.
    /// Enables WAL mode and runs pending migrations automatically.
    /// If `encryption_key` is provided, certificate private keys are encrypted at rest.
    pub fn open(path: &Path, encryption_key: Option<EncryptionKey>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch("PRAGMA busy_timeout=5000;")?;
        // synchronous=NORMAL paired with WAL is the documented SQLite
        // recommendation: durable against power loss, ~10x faster
        // commits than the default FULL on spinning disk and noticeably
        // faster on SSD under write bursts (imports, ACME renewals,
        // bulk edits). The narrow uncommitted window between fsyncs is
        // acceptable for config state given the export/backup story.
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
        let store = Self {
            conn,
            encryption_key,
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self {
            conn,
            encryption_key: None,
        };
        store.run_migrations()?;
        Ok(store)
    }

    /// Open an in-memory database with an encryption key (for testing encryption).
    pub fn open_in_memory_with_key(encryption_key: EncryptionKey) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self {
            conn,
            encryption_key: Some(encryption_key),
        };
        store.run_migrations()?;
        Ok(store)
    }

    pub(super) fn encrypt_key_pem(&self, key_pem: &str) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => key.encrypt(key_pem.as_bytes()),
            None => Ok(key_pem.as_bytes().to_vec()),
        }
    }

    pub(super) fn decrypt_key_pem(&self, data: &[u8]) -> Result<String> {
        match &self.encryption_key {
            Some(key) => {
                let plaintext = key.decrypt(data)?;
                String::from_utf8(plaintext).map_err(|e| {
                    ConfigError::Validation(format!("decrypted key_pem is not valid UTF-8: {e}"))
                })
            }
            None => String::from_utf8(data.to_vec())
                .map_err(|e| ConfigError::Validation(format!("key_pem is not valid UTF-8: {e}"))),
        }
    }

    /// Encrypt raw bytes for a BLOB column (no UTF-8 assumption).
    pub(super) fn encrypt_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => key.encrypt(plaintext),
            None => Ok(plaintext.to_vec()),
        }
    }

    /// Decrypt raw bytes from a BLOB column.
    pub(super) fn decrypt_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => key.decrypt(data),
            None => Ok(data.to_vec()),
        }
    }

    pub(super) fn encrypt_config(&self, config: &str) -> Result<String> {
        match &self.encryption_key {
            Some(key) => {
                let encrypted = key.encrypt(config.as_bytes())?;
                Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
            }
            None => Ok(config.to_string()),
        }
    }

    pub(super) fn decrypt_config(&self, stored: &str) -> Result<String> {
        match &self.encryption_key {
            Some(key) => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(stored)
                    .map_err(|e| ConfigError::Validation(format!("invalid base64 config: {e}")))?;
                let plaintext = key.decrypt(&decoded)?;
                String::from_utf8(plaintext).map_err(|e| {
                    ConfigError::Validation(format!("decrypted config not UTF-8: {e}"))
                })
            }
            None => Ok(stored.to_string()),
        }
    }

    fn run_migrations(&self) -> Result<()> {
        // Ensure schema_migrations table exists before querying it.
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        let current_version: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;

        for &(version, migrate) in MIGRATIONS {
            if version > current_version {
                tracing::info!("applying schema migration v{version}");
                migrate(&self.conn)?;
                self.conn.execute(
                    "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                    params![version],
                )?;
            }
        }

        Ok(())
    }

    /// Return the current schema version.
    pub fn schema_version(&self) -> Result<i64> {
        let v = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        Ok(v)
    }

    // ---- Key Rotation ----

    /// Re-encrypt every encrypted-at-rest value from the current
    /// encryption key to a new one, in a single transaction, driven
    /// by [`ENCRYPTED_COLUMNS`] (Story 9.1 AC #8).
    ///
    /// The rotation used to be a hardcoded two-table loop, which
    /// silently skipped `dns_providers.config` - a real bug this
    /// rework fixes: rotating the key left every DNS provider
    /// credential encrypted under the retired key, breaking DNS-01
    /// issuance at the next renewal while rotation reported success.
    /// A registry entry is now the ONLY way a column takes part, and
    /// the source-scan test in `tests.rs` fails when a store module
    /// encrypts into a table the registry does not name.
    pub fn rotate_encryption_key(&self, new_key: &EncryptionKey) -> Result<u32> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| ConfigError::Validation(format!("failed to begin transaction: {e}")))?;

        let mut count = 0u32;

        for column in ENCRYPTED_COLUMNS {
            match column {
                EncryptedColumn::Blob { table, id_col, col } => {
                    let mut stmt = tx.prepare(&format!("SELECT {id_col}, {col} FROM {table}"))?;
                    // A row that fails to read aborts the whole
                    // rotation: silently skipping it would leave that
                    // secret under the retired key while the rotation
                    // reports success - the exact failure AC #8 exists
                    // to eliminate.
                    let rows: Vec<(String, Vec<u8>)> = stmt
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<(String, Vec<u8>)>>>()?;
                    drop(stmt);
                    let mut update = tx.prepare(&format!(
                        "UPDATE {table} SET {col} = ?1 WHERE {id_col} = ?2"
                    ))?;
                    for (id, stored) in &rows {
                        // Raw bytes: BLOB columns hold PEM text AND raw
                        // keys (the token HMAC key), so no UTF-8
                        // assumption belongs here.
                        let plaintext = self.decrypt_bytes(stored)?;
                        let re_encrypted = Self::reencrypt_verified(new_key, &plaintext)?;
                        update.execute(params![re_encrypted, id])?;
                        count += 1;
                    }
                }
                EncryptedColumn::Text { table, id_col, col } => {
                    let mut stmt = tx.prepare(&format!("SELECT {id_col}, {col} FROM {table}"))?;
                    let rows: Vec<(String, String)> = stmt
                        .query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<(String, String)>>>()?;
                    drop(stmt);
                    let mut update = tx.prepare(&format!(
                        "UPDATE {table} SET {col} = ?1 WHERE {id_col} = ?2"
                    ))?;
                    for (id, stored) in &rows {
                        let plaintext = self.decrypt_config(stored)?;
                        let re_encrypted = Self::reencrypt_verified(new_key, plaintext.as_bytes())?;
                        let re_encoded =
                            base64::engine::general_purpose::STANDARD.encode(&re_encrypted);
                        update.execute(params![re_encoded, id])?;
                        count += 1;
                    }
                }
                EncryptedColumn::KvText {
                    table,
                    key_col,
                    val_col,
                    row_key,
                } => {
                    let stored: Option<String> = tx
                        .query_row(
                            &format!("SELECT {val_col} FROM {table} WHERE {key_col} = ?1"),
                            params![row_key],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if let Some(stored) = stored.filter(|s| !s.is_empty()) {
                        let plaintext = self.decrypt_config(&stored)?;
                        let re_encrypted = Self::reencrypt_verified(new_key, plaintext.as_bytes())?;
                        let re_encoded =
                            base64::engine::general_purpose::STANDARD.encode(&re_encrypted);
                        tx.execute(
                            &format!("UPDATE {table} SET {val_col} = ?1 WHERE {key_col} = ?2"),
                            params![re_encoded, row_key],
                        )?;
                        count += 1;
                    }
                }
            }
        }

        tx.commit()
            .map_err(|e| ConfigError::Validation(format!("failed to commit transaction: {e}")))?;

        Ok(count)
    }

    /// Encrypt `plaintext` under `new_key` and prove the ciphertext
    /// decrypts back to the same bytes before it is written. Rotation
    /// is a one-way door - the old ciphertext is overwritten inside
    /// the transaction and the plaintext exists nowhere else - so an
    /// unreadable re-encryption must abort, not commit.
    fn reencrypt_verified(new_key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>> {
        let re_encrypted = new_key.encrypt(plaintext)?;
        let check = new_key.decrypt(&re_encrypted)?;
        if check != plaintext {
            return Err(ConfigError::Validation(
                "post-rotation verification failed: re-encrypted value does not decrypt back"
                    .to_string(),
            ));
        }
        Ok(re_encrypted)
    }

    /// Read the persisted cluster configuration generation (Story 9.1
    /// AC #6). Returns 0 on a store that has never taken a cluster
    /// mutation.
    pub fn cluster_config_generation(&self) -> Result<u64> {
        let value: i64 = self.conn.query_row(
            "SELECT value FROM cluster_state WHERE key = 'config_generation'",
            [],
            |row| row.get(0),
        )?;
        Ok(value.max(0) as u64)
    }

    /// Atomically increment and return the persisted cluster
    /// configuration generation. Every cluster-replicated mutation
    /// calls this (Story 9.4); the returned value survives restarts,
    /// unlike the supervisor's in-memory `reload_generation`.
    pub fn increment_cluster_config_generation(&self) -> Result<u64> {
        // Single-statement RETURNING (as bot_stash.rs already does):
        // an UPDATE followed by a separate SELECT would let two
        // concurrent mutators read the same post-increment value and
        // stamp two distinct configs with one generation.
        let value: i64 = self.conn.query_row(
            "UPDATE cluster_state SET value = value + 1 WHERE key = 'config_generation' \
             RETURNING value",
            [],
            |row| row.get(0),
        )?;
        Ok(value.max(0) as u64)
    }

    /// Read a follower's telemetry fan-in cursor (Story 9.6 AC #5).
    ///
    /// The highest local rowid this node has already delivered to its
    /// control plane, per kind. Persisted rather than in-memory
    /// because a restart would otherwise re-send everything the local
    /// retention still holds, which is up to 100 000 rows per kind
    /// arriving in one burst at exactly the moment a node is least
    /// able to absorb it.
    ///
    /// Returns 0 on a node that has never pushed, which correctly
    /// means "start from the oldest row still retained".
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure.
    pub fn telemetry_cursor(&self, kind: TelemetryCursor) -> Result<u64> {
        let value: Option<i64> = self
            .conn
            .query_row(
                "SELECT value FROM cluster_state WHERE key = ?1",
                params![kind.as_key()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value.unwrap_or(0).max(0) as u64)
    }

    /// Advance a telemetry cursor, never backwards.
    ///
    /// `MAX` rather than a plain write: two drains racing, or an
    /// out-of-order acknowledgement, must not rewind the cursor and
    /// re-send rows the control plane already stored.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a write failure.
    pub fn advance_telemetry_cursor(&self, kind: TelemetryCursor, to: u64) -> Result<()> {
        let to = i64::try_from(to).unwrap_or(i64::MAX);
        self.conn.execute(
            "INSERT INTO cluster_state (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
            params![kind.as_key(), to],
        )?;
        Ok(())
    }

    /// Read the persisted supervisor takeover epoch (Story 9.1 AC #7).
    pub fn cluster_takeover_epoch(&self) -> Result<u64> {
        let value: i64 = self.conn.query_row(
            "SELECT value FROM cluster_state WHERE key = 'takeover_epoch'",
            [],
            |row| row.get(0),
        )?;
        Ok(value.max(0) as u64)
    }

    /// Atomically increment and return the supervisor takeover epoch.
    ///
    /// The hot-upgrade double-session interlock (Story 9.1 AC #7): a
    /// NEW supervisor taking over via `--hot-upgrade` bumps this
    /// before serving the cluster plane. Cluster sessions (Story 9.2)
    /// tag themselves with the epoch they were accepted under, and
    /// the session registry terminates any session from an older
    /// epoch, so during the old/new supervisor overlap a follower can
    /// never hold two live sessions for one `node_id` - the old
    /// supervisor's sessions are fenced the moment the new one takes
    /// the epoch.
    pub fn increment_cluster_takeover_epoch(&self) -> Result<u64> {
        let value: i64 = self.conn.query_row(
            "UPDATE cluster_state SET value = value + 1 WHERE key = 'takeover_epoch' \
             RETURNING value",
            [],
            |row| row.get(0),
        )?;
        Ok(value.max(0) as u64)
    }

    /// Clear all importable data before applying a TOML import.
    ///
    /// "Importable" here means : every table whose rows are part of
    /// the `ExportData` shape that `import_to_store` round-trips. The
    /// import contract is "wipe + replace" against the imported set ;
    /// that's why this function exists.
    ///
    /// **Tables NOT in the delete set, by intent** (audit M-25
    /// closure - the previous absence of this list was the bug) :
    ///
    /// - `sessions` : operator stays logged in across an import.
    ///   Wiping would drop the active session that just triggered
    ///   the import, breaking the redirect-to-dashboard flow.
    /// - `bot_pending_challenges` : ephemeral, expires on its own
    ///   via `prune_expired` ; wiping would invalidate in-flight
    ///   browser challenges and force every visitor to re-solve.
    /// - `probe_configs` + `probe_results` : observability data.
    ///   Probes are operator-local infra config (intentionally NOT
    ///   in the TOML export shape - operators run different probe
    ///   sets per environment) ; results are historical telemetry
    ///   the operator pays for collecting.
    /// - `sla_buckets` + `load_test_configs` + `load_test_results` :
    ///   same shape as probes - environment-local config + historical
    ///   telemetry, not part of the portable TOML.
    /// - `cert_export_acls` : operator-local filesystem ACL
    ///   configuration (target uid / gid live on the destination
    ///   host, not in source-of-truth config). NOT in the TOML
    ///   export today by design.
    ///
    /// `dns_providers` IS in the delete set because the TOML export
    /// carries DNS-provider credentials (in scrubbed form per audit
    /// L-5) ; an operator importing a previously-exported config
    /// expects the provider list to round-trip.
    pub fn clear_all(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM route_backends;
             DELETE FROM routes;
             DELETE FROM backends;
             DELETE FROM certificates;
             DELETE FROM notification_configs;
             DELETE FROM dns_providers;
             DELETE FROM user_preferences;
             DELETE FROM users;
             DELETE FROM global_settings;",
        )?;
        Ok(())
    }
}

/// Generate a new UUID v4 string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    /// Late `routes` columns that historically only ever arrived via
    /// the previously unconditional post-v22 ALTER blocks. Their
    /// presence proves the tracked runner applied the full tail.
    const LATE_ROUTE_COLUMNS: &[&str] = &[
        "sticky_session",
        "bot_protection",
        "mtls",
        "rate_limit",
        "header_rules",
        "geoip",
        "serve_robots_txt",
        "group_name",
        "node_selector",
    ];

    fn max_migration_version() -> i64 {
        MIGRATIONS
            .iter()
            .map(|&(version, _)| version)
            .max()
            .expect("MIGRATIONS is non-empty")
    }

    fn column_count(conn: &Connection, table: &str, column: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
            params![table, column],
            |row| row.get(0),
        )
        .expect("pragma_table_info query")
    }

    #[test]
    fn migration_versions_are_contiguous_and_ascending() {
        // A gap or a duplicate would let an entry silently never run
        // (or run twice) on some databases; assert the invariant the
        // whole runner leans on.
        for (index, &(version, _)) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                version,
                index as i64 + 1,
                "MIGRATIONS[{index}] must have version {}",
                index + 1
            );
        }
    }

    #[test]
    fn fresh_db_reaches_latest_version_with_all_late_columns() {
        let store = ConfigStore::open_in_memory().expect("fresh in-memory open");

        assert_eq!(
            store.schema_version().expect("schema_version read"),
            max_migration_version(),
            "a fresh DB must land on the highest tracked migration version"
        );

        for column in LATE_ROUTE_COLUMNS {
            assert_eq!(
                column_count(&store.conn, "routes", column),
                1,
                "routes.{column} must exist after a fresh migration run"
            );
        }
        // A late non-routes column too (added by the last migration).
        assert_eq!(
            column_count(&store.conn, "sessions", "role"),
            1,
            "sessions.role must exist after a fresh migration run"
        );
    }

    #[test]
    fn old_field_db_with_preexisting_columns_upgrades_cleanly() {
        // Reproduce the exact field state the tracked runner must
        // survive: a database whose recorded version predates the
        // post-v22 tail, yet which already carries several of those
        // "late" columns because the historical code added them via
        // unconditional `ALTER TABLE ADD COLUMN` on every open without
        // ever advancing the version. A naive `version > current` gate
        // re-issuing a bare ALTER here would abort on
        // "duplicate column name".
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("field.db");
        {
            let conn = Connection::open(&db_path).expect("raw open");
            // Base schema (001 creates schema_migrations + routes +
            // admin_users; 019 creates sessions), version pinned at 21
            // (pre-RBAC).
            conn.execute_batch(MIGRATION_V1).expect("001 initial");
            conn.execute_batch(MIGRATION_V19).expect("019 sessions");
            conn.execute_batch("INSERT INTO schema_migrations (version) VALUES (21);")
                .expect("pin version 21");
            // Field drift: several late columns already present with no
            // corresponding version bump.
            conn.execute_batch(
                "ALTER TABLE routes ADD COLUMN sticky_session INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE routes ADD COLUMN mtls TEXT DEFAULT NULL;
                 ALTER TABLE routes ADD COLUMN rate_limit TEXT DEFAULT NULL;
                 ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'super_admin';",
            )
            .expect("simulate unconditional field ALTERs");
        }

        // The upgrade must not error despite the pre-existing columns.
        let store = ConfigStore::open(&db_path, None)
            .expect("migration runner must tolerate pre-existing late columns");

        assert_eq!(
            store.schema_version().expect("schema_version read"),
            max_migration_version(),
            "upgrade must reach the highest tracked version"
        );

        // Every pre-existing late column is present exactly once: the
        // idempotent guard skipped the duplicate ALTER instead of
        // erroring or adding a second column.
        for column in ["sticky_session", "mtls", "rate_limit"] {
            assert_eq!(
                column_count(&store.conn, "routes", column),
                1,
                "routes.{column} must exist exactly once after upgrade"
            );
        }
        assert_eq!(
            column_count(&store.conn, "sessions", "role"),
            1,
            "sessions.role must exist exactly once after upgrade"
        );

        // Columns that were NOT pre-added must now exist too: the tail
        // ran to completion rather than aborting on the first
        // duplicate.
        for column in [
            "bot_protection",
            "header_rules",
            "serve_robots_txt",
            "group_name",
        ] {
            assert_eq!(
                column_count(&store.conn, "routes", column),
                1,
                "routes.{column} must be added by the upgrade"
            );
        }
    }

    #[test]
    fn migrations_are_idempotent_on_second_run() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("idem.db");

        let first = ConfigStore::open(&db_path, None).expect("first open runs migrations");
        let version_after_first = first.schema_version().expect("version read");
        assert_eq!(version_after_first, max_migration_version());
        drop(first);

        // Re-opening runs run_migrations again; every entry is already
        // recorded, so the loop body never fires and nothing changes.
        let second = ConfigStore::open(&db_path, None).expect("second open is a no-op");
        assert_eq!(
            second.schema_version().expect("version read"),
            version_after_first,
            "a second run must not advance or regress the version"
        );
    }

    // ---- Migration 53: unique cluster node names ----

    /// Enrol a node with only the columns `cluster_nodes` has no
    /// default for. The rename pass reads three of them and nothing
    /// else, so a full `ClusterNode` would only obscure what the test
    /// is about.
    fn enrol(conn: &Connection, node_id: &str, name: &str, enrolled_at: &str) {
        conn.execute(
            "INSERT INTO cluster_nodes \
             (node_id, name, cert_fingerprint, cert_serial, status, enrolled_at, cert_not_after) \
             VALUES (?1, ?2, ?1, ?1, 'active', ?3, '2027-01-01T00:00:00+00:00')",
            params![node_id, name, enrolled_at],
        )
        .expect("test setup: node inserts");
    }

    fn name_of(conn: &Connection, node_id: &str) -> String {
        conn.query_row(
            "SELECT name FROM cluster_nodes WHERE node_id = ?1",
            params![node_id],
            |row| row.get(0),
        )
        .expect("test setup: name reads")
    }

    /// A store at the current head with the migration-53 index removed,
    /// which is the shape of a fleet enrolled before that migration
    /// existed: names are free to collide.
    fn store_without_the_name_index() -> ConfigStore {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        store
            .conn
            .execute_batch("DROP INDEX IF EXISTS idx_cluster_nodes_name;")
            .expect("test setup: index drops");
        store
    }

    #[test]
    fn migration_53_renames_duplicate_names_keeping_the_oldest_enrollment() {
        let store = store_without_the_name_index();
        // Inserted out of enrollment order on purpose: the winner is
        // the oldest `enrolled_at`, not the first row SQLite hands back.
        enrol(
            &store.conn,
            "33333333-new",
            "edge",
            "2026-03-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "11111111-old",
            "edge",
            "2026-01-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "22222222-mid",
            "edge",
            "2026-02-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "44444444-solo",
            "edge-solo",
            "2026-01-15T00:00:00+00:00",
        );

        migrate_cluster_node_name_unique(&store.conn)
            .expect("a fleet with duplicate names must still boot");

        assert_eq!(name_of(&store.conn, "11111111-old"), "edge");
        assert_eq!(name_of(&store.conn, "22222222-mid"), "edge-22222222");
        assert_eq!(name_of(&store.conn, "33333333-new"), "edge-33333333");
        assert_eq!(
            name_of(&store.conn, "44444444-solo"),
            "edge-solo",
            "a name held by one node is never touched"
        );

        // The index the whole migration exists for is now in place and
        // enforcing.
        let duplicate = store.conn.execute(
            "INSERT INTO cluster_nodes \
             (node_id, name, cert_fingerprint, cert_serial, status, enrolled_at, cert_not_after) \
             VALUES ('55555555-late', 'edge', 'fp', 'sn', 'pending', \
             '2026-04-01T00:00:00+00:00', '2027-01-01T00:00:00+00:00')",
            [],
        );
        assert!(
            duplicate.is_err(),
            "the UNIQUE index must refuse a second node called edge"
        );
    }

    #[test]
    fn migration_53_is_idempotent_on_a_second_run() {
        let store = store_without_the_name_index();
        enrol(
            &store.conn,
            "11111111-old",
            "edge",
            "2026-01-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "22222222-mid",
            "edge",
            "2026-02-01T00:00:00+00:00",
        );

        migrate_cluster_node_name_unique(&store.conn).expect("first run renames");
        let after_first = name_of(&store.conn, "22222222-mid");
        migrate_cluster_node_name_unique(&store.conn).expect("second run is a no-op");

        assert_eq!(name_of(&store.conn, "11111111-old"), "edge");
        assert_eq!(
            name_of(&store.conn, "22222222-mid"),
            after_first,
            "a second pass must not suffix an already unique name again"
        );
    }

    #[test]
    fn migration_53_disambiguates_when_the_suffixed_name_is_itself_taken() {
        let store = store_without_the_name_index();
        enrol(
            &store.conn,
            "11111111-old",
            "edge",
            "2026-01-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "22222222-mid",
            "edge",
            "2026-02-01T00:00:00+00:00",
        );
        // An operator who already named a node exactly what the rename
        // would produce. Colliding again would fail the index and take
        // the boot down, which is the one outcome the pass must avoid.
        enrol(
            &store.conn,
            "99999999-squat",
            "edge-22222222",
            "2026-01-05T00:00:00+00:00",
        );

        migrate_cluster_node_name_unique(&store.conn)
            .expect("a squatted rename target must not fail the boot");

        assert_eq!(name_of(&store.conn, "11111111-old"), "edge");
        assert_eq!(name_of(&store.conn, "99999999-squat"), "edge-22222222");
        assert_eq!(name_of(&store.conn, "22222222-mid"), "edge-22222222-1");
    }

    #[test]
    fn a_renamed_node_still_fits_the_node_name_length_rule() {
        // A selector entry is capped at 64 characters, so a rename that
        // overflowed would produce a node no route could ever name.
        let long_name = "e".repeat(64);
        let store = store_without_the_name_index();
        enrol(
            &store.conn,
            "11111111-old",
            &long_name,
            "2026-01-01T00:00:00+00:00",
        );
        enrol(
            &store.conn,
            "22222222-mid",
            &long_name,
            "2026-02-01T00:00:00+00:00",
        );

        migrate_cluster_node_name_unique(&store.conn).expect("rename succeeds");

        let renamed = name_of(&store.conn, "22222222-mid");
        assert_eq!(renamed.chars().count(), 64);
        assert!(renamed.ends_with("-22222222"), "renamed to {renamed}");
        assert!(crate::models::validate_node_selector_names(&[renamed]).is_ok());
    }

    // ---- Migration 54: ACME challenge expiry ----

    #[test]
    fn migration_54_gives_acme_challenges_an_expiry_and_an_index() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        assert_eq!(
            column_count(&store.conn, "acme_challenges", "expires_at"),
            1,
            "acme_challenges.expires_at must exist exactly once"
        );
        let index_count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' \
                 AND name = 'idx_acme_challenges_expiry'",
                [],
                |row| row.get(0),
            )
            .expect("test setup: sqlite_master query");
        assert_eq!(index_count, 1, "the purge must not table-scan");
    }

    #[test]
    fn migration_54_expires_rows_written_before_it_existed() {
        // A row a pre-migration database still holds is a leaked token:
        // challenges live for minutes, so the epoch default is the
        // right answer, not a lossy one.
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        store
            .conn
            .execute(
                "INSERT INTO acme_challenges (token, key_auth) VALUES ('legacy', 'auth')",
                [],
            )
            .expect("test setup: legacy row inserts");

        let now = chrono::Utc::now();
        assert_eq!(
            store
                .get_acme_challenge("legacy", now)
                .expect("read succeeds"),
            None,
            "a token that survived the upgrade must not be served"
        );
        assert_eq!(
            store
                .purge_expired_acme_challenges(now)
                .expect("purge succeeds"),
            1
        );
    }
}
