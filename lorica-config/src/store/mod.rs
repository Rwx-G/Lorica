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

use std::path::Path;

use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::crypto::EncryptionKey;
use crate::error::{ConfigError, Result};

mod ai_crawlers;
mod backends;
pub mod bot_stash;
mod cert_export_acls;
mod certs;
mod dns_providers;
mod loadtest;
mod notifications;
mod preferences;
mod probes;
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
];

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
    add_column_if_absent(conn, "routes", "sticky_session", "INTEGER NOT NULL DEFAULT 0")
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
    add_column_if_absent(conn, "routes", "stale_if_error_s", "INTEGER NOT NULL DEFAULT 60")
}

fn migrate_route_retry_on_methods(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "retry_on_methods", "TEXT NOT NULL DEFAULT '[]'")
}

fn migrate_route_maintenance(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "maintenance_mode", "INTEGER NOT NULL DEFAULT 0")?;
    add_column_if_absent(conn, "routes", "error_page_html", "TEXT DEFAULT NULL")
}

fn migrate_route_cache_vary_headers(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "cache_vary_headers", "TEXT NOT NULL DEFAULT '[]'")
}

fn migrate_route_header_rules(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "header_rules", "TEXT NOT NULL DEFAULT '[]'")
}

fn migrate_route_traffic_splits(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "routes", "traffic_splits", "TEXT NOT NULL DEFAULT '[]'")
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
    add_column_if_absent(conn, "routes", "ai_bot_spoofed_fallback", "TEXT DEFAULT NULL")
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
    add_column_if_absent(conn, "routes", "serve_robots_txt", "INTEGER NOT NULL DEFAULT 0")
}

fn migrate_bot_pending_prefix_index(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_bot_pending_prefix
         ON bot_pending_challenges(ip_prefix_disc, ip_prefix_bytes);",
    )
}

fn migrate_session_role(conn: &Connection) -> rusqlite::Result<()> {
    add_column_if_absent(conn, "sessions", "role", "TEXT NOT NULL DEFAULT 'super_admin'")
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
                        let plaintext = self.decrypt_key_pem(stored)?;
                        let re_encrypted =
                            Self::reencrypt_verified(new_key, plaintext.as_bytes())?;
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
                        let re_encrypted =
                            Self::reencrypt_verified(new_key, plaintext.as_bytes())?;
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
                        let re_encrypted =
                            Self::reencrypt_verified(new_key, plaintext.as_bytes())?;
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
        for column in ["bot_protection", "header_rules", "serve_robots_txt", "group_name"] {
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
}
