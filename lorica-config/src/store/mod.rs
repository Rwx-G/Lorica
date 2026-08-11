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
use rusqlite::{params, Connection};
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
        // Ensure schema_migrations table exists before querying it
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

        if current_version < 1 {
            tracing::info!("applying migration 001_initial");
            self.conn.execute_batch(MIGRATION_V1)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![1],
            )?;
        }

        if current_version < 2 {
            // Check if column already exists (another process may have added it)
            let has_column: bool = self
                .conn
                .prepare("SELECT COUNT(*) FROM pragma_table_info('backends') WHERE name='health_check_path'")?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;

            if !has_column {
                tracing::info!("applying migration 002_add_health_check_path");
                self.conn.execute_batch(MIGRATION_V2)?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![2],
            )?;
        }

        if current_version < 3 {
            tracing::info!("applying migration 003_sla_metrics");
            self.conn.execute_batch(MIGRATION_V3)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![3],
            )?;
        }

        if current_version < 4 {
            tracing::info!("applying migration 004_probe_configs");
            self.conn.execute_batch(MIGRATION_V4)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![4],
            )?;
        }

        if current_version < 5 {
            tracing::info!("applying migration 005_load_tests");
            self.conn.execute_batch(MIGRATION_V5)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![5],
            )?;
        }

        if current_version < 6 {
            let has_column: bool = self
                .conn
                .prepare("SELECT COUNT(*) FROM pragma_table_info('sla_buckets') WHERE name='cfg_max_latency_ms'")?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;

            if !has_column {
                tracing::info!("applying migration 006_sla_bucket_config_snapshot");
                self.conn.execute_batch(MIGRATION_V6)?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![6],
            )?;
        }

        if current_version < 7 {
            let has_column: bool = self
                .conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('routes') WHERE name='force_https'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;

            if !has_column {
                tracing::info!("applying migration 007_route_config");
                self.conn.execute_batch(MIGRATION_V7)?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![7],
            )?;
        }

        if current_version < 8 {
            let has_column: bool = self
                .conn
                .prepare("SELECT COUNT(*) FROM pragma_table_info('backends') WHERE name='name'")?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;

            if !has_column {
                tracing::info!("applying migration 008_backend_name_group");
                self.conn.execute_batch(MIGRATION_V8)?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![8],
            )?;
        }

        if current_version < 9 {
            let has_column: bool = self
                .conn
                .prepare(
                    "SELECT COUNT(*) FROM pragma_table_info('routes') WHERE name='cache_enabled'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;

            if !has_column {
                tracing::info!("applying migration 009_cache_and_protection");
                self.conn.execute_batch(MIGRATION_V9)?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![9],
            )?;
        }

        if current_version < 10 {
            tracing::info!("applying migration 010_sla_default_range");
            self.conn.execute_batch(MIGRATION_V10)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![10],
            )?;
        }

        if current_version < 11 {
            tracing::info!("applying migration 011_backend_h2_upstream");
            self.conn.execute_batch(MIGRATION_V11)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![11],
            )?;
        }

        if current_version < 12 {
            tracing::info!("applying migration 012_route_regex_rewrite");
            self.conn.execute_batch(MIGRATION_V12)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![12],
            )?;
        }

        if current_version < 13 {
            tracing::info!("applying migration 013_waf_persistence");
            self.conn.execute_batch(MIGRATION_V13)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![13],
            )?;
        }

        if current_version < 14 {
            tracing::info!("applying migration 014_backend_tls_sni");
            self.conn.execute_batch(MIGRATION_V14)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![14],
            )?;
        }

        if current_version < 15 {
            tracing::info!("applying migration 015_probe_results");
            self.conn.execute_batch(MIGRATION_V15)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![15],
            )?;
        }

        if current_version < 16 {
            tracing::info!("applying migration 016_backend_tls_skip_verify");
            self.conn.execute_batch(MIGRATION_V16)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![16],
            )?;
        }

        if current_version < 17 {
            if let Err(e) = self.conn.execute(
                "ALTER TABLE routes ADD COLUMN redirect_to TEXT DEFAULT NULL",
                [],
            ) {
                tracing::debug!("redirect_to column may already exist: {e}");
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![17],
            )?;
        }

        if current_version < 18 {
            let _ = self.conn.execute(
                "ALTER TABLE routes ADD COLUMN path_rules TEXT DEFAULT '[]'",
                [],
            );
            let _ = self.conn.execute(
                "ALTER TABLE routes ADD COLUMN return_status INTEGER DEFAULT NULL",
                [],
            );
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![18],
            )?;
        }

        // Unconditional column additions (idempotent, let _ = ignores "already exists")
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN sticky_session INTEGER NOT NULL DEFAULT 0",
            [],
        );

        if current_version < 19 {
            tracing::info!("applying migration 017_acme_method");
            self.conn.execute_batch(MIGRATION_V17)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![19],
            )?;
        }

        if current_version < 20 {
            tracing::info!("applying migration 018_dns_providers");
            // Table creation is idempotent; ALTER TABLE may fail if column already exists.
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS dns_providers (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    provider_type TEXT NOT NULL,
                    config TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );",
            )?;
            if let Err(e) = self.conn.execute(
                "ALTER TABLE certificates ADD COLUMN acme_dns_provider_id TEXT DEFAULT NULL",
                [],
            ) {
                tracing::debug!("acme_dns_provider_id column may already exist: {e}");
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![20],
            )?;
        }

        if current_version < 21 {
            tracing::info!("applying migration 019_sessions");
            self.conn.execute_batch(MIGRATION_V19)?;
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![21],
            )?;
        }

        // V22: basic auth per route
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN basic_auth_username TEXT DEFAULT NULL",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN basic_auth_password_hash TEXT DEFAULT NULL",
            [],
        );

        // V23: stale cache config per route
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN stale_while_revalidate_s INTEGER NOT NULL DEFAULT 10",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN stale_if_error_s INTEGER NOT NULL DEFAULT 60",
            [],
        );

        // V24: retry_on_methods
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN retry_on_methods TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // V24: maintenance mode + custom error pages
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN maintenance_mode INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN error_page_html TEXT DEFAULT NULL",
            [],
        );

        // V25: per-route cache variance headers
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN cache_vary_headers TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // V26: header-based routing rules (A/B testing, multi-tenant)
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN header_rules TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // V27: canary traffic splits (percent-based backend diversion)
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN traffic_splits TEXT NOT NULL DEFAULT '[]'",
            [],
        );

        // V28: forward-auth per route (Authelia / Authentik / Keycloak).
        // Stored as a JSON blob or NULL (feature off by default).
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN forward_auth TEXT DEFAULT NULL",
            [],
        );

        // V29: request mirroring (shadow testing). JSON blob or NULL.
        let _ = self
            .conn
            .execute("ALTER TABLE routes ADD COLUMN mirror TEXT DEFAULT NULL", []);

        // V30: response body rewriting (Nginx sub_filter equivalent).
        // JSON blob or NULL (feature off by default).
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN response_rewrite TEXT DEFAULT NULL",
            [],
        );

        // V31: mTLS client verification (per-route CA + required flag +
        // org allowlist). JSON blob or NULL.
        let _ = self
            .conn
            .execute("ALTER TABLE routes ADD COLUMN mtls TEXT DEFAULT NULL", []);

        // V32: indexes on sessions(expires_at) and sessions(user_id).
        // The session GC scans expired rows on every tick and the
        // password-change flow deletes sessions for one user; both
        // queries were full-table scans before this index. CREATE
        // INDEX IF NOT EXISTS is idempotent so the migration is safe
        // to re-run.
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",
            [],
        );
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            [],
        );

        // V33: per-route token-bucket rate limit (WPAR-1 / Phase 3d).
        // JSON blob or NULL (feature off by default). Schema:
        //   { "capacity": u32, "refill_per_sec": u32,
        //     "scope": "per_ip" | "per_route" }
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN rate_limit TEXT DEFAULT NULL",
            [],
        );

        // V34: per-route GeoIP country filter (v1.4.0 Epic 2 story 2.2).
        // JSON blob or NULL (feature off by default). Schema:
        //   { "mode": "allowlist" | "denylist",
        //     "countries": ["FR", "DE", ...] }
        // The supervisor's shared-memory `.mmdb` reader (loaded from
        // `GlobalSettings.geoip_db_path`) is the lookup source; a NULL
        // column skips the GeoIP check entirely for that route.
        let _ = self
            .conn
            .execute("ALTER TABLE routes ADD COLUMN geoip TEXT DEFAULT NULL", []);

        // V35: per-route bot-protection challenge (v1.4.0 Epic 3
        // story 3.3). JSON blob or NULL (feature off by default).
        // Schema: serde-serialised `BotProtectionConfig` with mode,
        // cookie_ttl_s, pow_difficulty, captcha_alphabet, bypass
        // (ip_cidrs / asns / countries / user_agents / rdns), and
        // only_country. NULL column = request_filter skips the
        // bot-protection stage for this route.
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN bot_protection TEXT DEFAULT NULL",
            [],
        );

        // V36: cross-worker bot-protection pending-challenge stash
        // (v1.4.0 Epic 3 follow-up closing the per-worker-stash
        // deferred item). Each row = one pending PoW or captcha
        // challenge waiting for the client to solve. SQLite-backed
        // so a client solving on worker A can submit on worker B;
        // the DELETE RETURNING on take() gives atomic "first solver
        // wins" semantics across workers without any RPC.
        //   - nonce (hex): primary key, 32 chars for PoW / 32 for
        //     captcha. Generated with `OsRng`, unpredictable.
        //   - kind: "pow" or "captcha" — deserialise dispatch key.
        //   - payload: JSON blob of the mode-specific fields.
        //     PoW: { nonce_hex, difficulty }; captcha:
        //     { expected_text } (PNG bytes are stored in the
        //     separate `png_bytes` column for binary efficiency).
        //   - mode: numeric value of `lorica_challenge::Mode`
        //     (1 = Cookie, 2 = Javascript, 3 = Captcha) so the
        //     verdict cookie payload can be rebuilt.
        //   - route_id: the route_id the cookie will be bound to.
        //   - ip_prefix_disc + ip_prefix_bytes: client IP prefix
        //     (/24 or /64) so the solve handler rejects a network
        //     change mid-challenge.
        //   - return_url: where the client bounces to on success.
        //   - cookie_ttl_s: u32, copied from the route config at
        //     stash time so a route edit between stash+solve does
        //     not re-sign cookies with an unexpected TTL.
        //   - expires_at: UNIX seconds, stash-time + 5 min.
        //   - png_bytes: captcha image BLOB. NULL for PoW entries.
        let _ = self.conn.execute_batch(
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
        );

        // V37: per-route group_name (v1.4.1 dashboard UX). Free-form
        // classification label mirroring `Backend.group_name` so
        // operators can filter / group routes in the dashboard
        // (prod / staging / homelab / legacy, etc.). Pure metadata -
        // never read on the proxy hot path, never exposed as a
        // Prometheus label (bounded-cardinality concern). Empty
        // string = ungrouped.
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN group_name TEXT NOT NULL DEFAULT ''",
            [],
        );

        // V38: per-pattern ACL for the certificate export zone
        // (v1.4.1). One row = one rule. Exporter walks ACLs in
        // longest-pattern-first order and applies the first match's
        // uid / gid instead of the global default. `allowed_uid` and
        // `allowed_gid` are NULLable so an ACL can override only the
        // group without touching the owner, or vice versa.
        let _ = self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cert_export_acls (
                id TEXT PRIMARY KEY,
                hostname_pattern TEXT NOT NULL,
                allowed_uid INTEGER,
                allowed_gid INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        );

        // V39: per-route AI / LLM crawler deny-list policy (Story
        // 8.2 AC #2 + #3). `ai_bot_policy` is one of the
        // serde-rendered enum strings ("off" / "deny" / "log") or
        // NULL for the absent / Off semantic. `ai_bot_spoofed_fallback`
        // is one of "deny" / "log" / "allow" or NULL to defer to the
        // global `GlobalSettings.ai_bot_treat_spoofed_as` (default
        // "deny"). CHECK constraint enforced at the API boundary
        // via serde-derive parsing of the enum (the validation-split
        // convention documented at the top of this file).
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN ai_bot_policy TEXT DEFAULT NULL",
            [],
        );
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN ai_bot_spoofed_fallback TEXT DEFAULT NULL",
            [],
        );

        // V40: custom AI-crawler registry (Story 8.2 AC #6). One row
        // = one operator-defined entry merged with the built-in
        // BUILTIN_CRAWLERS list at request-evaluation time
        // (custom-wins-on-conflict per `name`). `verification_kind`
        // is one of 'rdns' | 'ip_ranges' | 'ua_only' ;
        // `verification_data` carries a JSON blob :
        //   {"suffixes": [".x.com", ...]}     for 'rdns'
        //   {"cidrs": ["1.2.3.0/24", ...]}    for 'ip_ranges'
        //   NULL                               for 'ua_only'
        // JSON-blob convention mirrors `routes.aliases_json` /
        // `routes.path_rules` rather than a comma-separated TEXT
        // (avoids the comma-in-suffix edge case).
        let _ = self.conn.execute_batch(
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
        );

        // V41: per-route auto-served /robots.txt opt-in (Story 8.2
        // AC #10). Default 0 (false) preserves backward compat -
        // existing deployments keep passthrough to backend. When 1
        // (true), Lorica intercepts GET /robots.txt for this route
        // and serves a registry-driven body filtered to crawlers
        // with `ai_bot_policy != Off` on this route. No global
        // toggle by design (avoids silent default-behaviour change
        // on upgrade).
        let _ = self.conn.execute(
            "ALTER TABLE routes ADD COLUMN serve_robots_txt INTEGER NOT NULL DEFAULT 0",
            [],
        );

        // V22 (real version gate - first since 21): `users` table
        // replaces `admin_users` (Story 8.3 RBAC). This one carries a
        // data backfill (the single pre-RBAC admin row migrates as
        // role = 'super_admin') so it CANNOT be an ungated idempotent
        // ALTER like the V22-V41 blocks above: the backfill must run
        // exactly once. Concurrent-open safety (supervisor + workers
        // race the migration at boot): the backfill + drop only run
        // while `admin_users` still exists, so the losing process
        // skips them cleanly.
        if current_version < 22 {
            tracing::info!("applying migration 022_users_rbac");
            self.conn.execute_batch(
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
            let has_admin_users: bool = self
                .conn
                .prepare(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='admin_users'",
                )?
                .query_row([], |row| row.get::<_, i64>(0))
                .map(|c| c > 0)?;
            if has_admin_users {
                self.conn.execute_batch(
                    "INSERT OR IGNORE INTO users
                        (id, username, password_hash, role, must_change_password,
                         created_at, last_login_at)
                     SELECT id, username, password_hash, 'super_admin',
                            must_change_password, created_at, last_login
                     FROM admin_users;
                     DROP TABLE admin_users;",
                )?;
            }
            self.conn.execute(
                "INSERT OR IGNORE INTO schema_migrations (version) VALUES (?1)",
                params![22],
            )?;
        }

        // V43: per-prefix index for the bot-stash per-IP-prefix cap
        // (Story 8.9 AC #6). The COUNT on (disc, bytes) runs on every
        // challenge issuance; without the index it is a full-table
        // scan of up to bot_stash_max_entries rows.
        let _ = self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bot_pending_prefix
             ON bot_pending_challenges(ip_prefix_disc, ip_prefix_bytes)",
            [],
        );

        // V42: sessions carry the owning user's role so `require_auth`
        // can authorise without a per-request users read. Default
        // 'super_admin' covers pre-RBAC rows: every session minted
        // before this migration belongs to the single admin account,
        // and sessions are 30-minute ephemeral anyway. Role changes
        // invalidate the user's sessions (Story 8.3), so a stale
        // denormalised role cannot outlive a demotion.
        let _ = self.conn.execute(
            "ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'super_admin'",
            [],
        );

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

    /// Re-encrypt all secrets (certificate private keys and notification configs)
    /// from the current encryption key to a new one. Runs in a single transaction.
    pub fn rotate_encryption_key(&self, new_key: &EncryptionKey) -> Result<u32> {
        let tx = self
            .conn
            .unchecked_transaction()
            .map_err(|e| ConfigError::Validation(format!("failed to begin transaction: {e}")))?;

        let mut count = 0u32;

        // Re-encrypt certificate private keys (key_pem is BLOB)
        let mut stmt = tx.prepare("SELECT id, key_pem FROM certificates")?;
        let certs: Vec<(String, Vec<u8>)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for (id, encrypted_key_pem) in &certs {
            let plaintext = self.decrypt_key_pem(encrypted_key_pem)?;
            let re_encrypted = new_key.encrypt(plaintext.as_bytes())?;
            tx.execute(
                "UPDATE certificates SET key_pem = ?1 WHERE id = ?2",
                params![re_encrypted, id],
            )?;
            count += 1;
        }

        // Re-encrypt notification configs (config is TEXT, base64-encoded)
        let mut stmt = tx.prepare("SELECT id, config FROM notification_configs")?;
        let configs: Vec<(String, String)> = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        for (id, encrypted_config) in &configs {
            let plaintext = self.decrypt_config(encrypted_config)?;
            let re_encrypted = new_key.encrypt(plaintext.as_bytes())?;
            let re_encoded = base64::engine::general_purpose::STANDARD.encode(&re_encrypted);
            tx.execute(
                "UPDATE notification_configs SET config = ?1 WHERE id = ?2",
                params![re_encoded, id],
            )?;
            count += 1;
        }

        tx.commit()
            .map_err(|e| ConfigError::Validation(format!("failed to commit transaction: {e}")))?;

        Ok(count)
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
