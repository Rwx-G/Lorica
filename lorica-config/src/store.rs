use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json;
use uuid::Uuid;

use crate::crypto::EncryptionKey;
use crate::error::{ConfigError, Result};
use crate::models::*;

const MIGRATION_V1: &str = include_str!("migrations/001_initial.sql");
const MIGRATION_V2: &str = include_str!("migrations/002_add_health_check_path.sql");
const MIGRATION_V3: &str = include_str!("migrations/003_sla_metrics.sql");
const MIGRATION_V4: &str = include_str!("migrations/004_probe_configs.sql");
const MIGRATION_V5: &str = include_str!("migrations/005_load_tests.sql");
const MIGRATION_V6: &str = include_str!("migrations/006_sla_bucket_config_snapshot.sql");
const MIGRATION_V7: &str = include_str!("migrations/007_route_config.sql");
const MIGRATION_V8: &str = include_str!("migrations/008_backend_name_group.sql");
const MIGRATION_V9: &str = include_str!("migrations/009_cache_and_protection.sql");
const MIGRATION_V10: &str = include_str!("migrations/010_sla_default_range.sql");
const MIGRATION_V11: &str = include_str!("migrations/011_backend_h2_upstream.sql");
const MIGRATION_V12: &str = include_str!("migrations/012_route_regex_rewrite.sql");
const MIGRATION_V13: &str = include_str!("migrations/013_waf_persistence.sql");

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

    fn encrypt_key_pem(&self, key_pem: &str) -> Result<Vec<u8>> {
        match &self.encryption_key {
            Some(key) => key.encrypt(key_pem.as_bytes()),
            None => Ok(key_pem.as_bytes().to_vec()),
        }
    }

    fn decrypt_key_pem(&self, data: &[u8]) -> Result<String> {
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

    // ---- Routes ----

    /// Check that no other route uses any of the given hostnames (primary or alias).
    /// Returns an error naming the conflicting hostname and route if found.
    fn validate_hostname_uniqueness(
        &self,
        route_id: &str,
        hostname: &str,
        aliases: &[String],
    ) -> Result<()> {
        // Collect all hostnames to check
        let mut check: Vec<&str> = vec![hostname];
        for a in aliases {
            check.push(a.as_str());
        }

        // Check against all existing routes
        let mut stmt = self
            .conn
            .prepare("SELECT id, hostname, hostname_aliases FROM routes WHERE id != ?1")?;
        let rows = stmt.query_map(params![route_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;

        for row in rows {
            let (other_id, other_host, aliases_json) = row?;
            let other_aliases: Vec<String> =
                serde_json::from_str(&aliases_json).unwrap_or_default();

            for h in &check {
                if *h == other_host {
                    return Err(ConfigError::Validation(format!(
                        "hostname '{h}' already used by route {other_id}"
                    )));
                }
                if other_aliases.iter().any(|a| a == *h) {
                    return Err(ConfigError::Validation(format!(
                        "hostname '{h}' already used as alias on route {other_id}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Insert a new route into the database.
    pub fn create_route(&self, route: &Route) -> Result<()> {
        self.validate_hostname_uniqueness(&route.id, &route.hostname, &route.hostname_aliases)?;

        let hostname_aliases_json = serde_json::to_string(&route.hostname_aliases)
            .map_err(|e| ConfigError::Validation(format!("invalid hostname_aliases: {e}")))?;
        let proxy_headers_json = serde_json::to_string(&route.proxy_headers)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers: {e}")))?;
        let response_headers_json = serde_json::to_string(&route.response_headers)
            .map_err(|e| ConfigError::Validation(format!("invalid response_headers: {e}")))?;
        let proxy_headers_remove_json = serde_json::to_string(&route.proxy_headers_remove)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers_remove: {e}")))?;
        let response_headers_remove_json = serde_json::to_string(&route.response_headers_remove)
            .map_err(|e| {
                ConfigError::Validation(format!("invalid response_headers_remove: {e}"))
            })?;
        let ip_allowlist_json = serde_json::to_string(&route.ip_allowlist)
            .map_err(|e| ConfigError::Validation(format!("invalid ip_allowlist: {e}")))?;
        let ip_denylist_json = serde_json::to_string(&route.ip_denylist)
            .map_err(|e| ConfigError::Validation(format!("invalid ip_denylist: {e}")))?;
        let cors_allowed_origins_json = serde_json::to_string(&route.cors_allowed_origins)
            .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_origins: {e}")))?;
        let cors_allowed_methods_json = serde_json::to_string(&route.cors_allowed_methods)
            .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_methods: {e}")))?;

        self.conn.execute(
            "INSERT INTO routes (id, hostname, path_prefix, certificate_id, load_balancing,
             waf_enabled, waf_mode, topology_type, enabled,
             force_https, redirect_hostname, hostname_aliases,
             proxy_headers, response_headers, security_headers,
             connect_timeout_s, read_timeout_s, send_timeout_s,
             strip_path_prefix, add_path_prefix,
             path_rewrite_pattern, path_rewrite_replacement,
             access_log_enabled,
             proxy_headers_remove, response_headers_remove,
             max_request_body_bytes, websocket_enabled,
             rate_limit_rps, rate_limit_burst,
             ip_allowlist, ip_denylist,
             cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
             compression_enabled, retry_attempts,
             cache_enabled, cache_ttl_s, cache_max_bytes,
             max_connections, slowloris_threshold_ms,
             auto_ban_threshold, auto_ban_duration_s,
             created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22,
                     ?23, ?24, ?25, ?26, ?27, ?28, ?29, ?30, ?31, ?32, ?33,
                     ?34, ?35, ?36, ?37, ?38, ?39, ?40, ?41, ?42, ?43, ?44, ?45)",
            params![
                route.id,
                route.hostname,
                route.path_prefix,
                route.certificate_id,
                route.load_balancing.as_str(),
                route.waf_enabled,
                route.waf_mode.as_str(),
                route.topology_type.as_str(),
                route.enabled,
                route.force_https,
                route.redirect_hostname,
                hostname_aliases_json,
                proxy_headers_json,
                response_headers_json,
                route.security_headers,
                route.connect_timeout_s,
                route.read_timeout_s,
                route.send_timeout_s,
                route.strip_path_prefix,
                route.add_path_prefix,
                route.path_rewrite_pattern,
                route.path_rewrite_replacement,
                route.access_log_enabled,
                proxy_headers_remove_json,
                response_headers_remove_json,
                route.max_request_body_bytes.map(|v| v as i64),
                route.websocket_enabled,
                route.rate_limit_rps.map(|v| v as i32),
                route.rate_limit_burst.map(|v| v as i32),
                ip_allowlist_json,
                ip_denylist_json,
                cors_allowed_origins_json,
                cors_allowed_methods_json,
                route.cors_max_age_s,
                route.compression_enabled,
                route.retry_attempts.map(|v| v as i32),
                route.cache_enabled,
                route.cache_ttl_s,
                route.cache_max_bytes,
                route.max_connections.map(|v| v as i32),
                route.slowloris_threshold_ms,
                route.auto_ban_threshold.map(|v| v as i32),
                route.auto_ban_duration_s,
                route.created_at.to_rfc3339(),
                route.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a route by ID, or `None` if not found.
    pub fn get_route(&self, id: &str) -> Result<Option<Route>> {
        self.conn
            .query_row(
                "SELECT id, hostname, path_prefix, certificate_id, load_balancing,
                 waf_enabled, waf_mode, topology_type, enabled,
                 force_https, redirect_hostname, hostname_aliases,
                 proxy_headers, response_headers, security_headers,
                 connect_timeout_s, read_timeout_s, send_timeout_s,
                 strip_path_prefix, add_path_prefix,
                 path_rewrite_pattern, path_rewrite_replacement,
                 access_log_enabled,
                 proxy_headers_remove, response_headers_remove,
                 max_request_body_bytes, websocket_enabled,
                 rate_limit_rps, rate_limit_burst,
                 ip_allowlist, ip_denylist,
                 cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
                 compression_enabled, retry_attempts,
                 cache_enabled, cache_ttl_s, cache_max_bytes,
                 max_connections, slowloris_threshold_ms,
                 auto_ban_threshold, auto_ban_duration_s,
                 created_at, updated_at
                 FROM routes WHERE id = ?1",
                params![id],
                |row| Ok(row_to_route(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all routes, ordered by hostname and path prefix.
    pub fn list_routes(&self) -> Result<Vec<Route>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, hostname, path_prefix, certificate_id, load_balancing,
             waf_enabled, waf_mode, topology_type, enabled,
             force_https, redirect_hostname, hostname_aliases,
             proxy_headers, response_headers, security_headers,
             connect_timeout_s, read_timeout_s, send_timeout_s,
             strip_path_prefix, add_path_prefix,
             path_rewrite_pattern, path_rewrite_replacement,
             access_log_enabled,
             proxy_headers_remove, response_headers_remove,
             max_request_body_bytes, websocket_enabled,
             rate_limit_rps, rate_limit_burst,
             ip_allowlist, ip_denylist,
             cors_allowed_origins, cors_allowed_methods, cors_max_age_s,
             compression_enabled, retry_attempts,
             cache_enabled, cache_ttl_s, cache_max_bytes,
             max_connections, slowloris_threshold_ms,
             auto_ban_threshold, auto_ban_duration_s,
             created_at, updated_at
             FROM routes ORDER BY hostname, path_prefix",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_route(row)))?;
        let mut routes = Vec::new();
        for r in rows {
            routes.push(r??);
        }
        Ok(routes)
    }

    /// Update an existing route. Returns `NotFound` if the ID does not exist.
    pub fn update_route(&self, route: &Route) -> Result<()> {
        self.validate_hostname_uniqueness(&route.id, &route.hostname, &route.hostname_aliases)?;

        let hostname_aliases_json = serde_json::to_string(&route.hostname_aliases)
            .map_err(|e| ConfigError::Validation(format!("invalid hostname_aliases: {e}")))?;
        let proxy_headers_json = serde_json::to_string(&route.proxy_headers)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers: {e}")))?;
        let response_headers_json = serde_json::to_string(&route.response_headers)
            .map_err(|e| ConfigError::Validation(format!("invalid response_headers: {e}")))?;
        let proxy_headers_remove_json = serde_json::to_string(&route.proxy_headers_remove)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers_remove: {e}")))?;
        let response_headers_remove_json = serde_json::to_string(&route.response_headers_remove)
            .map_err(|e| {
                ConfigError::Validation(format!("invalid response_headers_remove: {e}"))
            })?;
        let ip_allowlist_json = serde_json::to_string(&route.ip_allowlist)
            .map_err(|e| ConfigError::Validation(format!("invalid ip_allowlist: {e}")))?;
        let ip_denylist_json = serde_json::to_string(&route.ip_denylist)
            .map_err(|e| ConfigError::Validation(format!("invalid ip_denylist: {e}")))?;
        let cors_allowed_origins_json = serde_json::to_string(&route.cors_allowed_origins)
            .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_origins: {e}")))?;
        let cors_allowed_methods_json = serde_json::to_string(&route.cors_allowed_methods)
            .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_methods: {e}")))?;

        let changed = self.conn.execute(
            "UPDATE routes SET hostname=?2, path_prefix=?3, certificate_id=?4,
             load_balancing=?5, waf_enabled=?6, waf_mode=?7, topology_type=?8,
             enabled=?9, force_https=?10, redirect_hostname=?11,
             hostname_aliases=?12, proxy_headers=?13, response_headers=?14,
             security_headers=?15, connect_timeout_s=?16, read_timeout_s=?17,
             send_timeout_s=?18, strip_path_prefix=?19, add_path_prefix=?20,
             path_rewrite_pattern=?21, path_rewrite_replacement=?22,
             access_log_enabled=?23, proxy_headers_remove=?24,
             response_headers_remove=?25, max_request_body_bytes=?26,
             websocket_enabled=?27, rate_limit_rps=?28, rate_limit_burst=?29,
             ip_allowlist=?30, ip_denylist=?31,
             cors_allowed_origins=?32, cors_allowed_methods=?33, cors_max_age_s=?34,
             compression_enabled=?35, retry_attempts=?36,
             cache_enabled=?37, cache_ttl_s=?38, cache_max_bytes=?39,
             max_connections=?40, slowloris_threshold_ms=?41,
             auto_ban_threshold=?42, auto_ban_duration_s=?43,
             updated_at=?44 WHERE id=?1",
            params![
                route.id,
                route.hostname,
                route.path_prefix,
                route.certificate_id,
                route.load_balancing.as_str(),
                route.waf_enabled,
                route.waf_mode.as_str(),
                route.topology_type.as_str(),
                route.enabled,
                route.force_https,
                route.redirect_hostname,
                hostname_aliases_json,
                proxy_headers_json,
                response_headers_json,
                route.security_headers,
                route.connect_timeout_s,
                route.read_timeout_s,
                route.send_timeout_s,
                route.strip_path_prefix,
                route.add_path_prefix,
                route.path_rewrite_pattern,
                route.path_rewrite_replacement,
                route.access_log_enabled,
                proxy_headers_remove_json,
                response_headers_remove_json,
                route.max_request_body_bytes.map(|v| v as i64),
                route.websocket_enabled,
                route.rate_limit_rps.map(|v| v as i32),
                route.rate_limit_burst.map(|v| v as i32),
                ip_allowlist_json,
                ip_denylist_json,
                cors_allowed_origins_json,
                cors_allowed_methods_json,
                route.cors_max_age_s,
                route.compression_enabled,
                route.retry_attempts.map(|v| v as i32),
                route.cache_enabled,
                route.cache_ttl_s,
                route.cache_max_bytes,
                route.max_connections.map(|v| v as i32),
                route.slowloris_threshold_ms,
                route.auto_ban_threshold.map(|v| v as i32),
                route.auto_ban_duration_s,
                route.updated_at.to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("route {}", route.id)));
        }
        Ok(())
    }

    /// Delete a route by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_route(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM routes WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("route {id}")));
        }
        Ok(())
    }

    // ---- Backends ----

    /// Validate that a backend address contains a port (ip:port format).
    fn validate_backend_address(address: &str) -> Result<()> {
        if !address.contains(':') || address.ends_with(':') {
            return Err(ConfigError::Validation(format!(
                "backend address must be in ip:port format (got '{address}')"
            )));
        }
        let port_str = address.rsplit(':').next().unwrap_or("");
        if port_str.parse::<u16>().is_err() {
            return Err(ConfigError::Validation(format!(
                "backend address has invalid port (got '{address}')"
            )));
        }
        Ok(())
    }

    /// Insert a new backend into the database.
    pub fn create_backend(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        self.conn.execute(
            "INSERT INTO backends (id, address, name, group_name, weight, health_status,
             health_check_enabled, health_check_interval_s, health_check_path,
             lifecycle_state, active_connections, tls_upstream, h2_upstream, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.created_at.to_rfc3339(),
                backend.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a backend by ID, or `None` if not found.
    pub fn get_backend(&self, id: &str) -> Result<Option<Backend>> {
        self.conn
            .query_row(
                "SELECT id, address, name, group_name, weight, health_status,
                 health_check_enabled, health_check_interval_s, health_check_path,
                 lifecycle_state, active_connections, tls_upstream, created_at, updated_at, h2_upstream
                 FROM backends WHERE id = ?1",
                params![id],
                |row| Ok(row_to_backend(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all backends, ordered by address.
    pub fn list_backends(&self) -> Result<Vec<Backend>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, name, group_name, weight, health_status,
             health_check_enabled, health_check_interval_s, health_check_path,
             lifecycle_state, active_connections, tls_upstream, created_at, updated_at, h2_upstream
             FROM backends ORDER BY address",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_backend(row)))?;
        let mut backends = Vec::new();
        for r in rows {
            backends.push(r??);
        }
        Ok(backends)
    }

    /// Update an existing backend. Returns `NotFound` if the ID does not exist.
    pub fn update_backend(&self, backend: &Backend) -> Result<()> {
        Self::validate_backend_address(&backend.address)?;
        let changed = self.conn.execute(
            "UPDATE backends SET address=?2, name=?3, group_name=?4, weight=?5,
             health_status=?6, health_check_enabled=?7, health_check_interval_s=?8,
             health_check_path=?9, lifecycle_state=?10, active_connections=?11,
             tls_upstream=?12, h2_upstream=?13, updated_at=?14 WHERE id=?1",
            params![
                backend.id,
                backend.address,
                backend.name,
                backend.group_name,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.h2_upstream,
                backend.updated_at.to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {}", backend.id)));
        }
        Ok(())
    }

    /// Delete a backend by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_backend(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM backends WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("backend {id}")));
        }
        Ok(())
    }

    // ---- Route-Backend associations ----

    /// Associate a backend with a route. Idempotent (ignores duplicates).
    pub fn link_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO route_backends (route_id, backend_id) VALUES (?1, ?2)",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

    /// Remove an association between a route and a backend.
    pub fn unlink_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM route_backends WHERE route_id=?1 AND backend_id=?2",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

    /// List backend IDs associated with a given route.
    pub fn list_backends_for_route(&self, route_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT backend_id FROM route_backends WHERE route_id=?1 ORDER BY backend_id",
        )?;
        let rows = stmt.query_map(params![route_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    /// List route IDs associated with a given backend.
    pub fn list_routes_for_backend(&self, backend_id: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT route_id FROM route_backends WHERE backend_id=?1 ORDER BY route_id")?;
        let rows = stmt.query_map(params![backend_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    // ---- Certificates ----

    /// Insert a new certificate. The `key_pem` field is encrypted at rest if an encryption key is configured.
    pub fn create_certificate(&self, cert: &Certificate) -> Result<()> {
        let san_json = serde_json::to_string(&cert.san_domains)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_key = self.encrypt_key_pem(&cert.key_pem)?;
        self.conn.execute(
            "INSERT INTO certificates (id, domain, san_domains, fingerprint, cert_pem, key_pem,
             issuer, not_before, not_after, is_acme, acme_auto_renew, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                cert.id,
                cert.domain,
                san_json,
                cert.fingerprint,
                cert.cert_pem,
                encrypted_key,
                cert.issuer,
                cert.not_before.to_rfc3339(),
                cert.not_after.to_rfc3339(),
                cert.is_acme,
                cert.acme_auto_renew,
                cert.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a certificate by ID, or `None` if not found. Decrypts `key_pem` transparently.
    pub fn get_certificate(&self, id: &str) -> Result<Option<Certificate>> {
        self.conn
            .query_row(
                "SELECT id, domain, san_domains, fingerprint, cert_pem, key_pem,
                 issuer, not_before, not_after, is_acme, acme_auto_renew, created_at
                 FROM certificates WHERE id = ?1",
                params![id],
                |row| Ok(self.row_to_certificate(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all certificates, ordered by domain. Decrypts `key_pem` transparently.
    pub fn list_certificates(&self) -> Result<Vec<Certificate>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, domain, san_domains, fingerprint, cert_pem, key_pem,
             issuer, not_before, not_after, is_acme, acme_auto_renew, created_at
             FROM certificates ORDER BY domain",
        )?;
        let rows = stmt.query_map([], |row| Ok(self.row_to_certificate(row)))?;
        let mut certs = Vec::new();
        for r in rows {
            certs.push(r??);
        }
        Ok(certs)
    }

    /// Update an existing certificate. Re-encrypts `key_pem` at rest.
    pub fn update_certificate(&self, cert: &Certificate) -> Result<()> {
        let san_json = serde_json::to_string(&cert.san_domains)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let encrypted_key = self.encrypt_key_pem(&cert.key_pem)?;
        let changed = self.conn.execute(
            "UPDATE certificates SET domain=?2, san_domains=?3, fingerprint=?4,
             cert_pem=?5, key_pem=?6, issuer=?7, not_before=?8, not_after=?9,
             is_acme=?10, acme_auto_renew=?11 WHERE id=?1",
            params![
                cert.id,
                cert.domain,
                san_json,
                cert.fingerprint,
                cert.cert_pem,
                encrypted_key,
                cert.issuer,
                cert.not_before.to_rfc3339(),
                cert.not_after.to_rfc3339(),
                cert.is_acme,
                cert.acme_auto_renew,
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("certificate {}", cert.id)));
        }
        Ok(())
    }

    /// Delete a certificate by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_certificate(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM certificates WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("certificate {id}")));
        }
        Ok(())
    }

    // ---- Notification Configs ----

    /// Insert a new notification configuration.
    pub fn create_notification_config(&self, nc: &NotificationConfig) -> Result<()> {
        let alert_json = serde_json::to_string(&nc.alert_types)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        self.conn.execute(
            "INSERT INTO notification_configs (id, channel, enabled, config, alert_types)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                nc.id,
                nc.channel.as_str(),
                nc.enabled,
                nc.config,
                alert_json,
            ],
        )?;
        Ok(())
    }

    /// Fetch a notification config by ID, or `None` if not found.
    pub fn get_notification_config(&self, id: &str) -> Result<Option<NotificationConfig>> {
        self.conn
            .query_row(
                "SELECT id, channel, enabled, config, alert_types
                 FROM notification_configs WHERE id = ?1",
                params![id],
                |row| Ok(row_to_notification_config(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all notification configs, ordered by channel.
    pub fn list_notification_configs(&self) -> Result<Vec<NotificationConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, channel, enabled, config, alert_types
             FROM notification_configs ORDER BY channel",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_notification_config(row)))?;
        let mut configs = Vec::new();
        for r in rows {
            configs.push(r??);
        }
        Ok(configs)
    }

    /// Update an existing notification config. Returns `NotFound` if the ID does not exist.
    pub fn update_notification_config(&self, nc: &NotificationConfig) -> Result<()> {
        let alert_json = serde_json::to_string(&nc.alert_types)
            .map_err(|e| ConfigError::Validation(e.to_string()))?;
        let changed = self.conn.execute(
            "UPDATE notification_configs SET channel=?2, enabled=?3, config=?4, alert_types=?5
             WHERE id=?1",
            params![
                nc.id,
                nc.channel.as_str(),
                nc.enabled,
                nc.config,
                alert_json
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "notification_config {}",
                nc.id
            )));
        }
        Ok(())
    }

    /// Delete a notification config by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_notification_config(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM notification_configs WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("notification_config {id}")));
        }
        Ok(())
    }

    // ---- User Preferences ----

    /// Insert a new user preference.
    pub fn create_user_preference(&self, pref: &UserPreference) -> Result<()> {
        self.conn.execute(
            "INSERT INTO user_preferences (id, preference_key, value, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                pref.id,
                pref.preference_key,
                pref.value.as_str(),
                pref.created_at.to_rfc3339(),
                pref.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Fetch a user preference by ID, or `None` if not found.
    pub fn get_user_preference(&self, id: &str) -> Result<Option<UserPreference>> {
        self.conn
            .query_row(
                "SELECT id, preference_key, value, created_at, updated_at
                 FROM user_preferences WHERE id = ?1",
                params![id],
                |row| Ok(row_to_user_preference(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch a user preference by its unique key, or `None` if not found.
    pub fn get_user_preference_by_key(&self, key: &str) -> Result<Option<UserPreference>> {
        self.conn
            .query_row(
                "SELECT id, preference_key, value, created_at, updated_at
                 FROM user_preferences WHERE preference_key = ?1",
                params![key],
                |row| Ok(row_to_user_preference(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all user preferences, ordered by key.
    pub fn list_user_preferences(&self) -> Result<Vec<UserPreference>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, preference_key, value, created_at, updated_at
             FROM user_preferences ORDER BY preference_key",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_user_preference(row)))?;
        let mut prefs = Vec::new();
        for r in rows {
            prefs.push(r??);
        }
        Ok(prefs)
    }

    /// Update an existing user preference. Returns `NotFound` if the ID does not exist.
    pub fn update_user_preference(&self, pref: &UserPreference) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE user_preferences SET preference_key=?2, value=?3, updated_at=?4
             WHERE id=?1",
            params![
                pref.id,
                pref.preference_key,
                pref.value.as_str(),
                pref.updated_at.to_rfc3339(),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!(
                "user_preference {}",
                pref.id
            )));
        }
        Ok(())
    }

    /// Delete a user preference by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_user_preference(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM user_preferences WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("user_preference {id}")));
        }
        Ok(())
    }

    // ---- Admin Users ----

    /// Insert a new admin user.
    pub fn create_admin_user(&self, user: &AdminUser) -> Result<()> {
        self.conn.execute(
            "INSERT INTO admin_users (id, username, password_hash, must_change_password,
             created_at, last_login) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.must_change_password,
                user.created_at.to_rfc3339(),
                user.last_login.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Fetch an admin user by ID, or `None` if not found.
    pub fn get_admin_user(&self, id: &str) -> Result<Option<AdminUser>> {
        self.conn
            .query_row(
                "SELECT id, username, password_hash, must_change_password, created_at, last_login
                 FROM admin_users WHERE id = ?1",
                params![id],
                |row| Ok(row_to_admin_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch an admin user by username, or `None` if not found.
    pub fn get_admin_user_by_username(&self, username: &str) -> Result<Option<AdminUser>> {
        self.conn
            .query_row(
                "SELECT id, username, password_hash, must_change_password, created_at, last_login
                 FROM admin_users WHERE username = ?1",
                params![username],
                |row| Ok(row_to_admin_user(row)),
            )
            .optional()?
            .transpose()
    }

    /// List all admin users, ordered by username.
    pub fn list_admin_users(&self) -> Result<Vec<AdminUser>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, username, password_hash, must_change_password, created_at, last_login
             FROM admin_users ORDER BY username",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_admin_user(row)))?;
        let mut users = Vec::new();
        for r in rows {
            users.push(r??);
        }
        Ok(users)
    }

    /// Update an existing admin user. Returns `NotFound` if the ID does not exist.
    pub fn update_admin_user(&self, user: &AdminUser) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE admin_users SET username=?2, password_hash=?3, must_change_password=?4,
             last_login=?5 WHERE id=?1",
            params![
                user.id,
                user.username,
                user.password_hash,
                user.must_change_password,
                user.last_login.map(|t| t.to_rfc3339()),
            ],
        )?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("admin_user {}", user.id)));
        }
        Ok(())
    }

    /// Delete an admin user by ID. Returns `NotFound` if the ID does not exist.
    pub fn delete_admin_user(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM admin_users WHERE id=?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("admin_user {id}")));
        }
        Ok(())
    }

    // ---- Global Settings ----

    /// Read all global settings from the key-value table.
    pub fn get_global_settings(&self) -> Result<GlobalSettings> {
        let mut stmt = self
            .conn
            .prepare("SELECT key, value FROM global_settings")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut settings = GlobalSettings::default();
        for r in rows {
            let (key, value) = r?;
            match key.as_str() {
                "management_port" => {
                    settings.management_port = value
                        .parse()
                        .map_err(|_| ConfigError::Validation("invalid management_port".into()))?;
                }
                "log_level" => settings.log_level = value,
                "default_health_check_interval_s" => {
                    settings.default_health_check_interval_s = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid default_health_check_interval_s".into())
                    })?;
                }
                "cert_warning_days" => {
                    settings.cert_warning_days = value
                        .parse()
                        .map_err(|_| ConfigError::Validation("invalid cert_warning_days".into()))?;
                }
                "cert_critical_days" => {
                    settings.cert_critical_days = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid cert_critical_days".into())
                    })?;
                }
                "default_topology_type" => {
                    settings.default_topology_type = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid default_topology_type".into())
                    })?;
                }
                "ip_blocklist_enabled" => {
                    settings.ip_blocklist_enabled = value == "true" || value == "1";
                }
                "max_global_connections" => {
                    settings.max_global_connections = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid max_global_connections".into())
                    })?;
                }
                "flood_threshold_rps" => {
                    settings.flood_threshold_rps = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid flood_threshold_rps".into())
                    })?;
                }
                "custom_security_presets" => {
                    settings.custom_security_presets =
                        serde_json::from_str(&value).map_err(|e| {
                            ConfigError::Validation(format!(
                                "invalid custom_security_presets JSON: {e}"
                            ))
                        })?;
                }
                _ => {}
            }
        }
        Ok(settings)
    }

    /// Write all global settings to the key-value table (upsert).
    pub fn update_global_settings(&self, settings: &GlobalSettings) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('management_port', ?1)",
            params![settings.management_port.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('log_level', ?1)",
            params![settings.log_level],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('default_health_check_interval_s', ?1)",
            params![settings.default_health_check_interval_s.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('cert_warning_days', ?1)",
            params![settings.cert_warning_days.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('cert_critical_days', ?1)",
            params![settings.cert_critical_days.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('default_topology_type', ?1)",
            params![settings.default_topology_type.as_str()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('ip_blocklist_enabled', ?1)",
            params![settings.ip_blocklist_enabled.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('max_global_connections', ?1)",
            params![settings.max_global_connections.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('flood_threshold_rps', ?1)",
            params![settings.flood_threshold_rps.to_string()],
        )?;
        let presets_json =
            serde_json::to_string(&settings.custom_security_presets).map_err(|e| {
                ConfigError::Validation(format!("failed to serialize custom_security_presets: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('custom_security_presets', ?1)",
            params![presets_json],
        )?;
        Ok(())
    }

    // ---- WAF persistence ----

    /// Save the list of disabled WAF rule IDs as a JSON array in global settings.
    pub fn save_waf_disabled_rules(&self, rule_ids: &[u32]) -> Result<()> {
        let json = serde_json::to_string(rule_ids)
            .map_err(|e| ConfigError::Validation(format!("failed to serialize disabled rules: {e}")))?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('waf_disabled_rules', ?1)",
            params![json],
        )?;
        Ok(())
    }

    /// Load the list of disabled WAF rule IDs from global settings.
    pub fn load_waf_disabled_rules(&self) -> Result<Vec<u32>> {
        let json: Option<String> = self.conn.query_row(
            "SELECT value FROM global_settings WHERE key = 'waf_disabled_rules'",
            [],
            |row| row.get(0),
        ).optional()?;
        match json {
            Some(s) => serde_json::from_str(&s)
                .map_err(|e| ConfigError::Validation(format!("invalid waf_disabled_rules JSON: {e}"))),
            None => Ok(Vec::new()),
        }
    }

    /// Save a WAF custom rule to the database.
    pub fn save_waf_custom_rule(&self, id: u32, description: &str, category: &str, pattern: &str, severity: u8, enabled: bool) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO waf_custom_rules (id, description, category, pattern, severity, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, description, category, pattern, severity as i32, enabled],
        )?;
        Ok(())
    }

    /// Delete a WAF custom rule from the database.
    pub fn delete_waf_custom_rule(&self, id: u32) -> Result<()> {
        self.conn.execute("DELETE FROM waf_custom_rules WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// Load all WAF custom rules from the database.
    pub fn load_waf_custom_rules(&self) -> Result<Vec<(u32, String, String, String, u8, bool)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, description, category, pattern, severity, enabled FROM waf_custom_rules ORDER BY id"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i32>(4)? as u8,
                row.get::<_, bool>(5)?,
            ))
        })?;
        let mut rules = Vec::new();
        for r in rows {
            rules.push(r?);
        }
        Ok(rules)
    }

    // ---- Helpers for export/import ----

    /// List all route-backend associations, ordered by route then backend ID.
    pub fn list_route_backends(&self) -> Result<Vec<RouteBackend>> {
        let mut stmt = self.conn.prepare(
            "SELECT route_id, backend_id FROM route_backends ORDER BY route_id, backend_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RouteBackend {
                route_id: row.get(0)?,
                backend_id: row.get(1)?,
            })
        })?;
        let mut links = Vec::new();
        for r in rows {
            links.push(r?);
        }
        Ok(links)
    }

    /// Clear all data (used before import).
    pub fn clear_all(&self) -> Result<()> {
        self.conn.execute_batch(
            "DELETE FROM route_backends;
             DELETE FROM routes;
             DELETE FROM backends;
             DELETE FROM certificates;
             DELETE FROM notification_configs;
             DELETE FROM user_preferences;
             DELETE FROM admin_users;
             DELETE FROM global_settings;",
        )?;
        Ok(())
    }

    fn row_to_certificate(&self, row: &rusqlite::Row<'_>) -> Result<Certificate> {
        let san_json: String = row.get(2)?;
        let san_domains: Vec<String> = serde_json::from_str(&san_json)
            .map_err(|e| ConfigError::Validation(format!("invalid san_domains JSON: {e}")))?;
        let key_pem_raw: Vec<u8> = row.get(5)?;
        let key_pem = self.decrypt_key_pem(&key_pem_raw)?;
        Ok(Certificate {
            id: row.get(0)?,
            domain: row.get(1)?,
            san_domains,
            fingerprint: row.get(3)?,
            cert_pem: row.get(4)?,
            key_pem,
            issuer: row.get(6)?,
            not_before: parse_datetime(&row.get::<_, String>(7)?)?,
            not_after: parse_datetime(&row.get::<_, String>(8)?)?,
            is_acme: row.get(9)?,
            acme_auto_renew: row.get(10)?,
            created_at: parse_datetime(&row.get::<_, String>(11)?)?,
        })
    }

    // ---- SLA Configuration ----

    /// Get SLA configuration for a route. Returns default if none configured.
    pub fn get_sla_config(&self, route_id: &str) -> Result<SlaConfig> {
        let result = self
            .conn
            .query_row(
                "SELECT route_id, target_pct, max_latency_ms, success_status_min,
                 success_status_max, created_at, updated_at
                 FROM sla_configs WHERE route_id = ?1",
                params![route_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, i32>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .optional()?;

        match result {
            Some((
                route_id,
                target_pct,
                max_latency_ms,
                min_status,
                max_status,
                created,
                updated,
            )) => Ok(SlaConfig {
                route_id,
                target_pct,
                max_latency_ms,
                success_status_min: min_status,
                success_status_max: max_status,
                created_at: parse_datetime(&created)?,
                updated_at: parse_datetime(&updated)?,
            }),
            None => Ok(SlaConfig::default_for_route(route_id)),
        }
    }

    /// Upsert SLA configuration for a route.
    pub fn upsert_sla_config(&self, config: &SlaConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sla_configs (route_id, target_pct, max_latency_ms,
             success_status_min, success_status_max, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(route_id) DO UPDATE SET
                target_pct = excluded.target_pct,
                max_latency_ms = excluded.max_latency_ms,
                success_status_min = excluded.success_status_min,
                success_status_max = excluded.success_status_max,
                updated_at = excluded.updated_at",
            params![
                config.route_id,
                config.target_pct,
                config.max_latency_ms,
                config.success_status_min,
                config.success_status_max,
                config.created_at.to_rfc3339(),
                config.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all SLA configurations.
    pub fn list_sla_configs(&self) -> Result<Vec<SlaConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT route_id, target_pct, max_latency_ms, success_status_min,
             success_status_max, created_at, updated_at FROM sla_configs",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i32>(3)?,
                row.get::<_, i32>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
            ))
        })?;
        let mut configs = Vec::new();
        for row in rows {
            let (route_id, target_pct, max_latency_ms, min_s, max_s, created, updated) = row?;
            configs.push(SlaConfig {
                route_id,
                target_pct,
                max_latency_ms,
                success_status_min: min_s,
                success_status_max: max_s,
                created_at: parse_datetime(&created)?,
                updated_at: parse_datetime(&updated)?,
            });
        }
        Ok(configs)
    }

    // ---- SLA Buckets ----

    /// Insert an aggregated SLA bucket.
    pub fn insert_sla_bucket(&self, bucket: &SlaBucket) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sla_buckets
             (route_id, bucket_start, request_count, success_count, error_count,
              latency_sum_ms, latency_min_ms, latency_max_ms,
              latency_p50_ms, latency_p95_ms, latency_p99_ms, source,
              cfg_max_latency_ms, cfg_status_min, cfg_status_max, cfg_target_pct)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                bucket.route_id,
                bucket.bucket_start.to_rfc3339(),
                bucket.request_count,
                bucket.success_count,
                bucket.error_count,
                bucket.latency_sum_ms,
                bucket.latency_min_ms,
                bucket.latency_max_ms,
                bucket.latency_p50_ms,
                bucket.latency_p95_ms,
                bucket.latency_p99_ms,
                bucket.source,
                bucket.cfg_max_latency_ms,
                bucket.cfg_status_min,
                bucket.cfg_status_max,
                bucket.cfg_target_pct,
            ],
        )?;
        Ok(())
    }

    /// Query SLA buckets for a route within a time range.
    pub fn query_sla_buckets(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        source: &str,
    ) -> Result<Vec<SlaBucket>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, bucket_start, request_count, success_count, error_count,
             latency_sum_ms, latency_min_ms, latency_max_ms,
             latency_p50_ms, latency_p95_ms, latency_p99_ms, source,
             cfg_max_latency_ms, cfg_status_min, cfg_status_max, cfg_target_pct
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
             ORDER BY bucket_start ASC",
        )?;
        let rows = stmt.query_map(
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            row_to_sla_bucket,
        )?;
        let mut buckets = Vec::new();
        for row in rows {
            buckets.push(row??);
        }
        Ok(buckets)
    }

    /// Compute an SLA summary for a route over a time window.
    pub fn compute_sla_summary(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
        window_label: &str,
        source: &str,
    ) -> Result<SlaSummary> {
        let row = self.conn.query_row(
            "SELECT COALESCE(SUM(request_count), 0),
                    COALESCE(SUM(success_count), 0),
                    COALESCE(SUM(latency_sum_ms), 0)
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4",
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;
        let (total, success, latency_sum) = row;

        // Weighted percentiles: pick the median bucket values weighted by request count
        let percentiles = self.conn.query_row(
            "SELECT COALESCE(MAX(latency_p50_ms), 0),
                    COALESCE(MAX(latency_p95_ms), 0),
                    COALESCE(MAX(latency_p99_ms), 0)
             FROM sla_buckets
             WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4",
            params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )?;

        let sla_pct = if total > 0 {
            (success as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let avg_latency = if total > 0 {
            latency_sum as f64 / total as f64
        } else {
            0.0
        };

        // Use the snapshot target_pct from the most recent bucket in the window,
        // so historical queries reflect the config active at recording time.
        // Fall back to live config if no buckets exist yet.
        let snapshot_target: f64 = self
            .conn
            .query_row(
                "SELECT cfg_target_pct FROM sla_buckets
                 WHERE route_id = ?1 AND bucket_start >= ?2 AND bucket_start < ?3 AND source = ?4
                 ORDER BY bucket_start DESC LIMIT 1",
                params![route_id, from.to_rfc3339(), to.to_rfc3339(), source],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| {
                self.get_sla_config(route_id)
                    .map(|c| c.target_pct)
                    .unwrap_or(99.9)
            });

        Ok(SlaSummary {
            route_id: route_id.to_string(),
            window: window_label.to_string(),
            total_requests: total,
            successful_requests: success,
            sla_pct,
            avg_latency_ms: avg_latency,
            p50_latency_ms: percentiles.0,
            p95_latency_ms: percentiles.1,
            p99_latency_ms: percentiles.2,
            target_pct: snapshot_target,
            meets_target: sla_pct >= snapshot_target,
        })
    }

    /// Delete SLA buckets older than a given timestamp (for data retention).
    pub fn prune_sla_buckets(&self, before: &DateTime<Utc>) -> Result<usize> {
        let count = self.conn.execute(
            "DELETE FROM sla_buckets WHERE bucket_start < ?1",
            params![before.to_rfc3339()],
        )?;
        Ok(count)
    }

    /// Export SLA data as JSON for a route over a time range.
    pub fn export_sla_data(
        &self,
        route_id: &str,
        from: &DateTime<Utc>,
        to: &DateTime<Utc>,
    ) -> Result<serde_json::Value> {
        let buckets = self.query_sla_buckets(route_id, from, to, "passive")?;
        let config = self.get_sla_config(route_id)?;
        Ok(serde_json::json!({
            "route_id": route_id,
            "from": from.to_rfc3339(),
            "to": to.to_rfc3339(),
            "config": config,
            "buckets": buckets,
        }))
    }

    // ---- Probe Configuration ----

    /// Create a new probe configuration.
    pub fn create_probe_config(&self, probe: &ProbeConfig) -> Result<()> {
        self.conn.execute(
            "INSERT INTO probe_configs (id, route_id, method, path, expected_status,
             interval_s, timeout_ms, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                probe.id,
                probe.route_id,
                probe.method,
                probe.path,
                probe.expected_status,
                probe.interval_s,
                probe.timeout_ms,
                probe.enabled,
                probe.created_at.to_rfc3339(),
                probe.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all probe configurations.
    pub fn list_probe_configs(&self) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at FROM probe_configs",
        )?;
        let rows = stmt.query_map([], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    /// List probe configurations for a specific route.
    pub fn list_probes_for_route(&self, route_id: &str) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at
             FROM probe_configs WHERE route_id = ?1",
        )?;
        let rows = stmt.query_map(params![route_id], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    /// Get a single probe configuration by ID.
    pub fn get_probe_config(&self, id: &str) -> Result<Option<ProbeConfig>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, route_id, method, path, expected_status, interval_s,
                 timeout_ms, enabled, created_at, updated_at
                 FROM probe_configs WHERE id = ?1",
                params![id],
                row_to_probe_config,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Update a probe configuration.
    pub fn update_probe_config(&self, probe: &ProbeConfig) -> Result<()> {
        let affected = self.conn.execute(
            "UPDATE probe_configs SET method = ?1, path = ?2, expected_status = ?3,
             interval_s = ?4, timeout_ms = ?5, enabled = ?6, updated_at = ?7
             WHERE id = ?8",
            params![
                probe.method,
                probe.path,
                probe.expected_status,
                probe.interval_s,
                probe.timeout_ms,
                probe.enabled,
                probe.updated_at.to_rfc3339(),
                probe.id,
            ],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("probe config {}", probe.id)));
        }
        Ok(())
    }

    /// Delete a probe configuration.
    pub fn delete_probe_config(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM probe_configs WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("probe config {id}")));
        }
        Ok(())
    }

    /// List all enabled probes (for the scheduler).
    pub fn list_enabled_probes(&self) -> Result<Vec<ProbeConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, route_id, method, path, expected_status, interval_s,
             timeout_ms, enabled, created_at, updated_at
             FROM probe_configs WHERE enabled = 1",
        )?;
        let rows = stmt.query_map([], row_to_probe_config)?;
        let mut probes = Vec::new();
        for row in rows {
            probes.push(row??);
        }
        Ok(probes)
    }

    // ---- Load Test Configuration ----

    /// Create a new load test configuration.
    pub fn create_load_test_config(&self, config: &LoadTestConfig) -> Result<()> {
        let headers_json = serde_json::to_string(&config.headers)
            .map_err(|e| ConfigError::Validation(format!("invalid headers: {e}")))?;
        self.conn.execute(
            "INSERT INTO load_test_configs (id, name, target_url, method, headers, body,
             concurrency, requests_per_second, duration_s, error_threshold_pct,
             schedule_cron, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                config.id,
                config.name,
                config.target_url,
                config.method,
                headers_json,
                config.body,
                config.concurrency,
                config.requests_per_second,
                config.duration_s,
                config.error_threshold_pct,
                config.schedule_cron,
                config.enabled,
                config.created_at.to_rfc3339(),
                config.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List all load test configurations.
    pub fn list_load_test_configs(&self) -> Result<Vec<LoadTestConfig>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, target_url, method, headers, body, concurrency,
             requests_per_second, duration_s, error_threshold_pct, schedule_cron,
             enabled, created_at, updated_at FROM load_test_configs ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_load_test_config)?;
        let mut configs = Vec::new();
        for row in rows {
            configs.push(row??);
        }
        Ok(configs)
    }

    /// Get a single load test configuration by ID.
    pub fn get_load_test_config(&self, id: &str) -> Result<Option<LoadTestConfig>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, name, target_url, method, headers, body, concurrency,
                 requests_per_second, duration_s, error_threshold_pct, schedule_cron,
                 enabled, created_at, updated_at FROM load_test_configs WHERE id = ?1",
                params![id],
                row_to_load_test_config,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }

    /// Update a load test configuration.
    pub fn update_load_test_config(&self, config: &LoadTestConfig) -> Result<()> {
        let headers_json = serde_json::to_string(&config.headers)
            .map_err(|e| ConfigError::Validation(format!("invalid headers: {e}")))?;
        let affected = self.conn.execute(
            "UPDATE load_test_configs SET name = ?1, target_url = ?2, method = ?3,
             headers = ?4, body = ?5, concurrency = ?6, requests_per_second = ?7,
             duration_s = ?8, error_threshold_pct = ?9, schedule_cron = ?10,
             enabled = ?11, updated_at = ?12 WHERE id = ?13",
            params![
                config.name,
                config.target_url,
                config.method,
                headers_json,
                config.body,
                config.concurrency,
                config.requests_per_second,
                config.duration_s,
                config.error_threshold_pct,
                config.schedule_cron,
                config.enabled,
                config.updated_at.to_rfc3339(),
                config.id,
            ],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!(
                "load test config {}",
                config.id
            )));
        }
        Ok(())
    }

    /// Delete a load test configuration.
    pub fn delete_load_test_config(&self, id: &str) -> Result<()> {
        let affected = self
            .conn
            .execute("DELETE FROM load_test_configs WHERE id = ?1", params![id])?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!("load test config {id}")));
        }
        Ok(())
    }

    /// Clone a load test configuration with a new ID and name suffix.
    pub fn clone_load_test_config(
        &self,
        source_id: &str,
        new_name: &str,
    ) -> Result<LoadTestConfig> {
        let source = self
            .get_load_test_config(source_id)?
            .ok_or_else(|| ConfigError::NotFound(format!("load test config {source_id}")))?;
        let now = Utc::now();
        let cloned = LoadTestConfig {
            id: new_id(),
            name: new_name.to_string(),
            created_at: now,
            updated_at: now,
            schedule_cron: None,
            ..source
        };
        self.create_load_test_config(&cloned)?;
        Ok(cloned)
    }

    // ---- Load Test Results ----

    /// Insert a load test result.
    pub fn insert_load_test_result(&self, result: &LoadTestResult) -> Result<()> {
        self.conn.execute(
            "INSERT INTO load_test_results (id, config_id, started_at, finished_at,
             total_requests, successful_requests, failed_requests, avg_latency_ms,
             p50_latency_ms, p95_latency_ms, p99_latency_ms, min_latency_ms,
             max_latency_ms, throughput_rps, aborted, abort_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                result.id,
                result.config_id,
                result.started_at.to_rfc3339(),
                result.finished_at.to_rfc3339(),
                result.total_requests,
                result.successful_requests,
                result.failed_requests,
                result.avg_latency_ms,
                result.p50_latency_ms,
                result.p95_latency_ms,
                result.p99_latency_ms,
                result.min_latency_ms,
                result.max_latency_ms,
                result.throughput_rps,
                result.aborted,
                result.abort_reason,
            ],
        )?;
        Ok(())
    }

    /// List results for a load test config, most recent first.
    pub fn list_load_test_results(&self, config_id: &str) -> Result<Vec<LoadTestResult>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, config_id, started_at, finished_at, total_requests,
             successful_requests, failed_requests, avg_latency_ms, p50_latency_ms,
             p95_latency_ms, p99_latency_ms, min_latency_ms, max_latency_ms,
             throughput_rps, aborted, abort_reason
             FROM load_test_results WHERE config_id = ?1 ORDER BY started_at DESC",
        )?;
        let rows = stmt.query_map(params![config_id], row_to_load_test_result)?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row??);
        }
        Ok(results)
    }

    /// Get the most recent result for a load test config.
    pub fn get_latest_load_test_result(&self, config_id: &str) -> Result<Option<LoadTestResult>> {
        let result = self
            .conn
            .query_row(
                "SELECT id, config_id, started_at, finished_at, total_requests,
                 successful_requests, failed_requests, avg_latency_ms, p50_latency_ms,
                 p95_latency_ms, p99_latency_ms, min_latency_ms, max_latency_ms,
                 throughput_rps, aborted, abort_reason
                 FROM load_test_results WHERE config_id = ?1
                 ORDER BY started_at DESC LIMIT 1",
                params![config_id],
                row_to_load_test_result,
            )
            .optional()?;
        match result {
            Some(r) => Ok(Some(r?)),
            None => Ok(None),
        }
    }
}

// ---- Row mapping helpers ----

fn parse_datetime(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ConfigError::Validation(format!("invalid datetime '{s}': {e}")))
}

fn parse_optional_datetime(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    match s {
        Some(s) => Ok(Some(parse_datetime(&s)?)),
        None => Ok(None),
    }
}

fn row_to_route(row: &rusqlite::Row<'_>) -> Result<Route> {
    let hostname_aliases_json: String = row.get(11)?;
    let hostname_aliases: Vec<String> = serde_json::from_str(&hostname_aliases_json)
        .map_err(|e| ConfigError::Validation(format!("invalid hostname_aliases JSON: {e}")))?;

    let proxy_headers_json: String = row.get(12)?;
    let proxy_headers: std::collections::HashMap<String, String> =
        serde_json::from_str(&proxy_headers_json)
            .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers JSON: {e}")))?;

    let response_headers_json: String = row.get(13)?;
    let response_headers: std::collections::HashMap<String, String> =
        serde_json::from_str(&response_headers_json)
            .map_err(|e| ConfigError::Validation(format!("invalid response_headers JSON: {e}")))?;

    let proxy_headers_remove_json: String = row.get(23)?;
    let proxy_headers_remove: Vec<String> = serde_json::from_str(&proxy_headers_remove_json)
        .map_err(|e| ConfigError::Validation(format!("invalid proxy_headers_remove JSON: {e}")))?;

    let response_headers_remove_json: String = row.get(24)?;
    let response_headers_remove: Vec<String> = serde_json::from_str(&response_headers_remove_json)
        .map_err(|e| {
            ConfigError::Validation(format!("invalid response_headers_remove JSON: {e}"))
        })?;

    let ip_allowlist_json: String = row.get(29)?;
    let ip_allowlist: Vec<String> = serde_json::from_str(&ip_allowlist_json)
        .map_err(|e| ConfigError::Validation(format!("invalid ip_allowlist JSON: {e}")))?;

    let ip_denylist_json: String = row.get(30)?;
    let ip_denylist: Vec<String> = serde_json::from_str(&ip_denylist_json)
        .map_err(|e| ConfigError::Validation(format!("invalid ip_denylist JSON: {e}")))?;

    let cors_allowed_origins_json: String = row.get(31)?;
    let cors_allowed_origins: Vec<String> = serde_json::from_str(&cors_allowed_origins_json)
        .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_origins JSON: {e}")))?;

    let cors_allowed_methods_json: String = row.get(32)?;
    let cors_allowed_methods: Vec<String> = serde_json::from_str(&cors_allowed_methods_json)
        .map_err(|e| ConfigError::Validation(format!("invalid cors_allowed_methods JSON: {e}")))?;

    Ok(Route {
        id: row.get(0)?,
        hostname: row.get(1)?,
        path_prefix: row.get(2)?,
        certificate_id: row.get(3)?,
        load_balancing: LoadBalancing::from_str(&row.get::<_, String>(4)?)
            .map_err(ConfigError::Validation)?,
        waf_enabled: row.get(5)?,
        waf_mode: WafMode::from_str(&row.get::<_, String>(6)?).map_err(ConfigError::Validation)?,
        topology_type: TopologyType::from_str(&row.get::<_, String>(7)?)
            .map_err(ConfigError::Validation)?,
        enabled: row.get(8)?,
        force_https: row.get(9)?,
        redirect_hostname: row.get(10)?,
        hostname_aliases,
        proxy_headers,
        response_headers,
        security_headers: row.get(14)?,
        connect_timeout_s: row.get(15)?,
        read_timeout_s: row.get(16)?,
        send_timeout_s: row.get(17)?,
        strip_path_prefix: row.get(18)?,
        add_path_prefix: row.get(19)?,
        path_rewrite_pattern: row.get(20)?,
        path_rewrite_replacement: row.get(21)?,
        access_log_enabled: row.get(22)?,
        proxy_headers_remove,
        response_headers_remove,
        max_request_body_bytes: row.get::<_, Option<i64>>(25)?.map(|v| v as u64),
        websocket_enabled: row.get(26)?,
        rate_limit_rps: row.get::<_, Option<i32>>(27)?.map(|v| v as u32),
        rate_limit_burst: row.get::<_, Option<i32>>(28)?.map(|v| v as u32),
        ip_allowlist,
        ip_denylist,
        cors_allowed_origins,
        cors_allowed_methods,
        cors_max_age_s: row.get(33)?,
        compression_enabled: row.get(34)?,
        retry_attempts: row.get::<_, Option<i32>>(35)?.map(|v| v as u32),
        cache_enabled: row.get(36)?,
        cache_ttl_s: row.get(37)?,
        cache_max_bytes: row.get(38)?,
        max_connections: row.get::<_, Option<i32>>(39)?.map(|v| v as u32),
        slowloris_threshold_ms: row.get(40)?,
        auto_ban_threshold: row.get::<_, Option<i32>>(41)?.map(|v| v as u32),
        auto_ban_duration_s: row.get(42)?,
        created_at: parse_datetime(&row.get::<_, String>(43)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(44)?)?,
    })
}

fn row_to_backend(row: &rusqlite::Row<'_>) -> Result<Backend> {
    Ok(Backend {
        id: row.get(0)?,
        address: row.get(1)?,
        name: row.get(2)?,
        group_name: row.get(3)?,
        weight: row.get(4)?,
        health_status: HealthStatus::from_str(&row.get::<_, String>(5)?)
            .map_err(ConfigError::Validation)?,
        health_check_enabled: row.get(6)?,
        health_check_interval_s: row.get(7)?,
        health_check_path: row.get(8)?,
        lifecycle_state: LifecycleState::from_str(&row.get::<_, String>(9)?)
            .map_err(ConfigError::Validation)?,
        active_connections: row.get(10)?,
        tls_upstream: row.get(11)?,
        created_at: parse_datetime(&row.get::<_, String>(12)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(13)?)?,
        h2_upstream: row.get(14)?,
    })
}

fn row_to_notification_config(row: &rusqlite::Row<'_>) -> Result<NotificationConfig> {
    let alert_json: String = row.get(4)?;
    let alert_types: Vec<String> = serde_json::from_str(&alert_json)
        .map_err(|e| ConfigError::Validation(format!("invalid alert_types JSON: {e}")))?;
    Ok(NotificationConfig {
        id: row.get(0)?,
        channel: NotificationChannel::from_str(&row.get::<_, String>(1)?)
            .map_err(ConfigError::Validation)?,
        enabled: row.get(2)?,
        config: row.get(3)?,
        alert_types,
    })
}

fn row_to_user_preference(row: &rusqlite::Row<'_>) -> Result<UserPreference> {
    Ok(UserPreference {
        id: row.get(0)?,
        preference_key: row.get(1)?,
        value: PreferenceValue::from_str(&row.get::<_, String>(2)?)
            .map_err(ConfigError::Validation)?,
        created_at: parse_datetime(&row.get::<_, String>(3)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(4)?)?,
    })
}

fn row_to_admin_user(row: &rusqlite::Row<'_>) -> Result<AdminUser> {
    Ok(AdminUser {
        id: row.get(0)?,
        username: row.get(1)?,
        password_hash: row.get(2)?,
        must_change_password: row.get(3)?,
        created_at: parse_datetime(&row.get::<_, String>(4)?)?,
        last_login: parse_optional_datetime(row.get(5)?)?,
    })
}

fn row_to_load_test_config(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<LoadTestConfig>> {
    let headers_json: String = row.get(4)?;
    let headers: std::collections::HashMap<String, String> =
        match serde_json::from_str(&headers_json) {
            Ok(h) => h,
            Err(e) => {
                return Ok(Err(ConfigError::Validation(format!(
                    "invalid headers JSON: {e}"
                ))))
            }
        };
    Ok(Ok(LoadTestConfig {
        id: row.get(0)?,
        name: row.get(1)?,
        target_url: row.get(2)?,
        method: row.get(3)?,
        headers,
        body: row.get(5)?,
        concurrency: row.get(6)?,
        requests_per_second: row.get(7)?,
        duration_s: row.get(8)?,
        error_threshold_pct: row.get(9)?,
        schedule_cron: row.get(10)?,
        enabled: row.get(11)?,
        created_at: match parse_datetime(&row.get::<_, String>(12)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        updated_at: match parse_datetime(&row.get::<_, String>(13)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
    }))
}

fn row_to_load_test_result(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<LoadTestResult>> {
    Ok(Ok(LoadTestResult {
        id: row.get(0)?,
        config_id: row.get(1)?,
        started_at: match parse_datetime(&row.get::<_, String>(2)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        finished_at: match parse_datetime(&row.get::<_, String>(3)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        total_requests: row.get(4)?,
        successful_requests: row.get(5)?,
        failed_requests: row.get(6)?,
        avg_latency_ms: row.get(7)?,
        p50_latency_ms: row.get(8)?,
        p95_latency_ms: row.get(9)?,
        p99_latency_ms: row.get(10)?,
        min_latency_ms: row.get(11)?,
        max_latency_ms: row.get(12)?,
        throughput_rps: row.get(13)?,
        aborted: row.get(14)?,
        abort_reason: row.get(15)?,
    }))
}

fn row_to_probe_config(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ProbeConfig>> {
    Ok(Ok(ProbeConfig {
        id: row.get(0)?,
        route_id: row.get(1)?,
        method: row.get(2)?,
        path: row.get(3)?,
        expected_status: row.get(4)?,
        interval_s: row.get(5)?,
        timeout_ms: row.get(6)?,
        enabled: row.get(7)?,
        created_at: match parse_datetime(&row.get::<_, String>(8)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        updated_at: match parse_datetime(&row.get::<_, String>(9)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
    }))
}

fn row_to_sla_bucket(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<SlaBucket>> {
    Ok(Ok(SlaBucket {
        id: row.get(0)?,
        route_id: row.get(1)?,
        bucket_start: match parse_datetime(&row.get::<_, String>(2)?) {
            Ok(dt) => dt,
            Err(e) => return Ok(Err(e)),
        },
        request_count: row.get(3)?,
        success_count: row.get(4)?,
        error_count: row.get(5)?,
        latency_sum_ms: row.get(6)?,
        latency_min_ms: row.get(7)?,
        latency_max_ms: row.get(8)?,
        latency_p50_ms: row.get(9)?,
        latency_p95_ms: row.get(10)?,
        latency_p99_ms: row.get(11)?,
        source: row.get(12)?,
        cfg_max_latency_ms: row.get(13)?,
        cfg_status_min: row.get(14)?,
        cfg_status_max: row.get(15)?,
        cfg_target_pct: row.get(16)?,
    }))
}

/// Generate a new UUID v4 string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}
