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

    /// Insert a new route into the database.
    pub fn create_route(&self, route: &Route) -> Result<()> {
        self.conn.execute(
            "INSERT INTO routes (id, hostname, path_prefix, certificate_id, load_balancing,
             waf_enabled, waf_mode, topology_type, enabled, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
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
                 waf_enabled, waf_mode, topology_type, enabled, created_at, updated_at
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
             waf_enabled, waf_mode, topology_type, enabled, created_at, updated_at
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
        let changed = self.conn.execute(
            "UPDATE routes SET hostname=?2, path_prefix=?3, certificate_id=?4,
             load_balancing=?5, waf_enabled=?6, waf_mode=?7, topology_type=?8,
             enabled=?9, updated_at=?10 WHERE id=?1",
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

    /// Insert a new backend into the database.
    pub fn create_backend(&self, backend: &Backend) -> Result<()> {
        self.conn.execute(
            "INSERT INTO backends (id, address, weight, health_status, health_check_enabled,
             health_check_interval_s, health_check_path, lifecycle_state, active_connections,
             tls_upstream, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                backend.id,
                backend.address,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
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
                "SELECT id, address, weight, health_status, health_check_enabled,
                 health_check_interval_s, health_check_path, lifecycle_state, active_connections,
                 tls_upstream, created_at, updated_at
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
            "SELECT id, address, weight, health_status, health_check_enabled,
             health_check_interval_s, health_check_path, lifecycle_state, active_connections,
             tls_upstream, created_at, updated_at
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
        let changed = self.conn.execute(
            "UPDATE backends SET address=?2, weight=?3, health_status=?4,
             health_check_enabled=?5, health_check_interval_s=?6, health_check_path=?7,
             lifecycle_state=?8, active_connections=?9, tls_upstream=?10,
             updated_at=?11 WHERE id=?1",
            params![
                backend.id,
                backend.address,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.health_check_path,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
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
        Ok(())
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
              latency_p50_ms, latency_p95_ms, latency_p99_ms, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
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
             latency_p50_ms, latency_p95_ms, latency_p99_ms, source
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

        let config = self.get_sla_config(route_id)?;

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
            target_pct: config.target_pct,
            meets_target: sla_pct >= config.target_pct,
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
        created_at: parse_datetime(&row.get::<_, String>(9)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(10)?)?,
    })
}

fn row_to_backend(row: &rusqlite::Row<'_>) -> Result<Backend> {
    Ok(Backend {
        id: row.get(0)?,
        address: row.get(1)?,
        weight: row.get(2)?,
        health_status: HealthStatus::from_str(&row.get::<_, String>(3)?)
            .map_err(ConfigError::Validation)?,
        health_check_enabled: row.get(4)?,
        health_check_interval_s: row.get(5)?,
        health_check_path: row.get(6)?,
        lifecycle_state: LifecycleState::from_str(&row.get::<_, String>(7)?)
            .map_err(ConfigError::Validation)?,
        active_connections: row.get(8)?,
        tls_upstream: row.get(9)?,
        created_at: parse_datetime(&row.get::<_, String>(10)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(11)?)?,
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
    }))
}

/// Generate a new UUID v4 string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}
