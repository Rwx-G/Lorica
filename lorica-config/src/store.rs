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
                "INSERT INTO schema_migrations (version) VALUES (?1)",
                params![1],
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

    pub fn create_backend(&self, backend: &Backend) -> Result<()> {
        self.conn.execute(
            "INSERT INTO backends (id, address, weight, health_status, health_check_enabled,
             health_check_interval_s, lifecycle_state, active_connections, tls_upstream,
             created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                backend.id,
                backend.address,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
                backend.lifecycle_state.as_str(),
                backend.active_connections,
                backend.tls_upstream,
                backend.created_at.to_rfc3339(),
                backend.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_backend(&self, id: &str) -> Result<Option<Backend>> {
        self.conn
            .query_row(
                "SELECT id, address, weight, health_status, health_check_enabled,
                 health_check_interval_s, lifecycle_state, active_connections, tls_upstream,
                 created_at, updated_at
                 FROM backends WHERE id = ?1",
                params![id],
                |row| Ok(row_to_backend(row)),
            )
            .optional()?
            .transpose()
    }

    pub fn list_backends(&self) -> Result<Vec<Backend>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, weight, health_status, health_check_enabled,
             health_check_interval_s, lifecycle_state, active_connections, tls_upstream,
             created_at, updated_at
             FROM backends ORDER BY address",
        )?;
        let rows = stmt.query_map([], |row| Ok(row_to_backend(row)))?;
        let mut backends = Vec::new();
        for r in rows {
            backends.push(r??);
        }
        Ok(backends)
    }

    pub fn update_backend(&self, backend: &Backend) -> Result<()> {
        let changed = self.conn.execute(
            "UPDATE backends SET address=?2, weight=?3, health_status=?4,
             health_check_enabled=?5, health_check_interval_s=?6, lifecycle_state=?7,
             active_connections=?8, tls_upstream=?9, updated_at=?10 WHERE id=?1",
            params![
                backend.id,
                backend.address,
                backend.weight,
                backend.health_status.as_str(),
                backend.health_check_enabled,
                backend.health_check_interval_s,
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

    pub fn link_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO route_backends (route_id, backend_id) VALUES (?1, ?2)",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

    pub fn unlink_route_backend(&self, route_id: &str, backend_id: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM route_backends WHERE route_id=?1 AND backend_id=?2",
            params![route_id, backend_id],
        )?;
        Ok(())
    }

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
                _ => {}
            }
        }
        Ok(settings)
    }

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
        Ok(())
    }

    // ---- Helpers for export/import ----

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
        lifecycle_state: LifecycleState::from_str(&row.get::<_, String>(6)?)
            .map_err(ConfigError::Validation)?,
        active_connections: row.get(7)?,
        tls_upstream: row.get(8)?,
        created_at: parse_datetime(&row.get::<_, String>(9)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(10)?)?,
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

/// Generate a new UUID v4 string.
pub fn new_id() -> String {
    Uuid::new_v4().to_string()
}
