use std::path::Path;

use serde::Deserialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::store::ConfigStore;

/// Deserialized counterpart of [`crate::export::ExportData`]. Each
/// collection defaults to empty on missing keys so partial imports
/// remain valid.
#[derive(Debug, Deserialize)]
pub struct ImportData {
    /// Export schema version (must be >= 1 ; 0 is rejected).
    pub version: u32,
    /// Snapshot of `GlobalSettings`.
    pub global_settings: GlobalSettings,
    /// All rows of the `routes` table.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// All rows of the `backends` table.
    #[serde(default)]
    pub backends: Vec<Backend>,
    /// All rows of the `route_backends` join table.
    #[serde(default)]
    pub route_backends: Vec<RouteBackend>,
    /// All rows of the `certificates` table.
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    /// All rows of the `notification_configs` table.
    #[serde(default)]
    pub notification_configs: Vec<NotificationConfig>,
    /// All rows of the `user_preferences` table.
    #[serde(default)]
    pub user_preferences: Vec<UserPreference>,
    /// All rows of the `admin_users` table (password hashes are
    /// redacted to `**REDACTED**` on export ; import rejects those).
    #[serde(default)]
    pub admin_users: Vec<AdminUser>,
}

/// Parse a TOML string into import data.
pub fn parse_toml(content: &str) -> Result<ImportData> {
    let data: ImportData = toml::from_str(content)
        .map_err(|e| ConfigError::Serialization(format!("TOML parse failed: {e}")))?;
    validate(&data)?;
    Ok(data)
}

/// Parse TOML for preview/diff only - skips redaction validation.
pub fn parse_toml_for_preview(content: &str) -> Result<ImportData> {
    let data: ImportData = toml::from_str(content)
        .map_err(|e| ConfigError::Serialization(format!("TOML parse failed: {e}")))?;
    validate_structure(&data)?;
    Ok(data)
}

/// Validate structural consistency (used by both import and preview).
fn validate_structure(data: &ImportData) -> Result<()> {
    if data.version == 0 {
        return Err(ConfigError::Validation(
            "export version must be >= 1".into(),
        ));
    }

    // Validate route-backend references
    for rb in &data.route_backends {
        if !data.routes.iter().any(|r| r.id == rb.route_id) {
            return Err(ConfigError::Validation(format!(
                "route_backend references unknown route_id: {}",
                rb.route_id
            )));
        }
        if !data.backends.iter().any(|b| b.id == rb.backend_id) {
            return Err(ConfigError::Validation(format!(
                "route_backend references unknown backend_id: {}",
                rb.backend_id
            )));
        }
    }

    Ok(())
}

/// Validate import data for consistency (rejects redacted data).
fn validate(data: &ImportData) -> Result<()> {
    validate_structure(data)?;

    // Reject redacted password hashes (from exports)
    for user in &data.admin_users {
        if user.password_hash == "**REDACTED**" {
            return Err(ConfigError::Validation(format!(
                "admin user '{}' has a redacted password hash (from export); \
                 set a real password hash or remove the user from the import file",
                user.username
            )));
        }
    }

    // Reject redacted SMTP passwords in notification configs
    for nc in &data.notification_configs {
        if nc.channel == NotificationChannel::Email && nc.config.contains("**REDACTED**") {
            return Err(ConfigError::Validation(format!(
                "notification config '{}' has a redacted SMTP password (from export); \
                 set a real password or remove the config from the import file",
                nc.id
            )));
        }
    }

    // Reject redacted certificate private keys
    for cert in &data.certificates {
        if cert.key_pem == "**REDACTED**" {
            return Err(ConfigError::Validation(format!(
                "certificate '{}' has a redacted private key (from export); \
                 provide the real key or remove the certificate from the import file",
                cert.id
            )));
        }
    }

    // Validate certificate references in routes
    for route in &data.routes {
        if let Some(cert_id) = &route.certificate_id {
            if !data.certificates.iter().any(|c| c.id == *cert_id) {
                return Err(ConfigError::Validation(format!(
                    "route '{}' references unknown certificate_id: {}",
                    route.id, cert_id
                )));
            }
        }
    }

    Ok(())
}

/// Import data into the store, replacing all existing data.
pub fn import_to_store(store: &ConfigStore, data: &ImportData) -> Result<()> {
    store.clear_all()?;

    store.update_global_settings(&data.global_settings)?;

    for cert in &data.certificates {
        store.create_certificate(cert)?;
    }
    for backend in &data.backends {
        store.create_backend(backend)?;
    }
    for route in &data.routes {
        store.create_route(route)?;
    }
    for rb in &data.route_backends {
        store.link_route_backend(&rb.route_id, &rb.backend_id)?;
    }
    for nc in &data.notification_configs {
        store.create_notification_config(nc)?;
    }
    for pref in &data.user_preferences {
        store.create_user_preference(pref)?;
    }
    for user in &data.admin_users {
        store.create_admin_user(user)?;
    }

    Ok(())
}

/// Import from a TOML file into the store.
pub fn import_from_file(store: &ConfigStore, path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let data = parse_toml(&content)?;
    import_to_store(store, &data)
}
