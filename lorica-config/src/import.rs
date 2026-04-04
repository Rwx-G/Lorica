use std::path::Path;

use serde::Deserialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::store::ConfigStore;

#[derive(Debug, Deserialize)]
pub struct ImportData {
    pub version: u32,
    pub global_settings: GlobalSettings,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub backends: Vec<Backend>,
    #[serde(default)]
    pub route_backends: Vec<RouteBackend>,
    #[serde(default)]
    pub certificates: Vec<Certificate>,
    #[serde(default)]
    pub notification_configs: Vec<NotificationConfig>,
    #[serde(default)]
    pub user_preferences: Vec<UserPreference>,
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

/// Validate import data for consistency.
fn validate(data: &ImportData) -> Result<()> {
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
