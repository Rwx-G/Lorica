use std::path::Path;

use serde::Serialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::store::ConfigStore;

const REDACTED: &str = "**REDACTED**";

const EXPORT_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct ExportData {
    pub version: u32,
    pub global_settings: GlobalSettings,
    pub routes: Vec<Route>,
    pub backends: Vec<Backend>,
    pub route_backends: Vec<RouteBackend>,
    pub certificates: Vec<Certificate>,
    pub notification_configs: Vec<NotificationConfig>,
    pub user_preferences: Vec<UserPreference>,
    pub admin_users: Vec<AdminUser>,
}

/// Export the full database state to a TOML string.
/// Password hashes are redacted from the export for security.
pub fn export_to_toml(store: &ConfigStore) -> Result<String> {
    let admin_users: Vec<AdminUser> = store
        .list_admin_users()?
        .into_iter()
        .map(|mut u| {
            u.password_hash = REDACTED.into();
            u
        })
        .collect();

    let notification_configs: Vec<NotificationConfig> = store
        .list_notification_configs()?
        .into_iter()
        .map(|mut nc| {
            if nc.channel == NotificationChannel::Email {
                if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&nc.config) {
                    if val
                        .get("smtp_password")
                        .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                    {
                        val["smtp_password"] = serde_json::json!(REDACTED);
                    }
                    nc.config = serde_json::to_string(&val).unwrap_or(nc.config);
                }
            }
            nc
        })
        .collect();

    let certificates: Vec<Certificate> = store
        .list_certificates()?
        .into_iter()
        .map(|mut c| {
            c.key_pem = REDACTED.into();
            c
        })
        .collect();

    let data = ExportData {
        version: EXPORT_FORMAT_VERSION,
        global_settings: store.get_global_settings()?,
        routes: store.list_routes()?,
        backends: store.list_backends()?,
        route_backends: store.list_route_backends()?,
        certificates,
        notification_configs,
        user_preferences: store.list_user_preferences()?,
        admin_users,
    };

    toml::to_string_pretty(&data)
        .map_err(|e| ConfigError::Serialization(format!("TOML serialization failed: {e}")))
}

/// Export the full database state to a TOML file.
pub fn export_to_file(store: &ConfigStore, path: &Path) -> Result<()> {
    let content = export_to_toml(store)?;
    std::fs::write(path, content)?;
    Ok(())
}
