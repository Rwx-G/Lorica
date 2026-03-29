use std::path::Path;

use serde::Serialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::store::ConfigStore;

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
pub fn export_to_toml(store: &ConfigStore) -> Result<String> {
    let data = ExportData {
        version: EXPORT_FORMAT_VERSION,
        global_settings: store.get_global_settings()?,
        routes: store.list_routes()?,
        backends: store.list_backends()?,
        route_backends: store.list_route_backends()?,
        certificates: store.list_certificates()?,
        notification_configs: store.list_notification_configs()?,
        user_preferences: store.list_user_preferences()?,
        admin_users: store.list_admin_users()?,
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
