//! Global settings persistence on `ConfigStore`.
//!
//! Settings are stored as a key/value table; the typed `GlobalSettings`
//! struct is projected from/to that table here.

use rusqlite::params;

use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::*;

impl ConfigStore {
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
                "waf_ban_threshold" => {
                    settings.waf_ban_threshold = value
                        .parse()
                        .map_err(|_| ConfigError::Validation("invalid waf_ban_threshold".into()))?;
                }
                "waf_ban_duration_s" => {
                    settings.waf_ban_duration_s = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid waf_ban_duration_s".into())
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
                "access_log_retention" => {
                    settings.access_log_retention = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid access_log_retention".into())
                    })?;
                }
                "sla_purge_enabled" => {
                    settings.sla_purge_enabled = value == "true" || value == "1";
                }
                "sla_purge_retention_days" => {
                    settings.sla_purge_retention_days = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid sla_purge_retention_days".into())
                    })?;
                }
                "sla_purge_schedule" => {
                    settings.sla_purge_schedule = value;
                }
                "trusted_proxies" => {
                    settings.trusted_proxies = serde_json::from_str(&value).map_err(|e| {
                        ConfigError::Validation(format!("invalid trusted_proxies JSON: {e}"))
                    })?;
                }
                "waf_whitelist_ips" => {
                    settings.waf_whitelist_ips = serde_json::from_str(&value).map_err(|e| {
                        ConfigError::Validation(format!("invalid waf_whitelist_ips JSON: {e}"))
                    })?;
                }
                "connection_deny_cidrs" => {
                    settings.connection_deny_cidrs = serde_json::from_str(&value).map_err(|e| {
                        ConfigError::Validation(format!("invalid connection_deny_cidrs JSON: {e}"))
                    })?;
                }
                "connection_allow_cidrs" => {
                    settings.connection_allow_cidrs =
                        serde_json::from_str(&value).map_err(|e| {
                            ConfigError::Validation(format!(
                                "invalid connection_allow_cidrs JSON: {e}"
                            ))
                        })?;
                }
                "otlp_endpoint" => {
                    settings.otlp_endpoint = if value.is_empty() { None } else { Some(value) };
                }
                "otlp_protocol" => settings.otlp_protocol = value,
                "otlp_service_name" => settings.otlp_service_name = value,
                "otlp_sampling_ratio" => {
                    settings.otlp_sampling_ratio = value.parse().map_err(|_| {
                        ConfigError::Validation("invalid otlp_sampling_ratio".into())
                    })?;
                }
                "geoip_db_path" => {
                    settings.geoip_db_path = if value.is_empty() { None } else { Some(value) };
                }
                "geoip_auto_update_enabled" => {
                    settings.geoip_auto_update_enabled = value == "true" || value == "1";
                }
                "bot_hmac_secret_hex" => {
                    settings.bot_hmac_secret_hex = value;
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
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('waf_ban_threshold', ?1)",
            params![settings.waf_ban_threshold.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('waf_ban_duration_s', ?1)",
            params![settings.waf_ban_duration_s.to_string()],
        )?;
        let presets_json =
            serde_json::to_string(&settings.custom_security_presets).map_err(|e| {
                ConfigError::Validation(format!("failed to serialize custom_security_presets: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('custom_security_presets', ?1)",
            params![presets_json],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('access_log_retention', ?1)",
            params![settings.access_log_retention.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('sla_purge_enabled', ?1)",
            params![settings.sla_purge_enabled.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('sla_purge_retention_days', ?1)",
            params![settings.sla_purge_retention_days.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('sla_purge_schedule', ?1)",
            params![settings.sla_purge_schedule],
        )?;
        let trusted_proxies_json =
            serde_json::to_string(&settings.trusted_proxies).map_err(|e| {
                ConfigError::Validation(format!("failed to serialize trusted_proxies: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('trusted_proxies', ?1)",
            params![trusted_proxies_json],
        )?;
        let waf_whitelist_json =
            serde_json::to_string(&settings.waf_whitelist_ips).map_err(|e| {
                ConfigError::Validation(format!("failed to serialize waf_whitelist_ips: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('waf_whitelist_ips', ?1)",
            params![waf_whitelist_json],
        )?;
        let connection_deny_json =
            serde_json::to_string(&settings.connection_deny_cidrs).map_err(|e| {
                ConfigError::Validation(format!("failed to serialize connection_deny_cidrs: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('connection_deny_cidrs', ?1)",
            params![connection_deny_json],
        )?;
        let connection_allow_json = serde_json::to_string(&settings.connection_allow_cidrs)
            .map_err(|e| {
                ConfigError::Validation(format!("failed to serialize connection_allow_cidrs: {e}"))
            })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('connection_allow_cidrs', ?1)",
            params![connection_allow_json],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('otlp_endpoint', ?1)",
            params![settings.otlp_endpoint.as_deref().unwrap_or("")],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('otlp_protocol', ?1)",
            params![settings.otlp_protocol],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('otlp_service_name', ?1)",
            params![settings.otlp_service_name],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('otlp_sampling_ratio', ?1)",
            // `f64::to_string` renders `1.0` as `"1"` which round-trips
            // through `parse::<f64>` just fine but confuses downstream
            // consumers (the API JSON encoder emits `1.0`, so the
            // stored string and the API echo diverge). `{:?}` goes via
            // Debug's Grisu3 formatter which always keeps the decimal
            // point (`1.0` stays `"1.0"`, `0.1` stays `"0.1"`), giving
            // a canonical round-trippable form.
            params![format!("{:?}", settings.otlp_sampling_ratio)],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('geoip_db_path', ?1)",
            params![settings.geoip_db_path.as_deref().unwrap_or("")],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('geoip_auto_update_enabled', ?1)",
            params![settings.geoip_auto_update_enabled.to_string()],
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES ('bot_hmac_secret_hex', ?1)",
            params![settings.bot_hmac_secret_hex],
        )?;
        Ok(())
    }
}
