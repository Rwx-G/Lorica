use std::path::Path;

use serde::Serialize;

use crate::error::{ConfigError, Result};
use crate::models::*;
use crate::store::ConfigStore;

const REDACTED: &str = "**REDACTED**";

const EXPORT_FORMAT_VERSION: u32 = 1;

/// Serializable snapshot of a store's full contents emitted by
/// [`export_to_toml`]. `version` tags the export schema for
/// forward-compatible reads from [`crate::import::ImportData`].
/// Sensitive fields (admin password hashes, certificate private keys,
/// SMTP passwords) are replaced with `**REDACTED**` before
/// serialization and re-import is rejected if the placeholder remains.
#[derive(Debug, Serialize)]
pub struct ExportData {
    /// Export schema version (matches `EXPORT_FORMAT_VERSION`).
    pub version: u32,
    /// Current `GlobalSettings` snapshot.
    pub global_settings: GlobalSettings,
    /// All rows of the `routes` table.
    pub routes: Vec<Route>,
    /// All rows of the `backends` table.
    pub backends: Vec<Backend>,
    /// All rows of the `route_backends` join table.
    pub route_backends: Vec<RouteBackend>,
    /// All rows of the `certificates` table (private keys redacted).
    pub certificates: Vec<Certificate>,
    /// All rows of `notification_configs`. Channel-specific secrets
    /// are redacted in the embedded JSON `config` blob : Email
    /// scrubs `smtp_password` ; Webhook + Slack scrub `url` and
    /// `auth_header` (the URL itself carries the bearer-style
    /// token in path for Slack / Discord / Teams incoming webhooks).
    pub notification_configs: Vec<NotificationConfig>,
    /// All rows of `user_preferences`.
    pub user_preferences: Vec<UserPreference>,
    /// All rows of `admin_users` (password hashes redacted).
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
            // Per-channel JSON-blob redaction. v1.5.1 audit L-5 :
            // the original code only scrubbed `smtp_password` for
            // the Email channel - the Webhook + Slack `url` and
            // `auth_header` fields leaked verbatim, even though
            // a Slack incoming-webhook URL like
            // `https://hooks.slack.com/services/T0/B0/SECRET`
            // is itself a bearer-style credential (anyone with the
            // URL can post to the channel) and `auth_header` carries
            // a literal `Bearer <token>` / `Basic <base64>`.
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&nc.config) {
                let mutated = match nc.channel {
                    NotificationChannel::Email => {
                        scrub_secret_field(&mut val, "smtp_password")
                    }
                    NotificationChannel::Webhook | NotificationChannel::Slack => {
                        // `url` carries the secret in the path for
                        // Slack / Discord / Teams webhooks.
                        // `auth_header` is the bearer / basic
                        // credential for plain HTTP webhooks. Both
                        // are scrubbed even when only one is set.
                        let a = scrub_secret_field(&mut val, "url");
                        let b = scrub_secret_field(&mut val, "auth_header");
                        a || b
                    }
                };
                if mutated {
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

    // Redact the bot-protection HMAC secret on export (v1.5.1
    // audit H-1). A non-empty secret in a TOML file shipped to CI
    // / git / S3 is equivalent to a forgeable bot-protection cookie
    // for every IP across every route until the next certificate
    // renewal rotates it. Import rejects the placeholder so a
    // round-trip cannot accidentally clear a live secret ; an empty
    // value (never-initialised) is exported as-is and re-generated
    // on first reload after import.
    let mut global_settings = store.get_global_settings()?;
    if !global_settings.bot_hmac_secret_hex.is_empty() {
        global_settings.bot_hmac_secret_hex = REDACTED.into();
    }

    let data = ExportData {
        version: EXPORT_FORMAT_VERSION,
        global_settings,
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

/// Replace the value of a secret field on a JSON object with the
/// `**REDACTED**` placeholder if it is currently a non-empty string.
/// Returns `true` when the JSON was mutated. Empty strings and
/// missing fields are no-ops so a never-configured channel exports
/// as-is and round-trips cleanly through the import-time validator.
fn scrub_secret_field(val: &mut serde_json::Value, field: &str) -> bool {
    if val
        .get(field)
        .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
    {
        val[field] = serde_json::json!(REDACTED);
        true
    } else {
        false
    }
}
