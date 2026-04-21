use serde::{Deserialize, Serialize};

use super::enums::NotificationChannel;

/// Notification destination (email / webhook / Slack). `config` is a
/// channel-specific JSON blob (encrypted at rest when the store has an
/// encryption key) and `alert_types` lists the alert categories this
/// destination subscribes to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Stable UUID.
    pub id: String,
    /// Transport used to deliver the alert.
    pub channel: NotificationChannel,
    /// Whether the dispatcher should route alerts through this
    /// destination.
    pub enabled: bool,
    /// Channel-specific JSON blob (SMTP credentials, webhook URL,
    /// etc.). Encrypted at rest when the store has an encryption
    /// key.
    pub config: String,
    /// Alert types this destination subscribes to (opaque string
    /// identifiers, see `lorica-notify::events::AlertType`).
    pub alert_types: Vec<String>,
}
