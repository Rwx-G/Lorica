use serde::{Deserialize, Serialize};

use super::enums::NotificationChannel;

/// Notification destination (email / webhook / Slack). `config` is a
/// channel-specific JSON blob (encrypted at rest when the store has an
/// encryption key) and `alert_types` lists the alert categories this
/// destination subscribes to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub id: String,
    pub channel: NotificationChannel,
    pub enabled: bool,
    pub config: String,
    pub alert_types: Vec<String>,
}
