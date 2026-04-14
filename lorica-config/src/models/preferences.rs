use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::PreferenceValue;

/// Persistent UI preference for the dashboard ("never show this dialog
/// again", etc.). `preference_key` is unique; lookup is via
/// `ConfigStore::get_user_preference_by_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreference {
    pub id: String,
    pub preference_key: String,
    pub value: PreferenceValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Dashboard / API administrator account. `password_hash` is an Argon2
/// hash; export redacts it to `**REDACTED**` and import refuses to load
/// records still carrying that placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
}
