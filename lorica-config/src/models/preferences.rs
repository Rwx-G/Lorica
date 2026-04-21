use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::PreferenceValue;

/// Persistent UI preference for the dashboard ("never show this dialog
/// again", etc.). `preference_key` is unique; lookup is via
/// `ConfigStore::get_user_preference_by_key`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPreference {
    /// Stable UUID; primary key.
    pub id: String,
    /// Unique opaque key identifying the UI dialog or choice
    /// (`"dashboard.show_tls_tip"`, etc.).
    pub preference_key: String,
    /// Stored decision.
    pub value: PreferenceValue,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Dashboard / API administrator account. `password_hash` is an Argon2
/// hash; export redacts it to `**REDACTED**` and import refuses to load
/// records still carrying that placeholder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminUser {
    /// Stable UUID.
    pub id: String,
    /// Unique username (lowercase ASCII by convention).
    pub username: String,
    /// Argon2id hash of the password.
    pub password_hash: String,
    /// `true` after an admin password reset ; the next login forces
    /// a password change.
    pub must_change_password: bool,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most-recent successful login, or `None` if the account has
    /// never logged in.
    pub last_login: Option<DateTime<Utc>>,
}
