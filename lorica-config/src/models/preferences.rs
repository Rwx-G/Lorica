use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::{PreferenceValue, Role};

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

/// Dashboard / API user account (Story 8.3 RBAC). `password_hash` is
/// an Argon2 hash; export redacts it to `**REDACTED**` and import
/// refuses to load records still carrying that placeholder.
///
/// Serde defaults + aliases keep pre-1.6.0 TOML exports importable:
/// those carried `[[admin_users]]` rows with a `last_login` key and no
/// `role` / `disabled_at` / `created_by` (the single admin was
/// implicitly the super admin, so `Role::SuperAdmin` is the default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Stable UUID.
    pub id: String,
    /// Unique username (lowercase ASCII by convention).
    pub username: String,
    /// Argon2id hash of the password.
    pub password_hash: String,
    /// RBAC role gating what this account can do.
    #[serde(default = "default_role")]
    pub role: Role,
    /// `true` after an admin password reset ; the next login forces
    /// a password change.
    pub must_change_password: bool,
    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Most-recent successful login, or `None` if the account has
    /// never logged in.
    #[serde(default, alias = "last_login")]
    pub last_login_at: Option<DateTime<Utc>>,
    /// When set, the account is disabled and login is rejected.
    #[serde(default)]
    pub disabled_at: Option<DateTime<Utc>>,
    /// `users.id` of the account that created this one, or `None`
    /// for the bootstrap admin and migrated rows.
    #[serde(default)]
    pub created_by: Option<String>,
}

fn default_role() -> Role {
    Role::SuperAdmin
}
