//! User account CRUD handlers (Story 8.3 AC #5).
//!
//! Every route under `/api/v1/users` is SuperAdmin-only (enforced by
//! the [`crate::middleware::authorize`] policy). Handler-level guards
//! cover what the role floor cannot: self-deletion and the
//! last-super-admin invariant. Any role change, disable, or password
//! reset invalidates every session of the target user immediately.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use lorica_config::models::{Role, User};
use serde::{Deserialize, Serialize};

use crate::auth::hash_password;
use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::{Session, SessionStore};
use crate::server::AppState;

/// JSON shape of a user account. `password_hash` never leaves the
/// server.
#[derive(Serialize)]
pub struct UserResponse {
    /// Stable UUID.
    pub id: String,
    /// Unique username.
    pub username: String,
    /// RBAC role (snake_case).
    pub role: Role,
    /// `true` when the next login forces a password change.
    pub must_change_password: bool,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 timestamp of the most recent login, or `null`.
    pub last_login_at: Option<String>,
    /// `true` when the account is disabled (login rejected).
    pub disabled: bool,
    /// `users.id` of the creating account, or `null` for the
    /// bootstrap admin and migrated rows.
    pub created_by: Option<String>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            username: user.username,
            role: user.role,
            must_change_password: user.must_change_password,
            created_at: user.created_at.to_rfc3339(),
            last_login_at: user.last_login_at.map(|t| t.to_rfc3339()),
            disabled: user.disabled_at.is_some(),
            created_by: user.created_by,
        }
    }
}

/// JSON body for `POST /api/v1/users`.
#[derive(Deserialize)]
pub struct CreateUserRequest {
    /// Username: 3-32 chars, lowercase alphanumeric plus `._-`,
    /// must start alphanumeric.
    pub username: String,
    /// Initial password (validated against the password policy).
    pub password: String,
    /// Role of the new account.
    pub role: Role,
}

/// JSON body for `PUT /api/v1/users/{id}`. Every field is optional;
/// only provided fields are applied.
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    /// New password (validated against the password policy). Sets
    /// `must_change_password` so the user rotates it on next login.
    pub password: Option<String>,
    /// New role.
    pub role: Option<Role>,
    /// Disable (`true`) or re-enable (`false`) the account.
    pub disabled: Option<bool>,
}

fn validate_username(username: &str) -> Result<(), ApiError> {
    let len = username.chars().count();
    if !(3..=32).contains(&len) {
        return Err(ApiError::BadRequest(
            "username must be 3-32 characters".into(),
        ));
    }
    let mut chars = username.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest_ok = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c));
    if !(first_ok && rest_ok) {
        return Err(ApiError::BadRequest(
            "username must be lowercase alphanumeric plus '._-', starting alphanumeric".into(),
        ));
    }
    Ok(())
}

/// GET /api/v1/users - list all accounts.
pub async fn list_users(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let users = db_blocking(&state.store, |store| {
        store.list_users().map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    let users: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();
    Ok(json_data(users))
}

/// GET /api/v1/users/{id} - fetch one account.
pub async fn get_user(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let user = db_blocking(&state.store, move |store| {
        store
            .get_user(&id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))
    })
    .await?;
    Ok(json_data(UserResponse::from(user)))
}

/// POST /api/v1/users - create an account.
pub async fn create_user(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_username(&body.username)?;

    let creator_id = session.user_id.clone();
    let created = db_blocking(&state.store, move |store| {
        let settings = store
            .get_global_settings()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        crate::password_policy::validate_password(&body.password, &settings)?;

        if store
            .get_user_by_username(&body.username)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .is_some()
        {
            return Err(ApiError::Conflict("username already exists".into()));
        }

        let user = User {
            id: uuid::Uuid::new_v4().to_string(),
            username: body.username.clone(),
            password_hash: hash_password(&body.password)?,
            role: body.role,
            must_change_password: false,
            created_at: Utc::now(),
            last_login_at: None,
            disabled_at: None,
            created_by: Some(creator_id),
        };
        store
            .create_user(&user)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>(user)
    })
    .await?;

    Ok(json_data_with_status(
        StatusCode::CREATED,
        UserResponse::from(created),
    ))
}

/// PUT /api/v1/users/{id} - update password / role / disabled flag.
pub async fn update_user(
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Path(id): Path<String>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Session invalidation happens AFTER the store guard drops
    // (SessionStore re-acquires the ConfigStore mutex; holding both
    // would deadlock - same ordering as change_password).
    let target_id = id.clone();
    let (updated, sessions_stale) = db_blocking(&state.store, move |store| {
        let mut user = store
            .get_user(&target_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

        let was_active_super_admin = user.role == Role::SuperAdmin && user.disabled_at.is_none();
        let demotes = body.role.is_some_and(|r| r != Role::SuperAdmin);
        let disables = body.disabled == Some(true);
        if was_active_super_admin && (demotes || disables) {
            let actives = store
                .count_active_super_admins()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            if actives <= 1 {
                return Err(ApiError::BadRequest(
                    "cannot demote or disable the last enabled super admin".into(),
                ));
            }
        }

        let mut sessions_stale = false;
        if let Some(password) = &body.password {
            let settings = store
                .get_global_settings()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            crate::password_policy::validate_password(password, &settings)?;
            user.password_hash = hash_password(password)?;
            // Admin-reset password: the target must pick their own
            // on next login.
            user.must_change_password = true;
            sessions_stale = true;
        }
        if let Some(role) = body.role {
            if role != user.role {
                sessions_stale = true;
            }
            user.role = role;
        }
        if let Some(disabled) = body.disabled {
            match (disabled, user.disabled_at) {
                (true, None) => {
                    user.disabled_at = Some(Utc::now());
                    sessions_stale = true;
                }
                (false, Some(_)) => user.disabled_at = None,
                _ => {}
            }
        }

        store
            .update_user(&user)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>((user, sessions_stale))
    })
    .await?;

    // Immediate effect: a demoted / disabled / password-reset account
    // is logged out everywhere (Story 8.3 Dev Notes decision).
    if sessions_stale {
        session_store.remove_all_for_user(&updated.id).await;
    }

    Ok(json_data(UserResponse::from(updated)))
}

/// DELETE /api/v1/users/{id} - delete an account.
pub async fn delete_user(
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if id == session.user_id {
        return Err(ApiError::BadRequest(
            "cannot delete your own account".into(),
        ));
    }

    let target_id = id.clone();
    db_blocking(&state.store, move |store| {
        let user = store
            .get_user(&target_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

        if user.role == Role::SuperAdmin && user.disabled_at.is_none() {
            let actives = store
                .count_active_super_admins()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            if actives <= 1 {
                return Err(ApiError::BadRequest(
                    "cannot delete the last enabled super admin".into(),
                ));
            }
        }

        store
            .delete_user(&target_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    session_store.remove_all_for_user(&id).await;

    Ok(json_data(serde_json::json!({ "message": "user deleted" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(validate_username("admin").is_ok());
        assert!(validate_username("ops.team-1").is_ok());
        assert!(validate_username("ab").is_err());
        assert!(validate_username("Admin").is_err());
        assert!(validate_username(".dot-first").is_err());
        assert!(validate_username("has space").is_err());
        assert!(validate_username(&"x".repeat(33)).is_err());
    }
}
