use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Extension};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
use crate::middleware::auth::{clear_session_cookie, session_cookie, Session, SessionStore};
use crate::middleware::rate_limit::RateLimiter;
use crate::server::AppState;

/// Build the Argon2 hasher with explicit production parameters.
/// Algorithm: Argon2id v0x13, 19 MiB memory, 2 iterations, 1 parallelism.
/// These match OWASP recommendations for password storage.
fn argon2_hasher() -> argon2::Argon2<'static> {
    argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19456, 2, 1, None).expect("valid Argon2 params"),
    )
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub must_change_password: bool,
    pub session_expires_at: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct PasswordChangedResponse {
    pub message: String,
}

/// POST /api/v1/auth/login
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(rate_limiter): Extension<RateLimiter>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let rate_key = format!("login:{}", addr.ip());
    if !rate_limiter.check(&rate_key).await {
        return Err(ApiError::RateLimited);
    }

    let store = state.store.lock().await;
    let user = store
        .get_admin_user_by_username(&body.username)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
        .map_err(|_| ApiError::Internal("invalid stored password hash".into()))?;

    use argon2::PasswordVerifier;
    argon2_hasher()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized("invalid credentials".into()))?;

    // Update last_login
    let mut updated_user = user.clone();
    updated_user.last_login = Some(Utc::now());
    store
        .update_admin_user(&updated_user)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    drop(store);

    let session_id = session_store
        .create(user.id.clone(), user.username.clone())
        .await;
    let expires_at = session_store
        .expires_at(&session_id)
        .await
        .unwrap_or_else(Utc::now);

    let response = LoginResponse {
        must_change_password: user.must_change_password,
        session_expires_at: expires_at.to_rfc3339(),
    };

    Ok((
        StatusCode::OK,
        [(http::header::SET_COOKIE, session_cookie(&session_id))],
        json_data(response),
    ))
}

/// POST /api/v1/auth/logout
pub async fn logout(
    Extension(session_store): Extension<SessionStore>,
    headers: http::HeaderMap,
) -> impl IntoResponse {
    if let Some(cookie_header) = headers.get(http::header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(session_id) = cookie.strip_prefix("lorica_session=") {
                    session_store.remove(session_id).await;
                }
            }
        }
    }

    (
        StatusCode::OK,
        [(http::header::SET_COOKIE, clear_session_cookie())],
        json_data(serde_json::json!({"message": "logged out"})),
    )
}

/// Extract the current session ID from request headers.
fn extract_current_session_id(headers: &http::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(http::header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix("lorica_session=") {
            return Some(value.to_string());
        }
    }
    None
}

/// PUT /api/v1/auth/password
pub async fn change_password(
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(session): Extension<Session>,
    headers: http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if body.new_password.len() < 8 {
        return Err(ApiError::BadRequest(
            "new password must be at least 8 characters".into(),
        ));
    }
    if body.new_password.len() > 128 {
        return Err(ApiError::BadRequest(
            "new password must not exceed 128 characters".into(),
        ));
    }

    let store = state.store.lock().await;
    let user = store
        .get_admin_user(&session.user_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    // Verify current password
    let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
        .map_err(|_| ApiError::Internal("invalid stored password hash".into()))?;

    use argon2::PasswordVerifier;
    argon2_hasher()
        .verify_password(body.current_password.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized("current password is incorrect".into()))?;

    // Hash new password
    let new_hash = hash_password(&body.new_password)?;

    let mut updated_user = user;
    updated_user.password_hash = new_hash;
    updated_user.must_change_password = false;
    store
        .update_admin_user(&updated_user)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Invalidate all sessions for this user except the current one
    let current_session_id = extract_current_session_id(&headers).unwrap_or_default();
    session_store
        .remove_all_for_user_except(&session.user_id, &current_session_id)
        .await;

    Ok(json_data(PasswordChangedResponse {
        message: "Password updated".into(),
    }))
}

/// Hash a password using argon2.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;
    use rand::rngs::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Generate a random password for first-run admin setup.
pub fn generate_random_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*";
    let mut rng = rand::thread_rng();
    (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Ensure an admin user exists. On first run, create one with a random password.
/// Returns the generated password if a new user was created.
pub fn ensure_admin_user(store: &lorica_config::ConfigStore) -> Result<Option<String>, ApiError> {
    let users = store
        .list_admin_users()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if !users.is_empty() {
        return Ok(None);
    }

    let password = generate_random_password();
    let password_hash = hash_password(&password)?;

    let admin = lorica_config::models::AdminUser {
        id: uuid::Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        password_hash,
        must_change_password: true,
        created_at: Utc::now(),
        last_login: None,
    };

    store
        .create_admin_user(&admin)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Some(password))
}
