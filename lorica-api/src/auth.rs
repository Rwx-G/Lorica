//! Login, logout, password change, and admin user bootstrap.
//!
//! Passwords are hashed with Argon2id using OWASP-recommended parameters.
//! Sessions are tracked by [`SessionStore`] and exposed via an HTTP-only
//! `lorica_session` cookie.

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

/// JSON body for `POST /api/v1/auth/login`.
#[derive(Deserialize)]
pub struct LoginRequest {
    /// Username.
    pub username: String,
    /// Plaintext password (hashed Argon2id in the store).
    pub password: String,
}

/// Successful login payload returned in the `data` envelope.
#[derive(Serialize)]
pub struct LoginResponse {
    /// `true` when the user must rotate their password on next login
    /// (post admin reset).
    pub must_change_password: bool,
    /// RFC 3339 expiry timestamp of the issued session cookie.
    pub session_expires_at: String,
}

/// JSON body for `PUT /api/v1/auth/password`.
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    /// Old password (verified against the stored Argon2id hash).
    pub current_password: String,
    /// New password ; re-hashed and persisted.
    pub new_password: String,
}

/// Acknowledgement returned after a successful password change.
#[derive(Serialize)]
pub struct PasswordChangedResponse {
    /// Human-readable message.
    pub message: String,
}

/// POST /api/v1/auth/login - verify credentials and issue a session cookie.
///
/// Rate limited per source IP. On success returns a `Set-Cookie` header
/// with the new `lorica_session` token and updates `last_login`.
pub async fn login(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(rate_limiter): Extension<RateLimiter>,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let client_ip = connect_info
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    // Legacy fixed 5/60 s login bucket. Retained via
    // `RateLimiter::check` (wrapper around the new
    // `check_bucket("login", ...)`). The Retry-After on the 429
    // response is computed from the same fixed window so clients
    // polite enough to honour it back off correctly.
    if !rate_limiter.check(client_ip.as_str()).await {
        // 60 s fixed window ceiling is good enough for the legacy
        // path ; the named-bucket version computes the exact
        // remaining time.
        return Err(ApiError::RateLimited(60));
    }

    let store = state.store.lock().await;
    let user = store
        .get_admin_user_by_username(&body.username)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::Unauthorized("invalid credentials".into()))?;

    let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
        .map_err(|e| ApiError::Internal(format!("invalid stored password hash: {e}")))?;

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

/// POST /api/v1/auth/logout - invalidate the current session and clear the cookie.
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

/// PUT /api/v1/auth/password - rotate the current user's password.
///
/// Verifies the current password, enforces 8-128 character bounds
/// on the new one, then invalidates **every** session belonging to
/// this user (including the currently active one) and mints a
/// fresh session. The response carries a `Set-Cookie` header with
/// the new session id so the legitimate user stays logged in while
/// any attacker holding the previous cookie gets a 401 on the
/// next call (v1.5.0 audit LOW-13).
pub async fn change_password(
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(session): Extension<Session>,
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

    // Verify current password + persist new hash. We scope the
    // ConfigStore Mutex guard so it drops BEFORE calling
    // `session_store.create(...)` below : `SessionStore::create`
    // re-acquires the same `ConfigStore` Mutex to persist the new
    // session row, and holding both would deadlock.
    {
        let store = state.store.lock().await;
        let user = store
            .get_admin_user(&session.user_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

        let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
            .map_err(|e| ApiError::Internal(format!("invalid stored password hash: {e}")))?;

        use argon2::PasswordVerifier;
        argon2_hasher()
            .verify_password(body.current_password.as_bytes(), &parsed_hash)
            .map_err(|_| ApiError::Unauthorized("current password is incorrect".into()))?;

        let new_hash = hash_password(&body.new_password)?;
        let mut updated_user = user;
        updated_user.password_hash = new_hash;
        updated_user.must_change_password = false;
        store
            .update_admin_user(&updated_user)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }

    // Invalidate EVERY session for this user (including the
    // currently active one) so a stolen cookie cannot outlive a
    // password rotation. Then mint a fresh session for the
    // legitimate user and ship it back via Set-Cookie. Both
    // session_store calls take `self.db.lock()` internally ; doing
    // this AFTER dropping the store guard above avoids the
    // classic lock-ordering deadlock.
    session_store.remove_all_for_user(&session.user_id).await;
    let new_session_id = session_store
        .create(session.user_id.clone(), session.username.clone())
        .await;

    Ok((
        [(http::header::SET_COOKIE, session_cookie(&new_session_id))],
        json_data(PasswordChangedResponse {
            message: "Password updated".into(),
        }),
    ))
}

/// Hash a password using argon2.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::PasswordHasher;

    // `argon2` 0.5 re-exports rand_core 0.6. Its `SaltString::generate`
    // accepts the rand_core 0.6 `CryptoRngCore` trait, which `rand`
    // 0.9's top-level `OsRng` does not implement (rand moved to
    // rand_core 0.9 in 0.9.0). Using the re-exported type keeps
    // argon2 on its own rand_core without forcing rand_core 0.6 as a
    // separate direct dep here.
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2_hasher()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::Internal(format!("password hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Generate a random password for first-run admin setup.
///
/// Uses `OsRng` (getrandom) rather than the thread-local RNG so the
/// first-run password is unpredictable even if any thread-local
/// seeding path ever degrades. Matches the other crypto-sensitive
/// RNG in this file (`hash_password`'s `SaltString::generate(OsRng)`).
/// Audit L-5.
pub fn generate_random_password() -> String {
    use rand::Rng;
    use rand::SeedableRng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*";
    // ChaCha20 seeded from OsRng : fast, deterministic-per-seed
    // sequence but seeded from OS entropy. `rand::rngs::OsRng` is
    // `CryptoRng + RngCore` ; `random_range` requires a `Rng`, so we
    // re-seed a CSPRNG from OsRng.
    let mut rng = rand_chacha::ChaCha20Rng::from_os_rng();
    (0..24)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
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
