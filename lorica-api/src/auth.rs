//! Login, logout, password change, and admin user bootstrap.
//!
//! Passwords are hashed with Argon2id using OWASP-recommended parameters.
//! Sessions are tracked by [`SessionStore`] and exposed via an HTTP-only
//! `lorica_session` cookie.


use axum::extract::{Extension};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::db::db_blocking;
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
///
/// `username` is optional as a backwards-compat shim (Story 8.3
/// AC #3): the pre-RBAC body was `{password}` only, and an omitted
/// username routes to the migrated `admin` account.
#[derive(Deserialize)]
pub struct LoginRequest {
    /// Username; defaults to `"admin"` when omitted (legacy body).
    pub username: Option<String>,
    /// Plaintext password (hashed Argon2id in the store).
    pub password: String,
}

/// Successful login payload returned in the `data` envelope.
#[derive(Serialize)]
pub struct LoginResponse {
    /// Username of the authenticated account.
    pub username: String,
    /// RBAC role of the authenticated account (snake_case).
    pub role: lorica_config::models::Role,
    /// `true` when the user must rotate their password on next login
    /// (post admin reset).
    pub must_change_password: bool,
    /// RFC 3339 expiry timestamp of the issued session cookie.
    pub session_expires_at: String,
}

/// Payload of `GET /api/v1/auth/me`: the identity behind the
/// current session cookie. The dashboard boot probe uses it to
/// restore the role after a page refresh.
#[derive(Serialize)]
pub struct MeResponse {
    /// Username of the session owner.
    pub username: String,
    /// RBAC role of the session owner (snake_case).
    pub role: lorica_config::models::Role,
    /// RFC 3339 expiry timestamp of the current session.
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
    connect_info: crate::audit::ClientConnectInfo,
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(rate_limiter): Extension<RateLimiter>,
    headers: http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let client_ip = connect_info.0
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

    // Credential check + last_login update run on the blocking pool ;
    // the Argon2 verification previously executed under the store
    // guard, so it stays inside the closure.
    let user = db_blocking(&state.store, move |store| {
        // Legacy `{password}` body shim: route to the migrated
        // single-admin account (Story 8.3 AC #3).
        let username = body.username.as_deref().unwrap_or("admin");
        let user = match store
            .get_user_by_username(username)
            .map_err(|e| ApiError::Internal(e.to_string()))?
        {
            Some(u) => u,
            None => {
                // Equalize cost with the valid-user path so response
                // latency does not reveal whether the username exists
                // (username enumeration timing oracle). The dummy verify
                // runs the same Argon2id work and always fails.
                let _ = verify_password(&body.password, DUMMY_PASSWORD_HASH.as_str());
                return Err(ApiError::Unauthorized("invalid credentials".into()));
            }
        };

        verify_password(&body.password, &user.password_hash)?;

        // A disabled account fails AFTER the hash verification with
        // the same generic message as a wrong password: timing and
        // wording leak neither "user exists" nor "user disabled".
        if user.disabled_at.is_some() {
            return Err(ApiError::Unauthorized("invalid credentials".into()));
        }

        // Update last_login_at
        let mut updated_user = user.clone();
        updated_user.last_login_at = Some(Utc::now());
        store
            .update_user(&updated_user)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>(user)
    })
    .await?;

    let session_id = session_store
        .create(user.id.clone(), user.username.clone(), user.role)
        .await;
    let expires_at = session_store
        .expires_at(&session_id)
        .await
        .unwrap_or_else(Utc::now);

    let response = LoginResponse {
        username: user.username.clone(),
        role: user.role,
        must_change_password: user.must_change_password,
        session_expires_at: expires_at.to_rfc3339(),
    };

    // Pre-session context: the Session extension does not exist yet,
    // so the audit context is built from the verified user directly.
    // Failed logins are deliberately NOT audited (rate-limiter
    // territory; auditing them would let an attacker grow the chain).
    let audit_ctx = crate::audit::AuditContext {
        username: user.username.clone(),
        role: user.role.as_str().to_string(),
        ip: client_ip.clone(),
        user_agent: headers
            .get(http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string(),
    };
    crate::audit::record(
        &state,
        &audit_ctx,
        "auth.login",
        ("user", &user.id),
        None,
        None,
    )
    .await;

    Ok((
        StatusCode::OK,
        [(http::header::SET_COOKIE, session_cookie(&session_id))],
        json_data(response),
    ))
}

/// POST /api/v1/auth/logout - invalidate the current session and clear the cookie.
pub async fn logout(
    connect_info: crate::audit::ClientConnectInfo,
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    headers: http::HeaderMap,
) -> impl IntoResponse {
    // Public route: no Session extension. The audit identity comes
    // from the session row looked up via the cookie BEFORE removal;
    // no valid session means nothing to audit.
    let mut audit_identity: Option<(crate::audit::AuditContext, String)> = None;
    if let Some(cookie_header) = headers.get(http::header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            for cookie in cookies.split(';') {
                let cookie = cookie.trim();
                if let Some(session_id) = cookie.strip_prefix("lorica_session=") {
                    if let Some(session) = session_store.get(session_id).await {
                        audit_identity = Some((
                            crate::audit::AuditContext::new(
                                &session,
                                connect_info.as_ref(),
                                &headers,
                            ),
                            session.user_id.clone(),
                        ));
                    }
                    session_store.remove(session_id).await;
                }
            }
        }
    }

    if let Some((audit_ctx, user_id)) = audit_identity {
        crate::audit::record(
            &state,
            &audit_ctx,
            "auth.logout",
            ("user", &user_id),
            None,
            None,
        )
        .await;
    }

    (
        StatusCode::OK,
        [(http::header::SET_COOKIE, clear_session_cookie())],
        json_data(serde_json::json!({"message": "logged out"})),
    )
}

/// GET /api/v1/auth/me - identity behind the current session.
///
/// Protected route: `require_auth` has already validated the cookie
/// and injected the [`Session`] extension. The dashboard calls this
/// on boot to restore `{username, role}` after a page refresh
/// (Story 8.3 AC #4/#7).
pub async fn me(Extension(session): Extension<Session>) -> impl IntoResponse {
    json_data(MeResponse {
        username: session.username.clone(),
        role: session.role,
        session_expires_at: session.expires_at.to_rfc3339(),
    })
}

/// PUT /api/v1/auth/password - rotate the current user's password.
///
/// Verifies the current password, enforces the configured password
/// policy (`password_min_length` + `password_require_complexity`,
/// Story 8.3 AC #8) on the new one, then invalidates **every**
/// session belonging to this user (including the currently active
/// one) and mints a fresh session. The response carries a
/// `Set-Cookie` header with the new session id so the legitimate
/// user stays logged in while any attacker holding the previous
/// cookie gets a 401 on the next call (v1.5.0 audit LOW-13).
pub async fn change_password(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session_store): Extension<SessionStore>,
    Extension(session): Extension<Session>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify current password + persist new hash. The ConfigStore
    // Mutex guard lives inside `db_blocking` and drops BEFORE calling
    // `session_store.create(...)` below : `SessionStore::create`
    // re-acquires the same `ConfigStore` Mutex to persist the new
    // session row, and holding both would deadlock. The Argon2
    // verify + re-hash previously ran under the guard, so they stay
    // inside the closure (on the blocking pool). The policy check
    // needs `GlobalSettings`, so it also runs inside the closure
    // (single store acquisition, current-password check first so a
    // wrong current password reads as 401 not 400).
    let user_id = session.user_id.clone();
    db_blocking(&state.store, move |store| {
        let user = store
            .get_user(&user_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("user not found".into()))?;

        verify_password(&body.current_password, &user.password_hash)
            .map_err(|_| ApiError::Unauthorized("current password is incorrect".into()))?;

        let settings = store
            .get_global_settings()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        crate::password_policy::validate_password(&body.new_password, &settings)?;

        let new_hash = hash_password(&body.new_password)?;
        let mut updated_user = user;
        updated_user.password_hash = new_hash;
        updated_user.must_change_password = false;
        store
            .update_user(&updated_user)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    // Invalidate EVERY session for this user (including the
    // currently active one) so a stolen cookie cannot outlive a
    // password rotation. Then mint a fresh session for the
    // legitimate user and ship it back via Set-Cookie. Both
    // session_store calls take `self.db.lock()` internally ; doing
    // this AFTER dropping the store guard above avoids the
    // classic lock-ordering deadlock.
    session_store.remove_all_for_user(&session.user_id).await;
    let new_session_id = session_store
        .create(
            session.user_id.clone(),
            session.username.clone(),
            session.role,
        )
        .await;

    // Passwords never reach the audit payloads, not even as a hash:
    // before/after stay explicitly None.
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "auth.password_change",
        ("user", &session.user_id),
        None,
        None,
    )
    .await;

    Ok((
        [(http::header::SET_COOKIE, session_cookie(&new_session_id))],
        json_data(PasswordChangedResponse {
            message: "Password updated".into(),
        }),
    ))
}

/// Verify a plaintext password against a stored Argon2id hash.
///
/// Returns 401 `invalid credentials` on mismatch; an unparseable
/// stored hash is a 500 (corrupted row, not a user error). Shared
/// by login, change-password, and the users CRUD.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<(), ApiError> {
    use argon2::PasswordVerifier;
    let parsed_hash = argon2::PasswordHash::new(stored_hash)
        .map_err(|e| ApiError::Internal(format!("invalid stored password hash: {e}")))?;
    argon2_hasher()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| ApiError::Unauthorized("invalid credentials".into()))
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

/// Fixed Argon2id hash used only to equalize the cost of a
/// user-not-found login with the real verify path, closing the username
/// enumeration timing oracle. A dummy verify against this hash always
/// fails but performs the same Argon2id work as a real verify. Computed
/// once with the production hashing parameters.
static DUMMY_PASSWORD_HASH: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    hash_password("timing-oracle-equalizer")
        .expect("hashing a fixed constant password is infallible")
});

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
        .list_users()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if !users.is_empty() {
        return Ok(None);
    }

    let password = generate_random_password();
    let password_hash = hash_password(&password)?;

    let admin = lorica_config::models::User {
        id: uuid::Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        password_hash,
        role: lorica_config::models::Role::SuperAdmin,
        must_change_password: true,
        created_at: Utc::now(),
        last_login_at: None,
        disabled_at: None,
        created_by: None,
    };

    store
        .create_user(&admin)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Some(password))
}
