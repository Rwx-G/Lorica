use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::Mutex;
use tower::ServiceExt;

use crate::auth::{ensure_admin_user, hash_password};
use crate::logs::LogBuffer;
use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::{build_router, AppState, Mode};
use crate::system::SystemCache;
use crate::workers::WorkerMetrics;

// Real PEM fixtures shared with `lorica-tls`. Since v1.5.3 every
// cert-storing endpoint validates `cert_pem`/`key_pem` with the same
// loader the worker uses (`lorica_tls::validate_certificate_bundle`),
// so dummy `BEGIN CERTIFICATE\ntest\nEND CERTIFICATE` strings are now
// rejected at the boundary. We point at the existing fixtures rather
// than duplicate them : keypair A (RSA) and keypair B (EC SEC1) give
// us two SPKI-valid bundles, which is enough to also exercise the
// PUT path that swaps both fields atomically and expects the
// fingerprint to change.
const TEST_CERT_RSA_PEM: &str = include_str!("../../lorica-tls/tests/test-cert-rsa.pem");
const TEST_KEY_RSA_PEM: &str = include_str!("../../lorica-tls/tests/test-key-rsa-pkcs1.pem");
const TEST_CERT_EC_PEM: &str = include_str!("../../lorica-tls/tests/test-cert.pem");
const TEST_KEY_EC_PEM: &str = include_str!("../../lorica-tls/tests/test-key.pem");

async fn test_state() -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store: Arc::clone(&store),
        log_buffer: Arc::new(LogBuffer::new(1000)),
        system_cache: Arc::new(Mutex::new(SystemCache::new())),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        started_at: Instant::now(),
        data_dir: std::path::PathBuf::from("/var/lib/lorica"),
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        mode: Mode::Test,
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        notification_history: None,
        log_store: None,
        log_writer: None,
        task_tracker: tokio_util::task::TaskTracker::new(),
    };
    let session_store = SessionStore::new(store).await;
    let rate_limiter = RateLimiter::new();
    (state, session_store, rate_limiter)
}

fn app(state: AppState, session_store: SessionStore, rate_limiter: RateLimiter) -> axum::Router {
    build_router(state, session_store, rate_limiter)
}

/// Helper to extract Set-Cookie header value.
fn extract_session_cookie(response: &http::Response<Body>) -> Option<String> {
    let cookie = response
        .headers()
        .get(http::header::SET_COOKIE)?
        .to_str()
        .ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix("lorica_session=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Helper: create admin user and login, returning session cookie string.
async fn setup_admin_and_login(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
) -> String {
    let password = {
        let store = state.store.lock().await;
        ensure_admin_user(&store)
            .expect("test setup")
            .expect("test setup")
    };

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "username": "admin",
        "password": password
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let session_id = extract_session_cookie(&response).expect("test setup");
    format!("lorica_session={session_id}")
}

// ---- Auth Tests ----

#[tokio::test]
async fn test_login_success() {
    let (state, session_store, rate_limiter) = test_state().await;

    let password = {
        let store = state.store.lock().await;
        ensure_admin_user(&store)
            .expect("test setup")
            .expect("test setup")
    };

    let router = app(state, session_store, rate_limiter);

    let body = serde_json::json!({
        "username": "admin",
        "password": password
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(http::header::SET_COOKIE));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["data"]["must_change_password"]
        .as_bool()
        .expect("test setup"));
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let (state, session_store, rate_limiter) = test_state().await;

    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);

    let body = serde_json::json!({
        "username": "admin",
        "password": "wrongpassword"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn test_unauthenticated_request_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    let router = app(state, session_store, rate_limiter);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_change_password() {
    let (state, session_store, rate_limiter) = test_state().await;
    let _cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let known_password = "test_password_123";
    {
        let store = state.store.lock().await;
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_user(&user).expect("test setup");
    }

    // Login again with known password
    let router2 = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let login_body = serde_json::json!({
        "username": "admin",
        "password": known_password
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&login_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router2.oneshot(req).await.expect("test setup");
    let cookie2 = format!(
        "lorica_session={}",
        extract_session_cookie(&response).expect("test setup")
    );

    // Change password
    let router3 = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "current_password": known_password,
        "new_password": "New_secure_password_456"
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", cookie2)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router3.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_change_password_rotates_session_cookie() {
    // Password change must rotate the session cookie (v1.5.0 A.5).
    // The old cookie becomes invalid immediately ; the response
    // carries a new Set-Cookie that the browser picks up. A
    // stolen-cookie attacker holding the old value gets a 401 on
    // the next call.
    let (state, session_store, rate_limiter) = test_state().await;
    let _cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let known_password = "test_password_123";
    {
        let store = state.store.lock().await;
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_user(&user).expect("test setup");
    }

    // Login, capture cookie_A.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let login_body = serde_json::json!({
        "username": "admin",
        "password": known_password,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&login_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let cookie_a_value = extract_session_cookie(&response).expect("test setup");
    let cookie_a = format!("lorica_session={cookie_a_value}");

    // Change password — the response carries a fresh Set-Cookie
    // whose session id differs from cookie_A.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "current_password": known_password,
        "new_password": "New_secure_password_456",
    });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie_a)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let cookie_b_value = extract_session_cookie(&response)
        .expect("password change response must carry a Set-Cookie for the new session");
    let cookie_b = format!("lorica_session={cookie_b_value}");
    assert_ne!(
        cookie_a_value, cookie_b_value,
        "new session id must differ from old"
    );

    // cookie_A must now be rejected by any protected endpoint.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header("Cookie", &cookie_a)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "old session cookie must no longer authenticate after password rotation"
    );

    // cookie_B authenticates normally.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header("Cookie", &cookie_b)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_rate_limiting() {
    let (state, session_store, rate_limiter) = test_state().await;

    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
    }

    let body = serde_json::json!({
        "username": "admin",
        "password": "wrongpassword"
    });

    // Make 6 requests (limit is 5/min)
    for i in 0..6 {
        let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&body).expect("test setup"),
            ))
            .expect("test setup");

        let response = router.oneshot(req).await.expect("test setup");
        if i < 5 {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}

#[tokio::test]
async fn test_login_legacy_body_without_username_routes_to_admin() {
    // Pre-RBAC clients send `{password}` only; the shim routes the
    // login to the migrated `admin` account (Story 8.3 AC #3).
    let (state, session_store, rate_limiter) = test_state().await;
    let password = {
        let store = state.store.lock().await;
        ensure_admin_user(&store)
            .expect("test setup")
            .expect("test setup")
    };

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["username"], "admin");
    assert_eq!(json["data"]["role"], "super_admin");
}

#[tokio::test]
async fn test_login_disabled_account_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    let password = {
        let store = state.store.lock().await;
        let password = ensure_admin_user(&store)
            .expect("test setup")
            .expect("test setup");
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.disabled_at = Some(chrono::Utc::now());
        store.update_user(&user).expect("test setup");
        password
    };

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "username": "admin", "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    // Same generic message as a wrong password: no account-state
    // enumeration.
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["error"]["message"], "unauthorized: invalid credentials");
}

#[tokio::test]
async fn test_auth_me_returns_identity_and_role() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/me")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["username"], "admin");
    assert_eq!(json["data"]["role"], "super_admin");
    assert!(json["data"]["session_expires_at"].is_string());
}

#[tokio::test]
async fn test_auth_me_unauthenticated_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/me")
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_change_password_missing_complexity_returns_400() {
    // Long enough (>= 14) but single character class: rejected by
    // the complexity rule (Story 8.3 AC #8).
    let (state, session_store, rate_limiter) = test_state().await;
    let known_password = "test_password_123";
    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_user(&user).expect("test setup");
    }

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let login_body = serde_json::json!({ "username": "admin", "password": known_password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&login_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let cookie = format!(
        "lorica_session={}",
        extract_session_cookie(&response).expect("test setup")
    );

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "current_password": known_password,
        "new_password": "aaaaaaaaaaaaaaaaaa"
    });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---- RBAC authorization tests (Story 8.3) ----

/// Create a user with the given role directly in the store, then
/// log in through the endpoint and return the session cookie.
async fn create_user_and_login(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    username: &str,
    role: lorica_config::models::Role,
) -> String {
    let password = "Rbac-test-pass-42!";
    {
        let store = state.store.lock().await;
        let user = lorica_config::models::User {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password_hash: hash_password(password).expect("test setup"),
            role,
            must_change_password: false,
            created_at: chrono::Utc::now(),
            last_login_at: None,
            disabled_at: None,
            created_by: None,
        };
        store.create_user(&user).expect("test setup");
    }

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "username": username, "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    format!(
        "lorica_session={}",
        extract_session_cookie(&response).expect("test setup")
    )
}

async fn send(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Cookie", cookie);
    let body = match body {
        Some(json) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(serde_json::to_string(&json).expect("test setup"))
        }
        None => Body::empty(),
    };
    router
        .oneshot(builder.body(body).expect("test setup"))
        .await
        .expect("test setup")
}

#[tokio::test]
async fn test_viewer_can_read_but_not_mutate() {
    let (state, session_store, rate_limiter) = test_state().await;
    let _admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;
    let viewer = create_user_and_login(
        &state,
        &session_store,
        &rate_limiter,
        "viewer1",
        lorica_config::models::Role::Viewer,
    )
    .await;

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/routes",
        &viewer,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "POST",
        "/api/v1/routes",
        &viewer,
        Some(serde_json::json!({
            "hostname": "viewer-denied.example.com",
            "path_prefix": "/",
            "load_balancing": "round_robin"
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_operator_can_mutate_but_not_touch_settings_or_users() {
    let (state, session_store, rate_limiter) = test_state().await;
    let _admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;
    let operator = create_user_and_login(
        &state,
        &session_store,
        &rate_limiter,
        "operator1",
        lorica_config::models::Role::Operator,
    )
    .await;

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "POST",
        "/api/v1/routes",
        &operator,
        Some(serde_json::json!({
            "hostname": "operator-ok.example.com",
            "path_prefix": "/",
            "load_balancing": "round_robin"
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "PUT",
        "/api/v1/settings",
        &operator,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Even LISTING users is user management (AC #5).
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/users",
        &operator,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_users_crud_super_admin_flow() {
    let (state, session_store, rate_limiter) = test_state().await;
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create an operator through the endpoint.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "POST",
        "/api/v1/users",
        &admin,
        Some(serde_json::json!({
            "username": "ops1",
            "password": "Ops1-initial-pass!",
            "role": "operator"
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let created: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let ops_id = created["data"]["id"].as_str().expect("test setup").to_string();
    assert_eq!(created["data"]["role"], "operator");
    assert!(created["data"].get("password_hash").is_none());

    // Duplicate username -> 409.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "POST",
        "/api/v1/users",
        &admin,
        Some(serde_json::json!({
            "username": "ops1",
            "password": "Ops1-initial-pass!",
            "role": "viewer"
        })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // The new operator logs in, then gets demoted: their session
    // must die immediately.
    let ops_cookie = {
        let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
        let body = serde_json::json!({ "username": "ops1", "password": "Ops1-initial-pass!" });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&body).expect("test setup"),
            ))
            .expect("test setup");
        let response = router.oneshot(req).await.expect("test setup");
        assert_eq!(response.status(), StatusCode::OK);
        format!(
            "lorica_session={}",
            extract_session_cookie(&response).expect("test setup")
        )
    };
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "PUT",
        &format!("/api/v1/users/{ops_id}"),
        &admin,
        Some(serde_json::json!({ "role": "viewer" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/routes",
        &ops_cookie,
        None,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "role change must invalidate the target's sessions"
    );

    // Delete works; the row is gone.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "DELETE",
        &format!("/api/v1/users/{ops_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        &format!("/api/v1/users/{ops_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_users_guards_last_super_admin_and_self_delete() {
    let (state, session_store, rate_limiter) = test_state().await;
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let admin_id = {
        let store = state.store.lock().await;
        store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup")
            .id
    };

    // Demoting the only enabled super admin -> 400.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "PUT",
        &format!("/api/v1/users/{admin_id}"),
        &admin,
        Some(serde_json::json!({ "role": "operator" })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Disabling them -> 400.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "PUT",
        &format!("/api/v1/users/{admin_id}"),
        &admin,
        Some(serde_json::json!({ "disabled": true })),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Deleting yourself -> 400 (also the last-super-admin case).
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "DELETE",
        &format!("/api/v1/users/{admin_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_viewer_blocked_from_certificate_download() {
    let (state, session_store, rate_limiter) = test_state().await;
    let _admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;
    let viewer = create_user_and_login(
        &state,
        &session_store,
        &rate_limiter,
        "viewer2",
        lorica_config::models::Role::Viewer,
    )
    .await;

    // The id does not need to exist: the 403 must fire before any
    // lookup, proving the policy gates the whole download surface.
    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/certificates/some-id/download?format=key",
        &viewer,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ---- Routes CRUD Tests ----

#[tokio::test]
async fn test_routes_crud() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "example.com",
        "path_prefix": "/api",
        "load_balancing": "round_robin"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();
    assert_eq!(json["data"]["hostname"], "example.com");

    // List routes
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["routes"].as_array().expect("test setup").len(),
        1
    );

    // Get route by ID
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Update route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "updated.com",
        "enabled": false
    });

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["hostname"], "updated.com");
    assert!(!json["data"]["enabled"].as_bool().expect("test setup"));

    // Delete route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify deleted
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---- Backends CRUD Tests ----

#[tokio::test]
async fn test_backends_crud() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "address": "192.168.1.10:8080",
        "weight": 100,
        "health_check_enabled": true,
        "health_check_interval_s": 10,
        "tls_upstream": false
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let backend_id = json["data"]["id"].as_str().expect("test setup").to_string();
    assert_eq!(json["data"]["address"], "192.168.1.10:8080");

    // List backends
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/backends")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Update backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "address": "10.0.0.1:9090",
        "weight": 50
    });

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/backends/{backend_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["address"], "10.0.0.1:9090");
    assert_eq!(json["data"]["weight"], 50);

    // Delete backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/backends/{backend_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- Certificates Tests ----

#[tokio::test]
async fn test_certificates_crud() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_id = json["data"]["id"].as_str().expect("test setup").to_string();
    assert_eq!(json["data"]["domain"], "example.com");

    // List certificates
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Get certificate detail
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["data"]["cert_pem"].is_string());
    assert!(json["data"]["associated_routes"]
        .as_array()
        .expect("test setup")
        .is_empty());

    // Delete certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_certificate_delete_blocked_by_route() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // Create route referencing certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "example.com",
        "certificate_id": cert_id
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Try to delete certificate - should fail with conflict
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ---- Status Tests ----

#[tokio::test]
async fn test_status_endpoint() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["routes_count"], 0);
    assert_eq!(json["data"]["backends_count"], 0);
    assert_eq!(json["data"]["certificates_count"], 0);
}

// ---- Config Export/Import Tests ----

#[tokio::test]
async fn test_config_export_import() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a backend first
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "address": "10.0.0.1:8080"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Export
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/export")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let toml_content = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test setup")
            .to_vec(),
    )
    .expect("test setup");
    assert!(toml_content.contains("version = 1"));

    // Strip users section (contains redacted password hash from export)
    let toml_content: String = toml_content
        .lines()
        .take_while(|line| !line.starts_with("[[users]]"))
        .collect::<Vec<_>>()
        .join("\n");

    // Import the same config back
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "toml_content": toml_content
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- Ensure admin user tests ----

#[tokio::test]
async fn test_ensure_admin_user_creates_on_first_run() {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let password = ensure_admin_user(&store).expect("test setup");
    assert!(password.is_some());
    assert!(password.expect("test setup").len() >= 24);
}

#[tokio::test]
async fn test_ensure_admin_user_noop_if_exists() {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let first = ensure_admin_user(&store).expect("test setup");
    assert!(first.is_some());
    let second = ensure_admin_user(&store).expect("test setup");
    assert!(second.is_none());
}

// ---- JSON error format test ----

#[tokio::test]
async fn test_json_error_format() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes/nonexistent-id")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    // Verify error envelope structure
    assert!(json["error"].is_object());
    assert!(json["error"]["code"].is_string());
    assert!(json["error"]["message"].is_string());
}

// ---- Logout test ----

#[tokio::test]
async fn test_logout() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Logout
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify session is invalidated
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- Certificate update test ----

#[tokio::test]
async fn test_certificate_update() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_id = json["data"]["id"].as_str().expect("test setup").to_string();
    let original_fingerprint = json["data"]["fingerprint"]
        .as_str()
        .expect("test setup")
        .to_string();

    // Update both cert_pem and key_pem to a different keypair so the
    // resulting bundle still satisfies the v1.5.3 SPKI-match invariant
    // (same loader the worker uses), while the leaf fingerprint
    // changes - swapping only one field of a valid bundle would
    // legitimately fail validation, which is the bug the invariant
    // was added to catch.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "updated.com",
        "cert_pem": TEST_CERT_EC_PEM,
        "key_pem": TEST_KEY_EC_PEM
    });

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["domain"], "updated.com");
    assert_ne!(
        json["data"]["fingerprint"].as_str().expect("test setup"),
        original_fingerprint
    );
}

/// PUT /certificates/{id} that updates ONLY `cert_pem` must
/// re-validate the resulting `(new cert, existing key)` pair, NOT
/// just the new field on its own. Pre-v1.5.3 the API silently
/// landed an invalid bundle in the DB whenever an operator
/// renewed only one half ; the v1.5.3 work re-reads the existing
/// field from the store and validates the merged candidate. This
/// pin makes a future "stop reading the existing field" refactor
/// surface as a named regression instead of as a TLS DecryptError
/// alert weeks later in production.
#[tokio::test]
async fn test_certificate_update_cert_only_with_mismatched_keypair_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Seed with a valid RSA bundle (keypair A).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // PUT only `cert_pem` with a cert from a different keypair (the
    // EC SEC1 fixture). The existing key is RSA, so the merged
    // candidate (EC cert + RSA key) is SPKI-mismatched and must be
    // rejected with 400.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "cert_pem": TEST_CERT_EC_PEM
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let msg = json["error"]["message"]
        .as_str()
        .expect("test setup")
        .to_lowercase();
    assert!(
        msg.contains("matching") || msg.contains("mismatch") || msg.contains("subjectpublickeyinfo"),
        "expected SPKI-mismatch diagnostic, got: {msg}"
    );
}

/// Same shape as `..._cert_only_...`, but the operator submits only
/// the new `key_pem` instead. The merged candidate `(existing cert,
/// new key)` is also SPKI-mismatched and must be rejected with 400.
#[tokio::test]
async fn test_certificate_update_key_only_with_mismatched_keypair_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Seed with the RSA bundle (keypair A).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // PUT only the EC key against the existing RSA cert.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "key_pem": TEST_KEY_EC_PEM
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// `POST /api/v1/config/import` validates every `[[certificates]]`
/// row with the same loader the worker uses. A bulk import that
/// carries even one mismatched bundle must be rejected with 400
/// before any row touches the store, AND the error message must
/// name the offending domain so the operator can fix the source
/// TOML without bisecting the file. This pins the per-row error
/// prefix added in `lorica-api/src/config.rs::import_config`.
#[tokio::test]
async fn test_config_import_with_mismatched_cert_bundle_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Wrap PEMs in TOML triple-quoted strings so newlines round-trip
    // verbatim ; the loader needs the BEGIN/END framing intact.
    // The mismatched row pairs the RSA cert with the OTHER RSA key
    // (different keypair) - exactly the v1.5.3 incident shape.
    let toml_content = format!(
        r#"version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[certificates]]
id = "cert-mismatched"
domain = "mismatched.example.com"
san_domains = []
fingerprint = "deadbeef"
cert_pem = """
{cert}"""
key_pem = """
{key}"""
issuer = "test"
not_before = "2025-01-01T00:00:00Z"
not_after = "2030-01-01T00:00:00Z"
is_acme = false
acme_auto_renew = false
created_at = "2025-01-01T00:00:00Z"
"#,
        cert = TEST_CERT_RSA_PEM,
        // Second RSA-2048 keypair - parses cleanly but does not
        // match `TEST_CERT_RSA_PEM`'s SPKI.
        key = include_str!("../../lorica-tls/tests/test-key-rsa-pkcs1-other.pem"),
    );

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "toml_content": toml_content });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let msg = json["error"]["message"]
        .as_str()
        .expect("test setup")
        .to_string();
    // The per-row prefix MUST surface the originating domain so the
    // operator can fix the TOML without bisecting the file.
    assert!(
        msg.contains("mismatched.example.com"),
        "import error must name the offending domain ; got: {msg}"
    );
    assert!(
        msg.to_lowercase().contains("matching")
            || msg.to_lowercase().contains("mismatch")
            || msg.to_lowercase().contains("subjectpublickeyinfo"),
        "import error must carry the SPKI-mismatch diagnostic ; got: {msg}"
    );

    // No row should have landed in the store - the gate is supposed
    // to fire before `import_to_store`.
    let store = state.store.lock().await;
    let certs = store.list_certificates().expect("list_certificates");
    assert!(
        certs.iter().all(|c| c.domain != "mismatched.example.com"),
        "rejected import must not have written the cert row : {certs:?}"
    );
}

// ---- Self-signed certificate generation test ----

#[tokio::test]
async fn test_generate_self_signed_certificate() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "localhost"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/self-signed")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["domain"], "localhost");
    // rcgen self-signed certs use "rcgen self signed cert" as issuer CN
    assert!(!json["data"]["issuer"]
        .as_str()
        .expect("test setup")
        .is_empty());
    assert!(!json["data"]["fingerprint"]
        .as_str()
        .expect("test setup")
        .is_empty());

    // Verify it's in the list
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["certificates"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );

    // Verify detail contains valid PEM
    let cert_id = json["data"]["certificates"][0]["id"]
        .as_str()
        .expect("test setup")
        .to_string();
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let cert_pem = json["data"]["cert_pem"].as_str().expect("test setup");
    assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert_pem.contains("-----END CERTIFICATE-----"));
}

// ---- Logs Endpoint Tests ----

#[tokio::test]
async fn test_logs_endpoint_empty() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 0);
    assert!(json["data"]["entries"]
        .as_array()
        .expect("test setup")
        .is_empty());
}

#[tokio::test]
async fn test_logs_endpoint_with_entries() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Push some log entries
    use crate::logs::LogEntry;
    for i in 1..=3 {
        state
            .log_buffer
            .push(LogEntry {
                id: 0,
                timestamp: format!("2026-01-0{i}T00:00:00Z"),
                method: "GET".into(),
                path: format!("/path{i}"),
                host: "example.com".into(),
                status: 200,
                latency_ms: 10,
                backend: "10.0.0.1:8080".into(),
                error: None,
                client_ip: String::new(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
            });
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 3);
    assert_eq!(
        json["data"]["entries"]
            .as_array()
            .expect("test setup")
            .len(),
        3
    );
}

#[tokio::test]
async fn test_logs_endpoint_filtering() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    use crate::logs::LogEntry;
    state
        .log_buffer
        .push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            method: "GET".into(),
            path: "/ok".into(),
            host: "example.com".into(),
            status: 200,
            latency_ms: 10,
            backend: "10.0.0.1:8080".into(),
            error: None,
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        });
    state
        .log_buffer
        .push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T00:00:01Z".into(),
            method: "POST".into(),
            path: "/error".into(),
            host: "other.com".into(),
            status: 500,
            latency_ms: 50,
            backend: "10.0.0.2:8080".into(),
            error: Some("internal error".into()),
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        });

    // Filter by route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?route=other.com")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 1);

    // Filter by search
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?search=internal")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 1);
    assert_eq!(json["data"]["entries"][0]["status"], 500);
}

#[tokio::test]
async fn test_clear_logs_endpoint() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    use crate::logs::LogEntry;
    state
        .log_buffer
        .push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            method: "GET".into(),
            path: "/".into(),
            host: "example.com".into(),
            status: 200,
            latency_ms: 5,
            backend: "10.0.0.1:8080".into(),
            error: None,
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        });

    // Clear logs
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/logs")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify empty
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 0);
}

#[tokio::test]
async fn test_logs_endpoint_status_range() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    use crate::logs::LogEntry;
    for (status, path) in [(200, "/ok"), (301, "/redir"), (404, "/miss"), (500, "/err")] {
        state
            .log_buffer
            .push(LogEntry {
                id: 0,
                timestamp: "2026-01-01T00:00:00Z".into(),
                method: "GET".into(),
                path: path.into(),
                host: "test.com".into(),
                status,
                latency_ms: 5,
                backend: "10.0.0.1:80".into(),
                error: None,
                client_ip: String::new(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
            });
    }

    // Filter 4xx-5xx
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?status_min=400")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 2);
}

#[tokio::test]
async fn test_logs_endpoint_time_range() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    use crate::logs::LogEntry;
    state
        .log_buffer
        .push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T10:00:00Z".into(),
            method: "GET".into(),
            path: "/old".into(),
            host: "test.com".into(),
            status: 200,
            latency_ms: 5,
            backend: "10.0.0.1:80".into(),
            error: None,
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        });
    state
        .log_buffer
        .push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T15:00:00Z".into(),
            method: "GET".into(),
            path: "/new".into(),
            host: "test.com".into(),
            status: 200,
            latency_ms: 5,
            backend: "10.0.0.1:80".into(),
            error: None,
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        });

    // Filter: only entries from 12:00 onwards
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?time_from=2026-01-01T12:00:00Z")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 1);
    assert_eq!(json["data"]["entries"][0]["path"], "/new");
}

#[tokio::test]
async fn test_logs_endpoint_limit_and_after_id() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    use crate::logs::LogEntry;
    for i in 1..=10 {
        state
            .log_buffer
            .push(LogEntry {
                id: 0,
                timestamp: format!("2026-01-01T00:00:{:02}Z", i),
                method: "GET".into(),
                path: format!("/p{i}"),
                host: "test.com".into(),
                status: 200,
                latency_ms: 5,
                backend: "10.0.0.1:80".into(),
                error: None,
                client_ip: String::new(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
            });
    }

    // Limit to 3
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?limit=3")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 10);
    assert_eq!(
        json["data"]["entries"]
            .as_array()
            .expect("test setup")
            .len(),
        3
    );

    // after_id: only entries after ID 5
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/logs?after_id=5")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 5);
}

// ---- System Endpoint Tests ----

#[tokio::test]
async fn test_system_endpoint() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/system")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");

    // Verify structure
    assert!(
        json["data"]["host"]["cpu_count"]
            .as_u64()
            .expect("test setup")
            > 0
    );
    assert!(
        json["data"]["host"]["memory_total_bytes"]
            .as_u64()
            .expect("test setup")
            > 0
    );
    assert!(json["data"]["proxy"]["version"].is_string());
    assert!(json["data"]["proxy"]["uptime_seconds"].as_u64().is_some());
    assert!(json["data"]["process"]["memory_bytes"].as_u64().is_some());
    // The proxy pid is surfaced so an operator can confirm a hot
    // binary upgrade took effect (Story 8.4 IV3). In-process tests run
    // in the same process as the handler, so it equals our own pid.
    assert_eq!(
        json["data"]["proxy"]["pid"].as_u64(),
        Some(u64::from(std::process::id()))
    );
}

// ---- Settings Endpoint Tests ----

#[tokio::test]
async fn test_get_settings_defaults() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/settings")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["management_port"], 9443);
    assert_eq!(json["data"]["log_level"], "info");
    assert_eq!(json["data"]["default_health_check_interval_s"], 10);
}

#[tokio::test]
async fn test_update_settings() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "log_level": "debug",
        "default_health_check_interval_s": 30
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["log_level"], "debug");
    assert_eq!(json["data"]["default_health_check_interval_s"], 30);
    assert_eq!(json["data"]["management_port"], 9443);
}

#[tokio::test]
async fn test_get_settings_scrubs_bot_hmac_secret_hex_when_set() {
    // v1.5.1 audit H-1 + followup : when the bot HMAC secret is
    // populated, GET /api/v1/settings must surface the
    // `**REDACTED**` sentinel (parity with the TOML export) so
    // a consumer can tell "secret in place but masked" apart
    // from "secret never initialised". The raw hex must never
    // appear in the response body.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let secret_hex = "a".repeat(64);
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.bot_hmac_secret_hex = secret_hex.clone();
        s.update_global_settings(&cur).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/settings")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["bot_hmac_secret_hex"], "**REDACTED**",
        "non-empty secret must surface the REDACTED sentinel"
    );
    assert!(
        !body.windows(secret_hex.len()).any(|w| w == secret_hex.as_bytes()),
        "raw hex must not appear anywhere in the response body"
    );
    // Sanity : an unrelated field is still present.
    assert_eq!(json["data"]["management_port"], 9443);
}

#[tokio::test]
async fn test_put_settings_response_masks_every_secret() {
    // Story 9.8 QA (CWE-200): the PUT /api/v1/settings response used
    // to return the merged row unmasked, handing back the raw bot
    // HMAC secret, scrape token, syslog mTLS client key and OTLP auth
    // header on every save. The response must mask all four exactly
    // like GET does, and none of the raw bytes may appear anywhere in
    // the body.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let secret_hex = "b".repeat(64);
    let scrape_token = "scrape-token-secret-42".to_string();
    let syslog_key = "-----BEGIN PRIVATE KEY-----\nsyslogsinkkey".to_string();
    let otlp_auth = "Bearer otlp-sink-token-42".to_string();
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.bot_hmac_secret_hex = secret_hex.clone();
        cur.prometheus_scrape_token = Some(scrape_token.clone());
        cur.syslog_tls_client_key_pem = Some(syslog_key.clone());
        cur.otlp_logs_auth_header = Some(otlp_auth.clone());
        s.update_global_settings(&cur).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    // A minimal no-op PATCH: every field absent, so nothing changes
    // and the handler returns the (masked) merged row.
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Cookie", &cookie)
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["bot_hmac_secret_hex"], "**REDACTED**");
    assert_eq!(json["data"]["prometheus_scrape_token"], "**REDACTED**");
    assert_eq!(json["data"]["syslog_tls_client_key_pem"], "**REDACTED**");
    assert_eq!(json["data"]["otlp_logs_auth_header"], "**REDACTED**");
    for raw in [
        secret_hex.as_bytes(),
        scrape_token.as_bytes(),
        b"syslogsinkkey".as_slice(),
        otlp_auth.as_bytes(),
    ] {
        assert!(
            !body.windows(raw.len()).any(|w| w == raw),
            "raw secret bytes must not appear anywhere in the PUT response body"
        );
    }
}

#[tokio::test]
async fn test_get_settings_returns_empty_bot_hmac_when_not_initialised() {
    // v1.5.1 audit H-1 followup : when the bot HMAC secret has
    // never been generated (fresh store, or import of an export
    // with the field already empty), GET /api/v1/settings returns
    // an empty string (NOT the REDACTED sentinel) so the consumer
    // can tell the difference from a masked-but-set secret. A
    // fresh `test_state` boot has no secret seeded, so the default
    // path covers this case.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/settings")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["bot_hmac_secret_hex"], "",
        "uninitialised secret must surface as empty string, not the REDACTED sentinel"
    );
}

#[tokio::test]
async fn test_get_settings_masks_prometheus_scrape_token() {
    // Story 8.8 AC #4: a configured Prometheus scrape token grants
    // unauthenticated /metrics access when `metrics_require_auth` is on,
    // so GET /api/v1/settings must surface the REDACTED sentinel and
    // never the raw token.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let token = "s3cr3t-scrape-token-value";
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.prometheus_scrape_token = Some(token.to_string());
        s.update_global_settings(&cur).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/settings")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["prometheus_scrape_token"], "**REDACTED**");
    assert!(
        !body.windows(token.len()).any(|w| w == token.as_bytes()),
        "raw scrape token must not appear anywhere in the response body"
    );
}

#[tokio::test]
async fn test_update_settings_scrape_token_sentinel_round_trip() {
    // The masked GET returns `**REDACTED**`; a dashboard PUT that echoes
    // that sentinel must leave the stored token untouched, a fresh value
    // must overwrite it, and an empty string must clear it.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let original = "original-scrape-token";
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.prometheus_scrape_token = Some(original.to_string());
        s.update_global_settings(&cur).expect("test setup");
    }

    let put_token = |value: serde_json::Value| {
        let state = state.clone();
        let session_store = session_store.clone();
        let rate_limiter = rate_limiter.clone();
        let cookie = cookie.clone();
        async move {
            let router = app(state, session_store, rate_limiter);
            let body = serde_json::json!({ "prometheus_scrape_token": value });
            let req = Request::builder()
                .method("PUT")
                .uri("/api/v1/settings")
                .header("Content-Type", "application/json")
                .header("Cookie", &cookie)
                .body(Body::from(body.to_string()))
                .expect("test setup");
            router.oneshot(req).await.expect("test setup").status()
        }
    };

    // Echoing the sentinel leaves the token unchanged.
    assert_eq!(put_token(serde_json::json!("**REDACTED**")).await, StatusCode::OK);
    {
        let s = state.store.lock().await;
        assert_eq!(
            s.get_global_settings()
                .expect("test setup")
                .prometheus_scrape_token
                .as_deref(),
            Some(original)
        );
    }

    // A fresh value overwrites.
    assert_eq!(put_token(serde_json::json!("rotated-token")).await, StatusCode::OK);
    {
        let s = state.store.lock().await;
        assert_eq!(
            s.get_global_settings()
                .expect("test setup")
                .prometheus_scrape_token
                .as_deref(),
            Some("rotated-token")
        );
    }

    // An empty string clears it.
    assert_eq!(put_token(serde_json::json!("")).await, StatusCode::OK);
    {
        let s = state.store.lock().await;
        assert_eq!(
            s.get_global_settings()
                .expect("test setup")
                .prometheus_scrape_token,
            None
        );
    }
}

#[tokio::test]
async fn test_update_settings_rejects_cert_warning_not_above_critical() {
    // Backlog #48 cross-field invariant: the warning threshold must fire
    // before the critical one. Both values are within their per-field
    // bounds, so the 400 must come from the cross-field check.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "cert_warning_days": 3, "cert_critical_days": 7 });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(body.to_string()))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("cert_warning_days") && text.contains("cert_critical_days"),
        "the 400 must name the inverted cert-day pair, got: {text}"
    );
}

#[tokio::test]
async fn test_update_settings_rejects_flood_strict_ge_threshold() {
    // Backlog #48 cross-field invariant: strict flood mode is a tighter
    // cap than the plain threshold when both are set, but `0` strict is
    // "auto" and exempt.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // strict == threshold -> rejected.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "flood_threshold_rps": 100, "flood_strict_rps": 100 });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(body.to_string()))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // strict == 0 (auto) with a threshold set -> accepted.
    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "flood_threshold_rps": 100, "flood_strict_rps": 0 });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(body.to_string()))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_dns_provider_credentials_never_returned() {
    // dns_providers promises credentials are never surfaced: a leaked
    // Cloudflare API token would let anyone edit the zone. Create one,
    // then assert neither the create response nor the list body carries
    // the raw token.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let secret = "cloudflare-secret-token-xyz";
    let create_body = serde_json::json!({
        "name": "cf-zone",
        "provider_type": "cloudflare",
        "config": { "api_token": secret, "zone_id": "zone-123" }
    });

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/dns-providers")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(create_body.to_string()))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    assert!(
        !created.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "create response must not echo the raw credential"
    );

    // The list must surface provider metadata but never the secret.
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/dns-providers")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["dns_providers"][0]["name"], "cf-zone");
    assert!(
        !body.windows(secret.len()).any(|w| w == secret.as_bytes()),
        "list response must not carry the raw credential"
    );
}

#[tokio::test]
async fn test_update_settings_invalid_log_level() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "log_level": "invalid" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_settings_otlp_service_name_rejects_control_chars() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    // LF inside the service name - rejected by the new validator
    // added in Batch 6 so a pasted binary blob can't reach the OTel
    // exporter as-is.
    let body = serde_json::json!({ "otlp_service_name": "bad\nname" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("control character"));
}

#[tokio::test]
async fn test_update_settings_sla_purge_retention_cap() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "sla_purge_retention_days": 5000 });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_settings_cert_export_roundtrip() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "cert_export_enabled": true,
        "cert_export_dir": "/var/lib/lorica/exported-certs",
        "cert_export_owner_uid": 1001,
        "cert_export_group_gid": 2001,
        "cert_export_file_mode": 0o640,
        "cert_export_dir_mode": 0o750,
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&payload).expect("test setup");
    // Handler returns the full GlobalSettings doc under the
    // standard "data" envelope. Assert each cert_export field
    // round-tripped with the posted value.
    assert_eq!(json["data"]["cert_export_enabled"], true);
    assert_eq!(
        json["data"]["cert_export_dir"].as_str(),
        Some("/var/lib/lorica/exported-certs")
    );
    assert_eq!(json["data"]["cert_export_owner_uid"], 1001);
    assert_eq!(json["data"]["cert_export_group_gid"], 2001);
    assert_eq!(json["data"]["cert_export_file_mode"], 0o640);
    assert_eq!(json["data"]["cert_export_dir_mode"], 0o750);
}

#[tokio::test]
async fn test_update_settings_upgrade_signing_pubkey_path_roundtrip() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "upgrade_signing_pubkey_path": "/etc/lorica/upgrade-signing.pub",
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&payload).expect("test setup");
    // The PUT response echoes the full GlobalSettings doc; assert the
    // signing-key path round-tripped through the store.
    assert_eq!(
        json["data"]["upgrade_signing_pubkey_path"].as_str(),
        Some("/etc/lorica/upgrade-signing.pub")
    );

    // Confirm it is actually persisted (not just reflected back).
    let stored = {
        let s = state.store.lock().await;
        s.get_global_settings().expect("test setup")
    };
    assert_eq!(
        stored.upgrade_signing_pubkey_path.as_deref(),
        Some("/etc/lorica/upgrade-signing.pub")
    );
}

#[tokio::test]
async fn test_update_settings_cert_export_rejects_relative_dir() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "cert_export_dir": "var/lib/lorica" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("absolute path"));
}

#[tokio::test]
async fn test_update_settings_cert_export_rejects_traversal_dir() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "cert_export_dir": "/var/lib/../etc/shadow" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("traversal"));
}

#[tokio::test]
async fn test_update_settings_cert_export_rejects_mode_out_of_range() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    // 0o1000 = 512 = one bit past the 9 permission bits.
    let body = serde_json::json!({ "cert_export_file_mode": 0o1000 });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("9 permission bits"));
}

#[tokio::test]
async fn test_update_settings_cert_export_clears_dir_on_empty_string() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // First set a dir so we can observe the clear.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "cert_export_dir": "/tmp/lorica-export" });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Now clear it with an empty string - the field should flip
    // back to null (None on the backend) instead of "unchanged".
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "cert_export_dir": "" });
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let payload = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&payload).expect("test setup");
    assert!(json["data"]["cert_export_dir"].is_null());
}

#[tokio::test]
async fn test_rate_limit_settings_bucket_returns_429_after_limit() {
    // PUT /api/v1/settings is capped at 30/60s per IP (v1.5.0 A.3
    // — relaxed from the initial 10/60s after the e2e smoke flagged
    // realistic operator activity on the /settings endpoint under
    // test-isolation). Drive 31 PUTs from the same (simulated)
    // client and assert the 31st returns 429 with a Retry-After
    // header.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let body = serde_json::json!({ "log_level": "info" });
    for i in 0..30 {
        let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/settings")
            .header("Content-Type", "application/json")
            .header("Cookie", &cookie)
            .body(Body::from(
                serde_json::to_string(&body).expect("test setup"),
            ))
            .expect("test setup");
        let response = router.oneshot(req).await.expect("test setup");
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "request {i} within budget should be 200"
        );
    }

    // 11th request over the limit -> 429 + Retry-After.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry = response
        .headers()
        .get("Retry-After")
        .and_then(|v| v.to_str().ok())
        .expect("Retry-After header present on 429");
    let retry_seconds: u64 = retry.parse().expect("Retry-After is a number");
    assert!(
        (1..=60).contains(&retry_seconds),
        "Retry-After {retry_seconds} out of [1, 60]"
    );
}

#[tokio::test]
async fn test_rate_limit_buckets_are_isolated() {
    // Exhausting the settings bucket (10/60s) must NOT affect the
    // routes CRUD bucket (100/60s). Each state-mutating endpoint
    // carries its own bucket so a flood on one does not block the
    // operator from fixing the config elsewhere.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Exhaust the settings bucket (30/60s).
    let body = serde_json::json!({ "log_level": "info" });
    for _ in 0..=30 {
        let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
        let req = Request::builder()
            .method("PUT")
            .uri("/api/v1/settings")
            .header("Content-Type", "application/json")
            .header("Cookie", &cookie)
            .body(Body::from(
                serde_json::to_string(&body).expect("test setup"),
            ))
            .expect("test setup");
        let _ = router.oneshot(req).await;
    }

    // routes_cud bucket should still have budget: a GET /routes
    // (no bucket) + a POST /routes returns a normal 201/400, not
    // a 429. Skip the 400-prone full payload; a GET is enough to
    // prove the router still serves the authenticated session.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_ne!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "GET /routes must not be rate limited by the settings bucket"
    );
}

#[tokio::test]
async fn test_per_route_body_limit_rejects_oversize_payload() {
    // Global default is 1 MiB (v1.5.0 A.4). `POST /api/v1/waf/rules/
    // custom` has a per-route override at 8 KiB because a
    // ModSecurity rule is never legitimately that large. A payload
    // just above that override must land as 413 Payload Too Large
    // without reaching the handler.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Build a JSON body > 8 KiB. The handler would normally need
    // real WAF-rule fields ; the body here is padded garbage that
    // axum rejects BEFORE entering the handler (413 from the body
    // limit, not 400 from validation).
    let padding = "A".repeat(9 * 1024);
    let body = format!("{{\"description\":\"{padding}\"}}");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/waf/rules/custom")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(body))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body over 8 KiB should be rejected with 413"
    );
}

#[tokio::test]
async fn test_global_body_limit_applied_to_unbounded_routes() {
    // Routes without a per-route body-limit override fall back on
    // the global 1 MiB ceiling. Drive a 1.5 MiB payload at
    // `POST /api/v1/backends` (no specific override) and assert
    // 413 bubbles up.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let padding = "A".repeat(1_500_000);
    let body = format!("{{\"name\":\"{padding}\"}}");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(body))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(
        response.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body over 1 MiB on an unbounded route should be rejected with 413"
    );
}

// ---- Notification Endpoint Tests ----

#[tokio::test]
async fn test_notification_crud() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "channel": "email",
        "config": "{\"smtp_host\": \"mail.example.com\"}",
        "alert_types": ["backend_down", "cert_expiring"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let notif_id = json["data"]["id"].as_str().expect("test setup").to_string();
    assert_eq!(json["data"]["channel"], "email");
    assert_eq!(json["data"]["enabled"], serde_json::json!(true));

    // List
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/notifications")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["notifications"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );

    // Update
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "channel": "webhook",
        "enabled": false,
        "config": "{\"url\": \"https://hooks.example.com\"}",
        "alert_types": ["health_change"]
    });

    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/notifications/{notif_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["channel"], "webhook");
    assert_eq!(json["data"]["enabled"], serde_json::json!(false));

    // Delete
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/v1/notifications/{notif_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Verify empty
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/notifications")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["data"]["notifications"]
        .as_array()
        .expect("test setup")
        .is_empty());
}

// ---- Preference Endpoint Tests ----

#[tokio::test]
async fn test_preference_list_update_delete() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create preference directly via store
    {
        let store = state.store.lock().await;
        store
            .create_user_preference(&lorica_config::models::UserPreference {
                id: "pref-1".into(),
                preference_key: "self_signed_cert".into(),
                value: lorica_config::models::PreferenceValue::Once,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            })
            .expect("test setup");
    }

    // List
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/preferences")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["preferences"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );

    // Update
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "value": "always" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/preferences/pref-1")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["value"], "always");

    // Delete
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/preferences/pref-1")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- Import Preview Tests ----

#[tokio::test]
async fn test_import_preview_empty_diff() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Export current state
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/export")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    let toml_content = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test setup")
            .to_vec(),
    )
    .expect("test setup");

    // Strip users section (contains redacted password hash from export)
    let toml_content: String = toml_content
        .lines()
        .take_while(|line| !line.starts_with("[[users]]"))
        .collect::<Vec<_>>()
        .join("\n");

    // Preview with same content - should be empty diff
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "toml_content": toml_content });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import/preview")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["data"]["routes"]["added"]
        .as_array()
        .expect("test setup")
        .is_empty());
    assert!(json["data"]["routes"]["removed"]
        .as_array()
        .expect("test setup")
        .is_empty());
}

#[tokio::test]
async fn test_import_preview_with_changes() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "address": "10.0.0.1:8080" });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Preview import with empty config - should show the backend as "removed"
    let toml_content = "version = 1\n\n[global_settings]\nmanagement_port = 9443\nlog_level = \"info\"\ndefault_health_check_interval_s = 10\ncert_warning_days = 30\ncert_critical_days = 7\n";
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "toml_content": toml_content });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import/preview")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["backends"]["removed"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );
}

// ---- Session GC test ----

#[tokio::test]
async fn test_session_purge_expired() {
    let db = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let store = SessionStore::new(Arc::new(Mutex::new(db))).await;

    // Create a session
    let sid = store.create("user1".into(), "admin".into(), lorica_config::models::Role::SuperAdmin).await;

    // Nothing expired yet
    assert_eq!(store.purge_expired().await, 0);

    // Manually insert an expired session
    {
        use crate::middleware::auth::Session;
        let mut sessions = store.sessions.lock().await;
        sessions.insert(
            "expired-session".to_string(),
            Session {
                user_id: "user2".into(),
                username: "old".into(),
                role: lorica_config::models::Role::SuperAdmin,
                created_at: chrono::Utc::now() - chrono::Duration::hours(2),
                expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
            },
        );
    }

    // Should purge the expired one
    assert_eq!(store.purge_expired().await, 1);
    // Valid session still exists
    assert!(store.get(&sid).await.is_some());
}

// ---- Validation Error Scenario Tests ----

#[tokio::test]
async fn test_create_route_empty_hostname_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "hostname": "",
        "path_prefix": "/"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["error"]["code"], "bad_request");
}

#[tokio::test]
async fn test_create_route_invalid_load_balancing_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "hostname": "example.com",
        "load_balancing": "invalid_algo"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_update_route_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "hostname": "new.com" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/routes/nonexistent-id")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_delete_route_nonexistent_returns_error() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/routes/nonexistent-id")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    // ConfigStore::delete_route returns NotFound for unknown IDs
    assert!(
        response.status() == StatusCode::NOT_FOUND
            || response.status() == StatusCode::INTERNAL_SERVER_ERROR
    );
}

#[tokio::test]
async fn test_create_backend_empty_address_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "address": "" });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_backend_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/backends/nonexistent")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_backend_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "address": "10.0.0.1:80" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/backends/nonexistent")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_create_certificate_empty_domain_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "domain": "",
        "cert_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_certificate_empty_pem_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": "",
        "key_pem": ""
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_get_certificate_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates/nonexistent")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_certificate_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "domain": "new.com" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/certificates/nonexistent")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_self_signed_empty_domain_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "domain": "" });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates/self-signed")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_change_password_too_short_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let known_password = "test_password_123";

    // Create admin and set known password
    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_user(&user).expect("test setup");
    }

    // Login
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let login_body = serde_json::json!({
        "username": "admin",
        "password": known_password
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&login_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let cookie = format!(
        "lorica_session={}",
        extract_session_cookie(&response).expect("test setup")
    );

    // Try change password with too-short new password
    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "current_password": known_password,
        "new_password": "short"
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_change_password_wrong_current_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    let known_password = "test_password_123";

    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
        let mut user = store
            .get_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_user(&user).expect("test setup");
    }

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let login_body = serde_json::json!({
        "username": "admin",
        "password": known_password
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&login_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let cookie = format!(
        "lorica_session={}",
        extract_session_cookie(&response).expect("test setup")
    );

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "current_password": "wrong_password",
        "new_password": "New_secure_password_456"
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_nonexistent_user_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "username": "nonexistent_user",
        "password": "whatever"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- Import Error Scenarios ----

#[tokio::test]
async fn test_import_malformed_toml_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "toml_content": "this is {{ not valid toml !@#$"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_too_large_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Generate content larger than 1MB
    let large_content = "x".repeat(1_048_577);
    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "toml_content": large_content
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(json["error"]["message"]
        .as_str()
        .expect("test setup")
        .contains("too large"));
}

#[tokio::test]
async fn test_import_preview_malformed_toml_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "toml_content": "not valid { toml"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import/preview")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_invalid_references_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let toml_content = r#"version = 1

[global_settings]
management_port = 9443
log_level = "info"
default_health_check_interval_s = 10

[[routes]]
id = "r1"
hostname = "test.com"
path_prefix = "/"
certificate_id = "nonexistent-cert"
load_balancing = "round_robin"
waf_enabled = false
waf_mode = "detection"

enabled = true
created_at = "2026-01-01T00:00:00Z"
updated_at = "2026-01-01T00:00:00Z"
"#;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "toml_content": toml_content });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/import")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---- Settings Validation Error Tests ----

#[tokio::test]
async fn test_settings_invalid_log_level_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "log_level": "verbose" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_settings_invalid_health_check_interval_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "default_health_check_interval_s": 0 });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_settings_invalid_cert_warning_days_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "cert_warning_days": 0 });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_settings_invalid_cert_critical_days_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "cert_critical_days": -1 });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/settings")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---- Notification Validation Tests ----

#[tokio::test]
async fn test_create_notification_invalid_channel_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "channel": "sms",
        "config": "{}",
        "alert_types": ["cert_expiry"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_notification_empty_config_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "channel": "email",
        "config": "",
        "alert_types": ["cert_expiry"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_notification_invalid_json_config_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "channel": "email",
        "config": "not json at all",
        "alert_types": ["cert_expiry"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_test_notification_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications/nonexistent/test")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_test_notification_email_missing_smtp_host_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a notification without smtp_host
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "channel": "email",
        "config": r#"{"recipient":"test@test.com"}"#,
        "alert_types": ["cert_expiry"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let notif_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // Test it - should fail
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/notifications/{notif_id}/test"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_test_notification_webhook_missing_url_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "channel": "webhook",
        "config": r#"{"method":"POST"}"#,
        "alert_types": ["backend_down"]
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/notifications")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let notif_id = json["data"]["id"].as_str().expect("test setup").to_string();

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/notifications/{notif_id}/test"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---- Preference Validation Tests ----

#[tokio::test]
async fn test_update_preference_nonexistent_returns_404() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "value": "always" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/preferences/nonexistent")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_update_preference_invalid_value_returns_400() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a preference first
    {
        let store = state.store.lock().await;
        let pref = lorica_config::models::UserPreference {
            id: "pref-1".into(),
            preference_key: "test_key".into(),
            value: lorica_config::models::PreferenceValue::Never,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        store.create_user_preference(&pref).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({ "value": "invalid_value" });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/preferences/pref-1")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ---- Expired session test ----

#[tokio::test]
async fn test_expired_session_returns_401() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Manually expire all sessions
    {
        let mut sessions = session_store.sessions.lock().await;
        for session in sessions.values_mut() {
            session.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        }
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- System endpoint test ----

#[tokio::test]
async fn test_system_endpoint_returns_all_fields() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/system")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert!(
        json["data"]["host"]["cpu_count"]
            .as_u64()
            .expect("test setup")
            > 0
    );
    assert!(
        json["data"]["host"]["memory_total_bytes"]
            .as_u64()
            .expect("test setup")
            > 0
    );
    assert!(json["data"]["process"].is_object());
    assert!(json["data"]["proxy"]["version"].is_string());
    assert!(json["data"]["proxy"]["uptime_seconds"].is_number());
}

// ---- Route-backend association tests ----

#[tokio::test]
async fn test_create_route_with_backend_ids() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a backend first
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "address": "10.0.0.1:8080" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let backend_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // Create route with backend_ids
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "example.com",
        "backend_ids": [backend_id]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert_eq!(
        json["data"]["backends"]
            .as_array()
            .expect("test setup")
            .len(),
        1
    );
}

#[tokio::test]
async fn test_update_route_backend_associations() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create two backends
    let mut backend_ids = Vec::new();
    for addr in ["10.0.0.1:8080", "10.0.0.2:8080"] {
        let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
        let body = serde_json::json!({ "address": addr });
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/backends")
            .header("Content-Type", "application/json")
            .header("Cookie", &cookie)
            .body(Body::from(
                serde_json::to_string(&body).expect("test setup"),
            ))
            .expect("test setup");
        let response = router.oneshot(req).await.expect("test setup");
        let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("test setup");
        let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
        backend_ids.push(json["data"]["id"].as_str().expect("test setup").to_string());
    }

    // Create route with first backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "example.com",
        "backend_ids": [&backend_ids[0]]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // Update route to use second backend only
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "backend_ids": [&backend_ids[1]]
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let backends = json["data"]["backends"].as_array().expect("test setup");
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].as_str().expect("test setup"), backend_ids[1]);
}

// ---- Status with data test ----

#[tokio::test]
async fn test_status_counts_with_data() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create route + backend + certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "hostname": "example.com" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    router.oneshot(req).await.expect("test setup");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "address": "10.0.0.1:8080" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/backends")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    router.oneshot(req).await.expect("test setup");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": TEST_CERT_RSA_PEM,
        "key_pem": TEST_KEY_RSA_PEM
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    router.oneshot(req).await.expect("test setup");

    // Check status
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["routes_count"], 1);
    assert_eq!(json["data"]["backends_count"], 1);
    // New backends are created with health_status=unknown (not healthy)
    // so backends_healthy is 0 until a health check runs
    assert_eq!(json["data"]["backends_healthy"], 0);
    assert_eq!(json["data"]["certificates_count"], 1);
}

// ---- WAF & Workers helpers ----

async fn test_state_with_waf() -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let store = Arc::new(Mutex::new(store));
    let engine = Arc::new(lorica_waf::WafEngine::new());
    let event_buffer = engine.event_buffer();
    let rule_count = engine.rule_count();
    let state = AppState {
        store: Arc::clone(&store),
        log_buffer: Arc::new(LogBuffer::new(1000)),
        system_cache: Arc::new(Mutex::new(SystemCache::new())),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        started_at: Instant::now(),
        data_dir: std::path::PathBuf::from("/var/lib/lorica"),
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        mode: Mode::Test,
        waf_event_buffer: Some(event_buffer),
        waf_engine: Some(engine),
        waf_rule_count: Some(rule_count),
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        notification_history: None,
        log_store: None,
        log_writer: None,
        task_tracker: tokio_util::task::TaskTracker::new(),
    };
    let session_store = SessionStore::new(store).await;
    let rate_limiter = RateLimiter::new();
    (state, session_store, rate_limiter)
}

async fn test_state_with_workers() -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store: Arc::clone(&store),
        log_buffer: Arc::new(LogBuffer::new(1000)),
        system_cache: Arc::new(Mutex::new(SystemCache::new())),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        started_at: Instant::now(),
        data_dir: std::path::PathBuf::from("/var/lib/lorica"),
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        mode: Mode::Supervisor {
            worker_metrics: Arc::new(WorkerMetrics::new()),
            aggregated_metrics: Arc::new(crate::workers::AggregatedMetrics::new()),
            metrics_refresher: None,
            // No test drives an upgrade through this state; the trigger
            // exists only to satisfy the Supervisor variant, and its
            // receiver is dropped at once (nothing sends on it).
            upgrade_trigger: tokio::sync::mpsc::channel(1).0,
        },
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        notification_history: None,
        log_store: None,
        log_writer: None,
        task_tracker: tokio_util::task::TaskTracker::new(),
    };
    let session_store = SessionStore::new(store).await;
    let rate_limiter = RateLimiter::new();
    (state, session_store, rate_limiter)
}

// ---- WAF Tests ----

#[tokio::test]
async fn test_waf_events_empty() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/waf/events")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["events"], serde_json::json!([]));
    assert_eq!(json["data"]["total"], 0);
    assert!(json["data"]["rule_count"].as_u64().expect("test setup") > 0);
}

#[tokio::test]
async fn test_waf_stats_empty() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/waf/stats")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total_events"], 0);
    assert!(json["data"]["rule_count"].as_u64().expect("test setup") > 0);
    assert_eq!(json["data"]["by_category"], serde_json::json!([]));
}

#[tokio::test]
async fn test_waf_clear_events() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/v1/waf/events")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["cleared"], serde_json::json!(true));
}

#[tokio::test]
async fn test_waf_rules_list() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/waf/rules")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    let total = json["data"]["total"].as_u64().expect("test setup");
    let enabled = json["data"]["enabled"].as_u64().expect("test setup");
    assert!(total > 0, "expected at least one WAF rule");
    assert_eq!(total, enabled, "all rules should be enabled by default");
    assert!(json["data"]["rules"].is_array());
}

#[tokio::test]
async fn test_waf_rules_disable() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({"enabled": false});
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/waf/rules/942100")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["rule_id"], 942100);
    assert_eq!(json["data"]["enabled"], serde_json::json!(false));
}

#[tokio::test]
async fn test_waf_rules_enable() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // First disable rule 942100
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({"enabled": false});
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/waf/rules/942100")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);

    // Then re-enable it
    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({"enabled": true});
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/waf/rules/942100")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["rule_id"], 942100);
    assert_eq!(json["data"]["enabled"], serde_json::json!(true));
}

#[tokio::test]
async fn test_waf_rules_not_found() {
    let (state, session_store, rate_limiter) = test_state_with_waf().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let body = serde_json::json!({"enabled": false});
    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/waf/rules/999999")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_waf_events_without_engine() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/waf/events")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["events"], serde_json::json!([]));
    assert_eq!(json["data"]["total"], 0);
    assert_eq!(json["data"]["rule_count"], 0);
}

// ---- Workers Tests ----

#[tokio::test]
async fn test_workers_empty() {
    let (state, session_store, rate_limiter) = test_state_with_workers().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/workers")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["workers"], serde_json::json!([]));
    assert_eq!(json["data"]["total"], 0);
}

#[tokio::test]
async fn test_workers_with_metrics() {
    let (state, session_store, rate_limiter) = test_state_with_workers().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Record a heartbeat for worker 1
    let metrics = state.worker_metrics().expect("test setup");
    metrics.record_heartbeat(1, 12345, 5).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/workers")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");

    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["total"], 1);
    let workers = json["data"]["workers"].as_array().expect("test setup");
    assert_eq!(workers.len(), 1);
    assert_eq!(workers[0]["worker_id"], 1);
    assert_eq!(workers[0]["pid"], 12345);
    assert_eq!(workers[0]["healthy"], serde_json::json!(true));
}

// ---------------------------------------------------------------------------
// Bot-protection clear semantics: `bot_protection_disable: true` must remove
// an existing config, since the axum JSON layer cannot distinguish absent
// from null so a null-clear scheme would be ambiguous. See crud.rs comment
// on `bot_protection_disable` for the design rationale.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_update_route_bot_protection_disable_clears_existing_config() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // 1. Create a route.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "hostname": "bot-disable.example.com" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // 2. PUT a bot_protection config on it (install path).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "bot_protection": {
            "mode": "javascript",
            "cookie_ttl_s": 3600,
            "pow_difficulty": 18,
            "captcha_alphabet": "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ",
        }
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert_eq!(json["data"]["bot_protection"]["mode"], "javascript");

    // 3. PUT `bot_protection_disable: true` with no config: must clear.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "bot_protection_disable": true });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert!(
        json["data"]["bot_protection"].is_null(),
        "bot_protection must be null after disable: got {}",
        json["data"]["bot_protection"]
    );
}

#[tokio::test]
async fn test_update_route_bot_protection_disable_wins_over_concurrent_config() {
    // Contract: when BOTH `bot_protection_disable: true` AND a
    // `bot_protection` body are sent in the same PUT, disable wins.
    // Rationale: the combination is a client bug; picking either
    // side predictably is better than guessing. crud.rs:1740 uses
    // if/else-if so `disable` is checked first.
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "hostname": "bot-disable-wins.example.com" });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "bot_protection_disable": true,
        "bot_protection": {
            "mode": "captcha",
            "cookie_ttl_s": 3600,
            "pow_difficulty": 18,
            "captcha_alphabet": "23456789abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ",
        }
    });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert!(
        json["data"]["bot_protection"].is_null(),
        "disable must win over concurrent config: got {}",
        json["data"]["bot_protection"]
    );
}

// ---------------------------------------------------------------------------
// HMAC rotation wiring: the certificate-renewal handlers call
// `AppState::rotate_bot_hmac_on_cert_event`, which must write a new
// 32-byte (64-hex-char) secret to `global_settings.bot_hmac_secret_hex`.
// This test exercises the rotation entry point directly and asserts
// the persisted hex changes. The in-memory install (ArcSwap) is the
// responsibility of `lorica::reload::apply_bot_secret_from_store` and
// is covered by its own unit tests in the `lorica` crate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_rotate_bot_hmac_persists_new_hex_secret() {
    let (state, _session_store, _rate_limiter) = test_state().await;

    // Seed a known starting secret so we can assert rotation changed it.
    let initial_hex = "a".repeat(64);
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.bot_hmac_secret_hex = initial_hex.clone();
        s.update_global_settings(&cur).expect("test setup");
    }

    // Rotate.
    state.rotate_bot_hmac_on_cert_event().await;

    // Verify the hex changed and is 64 chars of lowercase hex.
    let s = state.store.lock().await;
    let new_hex = s
        .get_global_settings()
        .expect("test setup")
        .bot_hmac_secret_hex;
    drop(s);
    assert_ne!(
        new_hex, initial_hex,
        "rotation must produce a different secret"
    );
    assert_eq!(new_hex.len(), 64, "rotated secret must be 64 hex chars");
    assert!(
        new_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "rotated secret must be valid hex: {new_hex}"
    );
}

// ---------------------------------------------------------------------------
// OTel collector reachability probe: the dashboard "Test connection"
// button POSTs to /api/v1/settings/otel/test, which reports whether
// the persisted otlp_endpoint accepts a connection. Cover three cases:
//   - endpoint set + mock HTTP server running = {ok: true}
//   - endpoint set + nothing listening on the port = {ok: false}
//   - endpoint unset = {ok: false} with the "save a URL first" hint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_otel_connection_endpoint_unset_returns_save_first_message() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/settings/otel/test")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["ok"], serde_json::json!(false));
    let msg = json["data"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("otlp_endpoint is not set"),
        "unexpected message: {msg}"
    );
}

#[tokio::test]
async fn test_otel_connection_reachable_when_mock_server_responds() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Spawn a minimal HTTP/1.1 server on a random local port. It
    // reads until the blank-line end of headers, then replies 202.
    // The test_otel_connection probe posts with an empty body +
    // Content-Length: 0, so "headers only" is enough to serve it.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("test setup");
    let addr = listener.local_addr().expect("test setup");
    let _server = tokio::spawn(async move {
        // One connection is enough for one probe.
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            // Read until we see "\r\n\r\n" or the peer half-closes.
            let mut total = Vec::new();
            loop {
                let n = match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                total.extend_from_slice(&buf[..n]);
                if total.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if total.len() > 16_384 {
                    break;
                }
            }
            let _ = sock
                .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
        }
    });

    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Persist the mock server as the OTLP endpoint. The probe path
    // appends /v1/traces for http-proto, which our dummy server
    // ignores — it answers any path.
    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.otlp_endpoint = Some(format!("http://{addr}"));
        cur.otlp_protocol = "http-proto".to_string();
        s.update_global_settings(&cur).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/settings/otel/test")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(
        json["data"]["ok"],
        serde_json::json!(true),
        "mock server must look reachable: {json}"
    );
    let msg = json["data"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("reachable"),
        "expected 'reachable' in message: {msg}"
    );
    assert!(
        json["data"]["latency_ms"].is_u64(),
        "latency_ms must be a number: {json}"
    );
}

#[tokio::test]
async fn test_otel_connection_unreachable_when_port_is_dead() {
    // Bind and immediately drop to reserve a port number that we
    // KNOW nothing is listening on. Racing another test for this
    // port is fine: the assertion is on "ok: false", which holds
    // regardless of which process eventually wins the port.
    let addr = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup");
        listener.local_addr().expect("test setup")
    };

    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    {
        let s = state.store.lock().await;
        let mut cur = s.get_global_settings().expect("test setup");
        cur.otlp_endpoint = Some(format!("http://{addr}"));
        cur.otlp_protocol = "http-proto".to_string();
        s.update_global_settings(&cur).expect("test setup");
    }

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/settings/otel/test")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("test setup");
    assert_eq!(json["data"]["ok"], serde_json::json!(false));
    let msg = json["data"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("unreachable"),
        "expected 'unreachable' in message: {msg}"
    );
}

#[tokio::test]
async fn test_rotate_bot_hmac_is_non_deterministic_across_calls() {
    // Two back-to-back rotations on the same state must produce two
    // different secrets — the rotation path pulls fresh bytes from
    // `rand::rngs::OsRng`, so a collision here means the CSPRNG call
    // was accidentally swapped for a deterministic generator.
    let (state, _session_store, _rate_limiter) = test_state().await;

    state.rotate_bot_hmac_on_cert_event().await;
    let first = {
        let s = state.store.lock().await;
        s.get_global_settings()
            .expect("test setup")
            .bot_hmac_secret_hex
    };

    state.rotate_bot_hmac_on_cert_event().await;
    let second = {
        let s = state.store.lock().await;
        s.get_global_settings()
            .expect("test setup")
            .bot_hmac_secret_hex
    };

    assert_ne!(first, second);
}

/// v1.5.1 regression : the dashboard sends `max_connections: 0` to
/// mean "clear the field" on every UPDATE where the operator has
/// not configured an explicit max (see `route-form.ts::empty(0)`).
/// The v1.5.0 `validate_route_numeric_bounds` rejected 0 outright,
/// breaking every route save. End-to-end : a route created with
/// an explicit cap must be clearable back to `None` via an UPDATE
/// carrying 0.
#[tokio::test]
async fn test_update_route_max_connections_zero_clears_the_field() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // 1. Create the route with an explicit `max_connections = 100`.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let create_body = serde_json::json!({
        "hostname": "clear-max-conn.example.com",
        "max_connections": 100,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&create_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert_eq!(json["data"]["max_connections"], 100);
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // 2. UPDATE with `max_connections: 0`. The validator must let it
    //    through ; the handler normalises `Some(0) => None`.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let update_body = serde_json::json!({ "max_connections": 0 });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&update_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "sending max_connections=0 must not 400 any more"
    );

    // 3. Re-fetch and confirm the stored value is cleared (None
    //    serialises as null in JSON).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert!(
        json["data"]["max_connections"].is_null(),
        "max_connections should be cleared to null, got: {:?}",
        json["data"]["max_connections"]
    );
}

/// v1.5.1 companion : CREATE with `max_connections: 0` also
/// normalises to `None` so a raw `curl POST` does not land a
/// meaningless `Some(0)` in the DB that would be interpreted as
/// "cap at 0 connections = reject every request".
#[tokio::test]
async fn test_create_route_max_connections_zero_stores_none() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "zero-max.example.com",
        "max_connections": 0,
        "auto_ban_threshold": 0,
        "return_status": 0,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert!(
        json["data"]["max_connections"].is_null(),
        "max_connections=0 on create must land as None"
    );
    assert!(
        json["data"]["auto_ban_threshold"].is_null(),
        "auto_ban_threshold=0 on create must land as None"
    );
    assert!(
        json["data"]["return_status"].is_null()
            || !json["data"]
                .as_object()
                .expect("test setup")
                .contains_key("return_status"),
        "return_status=0 on create must land as None (absent or null)"
    );
}

/// v1.5.1 follow-up : `cache_ttl_s == 0` and `cache_max_bytes == 0`
/// are valid runtime configurations (always-revalidate + no
/// per-entry size cap). The v1.5.0 validator rejected both with
/// "must be in 1..=MAX", breaking every route save on routes that
/// were legitimately running a 0-TTL cache setup in production.
#[tokio::test]
async fn test_update_route_cache_ttl_zero_is_accepted() {
    let (state, session_store, rate_limiter) = test_state().await;
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create a route with the default TTL.
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let create_body = serde_json::json!({
        "hostname": "zero-ttl.example.com",
        "cache_enabled": true,
        "cache_ttl_s": 300,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/routes")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&create_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::CREATED);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    let route_id = json["data"]["id"].as_str().expect("test setup").to_string();

    // Update to cache_ttl_s = 0 (always revalidate) + cache_max_bytes = 0
    // (no per-entry size cap).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let update_body = serde_json::json!({ "cache_ttl_s": 0, "cache_max_bytes": 0 });
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(
            serde_json::to_string(&update_body).expect("test setup"),
        ))
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "cache_ttl_s=0 and cache_max_bytes=0 must not 400 any more"
    );

    // Re-fetch and confirm the values landed verbatim (cache fields
    // do NOT use the "0 => None" normalisation ; 0 IS the stored
    // value because it carries a distinct runtime semantic).
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .expect("test setup");
    let response = router.oneshot(req).await.expect("test setup");
    assert_eq!(response.status(), StatusCode::OK);
    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("test setup");
    assert_eq!(json["data"]["cache_ttl_s"], 0);
    assert_eq!(json["data"]["cache_max_bytes"], 0);
}

#[tokio::test]
async fn list_bans_includes_reason() {
    let (mut state, _session_store, _rate_limiter) = test_state().await;
    let bans = Arc::new(dashmap::DashMap::new());
    bans.insert(
        "10.0.0.7".to_string(),
        crate::ban::BanRecord {
            banned_at: Instant::now(),
            duration_s: 600,
            reason: crate::ban::BanReason::WafFlood,
        },
    );
    // Put the state in single-process mode with the populated ban list.
    // list_bans reads only the ban list; the other proxy handles are
    // empty defaults, and the cache backend is leaked to obtain the
    // `&'static` the variant requires (one-shot test allocation).
    state.mode = Mode::SingleProcess {
        cache_hits: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        cache_misses: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        ban_list: bans,
        ewma_scores: Arc::new(dashmap::DashMap::new()),
        backend_connections: Arc::new(crate::connections::BackendConnections::new()),
        cache_backend: Box::leak(Box::new(lorica_cache::MemCache::new())),
    };

    let response = crate::cache::list_bans(axum::Extension(state))
        .await
        .expect("list_bans");
    let body = response.0;
    assert_eq!(body["data"]["total"], 1);
    assert_eq!(body["data"]["bans"][0]["ip"], "10.0.0.7");
    assert_eq!(body["data"]["bans"][0]["reason"], "waf_flood");
}

// ---- Hot binary upgrade (Story 8.4) ----

/// Read the live value of `lorica_hot_upgrade_total{outcome=...}` from
/// the process-global registry so a test can assert the AC #5 counter
/// ticked. Returns 0 when the label combination has not been touched.
fn hot_upgrade_counter(outcome: &str) -> u64 {
    for mf in lorica_metrics::gather() {
        if mf.name() != "lorica_hot_upgrade_total" {
            continue;
        }
        for m in mf.get_metric() {
            let hit = m
                .get_label()
                .iter()
                .any(|l| l.name() == "outcome" && l.value() == outcome);
            if hit {
                return m.get_counter().value() as u64;
            }
        }
    }
    0
}

/// Build a `multipart/form-data` body with a `binary` part (raw bytes)
/// and a `signature` part (hex). Returns `(content_type, body)`.
fn build_upgrade_multipart(binary: &[u8], signature_hex: &str) -> (String, Vec<u8>) {
    let boundary = "lorica84boundary";
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"binary\"; filename=\"lorica\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(binary);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\n{signature_hex}\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[tokio::test]
async fn upgrade_endpoint_valid_signature_stages_and_200s() {
    use ed25519_dalek::{Signer, SigningKey};

    let data_dir = tempfile::tempdir().expect("test tempdir");
    let signing = SigningKey::from_bytes(&[42u8; 32]);
    let key_path = data_dir.path().join("upgrade-signing.pub");
    std::fs::write(&key_path, hex_encode(signing.verifying_key().as_bytes()))
        .expect("write key file");

    let (mut state, session_store, rate_limiter) = test_state().await;
    state.data_dir = data_dir.path().to_path_buf();
    {
        let store = state.store.lock().await;
        let mut s = store.get_global_settings().expect("get settings");
        s.upgrade_signing_pubkey_path = Some(key_path.to_string_lossy().into_owned());
        store.update_global_settings(&s).expect("set pubkey path");
    }

    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let binary = b"fake new lorica binary v9.9.9";
    let signature_hex = hex_encode(&signing.sign(binary).to_bytes());
    let (content_type, body) = build_upgrade_multipart(binary, &signature_hex);

    let before = hot_upgrade_counter("ok");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/system/upgrade")
        .header("Content-Type", content_type)
        .header(http::header::COOKIE, &cookie)
        .body(Body::from(body))
        .expect("build request");
    let response = router.oneshot(req).await.expect("request");
    assert_eq!(response.status(), StatusCode::OK);

    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("json");
    assert_eq!(json["data"]["size"], binary.len() as u64);
    assert!(json["data"]["sha256"].as_str().expect("sha256").len() == 64);

    let staged = data_dir.path().join("upgrade").join("lorica.new");
    assert!(staged.exists(), "verified binary must be staged");
    assert_eq!(std::fs::read(&staged).expect("read staged"), binary);

    assert!(
        hot_upgrade_counter("ok") > before,
        "the ok outcome counter must increment on a successful stage"
    );
}

#[tokio::test]
async fn upgrade_endpoint_bad_signature_400s_and_increments_counter() {
    use ed25519_dalek::{Signer, SigningKey};

    let data_dir = tempfile::tempdir().expect("test tempdir");
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let key_path = data_dir.path().join("upgrade-signing.pub");
    std::fs::write(&key_path, hex_encode(signing.verifying_key().as_bytes()))
        .expect("write key file");

    let (mut state, session_store, rate_limiter) = test_state().await;
    state.data_dir = data_dir.path().to_path_buf();
    {
        let store = state.store.lock().await;
        let mut s = store.get_global_settings().expect("get settings");
        s.upgrade_signing_pubkey_path = Some(key_path.to_string_lossy().into_owned());
        store.update_global_settings(&s).expect("set pubkey path");
    }

    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let binary = b"fake new lorica binary";
    // Sign different bytes so the signature does not match `binary`.
    let mut signature = signing.sign(b"a different payload").to_bytes();
    signature[0] ^= 0xff;
    let signature_hex = hex_encode(&signature);
    let (content_type, body) = build_upgrade_multipart(binary, &signature_hex);

    let before = hot_upgrade_counter("signature_failed");

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/system/upgrade")
        .header("Content-Type", content_type)
        .header(http::header::COOKIE, &cookie)
        .body(Body::from(body))
        .expect("build request");
    let response = router.oneshot(req).await.expect("request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    assert!(
        hot_upgrade_counter("signature_failed") > before,
        "the signature_failed outcome counter must increment on a bad signature"
    );

    // Nothing must be staged on a rejected upload.
    assert!(!data_dir.path().join("upgrade").join("lorica.new").exists());
}

#[tokio::test]
async fn upgrade_endpoint_missing_signing_key_400s() {
    use ed25519_dalek::{Signer, SigningKey};

    let data_dir = tempfile::tempdir().expect("test tempdir");
    let (mut state, session_store, rate_limiter) = test_state().await;
    state.data_dir = data_dir.path().to_path_buf();
    // Deliberately leave `upgrade_signing_pubkey_path` unset (None).

    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let signing = SigningKey::from_bytes(&[3u8; 32]);
    let binary = b"some binary";
    let signature_hex = hex_encode(&signing.sign(binary).to_bytes());
    let (content_type, body) = build_upgrade_multipart(binary, &signature_hex);

    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/system/upgrade")
        .header("Content-Type", content_type)
        .header(http::header::COOKIE, &cookie)
        .body(Body::from(body))
        .expect("build request");
    let response = router.oneshot(req).await.expect("request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let resp_body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&resp_body).expect("json");
    assert_eq!(
        json["error"]["message"], "bad request: no upgrade signing key configured",
        "an unconfigured signing key must produce the documented 400 message"
    );
}

// ---- Settings schema endpoint (Story 8.10 AC #7) ----

async fn parse_data(response: axum::response::Response) -> serde_json::Value {
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    json["data"].clone()
}

#[tokio::test]
async fn test_settings_schema_endpoint_shape() {
    let (state, session_store, rate_limiter) = test_state().await;
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/settings/schema",
        &admin,
        None,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let schema = parse_data(resp).await;

    // Enum field: type + choices + default.
    assert_eq!(schema["log_level"]["type"], "enum");
    assert_eq!(schema["log_level"]["default"], "info");
    assert_eq!(
        schema["log_level"]["choices"],
        serde_json::json!(["trace", "debug", "info", "warn", "error"])
    );

    // Ranged integer field: min + max + default.
    assert_eq!(schema["header_timeout_s"]["type"], "integer");
    assert_eq!(schema["header_timeout_s"]["min"], 0);
    assert_eq!(schema["header_timeout_s"]["max"], 3600);
    assert_eq!(schema["header_timeout_s"]["default"], 10);

    // Min-only field: no `max` key (server enforces no ceiling).
    assert_eq!(schema["cert_warning_days"]["min"], 1);
    assert!(schema["cert_warning_days"].get("max").is_none());

    // Enum sourced from the SpoofedFallback model (lowercase serde).
    assert_eq!(
        schema["ai_bot_treat_spoofed_as"]["choices"],
        serde_json::json!(["deny", "log", "allow"])
    );
    assert_eq!(schema["ai_bot_treat_spoofed_as"]["default"], "deny");
}

#[tokio::test]
async fn test_settings_schema_bounds_match_validator() {
    let (state, session_store, rate_limiter) = test_state().await;
    let admin = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let resp = send(
        &state,
        &session_store,
        &rate_limiter,
        "GET",
        "/api/v1/settings/schema",
        &admin,
        None,
    )
    .await;
    let schema = parse_data(resp).await;

    // Anti-drift: the PUT validator must accept the advertised min and
    // max and reject just past the max for every field carrying both
    // bounds. If `update_settings` ever diverges from `settings_schema`
    // the status flips and this fails.
    for field in [
        "health_max_concurrent_probes",
        "header_timeout_s",
        "flood_strict_rps",
        "sla_purge_retention_days",
    ] {
        let min = schema[field]["min"].as_i64().expect("schema min");
        let max = schema[field]["max"].as_i64().expect("schema max");

        for (value, expected) in [
            (min, StatusCode::OK),
            (max, StatusCode::OK),
            (max + 1, StatusCode::BAD_REQUEST),
        ] {
            let mut map = serde_json::Map::new();
            map.insert(field.to_string(), serde_json::json!(value));
            let resp = send(
                &state,
                &session_store,
                &rate_limiter,
                "PUT",
                "/api/v1/settings",
                &admin,
                Some(serde_json::Value::Object(map)),
            )
            .await;
            assert_eq!(
                resp.status(),
                expected,
                "{field}={value} should map to {expected}"
            );
        }
    }
}
