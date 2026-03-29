use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::Mutex;
use tower::ServiceExt;

use crate::auth::{ensure_admin_user, hash_password};
use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::{build_router, AppState};

fn test_state() -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().unwrap();
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
    };
    let session_store = SessionStore::new();
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
        let pw = ensure_admin_user(&store).unwrap().unwrap();
        pw
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let session_id = extract_session_cookie(&response).unwrap();
    format!("lorica_session={session_id}")
}

// ---- Auth Tests ----

#[tokio::test]
async fn test_login_success() {
    let (state, session_store, rate_limiter) = test_state();

    let password = {
        let store = state.store.lock().await;
        ensure_admin_user(&store).unwrap().unwrap()
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(http::header::SET_COOKIE));

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"]["must_change_password"].as_bool().unwrap());
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let (state, session_store, rate_limiter) = test_state();

    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).unwrap();
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn test_unauthenticated_request_returns_401() {
    let (state, session_store, rate_limiter) = test_state();
    let router = app(state, session_store, rate_limiter);

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_change_password() {
    let (state, session_store, rate_limiter) = test_state();
    let _cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let known_password = "test_password_123";
    {
        let store = state.store.lock().await;
        let mut user = store.get_admin_user_by_username("admin").unwrap().unwrap();
        user.password_hash = hash_password(known_password).unwrap();
        store.update_admin_user(&user).unwrap();
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
        .body(Body::from(serde_json::to_string(&login_body).unwrap()))
        .unwrap();
    let response = router2.oneshot(req).await.unwrap();
    let cookie2 = format!(
        "lorica_session={}",
        extract_session_cookie(&response).unwrap()
    );

    // Change password
    let router3 = app(state, session_store, rate_limiter);
    let body = serde_json::json!({
        "current_password": known_password,
        "new_password": "new_secure_password_456"
    });

    let req = Request::builder()
        .method("PUT")
        .uri("/api/v1/auth/password")
        .header("Content-Type", "application/json")
        .header("Cookie", cookie2)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router3.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_rate_limiting() {
    let (state, session_store, rate_limiter) = test_state();

    {
        let store = state.store.lock().await;
        ensure_admin_user(&store).unwrap();
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
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = router.oneshot(req).await.unwrap();
        if i < 5 {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
}

// ---- Routes CRUD Tests ----

#[tokio::test]
async fn test_routes_crud() {
    let (state, session_store, rate_limiter) = test_state();
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let route_id = json["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(json["data"]["hostname"], "example.com");

    // List routes
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["routes"].as_array().unwrap().len(), 1);

    // Get route by ID
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Update route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "hostname": "updated.com",
        "enabled": false
    });

    let req = Request::builder()
        .method("PUT")
        .uri(&format!("/api/v1/routes/{route_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["hostname"], "updated.com");
    assert!(!json["data"]["enabled"].as_bool().unwrap());

    // Delete route
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify deleted
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/api/v1/routes/{route_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---- Backends CRUD Tests ----

#[tokio::test]
async fn test_backends_crud() {
    let (state, session_store, rate_limiter) = test_state();
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let backend_id = json["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(json["data"]["address"], "192.168.1.10:8080");

    // List backends
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/backends")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Update backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "address": "10.0.0.1:9090",
        "weight": 50
    });

    let req = Request::builder()
        .method("PUT")
        .uri(&format!("/api/v1/backends/{backend_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["address"], "10.0.0.1:9090");
    assert_eq!(json["data"]["weight"], 50);

    // Delete backend
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/backends/{backend_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- Certificates Tests ----

#[tokio::test]
async fn test_certificates_crud() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIBtest\n-----END PRIVATE KEY-----"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_id = json["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(json["data"]["domain"], "example.com");

    // List certificates
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Get certificate detail
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["data"]["cert_pem"].is_string());
    assert!(json["data"]["associated_routes"]
        .as_array()
        .unwrap()
        .is_empty());

    // Delete certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_certificate_delete_blocked_by_route() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_id = json["data"]["id"].as_str().unwrap().to_string();

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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Try to delete certificate - should fail with conflict
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("DELETE")
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

// ---- Status Tests ----

#[tokio::test]
async fn test_status_endpoint() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/status")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["routes_count"], 0);
    assert_eq!(json["data"]["backends_count"], 0);
    assert_eq!(json["data"]["certificates_count"], 0);
}

// ---- Config Export/Import Tests ----

#[tokio::test]
async fn test_config_export_import() {
    let (state, session_store, rate_limiter) = test_state();
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Export
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/config/export")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let toml_content = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(toml_content.contains("version = 1"));

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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ---- Ensure admin user tests ----

#[tokio::test]
async fn test_ensure_admin_user_creates_on_first_run() {
    let store = lorica_config::ConfigStore::open_in_memory().unwrap();
    let password = ensure_admin_user(&store).unwrap();
    assert!(password.is_some());
    assert!(password.unwrap().len() >= 24);
}

#[tokio::test]
async fn test_ensure_admin_user_noop_if_exists() {
    let store = lorica_config::ConfigStore::open_in_memory().unwrap();
    let first = ensure_admin_user(&store).unwrap();
    assert!(first.is_some());
    let second = ensure_admin_user(&store).unwrap();
    assert!(second.is_none());
}

// ---- JSON error format test ----

#[tokio::test]
async fn test_json_error_format() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes/nonexistent-id")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // Verify error envelope structure
    assert!(json["error"].is_object());
    assert!(json["error"]["code"].is_string());
    assert!(json["error"]["message"].is_string());
}

// ---- Logout test ----

#[tokio::test]
async fn test_logout() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Logout
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify session is invalidated
    let router = app(state, session_store, rate_limiter);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/routes")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- Certificate update test ----

#[tokio::test]
async fn test_certificate_update() {
    let (state, session_store, rate_limiter) = test_state();
    let cookie = setup_admin_and_login(&state, &session_store, &rate_limiter).await;

    // Create certificate
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "example.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\noriginal\n-----END PRIVATE KEY-----"
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/certificates")
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_id = json["data"]["id"].as_str().unwrap().to_string();
    let original_fingerprint = json["data"]["fingerprint"].as_str().unwrap().to_string();

    // Update certificate with new PEM
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "updated.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nupdated\n-----END CERTIFICATE-----"
    });

    let req = Request::builder()
        .method("PUT")
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .header("Content-Type", "application/json")
        .header("Cookie", &cookie)
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["domain"], "updated.com");
    assert_ne!(
        json["data"]["fingerprint"].as_str().unwrap(),
        original_fingerprint
    );
}

// ---- Self-signed certificate generation test ----

#[tokio::test]
async fn test_generate_self_signed_certificate() {
    let (state, session_store, rate_limiter) = test_state();
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
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["domain"], "localhost");
    assert_eq!(json["data"]["issuer"], "Self-signed");
    assert!(!json["data"]["fingerprint"].as_str().unwrap().is_empty());

    // Verify it's in the list
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/certificates")
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["data"]["certificates"].as_array().unwrap().len(), 1);

    // Verify detail contains valid PEM
    let cert_id = json["data"]["certificates"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let req = Request::builder()
        .method("GET")
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .header("Cookie", &cookie)
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let cert_pem = json["data"]["cert_pem"].as_str().unwrap();
    assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(cert_pem.contains("-----END CERTIFICATE-----"));
}

// ---- Session GC test ----

#[tokio::test]
async fn test_session_purge_expired() {
    let store = SessionStore::new();

    // Create a session
    let sid = store.create("user1".into(), "admin".into()).await;

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
