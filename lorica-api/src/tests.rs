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
use crate::server::{build_router, AppState};
use crate::system::SystemCache;
use crate::workers::WorkerMetrics;

async fn test_state() -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup");
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store: Arc::clone(&store),
        log_buffer: Arc::new(LogBuffer::new(1000)),
        system_cache: Arc::new(Mutex::new(SystemCache::new())),
        active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        started_at: Instant::now(),
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        worker_metrics: None,
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        cache_hits: None,
        cache_misses: None,
        ban_list: None,
        cache_backend: None,
        ewma_scores: None,
        backend_connections: None,
        notification_history: None,
        log_store: None,
        aggregated_metrics: None,
        metrics_refresher: None,
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
            .get_admin_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_admin_user(&user).expect("test setup");
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
        "new_password": "new_secure_password_456"
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
        "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIBtest\n-----END PRIVATE KEY-----"
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

    // Strip admin_users section (contains redacted password hash from export)
    let toml_content: String = toml_content
        .lines()
        .take_while(|line| !line.starts_with("[[admin_users]]"))
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
        "cert_pem": "-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----",
        "key_pem": "-----BEGIN PRIVATE KEY-----\noriginal\n-----END PRIVATE KEY-----"
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

    // Update certificate with new PEM
    let router = app(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({
        "domain": "updated.com",
        "cert_pem": "-----BEGIN CERTIFICATE-----\nupdated\n-----END CERTIFICATE-----"
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
            })
            .await;
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
        })
        .await;
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
        })
        .await;

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
        })
        .await;

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
            })
            .await;
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
        })
        .await;
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
        })
        .await;

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
            })
            .await;
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

    // Strip admin_users section (contains redacted password hash from export)
    let toml_content: String = toml_content
        .lines()
        .take_while(|line| !line.starts_with("[[admin_users]]"))
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
            .get_admin_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_admin_user(&user).expect("test setup");
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
            .get_admin_user_by_username("admin")
            .expect("test setup")
            .expect("test setup");
        user.password_hash = hash_password(known_password).expect("test setup");
        store.update_admin_user(&user).expect("test setup");
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
        "new_password": "new_secure_password_456"
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
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        worker_metrics: None,
        waf_event_buffer: Some(event_buffer),
        waf_engine: Some(engine),
        waf_rule_count: Some(rule_count),
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        cache_hits: None,
        cache_misses: None,
        ban_list: None,
        cache_backend: None,
        ewma_scores: None,
        backend_connections: None,
        notification_history: None,
        log_store: None,
        aggregated_metrics: None,
        metrics_refresher: None,
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
        http_port: 8080,
        https_port: 8443,
        config_reload_tx: None,
        worker_metrics: Some(Arc::new(WorkerMetrics::new())),
        waf_event_buffer: None,
        waf_engine: None,
        waf_rule_count: None,
        acme_challenge_store: None,
        pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        cache_hits: None,
        cache_misses: None,
        ban_list: None,
        cache_backend: None,
        ewma_scores: None,
        backend_connections: None,
        notification_history: None,
        log_store: None,
        aggregated_metrics: None,
        metrics_refresher: None,
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
    let metrics = state.worker_metrics.as_ref().expect("test setup");
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
