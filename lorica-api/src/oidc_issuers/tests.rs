// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Tests for issuer-entry administration, and for the bearer gate's
//! OIDC path through the real automation router.
//!
//! The one that matters most is
//! [`removing_an_issuer_refuses_the_next_id_token_immediately`]:
//! AC #5 says a removed entry refuses the next token, and the only way
//! that holds with no invalidation step is for the gate to read the
//! store on every request, which this test proves rather than assumes.
//!
//! The helpers duplicate the shape of the token-administration tests
//! on purpose; a private module is not worth coupling two test files.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::Mutex;
use tower::ServiceExt;

use lorica_config::models::Role;

use crate::auth::{ensure_admin_user, hash_password};
use crate::automation::oidc::test_support::{
    gitlab_claims, sign_hs256, MockIssuer, TestKey, AUDIENCE, ISSUER_URL,
};
use crate::automation::OidcVerifier;
use crate::logs::LogBuffer;
use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::{build_router, AppState, Mode};
use crate::system::SystemCache;

const ISSUERS_PATH: &str = "/api/v1/automation/oidc-issuers";
const WHOAMI_PATH: &str = "/automation/v1/whoami";

async fn test_state(issuer: Arc<MockIssuer>) -> (AppState, SessionStore, RateLimiter) {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup: store opens");
    let store = Arc::new(Mutex::new(store));
    let state = AppState {
        store: Arc::clone(&store),
        log_buffer: Arc::new(LogBuffer::new(100)),
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
        pending_dns_challenges: Arc::new(dashmap::DashMap::new()),
        sla_collector: None,
        load_test_engine: None,
        notification_history: None,
        log_store: None,
        log_writer: None,
        task_tracker: tokio_util::task::TaskTracker::new(),
        cluster: crate::cluster::ClusterRuntime::Standalone,
        oidc: Arc::new(OidcVerifier::new(issuer)),
    };
    let session_store = SessionStore::new(store).await;
    (state, session_store, RateLimiter::new())
}

fn session_cookie(response: &http::Response<Body>) -> String {
    let raw = response
        .headers()
        .get(http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .expect("test setup: login sets a cookie");
    let value = raw
        .split(';')
        .filter_map(|part| part.trim().strip_prefix("lorica_session="))
        .find(|value| !value.is_empty())
        .expect("test setup: cookie carries a session id");
    format!("lorica_session={value}")
}

async fn login(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    username: &str,
    password: &str,
) -> String {
    let router = build_router(state.clone(), session_store.clone(), rate_limiter.clone());
    let body = serde_json::json!({ "username": username, "password": password });
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/login")
        .header("Content-Type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("test setup: login request builds");
    let response = router.oneshot(req).await.expect("test setup: login runs");
    assert_eq!(response.status(), StatusCode::OK, "login should succeed");
    session_cookie(&response)
}

async fn super_admin(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
) -> String {
    let password = {
        let store = state.store.lock().await;
        ensure_admin_user(&store)
            .expect("test setup: admin bootstrap")
            .expect("test setup: admin password returned")
    };
    login(state, session_store, rate_limiter, "admin", &password).await
}

async fn operator(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
) -> String {
    let password = "Oidc-issuer-test-42!";
    {
        let store = state.store.lock().await;
        store
            .create_user(&lorica_config::models::User {
                id: uuid::Uuid::new_v4().to_string(),
                username: "operator".to_string(),
                password_hash: hash_password(password).expect("test setup: password hashes"),
                role: Role::Operator,
                must_change_password: false,
                created_at: chrono::Utc::now(),
                last_login_at: None,
                disabled_at: None,
                created_by: None,
            })
            .expect("test setup: user created");
    }
    login(state, session_store, rate_limiter, "operator", password).await
}

async fn management(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    method: &str,
    uri: &str,
    cookie: &str,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let router = build_router(state.clone(), session_store.clone(), rate_limiter.clone());
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("Cookie", cookie);
    let body = match body {
        Some(json) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    router
        .oneshot(builder.body(body).expect("test setup: request builds"))
        .await
        .expect("test setup: management request runs")
}

/// One request on the automation plane, through the real router with
/// its bearer gate, scope gate and audit layer.
async fn automation(state: &AppState, bearer: &str) -> axum::response::Response {
    let router = crate::automation::build_automation_router(state.clone());
    let req = Request::builder()
        .method("GET")
        .uri(WHOAMI_PATH)
        .header(http::header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("test setup: automation request builds");
    router
        .oneshot(req)
        .await
        .expect("test setup: automation request runs")
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup: body reads");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn create_body() -> serde_json::Value {
    serde_json::json!({
        "issuer": ISSUER_URL,
        "audience": AUDIENCE,
        "bound_claims": { "project_path": "acme/*", "ref_protected": "true" },
        "allowed_hostnames": ["*.review.example.com"],
        "allowed_backend_cidrs": ["10.0.0.0/8"],
        "scopes": ["environments:read", "environments:write"],
    })
}

/// Register an entry as SuperAdmin and return its id.
async fn register(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    cookie: &str,
    body: serde_json::Value,
) -> String {
    let response = management(
        state,
        session_store,
        rate_limiter,
        "POST",
        ISSUERS_PATH,
        cookie,
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    body_json(response).await["data"]["id"]
        .as_str()
        .expect("the entry carries an id")
        .to_string()
}

// ---- The management surface ----

#[tokio::test]
async fn an_entry_is_registered_listed_with_defaults_and_removed() {
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;

    let id = register(&state, &sessions, &limiter, &admin, create_body()).await;

    let listing = body_json(
        management(
            &state,
            &sessions,
            &limiter,
            "GET",
            ISSUERS_PATH,
            &admin,
            None,
        )
        .await,
    )
    .await;
    let rows = listing["data"]["issuers"]
        .as_array()
        .expect("the listing answers with an array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["id"], id);
    assert_eq!(
        rows[0]["jwks_url"],
        format!("{ISSUER_URL}/oauth/discovery/keys")
    );
    assert_eq!(rows[0]["max_ttl_seconds"], 7 * 24 * 60 * 60);
    assert_eq!(rows[0]["created_by"], "admin");
    assert_eq!(rows[0]["bound_claims"]["project_path"], "acme/*");

    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{ISSUERS_PATH}/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{ISSUERS_PATH}/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "a typo must not read as a removal"
    );
}

#[tokio::test]
async fn the_model_rules_are_refused_with_a_422_naming_the_field() {
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;

    for (field, value) in [
        ("issuer", serde_json::json!("http://gitlab.example.com")),
        ("bound_claims", serde_json::json!({ "ref_protected": "*" })),
        ("bound_claims", serde_json::json!({ "sub": "anything" })),
        ("scopes", serde_json::json!([])),
        ("allowed_hostnames", serde_json::json!(["*"])),
    ] {
        let mut body = create_body();
        body[field] = value;
        let response = management(
            &state,
            &sessions,
            &limiter,
            "POST",
            ISSUERS_PATH,
            &admin,
            Some(body),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field} must be refused"
        );
    }

    let mut unknown = create_body();
    unknown["created_by"] = serde_json::json!("mallory");
    let response = management(
        &state,
        &sessions,
        &limiter,
        "POST",
        ISSUERS_PATH,
        &admin,
        Some(unknown),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "a server-owned field on input is refused, not ignored"
    );
}

#[tokio::test]
async fn every_method_is_super_admin_only() {
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let id = register(&state, &sessions, &limiter, &admin, create_body()).await;
    let operator = operator(&state, &sessions, &limiter).await;

    for (method, uri, body) in [
        ("GET", ISSUERS_PATH.to_string(), None),
        ("POST", ISSUERS_PATH.to_string(), Some(create_body())),
        ("DELETE", format!("{ISSUERS_PATH}/{id}"), None),
    ] {
        let response = management(&state, &sessions, &limiter, method, &uri, &operator, body).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must be SuperAdmin"
        );
    }
}

#[tokio::test]
async fn the_admin_routes_are_not_reachable_through_the_automation_router() {
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    register(&state, &sessions, &limiter, &admin, create_body()).await;

    let router = crate::automation::build_automation_router(state.clone());
    let token = key.sign(&gitlab_claims());
    for (method, uri) in [("GET", ISSUERS_PATH), ("POST", ISSUERS_PATH)] {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("test setup: request builds");
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("test setup: request runs");
        assert_ne!(
            response.status(),
            StatusCode::OK,
            "{method} {uri} must not be served by the automation listener"
        );
        assert!(
            response.status() == StatusCode::NOT_FOUND
                || response.status() == StatusCode::FORBIDDEN
                || response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::UNAUTHORIZED,
            "{method} {uri} answered {}",
            response.status()
        );
    }
}

// ---- The bearer gate's OIDC path (AC #2, #5) ----

#[tokio::test]
async fn a_registered_issuer_makes_an_id_token_a_principal() {
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let id = register(&state, &sessions, &limiter, &admin, create_body()).await;

    let response = automation(&state, &key.sign(&gitlab_claims())).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["data"]["name"], "acme/web");
    assert_eq!(json["data"]["public_id"], id);
    assert_eq!(json["data"]["kind"], "oidc_project");
    assert_eq!(json["data"]["pipeline"]["pipeline_id"], "1234");
    assert_eq!(json["data"]["pipeline"]["ref"], "main");
}

#[tokio::test]
async fn removing_an_issuer_refuses_the_next_id_token_immediately() {
    let key = TestKey::generate("k1");
    let issuer = MockIssuer::serving(&[&key]);
    let (state, sessions, limiter) = test_state(issuer.clone()).await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let id = register(&state, &sessions, &limiter, &admin, create_body()).await;

    assert_eq!(
        automation(&state, &key.sign(&gitlab_claims()))
            .await
            .status(),
        StatusCode::OK
    );
    let fetches_before = issuer.fetches();

    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{ISSUERS_PATH}/{id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // The very next token, freshly minted and otherwise perfect, is
    // refused: the gate read the store, found no entry for the
    // audience, and never reached the key cache, which still holds a
    // key that would have verified it.
    let response = automation(&state, &key.sign(&gitlab_claims())).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        issuer.fetches(),
        fetches_before,
        "no fetch for a token no entry vouches for"
    );
}

#[tokio::test]
async fn every_refusal_answers_the_static_path_body() {
    // The wire must not say which mode was tried. Compare the bodies
    // of a static-token refusal, an OIDC refusal of each kind the
    // verifier distinguishes, and a value that is neither.
    let key = TestKey::generate("k1");
    let (state, sessions, limiter) = test_state(MockIssuer::serving(&[&key])).await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    register(&state, &sessions, &limiter, &admin, create_body()).await;

    let static_refusal = automation(
        &state,
        "0123456789abcdef01234567.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    )
    .await;
    assert_eq!(static_refusal.status(), StatusCode::UNAUTHORIZED);
    let reference = body_json(static_refusal).await;
    assert!(reference["error"]["message"].is_string());

    let mut other_audience = gitlab_claims();
    other_audience["aud"] = serde_json::json!("someone-else");
    let mut other_project = gitlab_claims();
    other_project["project_path"] = serde_json::json!("globex/web");
    let mut expired = gitlab_claims();
    expired["exp"] = serde_json::json!(chrono::Utc::now().timestamp() - 600);
    let replayed = key.sign(&gitlab_claims());
    assert_eq!(automation(&state, &replayed).await.status(), StatusCode::OK);

    for (label, bearer) in [
        ("wrong audience", key.sign(&other_audience)),
        ("bound claim mismatch", key.sign(&other_project)),
        ("expired", key.sign(&expired)),
        ("replayed", replayed),
        (
            "algorithm confusion",
            sign_hs256(&key.public_key_der(), "k1", &gitlab_claims()),
        ),
        ("neither credential", "not-a-credential".to_string()),
    ] {
        let response = automation(&state, &bearer).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{label}");
        assert_eq!(
            response
                .headers()
                .get(http::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer realm=\"lorica-automation\""),
            "{label}"
        );
        assert_eq!(
            body_json(response).await,
            reference,
            "{label}: the body must not differ"
        );
    }
}
