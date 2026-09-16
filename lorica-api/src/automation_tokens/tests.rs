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

//! Tests for automation-token administration.
//!
//! The one that matters most is
//! [`a_minted_token_is_accepted_by_the_automation_listener`]: the mint
//! and the verification were written on opposite sides of the product,
//! against the same model but never against each other, and a
//! disagreement between them is a credential that looks fine in the
//! dashboard and fails on every call.
//!
//! The helpers below duplicate the shape of the crate-wide test
//! harness on purpose. They are small, and a private module is not
//! worth coupling two test files that different people edit.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tokio::sync::Mutex;
use tower::ServiceExt;

use lorica_config::models::Role;

use crate::auth::{ensure_admin_user, hash_password};
use crate::logs::LogBuffer;
use crate::middleware::auth::SessionStore;
use crate::middleware::rate_limit::RateLimiter;
use crate::server::{build_router, AppState, Mode};
use crate::system::SystemCache;

/// The management-plane path both list and create live on.
const TOKENS_PATH: &str = "/api/v1/automation/tokens";

/// The one automation endpoint Story 10.3 ships, used here as proof
/// that a minted credential authenticates.
const WHOAMI_PATH: &str = "/automation/v1/whoami";

async fn test_state() -> (AppState, SessionStore, RateLimiter) {
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
        oidc: crate::automation::oidc::test_support::verifier_without_issuer(),
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

/// The bootstrap SuperAdmin, logged in.
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

/// A user at `role`, logged in.
async fn user_at_role(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    username: &str,
    role: Role,
) -> String {
    let password = "Automation-token-test-42!";
    {
        let store = state.store.lock().await;
        store
            .create_user(&lorica_config::models::User {
                id: uuid::Uuid::new_v4().to_string(),
                username: username.to_string(),
                password_hash: hash_password(password).expect("test setup: password hashes"),
                role,
                must_change_password: false,
                created_at: chrono::Utc::now(),
                last_login_at: None,
                disabled_at: None,
                created_by: None,
            })
            .expect("test setup: user created");
    }
    login(state, session_store, rate_limiter, username, password).await
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
async fn automation(
    state: &AppState,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
) -> axum::response::Response {
    let router = crate::automation::build_automation_router(state.clone());
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = bearer {
        builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    router
        .oneshot(
            builder
                .body(Body::empty())
                .expect("test setup: automation request builds"),
        )
        .await
        .expect("test setup: automation request runs")
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup: body reads");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// A create body that validates, so each test below changes exactly
/// one thing.
fn create_body() -> serde_json::Value {
    serde_json::json!({
        "name": "ci pipeline",
        "scopes": ["environments:read", "environments:write"],
        "allowed_hostnames": ["*.preview.example.com"],
        "allowed_backend_cidrs": ["10.0.0.0/8"],
    })
}

/// Mint a token as SuperAdmin and return `(full token, public_id)`.
async fn mint(
    state: &AppState,
    session_store: &SessionStore,
    rate_limiter: &RateLimiter,
    cookie: &str,
) -> (String, String) {
    let response = management(
        state,
        session_store,
        rate_limiter,
        "POST",
        TOKENS_PATH,
        cookie,
        Some(create_body()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let json = body_json(response).await;
    let data = &json["data"];
    (
        data["token"]
            .as_str()
            .expect("mint answers with the token")
            .to_string(),
        data["public_id"]
            .as_str()
            .expect("mint answers with the public id")
            .to_string(),
    )
}

// ---- Mint and verify agree ----

#[tokio::test]
async fn a_minted_token_is_accepted_by_the_automation_listener() {
    // The two halves of this credential were written separately: the
    // management plane hashes a fresh secret under the node key, and
    // the automation plane verifies a presented one against the stored
    // digest. Nothing but this test puts them in the same sentence.
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    let response = automation(&state, "GET", WHOAMI_PATH, Some(&token)).await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the listener must accept the token the management plane just minted"
    );
    let json = body_json(response).await;
    assert_eq!(json["data"]["public_id"], public_id);
    assert_eq!(json["data"]["name"], "ci pipeline");
}

#[tokio::test]
async fn a_tampered_secret_is_refused_even_with_a_known_public_id() {
    // The mirror of the test above: what makes the acceptance
    // meaningful is that the verification is actually checking the
    // secret and not merely the presence of a known row.
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    let secret = token
        .split_once('.')
        .expect("a minted token has both halves")
        .1;
    let mut flipped: Vec<char> = secret.chars().collect();
    flipped[0] = if flipped[0] == 'A' { 'B' } else { 'A' };
    let forged: String = format!("{public_id}.{}", flipped.into_iter().collect::<String>());

    let response = automation(&state, "GET", WHOAMI_PATH, Some(&forged)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---- The secret is returned exactly once ----

#[tokio::test]
async fn the_full_token_is_returned_exactly_once_and_never_again() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, _) = mint(&state, &sessions, &limiter, &admin).await;

    let listing = body_json(
        management(
            &state,
            &sessions,
            &limiter,
            "GET",
            TOKENS_PATH,
            &admin,
            None,
        )
        .await,
    )
    .await;
    let rendered = listing.to_string();
    assert!(
        !rendered.contains(&token),
        "the listing must not carry the token string"
    );
    assert!(
        !rendered.contains("\"token\""),
        "the listing must not carry a token field at all"
    );
}

#[tokio::test]
async fn a_listed_token_carries_no_secret_and_no_hmac() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    let stored_hmac = {
        let store = state.store.lock().await;
        store
            .get_automation_token(&public_id)
            .expect("test setup: the row reads")
            .expect("test setup: the row exists")
            .secret_hmac
    };

    let listing = body_json(
        management(
            &state,
            &sessions,
            &limiter,
            "GET",
            TOKENS_PATH,
            &admin,
            None,
        )
        .await,
    )
    .await;
    let rows = listing["data"]["tokens"]
        .as_array()
        .expect("the listing answers with an array");
    assert_eq!(rows.len(), 1);
    let row = rows[0].as_object().expect("each listed token is an object");

    assert!(!row.contains_key("secret_hmac"));
    assert!(!row.contains_key("secret"));
    assert!(!row.contains_key("token"));
    let rendered = listing.to_string();
    assert!(
        !rendered.contains(&stored_hmac),
        "the stored HMAC is the offline-guessing target; it must not be rendered"
    );
    assert!(!rendered.contains(&token));

    // What the listing DOES carry, because it is what an operator
    // reads it for.
    assert_eq!(row["public_id"], public_id);
    assert_eq!(row["name"], "ci pipeline");
    assert!(row.contains_key("last_used_at"));
    assert!(row.contains_key("revoked_at"));
    assert!(row.contains_key("expires_at"));
    assert!(row.contains_key("scopes"));
    assert!(row.contains_key("allowed_hostnames"));
}

// ---- Revocation ----

#[tokio::test]
async fn revoke_stamps_the_row_and_keeps_it() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (_, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{TOKENS_PATH}/{public_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let revoked_at = body_json(response).await["data"]["revoked_at"].clone();
    assert!(revoked_at.is_string(), "revocation stamps the row");

    // The row survives, which is the whole point: after an incident
    // the audit trail has to still name the credential.
    let listing = body_json(
        management(
            &state,
            &sessions,
            &limiter,
            "GET",
            TOKENS_PATH,
            &admin,
            None,
        )
        .await,
    )
    .await;
    let rows = listing["data"]["tokens"]
        .as_array()
        .expect("the listing answers with an array");
    assert_eq!(rows.len(), 1, "revoking must not delete the row");
    assert_eq!(rows[0]["public_id"], public_id);
    assert_eq!(rows[0]["revoked_at"], revoked_at);
}

#[tokio::test]
async fn a_revoked_token_is_refused_by_the_listener_on_its_next_request() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    assert_eq!(
        automation(&state, "GET", WHOAMI_PATH, Some(&token))
            .await
            .status(),
        StatusCode::OK
    );

    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{TOKENS_PATH}/{public_id}"),
        &admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    // Nothing caches the token row, so the very next request sees the
    // revocation with no invalidation step in between.
    assert_eq!(
        automation(&state, "GET", WHOAMI_PATH, Some(&token))
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoking_twice_is_not_an_error_and_keeps_the_first_stamp() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (_, public_id) = mint(&state, &sessions, &limiter, &admin).await;
    let uri = format!("{TOKENS_PATH}/{public_id}");

    let first = management(&state, &sessions, &limiter, "DELETE", &uri, &admin, None).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_stamp = body_json(first).await["data"]["revoked_at"].clone();

    let second = management(&state, &sessions, &limiter, "DELETE", &uri, &admin, None).await;
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "revocation is done under pressure, often twice; the second call \
         finds the state the caller wanted"
    );
    assert_eq!(
        body_json(second).await["data"]["revoked_at"],
        first_stamp,
        "the second revoke must not rewrite when the credential stopped working"
    );
}

#[tokio::test]
async fn revoking_an_unknown_public_id_is_a_404() {
    // A different mistake from revoking twice: answering 200 would let
    // a typo read as a successful revocation.
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let response = management(
        &state,
        &sessions,
        &limiter,
        "DELETE",
        &format!("{TOKENS_PATH}/ffffffffffffffffffffffff"),
        &admin,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---- Role floor ----

#[tokio::test]
async fn the_admin_routes_are_super_admin_and_refused_below() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (_, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    for role in [Role::Operator, Role::Viewer] {
        let cookie = user_at_role(
            &state,
            &sessions,
            &limiter,
            &format!("below-{}", role.as_str()),
            role,
        )
        .await;
        for (method, uri, body) in [
            ("GET", TOKENS_PATH.to_string(), None),
            ("POST", TOKENS_PATH.to_string(), Some(create_body())),
            ("DELETE", format!("{TOKENS_PATH}/{public_id}"), None),
        ] {
            let response =
                management(&state, &sessions, &limiter, method, &uri, &cookie, body).await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "{method} {uri} must be SuperAdmin-only ({} tried it)",
                role.as_str()
            );
        }
    }
}

// ---- Plane separation ----

#[tokio::test]
async fn the_admin_routes_are_not_reachable_through_the_automation_router() {
    // A token that can mint tokens outlives its own revocation: its
    // holder mints a successor before an operator withdraws it. So the
    // automation router has no route for these paths, and a token
    // carrying every scope in the enum still gets nowhere: the scope
    // gate wraps the whole router and refuses an undeclared path for
    // every caller, which is why the answer is 403 rather than the 404
    // an unrouted path would give on its own.
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (token, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    for (method, uri) in [
        ("GET", TOKENS_PATH.to_string()),
        ("POST", TOKENS_PATH.to_string()),
        ("DELETE", format!("{TOKENS_PATH}/{public_id}")),
    ] {
        let response = automation(&state, method, &uri, Some(&token)).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} {uri} must not be served on the automation plane"
        );
    }

    // And nothing happened on the way: no token was minted, and the one
    // that exists is still standing. A refusal that had already written
    // would be worse than no refusal at all.
    let rows = {
        let store = state.store.lock().await;
        store
            .list_automation_tokens()
            .expect("test setup: the listing reads")
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].public_id, public_id);
    assert_eq!(rows[0].revoked_at, None);
}

// ---- Validation is the model's ----

#[tokio::test]
async fn an_invalid_request_is_refused_by_the_models_validator_with_the_field_named() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;

    // Each case: the field changed, and the word the model's message
    // must carry so the operator knows what to fix.
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        ("name", serde_json::json!(""), "name"),
        ("allowed_hostnames", serde_json::json!([]), "hostname"),
        (
            "allowed_hostnames",
            serde_json::json!(["*"]),
            "hostname pattern",
        ),
        ("scopes", serde_json::json!([]), "scope"),
        (
            "allowed_backend_cidrs",
            serde_json::json!(["not-a-cidr"]),
            "allowed_backend_cidrs",
        ),
        ("max_ttl_seconds", serde_json::json!(0), "max_ttl_seconds"),
    ];

    for (field, value, expected_word) in cases {
        let mut body = create_body();
        body[field] = value;
        let response = management(
            &state,
            &sessions,
            &limiter,
            "POST",
            TOKENS_PATH,
            &admin,
            Some(body),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a body the server understood and refuses on the merits is a 422 ({field})"
        );
        let message = body_json(response).await["error"]["message"]
            .as_str()
            .expect("the refusal carries a message")
            .to_string();
        assert!(
            message.contains(expected_word),
            "the refusal for {field} must name it; got {message:?}"
        );
    }
}

#[tokio::test]
async fn a_server_owned_field_on_the_body_is_refused() {
    // `deny_unknown_fields`: `public_id`, `secret_hmac` and the two
    // usage stamps are the server's, and a client that sends one is
    // describing a token this endpoint would not have minted.
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    for field in ["public_id", "secret_hmac", "created_by", "last_used_at"] {
        let mut body = create_body();
        body[field] = serde_json::json!("whatever");
        let response = management(
            &state,
            &sessions,
            &limiter,
            "POST",
            TOKENS_PATH,
            &admin,
            Some(body),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{field} is server-owned and must be refused on input"
        );
    }
}

#[tokio::test]
async fn expires_at_and_lifetime_days_together_are_refused() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let mut body = create_body();
    body["expires_at"] = serde_json::json!("2030-01-01T00:00:00Z");
    body["lifetime_days"] = serde_json::json!(30);
    let response = management(
        &state,
        &sessions,
        &limiter,
        "POST",
        TOKENS_PATH,
        &admin,
        Some(body),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn an_omitted_expiry_falls_back_to_the_models_default_lifetime() {
    let (state, sessions, limiter) = test_state().await;
    let admin = super_admin(&state, &sessions, &limiter).await;
    let (_, public_id) = mint(&state, &sessions, &limiter, &admin).await;

    let stored = {
        let store = state.store.lock().await;
        store
            .get_automation_token(&public_id)
            .expect("test setup: the row reads")
            .expect("test setup: the row exists")
    };
    let lifetime = stored.expires_at - stored.created_at;
    assert_eq!(
        lifetime.num_days(),
        lorica_config::models::AUTOMATION_TOKEN_DEFAULT_LIFETIME_DAYS
    );
    assert_eq!(
        stored.max_ttl_seconds,
        lorica_config::models::AUTOMATION_TOKEN_DEFAULT_MAX_TTL_SECONDS
    );
}

// ---- The expiry resolver ----

#[test]
fn the_expiry_resolver_takes_one_form_or_the_other_but_not_both() {
    let created_at = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .expect("test setup: valid timestamp")
        .with_timezone(&chrono::Utc);
    let explicit = created_at + chrono::TimeDelta::days(3);

    assert_eq!(
        super::resolve_expiry(created_at, Some(explicit), None).expect("explicit expiry"),
        explicit
    );
    assert_eq!(
        super::resolve_expiry(created_at, None, Some(3)).expect("lifetime in days"),
        explicit
    );
    assert!(super::resolve_expiry(created_at, Some(explicit), Some(3)).is_err());
    // An unrepresentable duration is refused rather than saturating to
    // an instant nobody asked for.
    assert!(super::resolve_expiry(created_at, None, Some(i64::MAX)).is_err());
}
