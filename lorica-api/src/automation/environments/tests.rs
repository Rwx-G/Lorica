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

//! Tests for the environment resource, through the real automation
//! router: bearer gate, scope gate, audit layer, handler.
//!
//! The two that matter most: the transaction leaves zero rows on a
//! failed certificate resolution (asserted on every table, not on the
//! status alone), and ownership is refused on all three verbs. A rule
//! enforced on delete but not on update is not a rule.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;
use tower::ServiceExt;

use lorica_config::models::{
    mint_automation_token, AutomationScope, AutomationToken, Certificate, LoadBalancing, ManagedBy,
    Route, WafMode,
};

use super::reap_expired_environments;
use crate::audit::AuditQuery;
use crate::logs::LogBuffer;
use crate::metrics::gathered_counter;
use crate::server::{AppState, Mode};
use crate::system::SystemCache;

const COLLECTION: &str = "/automation/v1/environments";
const HOSTNAME: &str = "pr-42.review.example.com";

fn test_state() -> AppState {
    let store = lorica_config::ConfigStore::open_in_memory().expect("test setup: store opens");
    AppState {
        store: Arc::new(Mutex::new(store)),
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
    }
}

/// Mint a token straight into the store and return the full string.
async fn mint(state: &AppState, name: &str, scopes: &[AutomationScope]) -> String {
    let store = state.store.lock().await;
    let key = store
        .automation_token_hmac_key()
        .expect("test setup: hmac key");
    let minted = mint_automation_token(&key).expect("test setup: mint");
    let now = Utc::now();
    store
        .create_automation_token(&AutomationToken {
            public_id: minted.public_id,
            name: name.to_string(),
            secret_hmac: minted.secret_hmac,
            scopes: scopes.to_vec(),
            // The second pattern is a name no certificate covers, for
            // the failed-resolution tests.
            allowed_hostnames: vec![
                "*.review.example.com".to_string(),
                "*.uncovered.example.com".to_string(),
            ],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            created_by: "admin".to_string(),
            created_at: now,
            expires_at: now + Duration::days(30),
            last_used_at: None,
            revoked_at: None,
        })
        .expect("test setup: token stored");
    minted.token
}

/// A token that can read and write environments.
async fn writer(state: &AppState, name: &str) -> String {
    mint(
        state,
        name,
        &[
            AutomationScope::EnvironmentsRead,
            AutomationScope::EnvironmentsWrite,
        ],
    )
    .await
}

fn at(rfc3339: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(rfc3339)
        .expect("test setup: valid timestamp")
        .with_timezone(&Utc)
}

async fn seed_certificate(state: &AppState, id: &str, domain: &str, not_after: &str) {
    let store = state.store.lock().await;
    store
        .create_certificate(&Certificate {
            id: id.to_string(),
            domain: domain.to_string(),
            san_domains: Vec::new(),
            fingerprint: format!("fp-{id}"),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            issuer: "test".to_string(),
            not_before: at("2026-01-01T00:00:00Z"),
            not_after: at(not_after),
            is_acme: false,
            acme_auto_renew: false,
            created_at: at("2026-01-01T00:00:00Z"),
            acme_method: None,
            acme_dns_provider_id: None,
        })
        .expect("test setup: certificate stored");
}

/// The wildcard every happy-path test relies on.
async fn seed_wildcard(state: &AppState) {
    seed_certificate(
        state,
        "wild",
        "*.review.example.com",
        "2027-01-01T00:00:00Z",
    )
    .await;
}

/// A manually created route on `hostname`, the kind an operator owns.
async fn seed_manual_route(state: &AppState, id: &str, hostname: &str, aliases: &[&str]) {
    let now = Utc::now();
    let route = Route {
        id: id.to_string(),
        hostname: hostname.to_string(),
        path_prefix: "/".to_string(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: WafMode::Detection,
        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: aliases.iter().map(|a| (*a).to_string()).collect(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "moderate".to_string(),
        connect_timeout_s: 5,
        read_timeout_s: 60,
        send_timeout_s: 60,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: true,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52_428_800,
        max_connections: None,
        slowloris_threshold_ms: 5_000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3_600,
        path_rules: Vec::new(),
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: Vec::new(),
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: Vec::new(),
        header_rules: Vec::new(),
        traffic_splits: Vec::new(),
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: String::new(),
        node_selector: Vec::new(),
        ai_bot_policy: None,
        ai_bot_spoofed_fallback: None,
        serve_robots_txt: false,
        managed_by: None,
        created_at: now,
        updated_at: now,
    };
    state
        .store
        .lock()
        .await
        .create_route(&route)
        .expect("test setup: manual route stored");
}

/// One request on the automation plane, through the real router.
async fn automation(
    state: &AppState,
    method: &str,
    uri: &str,
    bearer: &str,
    body: Option<serde_json::Value>,
    extra_headers: &[(&str, &str)],
) -> axum::response::Response {
    let router = crate::automation::build_automation_router(state.clone());
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(http::header::AUTHORIZATION, format!("Bearer {bearer}"));
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
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
        .expect("test setup: request runs")
}

async fn put(
    state: &AppState,
    bearer: &str,
    name: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    automation(
        state,
        "PUT",
        &format!("{COLLECTION}/{name}"),
        bearer,
        Some(body),
        &[],
    )
    .await
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("test setup: body reads");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

async fn error_message(response: axum::response::Response) -> String {
    body_json(response).await["error"]["message"]
        .as_str()
        .expect("a refusal carries a message")
        .to_string()
}

/// A body that validates, so each test below changes exactly one thing.
fn env_body() -> serde_json::Value {
    serde_json::json!({
        "hostname": HOSTNAME,
        "backends": [{ "address": "10.0.12.34:8080" }],
        "certificate": "auto",
        "ttl_seconds": 600,
    })
}

/// Every row count the transaction can touch, in one read.
struct RowCounts {
    routes: usize,
    backends: usize,
    joins: usize,
    environments: usize,
}

async fn row_counts(state: &AppState) -> RowCounts {
    let store = state.store.lock().await;
    RowCounts {
        routes: store.list_routes().expect("routes read").len(),
        backends: store.list_backends().expect("backends read").len(),
        joins: store.list_route_backends().expect("joins read").len(),
        environments: store
            .list_automation_environments()
            .expect("environments read")
            .len(),
    }
}

fn assert_no_rows(counts: &RowCounts) {
    assert_eq!(counts.routes, 0, "no route row may survive a refusal");
    assert_eq!(counts.backends, 0, "no backend row may survive a refusal");
    assert_eq!(counts.joins, 0, "no join row may survive a refusal");
    assert_eq!(
        counts.environments, 0,
        "no environment row may survive a refusal"
    );
}

// ---- Create and update (AC #1, #2, #5) ----

#[tokio::test]
async fn create_returns_201_and_an_identical_put_returns_200_with_the_same_route_id() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;

    let response = put(&state, &token, "pr-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        response.headers().get(http::header::ETAG).is_some(),
        "a write answers with the ETag a pipeline sends back"
    );
    let first = body_json(response).await["data"].clone();
    assert_eq!(first["name"], "pr-42");
    assert_eq!(first["url"], format!("https://{HOSTNAME}/"));
    assert_eq!(first["certificate_id"], "wild");
    assert_eq!(
        first["applied_generation"], 0,
        "a standalone node has no fleet"
    );
    assert_eq!(first["backend_ids"].as_array().map(Vec::len), Some(1));
    let route_id = first["route_id"].as_str().expect("route id").to_string();

    // The rows carry the mark the dashboard reads (AC #8).
    {
        let store = state.store.lock().await;
        let route = store
            .get_route(&route_id)
            .expect("route read")
            .expect("the route exists");
        assert_eq!(
            route.managed_by,
            Some(ManagedBy::Automation {
                environment: "pr-42".to_string()
            })
        );
        assert_eq!(route.group_name, "automation:pr-42");
        assert_eq!(route.certificate_id.as_deref(), Some("wild"));
        let backends = store.list_backends().expect("backends read");
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].group_name, "automation:pr-42");
        assert_eq!(
            backends[0].managed_by,
            Some(ManagedBy::Automation {
                environment: "pr-42".to_string()
            })
        );
    }

    let response = put(&state, &token, "pr-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let second = body_json(response).await["data"].clone();
    assert_eq!(second["route_id"], route_id, "an update keeps the route");
    assert_ne!(
        second["backend_ids"], first["backend_ids"],
        "an update replaces the backend set"
    );

    let counts = row_counts(&state).await;
    assert_eq!(counts.routes, 1);
    assert_eq!(counts.backends, 1, "the replaced backends are gone");
    assert_eq!(counts.joins, 1);
    assert_eq!(counts.environments, 1);
}

// ---- The refusals, each with the field named ----

#[tokio::test]
async fn a_name_that_is_not_an_rfc_1123_label_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let response = put(&state, &token, "PR-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error_message(response).await.contains("name"));
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_hostname_outside_the_token_allowlist_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut body = env_body();
    body["hostname"] = serde_json::json!("pr-42.prod.example.com");
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the token is real and the grant is not there"
    );
    let message = error_message(response).await;
    assert!(message.contains("hostname"), "{message}");
    assert!(message.contains("allowed_hostnames"), "{message}");
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_wildcard_hostname_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut body = env_body();
    body["hostname"] = serde_json::json!("*.review.example.com");
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let message = error_message(response).await;
    assert!(message.contains("hostname"), "{message}");
    assert!(message.contains("wildcard"), "{message}");
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_listener_host_is_refused() {
    // The management listener is loopback and the automation listener
    // binds an address, so the names that could reach either are
    // `localhost` and an address literal.
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    for hostname in ["localhost", "api.localhost", "127.0.0.1", "10.0.0.1", "::1"] {
        let mut body = env_body();
        body["hostname"] = serde_json::json!(hostname);
        let response = put(&state, &token, "pr-42", body).await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{hostname} must be refused"
        );
        let message = error_message(response).await;
        assert!(message.contains("hostname"), "{message}");
    }
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_hostname_held_by_another_route_is_a_409_that_names_only_the_hostname() {
    let state = test_state();
    seed_wildcard(&state).await;
    seed_manual_route(&state, "manual-route-id", HOSTNAME, &[]).await;
    seed_manual_route(
        &state,
        "alias-route-id",
        "other.review.example.com",
        &["pr-43.review.example.com"],
    )
    .await;
    let token = writer(&state, "acme-ci").await;

    let response = put(&state, &token, "pr-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let message = error_message(response).await;
    assert!(message.contains(HOSTNAME), "{message}");
    assert!(
        !message.contains("manual-route-id"),
        "the owning route's details must not leak: {message}"
    );

    let mut body = env_body();
    body["hostname"] = serde_json::json!("pr-43.review.example.com");
    let response = put(&state, &token, "pr-43", body).await;
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "an alias holds a hostname as much as a primary does"
    );

    let counts = row_counts(&state).await;
    assert_eq!(counts.routes, 2, "only the two manual routes");
    assert_eq!(counts.environments, 0);
}

#[tokio::test]
async fn an_environment_may_keep_its_own_hostname_on_update() {
    // The collision rule skips the route the environment already owns,
    // or every second PUT would be a 409 against itself.
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::OK
    );
    // Another environment on the same hostname is still a conflict.
    let response = put(&state, &token, "pr-43", env_body()).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn a_backend_outside_the_token_cidrs_is_refused_with_the_address_named() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut body = env_body();
    body["backends"] = serde_json::json!([
        { "address": "10.0.0.5:8080" },
        { "address": "192.0.2.9:8080" },
    ]);
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let message = error_message(response).await;
    assert!(message.contains("backends[1].address"), "{message}");
    assert!(message.contains("192.0.2.9:8080"), "{message}");
    assert!(message.contains("allowed_backend_cidrs"), "{message}");
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_backend_address_that_is_a_name_or_has_no_port_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    for address in ["app.internal:8080", "10.0.0.5", "10.0.0.5:0", ""] {
        let mut body = env_body();
        body["backends"] = serde_json::json!([{ "address": address }]);
        let response = put(&state, &token, "pr-42", body).await;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{address:?} must be refused"
        );
        let message = error_message(response).await;
        assert!(message.contains("backends[0].address"), "{message}");
    }
    let mut body = env_body();
    body["backends"] = serde_json::json!([]);
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error_message(response).await.contains("backends"));
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_ttl_over_the_token_ceiling_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    for ttl in [3_601, 0] {
        let mut body = env_body();
        body["ttl_seconds"] = serde_json::json!(ttl);
        let response = put(&state, &token, "pr-42", body).await;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "{ttl}");
        let message = error_message(response).await;
        assert!(message.contains("ttl_seconds"), "{message}");
    }
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn an_unknown_field_is_refused() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut body = env_body();
    body["expires_at"] = serde_json::json!("2030-01-01T00:00:00Z");
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let mut body = env_body();
    body["backends"] = serde_json::json!([{ "address": "10.0.0.5:8080", "id": "mine" }]);
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn too_many_labels_are_refused_by_the_model() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let labels: BTreeMap<String, String> = (0..17)
        .map(|i| (format!("k{i}"), "v".to_string()))
        .collect();
    let mut body = env_body();
    body["labels"] = serde_json::to_value(labels).expect("labels serialise");
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error_message(response).await.contains("labels"));
    assert_no_rows(&row_counts(&state).await);
}

// ---- The certificate (AC #4) ----

#[tokio::test]
async fn no_covering_certificate_is_a_422_that_leaves_zero_rows() {
    let state = test_state();
    seed_certificate(&state, "prod", "*.prod.example.com", "2027-01-01T00:00:00Z").await;
    let token = writer(&state, "acme-ci").await;

    let response = put(&state, &token, "pr-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let message = error_message(response).await;
    assert!(
        message.contains(super::NO_CERTIFICATE_COVERS_HOSTNAME),
        "{message}"
    );
    assert!(
        message.contains("*.review.example.com"),
        "the wildcard an operator could provision: {message}"
    );
    assert!(
        message.contains("provision-dns"),
        "points at the DNS-01 endpoint: {message}"
    );
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn a_failed_resolution_on_update_leaves_the_previous_environment_intact() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let created = body_json(put(&state, &token, "pr-42", env_body()).await).await["data"].clone();
    let route_id = created["route_id"].as_str().expect("route id").to_string();
    let backend_ids = created["backend_ids"].clone();
    let before = state
        .store
        .lock()
        .await
        .get_automation_environment("pr-42")
        .expect("environment read")
        .expect("the environment exists");

    // A hostname the token may claim but no certificate covers, with a
    // new backend set: the resolution fails after the request has
    // asked for both the route and the backends to change.
    let mut body = env_body();
    body["hostname"] = serde_json::json!("pr-42.uncovered.example.com");
    body["backends"] = serde_json::json!([{ "address": "10.0.99.99:9090" }]);
    let response = put(&state, &token, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let store = state.store.lock().await;
    let route = store
        .get_route(&route_id)
        .expect("route read")
        .expect("the previous route stands");
    assert_eq!(route.hostname, HOSTNAME);
    assert_eq!(route.certificate_id.as_deref(), Some("wild"));
    let linked = store
        .list_backends_for_route(&route_id)
        .expect("joins read");
    assert_eq!(
        serde_json::to_value(&linked).expect("ids serialise"),
        backend_ids,
        "the previous backend set stands"
    );
    let backends = store.list_backends().expect("backends read");
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].address, "10.0.12.34:8080");
    let after = store
        .get_automation_environment("pr-42")
        .expect("environment read")
        .expect("the environment stands");
    assert_eq!(after, before, "the environment row is untouched");
}

#[tokio::test]
async fn an_explicit_certificate_needs_certificates_read_and_must_exist() {
    let state = test_state();
    seed_certificate(
        &state,
        "explicit",
        "elsewhere.example.com",
        "2027-01-01T00:00:00Z",
    )
    .await;

    let without = writer(&state, "acme-ci").await;
    let mut body = env_body();
    body["certificate"] = serde_json::json!("explicit");
    let response = put(&state, &without, "pr-42", body.clone()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(error_message(response).await.contains("certificates:read"));

    let with = mint(
        &state,
        "acme-deploy",
        &[
            AutomationScope::EnvironmentsRead,
            AutomationScope::EnvironmentsWrite,
            AutomationScope::CertificatesRead,
        ],
    )
    .await;
    let mut missing = env_body();
    missing["certificate"] = serde_json::json!("ghost");
    let response = put(&state, &with, "pr-42", missing).await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(error_message(response).await.contains("certificate"));
    assert_no_rows(&row_counts(&state).await);

    let response = put(&state, &with, "pr-42", body).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        body_json(response).await["data"]["certificate_id"],
        "explicit"
    );
}

// ---- Ownership (AC #6) ----

#[tokio::test]
async fn ownership_is_refused_on_get_put_and_delete_for_another_prefix() {
    let state = test_state();
    seed_wildcard(&state).await;
    let acme = writer(&state, "acme-ci").await;
    let globex = writer(&state, "globex-ci").await;
    let acme_deploy = writer(&state, "acme-deploy").await;
    assert_eq!(
        put(&state, &acme, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );
    let uri = format!("{COLLECTION}/pr-42");

    for (method, body) in [("GET", None), ("PUT", Some(env_body())), ("DELETE", None)] {
        let response = automation(&state, method, &uri, &globex, body, &[]).await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{method} by another prefix must be refused"
        );
    }
    let counts = row_counts(&state).await;
    assert_eq!(counts.environments, 1, "the refusals wrote nothing");
    assert_eq!(counts.routes, 1);

    // The same prefix is the same project.
    assert_eq!(
        automation(&state, "GET", &uri, &acme_deploy, None, &[])
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_shared_environment_is_open_to_every_prefix() {
    let state = test_state();
    seed_wildcard(&state).await;
    let acme = writer(&state, "acme-ci").await;
    let globex = writer(&state, "globex-ci").await;
    let mut body = env_body();
    body["labels"] = serde_json::json!({ "shared": "true" });
    assert_eq!(
        put(&state, &acme, "pr-42", body.clone()).await.status(),
        StatusCode::CREATED
    );
    let uri = format!("{COLLECTION}/pr-42");

    assert_eq!(
        automation(&state, "GET", &uri, &globex, None, &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        automation(&state, "PUT", &uri, &globex, Some(body), &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        automation(&state, "DELETE", &uri, &globex, None, &[])
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_no_rows(&row_counts(&state).await);
}

#[tokio::test]
async fn the_list_returns_only_accessible_environments_and_honours_the_filters() {
    let state = test_state();
    seed_wildcard(&state).await;
    let acme = writer(&state, "acme-ci").await;
    let globex = writer(&state, "globex-ci").await;

    let mut own = env_body();
    own["hostname"] = serde_json::json!("pr-1.review.example.com");
    own["labels"] = serde_json::json!({ "team": "acme" });
    assert_eq!(
        put(&state, &acme, "pr-1", own).await.status(),
        StatusCode::CREATED
    );
    let mut shared = env_body();
    shared["hostname"] = serde_json::json!("pr-2.review.example.com");
    shared["labels"] = serde_json::json!({ "shared": "true" });
    assert_eq!(
        put(&state, &globex, "pr-2", shared).await.status(),
        StatusCode::CREATED
    );
    let mut theirs = env_body();
    theirs["hostname"] = serde_json::json!("pr-3.review.example.com");
    assert_eq!(
        put(&state, &globex, "pr-3", theirs).await.status(),
        StatusCode::CREATED
    );

    async fn names(state: &AppState, bearer: &str, query: &str) -> Vec<String> {
        let response = automation(
            state,
            "GET",
            &format!("{COLLECTION}{query}"),
            bearer,
            None,
            &[],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "{query}");
        body_json(response).await["data"]["environments"]
            .as_array()
            .expect("an array")
            .iter()
            .map(|e| e["name"].as_str().expect("a name").to_string())
            .collect()
    }

    assert_eq!(names(&state, &acme, "").await, vec!["pr-1", "pr-2"]);
    assert_eq!(names(&state, &globex, "").await, vec!["pr-2", "pr-3"]);
    assert_eq!(names(&state, &acme, "?label=team:acme").await, vec!["pr-1"]);
    assert_eq!(
        names(&state, &acme, "?label=shared:true").await,
        vec!["pr-2"]
    );
    assert_eq!(
        names(&state, &acme, "?hostname=PR-2.review.example.com").await,
        vec!["pr-2"]
    );
    // The `+` of the UTC offset must be percent-encoded in a query
    // string, or it decodes to a space.
    let far = (Utc::now() + Duration::days(1))
        .to_rfc3339()
        .replace('+', "%2B");
    let soon = (Utc::now() + Duration::seconds(5))
        .to_rfc3339()
        .replace('+', "%2B");
    assert_eq!(
        names(&state, &acme, &format!("?expiring_before={far}")).await,
        vec!["pr-1", "pr-2"]
    );
    assert!(names(&state, &acme, &format!("?expiring_before={soon}"))
        .await
        .is_empty());

    let response = automation(
        &state,
        "GET",
        &format!("{COLLECTION}?label=nocolon"),
        &acme,
        None,
        &[],
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---- Concurrency (AC #9) ----

#[tokio::test]
async fn an_if_match_that_does_not_match_is_a_412() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let uri = format!("{COLLECTION}/pr-42");
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );
    let response = automation(&state, "GET", &uri, &token, None, &[]).await;
    let etag = response
        .headers()
        .get(http::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("GET answers with an ETag")
        .to_string();

    let stale = automation(
        &state,
        "PUT",
        &uri,
        &token,
        Some(env_body()),
        &[("If-Match", "\"2020-01-01T00:00:00+00:00\"")],
    )
    .await;
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        body_json(stale).await["error"]["code"],
        "precondition_failed"
    );

    let fresh = automation(
        &state,
        "PUT",
        &uri,
        &token,
        Some(env_body()),
        &[("If-Match", etag.as_str())],
    )
    .await;
    assert_eq!(fresh.status(), StatusCode::OK);

    // A precondition on a name that does not exist fails too.
    let absent = automation(
        &state,
        "PUT",
        &format!("{COLLECTION}/pr-99"),
        &token,
        Some(env_body()),
        &[("If-Match", "*")],
    )
    .await;
    assert_eq!(absent.status(), StatusCode::PRECONDITION_FAILED);
}

// ---- Delete (AC #6) ----

#[tokio::test]
async fn delete_is_idempotent_and_removes_every_row() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let uri = format!("{COLLECTION}/pr-42");
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );

    assert_eq!(
        automation(&state, "DELETE", &uri, &token, None, &[])
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_no_rows(&row_counts(&state).await);
    assert_eq!(
        automation(&state, "DELETE", &uri, &token, None, &[])
            .await
            .status(),
        StatusCode::NO_CONTENT,
        "a second delete finds the state the caller wanted"
    );
    assert_eq!(
        automation(&state, "GET", &uri, &token, None, &[])
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        automation(
            &state,
            "DELETE",
            &format!("{COLLECTION}/never-existed"),
            &token,
            None,
            &[]
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );
}

// ---- The reaper (AC #7) ----

#[tokio::test]
async fn the_reaper_deletes_an_expired_environment_and_audits_and_skips_an_unexpired_one() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut expired = env_body();
    expired["hostname"] = serde_json::json!("pr-old.review.example.com");
    assert_eq!(
        put(&state, &token, "pr-old", expired).await.status(),
        StatusCode::CREATED
    );
    let mut live = env_body();
    live["hostname"] = serde_json::json!("pr-new.review.example.com");
    assert_eq!(
        put(&state, &token, "pr-new", live).await.status(),
        StatusCode::CREATED
    );
    {
        let store = state.store.lock().await;
        let mut row = store
            .get_automation_environment("pr-old")
            .expect("environment read")
            .expect("the environment exists");
        row.expires_at = Utc::now() - Duration::minutes(1);
        store
            .upsert_automation_environment(&row)
            .expect("test setup: expiry moved into the past");
    }
    let dir = tempfile::tempdir().expect("test setup: tempdir");
    let log_store = Arc::new(
        crate::log_store::LogStore::open(dir.path()).expect("test setup: log store opens"),
    );

    let reaped =
        reap_expired_environments(&state.store, Some(Arc::clone(&log_store)), Utc::now()).await;
    assert_eq!(reaped, vec!["pr-old".to_string()]);

    let store = state.store.lock().await;
    let names: Vec<String> = store
        .list_automation_environments()
        .expect("environments read")
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, vec!["pr-new".to_string()]);
    let routes = store.list_routes().expect("routes read");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].hostname, "pr-new.review.example.com");
    let backends = store.list_backends().expect("backends read");
    assert_eq!(
        backends.len(),
        1,
        "the expired environment's backends are gone"
    );
    assert_eq!(store.list_route_backends().expect("joins read").len(), 1);

    let (rows, _) = log_store
        .query_audit(&AuditQuery {
            action_prefix: Some(super::ENVIRONMENT_EXPIRED_ACTION.to_string()),
            limit: 10,
            ..AuditQuery::default()
        })
        .expect("audit read");
    assert_eq!(rows.len(), 1, "exactly one expiry audit row");
    assert_eq!(rows[0].target_type, super::ENVIRONMENT_TARGET_TYPE);
    assert_eq!(rows[0].target_id, "pr-old");

    // A second sweep has nothing to do and audits nothing more.
    drop(store);
    let reaped =
        reap_expired_environments(&state.store, Some(Arc::clone(&log_store)), Utc::now()).await;
    assert!(reaped.is_empty());
}

// ---- Scope gate on the new paths ----

#[tokio::test]
async fn a_read_only_token_cannot_write_and_a_missing_scope_is_403() {
    let state = test_state();
    seed_wildcard(&state).await;
    let reader = mint(&state, "acme-ci", &[AutomationScope::EnvironmentsRead]).await;
    let response = put(&state, &reader, "pr-42", env_body()).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(error_message(response).await.contains("environments:write"));
    assert_eq!(
        automation(&state, "GET", COLLECTION, &reader, None, &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_no_rows(&row_counts(&state).await);
}

// ---- Re-resolution at snapshot build (AC #4) ----

/// What a snapshot build does under the store lock, on this state.
async fn reresolve(state: &AppState) -> Vec<super::ReresolvedCertificate> {
    let store = state.store.lock().await;
    let mut routes = store.list_routes().expect("routes read");
    let certificates = store.list_certificates().expect("certificates read");
    let rewritten =
        super::reresolve_auto_certificates(&store, &mut routes, &certificates, Utc::now())
            .expect("re-resolution runs");
    // The slice the snapshot is built from carries the rewrite too.
    for change in &rewritten {
        let in_slice = routes
            .iter()
            .find(|route| route.id == change.route_id)
            .expect("the rewritten route is in the slice");
        assert_eq!(
            in_slice.certificate_id.as_deref(),
            Some(change.current.as_str())
        );
    }
    rewritten
}

async fn stored_certificate_id(state: &AppState, environment: &str) -> Option<String> {
    let store = state.store.lock().await;
    let row = store
        .get_automation_environment(environment)
        .expect("environment read")
        .expect("the environment exists");
    store
        .get_route(&row.route_id)
        .expect("route read")
        .expect("the route exists")
        .certificate_id
}

#[tokio::test]
async fn an_auto_environment_follows_a_new_certificate_and_an_explicit_one_does_not() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = mint(
        &state,
        "acme-ci",
        &[
            AutomationScope::EnvironmentsRead,
            AutomationScope::EnvironmentsWrite,
            AutomationScope::CertificatesRead,
        ],
    )
    .await;
    assert_eq!(
        put(&state, &token, "pr-auto", env_body()).await.status(),
        StatusCode::CREATED
    );
    let mut explicit = env_body();
    explicit["hostname"] = serde_json::json!("pr-pinned.review.example.com");
    explicit["certificate"] = serde_json::json!("wild");
    assert_eq!(
        put(&state, &token, "pr-pinned", explicit).await.status(),
        StatusCode::CREATED
    );

    // The wildcard is replaced by a NEW id with a later expiry, the
    // case a renewal in place never produces.
    seed_certificate(
        &state,
        "wild-newer",
        "*.review.example.com",
        "2028-01-01T00:00:00Z",
    )
    .await;

    let rewritten = reresolve(&state).await;
    assert_eq!(rewritten.len(), 1, "only the auto environment moves");
    assert_eq!(rewritten[0].environment, "pr-auto");
    assert_eq!(rewritten[0].previous.as_deref(), Some("wild"));
    assert_eq!(rewritten[0].current, "wild-newer");
    assert_eq!(
        stored_certificate_id(&state, "pr-auto").await.as_deref(),
        Some("wild-newer"),
        "the row a follower receives carries the new id"
    );
    assert_eq!(
        stored_certificate_id(&state, "pr-pinned").await.as_deref(),
        Some("wild"),
        "an explicit binding is untouched by the same event"
    );

    // Settled: a second build has nothing to rewrite.
    assert!(reresolve(&state).await.is_empty());
}

#[tokio::test]
async fn no_covering_certificate_keeps_the_last_id_on_the_route() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );

    // The resolver sees no certificate at all, which is what a deleted
    // wildcard looks like from the snapshot build.
    let rewritten = {
        let store = state.store.lock().await;
        let mut routes = store.list_routes().expect("routes read");
        super::reresolve_auto_certificates(&store, &mut routes, &[], Utc::now())
            .expect("re-resolution runs")
    };
    assert!(rewritten.is_empty());
    assert_eq!(
        stored_certificate_id(&state, "pr-42").await.as_deref(),
        Some("wild"),
        "the last certificate that served stays on the row"
    );
    // The WARN this path emits is asserted in `lorica::reload`, where a
    // tracing tap is available; this crate has none.
}

#[tokio::test]
async fn a_follower_identity_makes_the_re_resolution_a_no_op() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );
    seed_certificate(
        &state,
        "wild-newer",
        "*.review.example.com",
        "2028-01-01T00:00:00Z",
    )
    .await;
    {
        let now = Utc::now();
        state
            .store
            .lock()
            .await
            .set_cluster_identity(&lorica_config::models::ClusterIdentity {
                node_id: "00000000-0000-4000-8000-000000000001".to_string(),
                node_name: "follower01".to_string(),
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_pem: String::new(),
                control_plane: "cp.internal:9444".to_string(),
                server_name: "cp.internal".to_string(),
                enrolled_at: now,
                cert_not_after: now + Duration::days(90),
            })
            .expect("test setup: follower identity");
    }

    assert!(
        reresolve(&state).await.is_empty(),
        "a follower's certificate_id arrives by replication"
    );
    assert_eq!(
        stored_certificate_id(&state, "pr-42").await.as_deref(),
        Some("wild")
    );
}

// ---- Metrics (AC #10) ----

const OPS: &str = "lorica_automation_environment_ops_total";

// The counters are process-global and the tests in this binary run in
// parallel, most of them through the same handlers, so a delta is
// asserted as a floor and never as an exact figure.

#[tokio::test]
async fn environment_operations_are_counted_by_op_and_outcome() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let create_ok = gathered_counter(OPS, &[("op", "create"), ("outcome", "ok")]);
    let update_ok = gathered_counter(OPS, &[("op", "update"), ("outcome", "ok")]);
    let create_refused = gathered_counter(OPS, &[("op", "create"), ("outcome", "refused")]);
    let delete_ok = gathered_counter(OPS, &[("op", "delete"), ("outcome", "ok")]);

    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::CREATED
    );
    assert_eq!(
        put(&state, &token, "pr-42", env_body()).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        put(&state, &token, "PR-BAD", env_body()).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        automation(
            &state,
            "DELETE",
            &format!("{COLLECTION}/pr-42"),
            &token,
            None,
            &[]
        )
        .await
        .status(),
        StatusCode::NO_CONTENT
    );

    assert!(gathered_counter(OPS, &[("op", "create"), ("outcome", "ok")]) > create_ok);
    assert!(gathered_counter(OPS, &[("op", "update"), ("outcome", "ok")]) > update_ok);
    assert!(gathered_counter(OPS, &[("op", "create"), ("outcome", "refused")]) > create_refused);
    assert!(gathered_counter(OPS, &[("op", "delete"), ("outcome", "ok")]) > delete_ok);
}

#[tokio::test]
async fn the_reaper_counts_its_runs_and_expiries_and_publishes_the_gauge() {
    let state = test_state();
    seed_wildcard(&state).await;
    let token = writer(&state, "acme-ci").await;
    let mut expired = env_body();
    expired["hostname"] = serde_json::json!("pr-old.review.example.com");
    assert_eq!(
        put(&state, &token, "pr-old", expired).await.status(),
        StatusCode::CREATED
    );
    let mut live = env_body();
    live["hostname"] = serde_json::json!("pr-new.review.example.com");
    assert_eq!(
        put(&state, &token, "pr-new", live).await.status(),
        StatusCode::CREATED
    );
    {
        let store = state.store.lock().await;
        let mut row = store
            .get_automation_environment("pr-old")
            .expect("environment read")
            .expect("the environment exists");
        row.expires_at = Utc::now() - Duration::minutes(1);
        store
            .upsert_automation_environment(&row)
            .expect("test setup: expiry moved into the past");
        // Before the sweep the expired row is still there and counted
        // as such.
        let counts = super::publish_environment_gauges(&store, Utc::now()).expect("gauge count");
        assert_eq!(
            counts,
            super::EnvironmentCounts {
                active: 1,
                expired: 1
            }
        );
    }

    let runs = gathered_counter("lorica_automation_reaper_runs_total", &[]);
    let expire_ok = gathered_counter(OPS, &[("op", "expire"), ("outcome", "ok")]);
    let reaped = reap_expired_environments(&state.store, None, Utc::now()).await;
    assert_eq!(reaped, vec!["pr-old".to_string()]);
    assert!(gathered_counter("lorica_automation_reaper_runs_total", &[]) > runs);
    assert!(gathered_counter(OPS, &[("op", "expire"), ("outcome", "ok")]) > expire_ok);

    // After the sweep the gauge describes the committed row set. The
    // gauge itself is process-global and other tests write it
    // concurrently, so the counts are asserted on what the sweep's
    // refresh computed rather than on the registry's rendering.
    let store = state.store.lock().await;
    let counts = super::publish_environment_gauges(&store, Utc::now()).expect("gauge count");
    assert_eq!(
        counts,
        super::EnvironmentCounts {
            active: 1,
            expired: 0
        }
    );
}

#[tokio::test]
async fn every_automation_request_is_counted_by_its_outcome() {
    let state = test_state();
    let reader = mint(&state, "acme-ci", &[AutomationScope::EnvironmentsRead]).await;
    const REQUESTS: &str = "lorica_automation_requests_total";
    let ok = gathered_counter(REQUESTS, &[("outcome", "ok")]);
    let unauthenticated = gathered_counter(REQUESTS, &[("outcome", "unauthenticated")]);

    assert_eq!(
        automation(&state, "GET", COLLECTION, &reader, None, &[])
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        automation(&state, "GET", COLLECTION, "not-a-token", None, &[])
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );

    assert!(gathered_counter(REQUESTS, &[("outcome", "ok")]) > ok);
    assert!(gathered_counter(REQUESTS, &[("outcome", "unauthenticated")]) > unauthenticated);
}

// ---- Pure helpers ----

#[test]
fn if_match_compares_strong_and_weak_tags_and_the_star() {
    use super::if_match_holds;
    assert!(if_match_holds(None, Some("\"a\"")));
    assert!(if_match_holds(None, None));
    assert!(if_match_holds(Some("\"a\""), Some("\"a\"")));
    assert!(if_match_holds(Some("W/\"a\""), Some("\"a\"")));
    assert!(if_match_holds(Some("\"b\", \"a\""), Some("\"a\"")));
    assert!(if_match_holds(Some("*"), Some("\"a\"")));
    assert!(!if_match_holds(Some("\"b\""), Some("\"a\"")));
    assert!(!if_match_holds(Some("*"), None));
    assert!(!if_match_holds(Some("\"a\""), None));
}

#[test]
fn the_path_prefix_defaults_to_root_and_refuses_what_a_url_would_misread() {
    use super::validate_path_prefix;
    assert_eq!(validate_path_prefix(None).expect("default"), "/");
    assert_eq!(validate_path_prefix(Some("  ")).expect("blank"), "/");
    assert_eq!(validate_path_prefix(Some("/app")).expect("path"), "/app");
    for bad in ["app", "/a b", "/a?x", "/a#f", "/../etc"] {
        assert!(validate_path_prefix(Some(bad)).is_err(), "{bad:?}");
    }
}

// ---- An ID token as the principal (Story 10.5 AC #3) ----

mod oidc {
    use super::*;
    use crate::automation::oidc::test_support::{
        gitlab_claims, MockIssuer, TestKey, AUDIENCE, ISSUER_URL, JWKS_URL,
    };
    use crate::automation::OidcVerifier;
    use lorica_config::models::OidcIssuer;

    /// A state whose verifier trusts `issuer`, with one registered entry
    /// bound to `bound_claims`.
    async fn state_with_entry(issuer: &Arc<MockIssuer>, bound_claims: &[(&str, &str)]) -> AppState {
        let mut state = test_state();
        state.oidc = Arc::new(OidcVerifier::new(issuer.clone()));
        let entry = OidcIssuer {
            id: "issuer-1".to_string(),
            issuer: ISSUER_URL.to_string(),
            audience: AUDIENCE.to_string(),
            jwks_url: JWKS_URL.to_string(),
            bound_claims: bound_claims
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            allowed_hostnames: vec!["*.review.example.com".to_string()],
            allowed_backend_cidrs: vec!["10.0.0.0/8".to_string()],
            max_ttl_seconds: 3_600,
            scopes: vec![
                AutomationScope::EnvironmentsRead,
                AutomationScope::EnvironmentsWrite,
            ],
            created_by: "admin".to_string(),
            created_at: Utc::now(),
        };
        state
            .store
            .lock()
            .await
            .create_oidc_issuer(&entry)
            .expect("test setup: issuer entry stored");
        state
    }

    #[tokio::test]
    async fn an_id_token_creates_an_environment_owned_by_its_project_path() {
        let key = TestKey::generate("k1");
        let issuer = MockIssuer::serving(&[&key]);
        let state = state_with_entry(&issuer, &[("project_path", "acme/*")]).await;
        seed_wildcard(&state).await;

        let response = put(&state, &key.sign(&gitlab_claims()), "pr-42", env_body()).await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let stored = state
            .store
            .lock()
            .await
            .get_automation_environment("pr-42")
            .expect("environment read")
            .expect("the environment exists");
        assert_eq!(
            stored.owner.kind,
            lorica_config::models::OwnerKind::OidcProject
        );
        assert_eq!(stored.owner.principal, "acme/web");
        let pipeline = stored.pipeline.expect("the job identity is recorded");
        assert_eq!(pipeline.project_path, "acme/web");
        assert_eq!(pipeline.git_ref.as_deref(), Some("main"));
        assert_eq!(pipeline.pipeline_id.as_deref(), Some("1234"));
        assert_eq!(pipeline.job_id.as_deref(), Some("5678"));
        assert_eq!(pipeline.user_login.as_deref(), Some("dev"));
        assert_eq!(stored.last_pipeline.as_deref(), Some("1234"));

        // The view reports the job, and the audit trail names the
        // project with the issuer entry it came through.
        let view = body_json(
            automation(
                &state,
                "GET",
                &format!("{COLLECTION}/pr-42"),
                &key.sign(&gitlab_claims()),
                None,
                &[],
            )
            .await,
        )
        .await;
        assert_eq!(view["data"]["owner"]["kind"], "oidc_project");
        assert_eq!(view["data"]["pipeline"]["job_id"], "5678");
    }

    #[tokio::test]
    async fn ownership_is_enforced_on_project_path_and_a_static_token_never_matches_it() {
        let key = TestKey::generate("k1");
        let issuer = MockIssuer::serving(&[&key]);
        let state = state_with_entry(&issuer, &[]).await;
        seed_wildcard(&state).await;
        assert_eq!(
            put(&state, &key.sign(&gitlab_claims()), "pr-42", env_body())
                .await
                .status(),
            StatusCode::CREATED
        );
        let uri = format!("{COLLECTION}/pr-42");

        // Another job of the same project reaches it. The Story 10.4
        // prefix rule applies to the project path as it does to a token
        // name: the part before the first `-`, so `acme/web-docs` is
        // the same owner and `acme/api` is not, whatever the namespace.
        let mut later_job = gitlab_claims();
        later_job["pipeline_id"] = serde_json::json!("1235");
        assert_eq!(
            automation(&state, "GET", &uri, &key.sign(&later_job), None, &[])
                .await
                .status(),
            StatusCode::OK
        );
        let mut same_prefix = gitlab_claims();
        same_prefix["project_path"] = serde_json::json!("acme/web-docs");
        assert_eq!(
            automation(&state, "GET", &uri, &key.sign(&same_prefix), None, &[])
                .await
                .status(),
            StatusCode::OK
        );
        for other in ["acme/api", "globex/web"] {
            let mut stranger = gitlab_claims();
            stranger["project_path"] = serde_json::json!(other);
            assert_eq!(
                automation(&state, "GET", &uri, &key.sign(&stranger), None, &[])
                    .await
                    .status(),
                StatusCode::FORBIDDEN,
                "{other}"
            );
        }

        // A static token whose NAME equals the project path is another
        // kind of principal: issued by a different authority, never the
        // same owner.
        let impostor = writer(&state, "acme/web").await;
        assert_eq!(
            automation(&state, "GET", &uri, &impostor, None, &[])
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        let counts = row_counts(&state).await;
        assert_eq!(counts.environments, 1);
    }

    #[tokio::test]
    async fn a_protected_environment_binding_ties_the_name_to_the_job_environment() {
        let key = TestKey::generate("k1");
        let issuer = MockIssuer::serving(&[&key]);
        let state = state_with_entry(&issuer, &[("environment_protected", "true")]).await;
        seed_wildcard(&state).await;

        // Every token is a fresh job: a `jti` is consumed by the first
        // request it authenticates, refused or not.
        let staging_job = || {
            let mut claims = gitlab_claims();
            claims["environment"] = serde_json::json!("staging");
            claims["environment_protected"] = serde_json::json!("true");
            claims
        };

        // A name that is not the job's environment slug is refused with
        // the field named.
        let response = put(&state, &key.sign(&staging_job()), "pr-42", env_body()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let message = error_message(response).await;
        assert!(message.contains("name `pr-42`"), "{message}");
        assert!(message.contains("`staging`"), "{message}");
        assert_no_rows(&row_counts(&state).await);

        // The slug itself is accepted.
        let mut body = env_body();
        body["hostname"] = serde_json::json!("staging.review.example.com");
        assert_eq!(
            put(&state, &key.sign(&staging_job()), "staging", body)
                .await
                .status(),
            StatusCode::CREATED
        );

        // A token without the environment claim can never satisfy the
        // binding, whatever the name.
        let mut no_environment = staging_job();
        no_environment
            .as_object_mut()
            .expect("object")
            .remove("environment");
        let response = put(&state, &key.sign(&no_environment), "staging", env_body()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(error_message(response)
            .await
            .contains("no environment claim"));
    }

    #[tokio::test]
    async fn an_unbound_entry_leaves_the_name_free() {
        let key = TestKey::generate("k1");
        let issuer = MockIssuer::serving(&[&key]);
        let state = state_with_entry(&issuer, &[("environment_protected", "false")]).await;
        seed_wildcard(&state).await;
        assert_eq!(
            put(&state, &key.sign(&gitlab_claims()), "pr-42", env_body())
                .await
                .status(),
            StatusCode::CREATED
        );
    }
}
