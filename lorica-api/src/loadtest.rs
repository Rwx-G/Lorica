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

//! Load test configuration CRUD plus run lifecycle (start, abort, results).

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use lorica_bench::load_test;
use lorica_config::models::LoadTestConfig;
use lorica_config::store::new_id;
use serde::Deserialize;
use std::time::Duration;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// GET /api/v1/loadtest/configs - list every saved load test configuration.
pub async fn list_configs(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let configs = store
        .list_load_test_configs()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(configs))
}

/// JSON body for `POST /api/v1/loadtest/configs`. Optional fields receive defaults.
#[derive(Deserialize)]
pub struct CreateLoadTestConfig {
    /// Human-readable label shown in the dashboard.
    pub name: String,
    /// Absolute URL the load test hits (must point at a configured
    /// route or localhost).
    pub target_url: String,
    /// HTTP method (uppercase). Defaults to `GET`.
    pub method: Option<String>,
    /// Request headers sent on every iteration.
    pub headers: Option<HashMap<String, String>>,
    /// Optional request body (string, UTF-8).
    pub body: Option<String>,
    /// Concurrent virtual users. Defaults to 10.
    pub concurrency: Option<i32>,
    /// Target steady-state RPS. Defaults to 100.
    pub requests_per_second: Option<i32>,
    /// Steady-state duration (s). Defaults to 30.
    pub duration_s: Option<i32>,
    /// Auto-abort threshold on error rate (0.0..=100.0).
    pub error_threshold_pct: Option<f64>,
    /// Cron expression for scheduled runs. `None` = manual only.
    pub schedule_cron: Option<String>,
}

/// Validate that the load test target URL points to a configured
/// route AND lands on the proxy's own listener port AND does not
/// target the management plane.
///
/// This prevents using the load test engine as an internal port-
/// scanner / amplifier : without the port + path constraints, an
/// admin-controlled config for `route.example.com` could drive
/// traffic to `https://route.example.com:6379/_health` (which the
/// load tester forces to resolve to 127.0.0.1) or to
/// `https://route.example.com/api/v1/...` (the management API
/// shares the host) - turning the load tester into a stolen-session
/// pivot tool. Audit L-2.
fn validate_target_url(
    url: &str,
    store: &lorica_config::ConfigStore,
    http_port: u16,
    https_port: u16,
) -> Result<(), ApiError> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| {
            ApiError::BadRequest("target URL must start with http:// or https://".into())
        })?;

    let scheme_is_https = url.starts_with("https://");
    let (authority, path_suffix) = match without_scheme.split_once('/') {
        Some((a, rest)) => (a, format!("/{rest}")),
        None => (without_scheme, String::from("/")),
    };

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal : `[::1]:8080`
        let (h, rest) = stripped
            .split_once(']')
            .ok_or_else(|| ApiError::BadRequest("malformed IPv6 literal in target URL".into()))?;
        let p = rest.trim_start_matches(':').parse::<u16>().ok();
        (h, p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok()),
            None => (authority, None),
        }
    };

    // Effective port : explicit > scheme default. If neither yields
    // a parseable u16, fall back to the proxy's own listener for the
    // scheme so the operator's "no port" shorthand stays valid.
    let effective_port = port.unwrap_or(if scheme_is_https { https_port } else { http_port });

    if effective_port != http_port && effective_port != https_port {
        return Err(ApiError::BadRequest(format!(
            "load test target port {effective_port} must match the proxy's http_port ({http_port}) or https_port ({https_port}) - the load tester resolves the host to loopback and would otherwise drive traffic to an arbitrary local service"
        )));
    }

    // Reject paths that hit the management plane / well-known
    // surfaces - the load tester would amplify a malicious admin
    // session into a self-DoS or a bypass of the dashboard's own
    // rate limits.
    let lower_path = path_suffix.to_ascii_lowercase();
    for forbidden in ["/api/", "/lorica/", "/.well-known/", "/metrics"] {
        if lower_path == forbidden.trim_end_matches('/') || lower_path.starts_with(forbidden) {
            return Err(ApiError::BadRequest(format!(
                "load test target path `{lower_path}` is reserved for the management plane and not a valid traffic target"
            )));
        }
    }

    // Allow localhost for backward compatibility (lets operators
    // smoke-test the proxy directly via 127.0.0.1).
    if matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Ok(());
    }

    // Allow hostnames that match a configured route
    let routes = store
        .list_routes()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let is_route = routes.iter().any(|r| r.hostname == host);
    if !is_route {
        return Err(ApiError::BadRequest(
            "load test target must be a configured route hostname or localhost".into(),
        ));
    }

    Ok(())
}

/// POST /api/v1/loadtest/configs - create a new load test configuration. Target must match a configured route.
pub async fn create_config(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateLoadTestConfig>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let store = state.store.lock().await;
    validate_target_url(&body.target_url, &store, state.http_port, state.https_port)?;
    drop(store);

    let now = Utc::now();
    let config = LoadTestConfig {
        id: new_id(),
        name: body.name,
        target_url: body.target_url,
        method: body.method.unwrap_or_else(|| "GET".to_string()),
        headers: body.headers.unwrap_or_default(),
        body: body.body,
        concurrency: body.concurrency.unwrap_or(10),
        requests_per_second: body.requests_per_second.unwrap_or(100),
        duration_s: body.duration_s.unwrap_or(30),
        error_threshold_pct: body.error_threshold_pct.unwrap_or(10.0),
        schedule_cron: body.schedule_cron,
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    let store = state.store.lock().await;
    store
        .create_load_test_config(&config)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data_with_status(
        axum::http::StatusCode::CREATED,
        config,
    ))
}

/// JSON body for `PUT /api/v1/loadtest/configs/:id`. Only supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateLoadTestConfig {
    /// New label.
    pub name: Option<String>,
    /// New target URL (must be a configured route or localhost).
    pub target_url: Option<String>,
    /// New HTTP method.
    pub method: Option<String>,
    /// New request header map.
    pub headers: Option<HashMap<String, String>>,
    /// New request body.
    pub body: Option<String>,
    /// New concurrency level.
    pub concurrency: Option<i32>,
    /// New steady-state RPS target.
    pub requests_per_second: Option<i32>,
    /// New steady-state duration (s).
    pub duration_s: Option<i32>,
    /// New auto-abort error-rate threshold (%).
    pub error_threshold_pct: Option<f64>,
    /// New cron schedule (`None` + missing = manual).
    pub schedule_cron: Option<String>,
    /// Enable / disable scheduled runs.
    pub enabled: Option<bool>,
}

/// PUT /api/v1/loadtest/configs/:id - patch fields on a saved load test configuration.
pub async fn update_config(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateLoadTestConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    if let Some(ref url) = body.target_url {
        validate_target_url(url, &store, state.http_port, state.https_port)?;
    }
    let mut config = store
        .get_load_test_config(&id)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("load test config {id}")))?;

    if let Some(v) = body.name {
        config.name = v;
    }
    if let Some(v) = body.target_url {
        config.target_url = v;
    }
    if let Some(v) = body.method {
        config.method = v;
    }
    if let Some(v) = body.headers {
        config.headers = v;
    }
    if let Some(v) = body.body {
        config.body = Some(v);
    }
    if let Some(v) = body.concurrency {
        config.concurrency = v;
    }
    if let Some(v) = body.requests_per_second {
        config.requests_per_second = v;
    }
    if let Some(v) = body.duration_s {
        config.duration_s = v;
    }
    if let Some(v) = body.error_threshold_pct {
        config.error_threshold_pct = v;
    }
    if let Some(v) = body.schedule_cron {
        config.schedule_cron = Some(v);
    }
    if let Some(v) = body.enabled {
        config.enabled = v;
    }
    config.updated_at = Utc::now();

    store
        .update_load_test_config(&config)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(config))
}

/// DELETE /api/v1/loadtest/configs/:id - delete a saved load test configuration.
pub async fn delete_config(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store
        .delete_load_test_config(&id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(serde_json::json!({"deleted": id})))
}

/// POST /api/v1/loadtest/start/:config_id - launch a load test, returning a confirmation requirement if it exceeds safe limits.
pub async fn start_test(
    Extension(state): Extension<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (config, limits) = {
        let store = state.store.lock().await;
        let config = store
            .get_load_test_config(&config_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("load test config {config_id}")))?;
        let settings = store.get_global_settings().unwrap_or_default();
        let limits = load_test::SafeLimits::from_settings(&settings);
        (config, limits)
    };

    let engine = state
        .load_test_engine
        .as_ref()
        .ok_or_else(|| ApiError::Internal("load test engine not available".into()))?;

    if engine.is_running().await {
        return Err(ApiError::Conflict("a load test is already running".into()));
    }

    // Check safe limits from global settings
    if load_test::exceeds_safe_limits(&config, &limits) {
        let warnings = load_test::describe_exceeded_limits(&config, &limits);
        return Ok(json_data(serde_json::json!({
            "status": "requires_confirmation",
            "warnings": warnings,
            "message": "This test exceeds safe limits. POST to /api/v1/loadtest/start/:id/confirm to proceed."
        })));
    }

    // Run the test in a background task, tracked so graceful
    // shutdown waits for it to finish (bounded by the supervisor
    // drain timeout) rather than leaving partial results.
    let engine = Arc::clone(engine);
    let store = Arc::clone(&state.store);
    state.task_tracker.spawn(async move {
        engine.run(&config, &store).await;
    });

    Ok(json_data(serde_json::json!({
        "status": "started",
        "config_id": config_id
    })))
}

/// POST /api/v1/loadtest/start/:config_id/confirm - launch a load test that exceeds safe limits, after explicit user confirmation.
pub async fn start_test_confirmed(
    Extension(state): Extension<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let config = {
        let store = state.store.lock().await;
        store
            .get_load_test_config(&config_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound(format!("load test config {config_id}")))?
    };

    let engine = state
        .load_test_engine
        .as_ref()
        .ok_or_else(|| ApiError::Internal("load test engine not available".into()))?;

    if engine.is_running().await {
        return Err(ApiError::Conflict("a load test is already running".into()));
    }

    let engine = Arc::clone(engine);
    let store = Arc::clone(&state.store);
    state.task_tracker.spawn(async move {
        engine.run(&config, &store).await;
    });

    Ok(json_data(serde_json::json!({
        "status": "started",
        "config_id": config_id,
        "safe_limits_bypassed": true
    })))
}

/// GET /api/v1/loadtest/status - return progress for the active test or `{"active":false}`.
pub async fn get_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .load_test_engine
        .as_ref()
        .ok_or_else(|| ApiError::Internal("load test engine not available".into()))?;

    match engine.progress().await {
        Some(progress) => Ok(json_data(progress)),
        None => Ok(json_data(serde_json::json!({
            "active": false,
            "message": "no load test running"
        }))),
    }
}

/// POST /api/v1/loadtest/abort - request that the running load test stop.
pub async fn abort_test(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .load_test_engine
        .as_ref()
        .ok_or_else(|| ApiError::Internal("load test engine not available".into()))?;

    engine.abort().await;
    Ok(json_data(serde_json::json!({"status": "abort_requested"})))
}

/// GET /api/v1/loadtest/results/:config_id - list every persisted result for a config (newest first).
pub async fn get_results(
    Extension(state): Extension<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let results = store
        .list_load_test_results(&config_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(results))
}

/// GET /api/v1/loadtest/results/:config_id/compare - diff the latest and previous run for a config.
pub async fn compare_results(
    Extension(state): Extension<AppState>,
    Path(config_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let results = store
        .list_load_test_results(&config_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if results.is_empty() {
        return Err(ApiError::NotFound(format!(
            "no results for config {config_id}"
        )));
    }

    let current = results[0].clone();
    let previous = results.get(1).cloned();
    let comparison = load_test::compare_results(current, previous);

    Ok(json_data(comparison))
}

/// GET /api/v1/loadtest/ws - WebSocket endpoint for real-time load test progress.
///
/// Sends a JSON message every second with current progress or `{"active":false}`
/// when no test is running.
pub async fn loadtest_ws(
    ws: WebSocketUpgrade,
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    let engine = state.load_test_engine.clone();
    ws.on_upgrade(move |socket| handle_loadtest_stream(socket, engine))
}

async fn handle_loadtest_stream(
    socket: WebSocket,
    engine: Option<Arc<lorica_bench::LoadTestEngine>>,
) {
    let (mut sender, mut receiver) = socket.split();

    // Send progress updates every second
    let send_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;

            let json = match &engine {
                Some(e) => match e.progress().await {
                    Some(progress) => serde_json::to_string(&progress).unwrap_or_default(),
                    None => r#"{"active":false}"#.to_string(),
                },
                None => r#"{"active":false}"#.to_string(),
            };

            if sender.send(Message::Text(json)).await.is_err() {
                break; // Client disconnected
            }
        }
    });

    // Consume incoming messages (ping/pong, close) but don't process them
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}

/// JSON body for `POST /api/v1/loadtest/configs/:id/clone` - optional new name.
#[derive(Deserialize)]
pub struct CloneConfig {
    /// Optional new name for the clone ; defaults to `"<orig> (copy)"`.
    pub name: Option<String>,
}

/// POST /api/v1/loadtest/configs/:id/clone - duplicate a configuration so successive runs are comparable.
pub async fn clone_config(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<CloneConfig>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let store = state.store.lock().await;
    let new_name = body.name.unwrap_or_else(|| format!("Copy of {id}"));
    let cloned = store
        .clone_load_test_config(&id, &new_name)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data_with_status(
        axum::http::StatusCode::CREATED,
        cloned,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> lorica_config::ConfigStore {
        lorica_config::ConfigStore::open_in_memory().expect("test setup: open in-memory store")
    }

    // Port args mirror the proxy's defaults ; tests use 8080 / 8443
    // for HTTP / HTTPS so the port-validation arms can be exercised.
    const TEST_HTTP_PORT: u16 = 8080;
    const TEST_HTTPS_PORT: u16 = 8443;

    #[test]
    fn validate_target_url_allows_localhost() {
        let store = test_store();
        assert!(validate_target_url("http://127.0.0.1:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok());
        assert!(validate_target_url("https://127.0.0.1:8443/health", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok());
        assert!(validate_target_url("http://localhost:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok());
        assert!(validate_target_url("https://localhost:8443/path", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok());
        assert!(validate_target_url("http://[::1]:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok());
    }

    #[test]
    fn validate_target_url_rejects_external() {
        let store = test_store();
        assert!(validate_target_url("http://10.0.0.1:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
        assert!(validate_target_url("https://example.com:8443/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
        assert!(validate_target_url("http://192.168.1.1:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
        assert!(validate_target_url("http://0.0.0.0:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
    }

    #[test]
    fn validate_target_url_rejects_bad_scheme() {
        let store = test_store();
        assert!(validate_target_url("ftp://127.0.0.1/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
        assert!(validate_target_url("127.0.0.1:8080/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err());
    }

    // v1.5.2 audit L-2 : port + path constraints.

    #[test]
    fn validate_target_url_rejects_off_proxy_port() {
        let store = test_store();
        // Port 6379 (Redis) on a localhost target must be rejected
        // even though the host is loopback.
        assert!(
            validate_target_url("http://127.0.0.1:6379/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        // Port 22 (SSH) similar.
        assert!(
            validate_target_url("http://localhost:22/", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
    }

    #[test]
    fn validate_target_url_rejects_management_paths() {
        let store = test_store();
        // /api/ is the management plane prefix.
        assert!(
            validate_target_url("http://127.0.0.1:8080/api/v1/auth/login", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        // /metrics is the unauth Prometheus endpoint (cf. backlog #20).
        assert!(
            validate_target_url("http://127.0.0.1:8080/metrics", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        // /lorica/ + /.well-known/ are reserved.
        assert!(
            validate_target_url("http://127.0.0.1:8080/lorica/bot/solve", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        assert!(
            validate_target_url("http://127.0.0.1:8080/.well-known/acme-challenge/x", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        // Non-management paths still pass.
        assert!(
            validate_target_url("http://127.0.0.1:8080/healthz", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_ok()
        );
    }

    #[test]
    fn validate_target_url_path_check_is_case_insensitive() {
        // Operators uppercasing /API/ or mixing /Api/ should still
        // be rejected ; the proxy normalises case at routing time so
        // the load tester must too.
        let store = test_store();
        assert!(
            validate_target_url("http://127.0.0.1:8080/API/foo", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
        assert!(
            validate_target_url("http://127.0.0.1:8080/Lorica/bot/solve", &store, TEST_HTTP_PORT, TEST_HTTPS_PORT).is_err()
        );
    }
}
