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

/// GET /api/v1/loadtest/configs
/// List all load test configurations.
pub async fn list_configs(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let configs = store
        .list_load_test_configs()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(configs))
}

/// POST /api/v1/loadtest/configs
/// Create a new load test configuration.
#[derive(Deserialize)]
pub struct CreateLoadTestConfig {
    pub name: String,
    pub target_url: String,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub concurrency: Option<i32>,
    pub requests_per_second: Option<i32>,
    pub duration_s: Option<i32>,
    pub error_threshold_pct: Option<f64>,
    pub schedule_cron: Option<String>,
}

/// Validate that the load test target URL points to a configured route.
/// This prevents using the load test engine to attack external hosts.
fn validate_target_url(
    url: &str,
    store: &lorica_config::ConfigStore,
) -> Result<(), ApiError> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| {
            ApiError::BadRequest("target URL must start with http:// or https://".into())
        })?;

    let authority = without_scheme.split('/').next().unwrap_or("");
    let host = if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .unwrap_or("")
            .trim_start_matches('[')
    } else {
        authority.split(':').next().unwrap_or("")
    };

    // Allow localhost for backward compatibility
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

pub async fn create_config(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateLoadTestConfig>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let store = state.store.lock().await;
    validate_target_url(&body.target_url, &store)?;
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

/// PUT /api/v1/loadtest/configs/:id
/// Update an existing load test configuration.
#[derive(Deserialize)]
pub struct UpdateLoadTestConfig {
    pub name: Option<String>,
    pub target_url: Option<String>,
    pub method: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub body: Option<String>,
    pub concurrency: Option<i32>,
    pub requests_per_second: Option<i32>,
    pub duration_s: Option<i32>,
    pub error_threshold_pct: Option<f64>,
    pub schedule_cron: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn update_config(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateLoadTestConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    if let Some(ref url) = body.target_url {
        validate_target_url(url, &store)?;
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

/// DELETE /api/v1/loadtest/configs/:id
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

/// POST /api/v1/loadtest/start/:config_id
/// Start a load test.
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

    // Run the test in a background task
    let engine = Arc::clone(engine);
    let store = Arc::clone(&state.store);
    tokio::spawn(async move {
        engine.run(&config, &store).await;
    });

    Ok(json_data(serde_json::json!({
        "status": "started",
        "config_id": config_id
    })))
}

/// POST /api/v1/loadtest/start/:config_id/confirm
/// Start a load test that exceeds safe limits (user confirmed).
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
    tokio::spawn(async move {
        engine.run(&config, &store).await;
    });

    Ok(json_data(serde_json::json!({
        "status": "started",
        "config_id": config_id,
        "safe_limits_bypassed": true
    })))
}

/// GET /api/v1/loadtest/status
/// Get status of the currently running test.
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

/// POST /api/v1/loadtest/abort
/// Abort the currently running test.
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

/// GET /api/v1/loadtest/results/:config_id
/// Get historical results for a load test configuration.
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

/// GET /api/v1/loadtest/results/:config_id/compare
/// Compare the latest result with the previous one.
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

/// POST /api/v1/loadtest/configs/:id/clone
/// Clone a load test configuration for reproducible comparisons.
#[derive(Deserialize)]
pub struct CloneConfig {
    pub name: Option<String>,
}

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
        lorica_config::ConfigStore::open_in_memory().unwrap()
    }

    #[test]
    fn validate_target_url_allows_localhost() {
        let store = test_store();
        assert!(validate_target_url("http://127.0.0.1:8080/", &store).is_ok());
        assert!(validate_target_url("https://127.0.0.1:8443/api/health", &store).is_ok());
        assert!(validate_target_url("http://localhost:8080/", &store).is_ok());
        assert!(validate_target_url("https://localhost:8443/path", &store).is_ok());
        assert!(validate_target_url("http://[::1]:8080/", &store).is_ok());
    }

    #[test]
    fn validate_target_url_rejects_external() {
        let store = test_store();
        assert!(validate_target_url("http://10.0.0.1:8080/", &store).is_err());
        assert!(validate_target_url("https://example.com/", &store).is_err());
        assert!(validate_target_url("http://192.168.1.1/", &store).is_err());
        assert!(validate_target_url("http://0.0.0.0:8080/", &store).is_err());
    }

    #[test]
    fn validate_target_url_rejects_bad_scheme() {
        let store = test_store();
        assert!(validate_target_url("ftp://127.0.0.1/", &store).is_err());
        assert!(validate_target_url("127.0.0.1:8080/", &store).is_err());
    }
}
