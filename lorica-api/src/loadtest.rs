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

use axum::extract::Path;
use axum::Extension;
use axum::Json;
use chrono::Utc;
use lorica_bench::load_test;
use lorica_config::models::LoadTestConfig;
use lorica_config::store::new_id;
use serde::Deserialize;

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

pub async fn create_config(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateLoadTestConfig>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
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

    // Check safe limits
    if load_test::exceeds_safe_limits(&config) {
        let warnings = load_test::describe_exceeded_limits(&config);
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
