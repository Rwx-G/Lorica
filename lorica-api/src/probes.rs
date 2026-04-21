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

//! Active SLA probe configuration endpoints (CRUD plus per-probe history).

use axum::extract::{Path, Query};
use axum::Extension;
use axum::Json;
use chrono::Utc;
use lorica_config::models::ProbeConfig;
use lorica_config::store::new_id;
use serde::Deserialize;

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// GET /api/v1/probes
/// List all probe configurations.
pub async fn list_probes(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let probes = store
        .list_probe_configs()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(probes))
}

/// GET /api/v1/probes/route/:route_id
/// List probes for a specific route.
pub async fn list_probes_for_route(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;
    let probes = store
        .list_probes_for_route(&route_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(json_data(probes))
}

/// JSON body for `POST /api/v1/probes`. Optional fields fall back to safe defaults.
#[derive(Deserialize)]
pub struct CreateProbe {
    /// `Route.id` the probe exercises.
    pub route_id: String,
    /// HTTP method (uppercase). Default `GET`.
    pub method: Option<String>,
    /// Request path. Default `/`.
    pub path: Option<String>,
    /// HTTP status that counts as success. Default 200.
    pub expected_status: Option<i32>,
    /// Interval between runs (s). Default 60.
    pub interval_s: Option<i32>,
    /// Per-run timeout (ms). Default 5000.
    pub timeout_ms: Option<i32>,
}

/// POST /api/v1/probes - create a new active probe attached to a route.
pub async fn create_probe(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateProbe>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    let store = state.store.lock().await;

    // Verify route exists
    store
        .get_route(&body.route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {}", body.route_id)))?;

    let now = Utc::now();
    let probe = ProbeConfig {
        id: new_id(),
        route_id: body.route_id,
        method: body.method.unwrap_or_else(|| "GET".to_string()),
        path: body.path.unwrap_or_else(|| "/".to_string()),
        expected_status: body.expected_status.unwrap_or(200),
        interval_s: body.interval_s.unwrap_or(30),
        timeout_ms: body.timeout_ms.unwrap_or(5000),
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    if probe.interval_s < 5 {
        return Err(ApiError::BadRequest(
            "interval_s must be at least 5 seconds".into(),
        ));
    }

    store
        .create_probe_config(&probe)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    state.notify_config_changed();
    Ok(json_data_with_status(
        axum::http::StatusCode::CREATED,
        probe,
    ))
}

/// JSON body for `PUT /api/v1/probes/:id`. Only supplied fields are applied.
#[derive(Deserialize)]
pub struct UpdateProbe {
    /// New HTTP method.
    pub method: Option<String>,
    /// New request path.
    pub path: Option<String>,
    /// New expected status code.
    pub expected_status: Option<i32>,
    /// New interval between runs (s, min 5).
    pub interval_s: Option<i32>,
    /// New per-run timeout (ms).
    pub timeout_ms: Option<i32>,
    /// Toggle the probe on / off.
    pub enabled: Option<bool>,
}

/// PUT /api/v1/probes/:id - patch fields on an existing probe configuration.
pub async fn update_probe(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateProbe>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    let mut probe = store
        .get_probe_config(&id)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("probe {id}")))?;

    if let Some(method) = body.method {
        probe.method = method;
    }
    if let Some(path) = body.path {
        probe.path = path;
    }
    if let Some(status) = body.expected_status {
        probe.expected_status = status;
    }
    if let Some(interval) = body.interval_s {
        if interval < 5 {
            return Err(ApiError::BadRequest(
                "interval_s must be at least 5 seconds".into(),
            ));
        }
        probe.interval_s = interval;
    }
    if let Some(timeout) = body.timeout_ms {
        probe.timeout_ms = timeout;
    }
    if let Some(enabled) = body.enabled {
        probe.enabled = enabled;
    }
    probe.updated_at = Utc::now();

    store
        .update_probe_config(&probe)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    state.notify_config_changed();
    Ok(json_data(probe))
}

/// DELETE /api/v1/probes/:id
/// Delete a probe configuration.
pub async fn delete_probe(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store
        .delete_probe_config(&id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    state.notify_config_changed();
    Ok(json_data(serde_json::json!({"deleted": id})))
}

/// Optional `?limit=N` query parameter for probe history; capped at 1000.
#[derive(Deserialize)]
pub struct ProbeHistoryQuery {
    /// Maximum number of result rows to return.
    pub limit: Option<usize>,
}

/// GET /api/v1/probes/:id/history - return up to `limit` recent probe execution results.
pub async fn probe_history(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Query(params): Query<ProbeHistoryQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store
        .get_probe_config(&id)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("probe {id}")))?;

    let limit = params.limit.unwrap_or(100).min(1000);
    let results = store
        .list_probe_results(&id, limit)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let total = results.len();
    Ok(json_data(serde_json::json!({
        "results": results,
        "total": total,
    })))
}

/// GET /api/v1/sla/routes/:id/active
/// Returns active SLA summaries for a route (from probe results).
pub async fn get_active_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let summaries = lorica_bench::results::compute_all_windows(&store, &route_id, "active")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(summaries))
}
