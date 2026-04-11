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

use axum::extract::Path;
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// GET /api/v1/sla/routes/:id
/// Returns SLA summaries for all standard windows (1h, 24h, 7d, 30d).
pub async fn get_route_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    // Verify route exists
    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let summaries = lorica_bench::results::compute_all_windows(&store, &route_id, "passive")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(summaries))
}

/// GET /api/v1/sla/routes/:id/buckets?from=...&to=...
/// Returns raw SLA buckets for a route within a time range.
#[derive(Deserialize)]
pub struct BucketQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub source: Option<String>,
}

pub async fn get_route_sla_buckets(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<BucketQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let now = Utc::now();
    let from = query
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| now - Duration::hours(24));
    let to = query
        .to
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(now);
    let source = query.source.as_deref().unwrap_or("passive");

    let buckets = store
        .query_sla_buckets(&route_id, &from, &to, source)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(buckets))
}

/// GET /api/v1/sla/routes/:id/config
/// Returns the SLA configuration for a route.
pub async fn get_sla_config(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let config = store
        .get_sla_config(&route_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(json_data(config))
}

/// PUT /api/v1/sla/routes/:id/config
/// Update SLA configuration for a route.
#[derive(Deserialize)]
pub struct UpdateSlaConfig {
    pub target_pct: Option<f64>,
    pub max_latency_ms: Option<i64>,
    pub success_status_min: Option<i32>,
    pub success_status_max: Option<i32>,
}

pub async fn update_sla_config(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    Json(body): Json<UpdateSlaConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let mut config = store
        .get_sla_config(&route_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if let Some(target) = body.target_pct {
        if !(0.0..=100.0).contains(&target) {
            return Err(ApiError::BadRequest(
                "target_pct must be between 0 and 100".into(),
            ));
        }
        config.target_pct = target;
    }
    if let Some(latency) = body.max_latency_ms {
        if latency <= 0 {
            return Err(ApiError::BadRequest(
                "max_latency_ms must be positive".into(),
            ));
        }
        config.max_latency_ms = latency;
    }
    if let Some(min) = body.success_status_min {
        config.success_status_min = min;
    }
    if let Some(max) = body.success_status_max {
        config.success_status_max = max;
    }
    config.updated_at = Utc::now();

    store
        .upsert_sla_config(&config)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Update the in-memory collector cache
    if let Some(ref collector) = state.sla_collector {
        collector.set_sla_config(&route_id, config.clone());
    }

    Ok(json_data(config))
}

/// GET /api/v1/sla/routes/:id/export?format=json|csv&from=...&to=...
/// Export SLA data for reporting.
#[derive(Deserialize)]
pub struct ExportQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub format: Option<String>,
}

fn parse_export_range(query: &ExportQuery) -> (chrono::DateTime<Utc>, chrono::DateTime<Utc>) {
    let now = Utc::now();
    let from = query
        .from
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| now - Duration::days(30));
    let to = query
        .to
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(now);
    (from, to)
}

pub async fn export_sla_data(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ExportQuery>,
) -> Result<axum::response::Response, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let (from, to) = parse_export_range(&query);

    let buckets = store
        .query_sla_buckets(&route_id, &from, &to, "passive")
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let is_csv = query
        .format
        .as_deref()
        .map(|f| f.eq_ignore_ascii_case("csv"))
        .unwrap_or(false);

    if is_csv {
        let mut csv = String::from(
            "bucket_start,request_count,success_count,error_count,\
             latency_sum_ms,latency_min_ms,latency_max_ms,\
             latency_p50_ms,latency_p95_ms,latency_p99_ms\n",
        );
        for b in &buckets {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                b.bucket_start.to_rfc3339(),
                b.request_count,
                b.success_count,
                b.error_count,
                b.latency_sum_ms,
                b.latency_min_ms,
                b.latency_max_ms,
                b.latency_p50_ms,
                b.latency_p95_ms,
                b.latency_p99_ms,
            ));
        }
        Ok(axum::response::Response::builder()
            .header("Content-Type", "text/csv")
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"sla-{route_id}.csv\""),
            )
            .body(axum::body::Body::from(csv))
            .expect("CSV response builder"))
    } else {
        let config = store
            .get_sla_config(&route_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let export = serde_json::json!({
            "route_id": route_id,
            "from": from.to_rfc3339(),
            "to": to.to_rfc3339(),
            "config": config,
            "buckets": buckets,
        });
        Ok(Json(serde_json::json!({ "data": export })).into_response())
    }
}

/// DELETE /api/v1/sla/routes/:id/data
/// Clear all SLA data for a route.
pub async fn clear_route_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;

    store
        .get_route(&route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

    let deleted = store
        .delete_sla_buckets_for_route(&route_id)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Clear in-memory buckets for this route
    if let Some(ref collector) = state.sla_collector {
        collector.clear_route(&route_id);
    }

    Ok(json_data(serde_json::json!({
        "route_id": route_id,
        "deleted_buckets": deleted,
    })))
}

/// GET /api/v1/sla/overview
/// Returns SLA summaries for all routes (24h window).
pub async fn get_sla_overview(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let routes = store
        .list_routes()
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    let now = Utc::now();
    let from = now - Duration::hours(24);

    let mut overview = Vec::new();
    let from_1h = now - Duration::hours(1);
    for route in &routes {
        let summary_1h = store
            .compute_sla_summary(&route.id, &from_1h, &now, "1h", "passive")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        overview.push(summary_1h);
        let summary_24h = store
            .compute_sla_summary(&route.id, &from, &now, "24h", "passive")
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        overview.push(summary_24h);
    }

    Ok(json_data(overview))
}
