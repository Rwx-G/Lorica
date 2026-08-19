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

//! Read and configure SLA windows, raw buckets, and CSV/JSON exports per route.

use axum::extract::{Path};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// GET /api/v1/sla/routes/:id - return passive SLA summaries for all standard windows (1h, 24h, 7d, 30d).
pub async fn get_route_sla(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let summaries = db_blocking(&state.store, move |store| {
        // Verify route exists
        store
            .get_route(&route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

        lorica_bench::results::compute_all_windows(store, &route_id, "passive")
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    Ok(json_data(summaries))
}

/// Query parameters for bucket queries: `?from=&to=&source=passive|active`.
#[derive(Deserialize)]
pub struct BucketQuery {
    /// Start of the window (RFC 3339) ; default now - 24 h.
    pub from: Option<String>,
    /// End of the window (RFC 3339) ; default now.
    pub to: Option<String>,
    /// Bucket source (`"passive"` / `"active"`) ; default `"passive"`.
    pub source: Option<String>,
}

/// GET /api/v1/sla/routes/:id/buckets - return raw SLA buckets within the requested time range.
pub async fn get_route_sla_buckets(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<BucketQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
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
    let source = query.source.unwrap_or_else(|| "passive".to_string());

    let buckets = db_blocking(&state.store, move |store| {
        store
            .get_route(&route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

        store
            .query_sla_buckets(&route_id, &from, &to, &source)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    Ok(json_data(buckets))
}

/// GET /api/v1/sla/routes/:id/config - return the per-route SLA target / latency / status thresholds.
pub async fn get_sla_config(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let config = db_blocking(&state.store, move |store| {
        store
            .get_route(&route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {route_id}")))?;

        store
            .get_sla_config(&route_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    Ok(json_data(config))
}

/// JSON body for `PUT /api/v1/sla/routes/:id/config`. Only supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateSlaConfig {
    /// New SLA target percentage (0..=100).
    pub target_pct: Option<f64>,
    /// New latency ceiling (ms).
    pub max_latency_ms: Option<i64>,
    /// New success-status range lower bound.
    pub success_status_min: Option<i32>,
    /// New success-status range upper bound.
    pub success_status_max: Option<i32>,
}

/// PUT /api/v1/sla/routes/:id/config - patch SLA targets and refresh the live collector cache.
pub async fn update_sla_config(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(route_id): Path<String>,
    Json(body): Json<UpdateSlaConfig>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db_route_id = route_id.clone();
    let (before_config, config) = db_blocking(&state.store, move |store| {
        store
            .get_route(&db_route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {db_route_id}")))?;

        let mut config = store
            .get_sla_config(&db_route_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let before_config = config.clone();

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

        Ok((before_config, config))
    })
    .await?;

    // Update the in-memory collector cache
    if let Some(ref collector) = state.sla_collector {
        collector.set_sla_config(&route_id, config.clone());
    }

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    let before = serde_json::to_value(&before_config).ok();
    let after = serde_json::to_value(&config).ok();
    crate::audit::record(
        &state,
        &audit_ctx,
        "sla.config_update",
        ("route", &route_id),
        before.as_ref(),
        after.as_ref(),
    )
    .await;

    Ok(json_data(config))
}

/// Query parameters for SLA export: `?from=&to=&format=json|csv` (default 30d, JSON).
#[derive(Deserialize)]
pub struct ExportQuery {
    /// Start of the export window (RFC 3339). Default now - 30 d.
    pub from: Option<String>,
    /// End of the export window (RFC 3339). Default now.
    pub to: Option<String>,
    /// Output format (`"json"` / `"csv"`). Default `"json"`.
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

/// GET /api/v1/sla/routes/:id/export - download passive SLA buckets as JSON or CSV.
pub async fn export_sla_data(
    Extension(state): Extension<AppState>,
    Path(route_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ExportQuery>,
) -> Result<axum::response::Response, ApiError> {
    let (from, to) = parse_export_range(&query);

    let is_csv = query
        .format
        .as_deref()
        .map(|f| f.eq_ignore_ascii_case("csv"))
        .unwrap_or(false);

    let db_route_id = route_id.clone();
    let (buckets, config) = db_blocking(&state.store, move |store| {
        store
            .get_route(&db_route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {db_route_id}")))?;

        let buckets = store
            .query_sla_buckets(&db_route_id, &from, &to, "passive")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        // The JSON export embeds the SLA config; CSV does not need it.
        let config = if is_csv {
            None
        } else {
            Some(
                store
                    .get_sla_config(&db_route_id)
                    .map_err(|e| ApiError::Internal(e.to_string()))?,
            )
        };

        Ok::<_, ApiError>((buckets, config))
    })
    .await?;

    // `config` is `Some` exactly when the JSON export was requested.
    if let Some(config) = config {
        let export = serde_json::json!({
            "route_id": route_id,
            "from": from.to_rfc3339(),
            "to": to.to_rfc3339(),
            "config": config,
            "buckets": buckets,
        });
        Ok(Json(serde_json::json!({ "data": export })).into_response())
    } else {
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
    }
}

/// DELETE /api/v1/sla/routes/:id/data - delete every persisted SLA bucket and clear the in-memory collector.
pub async fn clear_route_sla(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(route_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let db_route_id = route_id.clone();
    let deleted = db_blocking(&state.store, move |store| {
        store
            .get_route(&db_route_id)?
            .ok_or_else(|| ApiError::NotFound(format!("route {db_route_id}")))?;

        store
            .delete_sla_buckets_for_route(&db_route_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;

    // Clear in-memory buckets for this route
    if let Some(ref collector) = state.sla_collector {
        collector.clear_route(&route_id);
    }

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "sla.data_clear",
        ("route", &route_id),
        None,
        None,
    )
    .await;

    Ok(json_data(serde_json::json!({
        "route_id": route_id,
        "deleted_buckets": deleted,
    })))
}

/// GET /api/v1/sla/overview - return 1h and 24h passive SLA summaries for every route.
pub async fn get_sla_overview(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // One store acquisition for the whole overview, as before the
    // blocking-pool migration: every per-route summary runs inside a
    // single closure.
    let overview = db_blocking(&state.store, move |store| {
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

        Ok::<_, ApiError>(overview)
    })
    .await?;

    Ok(json_data(overview))
}
