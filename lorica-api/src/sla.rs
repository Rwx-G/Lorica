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
//!
//! On a control plane the three reads (overview, per-route windows,
//! raw buckets) and the active-probe windows in `probes.rs` accept
//! `?node=<node_id>` (Story 9.7 AC #5, Epic 9 close): the figures are
//! then ONE follower's own, computed on that follower over its cluster
//! session and served here unchanged. Nothing fans in for SLA, and
//! nothing is aggregated: a fleet percentile is not a function of
//! per-node percentiles, so the page shows one node at a time.

use axum::extract::{Path, Query};
use axum::response::IntoResponse;
use axum::Extension;
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use lorica_cluster::messages::{SlaBucketRow, SlaPull, SlaPullAck, SlaSummaryRow};
use lorica_config::models::{Role, SlaBucket, SlaSummary};
use serde::Deserialize;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// `?node=` on an SLA read. Absent or empty: this node's own figures.
#[derive(Deserialize)]
pub struct NodeQuery {
    /// A follower's node id, on a control plane.
    pub node: Option<String>,
}

/// Which node a read is for, or `None` for this one.
fn foreign_node(node: &Option<String>) -> Option<&str> {
    node.as_deref().filter(|n| !n.is_empty())
}

/// Read one follower's SLA over the cluster plane (Story 9.7 AC #5).
///
/// Operator floor, like every other fleet read since the Epic 9
/// close; 409 off a control plane; 409 with the reason when the node
/// holds no session or refused, because the honest answer to "what
/// does that node measure" when it cannot be asked is not an empty
/// chart.
pub(crate) async fn pull_from_node(
    state: &AppState,
    session: &Session,
    node: &str,
    pull: SlaPull,
) -> Result<SlaPullAck, ApiError> {
    if session.role < Role::Operator {
        return Err(ApiError::Forbidden(
            "another node's SLA is a fleet read: Operator or above".into(),
        ));
    }
    let control = crate::cluster::control_plane_for_reads(state)?;
    control
        .sla_pull(node, pull)
        .await
        .map_err(|e| ApiError::Conflict(format!("node {node}: {e}")))
}

/// Answer a [`SlaPull`] over `store`: what the FOLLOWER runs. Kept in
/// this crate so the same code serves the local handlers and the
/// proxied read, and so it is testable without a cluster.
///
/// # Errors
///
/// The store's error text, or `route ... not found` for a route this
/// node does not hold (a control plane may ask about a route the
/// follower's selector excluded).
pub fn answer_sla_pull(
    store: &lorica_config::ConfigStore,
    pull: &SlaPull,
) -> Result<SlaPullAck, String> {
    let now = Utc::now();
    if pull.route_id.is_empty() {
        let routes = store.list_routes().map_err(|e| e.to_string())?;
        let mut summaries = Vec::with_capacity(routes.len() * 2);
        let from_1h = now - Duration::hours(1);
        let from_24h = now - Duration::hours(24);
        for route in &routes {
            for (from, window) in [(from_1h, "1h"), (from_24h, "24h")] {
                let summary = store
                    .compute_sla_summary(&route.id, &from, &now, window, &pull.source)
                    .map_err(|e| e.to_string())?;
                summaries.push(summary_to_wire(&summary));
            }
        }
        return Ok(SlaPullAck {
            summaries,
            buckets: Vec::new(),
        });
    }
    store
        .get_route(&pull.route_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("route {} not found on this node", pull.route_id))?;
    if pull.buckets {
        let from = parse_rfc3339(&pull.from).unwrap_or_else(|| now - Duration::hours(24));
        let to = parse_rfc3339(&pull.to).unwrap_or(now);
        let buckets = store
            .query_sla_buckets(&pull.route_id, &from, &to, &pull.source)
            .map_err(|e| e.to_string())?;
        return Ok(SlaPullAck {
            summaries: Vec::new(),
            buckets: buckets.iter().map(bucket_to_wire).collect(),
        });
    }
    let summaries = lorica_bench::results::compute_all_windows(store, &pull.route_id, &pull.source)
        .map_err(|e| e.to_string())?;
    Ok(SlaPullAck {
        summaries: summaries.iter().map(summary_to_wire).collect(),
        buckets: Vec::new(),
    })
}

fn parse_rfc3339(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// The API struct, field for field, onto the wire.
pub fn summary_to_wire(s: &SlaSummary) -> SlaSummaryRow {
    SlaSummaryRow {
        route_id: s.route_id.clone(),
        window: s.window.clone(),
        total_requests: s.total_requests,
        successful_requests: s.successful_requests,
        sla_pct: s.sla_pct,
        avg_latency_ms: s.avg_latency_ms,
        p50_latency_ms: s.p50_latency_ms,
        p95_latency_ms: s.p95_latency_ms,
        p99_latency_ms: s.p99_latency_ms,
        target_pct: s.target_pct,
        meets_target: s.meets_target,
    }
}

/// The wire row back into the API struct the dashboard already reads.
pub fn summary_from_wire(r: SlaSummaryRow) -> SlaSummary {
    SlaSummary {
        route_id: r.route_id,
        window: r.window,
        total_requests: r.total_requests,
        successful_requests: r.successful_requests,
        sla_pct: r.sla_pct,
        avg_latency_ms: r.avg_latency_ms,
        p50_latency_ms: r.p50_latency_ms,
        p95_latency_ms: r.p95_latency_ms,
        p99_latency_ms: r.p99_latency_ms,
        target_pct: r.target_pct,
        meets_target: r.meets_target,
    }
}

/// The API bucket, field for field, onto the wire. The row id is
/// this node's and travels nowhere.
pub fn bucket_to_wire(b: &SlaBucket) -> SlaBucketRow {
    SlaBucketRow {
        route_id: b.route_id.clone(),
        bucket_start: b.bucket_start.to_rfc3339(),
        request_count: b.request_count,
        success_count: b.success_count,
        error_count: b.error_count,
        latency_sum_ms: b.latency_sum_ms,
        latency_min_ms: b.latency_min_ms,
        latency_max_ms: b.latency_max_ms,
        latency_p50_ms: b.latency_p50_ms,
        latency_p95_ms: b.latency_p95_ms,
        latency_p99_ms: b.latency_p99_ms,
        source: b.source.clone(),
        cfg_max_latency_ms: b.cfg_max_latency_ms,
        cfg_status_min: b.cfg_status_min,
        cfg_status_max: b.cfg_status_max,
        cfg_target_pct: b.cfg_target_pct,
    }
}

/// The wire bucket back into the API struct.
///
/// # Errors
///
/// A `bucket_start` that is not RFC 3339: the follower wrote it from
/// a `DateTime`, so this is a peer that is not a Lorica follower.
pub fn bucket_from_wire(r: SlaBucketRow) -> Result<SlaBucket, String> {
    let bucket_start = parse_rfc3339(&r.bucket_start)
        .ok_or_else(|| format!("bucket_start {:?} is not RFC 3339", r.bucket_start))?;
    Ok(SlaBucket {
        id: None,
        route_id: r.route_id,
        bucket_start,
        request_count: r.request_count,
        success_count: r.success_count,
        error_count: r.error_count,
        latency_sum_ms: r.latency_sum_ms,
        latency_min_ms: r.latency_min_ms,
        latency_max_ms: r.latency_max_ms,
        latency_p50_ms: r.latency_p50_ms,
        latency_p95_ms: r.latency_p95_ms,
        latency_p99_ms: r.latency_p99_ms,
        source: r.source,
        cfg_max_latency_ms: r.cfg_max_latency_ms,
        cfg_status_min: r.cfg_status_min,
        cfg_status_max: r.cfg_status_max,
        cfg_target_pct: r.cfg_target_pct,
    })
}

/// GET /api/v1/sla/routes/:id - return passive SLA summaries for all standard windows (1h, 24h, 7d, 30d).
/// With `?node=`, the same for one follower (Story 9.7 AC #5).
pub async fn get_route_sla(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(route_id): Path<String>,
    Query(node): Query<NodeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(node) = foreign_node(&node.node) {
        let pull = SlaPull {
            route_id,
            source: "passive".to_string(),
            ..SlaPull::default()
        };
        let ack = pull_from_node(&state, &session, node, pull).await?;
        let summaries: Vec<SlaSummary> = ack.summaries.into_iter().map(summary_from_wire).collect();
        return Ok(json_data(summaries));
    }
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

/// Query parameters for bucket queries: `?from=&to=&source=passive|active&node=`.
#[derive(Deserialize)]
pub struct BucketQuery {
    /// Start of the window (RFC 3339) ; default now - 24 h.
    pub from: Option<String>,
    /// End of the window (RFC 3339) ; default now.
    pub to: Option<String>,
    /// Bucket source (`"passive"` / `"active"`) ; default `"passive"`.
    pub source: Option<String>,
    /// A follower's node id, on a control plane (Story 9.7 AC #5).
    pub node: Option<String>,
}

/// GET /api/v1/sla/routes/:id/buckets - return raw SLA buckets within the requested time range.
pub async fn get_route_sla_buckets(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(route_id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<BucketQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(node) = foreign_node(&query.node) {
        let pull = SlaPull {
            route_id,
            source: query.source.clone().unwrap_or_else(|| "passive".to_string()),
            from: query.from.clone().unwrap_or_default(),
            to: query.to.clone().unwrap_or_default(),
            buckets: true,
        };
        let ack = pull_from_node(&state, &session, node, pull).await?;
        let buckets = ack
            .buckets
            .into_iter()
            .map(bucket_from_wire)
            .collect::<Result<Vec<SlaBucket>, String>>()
            .map_err(ApiError::Internal)?;
        return Ok(json_data(buckets));
    }
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
/// With `?node=`, one follower's overview (Story 9.7 AC #5).
pub async fn get_sla_overview(
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Query(node): Query<NodeQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(node) = foreign_node(&node.node) {
        let pull = SlaPull {
            source: "passive".to_string(),
            ..SlaPull::default()
        };
        let ack = pull_from_node(&state, &session, node, pull).await?;
        let summaries: Vec<SlaSummary> = ack.summaries.into_iter().map(summary_from_wire).collect();
        return Ok(json_data(summaries));
    }
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
