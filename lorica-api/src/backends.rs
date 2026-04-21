//! CRUD endpoints for upstream backends, including graceful drain on delete.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// JSON view of a backend enriched with live EWMA score and active connection count.
#[derive(Serialize)]
pub struct BackendResponse {
    /// Backend row id.
    pub id: String,
    /// `host:port` target.
    pub address: String,
    /// Human-readable label.
    pub name: String,
    /// Free-form classification (prod / staging / ...).
    pub group_name: String,
    /// Load-balancing weight.
    pub weight: i32,
    /// Last observed health status (lowercase name).
    pub health_status: String,
    /// Lifecycle state (normal / closing / closed).
    pub lifecycle_state: String,
    /// Live count of active connections to this backend.
    pub active_connections: i32,
    /// Whether the health-check loop probes this backend.
    pub health_check_enabled: bool,
    /// Health-check interval (s).
    pub health_check_interval_s: i32,
    /// Optional HTTP health-check path ; TCP connect when `None`.
    pub health_check_path: Option<String>,
    /// Whether the upstream expects TLS.
    pub tls_upstream: bool,
    /// Whether the TLS cert chain is validated ; `true` accepts
    /// self-signed / invalid certs.
    pub tls_skip_verify: bool,
    /// SNI override ; `None` reuses the route hostname.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg.
    pub h2_upstream: bool,
    /// Live EWMA latency score for the Peak-EWMA LB policy (μs).
    pub ewma_score_us: f64,
    /// RFC 3339 insert timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
}

/// JSON body for `POST /api/v1/backends`. Optional fields fall back to defaults.
#[derive(Deserialize)]
pub struct CreateBackendRequest {
    /// `host:port` upstream address. Required.
    pub address: String,
    /// Human-readable label.
    pub name: Option<String>,
    /// Free-form classification label.
    pub group_name: Option<String>,
    /// LB weight.
    pub weight: Option<i32>,
    /// Enable the health-check loop.
    pub health_check_enabled: Option<bool>,
    /// Health-check interval (s).
    pub health_check_interval_s: Option<i32>,
    /// HTTP health-check path ; TCP connect when `None`.
    pub health_check_path: Option<String>,
    /// Whether the upstream expects TLS.
    pub tls_upstream: Option<bool>,
    /// Skip upstream cert validation.
    pub tls_skip_verify: Option<bool>,
    /// SNI override for the upstream handshake.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg.
    pub h2_upstream: Option<bool>,
}

/// JSON body for `PUT /api/v1/backends/:id`. Only the supplied fields are mutated.
#[derive(Deserialize)]
pub struct UpdateBackendRequest {
    /// New `host:port` upstream address.
    pub address: Option<String>,
    /// New human-readable label.
    pub name: Option<String>,
    /// New free-form classification label.
    pub group_name: Option<String>,
    /// New LB weight.
    pub weight: Option<i32>,
    /// Toggle the health-check loop.
    pub health_check_enabled: Option<bool>,
    /// New health-check interval (s).
    pub health_check_interval_s: Option<i32>,
    /// New HTTP health-check path.
    pub health_check_path: Option<String>,
    /// Upstream TLS toggle.
    pub tls_upstream: Option<bool>,
    /// Skip upstream cert validation.
    pub tls_skip_verify: Option<bool>,
    /// SNI override.
    pub tls_sni: Option<String>,
    /// Force HTTP/2 on the upstream leg.
    pub h2_upstream: Option<bool>,
}

fn backend_to_response(
    b: &lorica_config::models::Backend,
    ewma_score: f64,
    active_connections: i32,
) -> BackendResponse {
    BackendResponse {
        id: b.id.clone(),
        address: b.address.clone(),
        name: b.name.clone(),
        group_name: b.group_name.clone(),
        weight: b.weight,
        health_status: b.health_status.as_str().to_string(),
        lifecycle_state: b.lifecycle_state.as_str().to_string(),
        active_connections,
        health_check_enabled: b.health_check_enabled,
        health_check_interval_s: b.health_check_interval_s,
        health_check_path: b.health_check_path.clone(),
        tls_upstream: b.tls_upstream,
        tls_skip_verify: b.tls_skip_verify,
        tls_sni: b.tls_sni.clone(),
        h2_upstream: b.h2_upstream,
        ewma_score_us: ewma_score,
        created_at: b.created_at.to_rfc3339(),
        updated_at: b.updated_at.to_rfc3339(),
    }
}

/// Look up active connections for a backend address from shared state.
async fn get_backend_connections_async(state: &crate::server::AppState, addr: &str) -> i32 {
    // Direct counters (single-process mode)
    if let Some(ref bc) = state.backend_connections {
        return bc.get(addr) as i32;
    }
    // Aggregated from workers (supervisor mode)
    if let Some(ref agg) = state.aggregated_metrics {
        if let Some(count) = agg.merged_backend_connections().await.get(addr).copied() {
            return count as i32;
        }
    }
    0
}

/// Look up the EWMA score for a backend address from shared state.
/// In single-process mode, reads from the direct ewma_scores map.
/// In supervisor mode, reads from aggregated worker metrics.
async fn get_ewma_score_async(state: &crate::server::AppState, addr: &str) -> f64 {
    // Direct scores (single-process mode)
    if let Some(score) = state
        .ewma_scores
        .as_ref()
        .and_then(|scores| scores.read().get(addr).copied())
    {
        return score;
    }
    // Aggregated from workers (supervisor mode)
    if let Some(ref agg) = state.aggregated_metrics {
        if let Some(score) = agg.merged_ewma_scores().await.get(addr).copied() {
            return score;
        }
    }
    0.0
}

/// GET /api/v1/backends - list every backend with its live EWMA score and active connection count.
pub async fn list_backends(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let backends = store.list_backends()?;
    let mut responses = Vec::with_capacity(backends.len());
    for b in &backends {
        let score = get_ewma_score_async(&state, &b.address).await;
        let conns = get_backend_connections_async(&state, &b.address).await;
        responses.push(backend_to_response(b, score, conns));
    }
    Ok(json_data(serde_json::json!({ "backends": responses })))
}

/// POST /api/v1/backends - register a new upstream backend.
pub async fn create_backend(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateBackendRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.address.is_empty() {
        return Err(ApiError::BadRequest("address is required".into()));
    }

    let now = Utc::now();
    let backend = lorica_config::models::Backend {
        id: uuid::Uuid::new_v4().to_string(),
        address: body.address,
        name: body.name.unwrap_or_default(),
        group_name: body.group_name.unwrap_or_default(),
        weight: body.weight.unwrap_or(100),
        health_status: lorica_config::models::HealthStatus::Unknown,
        health_check_enabled: body.health_check_enabled.unwrap_or(true),
        health_check_interval_s: body.health_check_interval_s.unwrap_or(10),
        health_check_path: body.health_check_path.clone().filter(|s| !s.is_empty()),
        lifecycle_state: lorica_config::models::LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: body.tls_upstream.unwrap_or(false),
        tls_skip_verify: body.tls_skip_verify.unwrap_or(false),
        tls_sni: body.tls_sni.clone().filter(|s| !s.is_empty()),
        h2_upstream: body.h2_upstream.unwrap_or(false),
        created_at: now,
        updated_at: now,
    };

    let store = state.store.lock().await;
    store.create_backend(&backend)?;
    drop(store);
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        backend_to_response(&backend, 0.0, 0),
    ))
}

/// GET /api/v1/backends/:id - fetch a single backend by id.
pub async fn get_backend(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let backend = store
        .get_backend(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))?;
    let score = get_ewma_score_async(&state, &backend.address).await;
    let conns = get_backend_connections_async(&state, &backend.address).await;
    Ok(json_data(backend_to_response(&backend, score, conns)))
}

/// PUT /api/v1/backends/:id - patch backend fields and trigger a proxy reload.
pub async fn update_backend(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateBackendRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut backend = store
        .get_backend(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))?;

    if let Some(address) = body.address {
        backend.address = address;
    }
    if let Some(name) = body.name {
        backend.name = name;
    }
    if let Some(group_name) = body.group_name {
        backend.group_name = group_name;
    }
    if let Some(weight) = body.weight {
        backend.weight = weight;
    }
    if let Some(hc) = body.health_check_enabled {
        backend.health_check_enabled = hc;
        if !hc {
            backend.health_status = lorica_config::models::HealthStatus::Unknown;
        }
    }
    if let Some(interval) = body.health_check_interval_s {
        backend.health_check_interval_s = interval;
    }
    if let Some(path) = body.health_check_path {
        if path.is_empty() {
            backend.health_check_path = None;
        } else {
            backend.health_check_path = Some(path);
        }
    }
    if let Some(tls) = body.tls_upstream {
        backend.tls_upstream = tls;
    }
    if let Some(skip) = body.tls_skip_verify {
        backend.tls_skip_verify = skip;
    }
    if let Some(sni) = body.tls_sni {
        backend.tls_sni = if sni.is_empty() { None } else { Some(sni) };
    }
    if let Some(h2) = body.h2_upstream {
        backend.h2_upstream = h2;
    }
    backend.updated_at = Utc::now();

    store.update_backend(&backend)?;
    drop(store);
    state.notify_config_changed();
    let score = get_ewma_score_async(&state, &backend.address).await;
    let conns = get_backend_connections_async(&state, &backend.address).await;
    Ok(json_data(backend_to_response(&backend, score, conns)))
}

/// DELETE /api/v1/backends/:id - graceful drain delete.
///
/// Initiates graceful drain: sets lifecycle_state to Closing so no new
/// requests are routed to this backend, then spawns a background task
/// that waits for active connections to reach 0 (or a 60s timeout)
/// before deleting the backend from the database.
pub async fn delete_backend(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut backend = store
        .get_backend(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))?;

    // If already closing/closed, force delete immediately
    if backend.lifecycle_state != lorica_config::models::LifecycleState::Normal {
        store.delete_backend(&id)?;
        drop(store);
        state.notify_config_changed();
        return Ok(json_data(serde_json::json!({"message": "backend deleted"})));
    }

    // Transition to Closing - proxy stops routing new requests to this backend
    backend.lifecycle_state = lorica_config::models::LifecycleState::Closing;
    backend.updated_at = Utc::now();
    store.update_backend(&backend)?;
    drop(store);
    state.notify_config_changed();

    // Spawn background drain task under the shared tracker so
    // shutdown waits (up to the supervisor drain timeout) for any
    // in-flight drain to complete rather than ripping the DB row out
    // with connections still bound to it.
    let drain_state = state.clone();
    let drain_addr = backend.address.clone();
    let drain_id = id.clone();
    state.task_tracker.spawn(async move {
        const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + DRAIN_TIMEOUT;

        loop {
            let conns = get_backend_connections_async(&drain_state, &drain_addr).await;
            if conns <= 0 {
                tracing::info!(backend_id = %drain_id, "backend drained, deleting");
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    backend_id = %drain_id,
                    remaining_connections = conns,
                    "drain timeout exceeded, force deleting backend"
                );
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        // Delete from DB
        let store = drain_state.store.lock().await;
        if let Err(e) = store.delete_backend(&drain_id) {
            tracing::warn!(backend_id = %drain_id, error = %e, "failed to delete drained backend");
        }
        drop(store);
        drain_state.notify_config_changed();
    });

    Ok(json_data(serde_json::json!({
        "message": "backend draining",
        "lifecycle_state": "closing",
    })))
}
