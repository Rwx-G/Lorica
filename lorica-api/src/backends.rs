use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

#[derive(Serialize)]
pub struct BackendResponse {
    pub id: String,
    pub address: String,
    pub weight: i32,
    pub health_status: String,
    pub lifecycle_state: String,
    pub active_connections: i32,
    pub health_check_enabled: bool,
    pub health_check_interval_s: i32,
    pub health_check_path: Option<String>,
    pub tls_upstream: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct CreateBackendRequest {
    pub address: String,
    pub weight: Option<i32>,
    pub health_check_enabled: Option<bool>,
    pub health_check_interval_s: Option<i32>,
    pub health_check_path: Option<String>,
    pub tls_upstream: Option<bool>,
}

#[derive(Deserialize)]
pub struct UpdateBackendRequest {
    pub address: Option<String>,
    pub weight: Option<i32>,
    pub health_check_enabled: Option<bool>,
    pub health_check_interval_s: Option<i32>,
    pub health_check_path: Option<String>,
    pub tls_upstream: Option<bool>,
}

fn backend_to_response(b: &lorica_config::models::Backend) -> BackendResponse {
    BackendResponse {
        id: b.id.clone(),
        address: b.address.clone(),
        weight: b.weight,
        health_status: b.health_status.as_str().to_string(),
        lifecycle_state: b.lifecycle_state.as_str().to_string(),
        active_connections: b.active_connections,
        health_check_enabled: b.health_check_enabled,
        health_check_interval_s: b.health_check_interval_s,
        health_check_path: b.health_check_path.clone(),
        tls_upstream: b.tls_upstream,
        created_at: b.created_at.to_rfc3339(),
        updated_at: b.updated_at.to_rfc3339(),
    }
}

/// GET /api/v1/backends
pub async fn list_backends(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let backends = store.list_backends()?;
    let responses: Vec<_> = backends.iter().map(backend_to_response).collect();
    Ok(json_data(serde_json::json!({ "backends": responses })))
}

/// POST /api/v1/backends
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
        weight: body.weight.unwrap_or(100),
        health_status: lorica_config::models::HealthStatus::Healthy,
        health_check_enabled: body.health_check_enabled.unwrap_or(true),
        health_check_interval_s: body.health_check_interval_s.unwrap_or(10),
        health_check_path: body.health_check_path.clone(),
        lifecycle_state: lorica_config::models::LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: body.tls_upstream.unwrap_or(false),
        created_at: now,
        updated_at: now,
    };

    let store = state.store.lock().await;
    store.create_backend(&backend)?;
    drop(store);
    state.notify_config_changed();

    Ok(json_data_with_status(
        StatusCode::CREATED,
        backend_to_response(&backend),
    ))
}

/// GET /api/v1/backends/:id
pub async fn get_backend(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let backend = store
        .get_backend(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("backend {id}")))?;
    Ok(json_data(backend_to_response(&backend)))
}

/// PUT /api/v1/backends/:id
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
    if let Some(weight) = body.weight {
        backend.weight = weight;
    }
    if let Some(hc) = body.health_check_enabled {
        backend.health_check_enabled = hc;
    }
    if let Some(interval) = body.health_check_interval_s {
        backend.health_check_interval_s = interval;
    }
    if let Some(path) = body.health_check_path {
        backend.health_check_path = Some(path);
    }
    if let Some(tls) = body.tls_upstream {
        backend.tls_upstream = tls;
    }
    backend.updated_at = Utc::now();

    store.update_backend(&backend)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(backend_to_response(&backend)))
}

/// DELETE /api/v1/backends/:id
pub async fn delete_backend(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_backend(&id)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(serde_json::json!({"message": "backend deleted"})))
}
