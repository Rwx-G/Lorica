use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

#[derive(Serialize)]
pub struct RouteResponse {
    pub id: String,
    pub hostname: String,
    pub path_prefix: String,
    pub backends: Vec<String>,
    pub certificate_id: Option<String>,
    pub load_balancing: String,
    pub waf_enabled: bool,
    pub topology_type: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Deserialize)]
pub struct CreateRouteRequest {
    pub hostname: String,
    pub path_prefix: Option<String>,
    pub backend_ids: Option<Vec<String>>,
    pub certificate_id: Option<String>,
    pub load_balancing: Option<String>,
    pub topology_type: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateRouteRequest {
    pub hostname: Option<String>,
    pub path_prefix: Option<String>,
    pub backend_ids: Option<Vec<String>>,
    pub certificate_id: Option<String>,
    pub load_balancing: Option<String>,
    pub topology_type: Option<String>,
    pub enabled: Option<bool>,
}

fn route_to_response(
    route: &lorica_config::models::Route,
    backend_ids: Vec<String>,
) -> RouteResponse {
    RouteResponse {
        id: route.id.clone(),
        hostname: route.hostname.clone(),
        path_prefix: route.path_prefix.clone(),
        backends: backend_ids,
        certificate_id: route.certificate_id.clone(),
        load_balancing: route.load_balancing.as_str().to_string(),
        waf_enabled: route.waf_enabled,
        topology_type: route.topology_type.as_str().to_string(),
        enabled: route.enabled,
        created_at: route.created_at.to_rfc3339(),
        updated_at: route.updated_at.to_rfc3339(),
    }
}

/// GET /api/v1/routes
pub async fn list_routes(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let routes = store.list_routes()?;
    let mut responses = Vec::with_capacity(routes.len());
    for route in &routes {
        let backend_ids = store.list_backends_for_route(&route.id)?;
        responses.push(route_to_response(route, backend_ids));
    }
    Ok(json_data(serde_json::json!({ "routes": responses })))
}

/// POST /api/v1/routes
pub async fn create_route(
    Extension(state): Extension<AppState>,
    Json(body): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.hostname.is_empty() {
        return Err(ApiError::BadRequest("hostname is required".into()));
    }

    let lb = body
        .load_balancing
        .as_deref()
        .unwrap_or("round_robin")
        .parse::<lorica_config::models::LoadBalancing>()
        .map_err(ApiError::BadRequest)?;

    let topo = body
        .topology_type
        .as_deref()
        .unwrap_or("single_vm")
        .parse::<lorica_config::models::TopologyType>()
        .map_err(ApiError::BadRequest)?;

    let now = Utc::now();
    let route = lorica_config::models::Route {
        id: uuid::Uuid::new_v4().to_string(),
        hostname: body.hostname,
        path_prefix: body.path_prefix.unwrap_or_else(|| "/".to_string()),
        certificate_id: body.certificate_id,
        load_balancing: lb,
        waf_enabled: false,
        waf_mode: lorica_config::models::WafMode::Detection,
        topology_type: topo,
        enabled: true,
        created_at: now,
        updated_at: now,
    };

    let store = state.store.lock().await;
    store.create_route(&route)?;

    let backend_ids = body.backend_ids.unwrap_or_default();
    for bid in &backend_ids {
        store.link_route_backend(&route.id, bid)?;
    }

    let response = route_to_response(&route, backend_ids);
    Ok(json_data_with_status(StatusCode::CREATED, response))
}

/// GET /api/v1/routes/:id
pub async fn get_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let route = store
        .get_route(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {id}")))?;
    let backend_ids = store.list_backends_for_route(&route.id)?;
    Ok(json_data(route_to_response(&route, backend_ids)))
}

/// PUT /api/v1/routes/:id
pub async fn update_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
    Json(body): Json<UpdateRouteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let mut route = store
        .get_route(&id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {id}")))?;

    if let Some(hostname) = body.hostname {
        route.hostname = hostname;
    }
    if let Some(path_prefix) = body.path_prefix {
        route.path_prefix = path_prefix;
    }
    if let Some(certificate_id) = body.certificate_id {
        route.certificate_id = Some(certificate_id);
    }
    if let Some(lb) = body.load_balancing {
        route.load_balancing = lb
            .parse::<lorica_config::models::LoadBalancing>()
            .map_err(ApiError::BadRequest)?;
    }
    if let Some(topo) = body.topology_type {
        route.topology_type = topo
            .parse::<lorica_config::models::TopologyType>()
            .map_err(ApiError::BadRequest)?;
    }
    if let Some(enabled) = body.enabled {
        route.enabled = enabled;
    }
    route.updated_at = Utc::now();

    store.update_route(&route)?;

    // Update backend associations if provided
    if let Some(backend_ids) = &body.backend_ids {
        let current = store.list_backends_for_route(&id)?;
        for bid in &current {
            store.unlink_route_backend(&id, bid)?;
        }
        for bid in backend_ids {
            store.link_route_backend(&id, bid)?;
        }
    }

    let backend_ids = store.list_backends_for_route(&id)?;
    Ok(json_data(route_to_response(&route, backend_ids)))
}

/// DELETE /api/v1/routes/:id
pub async fn delete_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_route(&id)?;
    Ok(json_data(serde_json::json!({"message": "route deleted"})))
}
