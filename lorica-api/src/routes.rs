use std::collections::HashMap;

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
    pub waf_mode: String,
    pub topology_type: String,
    pub enabled: bool,
    pub force_https: bool,
    pub redirect_hostname: Option<String>,
    pub hostname_aliases: Vec<String>,
    pub proxy_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    pub security_headers: String,
    pub connect_timeout_s: i32,
    pub read_timeout_s: i32,
    pub send_timeout_s: i32,
    pub strip_path_prefix: Option<String>,
    pub add_path_prefix: Option<String>,
    pub path_rewrite_pattern: Option<String>,
    pub path_rewrite_replacement: Option<String>,
    pub access_log_enabled: bool,
    pub proxy_headers_remove: Vec<String>,
    pub response_headers_remove: Vec<String>,
    pub max_request_body_bytes: Option<u64>,
    pub websocket_enabled: bool,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub ip_allowlist: Vec<String>,
    pub ip_denylist: Vec<String>,
    pub cors_allowed_origins: Vec<String>,
    pub cors_allowed_methods: Vec<String>,
    pub cors_max_age_s: Option<i32>,
    pub compression_enabled: bool,
    pub retry_attempts: Option<u32>,
    pub cache_enabled: bool,
    pub cache_ttl_s: i32,
    pub cache_max_bytes: i64,
    pub max_connections: Option<u32>,
    pub slowloris_threshold_ms: i32,
    pub auto_ban_threshold: Option<u32>,
    pub auto_ban_duration_s: i32,
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
    pub waf_enabled: Option<bool>,
    pub waf_mode: Option<String>,
    pub force_https: Option<bool>,
    pub redirect_hostname: Option<String>,
    pub hostname_aliases: Option<Vec<String>>,
    pub proxy_headers: Option<HashMap<String, String>>,
    pub response_headers: Option<HashMap<String, String>>,
    pub security_headers: Option<String>,
    pub connect_timeout_s: Option<i32>,
    pub read_timeout_s: Option<i32>,
    pub send_timeout_s: Option<i32>,
    pub strip_path_prefix: Option<String>,
    pub add_path_prefix: Option<String>,
    pub path_rewrite_pattern: Option<String>,
    pub path_rewrite_replacement: Option<String>,
    pub access_log_enabled: Option<bool>,
    pub proxy_headers_remove: Option<Vec<String>>,
    pub response_headers_remove: Option<Vec<String>>,
    pub max_request_body_bytes: Option<u64>,
    pub websocket_enabled: Option<bool>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub ip_allowlist: Option<Vec<String>>,
    pub ip_denylist: Option<Vec<String>>,
    pub cors_allowed_origins: Option<Vec<String>>,
    pub cors_allowed_methods: Option<Vec<String>>,
    pub cors_max_age_s: Option<i32>,
    pub compression_enabled: Option<bool>,
    pub retry_attempts: Option<u32>,
    pub cache_enabled: Option<bool>,
    pub cache_ttl_s: Option<i32>,
    pub cache_max_bytes: Option<i64>,
    pub max_connections: Option<u32>,
    pub slowloris_threshold_ms: Option<i32>,
    pub auto_ban_threshold: Option<u32>,
    pub auto_ban_duration_s: Option<i32>,
}

#[derive(Deserialize)]
pub struct UpdateRouteRequest {
    pub hostname: Option<String>,
    pub path_prefix: Option<String>,
    pub backend_ids: Option<Vec<String>>,
    pub certificate_id: Option<String>,
    pub load_balancing: Option<String>,
    pub topology_type: Option<String>,
    pub waf_enabled: Option<bool>,
    pub waf_mode: Option<String>,
    pub enabled: Option<bool>,
    pub force_https: Option<bool>,
    pub redirect_hostname: Option<String>,
    pub hostname_aliases: Option<Vec<String>>,
    pub proxy_headers: Option<HashMap<String, String>>,
    pub response_headers: Option<HashMap<String, String>>,
    pub security_headers: Option<String>,
    pub connect_timeout_s: Option<i32>,
    pub read_timeout_s: Option<i32>,
    pub send_timeout_s: Option<i32>,
    pub strip_path_prefix: Option<String>,
    pub add_path_prefix: Option<String>,
    pub path_rewrite_pattern: Option<String>,
    pub path_rewrite_replacement: Option<String>,
    pub access_log_enabled: Option<bool>,
    pub proxy_headers_remove: Option<Vec<String>>,
    pub response_headers_remove: Option<Vec<String>>,
    pub max_request_body_bytes: Option<u64>,
    pub websocket_enabled: Option<bool>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub ip_allowlist: Option<Vec<String>>,
    pub ip_denylist: Option<Vec<String>>,
    pub cors_allowed_origins: Option<Vec<String>>,
    pub cors_allowed_methods: Option<Vec<String>>,
    pub cors_max_age_s: Option<i32>,
    pub compression_enabled: Option<bool>,
    pub retry_attempts: Option<u32>,
    pub cache_enabled: Option<bool>,
    pub cache_ttl_s: Option<i32>,
    pub cache_max_bytes: Option<i64>,
    pub max_connections: Option<u32>,
    pub slowloris_threshold_ms: Option<i32>,
    pub auto_ban_threshold: Option<u32>,
    pub auto_ban_duration_s: Option<i32>,
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
        waf_mode: route.waf_mode.as_str().to_string(),
        topology_type: route.topology_type.as_str().to_string(),
        enabled: route.enabled,
        force_https: route.force_https,
        redirect_hostname: route.redirect_hostname.clone(),
        hostname_aliases: route.hostname_aliases.clone(),
        proxy_headers: route.proxy_headers.clone(),
        response_headers: route.response_headers.clone(),
        security_headers: route.security_headers.clone(),
        connect_timeout_s: route.connect_timeout_s,
        read_timeout_s: route.read_timeout_s,
        send_timeout_s: route.send_timeout_s,
        strip_path_prefix: route.strip_path_prefix.clone(),
        add_path_prefix: route.add_path_prefix.clone(),
        path_rewrite_pattern: route.path_rewrite_pattern.clone(),
        path_rewrite_replacement: route.path_rewrite_replacement.clone(),
        access_log_enabled: route.access_log_enabled,
        proxy_headers_remove: route.proxy_headers_remove.clone(),
        response_headers_remove: route.response_headers_remove.clone(),
        max_request_body_bytes: route.max_request_body_bytes,
        websocket_enabled: route.websocket_enabled,
        rate_limit_rps: route.rate_limit_rps,
        rate_limit_burst: route.rate_limit_burst,
        ip_allowlist: route.ip_allowlist.clone(),
        ip_denylist: route.ip_denylist.clone(),
        cors_allowed_origins: route.cors_allowed_origins.clone(),
        cors_allowed_methods: route.cors_allowed_methods.clone(),
        cors_max_age_s: route.cors_max_age_s,
        compression_enabled: route.compression_enabled,
        retry_attempts: route.retry_attempts,
        cache_enabled: route.cache_enabled,
        cache_ttl_s: route.cache_ttl_s,
        cache_max_bytes: route.cache_max_bytes,
        max_connections: route.max_connections,
        slowloris_threshold_ms: route.slowloris_threshold_ms,
        auto_ban_threshold: route.auto_ban_threshold,
        auto_ban_duration_s: route.auto_ban_duration_s,
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
        .unwrap_or("standard")
        .parse::<lorica_config::models::TopologyType>()
        .map_err(ApiError::BadRequest)?;

    let waf_mode = body
        .waf_mode
        .as_deref()
        .unwrap_or("detection")
        .parse::<lorica_config::models::WafMode>()
        .map_err(ApiError::BadRequest)?;

    let now = Utc::now();
    let route = lorica_config::models::Route {
        id: uuid::Uuid::new_v4().to_string(),
        hostname: body.hostname,
        path_prefix: body.path_prefix.unwrap_or_else(|| "/".to_string()),
        certificate_id: body.certificate_id,
        load_balancing: lb,
        waf_enabled: body.waf_enabled.unwrap_or(false),
        waf_mode,
        topology_type: topo,
        enabled: true,
        force_https: body.force_https.unwrap_or(false),
        redirect_hostname: body.redirect_hostname,
        hostname_aliases: body.hostname_aliases.unwrap_or_default(),
        proxy_headers: body.proxy_headers.unwrap_or_default(),
        response_headers: body.response_headers.unwrap_or_default(),
        security_headers: body
            .security_headers
            .unwrap_or_else(|| "moderate".to_string()),
        connect_timeout_s: body.connect_timeout_s.unwrap_or(5),
        read_timeout_s: body.read_timeout_s.unwrap_or(60),
        send_timeout_s: body.send_timeout_s.unwrap_or(60),
        strip_path_prefix: body.strip_path_prefix,
        add_path_prefix: body.add_path_prefix,
        path_rewrite_pattern: body.path_rewrite_pattern,
        path_rewrite_replacement: body.path_rewrite_replacement,
        access_log_enabled: body.access_log_enabled.unwrap_or(true),
        proxy_headers_remove: body.proxy_headers_remove.unwrap_or_default(),
        response_headers_remove: body.response_headers_remove.unwrap_or_default(),
        max_request_body_bytes: body.max_request_body_bytes,
        websocket_enabled: body.websocket_enabled.unwrap_or(true),
        rate_limit_rps: body.rate_limit_rps,
        rate_limit_burst: body.rate_limit_burst,
        ip_allowlist: body.ip_allowlist.unwrap_or_default(),
        ip_denylist: body.ip_denylist.unwrap_or_default(),
        cors_allowed_origins: body.cors_allowed_origins.unwrap_or_default(),
        cors_allowed_methods: body.cors_allowed_methods.unwrap_or_default(),
        cors_max_age_s: body.cors_max_age_s,
        compression_enabled: body.compression_enabled.unwrap_or(false),
        retry_attempts: body.retry_attempts,
        cache_enabled: body.cache_enabled.unwrap_or(false),
        cache_ttl_s: body.cache_ttl_s.unwrap_or(300),
        cache_max_bytes: body.cache_max_bytes.unwrap_or(52428800),
        max_connections: body.max_connections,
        slowloris_threshold_ms: body.slowloris_threshold_ms.unwrap_or(5000),
        auto_ban_threshold: body.auto_ban_threshold,
        auto_ban_duration_s: body.auto_ban_duration_s.unwrap_or(3600),
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
    state.notify_config_changed();
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
        if certificate_id.is_empty() {
            route.certificate_id = None;
            route.force_https = false;
        } else {
            route.certificate_id = Some(certificate_id);
        }
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
    if let Some(waf_enabled) = body.waf_enabled {
        route.waf_enabled = waf_enabled;
    }
    if let Some(waf_mode) = body.waf_mode {
        route.waf_mode = waf_mode
            .parse::<lorica_config::models::WafMode>()
            .map_err(ApiError::BadRequest)?;
    }
    if let Some(enabled) = body.enabled {
        route.enabled = enabled;
    }
    if let Some(force_https) = body.force_https {
        route.force_https = force_https;
    }
    if let Some(redirect_hostname) = body.redirect_hostname {
        route.redirect_hostname = Some(redirect_hostname);
    }
    if let Some(hostname_aliases) = body.hostname_aliases {
        route.hostname_aliases = hostname_aliases;
    }
    if let Some(proxy_headers) = body.proxy_headers {
        route.proxy_headers = proxy_headers;
    }
    if let Some(response_headers) = body.response_headers {
        route.response_headers = response_headers;
    }
    if let Some(security_headers) = body.security_headers {
        route.security_headers = security_headers;
    }
    if let Some(connect_timeout_s) = body.connect_timeout_s {
        route.connect_timeout_s = connect_timeout_s;
    }
    if let Some(read_timeout_s) = body.read_timeout_s {
        route.read_timeout_s = read_timeout_s;
    }
    if let Some(send_timeout_s) = body.send_timeout_s {
        route.send_timeout_s = send_timeout_s;
    }
    if let Some(strip_path_prefix) = body.strip_path_prefix {
        route.strip_path_prefix = Some(strip_path_prefix);
    }
    if let Some(add_path_prefix) = body.add_path_prefix {
        route.add_path_prefix = Some(add_path_prefix);
    }
    if let Some(ref pattern) = body.path_rewrite_pattern {
        if pattern.is_empty() {
            route.path_rewrite_pattern = None;
            route.path_rewrite_replacement = None;
        } else {
            // Validate regex at API level
            if regex::Regex::new(pattern).is_err() {
                return Err(ApiError::BadRequest(format!(
                    "invalid path_rewrite_pattern regex: {pattern}"
                )));
            }
            if pattern.len() > 1024 {
                return Err(ApiError::BadRequest(
                    "path_rewrite_pattern must be <= 1024 characters".into(),
                ));
            }
            route.path_rewrite_pattern = Some(pattern.clone());
        }
    }
    if let Some(replacement) = body.path_rewrite_replacement {
        route.path_rewrite_replacement = Some(replacement);
    }
    if let Some(access_log_enabled) = body.access_log_enabled {
        route.access_log_enabled = access_log_enabled;
    }
    if let Some(proxy_headers_remove) = body.proxy_headers_remove {
        route.proxy_headers_remove = proxy_headers_remove;
    }
    if let Some(response_headers_remove) = body.response_headers_remove {
        route.response_headers_remove = response_headers_remove;
    }
    if let Some(max_request_body_bytes) = body.max_request_body_bytes {
        route.max_request_body_bytes = Some(max_request_body_bytes);
    }
    if let Some(websocket_enabled) = body.websocket_enabled {
        route.websocket_enabled = websocket_enabled;
    }
    if let Some(rate_limit_rps) = body.rate_limit_rps {
        route.rate_limit_rps = Some(rate_limit_rps);
    }
    if let Some(rate_limit_burst) = body.rate_limit_burst {
        route.rate_limit_burst = Some(rate_limit_burst);
    }
    if let Some(ip_allowlist) = body.ip_allowlist {
        route.ip_allowlist = ip_allowlist;
    }
    if let Some(ip_denylist) = body.ip_denylist {
        route.ip_denylist = ip_denylist;
    }
    if let Some(cors_allowed_origins) = body.cors_allowed_origins {
        route.cors_allowed_origins = cors_allowed_origins;
    }
    if let Some(cors_allowed_methods) = body.cors_allowed_methods {
        route.cors_allowed_methods = cors_allowed_methods;
    }
    if let Some(cors_max_age_s) = body.cors_max_age_s {
        route.cors_max_age_s = Some(cors_max_age_s);
    }
    if let Some(compression_enabled) = body.compression_enabled {
        route.compression_enabled = compression_enabled;
    }
    if let Some(retry_attempts) = body.retry_attempts {
        route.retry_attempts = Some(retry_attempts);
    }
    if let Some(cache_enabled) = body.cache_enabled {
        route.cache_enabled = cache_enabled;
    }
    if let Some(cache_ttl_s) = body.cache_ttl_s {
        route.cache_ttl_s = cache_ttl_s;
    }
    if let Some(cache_max_bytes) = body.cache_max_bytes {
        route.cache_max_bytes = cache_max_bytes;
    }
    if let Some(max_connections) = body.max_connections {
        route.max_connections = Some(max_connections);
    }
    if let Some(slowloris_threshold_ms) = body.slowloris_threshold_ms {
        route.slowloris_threshold_ms = slowloris_threshold_ms;
    }
    if let Some(auto_ban_threshold) = body.auto_ban_threshold {
        route.auto_ban_threshold = Some(auto_ban_threshold);
    }
    if let Some(auto_ban_duration_s) = body.auto_ban_duration_s {
        route.auto_ban_duration_s = auto_ban_duration_s;
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
    state.notify_config_changed();
    Ok(json_data(route_to_response(&route, backend_ids)))
}

/// DELETE /api/v1/routes/:id
pub async fn delete_route(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_route(&id)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(serde_json::json!({"message": "route deleted"})))
}
