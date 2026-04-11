use std::collections::HashMap;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

#[derive(Serialize)]
pub struct PathRuleResponse {
    pub path: String,
    pub match_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_ttl_s: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers_remove: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_rps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_burst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_status: Option<u16>,
}

#[derive(Deserialize)]
pub struct PathRuleRequest {
    pub path: String,
    pub match_type: Option<String>,
    pub backend_ids: Option<Vec<String>>,
    pub cache_enabled: Option<bool>,
    pub cache_ttl_s: Option<i32>,
    pub response_headers: Option<HashMap<String, String>>,
    pub response_headers_remove: Option<Vec<String>>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub redirect_to: Option<String>,
    pub return_status: Option<u16>,
}

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
    pub enabled: bool,
    pub force_https: bool,
    pub redirect_hostname: Option<String>,
    pub redirect_to: Option<String>,
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
    pub path_rules: Vec<PathRuleResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_status: Option<u16>,
    pub sticky_session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth_username: Option<String>,
    pub retry_on_methods: Vec<String>,
    pub maintenance_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_page_html: Option<String>,
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
    pub waf_enabled: Option<bool>,
    pub waf_mode: Option<String>,
    pub force_https: Option<bool>,
    pub redirect_hostname: Option<String>,
    pub redirect_to: Option<String>,
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
    pub path_rules: Option<Vec<PathRuleRequest>>,
    pub return_status: Option<u16>,
    pub sticky_session: Option<bool>,
    pub basic_auth_username: Option<String>,
    pub basic_auth_password: Option<String>,
    pub retry_on_methods: Option<Vec<String>>,
    pub maintenance_mode: Option<bool>,
    pub error_page_html: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateRouteRequest {
    pub hostname: Option<String>,
    pub path_prefix: Option<String>,
    pub backend_ids: Option<Vec<String>>,
    pub certificate_id: Option<String>,
    pub load_balancing: Option<String>,
    pub waf_enabled: Option<bool>,
    pub waf_mode: Option<String>,
    pub enabled: Option<bool>,
    pub force_https: Option<bool>,
    pub redirect_hostname: Option<String>,
    pub redirect_to: Option<String>,
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
    pub path_rules: Option<Vec<PathRuleRequest>>,
    pub return_status: Option<u16>,
    pub sticky_session: Option<bool>,
    pub basic_auth_username: Option<String>,
    pub basic_auth_password: Option<String>,
    pub retry_on_methods: Option<Vec<String>>,
    pub maintenance_mode: Option<bool>,
    pub error_page_html: Option<String>,
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
        enabled: route.enabled,
        force_https: route.force_https,
        redirect_hostname: route.redirect_hostname.clone(),
        redirect_to: route.redirect_to.clone(),
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
        path_rules: route
            .path_rules
            .iter()
            .map(|pr| PathRuleResponse {
                path: pr.path.clone(),
                match_type: pr.match_type.as_str().to_string(),
                backend_ids: pr.backend_ids.clone(),
                cache_enabled: pr.cache_enabled,
                cache_ttl_s: pr.cache_ttl_s,
                response_headers: pr.response_headers.clone(),
                response_headers_remove: pr.response_headers_remove.clone(),
                rate_limit_rps: pr.rate_limit_rps,
                rate_limit_burst: pr.rate_limit_burst,
                redirect_to: pr.redirect_to.clone(),
                return_status: pr.return_status,
            })
            .collect(),
        return_status: route.return_status,
        sticky_session: route.sticky_session,
        basic_auth_username: route.basic_auth_username.clone(),
        retry_on_methods: route.retry_on_methods.clone(),
        maintenance_mode: route.maintenance_mode,
        error_page_html: route.error_page_html.clone(),
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

    let waf_mode = body
        .waf_mode
        .as_deref()
        .unwrap_or("detection")
        .parse::<lorica_config::models::WafMode>()
        .map_err(ApiError::BadRequest)?;

    let path_rules = if let Some(ref prs) = body.path_rules {
        let mut rules = Vec::with_capacity(prs.len());
        for pr in prs {
            if !pr.path.starts_with('/') {
                return Err(ApiError::BadRequest(format!(
                    "path_rule path must start with '/': {}",
                    pr.path
                )));
            }
            let match_type = pr
                .match_type
                .as_deref()
                .unwrap_or("prefix")
                .parse::<lorica_config::models::PathMatchType>()
                .map_err(ApiError::BadRequest)?;
            rules.push(lorica_config::models::PathRule {
                path: pr.path.clone(),
                match_type,
                backend_ids: pr.backend_ids.clone(),
                cache_enabled: pr.cache_enabled,
                cache_ttl_s: pr.cache_ttl_s,
                response_headers: pr.response_headers.clone(),
                response_headers_remove: pr.response_headers_remove.clone(),
                rate_limit_rps: pr.rate_limit_rps,
                rate_limit_burst: pr.rate_limit_burst,
                redirect_to: pr.redirect_to.clone(),
                return_status: pr.return_status,
            });
        }
        rules
    } else {
        Vec::new()
    };

    let now = Utc::now();
    let route = lorica_config::models::Route {
        id: uuid::Uuid::new_v4().to_string(),
        hostname: body.hostname,
        path_prefix: body.path_prefix.unwrap_or_else(|| "/".to_string()),
        certificate_id: body.certificate_id,
        load_balancing: lb,
        waf_enabled: body.waf_enabled.unwrap_or(false),
        waf_mode,
        enabled: true,
        force_https: body.force_https.unwrap_or(false),
        redirect_hostname: body.redirect_hostname,
        redirect_to: body.redirect_to,
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
        path_rules,
        return_status: body.return_status,
        sticky_session: body.sticky_session.unwrap_or(false),
        basic_auth_username: body.basic_auth_username.clone(),
        basic_auth_password_hash: if let Some(ref pw) = body.basic_auth_password {
            Some(crate::auth::hash_password(pw)?)
        } else {
            None
        },
        retry_on_methods: body.retry_on_methods.clone().unwrap_or_default(),
        maintenance_mode: body.maintenance_mode.unwrap_or(false),
        error_page_html: body.error_page_html.clone(),
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
        route.redirect_hostname = if redirect_hostname.is_empty() { None } else { Some(redirect_hostname) };
    }
    if let Some(redirect_to) = body.redirect_to {
        if redirect_to.is_empty() {
            route.redirect_to = None;
        } else {
            route.redirect_to = Some(redirect_to);
        }
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
        route.strip_path_prefix = if strip_path_prefix.is_empty() { None } else { Some(strip_path_prefix) };
    }
    if let Some(add_path_prefix) = body.add_path_prefix {
        route.add_path_prefix = if add_path_prefix.is_empty() { None } else { Some(add_path_prefix) };
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
        route.max_request_body_bytes = if max_request_body_bytes == 0 { None } else { Some(max_request_body_bytes) };
    }
    if let Some(websocket_enabled) = body.websocket_enabled {
        route.websocket_enabled = websocket_enabled;
    }
    if let Some(rate_limit_rps) = body.rate_limit_rps {
        route.rate_limit_rps = if rate_limit_rps == 0 { None } else { Some(rate_limit_rps) };
    }
    if let Some(rate_limit_burst) = body.rate_limit_burst {
        route.rate_limit_burst = if rate_limit_burst == 0 { None } else { Some(rate_limit_burst) };
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
        route.cors_max_age_s = if cors_max_age_s == 0 { None } else { Some(cors_max_age_s) };
    }
    if let Some(compression_enabled) = body.compression_enabled {
        route.compression_enabled = compression_enabled;
    }
    if let Some(retry_attempts) = body.retry_attempts {
        route.retry_attempts = if retry_attempts == 0 { None } else { Some(retry_attempts) };
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
        route.max_connections = if max_connections == 0 { None } else { Some(max_connections) };
    }
    if let Some(slowloris_threshold_ms) = body.slowloris_threshold_ms {
        route.slowloris_threshold_ms = slowloris_threshold_ms;
    }
    if let Some(auto_ban_threshold) = body.auto_ban_threshold {
        route.auto_ban_threshold = if auto_ban_threshold == 0 { None } else { Some(auto_ban_threshold) };
    }
    if let Some(auto_ban_duration_s) = body.auto_ban_duration_s {
        route.auto_ban_duration_s = auto_ban_duration_s;
    }
    if let Some(ref prs) = body.path_rules {
        let mut rules = Vec::with_capacity(prs.len());
        for pr in prs {
            if !pr.path.starts_with('/') {
                return Err(ApiError::BadRequest(format!(
                    "path_rule path must start with '/': {}",
                    pr.path
                )));
            }
            let match_type = pr
                .match_type
                .as_deref()
                .unwrap_or("prefix")
                .parse::<lorica_config::models::PathMatchType>()
                .map_err(ApiError::BadRequest)?;
            rules.push(lorica_config::models::PathRule {
                path: pr.path.clone(),
                match_type,
                backend_ids: pr.backend_ids.clone(),
                cache_enabled: pr.cache_enabled,
                cache_ttl_s: pr.cache_ttl_s,
                response_headers: pr.response_headers.clone(),
                response_headers_remove: pr.response_headers_remove.clone(),
                rate_limit_rps: pr.rate_limit_rps,
                rate_limit_burst: pr.rate_limit_burst,
                redirect_to: pr.redirect_to.clone(),
                return_status: pr.return_status,
            });
        }
        route.path_rules = rules;
    }
    if let Some(return_status) = body.return_status {
        route.return_status = if return_status == 0 { None } else { Some(return_status) };
    }
    if let Some(sticky) = body.sticky_session {
        route.sticky_session = sticky;
    }
    if let Some(ref username) = body.basic_auth_username {
        route.basic_auth_username = if username.is_empty() { None } else { Some(username.clone()) };
    }
    if let Some(ref password) = body.basic_auth_password {
        route.basic_auth_password_hash = if password.is_empty() {
            None
        } else {
            Some(crate::auth::hash_password(password)?)
        };
    }
    if let Some(ref methods) = body.retry_on_methods {
        route.retry_on_methods = methods.clone();
    }
    if let Some(maintenance) = body.maintenance_mode {
        route.maintenance_mode = maintenance;
    }
    if let Some(ref html) = body.error_page_html {
        route.error_page_html = if html.is_empty() { None } else { Some(html.clone()) };
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
