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

#[derive(Serialize, Deserialize)]
pub struct HeaderRuleRequest {
    pub header_name: String,
    #[serde(default)]
    pub match_type: Option<String>,
    pub value: String,
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TrafficSplitRequest {
    #[serde(default)]
    pub name: String,
    pub weight_percent: u8,
    #[serde(default)]
    pub backend_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ForwardAuthConfigRequest {
    pub address: String,
    #[serde(default = "default_forward_auth_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default)]
    pub response_headers: Vec<String>,
}

fn default_forward_auth_timeout_ms() -> u32 {
    5_000
}

#[derive(Serialize, Deserialize, Clone)]
pub struct MirrorConfigRequest {
    #[serde(default)]
    pub backend_ids: Vec<String>,
    #[serde(default = "default_mirror_sample_percent")]
    pub sample_percent: u8,
    #[serde(default = "default_mirror_timeout_ms")]
    pub timeout_ms: u32,
    #[serde(default = "default_mirror_max_body_bytes")]
    pub max_body_bytes: u32,
}

fn default_mirror_sample_percent() -> u8 {
    100
}
fn default_mirror_timeout_ms() -> u32 {
    5_000
}
fn default_mirror_max_body_bytes() -> u32 {
    1_048_576
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
    pub stale_while_revalidate_s: i32,
    pub stale_if_error_s: i32,
    pub retry_on_methods: Vec<String>,
    pub maintenance_mode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_page_html: Option<String>,
    pub cache_vary_headers: Vec<String>,
    pub header_rules: Vec<HeaderRuleRequest>,
    pub traffic_splits: Vec<TrafficSplitRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorConfigRequest>,
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
    /// Plaintext password - hashed with Argon2id before storage. Never stored
    /// or logged in cleartext. The management API binds to localhost only;
    /// ensure TLS or SSH tunnel if accessing remotely.
    pub basic_auth_password: Option<String>,
    pub stale_while_revalidate_s: Option<i32>,
    pub stale_if_error_s: Option<i32>,
    pub retry_on_methods: Option<Vec<String>>,
    pub maintenance_mode: Option<bool>,
    pub error_page_html: Option<String>,
    pub cache_vary_headers: Option<Vec<String>>,
    pub header_rules: Option<Vec<HeaderRuleRequest>>,
    pub traffic_splits: Option<Vec<TrafficSplitRequest>>,
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    pub mirror: Option<MirrorConfigRequest>,
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
    /// Plaintext password - hashed with Argon2id before storage.
    pub basic_auth_password: Option<String>,
    pub stale_while_revalidate_s: Option<i32>,
    pub stale_if_error_s: Option<i32>,
    pub retry_on_methods: Option<Vec<String>>,
    pub maintenance_mode: Option<bool>,
    pub error_page_html: Option<String>,
    pub cache_vary_headers: Option<Vec<String>>,
    pub header_rules: Option<Vec<HeaderRuleRequest>>,
    pub traffic_splits: Option<Vec<TrafficSplitRequest>>,
    /// Update semantics: missing field = leave current value alone;
    /// present with empty `address` = clear; present with non-empty
    /// address = validate + install/replace.
    pub forward_auth: Option<ForwardAuthConfigRequest>,
    /// Update semantics: missing field = leave alone; present with
    /// empty `backend_ids` = clear; present with non-empty = validate
    /// + install/replace.
    pub mirror: Option<MirrorConfigRequest>,
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
        stale_while_revalidate_s: route.stale_while_revalidate_s,
        stale_if_error_s: route.stale_if_error_s,
        retry_on_methods: route.retry_on_methods.clone(),
        maintenance_mode: route.maintenance_mode,
        error_page_html: route.error_page_html.clone(),
        cache_vary_headers: route.cache_vary_headers.clone(),
        header_rules: route
            .header_rules
            .iter()
            .map(|hr| HeaderRuleRequest {
                header_name: hr.header_name.clone(),
                match_type: Some(hr.match_type.as_str().to_string()),
                value: hr.value.clone(),
                backend_ids: hr.backend_ids.clone(),
            })
            .collect(),
        traffic_splits: route
            .traffic_splits
            .iter()
            .map(|ts| TrafficSplitRequest {
                name: ts.name.clone(),
                weight_percent: ts.weight_percent,
                backend_ids: ts.backend_ids.clone(),
            })
            .collect(),
        forward_auth: route
            .forward_auth
            .as_ref()
            .map(|fa| ForwardAuthConfigRequest {
                address: fa.address.clone(),
                timeout_ms: fa.timeout_ms,
                response_headers: fa.response_headers.clone(),
            }),
        mirror: route.mirror.as_ref().map(|m| MirrorConfigRequest {
            backend_ids: m.backend_ids.clone(),
            sample_percent: m.sample_percent,
            timeout_ms: m.timeout_ms,
            max_body_bytes: m.max_body_bytes,
        }),
        created_at: route.created_at.to_rfc3339(),
        updated_at: route.updated_at.to_rfc3339(),
    }
}

/// Validate a MirrorConfigRequest and convert to stored model. Rejects
/// the two operator mistakes that make the feature silently broken:
/// non-existent backend IDs (caught at reload via a warning too, but
/// better to fail the write) and out-of-range weights.
fn build_mirror_config(
    body: &MirrorConfigRequest,
) -> Result<lorica_config::models::MirrorConfig, ApiError> {
    if body.backend_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "mirror.backend_ids must not be empty (use null/missing to disable)".into(),
        ));
    }
    if body.sample_percent > 100 {
        return Err(ApiError::BadRequest(format!(
            "mirror.sample_percent must be 0..=100, got {}",
            body.sample_percent
        )));
    }
    if body.timeout_ms == 0 {
        return Err(ApiError::BadRequest(
            "mirror.timeout_ms must be > 0".into(),
        ));
    }
    if body.timeout_ms > 60_000 {
        return Err(ApiError::BadRequest(
            "mirror.timeout_ms must be <= 60000 (60 seconds)".into(),
        ));
    }
    // Cap max_body_bytes at 128 MiB to prevent an operator from
    // unknowingly configuring memory amplification under the
    // 256-concurrent-mirrors cap.
    const MIRROR_MAX_BODY_CEILING: u32 = 128 * 1_048_576;
    if body.max_body_bytes > MIRROR_MAX_BODY_CEILING {
        return Err(ApiError::BadRequest(format!(
            "mirror.max_body_bytes must be <= {MIRROR_MAX_BODY_CEILING} ({} MiB); larger bodies should be mirrored via a dedicated replay tool",
            MIRROR_MAX_BODY_CEILING / 1_048_576
        )));
    }
    // Dedup and trim backend IDs so the engine doesn't spawn duplicate
    // sub-requests to the same shadow.
    let mut seen = std::collections::HashSet::new();
    let mut cleaned = Vec::with_capacity(body.backend_ids.len());
    for id in &body.backend_ids {
        let t = id.trim();
        if t.is_empty() {
            return Err(ApiError::BadRequest(
                "mirror.backend_ids entries must be non-empty".into(),
            ));
        }
        if seen.insert(t.to_string()) {
            cleaned.push(t.to_string());
        }
    }
    Ok(lorica_config::models::MirrorConfig {
        backend_ids: cleaned,
        sample_percent: body.sample_percent,
        timeout_ms: body.timeout_ms,
        max_body_bytes: body.max_body_bytes,
    })
}

/// Validate and convert a `ForwardAuthConfigRequest` to the stored
/// model. Rejects obvious operator mistakes at write time rather than at
/// the first request: empty address, non-absolute URL, zero or absurd
/// timeout, malformed response-header names.
fn build_forward_auth(
    body: &ForwardAuthConfigRequest,
) -> Result<lorica_config::models::ForwardAuthConfig, ApiError> {
    let address = body.address.trim();
    if address.is_empty() {
        return Err(ApiError::BadRequest(
            "forward_auth.address must not be empty (use null/missing to disable)".into(),
        ));
    }
    let parsed: http::Uri = address.parse().map_err(|e| {
        ApiError::BadRequest(format!("forward_auth.address must be an absolute URL: {e}"))
    })?;
    match parsed.scheme_str() {
        Some("http") | Some("https") => {}
        Some(s) => {
            return Err(ApiError::BadRequest(format!(
                "forward_auth.address must use http or https scheme, got {s}"
            )));
        }
        None => {
            return Err(ApiError::BadRequest(
                "forward_auth.address must be an absolute URL (scheme://host/path)".into(),
            ));
        }
    }
    if parsed.authority().is_none() {
        return Err(ApiError::BadRequest(
            "forward_auth.address must include a host (scheme://host/path)".into(),
        ));
    }
    if body.timeout_ms == 0 {
        return Err(ApiError::BadRequest(
            "forward_auth.timeout_ms must be > 0".into(),
        ));
    }
    if body.timeout_ms > 60_000 {
        return Err(ApiError::BadRequest(
            "forward_auth.timeout_ms must be <= 60000 (60 seconds); longer timeouts stall the request pipeline".into(),
        ));
    }
    for name in &body.response_headers {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "forward_auth.response_headers entries must be non-empty".into(),
            ));
        }
    }
    Ok(lorica_config::models::ForwardAuthConfig {
        address: address.to_string(),
        timeout_ms: body.timeout_ms,
        response_headers: body
            .response_headers
            .iter()
            .map(|h| h.trim().to_string())
            .collect(),
    })
}

/// Validate a traffic split request and convert it to the stored model.
/// Rejects the two operator mistakes that would silently break the feature:
/// weights outside 0..=100 (serde already caps at u8 max, but 101-255 still
/// slips through), and non-zero weight with an empty backend list (would
/// consume its weight band without diverting any traffic).
fn build_traffic_split(
    body: &TrafficSplitRequest,
) -> Result<lorica_config::models::TrafficSplit, ApiError> {
    if body.weight_percent > 100 {
        return Err(ApiError::BadRequest(format!(
            "traffic_splits: weight_percent must be 0..=100, got {}",
            body.weight_percent
        )));
    }
    if body.weight_percent > 0 && body.backend_ids.is_empty() {
        return Err(ApiError::BadRequest(
            "traffic_splits: a split with weight > 0 must list at least one backend".into(),
        ));
    }
    Ok(lorica_config::models::TrafficSplit {
        name: body.name.trim().to_string(),
        weight_percent: body.weight_percent,
        backend_ids: body.backend_ids.clone(),
    })
}

/// Per-route global check: cumulative weights must not exceed 100%. The
/// engine clamps silently but the operator experience is better if the
/// API rejects the typo before it hits the DB.
fn validate_traffic_splits(splits: &[lorica_config::models::TrafficSplit]) -> Result<(), ApiError> {
    let total: u32 = splits.iter().map(|s| s.weight_percent as u32).sum();
    if total > 100 {
        return Err(ApiError::BadRequest(format!(
            "traffic_splits: cumulative weight_percent must be <= 100, got {total}"
        )));
    }
    Ok(())
}

/// Parse and validate an incoming `HeaderRuleRequest`. Rejects empty header
/// names, empty Exact/Prefix values (would otherwise match every request),
/// and malformed regex patterns. Returns the fully-typed `HeaderRule` the
/// store can persist.
fn build_header_rule(
    body: &HeaderRuleRequest,
) -> Result<lorica_config::models::HeaderRule, ApiError> {
    let header_name = body.header_name.trim();
    if header_name.is_empty() {
        return Err(ApiError::BadRequest("header_rules: header_name must not be empty".into()));
    }
    let match_type: lorica_config::models::HeaderMatchType = body
        .match_type
        .as_deref()
        .unwrap_or("exact")
        .parse()
        .map_err(ApiError::BadRequest)?;
    if matches!(
        match_type,
        lorica_config::models::HeaderMatchType::Exact
            | lorica_config::models::HeaderMatchType::Prefix
    ) && body.value.is_empty()
    {
        return Err(ApiError::BadRequest(format!(
            "header_rules: {} match requires a non-empty value (use regex '.*' if you really want match-all)",
            match_type.as_str()
        )));
    }
    if matches!(match_type, lorica_config::models::HeaderMatchType::Regex) {
        regex::Regex::new(&body.value).map_err(|e| {
            ApiError::BadRequest(format!(
                "header_rules: invalid regex for header {header_name}: {e}"
            ))
        })?;
    }
    Ok(lorica_config::models::HeaderRule {
        header_name: header_name.to_string(),
        match_type,
        value: body.value.clone(),
        backend_ids: body.backend_ids.clone(),
    })
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
        stale_while_revalidate_s: body.stale_while_revalidate_s.unwrap_or(10),
        stale_if_error_s: body.stale_if_error_s.unwrap_or(60),
        retry_on_methods: body.retry_on_methods.clone().unwrap_or_default(),
        maintenance_mode: body.maintenance_mode.unwrap_or(false),
        error_page_html: body.error_page_html.clone(),
        cache_vary_headers: body.cache_vary_headers.clone().unwrap_or_default(),
        header_rules: body
            .header_rules
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(build_header_rule)
            .collect::<Result<Vec<_>, _>>()?,
        traffic_splits: {
            let splits = body
                .traffic_splits
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .map(build_traffic_split)
                .collect::<Result<Vec<_>, _>>()?;
            validate_traffic_splits(&splits)?;
            splits
        },
        forward_auth: match body.forward_auth.as_ref() {
            Some(fa) if !fa.address.trim().is_empty() => Some(build_forward_auth(fa)?),
            _ => None,
        },
        mirror: match body.mirror.as_ref() {
            Some(m) if !m.backend_ids.is_empty() => Some(build_mirror_config(m)?),
            _ => None,
        },
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
    if let Some(swr) = body.stale_while_revalidate_s {
        route.stale_while_revalidate_s = swr;
    }
    if let Some(sie) = body.stale_if_error_s {
        route.stale_if_error_s = sie;
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
    if let Some(ref headers) = body.cache_vary_headers {
        // Normalise on write: trim whitespace, drop empties. Downstream
        // variance logic lowercases on the hot path so no need to do it
        // here - keeps the dashboard showing exactly what the operator typed.
        route.cache_vary_headers = headers
            .iter()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .collect();
    }
    if let Some(ref rules) = body.header_rules {
        route.header_rules = rules
            .iter()
            .map(build_header_rule)
            .collect::<Result<Vec<_>, _>>()?;
    }
    if let Some(ref splits) = body.traffic_splits {
        let built = splits
            .iter()
            .map(build_traffic_split)
            .collect::<Result<Vec<_>, _>>()?;
        validate_traffic_splits(&built)?;
        route.traffic_splits = built;
    }
    if let Some(ref fa) = body.forward_auth {
        // Empty address = explicit "disable" signal from the dashboard.
        // Non-empty address = validate + install/replace.
        if fa.address.trim().is_empty() {
            route.forward_auth = None;
        } else {
            route.forward_auth = Some(build_forward_auth(fa)?);
        }
    }
    if let Some(ref m) = body.mirror {
        if m.backend_ids.is_empty() {
            route.mirror = None;
        } else {
            route.mirror = Some(build_mirror_config(m)?);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn split(name: &str, w: u8, ids: &[&str]) -> TrafficSplitRequest {
        TrafficSplitRequest {
            name: name.into(),
            weight_percent: w,
            backend_ids: ids.iter().map(|s| (*s).into()).collect(),
        }
    }

    #[test]
    fn build_traffic_split_rejects_weight_over_100() {
        let req = split("bad", 150, &["b"]);
        let err = build_traffic_split(&req).err().expect("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must be 0..=100")));
    }

    #[test]
    fn build_traffic_split_rejects_non_zero_weight_without_backends() {
        // Split that would consume a weight band but divert to nothing -
        // operator typo; surface as 400 instead of silently swallowing
        // traffic on reload.
        let req = split("typo", 5, &[]);
        let err = build_traffic_split(&req).err().expect("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("at least one backend")));
    }

    #[test]
    fn build_traffic_split_accepts_zero_weight_with_no_backends() {
        // Zero-weight entry is a valid "prepared but disabled" state,
        // used while staging a rollout.
        let req = split("", 0, &[]);
        assert!(build_traffic_split(&req).is_ok());
    }

    #[test]
    fn build_traffic_split_trims_name() {
        let req = split("  v2  ", 5, &["b"]);
        let built = build_traffic_split(&req).unwrap();
        assert_eq!(built.name, "v2");
    }

    #[test]
    fn validate_traffic_splits_rejects_cumulative_over_100() {
        let splits = vec![
            build_traffic_split(&split("a", 60, &["x"])).unwrap(),
            build_traffic_split(&split("b", 50, &["y"])).unwrap(),
        ];
        let err = validate_traffic_splits(&splits).err().expect("should reject");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("<= 100")));
    }

    #[test]
    fn validate_traffic_splits_accepts_cumulative_exactly_100() {
        let splits = vec![
            build_traffic_split(&split("a", 40, &["x"])).unwrap(),
            build_traffic_split(&split("b", 60, &["y"])).unwrap(),
        ];
        assert!(validate_traffic_splits(&splits).is_ok());
    }

    #[test]
    fn validate_traffic_splits_empty_is_ok() {
        assert!(validate_traffic_splits(&[]).is_ok());
    }

    // ---- Forward auth validation ----

    fn fa_req(address: &str, timeout_ms: u32, response_headers: Vec<&str>) -> ForwardAuthConfigRequest {
        ForwardAuthConfigRequest {
            address: address.into(),
            timeout_ms,
            response_headers: response_headers.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn build_forward_auth_accepts_http_url() {
        let built = build_forward_auth(&fa_req(
            "http://authelia.internal/api/verify",
            2_000,
            vec!["Remote-User"],
        ))
        .unwrap();
        assert_eq!(built.address, "http://authelia.internal/api/verify");
        assert_eq!(built.timeout_ms, 2_000);
        assert_eq!(built.response_headers, vec!["Remote-User".to_string()]);
    }

    #[test]
    fn build_forward_auth_accepts_https_url() {
        assert!(build_forward_auth(&fa_req(
            "https://auth.example.com/v1/verify",
            500,
            vec![],
        ))
        .is_ok());
    }

    #[test]
    fn build_forward_auth_rejects_empty_address() {
        let err = build_forward_auth(&fa_req("", 1000, vec![])).err().unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn build_forward_auth_rejects_non_absolute_url() {
        let err = build_forward_auth(&fa_req("/verify", 1000, vec![])).err().unwrap();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn build_forward_auth_rejects_non_http_scheme() {
        let err = build_forward_auth(&fa_req("ftp://x.example.com/", 1000, vec![]))
            .err()
            .unwrap();
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("http") || m.contains("https"))
        );
    }

    #[test]
    fn build_forward_auth_rejects_zero_timeout() {
        let err = build_forward_auth(&fa_req("http://a/", 0, vec![])).err().unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("> 0")));
    }

    #[test]
    fn build_forward_auth_rejects_over_one_minute_timeout() {
        let err = build_forward_auth(&fa_req("http://a/", 60_001, vec![]))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("60000")));
    }

    #[test]
    fn build_forward_auth_rejects_blank_response_header_entry() {
        let err = build_forward_auth(&fa_req("http://a/", 1000, vec!["Remote-User", "   "]))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("non-empty")));
    }

    #[test]
    fn build_forward_auth_trims_response_header_names() {
        let built = build_forward_auth(&fa_req(
            "http://a/",
            1000,
            vec![" Remote-User ", "Remote-Groups"],
        ))
        .unwrap();
        assert_eq!(
            built.response_headers,
            vec!["Remote-User".to_string(), "Remote-Groups".to_string()]
        );
    }

    // ---- Mirror validation ----

    fn mirror_req(backends: Vec<&str>, pct: u8, timeout: u32) -> MirrorConfigRequest {
        MirrorConfigRequest {
            backend_ids: backends.into_iter().map(String::from).collect(),
            sample_percent: pct,
            timeout_ms: timeout,
            max_body_bytes: 1_048_576,
        }
    }

    #[test]
    fn build_mirror_accepts_valid() {
        let built = build_mirror_config(&mirror_req(vec!["b1", "b2"], 25, 3000)).unwrap();
        assert_eq!(built.backend_ids, vec!["b1".to_string(), "b2".to_string()]);
        assert_eq!(built.sample_percent, 25);
        assert_eq!(built.timeout_ms, 3000);
    }

    #[test]
    fn build_mirror_rejects_empty_backend_list() {
        let err = build_mirror_config(&mirror_req(vec![], 100, 5000))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn build_mirror_rejects_sample_over_100() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 101, 5000))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("0..=100")));
    }

    #[test]
    fn build_mirror_rejects_zero_timeout() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 50, 0))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("> 0")));
    }

    #[test]
    fn build_mirror_rejects_over_60s_timeout() {
        let err = build_mirror_config(&mirror_req(vec!["b"], 50, 60_001))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("60000")));
    }

    #[test]
    fn build_mirror_rejects_blank_backend_id() {
        let err = build_mirror_config(&mirror_req(vec!["   "], 50, 5000))
            .err()
            .unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("non-empty")));
    }

    #[test]
    fn build_mirror_dedups_backend_ids() {
        // Duplicate backend IDs would spawn two sub-requests to the same
        // shadow per primary request, which is wasteful and skews any
        // load/error metrics the operator is watching on the shadow.
        let built = build_mirror_config(&mirror_req(vec!["b1", "b2", "b1"], 50, 5000)).unwrap();
        assert_eq!(built.backend_ids, vec!["b1".to_string(), "b2".to_string()]);
    }

    #[test]
    fn build_mirror_trims_backend_ids() {
        let built = build_mirror_config(&mirror_req(vec!["  b1  "], 50, 5000)).unwrap();
        assert_eq!(built.backend_ids, vec!["b1".to_string()]);
    }

    #[test]
    fn build_mirror_rejects_excessive_max_body_bytes() {
        // Cap is 128 MiB. Operator writing 512 MB would blow memory
        // under the 256 concurrent-mirror cap.
        let mut req = mirror_req(vec!["b"], 50, 5000);
        req.max_body_bytes = 256 * 1_048_576;
        let err = build_mirror_config(&req).err().unwrap();
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("128 MiB")));
    }

    #[test]
    fn build_mirror_accepts_zero_max_body_bytes_as_headers_only() {
        // 0 = opt into headers-only mirroring (the old v1 behaviour).
        // Explicitly allowed, not an error.
        let mut req = mirror_req(vec!["b"], 50, 5000);
        req.max_body_bytes = 0;
        let built = build_mirror_config(&req).unwrap();
        assert_eq!(built.max_body_bytes, 0);
    }

    #[test]
    fn build_forward_auth_trims_address() {
        let built = build_forward_auth(&fa_req("  http://a/verify  ", 1000, vec![]))
            .unwrap();
        assert_eq!(built.address, "http://a/verify");
    }
}
