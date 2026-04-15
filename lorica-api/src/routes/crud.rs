//! Route CRUD HTTP handlers: list/get/create/update/delete.
//!
//! Request/response wrapper types and the `route_to_response` view
//! builder live here too; per-feature validation helpers are delegated
//! to sibling modules (`header_rules`, `traffic_splits`,
//! `forward_auth`, `mirror`, `response_rewrite`, `mtls`, `path_rules`).

use std::collections::HashMap;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

use super::forward_auth::{build_forward_auth, ForwardAuthConfigRequest};
use super::header_rules::{build_header_rule, HeaderRuleRequest};
use super::mirror::{build_mirror_config, MirrorConfigRequest};
use super::mtls::{build_mtls_config, MtlsConfigRequest};
use super::path_rules::{build_path_rules, PathRuleRequest, PathRuleResponse};
use super::response_rewrite::{
    build_response_rewrite, ResponseRewriteConfigRequest, ResponseRewriteRuleRequest,
};
use super::traffic_splits::{build_traffic_split, validate_traffic_splits, TrafficSplitRequest};

/// Upper bound for `capacity` and `refill_per_sec`. Chosen to be large
/// enough for any realistic proxy workload while still rejecting
/// accidental values (e.g. u32::MAX) that would overflow downstream
/// arithmetic in the token-bucket refill path.
const RATE_LIMIT_MAX: u32 = 1_000_000;

/// Validate a per-route `GeoIpConfig` for API acceptance. Country
/// codes must be ISO 3166-1 alpha-2 (two ASCII letters, normalised to
/// upper). Duplicates are collapsed. Allowlist mode rejects empty
/// lists so an operator cannot accidentally block everything by
/// leaving the country list blank after switching modes.
fn validate_geoip(
    cfg: &lorica_config::models::GeoIpConfig,
) -> Result<lorica_config::models::GeoIpConfig, ApiError> {
    use lorica_config::models::GeoIpMode;

    let mut normalised: Vec<String> = Vec::with_capacity(cfg.countries.len());
    for raw in &cfg.countries {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() != 2 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(ApiError::BadRequest(format!(
                "geoip.countries: '{trimmed}' is not a valid ISO 3166-1 alpha-2 code"
            )));
        }
        let upper = trimmed.to_ascii_uppercase();
        if !normalised.contains(&upper) {
            normalised.push(upper);
        }
    }

    if cfg.mode == GeoIpMode::Allowlist && normalised.is_empty() {
        return Err(ApiError::BadRequest(
            "geoip.countries: allowlist mode with empty country list would block every request. \
             Use denylist mode or add at least one country"
                .into(),
        ));
    }

    // Upper bound on the country list so an operator cannot paste a
    // huge blob. 300 covers every ISO code twice over.
    const MAX_COUNTRIES: usize = 300;
    if normalised.len() > MAX_COUNTRIES {
        return Err(ApiError::BadRequest(format!(
            "geoip.countries: at most {MAX_COUNTRIES} entries allowed"
        )));
    }

    Ok(lorica_config::models::GeoIpConfig {
        mode: cfg.mode,
        countries: normalised,
    })
}

/// Validate a `RateLimit` config for API acceptance. Returns the
/// config unchanged on success, `ApiError::BadRequest` with a clear
/// message on validation failure.
fn validate_rate_limit(
    rl: &lorica_config::models::RateLimit,
) -> Result<lorica_config::models::RateLimit, ApiError> {
    if rl.capacity == 0 {
        return Err(ApiError::BadRequest(
            "rate_limit.capacity must be > 0 (use `rate_limit: null` or omit to disable)".into(),
        ));
    }
    if rl.capacity > RATE_LIMIT_MAX {
        return Err(ApiError::BadRequest(format!(
            "rate_limit.capacity must be <= {RATE_LIMIT_MAX}"
        )));
    }
    if rl.refill_per_sec > RATE_LIMIT_MAX {
        return Err(ApiError::BadRequest(format!(
            "rate_limit.refill_per_sec must be <= {RATE_LIMIT_MAX}"
        )));
    }
    Ok(rl.clone())
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use lorica_config::models::{RateLimit, RateLimitScope};

    fn rl(capacity: u32, refill_per_sec: u32) -> RateLimit {
        RateLimit {
            capacity,
            refill_per_sec,
            scope: RateLimitScope::PerIp,
        }
    }

    #[test]
    fn accepts_minimal_valid_config() {
        let out = validate_rate_limit(&rl(1, 0)).expect("capacity=1 refill=0 should pass");
        assert_eq!(out.capacity, 1);
        assert_eq!(out.refill_per_sec, 0);
    }

    #[test]
    fn accepts_at_cap() {
        assert!(validate_rate_limit(&rl(RATE_LIMIT_MAX, RATE_LIMIT_MAX)).is_ok());
    }

    #[test]
    fn rejects_zero_capacity() {
        match validate_rate_limit(&rl(0, 10)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("capacity"), "msg={msg}");
                assert!(msg.contains("> 0"), "msg should mention > 0: {msg}");
            }
            other => panic!("expected BadRequest on capacity=0, got {other:?}"),
        }
    }

    #[test]
    fn rejects_capacity_above_cap() {
        match validate_rate_limit(&rl(RATE_LIMIT_MAX + 1, 0)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("capacity"));
                assert!(msg.contains(&RATE_LIMIT_MAX.to_string()));
            }
            other => panic!("expected BadRequest on capacity overflow, got {other:?}"),
        }
    }

    #[test]
    fn rejects_refill_above_cap() {
        match validate_rate_limit(&rl(1, RATE_LIMIT_MAX + 1)) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("refill_per_sec"));
                assert!(msg.contains(&RATE_LIMIT_MAX.to_string()));
            }
            other => panic!("expected BadRequest on refill overflow, got {other:?}"),
        }
    }

    #[test]
    fn preserves_scope_across_validation() {
        let input = RateLimit {
            capacity: 42,
            refill_per_sec: 7,
            scope: RateLimitScope::PerRoute,
        };
        let out = validate_rate_limit(&input).unwrap();
        assert_eq!(out.scope, RateLimitScope::PerRoute);
    }

    #[test]
    fn does_not_mutate_input_on_success() {
        let input = rl(50, 5);
        let out = validate_rate_limit(&input).unwrap();
        // out is a clone, input untouched (the function takes &RateLimit).
        assert_eq!(input.capacity, 50);
        assert_eq!(out.capacity, 50);
    }
}

#[cfg(test)]
mod geoip_validation_tests {
    use super::*;
    use lorica_config::models::{GeoIpConfig, GeoIpMode};

    fn cfg(mode: GeoIpMode, countries: &[&str]) -> GeoIpConfig {
        GeoIpConfig {
            mode,
            countries: countries.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn normalises_country_case() {
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &["us", "Fr", "DE"])).unwrap();
        assert_eq!(out.countries, vec!["US", "FR", "DE"]);
    }

    #[test]
    fn trims_and_dedupes() {
        // Whitespace padding + duplicate after case-folding.
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &[" us ", "US", "fr"])).unwrap();
        assert_eq!(out.countries, vec!["US", "FR"]);
    }

    #[test]
    fn skips_empty_entries() {
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &["", "US", "   "])).unwrap();
        assert_eq!(out.countries, vec!["US"]);
    }

    #[test]
    fn rejects_non_alpha2() {
        match validate_geoip(&cfg(GeoIpMode::Denylist, &["USA"])) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("USA"), "msg={msg}");
                assert!(msg.contains("alpha-2"), "msg={msg}");
            }
            other => panic!("expected BadRequest on 3-letter code, got {other:?}"),
        }
    }

    #[test]
    fn rejects_digits() {
        assert!(matches!(
            validate_geoip(&cfg(GeoIpMode::Denylist, &["U1"])),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn rejects_allowlist_with_empty_list() {
        // Allowlist with no countries = block everyone; must be rejected
        // so the operator sees the mistake at API time instead of at
        // traffic time.
        match validate_geoip(&cfg(GeoIpMode::Allowlist, &[])) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("allowlist"), "msg={msg}");
                assert!(msg.contains("empty"), "msg={msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn accepts_denylist_with_empty_list() {
        // Denylist + empty = "block nobody", legal no-op (equivalent
        // to `geoip: null`, useful when keeping the row around for
        // quick re-enable).
        let out = validate_geoip(&cfg(GeoIpMode::Denylist, &[])).unwrap();
        assert_eq!(out.mode, GeoIpMode::Denylist);
        assert!(out.countries.is_empty());
    }

    #[test]
    fn rejects_oversize_list() {
        // 301 distinct ASCII alpha-2 combos would exceed MAX_COUNTRIES.
        // We cheat by generating synthetic duplicates - dedup kicks
        // first though, so pad with distinct codes.
        let mut long: Vec<String> = Vec::with_capacity(301);
        for a in b'A'..=b'Z' {
            for b in b'A'..=b'Z' {
                if long.len() >= 301 {
                    break;
                }
                long.push(format!("{}{}", a as char, b as char));
            }
        }
        assert!(long.len() > 300);
        let cfg = GeoIpConfig {
            mode: GeoIpMode::Denylist,
            countries: long,
        };
        match validate_geoip(&cfg) {
            Err(ApiError::BadRequest(msg)) => {
                assert!(msg.contains("at most 300"), "msg={msg}");
            }
            other => panic!("expected BadRequest on oversize list, got {other:?}"),
        }
    }
}

/// Full JSON view of a route returned by list / get / create / update endpoints.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls: Option<MtlsConfigRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
    pub created_at: String,
    pub updated_at: String,
}

/// JSON body for `POST /api/v1/routes`. Most fields are optional and fall back to defaults.
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
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    pub mtls: Option<MtlsConfigRequest>,
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
}

/// JSON body for `PUT /api/v1/routes/:id`. Only supplied fields are mutated.
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
    /// Update semantics: missing = leave alone; present with empty
    /// `rules` = clear; non-empty = validate + install/replace.
    pub response_rewrite: Option<ResponseRewriteConfigRequest>,
    /// Update semantics: missing = leave alone; present with empty
    /// `ca_cert_pem` = clear; non-empty = validate + install/replace.
    pub mtls: Option<MtlsConfigRequest>,
    /// Update semantics: missing = leave alone; present with
    /// `capacity = 0` = clear; present with `capacity > 0` =
    /// validate + install/replace.
    pub rate_limit: Option<lorica_config::models::RateLimit>,
    /// Update semantics: missing = leave alone; present with empty
    /// `countries` list = clear; present with non-empty = validate
    /// (ISO 3166-1 alpha-2 codes only) + install / replace. When
    /// `mode = Allowlist` an empty list is rejected at validation
    /// time so the operator cannot accidentally block everything.
    pub geoip: Option<lorica_config::models::GeoIpConfig>,
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
            .map(|hr| {
                // Recompute disabled state at read time by attempting
                // to compile the regex. The write-path validator
                // already rejects bad regex, so in normal operation
                // this is always `false`. The flag exists for out-of-
                // band edits (raw DB writes, TOML import of a stale
                // export, regex-crate version drift on upgrade) so
                // the dashboard can show a red badge and the operator
                // can republish the rule.
                let disabled =
                    matches!(hr.match_type, lorica_config::models::HeaderMatchType::Regex)
                        && regex::Regex::new(&hr.value).is_err();
                HeaderRuleRequest {
                    header_name: hr.header_name.clone(),
                    match_type: Some(hr.match_type.as_str().to_string()),
                    value: hr.value.clone(),
                    backend_ids: hr.backend_ids.clone(),
                    disabled,
                }
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
                verdict_cache_ttl_ms: fa.verdict_cache_ttl_ms,
            }),
        mirror: route.mirror.as_ref().map(|m| MirrorConfigRequest {
            backend_ids: m.backend_ids.clone(),
            sample_percent: m.sample_percent,
            timeout_ms: m.timeout_ms,
            max_body_bytes: m.max_body_bytes,
        }),
        response_rewrite: route
            .response_rewrite
            .as_ref()
            .map(|rr| ResponseRewriteConfigRequest {
                rules: rr
                    .rules
                    .iter()
                    .map(|r| ResponseRewriteRuleRequest {
                        pattern: r.pattern.clone(),
                        replacement: r.replacement.clone(),
                        is_regex: r.is_regex,
                        max_replacements: r.max_replacements,
                    })
                    .collect(),
                max_body_bytes: rr.max_body_bytes,
                content_type_prefixes: rr.content_type_prefixes.clone(),
            }),
        mtls: route.mtls.as_ref().map(|m| MtlsConfigRequest {
            ca_cert_pem: m.ca_cert_pem.clone(),
            required: m.required,
            allowed_organizations: m.allowed_organizations.clone(),
        }),
        rate_limit: route.rate_limit.clone(),
        geoip: route.geoip.clone(),
        created_at: route.created_at.to_rfc3339(),
        updated_at: route.updated_at.to_rfc3339(),
    }
}

/// GET /api/v1/routes - list every configured route with its linked backend ids.
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

/// POST /api/v1/routes - create a new route.
///
/// Validates type-shape (enum parsing, regex compilability); business
/// rules (hostname uniqueness) are enforced by the store layer.
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
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let waf_mode = body
        .waf_mode
        .as_deref()
        .unwrap_or("detection")
        .parse::<lorica_config::models::WafMode>()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let path_rules = if let Some(ref prs) = body.path_rules {
        build_path_rules(prs)?
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
        response_rewrite: match body.response_rewrite.as_ref() {
            Some(rr) if !rr.rules.is_empty() => Some(build_response_rewrite(rr)?),
            _ => None,
        },
        mtls: match body.mtls.as_ref() {
            Some(m) if !m.ca_cert_pem.trim().is_empty() => Some(build_mtls_config(m)?),
            _ => None,
        },
        rate_limit: match body.rate_limit.as_ref() {
            Some(rl) => Some(validate_rate_limit(rl)?),
            None => None,
        },
        geoip: match body.geoip.as_ref() {
            // Empty country list in denylist mode is legal (means "no
            // countries blocked"), but allowlist with empty list is
            // rejected by `validate_geoip`.
            Some(g) => Some(validate_geoip(g)?),
            None => None,
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

/// GET /api/v1/routes/:id - fetch a single route by id.
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

/// PUT /api/v1/routes/:id - patch route fields and trigger a proxy reload.
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
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(waf_enabled) = body.waf_enabled {
        route.waf_enabled = waf_enabled;
    }
    if let Some(waf_mode) = body.waf_mode {
        route.waf_mode = waf_mode
            .parse::<lorica_config::models::WafMode>()
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(enabled) = body.enabled {
        route.enabled = enabled;
    }
    if let Some(force_https) = body.force_https {
        route.force_https = force_https;
    }
    if let Some(redirect_hostname) = body.redirect_hostname {
        route.redirect_hostname = if redirect_hostname.is_empty() {
            None
        } else {
            Some(redirect_hostname)
        };
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
        route.strip_path_prefix = if strip_path_prefix.is_empty() {
            None
        } else {
            Some(strip_path_prefix)
        };
    }
    if let Some(add_path_prefix) = body.add_path_prefix {
        route.add_path_prefix = if add_path_prefix.is_empty() {
            None
        } else {
            Some(add_path_prefix)
        };
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
        route.max_request_body_bytes = if max_request_body_bytes == 0 {
            None
        } else {
            Some(max_request_body_bytes)
        };
    }
    if let Some(websocket_enabled) = body.websocket_enabled {
        route.websocket_enabled = websocket_enabled;
    }
    if let Some(rate_limit_rps) = body.rate_limit_rps {
        route.rate_limit_rps = if rate_limit_rps == 0 {
            None
        } else {
            Some(rate_limit_rps)
        };
    }
    if let Some(rate_limit_burst) = body.rate_limit_burst {
        route.rate_limit_burst = if rate_limit_burst == 0 {
            None
        } else {
            Some(rate_limit_burst)
        };
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
        route.cors_max_age_s = if cors_max_age_s == 0 {
            None
        } else {
            Some(cors_max_age_s)
        };
    }
    if let Some(compression_enabled) = body.compression_enabled {
        route.compression_enabled = compression_enabled;
    }
    if let Some(retry_attempts) = body.retry_attempts {
        route.retry_attempts = if retry_attempts == 0 {
            None
        } else {
            Some(retry_attempts)
        };
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
        route.max_connections = if max_connections == 0 {
            None
        } else {
            Some(max_connections)
        };
    }
    if let Some(slowloris_threshold_ms) = body.slowloris_threshold_ms {
        route.slowloris_threshold_ms = slowloris_threshold_ms;
    }
    if let Some(auto_ban_threshold) = body.auto_ban_threshold {
        route.auto_ban_threshold = if auto_ban_threshold == 0 {
            None
        } else {
            Some(auto_ban_threshold)
        };
    }
    if let Some(auto_ban_duration_s) = body.auto_ban_duration_s {
        route.auto_ban_duration_s = auto_ban_duration_s;
    }
    if let Some(ref prs) = body.path_rules {
        route.path_rules = build_path_rules(prs)?;
    }
    if let Some(return_status) = body.return_status {
        route.return_status = if return_status == 0 {
            None
        } else {
            Some(return_status)
        };
    }
    if let Some(sticky) = body.sticky_session {
        route.sticky_session = sticky;
    }
    if let Some(ref username) = body.basic_auth_username {
        route.basic_auth_username = if username.is_empty() {
            None
        } else {
            Some(username.clone())
        };
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
        route.error_page_html = if html.is_empty() {
            None
        } else {
            Some(html.clone())
        };
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
    if let Some(ref rr) = body.response_rewrite {
        if rr.rules.is_empty() {
            route.response_rewrite = None;
        } else {
            route.response_rewrite = Some(build_response_rewrite(rr)?);
        }
    }
    if let Some(ref m) = body.mtls {
        // Empty ca_cert_pem = explicit "disable" signal from dashboard.
        // Non-empty = validate + install/replace. Changes to the PEM
        // take effect on next restart (rustls ServerConfig is immutable
        // after build); required/allowed_organizations hot-reload.
        if m.ca_cert_pem.trim().is_empty() {
            route.mtls = None;
        } else {
            route.mtls = Some(build_mtls_config(m)?);
        }
    }
    if let Some(ref rl) = body.rate_limit {
        // capacity == 0 = explicit "disable" signal; any positive value
        // goes through validate_rate_limit and replaces the existing
        // config.
        if rl.capacity == 0 {
            route.rate_limit = None;
        } else {
            route.rate_limit = Some(validate_rate_limit(rl)?);
        }
    }
    if let Some(ref g) = body.geoip {
        // Empty country list in allowlist mode is rejected by
        // `validate_geoip`; empty list in denylist mode is legal and
        // means "filter disabled for this route". Empty list in
        // denylist mode also clears the `geoip` column on disk.
        use lorica_config::models::GeoIpMode;
        if g.mode == GeoIpMode::Denylist && g.countries.is_empty() {
            route.geoip = None;
        } else {
            route.geoip = Some(validate_geoip(g)?);
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

/// DELETE /api/v1/routes/:id - delete a route and notify the proxy.
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
