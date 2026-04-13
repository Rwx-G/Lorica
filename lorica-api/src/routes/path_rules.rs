//! Per-path rule types and validator.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Per-path rule view returned alongside a route (path match plus per-path overrides).
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

/// JSON body for a single path rule on a route create or update.
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

/// Validate a list of `PathRuleRequest`s and convert to the stored
/// `PathRule` model. Rejects paths that don't start with `/` and
/// unknown match-type strings.
pub(super) fn build_path_rules(
    prs: &[PathRuleRequest],
) -> Result<Vec<lorica_config::models::PathRule>, ApiError> {
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
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
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
    Ok(rules)
}
