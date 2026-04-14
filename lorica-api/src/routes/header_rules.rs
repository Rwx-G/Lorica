//! Header-based routing rule types and validator.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// Header-based routing rule (matches a header value, picks a backend pool).
#[derive(Serialize, Deserialize)]
pub struct HeaderRuleRequest {
    pub header_name: String,
    #[serde(default)]
    pub match_type: Option<String>,
    pub value: String,
    #[serde(default)]
    pub backend_ids: Vec<String>,
    /// Response-only indicator. Set to `true` by `route_to_response`
    /// when the rule's regex fails to compile at read time (meaning
    /// the proxy also skips this rule at runtime). Never read from
    /// the body on write paths - `#[serde(default)]` makes it
    /// ignored on deserialization so an attacker / stale dashboard
    /// can't disable a rule by posting `disabled: true`.
    #[serde(default, skip_deserializing)]
    pub disabled: bool,
}

/// Parse and validate an incoming `HeaderRuleRequest`. Rejects empty header
/// names, empty Exact/Prefix values (would otherwise match every request),
/// and malformed regex patterns. Returns the fully-typed `HeaderRule` the
/// store can persist.
pub(super) fn build_header_rule(
    body: &HeaderRuleRequest,
) -> Result<lorica_config::models::HeaderRule, ApiError> {
    let header_name = body.header_name.trim();
    if header_name.is_empty() {
        return Err(ApiError::BadRequest(
            "header_rules: header_name must not be empty".into(),
        ));
    }
    let match_type: lorica_config::models::HeaderMatchType = body
        .match_type
        .as_deref()
        .unwrap_or("exact")
        .parse()
        .map_err(|e: strum::ParseError| ApiError::BadRequest(e.to_string()))?;
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
