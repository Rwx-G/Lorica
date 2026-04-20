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
    for (i, pr) in prs.iter().enumerate() {
        if !pr.path.starts_with('/') {
            return Err(ApiError::BadRequest(format!(
                "path_rules[{i}].path must start with '/': {}",
                pr.path
            )));
        }
        if pr.path.len() > 1024 {
            return Err(ApiError::BadRequest(format!(
                "path_rules[{i}].path must be <= 1024 characters"
            )));
        }
        if pr.path.chars().any(|c| c.is_whitespace()) {
            return Err(ApiError::BadRequest(format!(
                "path_rules[{i}].path must not contain whitespace"
            )));
        }
        let match_type = pr
            .match_type
            .as_deref()
            .unwrap_or("prefix")
            .parse::<lorica_config::models::PathMatchType>()
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let redirect_to = match pr.redirect_to.as_deref() {
            Some(r) => {
                let v =
                    super::crud::validate_redirect_to(r, &format!("path_rules[{i}].redirect_to"))?;
                if v.is_empty() {
                    None
                } else {
                    Some(v)
                }
            }
            None => None,
        };
        if let Some(ref h) = pr.response_headers {
            super::crud::validate_http_headers_map(
                h,
                &format!("path_rules[{i}].response_headers"),
            )?;
        }
        if let Some(ref h) = pr.response_headers_remove {
            super::crud::validate_http_header_name_list(
                h,
                &format!("path_rules[{i}].response_headers_remove"),
            )?;
        }
        if let Some(status) = pr.return_status {
            if !(100..=599).contains(&status) {
                return Err(ApiError::BadRequest(format!(
                    "path_rules[{i}].return_status must be in 100..=599"
                )));
            }
        }
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
            redirect_to,
            return_status: pr.return_status,
        });
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pr(path: &str) -> PathRuleRequest {
        PathRuleRequest {
            path: path.into(),
            match_type: None,
            backend_ids: None,
            cache_enabled: None,
            cache_ttl_s: None,
            response_headers: None,
            response_headers_remove: None,
            rate_limit_rps: None,
            rate_limit_burst: None,
            redirect_to: None,
            return_status: None,
        }
    }

    #[test]
    fn rejects_path_without_leading_slash() {
        let err = build_path_rules(&[pr("api/v2")]).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must start with '/'")));
    }

    #[test]
    fn rejects_path_with_whitespace() {
        let err = build_path_rules(&[pr("/foo bar")]).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("whitespace")));
    }

    #[test]
    fn rejects_path_too_long() {
        let long = format!("/{}", "a".repeat(1100));
        let err = build_path_rules(&[pr(&long)]).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("1024")));
    }

    #[test]
    fn rejects_malformed_redirect_to() {
        let mut rule = pr("/tesla");
        rule.redirect_to = Some("example.com".into());
        let err = build_path_rules(&[rule]).expect_err("test setup");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("path_rules[0].redirect_to") && m.contains("http"))
        );
    }

    #[test]
    fn accepts_valid_redirect_to() {
        let mut rule = pr("/tesla");
        rule.redirect_to = Some("https://www.youtube.com/redirect?q=https://plex/".into());
        let rules = build_path_rules(&[rule]).unwrap();
        assert_eq!(
            rules[0].redirect_to.as_deref(),
            Some("https://www.youtube.com/redirect?q=https://plex/")
        );
    }

    #[test]
    fn rejects_return_status_out_of_range() {
        let mut rule = pr("/x");
        rule.return_status = Some(42);
        let err = build_path_rules(&[rule]).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("100..=599")));

        let mut rule = pr("/x");
        rule.return_status = Some(999);
        let err = build_path_rules(&[rule]).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("100..=599")));
    }

    #[test]
    fn accepts_standard_return_status() {
        let mut rule = pr("/x");
        rule.return_status = Some(418);
        assert!(build_path_rules(&[rule]).is_ok());
    }
}
