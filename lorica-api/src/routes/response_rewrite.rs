//! Response body rewrite configuration types and validator.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// One literal-or-regex find/replace rule applied to response bodies.
#[derive(Serialize, Deserialize, Clone)]
pub struct ResponseRewriteRuleRequest {
    pub pattern: String,
    pub replacement: String,
    #[serde(default)]
    pub is_regex: bool,
    #[serde(default)]
    pub max_replacements: Option<u32>,
}

/// Response body rewrite configuration: ordered rules, body size cap, content-type filter.
#[derive(Serialize, Deserialize, Clone)]
pub struct ResponseRewriteConfigRequest {
    #[serde(default)]
    pub rules: Vec<ResponseRewriteRuleRequest>,
    #[serde(default = "default_rewrite_max_body_bytes")]
    pub max_body_bytes: u32,
    #[serde(default)]
    pub content_type_prefixes: Vec<String>,
}

fn default_rewrite_max_body_bytes() -> u32 {
    1_048_576
}

/// Validate a ResponseRewriteConfigRequest and convert to stored model.
/// Rejects operator mistakes that would brick the feature:
///   - an empty rules vec with a non-null config object (should have
///     sent null instead),
///   - rules with empty pattern,
///   - regex patterns that fail to compile,
///   - max_body_bytes over 128 MiB (buffering cap across requests
///     has a real memory cost),
///   - max_replacements zero (would no-op; operator probably meant to
///     leave it unset).
pub(super) fn build_response_rewrite(
    body: &ResponseRewriteConfigRequest,
) -> Result<lorica_config::models::ResponseRewriteConfig, ApiError> {
    if body.rules.is_empty() {
        return Err(ApiError::BadRequest(
            "response_rewrite.rules must not be empty (use null/missing to disable)".into(),
        ));
    }
    const REWRITE_MAX_BODY_CEILING: u32 = 128 * 1_048_576;
    if body.max_body_bytes == 0 {
        return Err(ApiError::BadRequest(
            "response_rewrite.max_body_bytes must be > 0".into(),
        ));
    }
    if body.max_body_bytes > REWRITE_MAX_BODY_CEILING {
        return Err(ApiError::BadRequest(format!(
            "response_rewrite.max_body_bytes must be <= {REWRITE_MAX_BODY_CEILING} ({} MiB)",
            REWRITE_MAX_BODY_CEILING / 1_048_576
        )));
    }
    const PATTERN_MAX_LEN: usize = 4096;
    const REPLACEMENT_MAX_LEN: usize = 4096;
    // `$N` capture-group references in the replacement - compiled
    // once outside the per-rule loop.
    static REF_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let ref_re = REF_RE.get_or_init(|| regex::Regex::new(r"\$(\d+)").expect("static regex"));
    let mut rules = Vec::with_capacity(body.rules.len());
    for (i, rule) in body.rules.iter().enumerate() {
        if rule.pattern.is_empty() {
            return Err(ApiError::BadRequest(format!(
                "response_rewrite.rules[{i}]: pattern must not be empty"
            )));
        }
        if rule.pattern.len() > PATTERN_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "response_rewrite.rules[{i}]: pattern must be <= {PATTERN_MAX_LEN} characters"
            )));
        }
        if rule.replacement.len() > REPLACEMENT_MAX_LEN {
            return Err(ApiError::BadRequest(format!(
                "response_rewrite.rules[{i}]: replacement must be <= {REPLACEMENT_MAX_LEN} characters"
            )));
        }
        if rule.is_regex {
            // Pre-compile: catches "(unclosed" before a reload.
            let compiled = regex::Regex::new(&rule.pattern).map_err(|e| {
                ApiError::BadRequest(format!("response_rewrite.rules[{i}]: invalid regex: {e}"))
            })?;
            // Guard against replacements that reference capture groups
            // not present in the pattern (e.g. `$1` against `/foo` would
            // emit literal `$1` into the response stream and the
            // operator only notices once a user hits the page).
            let max_ref = compiled.captures_len().saturating_sub(1);
            let scan = rule.replacement.replace("$$", "");
            for cap in ref_re.captures_iter(&scan) {
                let n: usize = cap[1].parse().unwrap_or(0);
                if n > max_ref {
                    return Err(ApiError::BadRequest(format!(
                        "response_rewrite.rules[{i}]: replacement references `${n}` \
                         but the pattern has only {max_ref} capture group{s}",
                        s = if max_ref == 1 { "" } else { "s" }
                    )));
                }
            }
        }
        if let Some(n) = rule.max_replacements {
            if n == 0 {
                return Err(ApiError::BadRequest(format!(
                    "response_rewrite.rules[{i}]: max_replacements must be > 0 (or null for unlimited)"
                )));
            }
        }
        rules.push(lorica_config::models::ResponseRewriteRule {
            pattern: rule.pattern.clone(),
            replacement: rule.replacement.clone(),
            is_regex: rule.is_regex,
            max_replacements: rule.max_replacements,
        });
    }
    // Trim content-type prefixes; drop empties.
    let prefixes: Vec<String> = body
        .content_type_prefixes
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    Ok(lorica_config::models::ResponseRewriteConfig {
        rules,
        max_body_bytes: body.max_body_bytes,
        content_type_prefixes: prefixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rr_rule(pattern: &str, replacement: &str, is_regex: bool) -> ResponseRewriteRuleRequest {
        ResponseRewriteRuleRequest {
            pattern: pattern.into(),
            replacement: replacement.into(),
            is_regex,
            max_replacements: None,
        }
    }

    fn rr_cfg(rules: Vec<ResponseRewriteRuleRequest>) -> ResponseRewriteConfigRequest {
        ResponseRewriteConfigRequest {
            rules,
            max_body_bytes: 1_048_576,
            content_type_prefixes: vec![],
        }
    }

    #[test]
    fn build_response_rewrite_accepts_valid_config() {
        let cfg = rr_cfg(vec![
            rr_rule("internal", "public", false),
            rr_rule(r"\d+", "***", true),
        ]);
        let built = build_response_rewrite(&cfg).expect("test setup");
        assert_eq!(built.rules.len(), 2);
    }

    #[test]
    fn build_response_rewrite_rejects_empty_rules() {
        let cfg = rr_cfg(vec![]);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("must not be empty")));
    }

    #[test]
    fn build_response_rewrite_rejects_zero_max_body_bytes() {
        let mut cfg = rr_cfg(vec![rr_rule("a", "b", false)]);
        cfg.max_body_bytes = 0;
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("> 0")));
    }

    #[test]
    fn build_response_rewrite_rejects_excessive_max_body_bytes() {
        let mut cfg = rr_cfg(vec![rr_rule("a", "b", false)]);
        cfg.max_body_bytes = 200 * 1_048_576;
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("128 MiB")));
    }

    #[test]
    fn build_response_rewrite_rejects_empty_pattern() {
        let cfg = rr_cfg(vec![rr_rule("", "x", false)]);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("pattern must not be empty"))
        );
    }

    #[test]
    fn build_response_rewrite_rejects_invalid_regex_at_write_time() {
        // Operator shouldn't have to wait until reload + first request
        // to find out their regex is broken. Fail fast.
        let cfg = rr_cfg(vec![rr_rule("(unclosed", "x", true)]);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("invalid regex")));
    }

    #[test]
    fn build_response_rewrite_rejects_zero_max_replacements() {
        // 0 would be a no-op rule. Probably operator meant unlimited.
        let mut cfg = rr_cfg(vec![rr_rule("a", "b", false)]);
        cfg.rules[0].max_replacements = Some(0);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("max_replacements")));
    }

    #[test]
    fn build_response_rewrite_rejects_pattern_too_long() {
        let long = "a".repeat(8192);
        let cfg = rr_cfg(vec![rr_rule(&long, "x", false)]);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(matches!(err, ApiError::BadRequest(ref m) if m.contains("4096")));
    }

    #[test]
    fn build_response_rewrite_rejects_out_of_range_capture_reference() {
        // Pattern has no capture groups; `$1` in the replacement would
        // render as literal `$1` at runtime - almost certainly not what
        // the operator wanted.
        let cfg = rr_cfg(vec![rr_rule(r"\d+", "value: $1", true)]);
        let err = build_response_rewrite(&cfg).expect_err("test setup");
        assert!(
            matches!(err, ApiError::BadRequest(ref m) if m.contains("`$1`") && m.contains("only 0"))
        );
    }

    #[test]
    fn build_response_rewrite_accepts_dollar_dollar_escape() {
        // `$$5` in the replacement is a literal `$5`, not a capture
        // reference. The validator must not flag it.
        let cfg = rr_cfg(vec![rr_rule(r"\d+", "price: $$5", true)]);
        assert!(build_response_rewrite(&cfg).is_ok());
    }

    #[test]
    fn build_response_rewrite_accepts_in_range_capture_reference() {
        let cfg = rr_cfg(vec![rr_rule(r"(\d+) apples", "$1 oranges", true)]);
        assert!(build_response_rewrite(&cfg).is_ok());
    }

    #[test]
    fn build_response_rewrite_trims_and_drops_blank_content_types() {
        let mut cfg = rr_cfg(vec![rr_rule("a", "b", false)]);
        cfg.content_type_prefixes =
            vec!["  text/  ".into(), "   ".into(), "application/json".into()];
        let built = build_response_rewrite(&cfg).expect("test setup");
        assert_eq!(
            built.content_type_prefixes,
            vec!["text/".to_string(), "application/json".to_string()]
        );
    }
}
