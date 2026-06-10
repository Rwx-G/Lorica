// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Custom AI / LLM crawler CRUD HTTP handlers (Story 8.2 AC #6 + #7).
//!
//! Endpoints :
//! - `GET    /api/v1/ai-crawlers/custom`     - list custom entries
//! - `POST   /api/v1/ai-crawlers/custom`     - create one
//! - `PUT    /api/v1/ai-crawlers/custom/:id` - update one
//! - `DELETE /api/v1/ai-crawlers/custom/:id` - delete one
//!
//! Server-side validation pipeline (per AC #6) :
//! - Regex compiles via `RegexBuilder` with `size_limit(1 << 20)` +
//!   `dfa_size_limit(1 << 21)` ; on `Err` return HTTP 400 with the
//!   regex error message.
//! - The regex is then matched against a hardcoded baseline UA
//!   corpus (Chrome / Firefox / Safari / Edge / Opera, curl, wget,
//!   and 7 search-bot UAs) ; if any baseline UA matches, reject with
//!   HTTP 400 ("Pattern would match legitimate browser/crawler UA
//!   <example>"). Closes the admin-`(?i).*` privilege escalation.
//! - For `IpRanges`, every CIDR string is parsed via
//!   `ipnet::IpNet::from_str` ; first invalid entry returns HTTP 400.
//!   The list MUST have `len <= CUSTOM_CRAWLER_MAX_CIDRS`.
//! - For `Rdns`, the `suffixes` array MUST be non-empty.
//! - The total custom-crawler row count MUST stay below
//!   `CUSTOM_CRAWLER_MAX_COUNT` on insert.

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use ipnet::IpNet;
use lorica_config::models::{
    CustomCrawler, CustomVerification, CUSTOM_CRAWLER_MAX_CIDRS, CUSTOM_CRAWLER_MAX_COUNT,
};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::error::{json_data, json_data_with_status, ApiError};
use crate::server::AppState;

/// 20-entry baseline corpus matched against custom regexes at
/// validation time (AC #6 baseline-UA smoke test). Fixture lives
/// here rather than re-importing from `lorica/src/ai_bot.rs` to
/// avoid a backwards dep ; the two corpuses MUST stay in sync.
const BASELINE_UAS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "curl/8.4.0",
    "Wget/1.21.4",
    "PostmanRuntime/7.36.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Twitterbot/1.0)",
    "Mozilla/5.0 (compatible; LinkedInBot/1.0; +http://www.linkedin.com)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
];

/// Body shape for POST / PUT.
#[derive(Debug, Deserialize)]
pub struct CustomCrawlerRequest {
    /// Unique label.
    pub name: String,
    /// Regex source.
    pub user_agent_pattern: String,
    /// Verification mechanism (Rdns / IpRanges / UaOnly).
    pub verification: CustomVerification,
    /// Per-row enabled flag (default true).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Response shape for GET single / list / POST / PUT.
#[derive(Debug, Serialize)]
pub struct CustomCrawlerResponse {
    /// DB-assigned row id.
    pub id: i64,
    /// Stable label.
    pub name: String,
    /// Regex source.
    pub user_agent_pattern: String,
    /// Verification mechanism.
    pub verification: CustomVerification,
    /// Enabled flag.
    pub enabled: bool,
    /// RFC 3339 first-insert timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
}

impl From<CustomCrawler> for CustomCrawlerResponse {
    fn from(c: CustomCrawler) -> Self {
        Self {
            id: c.id,
            name: c.name,
            user_agent_pattern: c.user_agent_pattern,
            verification: c.verification,
            enabled: c.enabled,
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}

/// `GET /api/v1/ai-crawlers/custom` - list every custom crawler row.
pub async fn list_custom_crawlers(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let crawlers = store.list_custom_crawlers()?;
    let entries: Vec<CustomCrawlerResponse> =
        crawlers.into_iter().map(CustomCrawlerResponse::from).collect();
    Ok(json_data(serde_json::json!({
        "entries": entries,
        "built_in_count": 16,
        "max_count": CUSTOM_CRAWLER_MAX_COUNT,
    })))
}

/// `POST /api/v1/ai-crawlers/custom` - create a new custom crawler.
/// Pipeline-validates the regex (compile + baseline-UA smoke), the
/// verification kind payload, and the count cap.
pub async fn create_custom_crawler(
    Extension(state): Extension<AppState>,
    Json(body): Json<CustomCrawlerRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    validate_request(&body)?;
    let store = state.store.lock().await;
    let now = Utc::now();
    let entry = CustomCrawler {
        id: 0,
        name: body.name,
        user_agent_pattern: body.user_agent_pattern,
        verification: body.verification,
        enabled: body.enabled,
        created_at: now,
        updated_at: now,
    };
    let id = store.create_custom_crawler(&entry)?;
    let saved = store
        .get_custom_crawler(id)?
        .ok_or_else(|| ApiError::Internal("post-insert read failed".into()))?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data_with_status(
        StatusCode::CREATED,
        CustomCrawlerResponse::from(saved),
    ))
}

/// `PUT /api/v1/ai-crawlers/custom/:id` - update an existing row.
pub async fn update_custom_crawler(
    Extension(state): Extension<AppState>,
    Path(id): Path<i64>,
    Json(body): Json<CustomCrawlerRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_request(&body)?;
    let store = state.store.lock().await;
    let mut existing = store
        .get_custom_crawler(id)?
        .ok_or_else(|| ApiError::NotFound(format!("ai_crawler_custom {id}")))?;
    existing.name = body.name;
    existing.user_agent_pattern = body.user_agent_pattern;
    existing.verification = body.verification;
    existing.enabled = body.enabled;
    existing.updated_at = Utc::now();
    store.update_custom_crawler(&existing)?;
    let saved = store
        .get_custom_crawler(id)?
        .ok_or_else(|| ApiError::Internal("post-update read failed".into()))?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(CustomCrawlerResponse::from(saved)))
}

/// `DELETE /api/v1/ai-crawlers/custom/:id` - remove a row.
pub async fn delete_custom_crawler(
    Extension(state): Extension<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    store.delete_custom_crawler(id)?;
    drop(store);
    state.notify_config_changed();
    Ok(json_data(serde_json::json!({ "deleted": id })))
}

fn validate_request(body: &CustomCrawlerRequest) -> Result<(), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if body.name.len() > 64 {
        return Err(ApiError::BadRequest("name must be <= 64 characters".into()));
    }
    let compiled = compile_pattern(&body.user_agent_pattern)?;
    check_baseline_uas(&compiled)?;
    validate_verification(&body.verification)?;
    Ok(())
}

fn compile_pattern(pattern: &str) -> Result<Regex, ApiError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 21)
        .build()
        .map_err(|e| {
            ApiError::BadRequest(format!(
                "invalid user_agent_pattern: {e} \
                 (size_limit=1MB, dfa_size_limit=2MB ; simplify the regex)"
            ))
        })
}

fn check_baseline_uas(re: &Regex) -> Result<(), ApiError> {
    for baseline in BASELINE_UAS {
        if re.is_match(baseline) {
            return Err(ApiError::BadRequest(format!(
                "pattern would match legitimate browser/crawler UA: \
                 {baseline:?} ; please narrow the regex"
            )));
        }
    }
    Ok(())
}

fn validate_verification(v: &CustomVerification) -> Result<(), ApiError> {
    match v {
        CustomVerification::UaOnly => Ok(()),
        CustomVerification::Rdns { suffixes } => {
            if suffixes.is_empty() {
                return Err(ApiError::BadRequest(
                    "verification.suffixes must be non-empty for kind=rdns".into(),
                ));
            }
            for s in suffixes {
                if !s.starts_with('.') {
                    return Err(ApiError::BadRequest(format!(
                        "verification.suffixes entry {s:?} must start with a leading dot \
                         (e.g. .example.com)"
                    )));
                }
            }
            Ok(())
        }
        CustomVerification::IpRanges { cidrs } => {
            if cidrs.len() > CUSTOM_CRAWLER_MAX_CIDRS {
                return Err(ApiError::BadRequest(format!(
                    "verification.cidrs has {} entries ; cap is {CUSTOM_CRAWLER_MAX_CIDRS} \
                     (split into multiple custom crawlers if you need more)",
                    cidrs.len()
                )));
            }
            for entry in cidrs {
                if entry.parse::<IpNet>().is_err() {
                    return Err(ApiError::BadRequest(format!(
                        "verification.cidrs entry {entry:?} is not a valid CIDR"
                    )));
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn re(pattern: &str) -> Regex {
        compile_pattern(pattern).unwrap()
    }

    #[test]
    fn baseline_smoke_blocks_dot_star() {
        let r = re(r"(?i).*");
        assert!(check_baseline_uas(&r).is_err());
    }

    #[test]
    fn baseline_smoke_blocks_mozilla_match() {
        let r = re(r"Mozilla");
        assert!(check_baseline_uas(&r).is_err());
    }

    #[test]
    fn baseline_smoke_passes_specific_ai_pattern() {
        let r = re(r"\bMyCustomBot\b");
        assert!(check_baseline_uas(&r).is_ok());
    }

    #[test]
    fn cidr_cap_rejected_at_65() {
        let mut cidrs = Vec::with_capacity(65);
        for i in 0..65 {
            cidrs.push(format!("203.0.113.{i}/32"));
        }
        let v = CustomVerification::IpRanges { cidrs };
        let err = validate_verification(&v).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("cap is 64")),
            _ => panic!("wrong error"),
        }
    }

    #[test]
    fn cidr_cap_passes_at_64() {
        let mut cidrs = Vec::with_capacity(64);
        for i in 0..64 {
            cidrs.push(format!("203.0.113.{i}/32"));
        }
        let v = CustomVerification::IpRanges { cidrs };
        assert!(validate_verification(&v).is_ok());
    }

    #[test]
    fn invalid_cidr_rejected() {
        let v = CustomVerification::IpRanges {
            cidrs: vec!["not-a-cidr".into()],
        };
        assert!(validate_verification(&v).is_err());
    }

    #[test]
    fn rdns_empty_suffixes_rejected() {
        let v = CustomVerification::Rdns {
            suffixes: Vec::new(),
        };
        assert!(validate_verification(&v).is_err());
    }

    #[test]
    fn rdns_suffix_without_leading_dot_rejected() {
        let v = CustomVerification::Rdns {
            suffixes: vec!["example.com".into()],
        };
        assert!(validate_verification(&v).is_err());
    }

    #[test]
    fn rdns_suffix_with_leading_dot_accepted() {
        let v = CustomVerification::Rdns {
            suffixes: vec![".example.com".into(), ".other.org".into()],
        };
        assert!(validate_verification(&v).is_ok());
    }

    #[test]
    fn ua_only_no_payload_required() {
        assert!(validate_verification(&CustomVerification::UaOnly).is_ok());
    }
}
