// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Custom AI / LLM crawler CRUD + read HTTP handlers (Story 8.2
//! AC #6 + #7).
//!
//! Endpoints :
//! - `GET    /api/v1/ai-crawlers/custom`         - list custom entries
//! - `POST   /api/v1/ai-crawlers/custom`         - create one
//! - `PUT    /api/v1/ai-crawlers/custom/:id`     - update one
//! - `DELETE /api/v1/ai-crawlers/custom/:id`     - delete one
//! - `GET    /api/v1/ai-crawlers/builtin`        - list the 16 built-ins
//! - `GET    /api/v1/ai-crawlers/test`           - classify a UA (read-only)
//! - `GET    /api/v1/ai-crawlers/robots-preview` - preview the robots.txt body
//! - `GET    /api/v1/ai-crawlers/stats`          - 5-minute in-process top-5
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

use std::fmt::Write as _;

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use ipnet::IpNet;
use lorica_config::models::{
    AiBotPolicy, CustomCrawler, CustomVerification, Route, CUSTOM_CRAWLER_MAX_CIDRS,
    CUSTOM_CRAWLER_MAX_COUNT,
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

/// One built-in AI-crawler descriptor exposed by the read
/// endpoints (`/builtin`, `/test`, `/robots-preview`).
///
/// This is a deliberate small mirror of the authoritative
/// `lorica/src/ai_bot.rs::BUILTIN_CRAWLERS` registry. The binary
/// crate `lorica` depends on `lorica-api`, so `lorica-api` cannot
/// call back into the registry ; the duplication is the same
/// accepted pattern as the [`BASELINE_UAS`] copy above. The
/// `descriptor_count_matches_builtin_registry` unit test pins the
/// length at 16 as a drift tripwire - when a crawler is added to
/// `BUILTIN_CRAWLERS`, that test fails until this table is updated.
struct BuiltinDescriptor {
    /// Stable crawler label (matches the registry `name`).
    name: &'static str,
    /// Word-boundary-anchored, case-insensitive regex source.
    user_agent_pattern: &'static str,
    /// Verification kind label: `rdns | ip_ranges | ua_only`.
    verification_kind: &'static str,
    /// Short human-facing vendor label.
    source: &'static str,
}

/// Built-in descriptor table mirroring
/// `lorica/src/ai_bot.rs::BUILTIN_CRAWLERS` (snapshot 2026-05-03).
/// Source of truth lives in the binary crate ; keep the two in
/// sync (the count tripwire test guards the size only).
const BUILTIN_DESCRIPTORS: &[BuiltinDescriptor] = &[
    BuiltinDescriptor {
        name: "GPTBot",
        user_agent_pattern: r"(?i)\bGPTBot\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinDescriptor {
        name: "ChatGPT-User",
        user_agent_pattern: r"(?i)\bChatGPT-User\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinDescriptor {
        name: "OAI-SearchBot",
        user_agent_pattern: r"(?i)\bOAI-SearchBot\b",
        verification_kind: "ip_ranges",
        source: "OpenAI",
    },
    BuiltinDescriptor {
        name: "ClaudeBot",
        user_agent_pattern: r"(?i)\bClaudeBot\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinDescriptor {
        name: "Claude-User",
        user_agent_pattern: r"(?i)\bClaude-User\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinDescriptor {
        name: "Claude-SearchBot",
        user_agent_pattern: r"(?i)\bClaude-SearchBot\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinDescriptor {
        name: "anthropic-ai",
        user_agent_pattern: r"(?i)\banthropic-ai\b",
        verification_kind: "ip_ranges",
        source: "Anthropic",
    },
    BuiltinDescriptor {
        name: "CCBot",
        user_agent_pattern: r"(?i)\bCCBot/\d",
        verification_kind: "rdns",
        source: "Common Crawl",
    },
    BuiltinDescriptor {
        name: "PerplexityBot",
        user_agent_pattern: r"(?i)\bPerplexityBot/\d",
        verification_kind: "ip_ranges",
        source: "Perplexity",
    },
    BuiltinDescriptor {
        name: "Perplexity-User",
        user_agent_pattern: r"(?i)\bPerplexity-User/\d",
        verification_kind: "ip_ranges",
        source: "Perplexity",
    },
    BuiltinDescriptor {
        name: "Bytespider",
        user_agent_pattern: r"(?i)\bBytespider\b",
        verification_kind: "ua_only",
        source: "ByteDance",
    },
    BuiltinDescriptor {
        name: "Google-Extended",
        user_agent_pattern: r"(?i)\bGoogle-Extended\b",
        verification_kind: "ua_only",
        source: "Google",
    },
    BuiltinDescriptor {
        name: "Applebot",
        user_agent_pattern: r"(?i)\bApplebot(?:-Extended)?\b",
        verification_kind: "rdns",
        source: "Apple",
    },
    BuiltinDescriptor {
        name: "Amazonbot",
        user_agent_pattern: r"(?i)\b(?:Amazonbot|Amzn-SearchBot|Amzn-User)\b",
        verification_kind: "ip_ranges",
        source: "Amazon",
    },
    BuiltinDescriptor {
        name: "FacebookBot",
        user_agent_pattern: r"(?i)\b(?:FacebookBot|facebookexternalhit|meta-externalagent)\b",
        verification_kind: "ip_ranges",
        source: "Meta",
    },
    BuiltinDescriptor {
        name: "Diffbot",
        user_agent_pattern: r"(?i)\bDiffbot\b",
        verification_kind: "ua_only",
        source: "Diffbot",
    },
];

/// `GET /api/v1/ai-crawlers/builtin` - list the 16 built-in
/// descriptors (name + UA pattern + verification kind + vendor).
/// Read-only, no store access.
pub async fn list_builtin_crawlers() -> Json<serde_json::Value> {
    let entries: Vec<serde_json::Value> = BUILTIN_DESCRIPTORS
        .iter()
        .map(|d| {
            serde_json::json!({
                "name": d.name,
                "user_agent_pattern": d.user_agent_pattern,
                "verification_kind": d.verification_kind,
                "source": d.source,
            })
        })
        .collect();
    json_data(serde_json::json!({ "entries": entries }))
}

/// One merged (built-in overlaid with custom) registry entry used
/// by the `/test` classifier. Owned strings because custom rows
/// override built-ins by name.
struct MergedEntry {
    name: String,
    pattern: String,
    kind: String,
}

/// Verification-kind label for a custom row.
fn custom_kind_str(v: &CustomVerification) -> &'static str {
    match v {
        CustomVerification::Rdns { .. } => "rdns",
        CustomVerification::IpRanges { .. } => "ip_ranges",
        CustomVerification::UaOnly => "ua_only",
    }
}

/// Build the merged registry: the 16 built-in descriptors first,
/// then enabled custom rows overlaid by name (custom wins on a name
/// conflict, replacing the built-in in place ; new names append).
fn build_merged_registry(customs: &[CustomCrawler]) -> Vec<MergedEntry> {
    let mut merged: Vec<MergedEntry> = BUILTIN_DESCRIPTORS
        .iter()
        .map(|d| MergedEntry {
            name: d.name.to_string(),
            pattern: d.user_agent_pattern.to_string(),
            kind: d.verification_kind.to_string(),
        })
        .collect();
    for c in customs.iter().filter(|c| c.enabled) {
        let kind = custom_kind_str(&c.verification);
        if let Some(existing) = merged.iter_mut().find(|m| m.name == c.name) {
            existing.pattern = c.user_agent_pattern.clone();
            existing.kind = kind.to_string();
        } else {
            merged.push(MergedEntry {
                name: c.name.clone(),
                pattern: c.user_agent_pattern.clone(),
                kind: kind.to_string(),
            });
        }
    }
    merged
}

/// Return the first merged-registry entry whose pattern matches
/// `ua`. Each pattern is compiled with the same `RegexBuilder`
/// caps as the CRUD validator ; a custom row whose regex fails to
/// compile is skipped (built-in patterns always compile). Pure
/// User-Agent match - does NOT consult rDNS or IP ranges.
fn classify_ua<'a>(merged: &'a [MergedEntry], ua: &str) -> Option<&'a MergedEntry> {
    merged.iter().find(|m| {
        match RegexBuilder::new(&m.pattern)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .dfa_size_limit(1 << 21)
            .build()
        {
            Ok(re) => re.is_match(ua),
            Err(e) => {
                tracing::warn!(
                    target: "lorica::ai_bot",
                    crawler = %m.name,
                    pattern = %m.pattern,
                    error = %e,
                    "custom AI crawler pattern failed to compile in /test classifier ; skipping entry"
                );
                false
            }
        }
    })
}

/// Lowercased policy label (`off | deny | log`) for a route's
/// `ai_bot_policy`. `None` and `Off` both map to `off`.
fn policy_label(policy: Option<AiBotPolicy>) -> &'static str {
    match policy.unwrap_or(AiBotPolicy::Off) {
        AiBotPolicy::Off => "off",
        AiBotPolicy::Deny => "deny",
        AiBotPolicy::Log => "log",
    }
}

/// Capitalised policy label for the human-facing `note` field.
fn policy_display(policy: Option<AiBotPolicy>) -> &'static str {
    match policy.unwrap_or(AiBotPolicy::Off) {
        AiBotPolicy::Off => "Off",
        AiBotPolicy::Deny => "Deny",
        AiBotPolicy::Log => "Log",
    }
}

/// Query params for `GET /api/v1/ai-crawlers/test`.
#[derive(Debug, Deserialize)]
pub struct TestQuery {
    /// URL-decoded User-Agent string to classify.
    pub ua: String,
    /// Route whose `ai_bot_policy` decides `would_apply_policy`.
    pub route_id: String,
}

/// `GET /api/v1/ai-crawlers/test?ua=<urlencoded>&route_id=<id>` -
/// classify a User-Agent against the merged registry (built-in
/// overlaid with enabled custom rows). Read-only ; does NOT consult
/// rDNS or vendor IP ranges.
pub async fn test_crawler(
    Extension(state): Extension<AppState>,
    Query(q): Query<TestQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let customs = store.list_custom_crawlers()?;
    let route = store.get_route(&q.route_id)?;
    drop(store);

    let policy = route.as_ref().and_then(|r| r.ai_bot_policy);
    let merged = build_merged_registry(&customs);
    let matched = classify_ua(&merged, &q.ua);

    let (name, kind, note) = match matched {
        Some(m) => (
            Some(m.name.clone()),
            Some(m.kind.clone()),
            format!(
                "Matched {} via {}; route policy {}",
                m.name,
                m.kind,
                policy_display(policy)
            ),
        ),
        None => (None, None, "No AI bot match".to_string()),
    };

    Ok(json_data(serde_json::json!({
        "matched_crawler": name,
        "verification_kind": kind,
        "would_apply_policy": policy_label(policy),
        "note": note,
    })))
}

/// Active crawler names for a route's `/robots.txt` body. Empty
/// when the route's policy is `Off` (caller emits the allow-all
/// fallback). Otherwise the 16 built-in names plus enabled custom
/// names, deduped by name (custom wins, no duplicate block).
fn active_crawler_names(route: &Route, customs: &[CustomCrawler]) -> Vec<String> {
    if route.ai_bot_policy.unwrap_or(AiBotPolicy::Off) == AiBotPolicy::Off {
        return Vec::new();
    }
    let mut names: Vec<String> = BUILTIN_DESCRIPTORS.iter().map(|d| d.name.to_string()).collect();
    for c in customs.iter().filter(|c| c.enabled) {
        if !names.iter().any(|n| n == &c.name) {
            names.push(c.name.clone());
        }
    }
    names
}

/// Build the `/robots.txt` body for the preview endpoint. Mirrors
/// `lorica/src/ai_bot.rs::build_robots_txt_from_names` byte-for-byte
/// (header comment block, one `User-agent: <name>\nDisallow: /\n\n`
/// block per active name, or the allow-all fallback, trailing single
/// `\n`). Keep this in sync with that function ; duplication is
/// accepted because `lorica-api` cannot depend on the binary crate.
fn build_robots_preview(active_names: &[String]) -> String {
    let mut out = String::with_capacity(64 + active_names.len() * 48);
    let _ = writeln!(out, "# Generated by Lorica v{}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "# Source: ai-robots-txt/ai.robots.txt @ snapshot 2026-05-03");
    out.push('\n');
    if active_names.is_empty() {
        out.push_str("User-agent: *\nAllow: /\n");
        return out;
    }
    for name in active_names {
        let _ = writeln!(out, "User-agent: {name}");
        out.push_str("Disallow: /\n\n");
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

/// Query params for `GET /api/v1/ai-crawlers/robots-preview`.
#[derive(Debug, Deserialize)]
pub struct RobotsPreviewQuery {
    /// Route whose merged registry + policy shapes the body.
    pub route_id: String,
}

/// `GET /api/v1/ai-crawlers/robots-preview?route_id=<id>` - return
/// the body `check_robots_txt` WOULD emit for the route, regardless
/// of the route's `serve_robots_txt` flag.
pub async fn robots_preview(
    Extension(state): Extension<AppState>,
    Query(q): Query<RobotsPreviewQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let store = state.store.lock().await;
    let customs = store.list_custom_crawlers()?;
    let route = store
        .get_route(&q.route_id)?
        .ok_or_else(|| ApiError::NotFound(format!("route {}", q.route_id)))?;
    drop(store);

    let active = active_crawler_names(&route, &customs);
    let body = build_robots_preview(&active);

    Ok(json_data(serde_json::json!({
        "body": body,
        "route_id": q.route_id,
        "generated_at": Utc::now().to_rfc3339(),
    })))
}

/// Per-crawler aggregate over the stats window.
#[derive(Default)]
struct CrawlerAgg {
    count: u64,
    deny: u64,
    log: u64,
    spoofed: u64,
    ua_only_match: u64,
}

/// Aggregate `(crawler, action)` pairs into the top-5 crawlers by
/// count (descending ; ties broken by crawler name ascending) with
/// per-action breakdown.
fn aggregate_top5(events: &[(String, String)]) -> Vec<serde_json::Value> {
    let mut map: std::collections::HashMap<&str, CrawlerAgg> = std::collections::HashMap::new();
    for (crawler, action) in events {
        let agg = map.entry(crawler.as_str()).or_default();
        agg.count += 1;
        match action.as_str() {
            "deny" => agg.deny += 1,
            "log" => agg.log += 1,
            "spoofed" => agg.spoofed += 1,
            "ua_only_match" => agg.ua_only_match += 1,
            _ => {}
        }
    }
    let mut ranked: Vec<(&str, CrawlerAgg)> = map.into_iter().collect();
    ranked.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(b.0)));
    ranked
        .into_iter()
        .take(5)
        .map(|(crawler, agg)| {
            serde_json::json!({
                "crawler": crawler,
                "count": agg.count,
                "action_breakdown": {
                    "deny": agg.deny,
                    "log": agg.log,
                    "spoofed": agg.spoofed,
                    "ua_only_match": agg.ua_only_match,
                },
            })
        })
        .collect()
}

/// Query params for `GET /api/v1/ai-crawlers/stats`.
#[derive(Debug, Deserialize)]
pub struct StatsQuery {
    /// Route to report on.
    pub route_id: String,
    /// Only `5m` is accepted ; absent defaults to `5m`.
    #[serde(default)]
    pub window: Option<String>,
}

/// `GET /api/v1/ai-crawlers/stats?route_id=<id>&window=5m` - top-5
/// crawlers in the in-process 5-minute window for a route.
///
/// WORKERS-MODE LIMITATION : the backing ring buffer
/// (`metrics::AI_BOT_STATS_BUFFER`) is per-process. In multi-worker
/// mode `check_ai_bot` runs in the worker processes while this
/// endpoint runs in the supervisor, so the buffer reflects only
/// same-process evaluations. For the cross-process view, scrape the
/// Prometheus `lorica_ai_bot_total` counter via `/metrics` : the
/// AI-bot counters are now shipped from each worker to the
/// supervisor's registry (see `metrics::PER_WORKER_COUNTERS`), so
/// `/metrics` is a true cross-process aggregate. The 5-minute buffer
/// here is only an in-process convenience for the top-5 list, not a
/// cross-process aggregate.
pub async fn ai_crawler_stats(
    Query(q): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let window = q.window.as_deref().unwrap_or("5m");
    if window != "5m" {
        return Err(ApiError::BadRequest(
            "window must be '5m' (in-process buffer size) ; for longer ranges, scrape /metrics into your time-series backend".into(),
        ));
    }
    let events = crate::metrics::ai_bot_window_events(&q.route_id);
    let top_5 = aggregate_top5(&events);
    Ok(json_data(serde_json::json!({
        "window": "5m",
        "route_id": q.route_id,
        "top_5": top_5,
    })))
}

fn validate_request(body: &CustomCrawlerRequest) -> Result<(), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if body.name.len() > 64 {
        return Err(ApiError::BadRequest("name must be <= 64 characters".into()));
    }
    // The name is written verbatim into the auto-served /robots.txt as
    // `User-agent: {name}`. A control character (notably a newline)
    // would let an admin inject arbitrary robots.txt directives.
    if body.name.chars().any(|c| c.is_control()) {
        return Err(ApiError::BadRequest(
            "name must not contain control characters".into(),
        ));
    }
    reject_builtin_verification_downgrade(&body.name, &body.verification)?;
    let compiled = compile_pattern(&body.user_agent_pattern)?;
    check_baseline_uas(&compiled)?;
    validate_verification(&body.verification)?;
    Ok(())
}

/// Reject a custom row that would DOWNGRADE a built-in's verification
/// strength. AC #6 lets a custom row override a built-in by name (to
/// refresh a stale vendor IP list), but a custom `UaOnly` verification
/// replacing a built-in verified by `rdns` or `ip_ranges` turns a
/// strong, hard-to-spoof vendor identity into a forgeable UA-only
/// match. Same-or-stronger overrides (e.g. an `ip_ranges` refresh)
/// stay allowed. Name match is case-insensitive to mirror the
/// merge's name-collision semantics.
fn reject_builtin_verification_downgrade(
    name: &str,
    verification: &CustomVerification,
) -> Result<(), ApiError> {
    if !matches!(verification, CustomVerification::UaOnly) {
        return Ok(());
    }
    if let Some(descriptor) = BUILTIN_DESCRIPTORS
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
    {
        if matches!(descriptor.verification_kind, "rdns" | "ip_ranges") {
            return Err(ApiError::BadRequest(format!(
                "custom crawler '{name}' overrides a built-in verified by {}; \
                 downgrading to ua_only is not allowed - keep rdns/ip_ranges or rename",
                descriptor.verification_kind
            )));
        }
    }
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

    fn request(name: &str, pattern: &str, verification: CustomVerification) -> CustomCrawlerRequest {
        CustomCrawlerRequest {
            name: name.to_string(),
            user_agent_pattern: pattern.to_string(),
            verification,
            enabled: true,
        }
    }

    #[test]
    fn name_with_control_char_rejected() {
        // A newline in the name would inject robots.txt directives.
        let body = request(
            "Bad\nName",
            r"(?i)\bSomeBot\b",
            CustomVerification::UaOnly,
        );
        let err = validate_request(&body).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("control characters")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn builtin_verification_downgrade_to_ua_only_rejected() {
        // GPTBot is a built-in verified by ip_ranges. A custom row of
        // the same name with ua_only verification must be rejected.
        let body = request("GPTBot", r"(?i)\bMyGptbotClone\b", CustomVerification::UaOnly);
        let err = validate_request(&body).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => {
                assert!(msg.contains("downgrading to ua_only is not allowed"), "{msg}");
                assert!(msg.contains("ip_ranges"), "{msg}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
        // Case-insensitive name collision is caught too.
        let body_ci = request("ccbot", r"(?i)\bMyCcbotClone\b", CustomVerification::UaOnly);
        assert!(validate_request(&body_ci).is_err());
    }

    #[test]
    fn builtin_ip_ranges_refresh_allowed() {
        // The legitimate stale-IP-list refresh: same name, same-or-
        // stronger kind (ip_ranges), must pass.
        let body = request(
            "GPTBot",
            r"(?i)\bGPTBotRefresh\b",
            CustomVerification::IpRanges {
                cidrs: vec!["203.0.113.0/24".into()],
            },
        );
        assert!(validate_request(&body).is_ok());
    }

    fn custom(name: &str, pattern: &str, enabled: bool) -> CustomCrawler {
        let now = Utc::now();
        CustomCrawler {
            id: 0,
            name: name.to_string(),
            user_agent_pattern: pattern.to_string(),
            verification: CustomVerification::UaOnly,
            enabled,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn descriptor_count_matches_builtin_registry() {
        // Drift tripwire : the source of truth is
        // `lorica/src/ai_bot.rs::BUILTIN_CRAWLERS` (16 entries).
        // `lorica-api` cannot import it (back-dep), so this pins
        // the mirrored table size. If BUILTIN_CRAWLERS grows, this
        // fails until BUILTIN_DESCRIPTORS is updated to match.
        assert_eq!(BUILTIN_DESCRIPTORS.len(), 16);
    }

    #[test]
    fn descriptor_kinds_are_valid_labels() {
        for d in BUILTIN_DESCRIPTORS {
            assert!(
                matches!(d.verification_kind, "rdns" | "ip_ranges" | "ua_only"),
                "{} has invalid kind {}",
                d.name,
                d.verification_kind
            );
        }
    }

    #[test]
    fn classify_matches_builtin_ua() {
        let merged = build_merged_registry(&[]);
        let m = classify_ua(&merged, "Mozilla/5.0 (compatible; GPTBot/1.0)").expect("GPTBot");
        assert_eq!(m.name, "GPTBot");
        assert_eq!(m.kind, "ip_ranges");
    }

    #[test]
    fn classify_rejects_browser_ua() {
        let merged = build_merged_registry(&[]);
        let browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
                       (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert!(classify_ua(&merged, browser).is_none());
    }

    #[test]
    fn custom_overrides_builtin_by_name() {
        // A custom row named "GPTBot" with a different pattern must
        // replace the built-in in place (custom-wins-on-conflict).
        let customs = vec![custom("GPTBot", r"(?i)\bMyGptbotClone\b", true)];
        let merged = build_merged_registry(&customs);
        // Count is unchanged (replace in place, not append).
        assert_eq!(merged.len(), BUILTIN_DESCRIPTORS.len());
        // The real GPTBot UA no longer matches (built-in pattern gone).
        assert!(classify_ua(&merged, "Mozilla/5.0 (compatible; GPTBot/1.0)").is_none());
        // The override pattern matches and reports the custom name.
        let m = classify_ua(&merged, "MyGptbotClone/2.0").expect("override");
        assert_eq!(m.name, "GPTBot");
    }

    #[test]
    fn disabled_custom_is_ignored() {
        let customs = vec![custom("ExtraBot", r"(?i)\bExtraBot\b", false)];
        let merged = build_merged_registry(&customs);
        assert_eq!(merged.len(), BUILTIN_DESCRIPTORS.len());
        assert!(classify_ua(&merged, "ExtraBot/1.0").is_none());
    }

    #[test]
    fn custom_with_uncompilable_regex_is_skipped_not_panic() {
        // Unbalanced group never compiles ; classify must skip it.
        let customs = vec![custom("BadBot", r"(", true)];
        let merged = build_merged_registry(&customs);
        assert!(classify_ua(&merged, "anything BadBot").is_none());
    }

    fn route_with_policy(policy: Option<AiBotPolicy>) -> Route {
        let now = Utc::now();
        Route {
            id: "r1".to_string(),
            hostname: "example.com".to_string(),
            path_prefix: "/".to_string(),
            certificate_id: None,
            load_balancing: lorica_config::models::LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: lorica_config::models::WafMode::Detection,
            enabled: true,
            force_https: false,
            redirect_hostname: None,
            redirect_to: None,
            hostname_aliases: Vec::new(),
            proxy_headers: Default::default(),
            response_headers: Default::default(),
            security_headers: "moderate".to_string(),
            connect_timeout_s: 5,
            read_timeout_s: 60,
            send_timeout_s: 60,
            strip_path_prefix: None,
            add_path_prefix: None,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            access_log_enabled: true,
            proxy_headers_remove: Vec::new(),
            response_headers_remove: Vec::new(),
            max_request_body_bytes: None,
            websocket_enabled: true,
            rate_limit_rps: None,
            rate_limit_burst: None,
            ip_allowlist: Vec::new(),
            ip_denylist: Vec::new(),
            cors_allowed_origins: Vec::new(),
            cors_allowed_methods: Vec::new(),
            cors_max_age_s: None,
            compression_enabled: false,
            retry_attempts: None,
            cache_enabled: false,
            cache_ttl_s: 300,
            cache_max_bytes: 52_428_800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: Vec::new(),
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: Vec::new(),
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: Vec::new(),
            header_rules: Vec::new(),
            traffic_splits: Vec::new(),
            forward_auth: None,
            mirror: None,
            response_rewrite: None,
            mtls: None,
            rate_limit: None,
            geoip: None,
            bot_protection: None,
            ai_bot_policy: policy,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            group_name: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn robots_preview_fallback_when_policy_off() {
        let route = route_with_policy(None);
        let names = active_crawler_names(&route, &[]);
        assert!(names.is_empty());
        let body = build_robots_preview(&names);
        assert!(body.contains("User-agent: *"));
        assert!(body.contains("Allow: /"));
        assert!(body.starts_with("# Generated by Lorica v"));
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"));
    }

    #[test]
    fn robots_preview_active_when_policy_deny() {
        let route = route_with_policy(Some(AiBotPolicy::Deny));
        let customs = vec![custom("ExtraBot", r"(?i)\bExtraBot\b", true)];
        let names = active_crawler_names(&route, &customs);
        // 16 built-ins + 1 enabled custom.
        assert_eq!(names.len(), BUILTIN_DESCRIPTORS.len() + 1);
        let body = build_robots_preview(&names);
        assert_eq!(body.matches("Disallow: /").count(), names.len());
        assert!(body.contains("User-agent: GPTBot"));
        assert!(body.contains("User-agent: ExtraBot"));
        assert!(body.ends_with('\n'));
        assert!(!body.ends_with("\n\n"));
    }

    #[test]
    fn aggregate_top5_orders_by_count_then_name() {
        let events = vec![
            ("GPTBot".to_string(), "deny".to_string()),
            ("GPTBot".to_string(), "deny".to_string()),
            ("CCBot".to_string(), "log".to_string()),
            ("Applebot".to_string(), "spoofed".to_string()),
            ("Applebot".to_string(), "ua_only_match".to_string()),
        ];
        let top = aggregate_top5(&events);
        assert_eq!(top[0]["crawler"], "Applebot");
        assert_eq!(top[0]["count"], 2);
        // Applebot ties GPTBot at 2 ; name "Applebot" < "GPTBot".
        assert_eq!(top[1]["crawler"], "GPTBot");
        assert_eq!(top[1]["count"], 2);
        assert_eq!(top[2]["crawler"], "CCBot");
        assert_eq!(top[0]["action_breakdown"]["spoofed"], 1);
        assert_eq!(top[0]["action_breakdown"]["ua_only_match"], 1);
        assert_eq!(top[1]["action_breakdown"]["deny"], 2);
    }

    #[tokio::test]
    async fn stats_rejects_non_5m_window() {
        let q: StatsQuery = StatsQuery {
            route_id: "r1".to_string(),
            window: Some("1h".to_string()),
        };
        let err = ai_crawler_stats(Query(q)).await.unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("window must be '5m'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stats_accepts_5m_window() {
        let q: StatsQuery = StatsQuery {
            route_id: "no-such-route".to_string(),
            window: Some("5m".to_string()),
        };
        let resp = ai_crawler_stats(Query(q)).await.expect("ok");
        let json = resp.0;
        assert_eq!(json["data"]["window"], "5m");
        assert!(json["data"]["top_5"].as_array().expect("array").is_empty());
    }
}
