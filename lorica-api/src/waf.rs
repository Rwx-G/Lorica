// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! WAF security events API for the management dashboard.

use axum::extract::{ConnectInfo, Extension, Query};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::db::{db_blocking, log_db_blocking};
use crate::error::{json_data, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;
use lorica_waf::WafEvent;

/// Query parameters for the WAF events endpoint.
#[derive(Debug, Deserialize)]
pub struct WafEventsQuery {
    /// Maximum number of events to return (default 50).
    pub limit: Option<usize>,
    /// Filter by category (e.g. "sql_injection", "xss").
    pub category: Option<String>,
}

/// JSON envelope returned by the WAF events endpoint, including the engine's loaded rule count.
#[derive(Debug, Serialize)]
struct WafEventsResponse {
    events: Vec<WafEvent>,
    total: usize,
    rule_count: usize,
}

#[derive(Debug, Serialize)]
struct WafStatsResponse {
    total_events: u64,
    total_24h: u64,
    rule_count: usize,
    by_category: Vec<CategoryCount>,
}

#[derive(Debug, Serialize)]
struct CategoryCount {
    category: String,
    count: u64,
}

/// GET /api/v1/waf/events - list recent WAF events
pub async fn get_waf_events(
    Extension(state): Extension<AppState>,
    Query(params): Query<WafEventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(50).min(500);
    let rule_count = state.waf_rule_count.unwrap_or(0);

    // Read from persistent store if available, fall back to in-memory buffer.
    // When a category filter is specified, it is applied at the SQL level for
    // the persistent store (so LIMIT applies to the filtered set), and
    // post-query for the in-memory fallback.
    let events = if let Some(ref store) = state.log_store {
        // Off the tokio worker (audit M-7 / backlog #23).
        let category = params.category.clone();
        log_db_blocking(store, move |s| {
            s.list_waf_events(limit, category.as_deref())
        })
        .await?
    } else if let Some(ref waf_buffer) = state.waf_event_buffer {
        let buf = waf_buffer.lock();
        let iter = buf.iter().rev();
        if let Some(ref cat) = params.category {
            iter.filter(|e| e.category.as_str() == cat.as_str())
                .take(limit)
                .cloned()
                .collect()
        } else {
            iter.take(limit).cloned().collect()
        }
    } else {
        vec![]
    };

    let total = events.len();
    Ok(json_data(WafEventsResponse {
        events,
        total,
        rule_count,
    }))
}

/// GET /api/v1/waf/stats - WAF statistics summary.
///
/// Aggregated at the SQL level via `COUNT(*)` + `GROUP BY category`
/// so the dashboard counter reflects the actual table size (up to
/// the configured `enforce_waf_retention` budget). The previous
/// implementation loaded up to 10 000 rows into memory and returned
/// `events.len()`, capping the counter at 10 000 once the retention
/// window exceeded that.
pub async fn get_waf_stats(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rule_count = state.waf_rule_count.unwrap_or(0);

    // Read from persistent store if available, fall back to in-memory buffer
    let (total_events, total_24h, by_category) = if let Some(ref store) = state.log_store {
        // Off the tokio worker. COUNT(*) + GROUP BY can scan the
        // whole waf_events table under retention (up to 100 000
        // rows by default).
        // The query Result is passed through untouched so a query
        // error still falls back to empty stats below; only a join
        // failure is a hard error, as before.
        let stats = log_db_blocking(store, move |s| Ok(s.waf_event_stats())).await?;
        match stats {
            Ok((total, total_24h, cats)) => {
                let by_cat = cats
                    .into_iter()
                    .map(|(category, count)| CategoryCount { category, count })
                    .collect();
                (total, total_24h, by_cat)
            }
            Err(_) => (0u64, 0u64, vec![]),
        }
    } else if let Some(ref waf_buffer) = state.waf_event_buffer {
        let buf = waf_buffer.lock();
        let total = buf.len() as u64;
        let cutoff_24h: String =
            (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let mut total_24h = 0u64;
        let mut counts = std::collections::HashMap::new();
        for event in buf.iter() {
            if event.timestamp.as_str() >= cutoff_24h.as_str() {
                total_24h += 1;
            }
            *counts
                .entry(event.category.as_str().to_string())
                .or_insert(0u64) += 1;
        }
        let mut by_cat: Vec<CategoryCount> = counts
            .into_iter()
            .map(|(category, count)| CategoryCount { category, count })
            .collect();
        by_cat.sort_by_key(|c| std::cmp::Reverse(c.count));
        (total, total_24h, by_cat)
    } else {
        (0u64, 0u64, vec![])
    };

    Ok(json_data(WafStatsResponse {
        total_events,
        total_24h,
        rule_count,
        by_category,
    }))
}

/// GET /api/v1/waf/rules - list all WAF rules with enabled/disabled status
pub async fn get_waf_rules(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = if let Some(ref engine) = state.waf_engine {
        engine.list_rules()
    } else {
        vec![]
    };
    let total = rules.len();
    let enabled = rules.iter().filter(|r| r.enabled).count();
    Ok(json_data(serde_json::json!({
        "rules": rules,
        "total": total,
        "enabled": enabled,
    })))
}

/// JSON body for toggling a WAF rule on or off.
#[derive(Debug, Deserialize)]
pub struct RuleToggleRequest {
    /// Desired rule state (`true` = enabled).
    pub enabled: bool,
}

/// PUT /api/v1/waf/rules/:id - enable or disable a specific rule
pub async fn toggle_waf_rule(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    axum::extract::Path(rule_id): axum::extract::Path<u32>,
    Json(body): Json<RuleToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    let found = if body.enabled {
        engine.enable_rule(rule_id)
    } else {
        engine.disable_rule(rule_id)
    };

    if !found {
        return Err(ApiError::NotFound(format!("rule {rule_id} not found")));
    }

    // Persist disabled rules so they survive restarts (best-effort,
    // as before: a store error does not fail the toggle)
    {
        let disabled_ids = engine.disabled_rule_ids();
        let _ = db_blocking(&state.store, move |store| {
            store.save_waf_disabled_rules(&disabled_ids)
        })
        .await;
    }

    state.notify_config_changed();

    let payload = serde_json::json!({
        "rule_id": rule_id,
        "enabled": body.enabled,
    });
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "waf.rule_toggle",
        ("waf_rule", &rule_id.to_string()),
        None,
        Some(&payload),
    )
    .await;

    Ok(json_data(payload))
}

/// DELETE /api/v1/waf/events - clear WAF event buffer
pub async fn clear_waf_events(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(ref waf_buffer) = state.waf_event_buffer {
        let mut buf = waf_buffer.lock();
        buf.clear();
    }
    if let Some(ref store) = state.log_store {
        // Drain queued WAF events before the wipe so in-flight rows
        // cannot land right after the DELETE (backlog #24 barrier).
        if let Some(ref writer) = state.log_writer {
            let _ = writer.flush().await;
        }
        log_db_blocking(store, |s| {
            s.clear_waf_events()
                .map_err(|e| format!("failed to clear WAF events: {e}"))
        })
        .await?;
    }

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "waf.events_clear",
        ("waf_events", ""),
        None,
        None,
    )
    .await;

    Ok(json_data(serde_json::json!({"cleared": true})))
}

// ---- Custom WAF rules ----

/// JSON body for creating a user-defined WAF rule (regex pattern + category + severity).
#[derive(Debug, Deserialize)]
pub struct CreateCustomRuleRequest {
    /// Operator-assigned numeric rule id (must be unique).
    pub id: u32,
    /// Human-readable description.
    pub description: String,
    /// Rule category (e.g. `"sqli"`, `"xss"`).
    pub category: String,
    /// Rust `regex` pattern matched against the request.
    pub pattern: String,
    /// Severity level 1..=5 (higher = more urgent). Default 3.
    pub severity: Option<u8>,
}

/// POST /api/v1/waf/rules/custom - create a user-defined WAF rule
pub async fn create_custom_rule(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateCustomRuleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    let category = body
        .category
        .parse::<lorica_waf::RuleCategory>()
        .map_err(|e| ApiError::BadRequest(format!("invalid category: {e}")))?;

    // Captured before `body` moves into the persistence closure.
    let audit_after = serde_json::json!({
        "id": body.id,
        "description": body.description.clone(),
        "category": body.category.clone(),
        "pattern": body.pattern.clone(),
        "severity": body.severity.unwrap_or(3),
    });

    engine
        .add_custom_rule(
            body.id,
            body.description.clone(),
            category,
            &body.pattern,
            body.severity.unwrap_or(3),
        )
        .map_err(ApiError::BadRequest)?;

    // Persist custom rule to DB (best-effort, as before). `body`
    // moves into the closure; the response fields are kept first.
    let rule_id = body.id;
    let description = body.description.clone();
    let _ = db_blocking(&state.store, move |store| {
        store.save_waf_custom_rule(
            body.id,
            &body.description,
            &body.category,
            &body.pattern,
            body.severity.unwrap_or(3),
            true,
        )
    })
    .await;

    state.notify_config_changed();

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "waf.custom_rule_create",
        ("waf_rule", &rule_id.to_string()),
        None,
        Some(&audit_after),
    )
    .await;

    Ok(json_data(serde_json::json!({
        "id": rule_id,
        "description": description,
        "created": true,
    })))
}

/// GET /api/v1/waf/rules/custom - list user-defined WAF rules
pub async fn list_custom_rules(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let rules = if let Some(ref engine) = state.waf_engine {
        engine.list_custom_rules()
    } else {
        vec![]
    };
    let total = rules.len();
    Ok(json_data(serde_json::json!({
        "rules": rules,
        "total": total,
    })))
}

/// DELETE /api/v1/waf/rules/custom/:id - delete a user-defined WAF rule
pub async fn delete_custom_rule(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    axum::extract::Path(rule_id): axum::extract::Path<u32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    if engine.remove_custom_rule(rule_id) {
        // Remove from DB (best-effort, as before)
        let _ = db_blocking(&state.store, move |store| {
            store.delete_waf_custom_rule(rule_id)
        })
        .await;
        state.notify_config_changed();

        let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
        crate::audit::record(
            &state,
            &audit_ctx,
            "waf.custom_rule_delete",
            ("waf_rule", &rule_id.to_string()),
            None,
            None,
        )
        .await;

        Ok(json_data(
            serde_json::json!({"deleted": true, "id": rule_id}),
        ))
    } else {
        Err(ApiError::NotFound(format!("custom rule {rule_id}")))
    }
}

// ---- IP Blocklist endpoints ----

/// GET /api/v1/waf/blocklist - get IP blocklist status
pub async fn get_blocklist_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (enabled, count) = if let Some(ref engine) = state.waf_engine {
        let bl = engine.ip_blocklist();
        (bl.is_enabled(), bl.len())
    } else {
        (false, 0)
    };
    Ok(json_data(serde_json::json!({
        "enabled": enabled,
        "ip_count": count,
        "source": lorica_waf::ip_blocklist::DEFAULT_BLOCKLIST_URL,
    })))
}

/// JSON body for toggling the IP blocklist on or off.
#[derive(Debug, Deserialize)]
pub struct BlocklistToggleRequest {
    /// Desired state for the IP blocklist (`true` = active).
    pub enabled: bool,
}

/// PUT /api/v1/waf/blocklist - enable or disable the IP blocklist
pub async fn toggle_blocklist(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<BlocklistToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    engine.ip_blocklist().set_enabled(body.enabled);
    let count = engine.ip_blocklist().len();

    // Persist blocklist state so it survives restarts (best-effort,
    // as before: store errors do not fail the toggle)
    let enabled = body.enabled;
    let _ = db_blocking(&state.store, move |store| {
        if let Ok(mut settings) = store.get_global_settings() {
            settings.ip_blocklist_enabled = enabled;
            let _ = store.update_global_settings(&settings);
        }
        Ok::<_, ApiError>(())
    })
    .await;

    // Notify workers so they apply the new blocklist state
    state.notify_config_changed();

    let payload = serde_json::json!({
        "enabled": body.enabled,
        "ip_count": count,
    });
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "waf.blocklist_toggle",
        ("waf_blocklist", ""),
        None,
        Some(&payload),
    )
    .await;

    Ok(json_data(payload))
}

/// Fetch and load the blocklist from the remote URL.
/// Shared between the manual reload endpoint and the background task.
pub async fn fetch_and_load_blocklist(
    blocklist: &lorica_waf::IpBlocklist,
) -> Result<usize, String> {
    let url = lorica_waf::ip_blocklist::DEFAULT_BLOCKLIST_URL;

    // Disable redirect following on the blocklist fetcher : the
    // blocklist URL is operator-configurable (or comes from a third-
    // party feed) ; a redirect to an internal address would let an
    // attacker who controls the feed pivot into the supervisor's
    // loopback. Audit L-7.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("failed to fetch blocklist: {e}"))?;

    if !response.status().is_success() {
        return Err(format!("blocklist fetch returned {}", response.status()));
    }

    let text = response
        .text()
        .await
        .map_err(|e| format!("failed to read blocklist body: {e}"))?;

    Ok(blocklist.load_from_text(&text))
}

/// POST /api/v1/waf/blocklist/reload - reload the IP blocklist from the remote URL
pub async fn reload_blocklist(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    let count = fetch_and_load_blocklist(engine.ip_blocklist())
        .await
        .map_err(ApiError::Internal)?;

    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "waf.blocklist_reload",
        ("waf_blocklist", ""),
        None,
        None,
    )
    .await;

    Ok(json_data(serde_json::json!({
        "reloaded": true,
        "ip_count": count,
        "source": lorica_waf::ip_blocklist::DEFAULT_BLOCKLIST_URL,
    })))
}

/// Spawn a background task that refreshes the IP blocklist periodically.
///
/// Default interval: 6 hours (matching the Data-Shield update frequency).
/// Only fetches if the blocklist is enabled. Failures are logged, never fatal.
pub fn spawn_blocklist_refresh(
    engine: std::sync::Arc<lorica_waf::WafEngine>,
    interval: std::time::Duration,
    tracker: &tokio_util::task::TaskTracker,
) -> tokio::task::JoinHandle<()> {
    tracker.spawn(async move {
        // Initial fetch at startup if blocklist is already enabled (restored from settings)
        if engine.ip_blocklist().is_enabled() {
            match fetch_and_load_blocklist(engine.ip_blocklist()).await {
                Ok(count) => {
                    tracing::info!(count, "IP blocklist loaded at startup");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "IP blocklist initial load failed");
                }
            }
        }

        loop {
            tokio::time::sleep(interval).await;

            if !engine.ip_blocklist().is_enabled() {
                tracing::debug!("IP blocklist disabled, skipping refresh");
                continue;
            }

            match fetch_and_load_blocklist(engine.ip_blocklist()).await {
                Ok(count) => {
                    tracing::info!(count, "IP blocklist refreshed from remote");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "IP blocklist refresh failed, keeping previous list"
                    );
                }
            }
        }
    })
}
