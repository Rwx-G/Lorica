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

use axum::extract::{Extension, Query};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
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

#[derive(Debug, Serialize)]
struct WafEventsResponse {
    events: Vec<WafEvent>,
    total: usize,
    rule_count: usize,
}

#[derive(Debug, Serialize)]
struct WafStatsResponse {
    total_events: usize,
    rule_count: usize,
    by_category: Vec<CategoryCount>,
}

#[derive(Debug, Serialize)]
struct CategoryCount {
    category: String,
    count: usize,
}

/// GET /api/v1/waf/events - list recent WAF events
pub async fn get_waf_events(
    Extension(state): Extension<AppState>,
    Query(params): Query<WafEventsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let limit = params.limit.unwrap_or(50).min(500);
    let rule_count = state.waf_rule_count.unwrap_or(0);

    // Read from persistent store if available, fall back to in-memory buffer
    let events = if let Some(ref store) = state.log_store {
        store
            .list_waf_events(limit)
            .map_err(|e| ApiError::Internal(format!("waf event query failed: {e}")))?
    } else if let Some(ref waf_buffer) = state.waf_event_buffer {
        let buf = waf_buffer.lock();
        buf.iter().rev().take(limit).cloned().collect()
    } else {
        vec![]
    };

    // Apply category filter if specified
    let events: Vec<WafEvent> = if let Some(ref cat) = params.category {
        events
            .into_iter()
            .filter(|e| e.category.as_str() == cat.as_str())
            .collect()
    } else {
        events
    };

    let total = events.len();
    Ok(json_data(WafEventsResponse {
        events,
        total,
        rule_count,
    }))
}

/// GET /api/v1/waf/stats - WAF statistics summary
pub async fn get_waf_stats(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (total_events, by_category, rule_count) =
        if let Some(ref waf_buffer) = state.waf_event_buffer {
            let buf = waf_buffer.lock();
            let total = buf.len();

            let mut counts = std::collections::HashMap::new();
            for event in buf.iter() {
                *counts
                    .entry(event.category.as_str().to_string())
                    .or_insert(0usize) += 1;
            }

            let mut by_cat: Vec<CategoryCount> = counts
                .into_iter()
                .map(|(category, count)| CategoryCount { category, count })
                .collect();
            by_cat.sort_by(|a, b| b.count.cmp(&a.count));

            (total, by_cat, state.waf_rule_count.unwrap_or(0))
        } else {
            (0, vec![], 0)
        };

    Ok(json_data(WafStatsResponse {
        total_events,
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

#[derive(Debug, Deserialize)]
pub struct RuleToggleRequest {
    pub enabled: bool,
}

/// PUT /api/v1/waf/rules/:id - enable or disable a specific rule
pub async fn toggle_waf_rule(
    Extension(state): Extension<AppState>,
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

    // Persist disabled rules so they survive restarts
    {
        let disabled_ids = engine.disabled_rule_ids();
        let store = state.store.lock().await;
        let _ = store.save_waf_disabled_rules(&disabled_ids);
    }

    state.notify_config_changed();
    Ok(json_data(serde_json::json!({
        "rule_id": rule_id,
        "enabled": body.enabled,
    })))
}

/// DELETE /api/v1/waf/events - clear WAF event buffer
pub async fn clear_waf_events(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(ref waf_buffer) = state.waf_event_buffer {
        let mut buf = waf_buffer.lock();
        buf.clear();
    }
    if let Some(ref store) = state.log_store {
        store
            .clear_waf_events()
            .map_err(|e| ApiError::Internal(format!("failed to clear WAF events: {e}")))?;
    }
    Ok(json_data(serde_json::json!({"cleared": true})))
}

// ---- Custom WAF rules ----

#[derive(Debug, Deserialize)]
pub struct CreateCustomRuleRequest {
    pub id: u32,
    pub description: String,
    pub category: String,
    pub pattern: String,
    pub severity: Option<u8>,
}

/// POST /api/v1/waf/rules/custom - create a user-defined WAF rule
pub async fn create_custom_rule(
    Extension(state): Extension<AppState>,
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

    engine
        .add_custom_rule(
            body.id,
            body.description.clone(),
            category,
            &body.pattern,
            body.severity.unwrap_or(3),
        )
        .map_err(ApiError::BadRequest)?;

    // Persist custom rule to DB
    {
        let store = state.store.lock().await;
        let _ = store.save_waf_custom_rule(
            body.id,
            &body.description,
            &body.category,
            &body.pattern,
            body.severity.unwrap_or(3),
            true,
        );
    }

    state.notify_config_changed();
    Ok(json_data(serde_json::json!({
        "id": body.id,
        "description": body.description,
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
    Extension(state): Extension<AppState>,
    axum::extract::Path(rule_id): axum::extract::Path<u32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    if engine.remove_custom_rule(rule_id) {
        // Remove from DB
        {
            let store = state.store.lock().await;
            let _ = store.delete_waf_custom_rule(rule_id);
        }
        state.notify_config_changed();
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

#[derive(Debug, Deserialize)]
pub struct BlocklistToggleRequest {
    pub enabled: bool,
}

/// PUT /api/v1/waf/blocklist - enable or disable the IP blocklist
pub async fn toggle_blocklist(
    Extension(state): Extension<AppState>,
    Json(body): Json<BlocklistToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    engine.ip_blocklist().set_enabled(body.enabled);
    let count = engine.ip_blocklist().len();

    // Persist blocklist state so it survives restarts
    {
        let store = state.store.lock().await;
        if let Ok(mut settings) = store.get_global_settings() {
            settings.ip_blocklist_enabled = body.enabled;
            let _ = store.update_global_settings(&settings);
        }
    }

    // Notify workers so they apply the new blocklist state
    state.notify_config_changed();

    Ok(json_data(serde_json::json!({
        "enabled": body.enabled,
        "ip_count": count,
    })))
}

/// Fetch and load the blocklist from the remote URL.
/// Shared between the manual reload endpoint and the background task.
pub async fn fetch_and_load_blocklist(
    blocklist: &lorica_waf::IpBlocklist,
) -> Result<usize, String> {
    let url = lorica_waf::ip_blocklist::DEFAULT_BLOCKLIST_URL;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
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
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let engine = state
        .waf_engine
        .as_ref()
        .ok_or_else(|| ApiError::BadRequest("WAF engine not initialized".into()))?;

    let count = fetch_and_load_blocklist(engine.ip_blocklist())
        .await
        .map_err(ApiError::Internal)?;

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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
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
