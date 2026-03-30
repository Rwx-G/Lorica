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

    let (events, rule_count) = if let Some(ref waf_buffer) = state.waf_event_buffer {
        let buf = waf_buffer.lock().unwrap();
        let events: Vec<WafEvent> = buf
            .iter()
            .rev()
            .filter(|e| {
                if let Some(ref cat) = params.category {
                    e.category.as_str() == cat.as_str()
                } else {
                    true
                }
            })
            .take(limit)
            .cloned()
            .collect();
        (events, state.waf_rule_count.unwrap_or(0))
    } else {
        (vec![], 0)
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
            let buf = waf_buffer.lock().unwrap();
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
        let mut buf = waf_buffer.lock().unwrap();
        buf.clear();
    }
    Ok(json_data(serde_json::json!({"cleared": true})))
}
