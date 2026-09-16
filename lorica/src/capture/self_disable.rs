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

//! Disarming a rule that spent its total, off the request path.
//!
//! [`CaptureBudgets::admit`] decides that a rule is finished, under a
//! lock, in the middle of a request. What it does NOT do is write to
//! the configuration store: that is a SQLite `UPDATE` on a file every
//! worker shares, which under a contended WAL blocks for up to the
//! store's busy timeout, and a request must never wait on it.
//!
//! So the request path queues the rule and this task performs the
//! write, on the same shape as the other deferred work in this crate
//! (`spawn_bot_stash_prune`, `spawn_rate_limit_sync`): a ticker
//! registered with the process `TaskTracker`, draining state the hot
//! path only ever appends to, and running the SQL on the blocking pool
//! the way `bot::stash_blocking` does.
//!
//! The rule is disabled, never deleted. An operator who comes back to a
//! rule that stopped on its own must be able to see it, see the audit
//! line that says why, and re-arm it if that is what they want.

use std::sync::Arc;
use std::time::Duration;

use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use super::budgets::{CaptureBudgets, PendingDisable};

/// Audit action recorded when a rule disarms itself.
pub const CAPTURE_AUTO_DISABLED_ACTION: &str = "capture.rule.auto_disabled";

/// How often the task looks for rules that spent their total.
///
/// A rule stops recording the instant its budget is spent, so this
/// interval is only the lag on the STORED flag and the audit line, not
/// on the enforcement. Five seconds keeps an operator's view close to
/// the truth without a ticker that wakes for nothing all day.
pub const CAPTURE_DISABLE_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the task that persists self-disables queued by the budgets.
///
/// `log_store` is this node's audit sink; `None` (single-process boot
/// before the store exists, tests) still logs and still writes the
/// flag, it simply records no audit row.
pub fn spawn_capture_disable_task(
    budgets: Arc<CaptureBudgets>,
    store: Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    tracker: &TaskTracker,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tracker.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate tick
        loop {
            ticker.tick().await;
            for pending in budgets.take_pending_disables() {
                disable_one(&store, log_store.clone(), &pending).await;
            }
        }
    })
}

/// Flip one rule's `enabled` to false and audit it.
async fn disable_one(
    store: &Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    pending: &PendingDisable,
) {
    let guard = Arc::clone(store).lock_owned().await;
    let rule_id = pending.rule_id.clone();
    let written =
        tokio::task::spawn_blocking(move || guard.set_capture_rule_enabled(&rule_id, false)).await;

    match written {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            // A rule deleted between spending its budget and this tick
            // lands here. Nothing to repair: the rule is gone, which is
            // a stronger form of disabled than the one being asked for.
            warn!(
                capture_rule_id = %pending.rule_id,
                error = %e,
                "capture rule spent its total but could not be disabled in the store"
            );
            return;
        }
        Err(e) => {
            warn!(
                capture_rule_id = %pending.rule_id,
                error = %e,
                "capture self-disable write did not run"
            );
            return;
        }
    }

    info!(
        capture_rule_id = %pending.rule_id,
        route_id = %pending.route_id,
        budget = pending.budget,
        limit = pending.limit,
        "capture rule disabled itself after spending its budget"
    );

    lorica_api::audit::record_with_store(
        log_store,
        // The actor is the node, not an operator: no management session
        // is behind a budget running out. The identity mirrors the one
        // the cluster replica handler uses for its own node-side events,
        // so an operator reading the audit log sees the same shape.
        &lorica_api::audit::AuditContext {
            username: "capture".to_string(),
            role: "node".to_string(),
            ip: String::new(),
            user_agent: String::new(),
        },
        CAPTURE_AUTO_DISABLED_ACTION,
        ("capture_rule", &pending.rule_id),
        None,
        Some(&serde_json::json!({
            "rule_id": pending.rule_id,
            "route_id": pending.route_id,
            "budget": pending.budget,
            "limit": pending.limit,
            "enabled": false,
        })),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{
        CaptureEmit, CaptureLimits, CaptureMatch, CaptureOutput, CaptureRedaction, CaptureRule,
        CaptureScope,
    };

    fn stored_rule(id: &str) -> CaptureRule {
        CaptureRule {
            id: id.to_string(),
            name: format!("rule {id}"),
            route_id: "route-1".to_string(),
            enabled: true,
            match_: CaptureMatch::default(),
            emit: CaptureEmit {
                always: true,
                ..CaptureEmit::default()
            },
            capture: CaptureScope::default(),
            limits: CaptureLimits::default(),
            output: CaptureOutput::default(),
            redact: CaptureRedaction::default(),
            created_by: "admin".to_string(),
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            captures_emitted: 0,
            captures_dropped: 0,
        }
    }

    /// A route carrying nothing but its identity, so `capture_rules`
    /// has the `routes(id)` row its foreign key requires.
    fn bare_route(id: &str) -> lorica_config::models::Route {
        let now = chrono::Utc::now();
        lorica_config::models::Route {
            id: id.to_string(),
            hostname: format!("{id}.example.com"),
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
            proxy_headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
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
            slowloris_threshold_ms: 5_000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3_600,
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
            group_name: String::new(),
            node_selector: Vec::new(),
            ai_bot_policy: None,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            created_at: now,
            updated_at: now,
        }
    }

    /// An in-memory store holding one route and one capture rule on it.
    fn store_with_rule(rule: &CaptureRule) -> Arc<Mutex<ConfigStore>> {
        let store = ConfigStore::open_in_memory().expect("test setup: an in-memory store opens");
        store
            .create_route(&bare_route(&rule.route_id))
            .expect("test setup: the route is stored");
        store
            .create_capture_rule(rule)
            .expect("test setup: the capture rule is stored");
        Arc::new(Mutex::new(store))
    }

    #[tokio::test]
    async fn a_queued_disable_clears_the_stored_enabled_flag() {
        let rule = stored_rule("cap-1");
        let store = store_with_rule(&rule);
        disable_one(
            &store,
            None,
            &PendingDisable {
                rule_id: "cap-1".to_string(),
                route_id: "route-1".to_string(),
                budget: "max_captures",
                limit: 100,
            },
        )
        .await;

        let stored = store
            .lock()
            .await
            .get_capture_rule("cap-1")
            .expect("the store answers")
            .expect("the rule is still there");
        assert!(!stored.enabled, "the rule is disarmed, not deleted");
    }

    #[tokio::test]
    async fn a_disable_for_a_rule_that_is_gone_is_survivable() {
        let rule = stored_rule("cap-1");
        let store = store_with_rule(&rule);
        store
            .lock()
            .await
            .delete_capture_rule("cap-1")
            .expect("test setup: the rule is removed");
        disable_one(
            &store,
            None,
            &PendingDisable {
                rule_id: "cap-1".to_string(),
                route_id: "route-1".to_string(),
                budget: "max_captures",
                limit: 100,
            },
        )
        .await;
    }
}
