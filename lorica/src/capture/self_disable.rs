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

//! The store writes a capture admission owes, off the request path:
//! the per-rule counters, and disarming a rule that spent its total.
//!
//! [`CaptureBudgets::admit`] decides both, under a lock, in the middle
//! of a request. What it does NOT do is write to the configuration
//! store: that is a SQLite `UPDATE` on a file every worker shares,
//! which under a contended WAL blocks for up to the store's busy
//! timeout, and a request must never wait on it.
//!
//! So the request path queues and this task performs the writes, on
//! the same shape as the other deferred work in this crate
//! (`spawn_bot_stash_prune`, `spawn_rate_limit_sync`): a ticker
//! registered with the process `TaskTracker`, draining state the hot
//! path only ever appends to, and running the SQL on the blocking pool
//! the way `bot::stash_blocking` does. Every tick, the counters are
//! flushed first (one `UPDATE` per rule with something to add, under
//! one store lock) and the disables second, so a rule's stored
//! `captures_emitted` already equals its `max_captures` by the time its
//! `enabled` flag is cleared.
//!
//! The same tick also retires rules past their `expires_at` (Story
//! 10.1 AC #5). The compiled rule set already drops an expired rule
//! from the candidates, so nothing is recorded past the deadline; what
//! this sweep adds is the stored `enabled = false` and the audit line,
//! so the listing tells the operator the rule stopped and why. The
//! sweep runs on a standalone node or a control plane and never on a
//! follower: a follower's rules arrive by replication, and the control
//! plane's own sweep replicates the cleared flag to the fleet.
//!
//! The rule is disabled, never deleted. An operator who comes back to a
//! rule that stopped on its own must be able to see it, see the audit
//! line that says why, and re-arm it if that is what they want.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_config::models::CaptureRule;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use super::rule_budgets::{CaptureBudgets, PendingCounters, PendingDisable};

/// Audit action recorded when a rule disarms itself.
pub const CAPTURE_AUTO_DISABLED_ACTION: &str = "capture.rule.auto_disabled";

/// The `budget` value the audit payload carries when a rule stopped
/// because its `expires_at` passed rather than because a count or a
/// rate was spent.
pub const CAPTURE_EXPIRED_BUDGET: &str = "expired";

/// How often the task flushes counters and looks for rules that spent
/// their total or passed their expiry.
///
/// A rule stops recording the instant its budget is spent or its
/// deadline passes, so this interval is only the lag on the STORED
/// counters, flag and audit line, not on the enforcement. Five seconds
/// keeps an operator's view close to the truth without a ticker that
/// wakes for nothing all day.
pub const CAPTURE_DISABLE_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the task that persists the counters, the self-disables queued
/// by the budgets, and the expiry sweep.
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
            flush_counters(&store, budgets.take_pending_counters()).await;
            for pending in budgets.take_pending_disables() {
                disable_one(&store, log_store.clone(), &pending).await;
            }
            disable_expired(&store, log_store.clone(), Utc::now()).await;
        }
    })
}

/// Clear `enabled` on every armed rule whose `expires_at` is at or
/// before `now`, and audit each one, unless this node is a follower.
///
/// Returns the ids disabled, so a test can tell "nothing was due"
/// from "the sweep did not run". The role is read on every tick from
/// the stored identity rather than once at spawn, the way the
/// environment reaper does it, so a node that joins a fleet after boot
/// stops sweeping without a restart. A read failure counts as a
/// follower: disabling on a node whose role is unknown is the worse
/// mistake, and the next tick reads again.
pub async fn disable_expired(
    store: &Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    now: DateTime<Utc>,
) -> Vec<String> {
    let guard = Arc::clone(store).lock_owned().await;
    let swept = tokio::task::spawn_blocking(move || -> Result<Vec<CaptureRule>, String> {
        if guard.is_follower() {
            return Ok(Vec::new());
        }
        let mut expired = Vec::new();
        // The store answers with the armed rules that are already past
        // their expiry, through `idx_capture_rules_expires_at`. On a
        // node with nothing due, which is nearly every one of these
        // five-second ticks, that is an index probe rather than a scan
        // of the table and a JSON decode of every rule on it.
        for rule in guard
            .list_capture_rules_expiring_before(now)
            .map_err(|e| format!("capture rules unreadable: {e}"))?
        {
            match guard.set_capture_rule_enabled(&rule.id, false) {
                Ok(()) => expired.push(rule),
                Err(e) => warn!(
                    capture_rule_id = %rule.id,
                    error = %e,
                    "expired capture rule could not be disabled in the store"
                ),
            }
        }
        Ok(expired)
    })
    .await;

    let expired = match swept {
        Ok(Ok(expired)) => expired,
        Ok(Err(e)) => {
            warn!(error = %e, "capture expiry sweep skipped this tick");
            return Vec::new();
        }
        Err(e) => {
            warn!(error = %e, "capture expiry sweep did not run");
            return Vec::new();
        }
    };

    let mut ids = Vec::with_capacity(expired.len());
    for rule in expired {
        info!(
            capture_rule_id = %rule.id,
            route_id = %rule.route_id,
            expires_at = %rule.expires_at.to_rfc3339(),
            "capture rule disabled itself after its expiry passed"
        );
        audit_auto_disable(
            log_store.clone(),
            &rule.id,
            &serde_json::json!({
                "rule_id": rule.id,
                "route_id": rule.route_id,
                "budget": CAPTURE_EXPIRED_BUDGET,
                "expires_at": rule.expires_at.to_rfc3339(),
                "enabled": false,
            }),
        )
        .await;
        ids.push(rule.id);
    }
    ids
}

/// Add every rule's pending deltas to its stored counters, under one
/// store lock.
///
/// A rule that is gone by now is not an error: the store's bump is a
/// no-op on a missing row, by design, because a flush racing a delete
/// is routine. What is logged is a store that could not run the
/// statement at all.
async fn flush_counters(store: &Arc<Mutex<ConfigStore>>, pending: Vec<PendingCounters>) {
    if pending.is_empty() {
        return;
    }
    let guard = Arc::clone(store).lock_owned().await;
    let written = tokio::task::spawn_blocking(move || {
        for counters in &pending {
            if let Err(e) =
                guard.bump_capture_counters(&counters.rule_id, counters.emitted, counters.dropped)
            {
                warn!(
                    capture_rule_id = %counters.rule_id,
                    error = %e,
                    "capture counters could not be written to the store"
                );
            }
        }
    })
    .await;
    if let Err(e) = written {
        warn!(error = %e, "capture counter flush did not run");
    }
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

    audit_auto_disable(
        log_store,
        &pending.rule_id,
        &serde_json::json!({
            "rule_id": pending.rule_id,
            "route_id": pending.route_id,
            "budget": pending.budget,
            "limit": pending.limit,
            "enabled": false,
        }),
    )
    .await;
}

/// Record the [`CAPTURE_AUTO_DISABLED_ACTION`] row for one rule.
///
/// The actor is the node, not an operator: no management session is
/// behind a budget running out or a deadline passing, which is what
/// [`lorica_api::audit::AuditContext::node`] spells for every
/// background actor.
async fn audit_auto_disable(
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    rule_id: &str,
    payload: &serde_json::Value,
) {
    lorica_api::audit::record_with_store(
        log_store,
        &lorica_api::audit::AuditContext::node("capture"),
        CAPTURE_AUTO_DISABLED_ACTION,
        ("capture_rule", rule_id),
        None,
        Some(payload),
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
            managed_by: None,
            waf_body_scan_max_bytes: None,
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
    async fn flushed_counters_add_to_the_stored_totals_per_rule() {
        let rule = stored_rule("cap-1");
        let store = store_with_rule(&rule);
        flush_counters(
            &store,
            vec![PendingCounters {
                rule_id: "cap-1".to_string(),
                emitted: 3,
                dropped: 2,
            }],
        )
        .await;
        flush_counters(
            &store,
            vec![PendingCounters {
                rule_id: "cap-1".to_string(),
                emitted: 1,
                dropped: 0,
            }],
        )
        .await;

        let stored = store
            .lock()
            .await
            .get_capture_rule("cap-1")
            .expect("the store answers")
            .expect("the rule is still there");
        assert_eq!(stored.captures_emitted, 4);
        assert_eq!(stored.captures_dropped, 2);
        assert!(stored.enabled, "a counter flush does not touch the flag");
    }

    #[tokio::test]
    async fn a_counter_flush_for_a_rule_that_is_gone_is_survivable() {
        let rule = stored_rule("cap-1");
        let store = store_with_rule(&rule);
        store
            .lock()
            .await
            .delete_capture_rule("cap-1")
            .expect("test setup: the rule is removed");
        flush_counters(
            &store,
            vec![PendingCounters {
                rule_id: "cap-1".to_string(),
                emitted: 1,
                dropped: 0,
            }],
        )
        .await;
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

    // ---- the expiry sweep (Story 10.1 AC #5) ----

    /// An audit store in a plain unique directory: `lorica` does not
    /// depend on tempfile.
    fn audit_store(label: &str) -> Arc<lorica_api::log_store::LogStore> {
        let dir = std::env::temp_dir().join(format!(
            "lorica-capture-expiry-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("test setup: temp dir");
        Arc::new(lorica_api::log_store::LogStore::open(&dir).expect("test setup: log store opens"))
    }

    async fn stored_enabled(store: &Arc<Mutex<ConfigStore>>, id: &str) -> bool {
        store
            .lock()
            .await
            .get_capture_rule(id)
            .expect("the store answers")
            .expect("the rule is still there")
            .enabled
    }

    #[tokio::test]
    async fn an_enabled_rule_past_its_expiry_is_disabled_and_audited_on_the_next_tick() {
        let mut rule = stored_rule("cap-1");
        rule.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        let store = store_with_rule(&rule);
        let log_store = audit_store("expired");

        let disabled =
            disable_expired(&store, Some(Arc::clone(&log_store)), chrono::Utc::now()).await;
        assert_eq!(disabled, vec!["cap-1".to_string()]);
        assert!(
            !stored_enabled(&store, "cap-1").await,
            "the rule is disarmed, not deleted"
        );

        // `record_with_store` only enqueues the row; the flush is what
        // makes the read below deterministic.
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");
        let (rows, _) = log_store
            .query_audit(&lorica_api::audit::AuditQuery {
                action_prefix: Some(CAPTURE_AUTO_DISABLED_ACTION.to_string()),
                limit: 10,
                ..lorica_api::audit::AuditQuery::default()
            })
            .expect("audit read");
        assert_eq!(rows.len(), 1, "exactly one auto-disable audit row");
        assert_eq!(rows[0].target_type, "capture_rule");
        assert_eq!(rows[0].target_id, "cap-1");
        assert_eq!(rows[0].operator_username, "capture");
        // The stored row carries the payload's hash, so the payload
        // that says `budget: "expired"` is what the hash must match.
        let expected = serde_json::json!({
            "rule_id": "cap-1",
            "route_id": "route-1",
            "budget": CAPTURE_EXPIRED_BUDGET,
            "expires_at": rule.expires_at.to_rfc3339(),
            "enabled": false,
        });
        assert_eq!(
            rows[0].after_payload_hash,
            lorica_api::audit::hash_payload(Some(&expected))
        );

        // The next tick has nothing left to do.
        let again = disable_expired(&store, Some(log_store), chrono::Utc::now()).await;
        assert!(again.is_empty());
    }

    #[tokio::test]
    async fn a_rule_not_yet_expired_is_untouched() {
        let rule = stored_rule("cap-1");
        let store = store_with_rule(&rule);

        let disabled = disable_expired(&store, None, chrono::Utc::now()).await;
        assert!(disabled.is_empty());
        assert!(stored_enabled(&store, "cap-1").await);
    }

    #[tokio::test]
    async fn a_follower_identity_makes_the_expiry_sweep_a_no_op() {
        let mut rule = stored_rule("cap-1");
        rule.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        let store = store_with_rule(&rule);
        let now = chrono::Utc::now();
        store
            .lock()
            .await
            .set_cluster_identity(&lorica_config::models::ClusterIdentity {
                node_id: "00000000-0000-4000-8000-000000000001".to_string(),
                node_name: "follower01".to_string(),
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_pem: String::new(),
                control_plane: "cp.internal:9444".to_string(),
                server_name: "cp.internal".to_string(),
                enrolled_at: now,
                cert_not_after: now + chrono::Duration::days(90),
            })
            .expect("test setup: identity write");

        let disabled = disable_expired(&store, None, now).await;
        assert!(disabled.is_empty());
        assert!(
            stored_enabled(&store, "cap-1").await,
            "a follower waits for the control plane's replicated flag"
        );
    }
}
