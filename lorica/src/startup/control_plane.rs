// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Control-plane background tasks shared by the supervisor and
//! single-process boot paths.
//!
//! Worker mode does NOT call this helper - the workers run a leaner
//! data-plane subset (rDNS init, GeoIP / ASN handle setup, request-bucket
//! pruners) handled separately. The control-plane tasks defined here
//! orchestrate notification delivery, SLA + active-probe state, the IP
//! blocklist refresh, and the access-log / WAF event / probe-result /
//! SLA bucket retention sweep.
//!
//! The caller owns the `TaskTracker` and `AlertSender` because both are
//! needed BEFORE this helper runs (the supervisor wires `alert_sender`
//! into its WAF UDS listener and health-check loop ; both modes use the
//! tracker for shutdown drain). The returned `ControlPlaneHandles`
//! plumb into the API server `AppState` and the role-specific reload
//! listener that follows.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use tokio::sync::Mutex;
use tokio_util::task::TaskTracker;

use lorica_api::log_store::LogStore;
use lorica_bench::{LoadTestEngine, ProbeScheduler, SlaCollector};
use lorica_config::ConfigStore;
use lorica_notify::{AlertEvent, AlertSender, NotifyDispatcher};
use lorica_waf::WafEngine;

/// Handles produced by [`spawn_control_plane_tasks`], to be plumbed into
/// the role-specific API server `AppState` and reload listener.
pub struct ControlPlaneHandles {
    /// Notification dispatcher under tokio mutex so the role-specific
    /// reload listener can rebuild it in place via
    /// `*d = build_notify_dispatcher(&s)` on every config change.
    pub notify_dispatcher: Arc<Mutex<NotifyDispatcher>>,

    /// Recent-alerts ring buffer ; cloned from the dispatcher BEFORE
    /// the `Arc<Mutex<>>` wrap so the API state holds a direct handle
    /// without having to re-lock the dispatcher on every read.
    pub notification_history: Arc<PlMutex<VecDeque<AlertEvent>>>,

    /// Active synthetic probe scheduler. The reload listener calls
    /// `.reload().await` on every config change.
    pub probe_scheduler: Arc<ProbeScheduler>,

    /// Passive SLA collector. Already wired to its own background flush
    /// task (started inside this helper). The reload listener calls
    /// `.load_configs(&s)` on every config change.
    pub sla_collector: Arc<SlaCollector>,

    /// Load-test engine shared by the API server and (when wired) the
    /// cron scheduler.
    pub load_test_engine: Arc<LoadTestEngine>,
}

/// Spawn the control-plane background tasks shared between supervisor
/// and single-process modes.
///
/// Tasks spawned:
/// - IP blocklist auto-refresh (every 6h) tracked by `task_tracker`
/// - Persisted alert dispatcher: `alert_sender` broadcast ->
///   `NotifyDispatcher` + SQLite persistence with retention enforcement
/// - SLA collector flush task
/// - Retention sweep (access-log + probe-result + WAF event + SLA bucket)
///   running every hour, conditional on `log_store.is_some()`
///
/// Role-specific spawns (reload listener, API server, health check loop,
/// cert resolver hot-swap, worker monitor) stay in the caller.
pub async fn spawn_control_plane_tasks(
    store: &Arc<Mutex<ConfigStore>>,
    waf_engine: &Arc<WafEngine>,
    log_store: &Option<Arc<LogStore>>,
    alert_sender: &AlertSender,
    task_tracker: &TaskTracker,
) -> ControlPlaneHandles {
    // IP blocklist auto-refresh (every 6h, matching Data-Shield update freq).
    let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
        Arc::clone(waf_engine),
        Duration::from_secs(6 * 3600),
        task_tracker,
    );

    // Notification dispatcher built from the current settings snapshot.
    let notify_dispatcher = {
        let s = store.lock().await;
        crate::build_notify_dispatcher(&s)
    };
    let notification_history = notify_dispatcher.history();
    let notify_dispatcher = Arc::new(Mutex::new(notify_dispatcher));

    // Bridge: alert_sender (broadcast) -> NotifyDispatcher + DB persistence.
    let _alert_dispatcher = crate::spawn_persisted_alert_dispatcher(
        alert_sender,
        Arc::clone(&notify_dispatcher),
        log_store.clone(),
    );

    // Active synthetic probe scheduler.
    let probe_scheduler = Arc::new(ProbeScheduler::new(
        Arc::clone(store),
        Some(Arc::clone(&notify_dispatcher)),
    ));
    probe_scheduler.reload().await;

    // Passive SLA collector + background flush task.
    let sla_collector = Arc::new(SlaCollector::new());
    {
        let s = store.lock().await;
        sla_collector.load_configs(&s);
    }
    sla_collector.start_flush_task(Arc::clone(store), Some(Arc::clone(&notify_dispatcher)));

    // Load-test engine.
    let load_test_engine = Arc::new(LoadTestEngine::new());

    // Retention sweep: access-log + probe-result + WAF event + SLA bucket.
    // 1h cadence ; defaults match the previous inline implementations.
    if let Some(log_store_handle) = log_store.as_ref() {
        let retention_log_store = Arc::clone(log_store_handle);
        let retention_config_store = Arc::clone(store);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(3600));
            let mut last_sla_purge_day: u32 = 0;
            loop {
                interval.tick().await;
                let retention = {
                    let s = retention_config_store.lock().await;
                    s.get_global_settings()
                        .map(|gs| gs.access_log_retention)
                        .unwrap_or(100_000)
                };
                if retention > 0 {
                    if let Err(e) = retention_log_store.enforce_retention(retention as u64) {
                        tracing::warn!(error = %e, "access log retention cleanup failed");
                    }
                }
                {
                    let s = retention_config_store.lock().await;
                    if let Err(e) = s.purge_probe_results(1000) {
                        tracing::warn!(error = %e, "probe result retention cleanup failed");
                    }
                }
                if let Err(e) = retention_log_store.enforce_waf_retention(100_000) {
                    tracing::warn!(error = %e, "WAF event retention cleanup failed");
                }
                last_sla_purge_day =
                    crate::run_sla_purge(&retention_config_store, last_sla_purge_day).await;
            }
        });
    }

    ControlPlaneHandles {
        notify_dispatcher,
        notification_history,
        probe_scheduler,
        sla_collector,
        load_test_engine,
    }
}
