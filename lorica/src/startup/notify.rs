// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Notification helpers consumed by the control-plane spawn block.
//!
//! - [`build_notify_dispatcher`] reads every `notification_configs`
//!   row from the store and instantiates the matching channel
//!   (`Email`, `Webhook`, `Slack`) on a fresh `NotifyDispatcher`. Used
//!   at boot AND on every config-reload broadcast (the supervisor and
//!   single-process reload listeners both rebuild the dispatcher in
//!   place when the operator edits a notification channel from the
//!   dashboard).
//! - [`spawn_persisted_alert_dispatcher`] bridges the
//!   `lorica_notify::AlertSender` broadcast onto the dispatcher AND
//!   persists every event to the SQLite log store, with retention
//!   bounded at 500 rows. SQLite writes are off-loaded to
//!   `spawn_blocking` (audit H-7) and surface failures via the
//!   `lorica_notifier_events_dropped_total` counter.
//! - [`run_sla_purge`] runs the once-per-day SLA bucket purge from
//!   inside the hourly retention sweep loop.

use std::sync::Arc;

use chrono::Datelike;
use tokio::sync::Mutex;

/// Spawn alert dispatcher that also persists events to the log store
/// (SQLite). Runs forever ; drops on supervisor / single shutdown when
/// the underlying broadcast channel closes.
pub fn spawn_persisted_alert_dispatcher(
    alert_sender: &lorica_notify::AlertSender,
    dispatcher: Arc<Mutex<lorica_notify::NotifyDispatcher>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = alert_sender.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Dispatch via channels (email, webhook, etc.)
                    let d = dispatcher.lock().await;
                    d.dispatch(&event).await;
                    drop(d);

                    // Persist to log store. Both calls are sync rusqlite under
                    // `parking_lot::Mutex<Connection>` ; running them inline
                    // would block the alert dispatcher's async reactor (audit
                    // H-7). Off-load both to one `spawn_blocking` so the
                    // mutex acquisition + the SELECT COUNT(*) + DELETE pair
                    // happen on the blocking pool, and surface retention
                    // failures via the existing notifier-events-dropped metric
                    // (was a silent `let _ = ...` swallow that left the table
                    // unbounded if DELETE ever failed).
                    if let Some(ref store) = log_store {
                        let store = Arc::clone(store);
                        let event_for_blocking = event.clone();
                        let blocking_outcome = tokio::task::spawn_blocking(move || {
                            let insert = store.insert_notification_event(&event_for_blocking);
                            let retention = store.enforce_notification_retention(500);
                            (insert, retention)
                        })
                        .await;
                        match blocking_outcome {
                            Ok((insert, retention)) => {
                                if let Err(e) = insert {
                                    tracing::warn!(error = %e, "failed to persist notification event");
                                    lorica_api::metrics::inc_notifier_events_dropped("persist_failed", 1);
                                }
                                if let Err(e) = retention {
                                    tracing::warn!(error = %e, "notification retention enforcement failed");
                                    lorica_api::metrics::inc_notifier_events_dropped("retention_failed", 1);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "notification persistence task join failed");
                                lorica_api::metrics::inc_notifier_events_dropped("join_failed", 1);
                            }
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        dropped = n,
                        "alert dispatcher lagged, some notifications were dropped"
                    );
                    lorica_api::metrics::inc_notifier_events_dropped("lag", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    lorica_api::metrics::inc_notifier_events_dropped("closed", 1);
                    break;
                }
            }
        }
    })
}

/// Build a `NotifyDispatcher` from the persisted `notification_configs`
/// rows. Bad JSON in any row is silently skipped (the operator sees
/// the channel disappear from the dashboard ; the rest still wire up).
pub fn build_notify_dispatcher(store: &lorica_config::ConfigStore) -> lorica_notify::NotifyDispatcher {
    let mut dispatcher = lorica_notify::NotifyDispatcher::new();
    if let Ok(configs) = store.list_notification_configs() {
        for nc in configs {
            let config_json = &nc.config;
            match nc.channel {
                lorica_config::models::NotificationChannel::Email => {
                    if let Ok(email_cfg) =
                        serde_json::from_str::<lorica_notify::channels::EmailConfig>(config_json)
                    {
                        dispatcher.add_email_channel(nc.id, email_cfg, nc.alert_types, nc.enabled);
                    }
                }
                lorica_config::models::NotificationChannel::Webhook => {
                    if let Ok(webhook_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_webhook_channel(
                            nc.id,
                            webhook_cfg,
                            nc.alert_types,
                            nc.enabled,
                        );
                    }
                }
                lorica_config::models::NotificationChannel::Slack => {
                    if let Ok(slack_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_slack_channel(nc.id, slack_cfg, nc.alert_types, nc.enabled);
                    }
                }
            }
        }
    }
    dispatcher
}

/// Run the SLA data purge if enabled and the schedule matches today.
/// Returns the day-of-month on which the last purge ran ; the caller
/// uses this as a once-per-day guard inside the hourly retention loop.
pub async fn run_sla_purge(
    store: &Arc<Mutex<lorica_config::ConfigStore>>,
    last_purge_day: u32,
) -> u32 {
    let today = chrono::Utc::now().day();
    if today == last_purge_day {
        return last_purge_day;
    }
    let s = store.lock().await;
    let gs = match s.get_global_settings() {
        Ok(gs) => gs,
        Err(_) => return last_purge_day,
    };
    if !gs.sla_purge_enabled {
        return last_purge_day;
    }
    let should_run = match gs.sla_purge_schedule.as_str() {
        "daily" => true,
        "first_of_month" => today == 1,
        other => other.parse::<u32>().is_ok_and(|d| d == today),
    };
    if !should_run {
        return last_purge_day;
    }
    let cutoff = chrono::Utc::now() - chrono::Duration::days(gs.sla_purge_retention_days as i64);
    match s.prune_sla_buckets(&cutoff) {
        Ok(n) if n > 0 => {
            tracing::info!(
                count = n,
                retention_days = gs.sla_purge_retention_days,
                "purged old SLA buckets"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "SLA purge failed");
        }
        _ => {}
    }
    today
}
