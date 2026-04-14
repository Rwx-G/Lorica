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

//! DB read/write helpers: flushing completed buckets, evaluating thresholds,
//! and driving the background flush task.

use std::sync::Arc;

use chrono::Utc;
use lorica_config::ConfigStore;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::NotifyDispatcher;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info};

use super::bucket::RouteBucket;
use super::collector::SlaCollector;
use super::helpers::current_bucket_start;

/// Flush all completed (past-minute) buckets to the database.
/// Returns the number of buckets flushed.
pub(super) fn flush(collector: &SlaCollector, store: &ConfigStore) -> usize {
    let now_bucket = current_bucket_start();
    let mut to_flush: Vec<(String, Arc<RouteBucket>)> = Vec::new();

    if let Ok(mut buckets) = collector.buckets.lock() {
        let mut expired_keys = Vec::new();
        for (route_id, bucket) in buckets.iter() {
            if bucket.bucket_start < now_bucket {
                to_flush.push((route_id.clone(), Arc::clone(bucket)));
                expired_keys.push(route_id.clone());
            }
        }
        for key in expired_keys {
            buckets.remove(&key);
        }
    }

    let mut flushed = 0;
    for (route_id, bucket) in &to_flush {
        let mut sla_bucket = bucket.to_sla_bucket();
        sla_bucket.route_id = route_id.clone();

        if sla_bucket.request_count == 0 {
            continue;
        }

        // Stamp the config snapshot so historical reporting is consistent
        if let Ok(configs) = collector.sla_configs.lock() {
            if let Some(config) = configs.get(route_id) {
                sla_bucket.cfg_max_latency_ms = config.max_latency_ms;
                sla_bucket.cfg_status_min = config.success_status_min;
                sla_bucket.cfg_status_max = config.success_status_max;
                sla_bucket.cfg_target_pct = config.target_pct;
            }
        }

        if let Err(e) = store.insert_sla_bucket(&sla_bucket) {
            error!(route_id = %route_id, error = %e, "failed to flush SLA bucket");
        } else {
            debug!(
                route_id = %route_id,
                requests = sla_bucket.request_count,
                success = sla_bucket.success_count,
                "flushed SLA bucket"
            );
            flushed += 1;
        }
    }
    flushed
}

/// Start the background flush task that runs every 60 seconds.
pub(super) fn start_flush_task(
    collector: &Arc<SlaCollector>,
    store: Arc<TokioMutex<ConfigStore>>,
    dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
) -> tokio::task::JoinHandle<()> {
    let collector = Arc::clone(collector);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;

            // Flush buckets while holding the store lock, then release it.
            // Always check thresholds even if this process flushed nothing:
            // in worker mode, workers flush SLA data to the DB and the
            // supervisor must still check thresholds to dispatch alerts.
            let (flushed, alerts) = {
                let store_guard = store.lock().await;
                let flushed = flush(&collector, &store_guard);
                let alerts = if dispatcher.is_some() {
                    check_thresholds(&collector, &store_guard)
                } else {
                    Vec::new()
                };
                (flushed, alerts)
            };
            // store lock is released here

            if flushed > 0 {
                info!(count = flushed, "flushed SLA buckets to database");
            }

            // Dispatch alerts (requires async, no store lock held)
            if !alerts.is_empty() {
                if let Some(ref dispatcher) = dispatcher {
                    let d = dispatcher.lock().await;
                    for event in &alerts {
                        d.dispatch(event).await;
                    }
                }
            }
        }
    })
}

/// Check SLA thresholds and emit alerts only on state transitions:
/// - OK -> breached: emit SlaBreached
/// - breached -> OK: emit SlaRecovered
pub(super) fn check_thresholds(collector: &SlaCollector, store: &ConfigStore) -> Vec<AlertEvent> {
    let now = Utc::now();
    let one_hour_ago = now - chrono::Duration::hours(1);
    let mut alerts = Vec::new();

    let configs = match store.list_sla_configs() {
        Ok(c) => c,
        Err(_) => return alerts,
    };

    let mut breach_state = match collector.breach_state.lock() {
        Ok(s) => s,
        Err(_) => return alerts,
    };

    for config in configs {
        let summary =
            match store.compute_sla_summary(&config.route_id, &one_hour_ago, &now, "1h", "passive")
            {
                Ok(s) => s,
                Err(_) => continue,
            };

        if summary.total_requests == 0 {
            continue;
        }

        let was_breached = *breach_state.get(&config.route_id).unwrap_or(&false);
        let is_breached = !summary.meets_target;

        if is_breached && !was_breached {
            // Transition OK -> breached
            let event = AlertEvent::new(
                AlertType::SlaBreached,
                format!(
                    "SLA breach on route {}: {:.2}% (target: {:.1}%)",
                    config.route_id, summary.sla_pct, config.target_pct
                ),
            )
            .with_detail("route_id", &config.route_id)
            .with_detail("sla_pct", format!("{:.2}", summary.sla_pct))
            .with_detail("target_pct", format!("{:.1}", config.target_pct))
            .with_detail("total_requests", summary.total_requests.to_string());
            alerts.push(event);
        } else if !is_breached && was_breached {
            // Transition breached -> OK
            let event = AlertEvent::new(
                AlertType::SlaRecovered,
                format!(
                    "SLA recovered on route {}: {:.2}% (target: {:.1}%)",
                    config.route_id, summary.sla_pct, config.target_pct
                ),
            )
            .with_detail("route_id", &config.route_id)
            .with_detail("sla_pct", format!("{:.2}", summary.sla_pct))
            .with_detail("target_pct", format!("{:.1}", config.target_pct))
            .with_detail("total_requests", summary.total_requests.to_string());
            alerts.push(event);
        }

        breach_state.insert(config.route_id.clone(), is_breached);
    }
    alerts
}
