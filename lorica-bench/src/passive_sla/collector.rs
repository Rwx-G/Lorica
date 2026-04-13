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

//! `SlaCollector` records per-request metrics and drives background flushing
//! / threshold evaluation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use lorica_config::models::SlaConfig;
use lorica_config::ConfigStore;
use lorica_notify::NotifyDispatcher;
use tokio::sync::Mutex as TokioMutex;
use tracing::warn;

use super::bucket::RouteBucket;
use super::helpers::current_bucket_start;
use super::persistence;

/// SLA metrics collector for passive (real traffic) monitoring.
///
/// Records per-request metrics in lock-free atomic counters (hot path),
/// then flushes completed minute-buckets to SQLite via a background task.
pub struct SlaCollector {
    /// Per-route current minute bucket.
    pub(super) buckets: Arc<Mutex<HashMap<String, Arc<RouteBucket>>>>,
    /// Per-route SLA configuration cache.
    pub(super) sla_configs: Arc<Mutex<HashMap<String, SlaConfig>>>,
    /// Per-route breach state for edge-triggered notifications.
    /// `true` means the route is currently in breach.
    pub(super) breach_state: Arc<Mutex<HashMap<String, bool>>>,
}

impl SlaCollector {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            sla_configs: Arc::new(Mutex::new(HashMap::new())),
            breach_state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record a request metric from the proxy logging callback.
    ///
    /// This is called in the hot path - it only touches atomic counters
    /// and a brief mutex for the bucket lookup.
    pub fn record(&self, route_id: &str, status: u16, latency_ms: u64) {
        let bucket_start = current_bucket_start();
        let is_success = self.is_success(route_id, status, latency_ms);

        let bucket = {
            let mut buckets = match self.buckets.lock() {
                Ok(b) => b,
                Err(_) => return,
            };
            let entry = buckets
                .entry(route_id.to_string())
                .or_insert_with(|| Arc::new(RouteBucket::new(bucket_start)));

            // If we've moved to a new minute, the old bucket will be flushed
            // by the background task. Create a new one for the current minute.
            if entry.bucket_start != bucket_start {
                *entry = Arc::new(RouteBucket::new(bucket_start));
            }
            Arc::clone(entry)
        };

        bucket.record(latency_ms, is_success);
    }

    /// Remove all in-memory buckets for a route (after clearing DB data).
    pub fn clear_route(&self, route_id: &str) {
        if let Ok(mut buckets) = self.buckets.lock() {
            buckets.remove(route_id);
        }
    }

    /// Update the cached SLA config for a route.
    pub fn set_sla_config(&self, route_id: &str, config: SlaConfig) {
        if let Ok(mut configs) = self.sla_configs.lock() {
            configs.insert(route_id.to_string(), config);
        }
    }

    /// Load all SLA configs from the store into cache.
    pub fn load_configs(&self, store: &ConfigStore) {
        match store.list_sla_configs() {
            Ok(configs) => {
                if let Ok(mut cache) = self.sla_configs.lock() {
                    cache.clear();
                    for c in configs {
                        cache.insert(c.route_id.clone(), c);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "failed to load SLA configs");
            }
        }
    }

    pub(super) fn is_success(&self, route_id: &str, status: u16, latency_ms: u64) -> bool {
        if let Ok(configs) = self.sla_configs.lock() {
            if let Some(config) = configs.get(route_id) {
                return config.is_success(status, latency_ms);
            }
        }
        SlaConfig::default_for_route(route_id).is_success(status, latency_ms)
    }

    /// Flush all completed (past-minute) buckets to the database.
    /// Returns the number of buckets flushed.
    pub fn flush(&self, store: &ConfigStore) -> usize {
        persistence::flush(self, store)
    }

    /// Start the background flush task that runs every 60 seconds.
    pub fn start_flush_task(
        self: &Arc<Self>,
        store: Arc<TokioMutex<ConfigStore>>,
        dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
    ) -> tokio::task::JoinHandle<()> {
        persistence::start_flush_task(self, store, dispatcher)
    }
}

impl Default for SlaCollector {
    fn default() -> Self {
        Self::new()
    }
}
