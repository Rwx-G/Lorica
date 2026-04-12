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

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Timelike, Utc};
use lorica_config::models::{SlaBucket, SlaConfig};
use lorica_config::ConfigStore;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::NotifyDispatcher;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};

/// A single in-memory time bucket collecting metrics for one route.
struct RouteBucket {
    bucket_start: DateTime<Utc>,
    request_count: AtomicI64,
    success_count: AtomicI64,
    error_count: AtomicI64,
    latency_sum_ms: AtomicI64,
    latency_min_ms: AtomicI64,
    latency_max_ms: AtomicI64,
    latency_samples: Mutex<Vec<u64>>,
}

impl RouteBucket {
    fn new(bucket_start: DateTime<Utc>) -> Self {
        Self {
            bucket_start,
            request_count: AtomicI64::new(0),
            success_count: AtomicI64::new(0),
            error_count: AtomicI64::new(0),
            latency_sum_ms: AtomicI64::new(0),
            latency_min_ms: AtomicI64::new(i64::MAX),
            latency_max_ms: AtomicI64::new(0),
            latency_samples: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, latency_ms: u64, is_success: bool) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if is_success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_ms
            .fetch_add(latency_ms as i64, Ordering::Relaxed);

        // Update min (atomic CAS loop)
        let mut current = self.latency_min_ms.load(Ordering::Relaxed);
        let new_val = latency_ms as i64;
        while new_val < current {
            match self.latency_min_ms.compare_exchange_weak(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        // Update max
        let mut current = self.latency_max_ms.load(Ordering::Relaxed);
        while new_val > current {
            match self.latency_max_ms.compare_exchange_weak(
                current,
                new_val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }

        if let Ok(mut samples) = self.latency_samples.lock() {
            samples.push(latency_ms);
        }
    }

    fn to_sla_bucket(&self) -> SlaBucket {
        let request_count = self.request_count.load(Ordering::Relaxed);
        let min_ms = self.latency_min_ms.load(Ordering::Relaxed);
        let max_ms = self.latency_max_ms.load(Ordering::Relaxed);

        let (p50, p95, p99) = if let Ok(mut samples) = self.latency_samples.lock() {
            compute_percentiles(&mut samples)
        } else {
            (0, 0, 0)
        };

        SlaBucket {
            id: None,
            route_id: String::new(), // Set by caller
            bucket_start: self.bucket_start,
            request_count,
            success_count: self.success_count.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            latency_sum_ms: self.latency_sum_ms.load(Ordering::Relaxed),
            latency_min_ms: if request_count > 0 { min_ms } else { 0 },
            latency_max_ms: max_ms,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            source: "passive".to_string(),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        }
    }
}

/// Compute p50, p95, p99 from a mutable sample vec (sorts in place).
pub fn compute_percentiles(samples: &mut [u64]) -> (i64, i64, i64) {
    if samples.is_empty() {
        return (0, 0, 0);
    }
    samples.sort_unstable();
    let len = samples.len();
    let p50 = samples[len * 50 / 100] as i64;
    let p95 = samples[len * 95 / 100] as i64;
    let p99 = samples[std::cmp::min(len * 99 / 100, len - 1)] as i64;
    (p50, p95, p99)
}

/// Current minute bucket start (truncated to minute boundary).
fn current_bucket_start() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_nanosecond(0).unwrap().with_second(0).unwrap()
}

/// SLA metrics collector for passive (real traffic) monitoring.
///
/// Records per-request metrics in lock-free atomic counters (hot path),
/// then flushes completed minute-buckets to SQLite via a background task.
pub struct SlaCollector {
    /// Per-route current minute bucket.
    buckets: Arc<Mutex<HashMap<String, Arc<RouteBucket>>>>,
    /// Per-route SLA configuration cache.
    sla_configs: Arc<Mutex<HashMap<String, SlaConfig>>>,
    /// Per-route breach state for edge-triggered notifications.
    /// `true` means the route is currently in breach.
    breach_state: Arc<Mutex<HashMap<String, bool>>>,
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

    fn is_success(&self, route_id: &str, status: u16, latency_ms: u64) -> bool {
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
        let now_bucket = current_bucket_start();
        let mut to_flush: Vec<(String, Arc<RouteBucket>)> = Vec::new();

        if let Ok(mut buckets) = self.buckets.lock() {
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
            if let Ok(configs) = self.sla_configs.lock() {
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
    pub fn start_flush_task(
        self: &Arc<Self>,
        store: Arc<TokioMutex<ConfigStore>>,
        dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
    ) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(self);
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
                    let flushed = collector.flush(&store_guard);
                    let alerts = if dispatcher.is_some() {
                        collector.check_thresholds(&store_guard)
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
    fn check_thresholds(&self, store: &ConfigStore) -> Vec<AlertEvent> {
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let mut alerts = Vec::new();

        let configs = match store.list_sla_configs() {
            Ok(c) => c,
            Err(_) => return alerts,
        };

        let mut breach_state = match self.breach_state.lock() {
            Ok(s) => s,
            Err(_) => return alerts,
        };

        for config in configs {
            let summary = match store.compute_sla_summary(
                &config.route_id,
                &one_hour_ago,
                &now,
                "1h",
                "passive",
            ) {
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
}

impl Default for SlaCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_percentiles_empty() {
        let mut samples: Vec<u64> = vec![];
        assert_eq!(compute_percentiles(&mut samples), (0, 0, 0));
    }

    #[test]
    fn test_compute_percentiles_single() {
        let mut samples = vec![42];
        assert_eq!(compute_percentiles(&mut samples), (42, 42, 42));
    }

    #[test]
    fn test_compute_percentiles_distribution() {
        let mut samples: Vec<u64> = (1..=100).collect();
        let (p50, p95, p99) = compute_percentiles(&mut samples);
        assert_eq!(p50, 51); // index 50 in 0-based = value 51
        assert_eq!(p95, 96);
        assert_eq!(p99, 100);
    }

    #[test]
    fn test_route_bucket_record_success() {
        let bucket = RouteBucket::new(Utc::now());
        bucket.record(100, true);
        bucket.record(200, true);
        bucket.record(150, false);

        assert_eq!(bucket.request_count.load(Ordering::Relaxed), 3);
        assert_eq!(bucket.success_count.load(Ordering::Relaxed), 2);
        assert_eq!(bucket.error_count.load(Ordering::Relaxed), 1);
        assert_eq!(bucket.latency_sum_ms.load(Ordering::Relaxed), 450);
        assert_eq!(bucket.latency_min_ms.load(Ordering::Relaxed), 100);
        assert_eq!(bucket.latency_max_ms.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_route_bucket_to_sla_bucket() {
        let bucket = RouteBucket::new(Utc::now());
        bucket.record(10, true);
        bucket.record(20, true);
        bucket.record(30, false);

        let sla = bucket.to_sla_bucket();
        assert_eq!(sla.request_count, 3);
        assert_eq!(sla.success_count, 2);
        assert_eq!(sla.error_count, 1);
        assert_eq!(sla.latency_sum_ms, 60);
        assert_eq!(sla.latency_min_ms, 10);
        assert_eq!(sla.latency_max_ms, 30);
        assert_eq!(sla.source, "passive");
    }

    #[test]
    fn test_collector_record_and_flush() {
        let collector = SlaCollector::new();
        let store = ConfigStore::open_in_memory().unwrap();

        // Record some metrics
        collector.record("route-1", 200, 50);
        collector.record("route-1", 200, 100);
        collector.record("route-1", 500, 200);
        collector.record("route-2", 200, 30);

        // Flush won't write current-minute buckets (they're not complete yet).
        // So we expect 0 flushed for the current minute.
        let flushed = collector.flush(&store);
        assert_eq!(flushed, 0, "current-minute buckets should not flush");
    }

    #[test]
    fn test_collector_default_success_criteria() {
        let collector = SlaCollector::new();
        assert!(collector.is_success("any", 200, 100));
        assert!(collector.is_success("any", 301, 400));
        assert!(collector.is_success("any", 404, 100)); // 4xx client errors are not backend failures
        assert!(collector.is_success("any", 499, 100));
        assert!(!collector.is_success("any", 500, 100));
        assert!(!collector.is_success("any", 200, 600));
    }

    #[test]
    fn test_collector_custom_success_criteria() {
        let collector = SlaCollector::new();
        let config = SlaConfig {
            route_id: "r1".to_string(),
            target_pct: 99.0,
            max_latency_ms: 200,
            success_status_min: 200,
            success_status_max: 299,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        collector.set_sla_config("r1", config);

        assert!(collector.is_success("r1", 200, 100));
        assert!(!collector.is_success("r1", 301, 100)); // 3xx not in range
        assert!(!collector.is_success("r1", 200, 300)); // too slow
    }

    #[test]
    fn test_sla_config_is_success() {
        let config = SlaConfig::default_for_route("r1");
        assert!(config.is_success(200, 100));
        assert!(config.is_success(399, 500));
        assert!(config.is_success(404, 100)); // 4xx within 200-499 default
        assert!(config.is_success(499, 100));
        assert!(!config.is_success(500, 100)); // 5xx = real backend error
        assert!(!config.is_success(200, 501)); // exceeds max_latency_ms
    }

    #[test]
    fn test_current_bucket_start_truncated() {
        let bs = current_bucket_start();
        assert_eq!(bs.second(), 0);
        assert_eq!(bs.nanosecond(), 0);
    }

    #[test]
    fn test_store_sla_bucket_insert_and_query() {
        let store = ConfigStore::open_in_memory().unwrap();

        // Create a route first (FK constraint)
        let route = lorica_config::models::Route {
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
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let now = current_bucket_start();
        let bucket = SlaBucket {
            id: None,
            route_id: "r1".to_string(),
            bucket_start: now,
            request_count: 100,
            success_count: 95,
            error_count: 5,
            latency_sum_ms: 5000,
            latency_min_ms: 10,
            latency_max_ms: 200,
            latency_p50_ms: 40,
            latency_p95_ms: 150,
            latency_p99_ms: 190,
            source: "passive".to_string(),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        };
        store.insert_sla_bucket(&bucket).unwrap();

        let from = now - chrono::Duration::minutes(1);
        let to = now + chrono::Duration::minutes(1);
        let buckets = store
            .query_sla_buckets("r1", &from, &to, "passive")
            .unwrap();
        assert_eq!(buckets.len(), 1);
        assert_eq!(buckets[0].request_count, 100);
        assert_eq!(buckets[0].success_count, 95);
        assert_eq!(buckets[0].latency_p50_ms, 40);
    }

    #[test]
    fn test_store_sla_summary() {
        let store = ConfigStore::open_in_memory().unwrap();

        let route = lorica_config::models::Route {
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
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let now = current_bucket_start();
        for i in 0..3 {
            let bucket = SlaBucket {
                id: None,
                route_id: "r1".to_string(),
                bucket_start: now - chrono::Duration::minutes(i),
                request_count: 100,
                success_count: 99,
                error_count: 1,
                latency_sum_ms: 5000,
                latency_min_ms: 10,
                latency_max_ms: 200,
                latency_p50_ms: 40,
                latency_p95_ms: 150,
                latency_p99_ms: 190,
                source: "passive".to_string(),
                cfg_max_latency_ms: 500,
                cfg_status_min: 200,
                cfg_status_max: 399,
                cfg_target_pct: 99.9,
            };
            store.insert_sla_bucket(&bucket).unwrap();
        }

        let from = now - chrono::Duration::hours(1);
        let to = now + chrono::Duration::minutes(1);
        let summary = store
            .compute_sla_summary("r1", &from, &to, "1h", "passive")
            .unwrap();
        assert_eq!(summary.total_requests, 300);
        assert_eq!(summary.successful_requests, 297);
        assert!((summary.sla_pct - 99.0).abs() < 0.01);
        assert!(!summary.meets_target); // 99.0% < 99.9% default target
    }

    #[test]
    fn test_store_sla_summary_no_data() {
        let store = ConfigStore::open_in_memory().unwrap();
        let now = Utc::now();
        let from = now - chrono::Duration::hours(1);
        let summary = store
            .compute_sla_summary("nonexistent", &from, &now, "1h", "passive")
            .unwrap();
        assert_eq!(summary.total_requests, 0);
        assert_eq!(summary.sla_pct, 0.0);
        assert!(!summary.meets_target);
    }

    #[test]
    fn test_store_prune_buckets() {
        let store = ConfigStore::open_in_memory().unwrap();

        let route = lorica_config::models::Route {
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
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let now = current_bucket_start();
        let old = now - chrono::Duration::days(31);
        let recent = now - chrono::Duration::hours(1);

        for (start, suffix) in [(old, "old"), (recent, "recent")] {
            let bucket = SlaBucket {
                id: None,
                route_id: "r1".to_string(),
                bucket_start: start,
                request_count: 10,
                success_count: 10,
                error_count: 0,
                latency_sum_ms: 100,
                latency_min_ms: 5,
                latency_max_ms: 20,
                latency_p50_ms: 10,
                latency_p95_ms: 18,
                latency_p99_ms: 19,
                source: format!("passive_{suffix}"),
                cfg_max_latency_ms: 500,
                cfg_status_min: 200,
                cfg_status_max: 399,
                cfg_target_pct: 99.9,
            };
            // Use different source to avoid UNIQUE constraint
            store.insert_sla_bucket(&bucket).unwrap();
        }

        let cutoff = now - chrono::Duration::days(30);
        let pruned = store.prune_sla_buckets(&cutoff).unwrap();
        assert_eq!(pruned, 1);
    }

    #[test]
    fn test_store_sla_config_upsert_and_get() {
        let store = ConfigStore::open_in_memory().unwrap();

        let route = lorica_config::models::Route {
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
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        // Default config (no row in DB)
        let config = store.get_sla_config("r1").unwrap();
        assert_eq!(config.target_pct, 99.9);
        assert_eq!(config.max_latency_ms, 500);

        // Custom config
        let mut custom = SlaConfig::default_for_route("r1");
        custom.target_pct = 99.5;
        custom.max_latency_ms = 200;
        store.upsert_sla_config(&custom).unwrap();

        let config = store.get_sla_config("r1").unwrap();
        assert_eq!(config.target_pct, 99.5);
        assert_eq!(config.max_latency_ms, 200);
    }

    #[test]
    fn test_store_export_sla_data() {
        let store = ConfigStore::open_in_memory().unwrap();

        let route = lorica_config::models::Route {
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
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: vec![],
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: vec![],
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: vec![],
            header_rules: vec![],
            traffic_splits: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_route(&route).unwrap();

        let now = current_bucket_start();
        let bucket = SlaBucket {
            id: None,
            route_id: "r1".to_string(),
            bucket_start: now,
            request_count: 50,
            success_count: 48,
            error_count: 2,
            latency_sum_ms: 2500,
            latency_min_ms: 10,
            latency_max_ms: 200,
            latency_p50_ms: 40,
            latency_p95_ms: 150,
            latency_p99_ms: 190,
            source: "passive".to_string(),
            cfg_max_latency_ms: 500,
            cfg_status_min: 200,
            cfg_status_max: 399,
            cfg_target_pct: 99.9,
        };
        store.insert_sla_bucket(&bucket).unwrap();

        let from = now - chrono::Duration::hours(1);
        let to = now + chrono::Duration::hours(1);
        let export = store.export_sla_data("r1", &from, &to).unwrap();
        assert_eq!(export["route_id"], "r1");
        assert!(export["buckets"].is_array());
        assert_eq!(export["buckets"].as_array().unwrap().len(), 1);
    }
}
