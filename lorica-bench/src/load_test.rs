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

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica_config::models::{
    LoadTestComparison, LoadTestConfig, LoadTestResult, SAFE_LIMIT_CONCURRENCY,
    SAFE_LIMIT_DURATION_S, SAFE_LIMIT_RPS,
};
use lorica_config::store::new_id;
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::Mutex as TokioMutex;
use tracing::{info, warn};

/// Real-time snapshot of a running load test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestProgress {
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub current_rps: f64,
    pub avg_latency_ms: f64,
    pub error_rate_pct: f64,
    pub elapsed_s: f64,
    pub active: bool,
    pub aborted: bool,
    pub abort_reason: Option<String>,
}

/// Shared state for a running load test.
struct RunState {
    total: AtomicI64,
    success: AtomicI64,
    failed: AtomicI64,
    latency_sum_ms: AtomicU64,
    latency_min_ms: AtomicI64,
    latency_max_ms: AtomicI64,
    latency_samples: Mutex<Vec<u64>>,
    aborted: AtomicBool,
    abort_reason: Mutex<Option<String>>,
    started_at: Instant,
}

impl RunState {
    fn new() -> Self {
        Self {
            total: AtomicI64::new(0),
            success: AtomicI64::new(0),
            failed: AtomicI64::new(0),
            latency_sum_ms: AtomicU64::new(0),
            latency_min_ms: AtomicI64::new(i64::MAX),
            latency_max_ms: AtomicI64::new(0),
            latency_samples: Mutex::new(Vec::new()),
            aborted: AtomicBool::new(false),
            abort_reason: Mutex::new(None),
            started_at: Instant::now(),
        }
    }

    fn record(&self, latency_ms: u64, success: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_ms.fetch_add(latency_ms, Ordering::Relaxed);

        let val = latency_ms as i64;
        let mut current = self.latency_min_ms.load(Ordering::Relaxed);
        while val < current {
            match self.latency_min_ms.compare_exchange_weak(
                current,
                val,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let mut current = self.latency_max_ms.load(Ordering::Relaxed);
        while val > current {
            match self.latency_max_ms.compare_exchange_weak(
                current,
                val,
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

    fn progress(&self) -> LoadTestProgress {
        let total = self.total.load(Ordering::Relaxed);
        let success = self.success.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        let elapsed = self.started_at.elapsed().as_secs_f64();
        let latency_sum = self.latency_sum_ms.load(Ordering::Relaxed) as f64;

        LoadTestProgress {
            total_requests: total,
            successful_requests: success,
            failed_requests: failed,
            current_rps: if elapsed > 0.0 {
                total as f64 / elapsed
            } else {
                0.0
            },
            avg_latency_ms: if total > 0 {
                latency_sum / total as f64
            } else {
                0.0
            },
            error_rate_pct: if total > 0 {
                (failed as f64 / total as f64) * 100.0
            } else {
                0.0
            },
            elapsed_s: elapsed,
            active: !self.aborted.load(Ordering::Relaxed),
            aborted: self.aborted.load(Ordering::Relaxed),
            abort_reason: self.abort_reason.lock().ok().and_then(|r| r.clone()),
        }
    }

    fn abort(&self, reason: &str) {
        self.aborted.store(true, Ordering::Relaxed);
        if let Ok(mut r) = self.abort_reason.lock() {
            *r = Some(reason.to_string());
        }
    }
}

/// Dynamic safe limits, read from GlobalSettings.
pub struct SafeLimits {
    pub max_concurrency: i32,
    pub max_duration_s: i32,
    pub max_rps: i32,
}

impl Default for SafeLimits {
    fn default() -> Self {
        Self {
            max_concurrency: SAFE_LIMIT_CONCURRENCY,
            max_duration_s: SAFE_LIMIT_DURATION_S,
            max_rps: SAFE_LIMIT_RPS,
        }
    }
}

impl SafeLimits {
    pub fn from_settings(settings: &lorica_config::models::GlobalSettings) -> Self {
        Self {
            max_concurrency: settings.loadtest_max_concurrency,
            max_duration_s: settings.loadtest_max_duration_s,
            max_rps: settings.loadtest_max_rps,
        }
    }
}

/// Check if a load test configuration exceeds safe limits.
pub fn exceeds_safe_limits(config: &LoadTestConfig, limits: &SafeLimits) -> bool {
    config.concurrency > limits.max_concurrency
        || config.duration_s > limits.max_duration_s
        || config.requests_per_second > limits.max_rps
}

/// Describes which limits are exceeded.
pub fn describe_exceeded_limits(config: &LoadTestConfig, limits: &SafeLimits) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.concurrency > limits.max_concurrency {
        warnings.push(format!(
            "concurrency {} exceeds safe limit {}",
            config.concurrency, limits.max_concurrency
        ));
    }
    if config.duration_s > limits.max_duration_s {
        warnings.push(format!(
            "duration {}s exceeds safe limit {}s",
            config.duration_s, limits.max_duration_s
        ));
    }
    if config.requests_per_second > limits.max_rps {
        warnings.push(format!(
            "rps {} exceeds safe limit {}",
            config.requests_per_second, limits.max_rps
        ));
    }
    warnings
}

/// Load test engine that generates HTTP traffic against a target.
pub struct LoadTestEngine {
    http_client: reqwest::Client,
    current_run: TokioMutex<Option<Arc<RunState>>>,
}

impl LoadTestEngine {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .pool_max_idle_per_host(200)
            .build()
            .unwrap_or_default();

        Self {
            http_client,
            current_run: TokioMutex::new(None),
        }
    }

    /// Check if a load test is currently running.
    pub async fn is_running(&self) -> bool {
        self.current_run.lock().await.is_some()
    }

    /// Get current progress of the running test.
    pub async fn progress(&self) -> Option<LoadTestProgress> {
        let guard = self.current_run.lock().await;
        guard.as_ref().map(|state| state.progress())
    }

    /// Abort the currently running test.
    pub async fn abort(&self) {
        let guard = self.current_run.lock().await;
        if let Some(ref state) = *guard {
            state.abort("user requested abort");
        }
    }

    /// Execute a load test and return the result.
    pub async fn run(
        &self,
        config: &LoadTestConfig,
        store: &Arc<TokioMutex<ConfigStore>>,
    ) -> LoadTestResult {
        let state = Arc::new(RunState::new());

        // Set as current run
        {
            let mut guard = self.current_run.lock().await;
            *guard = Some(Arc::clone(&state));
        }

        let started_at = Utc::now();
        let duration = Duration::from_secs(config.duration_s.max(1) as u64);
        let error_threshold = config.error_threshold_pct;

        // Build a per-run client that resolves the target hostname to 127.0.0.1.
        // This ensures HTTPS requests use the correct SNI (hostname) while the
        // traffic stays local (loopback). Without this, https://127.0.0.1 would
        // send SNI=127.0.0.1 which doesn't match any certificate.
        let run_client = {
            let mut builder = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .pool_max_idle_per_host(200);
            if let Ok(url) = reqwest::Url::parse(&config.target_url) {
                if let Some(host) = url.host_str() {
                    let port = url.port_or_known_default().unwrap_or(80);
                    let dest = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                    builder = builder.resolve(host, dest);
                }
            }
            builder.build().unwrap_or_else(|_| self.http_client.clone())
        };

        info!(
            name = %config.name,
            target = %config.target_url,
            concurrency = config.concurrency,
            rps = config.requests_per_second,
            duration_s = config.duration_s,
            "starting load test"
        );

        // Spawn CPU circuit breaker monitor (aborts if CPU > 90% for 3 checks)
        let cpu_state = Arc::clone(&state);
        let cpu_monitor = tokio::spawn(async move {
            let mut sys = System::new();
            let mut high_cpu_count = 0u32;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                if cpu_state.aborted.load(Ordering::Relaxed) {
                    break;
                }
                sys.refresh_cpu_usage();
                let cpu_pct = sys.global_cpu_usage();
                if cpu_pct > 90.0 {
                    high_cpu_count += 1;
                    if high_cpu_count >= 3 {
                        warn!(
                            cpu_pct = format!("{cpu_pct:.1}"),
                            "CPU circuit breaker: aborting load test to protect proxy traffic"
                        );
                        cpu_state.abort(&format!(
                            "CPU circuit breaker: usage {cpu_pct:.0}% exceeded 90% threshold"
                        ));
                        break;
                    }
                } else {
                    high_cpu_count = 0;
                }
            }
        });

        // Spawn concurrent workers
        let mut handles = Vec::new();
        let request_interval = if config.requests_per_second > 0 {
            Duration::from_secs_f64(config.concurrency as f64 / config.requests_per_second as f64)
        } else {
            Duration::from_millis(10)
        };

        for _ in 0..config.concurrency.max(1) {
            let client = run_client.clone();
            let url = config.target_url.clone();
            let method = config.method.clone();
            let body = config.body.clone();
            let headers = config.headers.clone();
            let worker_state = Arc::clone(&state);
            let req_interval = request_interval;

            handles.push(tokio::spawn(async move {
                let deadline = Instant::now() + duration;
                let mut interval = tokio::time::interval(req_interval);

                while Instant::now() < deadline {
                    if worker_state.aborted.load(Ordering::Relaxed) {
                        break;
                    }

                    interval.tick().await;

                    let start = Instant::now();
                    let mut request = match method.as_str() {
                        "POST" => client.post(&url),
                        "PUT" => client.put(&url),
                        "DELETE" => client.delete(&url),
                        "HEAD" => client.head(&url),
                        _ => client.get(&url),
                    };

                    for (key, value) in &headers {
                        request = request.header(key.as_str(), value.as_str());
                    }

                    if let Some(ref b) = body {
                        request = request.body(b.clone());
                    }

                    let result = request.timeout(Duration::from_secs(30)).send().await;

                    let latency_ms = start.elapsed().as_millis() as u64;
                    let success = result
                        .as_ref()
                        .map(|r| r.status().is_success())
                        .unwrap_or(false);
                    worker_state.record(latency_ms, success);

                    // Check auto-abort on error threshold
                    let total = worker_state.total.load(Ordering::Relaxed);
                    if total > 10 {
                        let failed = worker_state.failed.load(Ordering::Relaxed);
                        let error_rate = (failed as f64 / total as f64) * 100.0;
                        if error_rate > error_threshold {
                            worker_state.abort(&format!(
                                "error rate {:.1}% exceeds threshold {:.1}%",
                                error_rate, error_threshold
                            ));
                            break;
                        }
                    }
                }
            }));
        }

        // Wait for all workers to complete
        for handle in handles {
            let _ = handle.await;
        }
        cpu_monitor.abort();

        let finished_at = Utc::now();
        let total = state.total.load(Ordering::Relaxed);
        let success = state.success.load(Ordering::Relaxed);
        let failed = state.failed.load(Ordering::Relaxed);
        let latency_sum = state.latency_sum_ms.load(Ordering::Relaxed) as f64;
        let elapsed = state.started_at.elapsed().as_secs_f64();
        let min_ms = state.latency_min_ms.load(Ordering::Relaxed);
        let max_ms = state.latency_max_ms.load(Ordering::Relaxed);

        let (p50, p95, p99) = if let Ok(mut samples) = state.latency_samples.lock() {
            crate::passive_sla::compute_percentiles(&mut samples)
        } else {
            (0, 0, 0)
        };

        let result = LoadTestResult {
            id: new_id(),
            config_id: config.id.clone(),
            started_at,
            finished_at,
            total_requests: total,
            successful_requests: success,
            failed_requests: failed,
            avg_latency_ms: if total > 0 {
                latency_sum / total as f64
            } else {
                0.0
            },
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
            min_latency_ms: if total > 0 { min_ms } else { 0 },
            max_latency_ms: max_ms,
            throughput_rps: if elapsed > 0.0 {
                total as f64 / elapsed
            } else {
                0.0
            },
            aborted: state.aborted.load(Ordering::Relaxed),
            abort_reason: state.abort_reason.lock().ok().and_then(|r| r.clone()),
        };

        info!(
            name = %config.name,
            total = result.total_requests,
            success = result.successful_requests,
            failed = result.failed_requests,
            rps = format!("{:.1}", result.throughput_rps),
            avg_latency = format!("{:.1}ms", result.avg_latency_ms),
            aborted = result.aborted,
            "load test completed"
        );

        // Store result in database
        {
            let s = store.lock().await;
            if let Err(e) = s.insert_load_test_result(&result) {
                warn!(error = %e, "failed to store load test result");
            }
        }

        // Clear current run
        {
            let mut guard = self.current_run.lock().await;
            *guard = None;
        }

        result
    }
}

impl Default for LoadTestEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Compare two load test results.
pub fn compare_results(
    current: LoadTestResult,
    previous: Option<LoadTestResult>,
) -> LoadTestComparison {
    let (latency_delta, throughput_delta) = match &previous {
        Some(prev) if prev.avg_latency_ms > 0.0 => {
            let lat_delta =
                ((current.avg_latency_ms - prev.avg_latency_ms) / prev.avg_latency_ms) * 100.0;
            let tp_delta = if prev.throughput_rps > 0.0 {
                ((current.throughput_rps - prev.throughput_rps) / prev.throughput_rps) * 100.0
            } else {
                0.0
            };
            (Some(lat_delta), Some(tp_delta))
        }
        _ => (None, None),
    };

    LoadTestComparison {
        current,
        previous,
        latency_delta_pct: latency_delta,
        throughput_delta_pct: throughput_delta,
    }
}

// Make compute_percentiles accessible from this module
pub use crate::passive_sla::compute_percentiles;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_test_config() -> LoadTestConfig {
        let now = Utc::now();
        LoadTestConfig {
            id: "lt1".to_string(),
            name: "Test Load".to_string(),
            target_url: "http://127.0.0.1:9999/test".to_string(),
            method: "GET".to_string(),
            headers: HashMap::new(),
            body: None,
            concurrency: 2,
            requests_per_second: 10,
            duration_s: 5,
            error_threshold_pct: 10.0,
            schedule_cron: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_safe_limits_check() {
        let limits = SafeLimits::default();
        let mut config = make_test_config();
        assert!(!exceeds_safe_limits(&config, &limits));

        config.concurrency = 200;
        assert!(exceeds_safe_limits(&config, &limits));

        config.concurrency = 10;
        config.duration_s = 120;
        assert!(exceeds_safe_limits(&config, &limits));
    }

    #[test]
    fn test_safe_limits_custom() {
        let limits = SafeLimits {
            max_concurrency: 500,
            max_duration_s: 300,
            max_rps: 5000,
        };
        let mut config = make_test_config();
        config.concurrency = 200;
        assert!(!exceeds_safe_limits(&config, &limits)); // under custom limit
        config.concurrency = 600;
        assert!(exceeds_safe_limits(&config, &limits));
    }

    #[test]
    fn test_describe_exceeded_limits() {
        let limits = SafeLimits::default();
        let mut config = make_test_config();
        config.concurrency = 200;
        config.duration_s = 120;
        let warnings = describe_exceeded_limits(&config, &limits);
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("concurrency"));
        assert!(warnings[1].contains("duration"));
    }

    #[test]
    fn test_run_state_record() {
        let state = RunState::new();
        state.record(100, true);
        state.record(200, false);
        state.record(50, true);

        assert_eq!(state.total.load(Ordering::Relaxed), 3);
        assert_eq!(state.success.load(Ordering::Relaxed), 2);
        assert_eq!(state.failed.load(Ordering::Relaxed), 1);
        assert_eq!(state.latency_min_ms.load(Ordering::Relaxed), 50);
        assert_eq!(state.latency_max_ms.load(Ordering::Relaxed), 200);
    }

    #[test]
    fn test_run_state_progress() {
        let state = RunState::new();
        state.record(100, true);
        state.record(200, false);

        let progress = state.progress();
        assert_eq!(progress.total_requests, 2);
        assert_eq!(progress.successful_requests, 1);
        assert_eq!(progress.failed_requests, 1);
        assert!((progress.error_rate_pct - 50.0).abs() < 0.01);
        assert!(!progress.aborted);
    }

    #[test]
    fn test_run_state_abort() {
        let state = RunState::new();
        state.abort("test abort");

        assert!(state.aborted.load(Ordering::Relaxed));
        let progress = state.progress();
        assert!(progress.aborted);
        assert_eq!(progress.abort_reason.as_deref(), Some("test abort"));
    }

    #[test]
    fn test_compare_results_with_previous() {
        let now = Utc::now();
        let current = LoadTestResult {
            id: "r1".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 1000,
            successful_requests: 950,
            failed_requests: 50,
            avg_latency_ms: 110.0,
            p50_latency_ms: 100,
            p95_latency_ms: 200,
            p99_latency_ms: 300,
            min_latency_ms: 10,
            max_latency_ms: 500,
            throughput_rps: 100.0,
            aborted: false,
            abort_reason: None,
        };
        let previous = LoadTestResult {
            id: "r0".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 1000,
            successful_requests: 990,
            failed_requests: 10,
            avg_latency_ms: 100.0,
            p50_latency_ms: 90,
            p95_latency_ms: 180,
            p99_latency_ms: 280,
            min_latency_ms: 10,
            max_latency_ms: 400,
            throughput_rps: 110.0,
            aborted: false,
            abort_reason: None,
        };

        let comparison = compare_results(current, Some(previous));
        assert!(comparison.latency_delta_pct.unwrap() > 0.0); // latency increased
        assert!(comparison.throughput_delta_pct.unwrap() < 0.0); // throughput decreased
    }

    #[test]
    fn test_compare_results_without_previous() {
        let now = Utc::now();
        let current = LoadTestResult {
            id: "r1".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 100,
            successful_requests: 100,
            failed_requests: 0,
            avg_latency_ms: 50.0,
            p50_latency_ms: 45,
            p95_latency_ms: 90,
            p99_latency_ms: 95,
            min_latency_ms: 10,
            max_latency_ms: 100,
            throughput_rps: 50.0,
            aborted: false,
            abort_reason: None,
        };

        let comparison = compare_results(current, None);
        assert!(comparison.latency_delta_pct.is_none());
        assert!(comparison.throughput_delta_pct.is_none());
    }

    #[test]
    fn test_store_load_test_crud() {
        let store = ConfigStore::open_in_memory().unwrap();

        let config = make_test_config();
        store.create_load_test_config(&config).unwrap();

        let configs = store.list_load_test_configs().unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "Test Load");

        let c = store.get_load_test_config("lt1").unwrap().unwrap();
        assert_eq!(c.concurrency, 2);

        store.delete_load_test_config("lt1").unwrap();
        assert!(store.get_load_test_config("lt1").unwrap().is_none());
    }

    #[test]
    fn test_store_load_test_results() {
        let store = ConfigStore::open_in_memory().unwrap();

        let config = make_test_config();
        store.create_load_test_config(&config).unwrap();

        let now = Utc::now();
        let result = LoadTestResult {
            id: "r1".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 100,
            successful_requests: 95,
            failed_requests: 5,
            avg_latency_ms: 42.5,
            p50_latency_ms: 35,
            p95_latency_ms: 90,
            p99_latency_ms: 120,
            min_latency_ms: 5,
            max_latency_ms: 200,
            throughput_rps: 33.3,
            aborted: false,
            abort_reason: None,
        };
        store.insert_load_test_result(&result).unwrap();

        let results = store.list_load_test_results("lt1").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_requests, 100);

        let latest = store.get_latest_load_test_result("lt1").unwrap().unwrap();
        assert_eq!(latest.id, "r1");
    }

    #[test]
    fn test_safe_limits_from_settings() {
        let settings = lorica_config::models::GlobalSettings {
            loadtest_max_concurrency: 500,
            loadtest_max_duration_s: 300,
            loadtest_max_rps: 5000,
            ..lorica_config::models::GlobalSettings::default()
        };
        let limits = SafeLimits::from_settings(&settings);
        assert_eq!(limits.max_concurrency, 500);
        assert_eq!(limits.max_duration_s, 300);
        assert_eq!(limits.max_rps, 5000);
    }

    #[test]
    fn test_describe_exceeded_limits_rps() {
        let limits = SafeLimits::default();
        let mut config = make_test_config();
        config.requests_per_second = 2000; // exceeds default 1000
        let warnings = describe_exceeded_limits(&config, &limits);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("rps"));
    }

    #[test]
    fn test_describe_exceeded_limits_none() {
        let limits = SafeLimits::default();
        let config = make_test_config(); // within limits
        let warnings = describe_exceeded_limits(&config, &limits);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_describe_exceeded_limits_all_three() {
        let limits = SafeLimits::default();
        let mut config = make_test_config();
        config.concurrency = 200;
        config.duration_s = 120;
        config.requests_per_second = 2000;
        let warnings = describe_exceeded_limits(&config, &limits);
        assert_eq!(warnings.len(), 3);
    }

    #[test]
    fn test_run_state_progress_zero_total() {
        let state = RunState::new();
        let progress = state.progress();
        assert_eq!(progress.total_requests, 0);
        assert_eq!(progress.successful_requests, 0);
        assert_eq!(progress.failed_requests, 0);
        assert_eq!(progress.avg_latency_ms, 0.0);
        assert_eq!(progress.error_rate_pct, 0.0);
        assert!(!progress.aborted);
    }

    #[test]
    fn test_compare_results_previous_zero_latency() {
        let now = Utc::now();
        let current = LoadTestResult {
            id: "r1".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 100,
            successful_requests: 100,
            failed_requests: 0,
            avg_latency_ms: 50.0,
            p50_latency_ms: 45,
            p95_latency_ms: 90,
            p99_latency_ms: 95,
            min_latency_ms: 10,
            max_latency_ms: 100,
            throughput_rps: 50.0,
            aborted: false,
            abort_reason: None,
        };
        let previous = LoadTestResult {
            id: "r0".to_string(),
            config_id: "lt1".to_string(),
            started_at: now,
            finished_at: now,
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            avg_latency_ms: 0.0, // zero latency means no delta
            p50_latency_ms: 0,
            p95_latency_ms: 0,
            p99_latency_ms: 0,
            min_latency_ms: 0,
            max_latency_ms: 0,
            throughput_rps: 0.0,
            aborted: false,
            abort_reason: None,
        };

        let comparison = compare_results(current, Some(previous));
        // When previous avg_latency_ms is 0, no delta should be computed
        assert!(comparison.latency_delta_pct.is_none());
    }

    #[test]
    fn test_load_test_config_store_update() {
        let store = ConfigStore::open_in_memory().unwrap();
        let mut config = make_test_config();
        store.create_load_test_config(&config).unwrap();

        config.name = "Updated Name".to_string();
        config.concurrency = 50;
        config.schedule_cron = Some("0 3 * * *".to_string());
        store.update_load_test_config(&config).unwrap();

        let fetched = store.get_load_test_config("lt1").unwrap().unwrap();
        assert_eq!(fetched.name, "Updated Name");
        assert_eq!(fetched.concurrency, 50);
        assert_eq!(fetched.schedule_cron.as_deref(), Some("0 3 * * *"));
    }

    #[tokio::test]
    async fn test_load_test_engine_not_running() {
        let engine = LoadTestEngine::new();
        assert!(!engine.is_running().await);
        assert!(engine.progress().await.is_none());
    }
}
