use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Load Test Models ---

/// User-defined load test scenario. Driven by `lorica-bench`; can be
/// invoked manually or scheduled via `schedule_cron`. Range checks
/// against `GlobalSettings::loadtest_max_*` happen at the API layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    /// Stable UUID; primary key.
    pub id: String,
    /// Human-readable label shown in the dashboard.
    pub name: String,
    /// Absolute URL the load test hits.
    pub target_url: String,
    /// HTTP method (uppercase).
    pub method: String,
    /// Request headers sent on every request.
    pub headers: std::collections::HashMap<String, String>,
    /// Optional request body (string, UTF-8).
    pub body: Option<String>,
    /// Number of concurrent virtual users.
    pub concurrency: i32,
    /// Target steady-state requests per second.
    pub requests_per_second: i32,
    /// Duration of the steady-state phase in seconds.
    pub duration_s: i32,
    /// Auto-abort threshold on error rate (0.0..=100.0).
    pub error_threshold_pct: f64,
    /// Cron expression scheduling recurring runs. `None` = manual.
    pub schedule_cron: Option<String>,
    /// Whether the scheduler should pick this config up.
    pub enabled: bool,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Default upper bound on concurrent virtual users per load test.
pub const SAFE_LIMIT_CONCURRENCY: i32 = 100;
/// Default upper bound on a single load test's duration, in seconds.
pub const SAFE_LIMIT_DURATION_S: i32 = 60;
/// Default upper bound on requests per second per load test.
pub const SAFE_LIMIT_RPS: i32 = 1000;

/// Aggregated outcome of one [`LoadTestConfig`] execution. `aborted`
/// is set with `abort_reason` when the run was stopped early (e.g.
/// `error_threshold_pct` exceeded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestResult {
    /// Stable UUID; primary key of the `load_test_results` table.
    pub id: String,
    /// `LoadTestConfig.id` this run came from.
    pub config_id: String,
    /// Start timestamp.
    pub started_at: DateTime<Utc>,
    /// Finish timestamp.
    pub finished_at: DateTime<Utc>,
    /// Total requests issued.
    pub total_requests: i64,
    /// Requests that returned a 2xx / 3xx.
    pub successful_requests: i64,
    /// Requests that returned a 4xx / 5xx or errored out.
    pub failed_requests: i64,
    /// Mean response latency (ms).
    pub avg_latency_ms: f64,
    /// p50 latency (ms).
    pub p50_latency_ms: i64,
    /// p95 latency (ms).
    pub p95_latency_ms: i64,
    /// p99 latency (ms).
    pub p99_latency_ms: i64,
    /// Fastest observed response (ms).
    pub min_latency_ms: i64,
    /// Slowest observed response (ms).
    pub max_latency_ms: i64,
    /// Measured throughput (requests per second).
    pub throughput_rps: f64,
    /// Whether the run was aborted early.
    pub aborted: bool,
    /// Human-readable abort cause, populated when `aborted == true`.
    pub abort_reason: Option<String>,
}

/// Pairing of two [`LoadTestResult`]s plus their relative deltas, used
/// by the dashboard to flag regressions between consecutive runs.
/// `previous` is `None` for the very first run of a config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestComparison {
    /// The run currently displayed.
    pub current: LoadTestResult,
    /// The immediately preceding run for the same `LoadTestConfig`.
    pub previous: Option<LoadTestResult>,
    /// Percentage change in p95 latency vs `previous`. Positive =
    /// regression.
    pub latency_delta_pct: Option<f64>,
    /// Percentage change in throughput vs `previous`. Negative =
    /// regression.
    pub throughput_delta_pct: Option<f64>,
}
