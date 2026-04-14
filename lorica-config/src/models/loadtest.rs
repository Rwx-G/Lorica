use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Load Test Models ---

/// User-defined load test scenario. Driven by `lorica-bench`; can be
/// invoked manually or scheduled via `schedule_cron`. Range checks
/// against `GlobalSettings::loadtest_max_*` happen at the API layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestConfig {
    pub id: String,
    pub name: String,
    pub target_url: String,
    pub method: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub concurrency: i32,
    pub requests_per_second: i32,
    pub duration_s: i32,
    pub error_threshold_pct: f64,
    pub schedule_cron: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
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
    pub id: String,
    pub config_id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: i64,
    pub p95_latency_ms: i64,
    pub p99_latency_ms: i64,
    pub min_latency_ms: i64,
    pub max_latency_ms: i64,
    pub throughput_rps: f64,
    pub aborted: bool,
    pub abort_reason: Option<String>,
}

/// Pairing of two [`LoadTestResult`]s plus their relative deltas, used
/// by the dashboard to flag regressions between consecutive runs.
/// `previous` is `None` for the very first run of a config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadTestComparison {
    pub current: LoadTestResult,
    pub previous: Option<LoadTestResult>,
    pub latency_delta_pct: Option<f64>,
    pub throughput_delta_pct: Option<f64>,
}
