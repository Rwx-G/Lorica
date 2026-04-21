use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- SLA Models ---

/// Per-route SLA target: the proxy classifies a request as "successful"
/// when its HTTP status is in `[success_status_min, success_status_max]`
/// AND its latency is `<= max_latency_ms`. `target_pct` is the success
/// percentage that defines "meets SLA" in summary reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    /// `Route.id` this SLA target applies to (primary key).
    pub route_id: String,
    /// Minimum success percentage to flag a window as meeting SLA
    /// (0.0..=100.0).
    pub target_pct: f64,
    /// Latency ceiling in milliseconds; responses slower than this
    /// count as failures even with a 2xx status.
    pub max_latency_ms: i64,
    /// Inclusive lower bound of the "success" status range.
    pub success_status_min: i32,
    /// Inclusive upper bound of the "success" status range.
    pub success_status_max: i32,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

impl SlaConfig {
    /// Build the default SLA target for a route: 99.9 % success at
    /// `<= 500 ms` for status codes 200-499. Used by
    /// `ConfigStore::get_sla_config` when no row exists yet.
    pub fn default_for_route(route_id: &str) -> Self {
        let now = Utc::now();
        Self {
            route_id: route_id.to_string(),
            target_pct: 99.9,
            max_latency_ms: 500,
            success_status_min: 200,
            success_status_max: 499,
            created_at: now,
            updated_at: now,
        }
    }

    /// Return true when the given response satisfies both the status
    /// and the latency thresholds of this SLA config.
    pub fn is_success(&self, status: u16, latency_ms: u64) -> bool {
        let status_ok = (status as i32) >= self.success_status_min
            && (status as i32) <= self.success_status_max;
        let latency_ok = (latency_ms as i64) <= self.max_latency_ms;
        status_ok && latency_ok
    }
}

/// Aggregated request statistics for one route over a fixed time window
/// (the "bucket"). Buckets are written by the SLA aggregator and read
/// back by `compute_sla_summary`. The `cfg_*` fields snapshot the
/// [`SlaConfig`] active when the bucket was recorded so historical
/// reports stay consistent if the live config is later edited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaBucket {
    /// Auto-incremented row id (`None` before insert).
    pub id: Option<i64>,
    /// `Route.id` this bucket aggregates.
    pub route_id: String,
    /// Start of the bucket window (RFC 3339).
    pub bucket_start: DateTime<Utc>,
    /// Total requests observed in the window.
    pub request_count: i64,
    /// Requests that matched the status + latency success criteria.
    pub success_count: i64,
    /// Requests that failed either criterion.
    pub error_count: i64,
    /// Sum of response latencies in the window (ms).
    pub latency_sum_ms: i64,
    /// Fastest response in the window (ms).
    pub latency_min_ms: i64,
    /// Slowest response in the window (ms).
    pub latency_max_ms: i64,
    /// p50 latency for the window (ms).
    pub latency_p50_ms: i64,
    /// p95 latency for the window (ms).
    pub latency_p95_ms: i64,
    /// p99 latency for the window (ms).
    pub latency_p99_ms: i64,
    /// Origin of the bucket (`"worker"`, `"supervisor"`).
    pub source: String,
    /// Snapshot of SLA config active when this bucket was recorded.
    /// Ensures historical reporting stays consistent after config changes.
    #[serde(default = "default_cfg_max_latency")]
    pub cfg_max_latency_ms: i64,
    /// Snapshot of `success_status_min`.
    #[serde(default = "default_cfg_status_min")]
    pub cfg_status_min: i32,
    /// Snapshot of `success_status_max`.
    #[serde(default = "default_cfg_status_max")]
    pub cfg_status_max: i32,
    /// Snapshot of `target_pct`.
    #[serde(default = "default_cfg_target_pct")]
    pub cfg_target_pct: f64,
}

fn default_cfg_max_latency() -> i64 {
    500
}
fn default_cfg_status_min() -> i32 {
    200
}
fn default_cfg_status_max() -> i32 {
    399
}
fn default_cfg_target_pct() -> f64 {
    99.9
}

/// Roll-up over a window of [`SlaBucket`]s for one route. Returned by
/// `ConfigStore::compute_sla_summary` for dashboard display.
/// `meets_target` compares `sla_pct` against the snapshot `target_pct`
/// from the most recent bucket in the window (falls back to live config
/// when the window is empty).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaSummary {
    /// `Route.id` this summary rolls up.
    pub route_id: String,
    /// Human label for the aggregation window (e.g. `"24h"`, `"7d"`).
    pub window: String,
    /// Total requests aggregated across the window.
    pub total_requests: i64,
    /// Requests that met both status and latency criteria.
    pub successful_requests: i64,
    /// Success percentage over the window (`successful / total`).
    pub sla_pct: f64,
    /// Mean response latency (ms).
    pub avg_latency_ms: f64,
    /// p50 latency for the window (ms).
    pub p50_latency_ms: i64,
    /// p95 latency for the window (ms).
    pub p95_latency_ms: i64,
    /// p99 latency for the window (ms).
    pub p99_latency_ms: i64,
    /// SLA target percentage (snapshot from the most-recent bucket
    /// or live config).
    pub target_pct: f64,
    /// `true` when `sla_pct >= target_pct`.
    pub meets_target: bool,
}
