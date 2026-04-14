use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- SLA Models ---

/// Per-route SLA target: the proxy classifies a request as "successful"
/// when its HTTP status is in `[success_status_min, success_status_max]`
/// AND its latency is `<= max_latency_ms`. `target_pct` is the success
/// percentage that defines "meets SLA" in summary reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaConfig {
    pub route_id: String,
    pub target_pct: f64,
    pub max_latency_ms: i64,
    pub success_status_min: i32,
    pub success_status_max: i32,
    pub created_at: DateTime<Utc>,
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
    pub id: Option<i64>,
    pub route_id: String,
    pub bucket_start: DateTime<Utc>,
    pub request_count: i64,
    pub success_count: i64,
    pub error_count: i64,
    pub latency_sum_ms: i64,
    pub latency_min_ms: i64,
    pub latency_max_ms: i64,
    pub latency_p50_ms: i64,
    pub latency_p95_ms: i64,
    pub latency_p99_ms: i64,
    pub source: String,
    /// Snapshot of SLA config active when this bucket was recorded.
    /// Ensures historical reporting stays consistent after config changes.
    #[serde(default = "default_cfg_max_latency")]
    pub cfg_max_latency_ms: i64,
    #[serde(default = "default_cfg_status_min")]
    pub cfg_status_min: i32,
    #[serde(default = "default_cfg_status_max")]
    pub cfg_status_max: i32,
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
    pub route_id: String,
    pub window: String,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub sla_pct: f64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: i64,
    pub p95_latency_ms: i64,
    pub p99_latency_ms: i64,
    pub target_pct: f64,
    pub meets_target: bool,
}
