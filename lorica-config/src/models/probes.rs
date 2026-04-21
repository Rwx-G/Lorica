use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// --- Probe Models ---

/// Active synthetic probe attached to a [`Route`]. Each enabled probe is
/// scheduled to issue `method path` against the route every `interval_s`
/// seconds and assert the response status equals `expected_status`
/// within `timeout_ms`.
///
/// [`Route`]: super::route::Route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Stable UUID; primary key of the `probes` table.
    pub id: String,
    /// `Route.id` this probe exercises.
    pub route_id: String,
    /// HTTP method issued by the probe (uppercase).
    pub method: String,
    /// Request-target path (`/foo?bar=baz` style).
    pub path: String,
    /// HTTP status the probe must see to count as a success.
    pub expected_status: i32,
    /// Interval in seconds between consecutive probe runs.
    pub interval_s: i32,
    /// Per-probe request timeout in milliseconds.
    pub timeout_ms: i32,
    /// Whether the probe is currently running (admin toggle).
    pub enabled: bool,
    /// Insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

/// One historical probe execution result, returned by
/// `ConfigStore::list_probe_results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultRow {
    /// Auto-incremented row id.
    pub id: i64,
    /// `ProbeConfig.id` this row was produced by.
    pub probe_id: String,
    /// Cached `Route.id` at the time of the probe run (denormalised).
    pub route_id: String,
    /// HTTP status returned by the upstream.
    pub status_code: u16,
    /// Wire latency observed by the probe (ms).
    pub latency_ms: u64,
    /// Whether `status_code` matched `ProbeConfig.expected_status`.
    pub success: bool,
    /// Error surface for connect / read failures. `None` on success.
    pub error: Option<String>,
    /// RFC 3339 timestamp of the probe execution.
    pub executed_at: String,
}
