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
    pub id: String,
    pub route_id: String,
    pub method: String,
    pub path: String,
    pub expected_status: i32,
    pub interval_s: i32,
    pub timeout_ms: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One historical probe execution result, returned by
/// `ConfigStore::list_probe_results`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResultRow {
    pub id: i64,
    pub probe_id: String,
    pub route_id: String,
    pub status_code: u16,
    pub latency_ms: u64,
    pub success: bool,
    pub error: Option<String>,
    pub executed_at: String,
}
