use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::enums::{HealthStatus, LifecycleState};

/// Single upstream target reachable at `address` (validated as
/// `host:port` by the store). Multiple backends are grouped via
/// `route_backends` and selected by the route's [`LoadBalancing`]
/// strategy. `health_status` is updated by the health-check loop and
/// `lifecycle_state` by the drain controller.
///
/// [`LoadBalancing`]: super::enums::LoadBalancing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backend {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub group_name: String,
    pub weight: i32,
    pub health_status: HealthStatus,
    pub health_check_enabled: bool,
    pub health_check_interval_s: i32,
    /// Optional HTTP health check path (e.g. "/healthz"). When set, HTTP GET
    /// is used instead of TCP connect for health checks.
    #[serde(default)]
    pub health_check_path: Option<String>,
    pub lifecycle_state: LifecycleState,
    pub active_connections: i32,
    pub tls_upstream: bool,
    /// Skip TLS certificate verification when connecting to this backend.
    /// Use for self-signed certificates. Default false.
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Override the SNI sent to this backend during TLS handshake.
    /// When empty, the route hostname is used instead.
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// Force HTTP/2 when connecting to this backend (h2c for plaintext,
    /// ALPN h2 for TLS). Default false (HTTP/1.1).
    #[serde(default)]
    pub h2_upstream: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Many-to-many association row between a [`Route`] and a [`Backend`].
/// Surfaced primarily by the export/import path; runtime code uses
/// `ConfigStore::list_backends_for_route` instead.
///
/// [`Route`]: super::route::Route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBackend {
    pub route_id: String,
    pub backend_id: String,
}
