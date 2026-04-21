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
    /// Stable UUID; primary key of the `backends` table.
    pub id: String,
    /// `host:port` target (or Unix-socket path prefixed with `unix:`).
    pub address: String,
    /// Human-readable label shown in the dashboard.
    #[serde(default)]
    pub name: String,
    /// Free-form classification label (same rule as `Route.group_name`).
    #[serde(default)]
    pub group_name: String,
    /// Load-balancing weight (higher = more traffic share).
    pub weight: i32,
    /// Latest health-check outcome.
    pub health_status: HealthStatus,
    /// Whether the health-check loop probes this backend.
    pub health_check_enabled: bool,
    /// Interval in seconds between consecutive health-check probes.
    pub health_check_interval_s: i32,
    /// Optional HTTP health check path (e.g. "/healthz"). When set, HTTP GET
    /// is used instead of TCP connect for health checks.
    #[serde(default)]
    pub health_check_path: Option<String>,
    /// `Enabled` / `Draining` / `Disabled`. Updated by the drain
    /// controller; the LB skips anything that is not `Enabled`.
    pub lifecycle_state: LifecycleState,
    /// Live connection counter, maintained by the proxy layer.
    pub active_connections: i32,
    /// Whether the upstream TCP is wrapped in TLS.
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
    /// First-insert timestamp (DB-assigned).
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp (refreshed on every UPDATE).
    pub updated_at: DateTime<Utc>,
}

/// Many-to-many association row between a [`Route`] and a [`Backend`].
/// Surfaced primarily by the export/import path; runtime code uses
/// `ConfigStore::list_backends_for_route` instead.
///
/// [`Route`]: super::route::Route
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteBackend {
    /// ID of the associated `Route`.
    pub route_id: String,
    /// ID of the associated `Backend`.
    pub backend_id: String,
}
