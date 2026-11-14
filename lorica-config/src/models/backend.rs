use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::automation_environment::ManagedBy;
use super::enums::{HealthStatus, LifecycleState};
use super::health_check::HealthCheck;

/// Single upstream target reachable at `address` (validated by the
/// store through [`backend_address_port`]). Multiple backends are grouped via
/// `route_backends` and selected by the route's [`LoadBalancing`]
/// strategy. `health_status` is updated by the health-check loop and
/// `lifecycle_state` by the drain controller.
///
/// [`LoadBalancing`]: super::enums::LoadBalancing
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// Stable UUID; primary key of the `backends` table.
    pub id: String,
    /// `host:port` target. Since 1.11.0 also a host without a port (a
    /// hostname, an IPv4 literal or a bracketed IPv6 literal), which
    /// only a port-range stream may use: the stream supplies the port
    /// (see [`backend_address_port`]).
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
    /// Deprecated since 1.11.0 in favour of `health_check`, and HTTP
    /// routes only; streams ignore it. The HTTP check path (e.g.
    /// "/healthz"), kept equal to `health_check`'s projection
    /// ([`HealthCheck::legacy_path`]) because a 1.10.6 binary reads and
    /// writes this column only. Readers use `health_check`.
    #[serde(default)]
    pub health_check_path: Option<String>,
    /// What one active probe is (Story 12.1, D-2). Set it through
    /// [`Backend::set_health_check`], which keeps `health_check_path`
    /// in step: the store reads a disagreeing pair by the path
    /// ([`HealthCheck::reconcile`]).
    #[serde(default)]
    pub health_check: HealthCheck,
    /// `Enabled` / `Draining` / `Disabled`. Updated by the drain
    /// controller; the LB skips anything that is not `Enabled`.
    pub lifecycle_state: LifecycleState,
    /// Live connection counter, maintained by the proxy layer.
    pub active_connections: i32,
    /// Whether the upstream TCP is wrapped in TLS. HTTP routes only;
    /// streams ignore it.
    pub tls_upstream: bool,
    /// Skip TLS certificate verification when connecting to this backend.
    /// Use for self-signed certificates. Default false. HTTP routes
    /// only; streams ignore it.
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Override the SNI sent to this backend during TLS handshake.
    /// When empty, the route hostname is used instead. HTTP routes
    /// only; streams ignore it.
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// Force HTTP/2 when connecting to this backend (h2c for plaintext,
    /// ALPN h2 for TLS). Default false (HTTP/1.1). HTTP routes only;
    /// streams ignore it.
    #[serde(default)]
    pub h2_upstream: bool,
    /// Who manages this backend when it is not the operator (Story
    /// 10.4 AC #8). Same contract as `Route::managed_by`: `None` is
    /// operator-managed, a `Some` is badged and refused in-place
    /// edits, and the mark replicates with the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<ManagedBy>,
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
#[serde(deny_unknown_fields)]
pub struct RouteBackend {
    /// ID of the associated `Route`.
    pub route_id: String,
    /// ID of the associated `Backend`.
    pub backend_id: String,
}

/// The port a backend address carries, or `None` for a portless
/// address (Story 12.1, D-6).
///
/// Accepted shapes:
///
/// - `host:port`, read as it always was: the text after the last `:`
///   is the port. An unbracketed IPv6 literal therefore keeps its old
///   reading (`2001:db8::1` is host `2001:db8:` and port 1), so no
///   stored backend changes meaning;
/// - a hostname or an IPv4 literal without a port;
/// - a bracketed IPv6 literal without a port (`[2001:db8::1]`).
///
/// A portless backend serves port-range streams only, which forward
/// listen port N to backend port N.
///
/// ```
/// use lorica_config::models::backend_address_port;
/// assert_eq!(backend_address_port("192.0.2.10:8080"), Ok(Some(8080)));
/// assert_eq!(backend_address_port("backend.example.com"), Ok(None));
/// assert_eq!(backend_address_port("[2001:db8::1]"), Ok(None));
/// assert!(backend_address_port("192.0.2.10:").is_err());
/// ```
///
/// # Errors
///
/// A message naming the address when it is none of the shapes above.
pub fn backend_address_port(address: &str) -> Result<Option<u16>, String> {
    if let Some(inner) = address
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(_) => Ok(None),
            Err(_) => Err(format!(
                "backend address has an invalid bracketed IPv6 literal (got '{address}')"
            )),
        };
    }
    if !address.contains(':') {
        let is_host = !address.is_empty()
            && address.len() <= 253
            && address
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_');
        return if is_host {
            Ok(None)
        } else {
            Err(format!(
                "backend address must be host:port, or a host without a port for a \
                 port-range stream (got '{address}')"
            ))
        };
    }
    if address.ends_with(':') {
        return Err(format!(
            "backend address must be in ip:port format (got '{address}')"
        ));
    }
    let port = address.rsplit(':').next().unwrap_or("");
    match port.parse::<u16>() {
        Ok(port) => Ok(Some(port)),
        Err(_) => Err(format!(
            "backend address has invalid port (got '{address}')"
        )),
    }
}

#[cfg(test)]
mod address_tests {
    use super::*;

    #[test]
    fn the_portless_forms_are_accepted_without_a_port() {
        for portless in [
            "backend.example.com",
            "backend",
            "192.0.2.10",
            "[2001:db8::1]",
            "[::1]",
        ] {
            assert_eq!(backend_address_port(portless), Ok(None), "{portless}");
        }
    }

    #[test]
    fn host_port_reads_as_it_always_did() {
        assert_eq!(backend_address_port("192.0.2.10:8080"), Ok(Some(8080)));
        assert_eq!(backend_address_port("[2001:db8::1]:53"), Ok(Some(53)));
        assert_eq!(
            backend_address_port("backend.example.com:443"),
            Ok(Some(443))
        );
        // An unbracketed IPv6 literal keeps its historical reading: the
        // text after the last colon is the port.
        assert_eq!(backend_address_port("2001:db8::1"), Ok(Some(1)));
    }

    #[test]
    fn malformed_addresses_are_refused() {
        for bad in [
            "",
            "192.0.2.10:",
            "192.0.2.10:http",
            "192.0.2.10:70000",
            "[2001:db8::zz]",
            "[192.0.2.10]",
            "two words",
            "host/path",
        ] {
            assert!(backend_address_port(bad).is_err(), "{bad}");
        }
    }
}
