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

//! Follower dialer (Story 9.2 AC #9): one long-lived OUTBOUND mutual
//! TLS connection to the control plane, so a follower never exposes an
//! inbound port.
//!
//! The reconnect loop: resolve the control-plane name, TCP + TLS
//! connect under `connect_timeout`, session handshake, publish the
//! endpoint (tagged with a session generation) into an
//! [`arc_swap::ArcSwapOption`] read lock-free by the rest of the
//! process, heartbeat until the connection dies, clear the slot, back
//! off and retry. Every transition is logged: a follower that cannot
//! reach its control plane is the epic's most common support case and
//! must be debuggable from its own journal.
//!
//! # The dial target is a NAME, resolved on every attempt
//!
//! `control_plane` is kept as an unresolved `host:port` and resolved
//! inside each attempt (every address the name resolves to is tried
//! in order). A control plane that fails over, is re-provisioned or
//! is rescheduled onto another address is followed by the fleet on
//! its next reconnect; pinning one `SocketAddr` at spawn time would
//! turn every such event into a fleet-wide, silent, restart-only
//! outage. The certificate identity (`server_name`) is independent of
//! the address.
//!
//! # Backoff
//!
//! Exponential with equal jitter: after `n` consecutive failures the
//! nominal delay is `base * 2^n` clamped to the cap, and the actual
//! delay is `nominal/2 + uniform(0..nominal/2)` so a fleet does not
//! reconnect in lockstep while every node still retries within its
//! nominal bound. The cap starts at `default_backoff_cap` and, once a
//! `HelloAck`/`HeartbeatAck` supplies `fleet_size_hint`, becomes
//! `clamp(default_backoff_cap + hint seconds, default_backoff_cap,
//! 300s)`: a 200-node fleet spreads its reconvergence over minutes, a
//! 3-node lab stays snappy. A `RETRY_LATER` answer sets the next delay
//! to the server-provided `retry_after_s` (AC #10), clamped to the
//! same 300 s ceiling so a buggy or hostile control plane cannot park
//! a follower for years, and floored by the exponential schedule so
//! a control plane answering `retry_after_s = 0` forever cannot keep
//! a follower in a one-second full-mTLS reconnect loop either.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use lorica_command::RpcEndpoint;

use crate::handshake::{client_handshake, HandshakeConfig, HandshakeError};
use crate::limits::cluster_rpc_limits;
use crate::messages::{cluster_response, ClusterFrame, ClusterRequest, ClusterStatus, Heartbeat};
use crate::tls::{client_config, negotiated_cluster_alpn, ClusterTlsError};

/// Hard ceiling on every reconnect delay: the scaled backoff cap AND
/// a server-provided `retry_after_s`.
pub const BACKOFF_CAP_CEILING: Duration = Duration::from_secs(300);

/// Why a dialer could not be spawned.
#[derive(Debug, thiserror::Error)]
pub enum DialerError {
    /// The TLS material or server name was unusable.
    #[error(transparent)]
    Tls(#[from] ClusterTlsError),
    /// `control_plane` is not a `host:port`.
    #[error("invalid control-plane address {0:?}: expected host:port")]
    Address(String),
}

/// Dialer counters (bridged to Prometheus by the binary, AC #12).
#[derive(Debug, Default)]
pub struct DialerStats {
    /// TCP+TLS connection attempts.
    pub connect_attempts: AtomicU64,
    /// Attempts that failed before the session handshake (resolution,
    /// TCP, TLS, `connect_timeout`, missing ALPN).
    pub connect_failures: AtomicU64,
    /// Sessions admitted by the control plane.
    pub handshakes_ok: AtomicU64,
    /// Handshakes refused (version/schema/violation).
    pub handshake_refusals: AtomicU64,
    /// RETRY_LATER answers honoured (AC #10).
    pub retry_later: AtomicU64,
    /// Heartbeats acknowledged.
    pub heartbeats_ok: AtomicU64,
    /// Heartbeats that failed (and tore the connection down).
    pub heartbeat_failures: AtomicU64,
    /// Times an established connection was lost.
    pub disconnects: AtomicU64,
}

/// Inputs for [`Dialer::spawn`]. Construct with [`DialerConfig::new`];
/// every field stays public so callers (and tests) can tune it.
#[derive(Clone)]
pub struct DialerConfig {
    /// Control-plane `host:port`, resolved on EVERY attempt (see the
    /// module doc).
    pub control_plane: String,
    /// Name the control-plane certificate must verify as (its SAN).
    pub server_name: String,
    /// Cluster CA bundle (the ONLY trust root).
    pub ca_pem: String,
    /// This node's `clientAuth` leaf.
    pub client_cert_pem: String,
    /// This node's private key.
    pub client_key_pem: String,
    /// Protocol/schema inputs for the session handshake.
    pub handshake: HandshakeConfig,
    /// Display name sent in the Hello (identity is the certificate).
    /// Default: empty.
    pub node_name: String,
    /// Interval between liveness probes on an established session.
    /// Default 15 s (must stay below the transport's 30 s
    /// `frame_read_timeout`).
    pub heartbeat_interval: Duration,
    /// Per-request timeout (handshake and heartbeats). Default 10 s.
    pub request_timeout: Duration,
    /// Bound on name resolution + TCP connect + TLS handshake
    /// together. Default 10 s: a peer that accepts TCP and then
    /// stalls must not wedge the loop.
    pub connect_timeout: Duration,
    /// First-failure backoff delay. Default 1 s.
    pub base_backoff: Duration,
    /// Backoff cap before any fleet-size hint arrives; also the floor
    /// of the scaled cap (see the module doc). Default 60 s.
    pub default_backoff_cap: Duration,
}

impl DialerConfig {
    /// A config with the documented defaults for every timing knob.
    /// `control_plane` is a `host:port` (validated at spawn).
    pub fn new(
        control_plane: &str,
        server_name: &str,
        ca_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
        local_schema_version: u32,
    ) -> Self {
        Self {
            control_plane: control_plane.to_string(),
            server_name: server_name.to_string(),
            ca_pem: ca_pem.to_string(),
            client_cert_pem: client_cert_pem.to_string(),
            client_key_pem: client_key_pem.to_string(),
            handshake: HandshakeConfig::new(local_schema_version),
            node_name: String::new(),
            heartbeat_interval: Duration::from_secs(15),
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            base_backoff: Duration::from_secs(1),
            default_backoff_cap: Duration::from_secs(60),
        }
    }

    /// Set the display name sent in the Hello.
    pub fn with_node_name(mut self, node_name: &str) -> Self {
        self.node_name = node_name.to_string();
        self
    }
}

/// Split a `host:port` into its parts, refusing a bare host, a bare
/// port and a non-numeric port. IPv6 literals must be bracketed.
pub fn split_host_port(value: &str) -> Result<(&str, u16), DialerError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| DialerError::Address(value.to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| DialerError::Address(value.to_string()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(DialerError::Address(value.to_string()));
    }
    Ok((host, port))
}

/// One established session: the endpoint plus a generation that
/// increments on every successful handshake, so a consumer running a
/// multi-step exchange (Story 9.4's Prepare/Commit) can tell that a
/// reconnect happened in between and must not mix the two sessions.
#[derive(Clone)]
pub struct SessionHandle {
    /// Monotonic per dialer; starts at 1.
    pub generation: u64,
    /// The live endpoint.
    pub endpoint: Arc<RpcEndpoint<ClusterFrame>>,
}

/// Lock-free view of the follower's current control-plane connection.
///
/// `None` whenever the dialer is between connections; consumers must
/// treat that as "control plane unreachable right now" and not queue.
#[derive(Clone)]
pub struct ClusterConnection {
    slot: Arc<ArcSwapOption<SessionHandle>>,
}

impl ClusterConnection {
    /// The live session, if one is currently established.
    pub fn current(&self) -> Option<SessionHandle> {
        self.slot.load_full().map(|s| (*s).clone())
    }
}

/// Handle to a running dialer.
pub struct DialerHandle {
    connection: ClusterConnection,
    stats: Arc<DialerStats>,
    connector: Arc<ArcSwap<TlsConnector>>,
    ca_pem: String,
    reconnect: Arc<tokio::sync::Notify>,
    task: JoinHandle<()>,
}

impl DialerHandle {
    /// The connection slot consumers read.
    pub fn connection(&self) -> ClusterConnection {
        self.connection.clone()
    }

    /// The dialer's counters.
    pub fn stats(&self) -> Arc<DialerStats> {
        Arc::clone(&self.stats)
    }

    /// Swap in a renewed identity (Story 9.3 AC #12): the NEXT
    /// connection presents the new leaf; the established session is
    /// untouched.
    pub fn update_identity(
        &self,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> Result<(), ClusterTlsError> {
        let tls = client_config(&self.ca_pem, client_cert_pem, client_key_pem)?;
        self.connector.store(Arc::new(TlsConnector::from(Arc::new(tls))));
        Ok(())
    }

    /// Drop the established session and dial again immediately (no
    /// backoff): after a renewal, so the control plane sees the new
    /// certificate now and retires the superseded one, instead of
    /// whenever the old session happens to end.
    pub fn reconnect(&self) {
        self.reconnect.notify_one();
    }

    /// Stop dialing and clear the connection slot.
    pub fn shutdown(self) {
        self.task.abort();
        self.connection.slot.store(None);
    }
}

/// The follower's reconnecting dialer (AC #9).
pub struct Dialer;

impl Dialer {
    /// Validate the address shape and the TLS material, then spawn the
    /// reconnect loop.
    pub fn spawn(config: DialerConfig) -> Result<DialerHandle, DialerError> {
        split_host_port(&config.control_plane)?;
        let tls = client_config(&config.ca_pem, &config.client_cert_pem, &config.client_key_pem)?;
        let server_name: ServerName<'static> = ServerName::try_from(config.server_name.clone())
            .map_err(|e| ClusterTlsError::Parse(format!("invalid server name: {e}")))?;
        let connector: Arc<ArcSwap<TlsConnector>> =
            Arc::new(ArcSwap::from_pointee(TlsConnector::from(Arc::new(tls))));

        let slot: Arc<ArcSwapOption<SessionHandle>> = Arc::new(ArcSwapOption::empty());
        let stats = Arc::new(DialerStats::default());
        let connection = ClusterConnection {
            slot: Arc::clone(&slot),
        };
        let ca_pem = config.ca_pem.clone();

        let reconnect = Arc::new(tokio::sync::Notify::new());
        let loop_slot = Arc::clone(&slot);
        let loop_stats = Arc::clone(&stats);
        let loop_connector = Arc::clone(&connector);
        let loop_reconnect = Arc::clone(&reconnect);
        let task = tokio::spawn(async move {
            dial_loop(
                config,
                loop_connector,
                server_name,
                loop_slot,
                loop_stats,
                loop_reconnect,
            )
            .await;
        });

        Ok(DialerHandle {
            connection,
            stats,
            connector,
            ca_pem,
            reconnect,
            task,
        })
    }
}

async fn dial_loop(
    config: DialerConfig,
    connector: Arc<ArcSwap<TlsConnector>>,
    server_name: ServerName<'static>,
    slot: Arc<ArcSwapOption<SessionHandle>>,
    stats: Arc<DialerStats>,
    reconnect: Arc<tokio::sync::Notify>,
) {
    let mut failures: u32 = 0;
    let mut fleet_hint: u32 = 0;
    let mut generation: u64 = 0;
    let mut jitter = Jitter::seeded();
    // Set when the control plane answered RETRY_LATER: the next delay
    // is at least this long.
    let mut server_delay: Option<Duration> = None;
    // Sticky refusal state: the FIRST refusal of a given status logs
    // at error, repeats at debug, so a mis-ordered fleet upgrade is one
    // loud line rather than a silent retry loop or a log flood.
    let mut sticky_refusal: Option<ClusterStatus> = None;
    let mut was_connected = false;

    loop {
        stats.connect_attempts.fetch_add(1, Ordering::Relaxed);
        // Loaded per attempt so a renewed identity takes effect on
        // the next connection.
        let current_connector = connector.load_full();
        match connect_once(&config, &current_connector, &server_name).await {
            Ok((endpoint, ack_hint, negotiated_version, addr)) => {
                stats.handshakes_ok.fetch_add(1, Ordering::Relaxed);
                failures = 0;
                server_delay = None;
                sticky_refusal = None;
                fleet_hint = ack_hint;
                generation += 1;
                was_connected = true;
                tracing::info!(
                    control_plane = %config.control_plane,
                    resolved = %addr,
                    generation,
                    protocol = negotiated_version,
                    fleet_size_hint = fleet_hint,
                    "cluster session established with the control plane"
                );
                let endpoint = Arc::new(endpoint);
                slot.store(Some(Arc::new(SessionHandle {
                    generation,
                    endpoint: Arc::clone(&endpoint),
                })));

                let (hint, requested) = tokio::select! {
                    hint = heartbeat_until_dead(&config, &endpoint, fleet_hint, &stats) => (hint, false),
                    _ = reconnect.notified() => (fleet_hint, true),
                };
                fleet_hint = hint;
                slot.store(None);
                stats.disconnects.fetch_add(1, Ordering::Relaxed);
                if requested {
                    tracing::info!(
                        control_plane = %config.control_plane,
                        generation,
                        "cluster session dropped on request; reconnecting now"
                    );
                    continue;
                }
                tracing::warn!(
                    control_plane = %config.control_plane,
                    generation,
                    "cluster session lost; reconnecting"
                );
            }
            Err(DialFailure::RetryLater(retry_after_s)) => {
                stats.retry_later.fetch_add(1, Ordering::Relaxed);
                // Counted as a failure so the exponential schedule
                // floors a control plane that keeps saying "now".
                failures = failures.saturating_add(1);
                let delay = Duration::from_secs(u64::from(retry_after_s.max(1)))
                    .min(BACKOFF_CAP_CEILING);
                tracing::info!(
                    control_plane = %config.control_plane,
                    retry_in = ?delay,
                    "control plane admission is full; retrying later"
                );
                server_delay = Some(delay);
            }
            Err(DialFailure::Refused(status)) => {
                stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
                if sticky_refusal != Some(status) {
                    sticky_refusal = Some(status);
                    tracing::error!(
                        control_plane = %config.control_plane,
                        ?status,
                        "control plane refused the session; will keep retrying on the capped \
                         schedule but this needs an operator (version or schema mismatch, or a \
                         protocol fault)"
                    );
                } else {
                    tracing::debug!(control_plane = %config.control_plane, ?status, "session still refused");
                }
            }
            Err(DialFailure::Transport(reason)) => {
                stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
                // First failure after a connected period (or at boot)
                // is the transition worth a warning; the rest of the
                // storm stays at debug.
                if failures == 1 || was_connected {
                    was_connected = false;
                    tracing::warn!(
                        control_plane = %config.control_plane,
                        reason = %reason,
                        "cannot reach the control plane; backing off"
                    );
                } else {
                    tracing::debug!(control_plane = %config.control_plane, reason = %reason, failures, "connect failed");
                }
            }
        }

        let scheduled = backoff_delay(
            config.base_backoff,
            backoff_cap(config.default_backoff_cap, fleet_hint),
            failures,
            &mut jitter,
        );
        let delay = match server_delay.take() {
            Some(server) => server.max(scheduled),
            None => scheduled,
        };
        tokio::time::sleep(delay).await;
    }
}

enum DialFailure {
    /// Resolution/TCP/TLS/transport-level failure, with the cause for
    /// the log.
    Transport(String),
    /// The control plane refused the session outright.
    Refused(ClusterStatus),
    /// The admission gate asked us to come back later (AC #10).
    RetryLater(u32),
}

/// Resolve a `host:port` and connect to the first address that
/// answers, in resolution order. Shared by the dialer, the joiner and
/// the CLI so "how the fleet reaches a name" has one definition. The
/// caller bounds it with a timeout.
pub async fn resolve_and_connect(
    target: &str,
) -> Result<(tokio::net::TcpStream, SocketAddr), String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .map_err(|e| format!("resolve {target}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {target}: no addresses"));
    }
    let mut last_error = String::new();
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => return Ok((tcp, addr)),
            Err(e) => last_error = format!("tcp connect {addr}: {e}"),
        }
    }
    Err(last_error)
}

async fn connect_once(
    config: &DialerConfig,
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Result<(RpcEndpoint<ClusterFrame>, u32, u32, SocketAddr), DialFailure> {
    // Resolution + TCP + TLS under one budget: a peer that answers TCP
    // and then stalls (route hijack, stale address) must not wedge the
    // loop.
    let (tls, addr) = tokio::time::timeout(config.connect_timeout, async {
        let (tcp, addr) = resolve_and_connect(&config.control_plane)
            .await
            .map_err(DialFailure::Transport)?;
        let tls = connector
            .connect(server_name.clone(), tcp)
            .await
            .map_err(|e| DialFailure::Transport(format!("tls connect {addr}: {e}")))?;
        Ok::<_, DialFailure>((tls, addr))
    })
    .await
    .map_err(|_| DialFailure::Transport("connect timed out".to_string()))??;
    if !negotiated_cluster_alpn(tls.get_ref().1) {
        return Err(DialFailure::Transport(
            "server did not negotiate the cluster ALPN".to_string(),
        ));
    }
    // The incoming half is dropped: no server-initiated requests exist
    // in Story 9.2 (Story 9.4 must keep it for pushes).
    let (endpoint, _incoming) =
        RpcEndpoint::<ClusterFrame>::with_limits(tls, cluster_rpc_limits());
    match client_handshake(
        &endpoint,
        &config.handshake,
        &config.node_name,
        config.request_timeout,
    )
    .await
    {
        Ok(ack) => Ok((endpoint, ack.fleet_size_hint, ack.negotiated_version, addr)),
        Err(HandshakeError::RetryLater { retry_after_s }) => {
            Err(DialFailure::RetryLater(retry_after_s))
        }
        Err(HandshakeError::Refused(status)) => Err(DialFailure::Refused(status)),
        Err(HandshakeError::ProtocolViolation) => {
            Err(DialFailure::Refused(ClusterStatus::ProtocolViolation))
        }
        Err(HandshakeError::Transport(e)) => {
            Err(DialFailure::Transport(format!("handshake transport: {e}")))
        }
    }
}

/// Heartbeat until the session dies; returns the freshest fleet-size
/// hint so the next backoff cap reflects roster growth.
async fn heartbeat_until_dead(
    config: &DialerConfig,
    endpoint: &Arc<RpcEndpoint<ClusterFrame>>,
    mut fleet_hint: u32,
    stats: &DialerStats,
) -> u32 {
    loop {
        tokio::time::sleep(config.heartbeat_interval).await;
        if endpoint.is_closed() {
            tracing::debug!("cluster session endpoint closed");
            return fleet_hint;
        }
        let probe = ClusterRequest::heartbeat(Heartbeat {
            timestamp_ms: unix_millis(),
        });
        match endpoint.request(probe, config.request_timeout).await {
            Ok(resp) => match resp.body {
                Some(cluster_response::Body::HeartbeatAck(ack)) => {
                    stats.heartbeats_ok.fetch_add(1, Ordering::Relaxed);
                    fleet_hint = ack.fleet_size_hint;
                }
                _ => {
                    stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(status = ?resp.cluster_status(), "heartbeat answered without an ack; dropping the session");
                    return fleet_hint;
                }
            },
            Err(e) => {
                stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %e, "heartbeat failed; dropping the session");
                return fleet_hint;
            }
        }
    }
}

/// The scaled backoff cap (see the module doc formula). An operator
/// configuring `default_cap` above the ceiling keeps their value
/// (`clamp` would panic on an inverted range).
fn backoff_cap(default_cap: Duration, fleet_hint: u32) -> Duration {
    let scaled = default_cap + Duration::from_secs(u64::from(fleet_hint));
    scaled.min(BACKOFF_CAP_CEILING).max(default_cap.min(BACKOFF_CAP_CEILING))
}

/// Exponential delay with equal jitter.
fn backoff_delay(base: Duration, cap: Duration, failures: u32, jitter: &mut Jitter) -> Duration {
    let exp = failures.min(16); // 2^16 * any sane base saturates the cap
    let nominal = base.saturating_mul(1u32 << exp).min(cap);
    let half = nominal / 2;
    half + jitter.uniform(half)
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Small xorshift PRNG for backoff jitter: not security-relevant, and
/// keeps `rand` out of the crate's dependency set.
struct Jitter(u64);

impl Jitter {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
            .unwrap_or(0x9e37_79b9_7f4a_7c15)
            | 1;
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform-ish duration in `[0, bound]`.
    fn uniform(&mut self, bound: Duration) -> Duration {
        let bound_ms = bound.as_millis() as u64;
        if bound_ms == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(self.next() % (bound_ms + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_cap_scales_with_the_fleet_hint_within_bounds() {
        let default_cap = Duration::from_secs(60);
        assert_eq!(backoff_cap(default_cap, 0), default_cap);
        assert_eq!(backoff_cap(default_cap, 30), Duration::from_secs(90));
        assert_eq!(backoff_cap(default_cap, 100_000), BACKOFF_CAP_CEILING);
    }

    #[test]
    fn backoff_delay_grows_and_respects_the_cap() {
        let mut jitter = Jitter::seeded();
        let base = Duration::from_millis(500);
        let cap = Duration::from_secs(30);
        let first = backoff_delay(base, cap, 0, &mut jitter);
        assert!(first >= base / 2 && first <= base, "got {first:?}");
        let capped = backoff_delay(base, cap, 12, &mut jitter);
        assert!(capped >= cap / 2 && capped <= cap, "got {capped:?}");
    }

    #[test]
    fn jitter_stays_within_its_bound() {
        let mut jitter = Jitter::seeded();
        let bound = Duration::from_millis(250);
        for _ in 0..1000 {
            assert!(jitter.uniform(bound) <= bound);
        }
    }

    #[test]
    fn config_defaults_keep_heartbeats_inside_the_frame_read_timeout() {
        let cfg = DialerConfig::new("cp.example.com:9444", "cp", "", "", "", 49);
        assert!(cfg.heartbeat_interval < cluster_rpc_limits().frame_read_timeout);
        assert!(cfg.connect_timeout > Duration::ZERO);
        assert_eq!(cfg.with_node_name("edge-1").node_name, "edge-1");
    }

    #[test]
    fn host_port_shapes_are_validated_at_spawn() {
        assert_eq!(
            split_host_port("cp.example.com:9444").expect("dns name"),
            ("cp.example.com", 9444)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:9444").expect("v6 literal"),
            ("2001:db8::1", 9444)
        );
        for bad in ["cp.example.com", "9444", ":9444", "cp.example.com:port"] {
            assert!(
                matches!(split_host_port(bad), Err(DialerError::Address(_))),
                "{bad} must be refused"
            );
        }
    }
}
