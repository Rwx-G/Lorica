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
//! The reconnect loop: TLS connect, session handshake, publish the
//! endpoint into an [`arc_swap::ArcSwapOption`] read lock-free by the
//! rest of the process, heartbeat until the connection dies, clear the
//! slot, back off and retry.
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
//! 3-node lab stays snappy. A `RETRY_LATER` answer overrides the next
//! delay with the server-provided `retry_after_s` (AC #10).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use lorica_command::RpcEndpoint;

use crate::handshake::{client_handshake, HandshakeConfig, HandshakeError};
use crate::messages::{cluster_request, cluster_response, ClusterFrame, ClusterRequest, Heartbeat};
use crate::tls::{client_config, ClusterTlsError};

/// Hard ceiling on the reconnect backoff cap, whatever the fleet size
/// hint says.
const BACKOFF_CAP_CEILING: Duration = Duration::from_secs(300);

/// Dialer counters (bridged to Prometheus by the binary, AC #12).
#[derive(Debug, Default)]
pub struct DialerStats {
    /// TCP+TLS connection attempts.
    pub connect_attempts: AtomicU64,
    /// Attempts that failed before the session handshake.
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

/// Inputs for [`Dialer::spawn`].
#[derive(Clone)]
pub struct DialerConfig {
    /// Control-plane `host:port` to dial.
    pub control_plane_addr: String,
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
    pub node_name: String,
    /// Interval between liveness probes on an established session.
    pub heartbeat_interval: Duration,
    /// Per-request timeout (handshake and heartbeats).
    pub request_timeout: Duration,
    /// First-failure backoff delay.
    pub base_backoff: Duration,
    /// Backoff cap before any fleet-size hint arrives; also the floor
    /// of the scaled cap (see the module doc).
    pub default_backoff_cap: Duration,
}

/// Lock-free view of the follower's current control-plane connection.
///
/// `None` whenever the dialer is between connections; consumers must
/// treat that as "control plane unreachable right now" and not queue.
#[derive(Clone)]
pub struct ClusterConnection {
    slot: Arc<ArcSwapOption<RpcEndpoint<ClusterFrame>>>,
}

impl ClusterConnection {
    /// The live endpoint, if a session is currently established.
    pub fn current(&self) -> Option<Arc<RpcEndpoint<ClusterFrame>>> {
        self.slot.load_full()
    }
}

/// Handle to a running dialer.
pub struct DialerHandle {
    connection: ClusterConnection,
    stats: Arc<DialerStats>,
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

    /// Stop dialing and clear the connection slot.
    pub fn shutdown(self) {
        self.task.abort();
        self.connection.slot.store(None);
    }
}

/// The follower's reconnecting dialer (AC #9).
pub struct Dialer;

impl Dialer {
    /// Validate the TLS material and spawn the reconnect loop.
    pub fn spawn(config: DialerConfig) -> Result<DialerHandle, ClusterTlsError> {
        let tls = client_config(&config.ca_pem, &config.client_cert_pem, &config.client_key_pem)?;
        let server_name: ServerName<'static> = ServerName::try_from(config.server_name.clone())
            .map_err(|e| ClusterTlsError::Parse(format!("invalid server name: {e}")))?;
        let connector = TlsConnector::from(Arc::new(tls));

        let slot: Arc<ArcSwapOption<RpcEndpoint<ClusterFrame>>> =
            Arc::new(ArcSwapOption::empty());
        let stats = Arc::new(DialerStats::default());
        let connection = ClusterConnection {
            slot: Arc::clone(&slot),
        };

        let loop_slot = Arc::clone(&slot);
        let loop_stats = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            dial_loop(config, connector, server_name, loop_slot, loop_stats).await;
        });

        Ok(DialerHandle {
            connection,
            stats,
            task,
        })
    }
}

async fn dial_loop(
    config: DialerConfig,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    slot: Arc<ArcSwapOption<RpcEndpoint<ClusterFrame>>>,
    stats: Arc<DialerStats>,
) {
    let mut failures: u32 = 0;
    let mut fleet_hint: u32 = 0;
    let mut jitter = Jitter::seeded();
    // Set when the control plane answered RETRY_LATER: overrides the
    // exponential delay once.
    let mut server_delay: Option<Duration> = None;

    loop {
        stats.connect_attempts.fetch_add(1, Ordering::Relaxed);
        match connect_once(&config, &connector, &server_name).await {
            Ok((endpoint, ack_hint)) => {
                stats.handshakes_ok.fetch_add(1, Ordering::Relaxed);
                failures = 0;
                server_delay = None;
                fleet_hint = ack_hint;
                let endpoint = Arc::new(endpoint);
                slot.store(Some(Arc::clone(&endpoint)));

                fleet_hint =
                    heartbeat_until_dead(&config, &endpoint, fleet_hint, &stats).await;
                slot.store(None);
                stats.disconnects.fetch_add(1, Ordering::Relaxed);
            }
            Err(DialFailure::RetryLater(retry_after_s)) => {
                stats.retry_later.fetch_add(1, Ordering::Relaxed);
                server_delay = Some(Duration::from_secs(u64::from(retry_after_s.max(1))));
            }
            Err(DialFailure::Refused) => {
                stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
            }
            Err(DialFailure::Transport) => {
                stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
            }
        }

        let delay = match server_delay.take() {
            Some(d) => d,
            None => backoff_delay(
                config.base_backoff,
                backoff_cap(config.default_backoff_cap, fleet_hint),
                failures,
                &mut jitter,
            ),
        };
        tokio::time::sleep(delay).await;
    }
}

enum DialFailure {
    /// TCP/TLS/transport-level failure.
    Transport,
    /// The control plane refused the session outright.
    Refused,
    /// The admission gate asked us to come back later (AC #10).
    RetryLater(u32),
}

async fn connect_once(
    config: &DialerConfig,
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Result<(RpcEndpoint<ClusterFrame>, u32), DialFailure> {
    let tcp = tokio::net::TcpStream::connect(&config.control_plane_addr)
        .await
        .map_err(|_| DialFailure::Transport)?;
    let tls = connector
        .connect(server_name.clone(), tcp)
        .await
        .map_err(|_| DialFailure::Transport)?;
    let (endpoint, _incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    match client_handshake(
        &endpoint,
        &config.handshake,
        &config.node_name,
        config.request_timeout,
    )
    .await
    {
        Ok(ack) => Ok((endpoint, ack.fleet_size_hint)),
        Err(HandshakeError::RetryLater { retry_after_s }) => {
            Err(DialFailure::RetryLater(retry_after_s))
        }
        Err(HandshakeError::Refused(_)) | Err(HandshakeError::ProtocolViolation) => {
            Err(DialFailure::Refused)
        }
        Err(HandshakeError::Transport(_)) => Err(DialFailure::Transport),
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
            return fleet_hint;
        }
        let probe = ClusterRequest {
            sequence: 0, // stamped by the endpoint
            body: Some(cluster_request::Body::Heartbeat(Heartbeat {
                timestamp_ms: unix_millis(),
            })),
        };
        match endpoint.request(probe, config.request_timeout).await {
            Ok(resp) => match resp.body {
                Some(cluster_response::Body::HeartbeatAck(ack)) => {
                    stats.heartbeats_ok.fetch_add(1, Ordering::Relaxed);
                    fleet_hint = ack.fleet_size_hint;
                }
                _ => {
                    stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                    return fleet_hint;
                }
            },
            Err(_) => {
                stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
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
}
