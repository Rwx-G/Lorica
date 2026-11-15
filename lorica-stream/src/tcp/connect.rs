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

//! The connect phase (Story 12.3 D-e to D-h, D-l, D-m): pick a
//! candidate, check its destination, admit it through the breaker, bind
//! the source, connect under the connect timeout, and on failure try
//! another candidate within the attempt budget.
//!
//! The client is never read here: a client-first protocol's bytes wait
//! in the kernel receive buffer, and the only client bytes the engine
//! holds are the pre-forwarding preamble, replayed to whichever attempt
//! connects. A retry therefore never loses or repeats a client byte.
//!
//! Each backend is tried at most once per connection, and every way a
//! candidate can be passed over (a breaker `Deny`, a local destination,
//! no source address of its family) removes it for this connection.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    backend_address_host, backend_address_port, Backend, HealthStatus, LifecycleState, Stream,
    StreamEndReason,
};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::counters::{ConnectFailureKind, StreamCounters, StreamStats};
use crate::local::{BoundPorts, LocalRefusal, NodeLocality};
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{Admission, BackendSelector, BreakerGate, Candidate, SelectionRequest};
use crate::table::{LinkedBackend, StreamTable};

/// Interval between TCP keepalive probes on a backend socket, the
/// constant HTTP's upstream keepalive uses beside its idle time (D-d).
pub const BACKEND_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Unanswered keepalive probes before the kernel drops a backend
/// connection.
pub const BACKEND_KEEPALIVE_PROBES: u32 = 3;

/// What a connect phase shares across connections.
pub(crate) struct Shared {
    pub(crate) selector: Arc<dyn BackendSelector>,
    pub(crate) breaker: Arc<dyn BreakerGate>,
    pub(crate) resolver: Arc<ResolverCache>,
    pub(crate) counters: Arc<StreamCounters>,
    pub(crate) reserved: Option<ReservedPorts>,
    pub(crate) exclusions: LocalExclusions,
    pub(crate) rotation: Rotation,
}

/// Rotating counters: per stream for source addresses, one for the
/// address choice within a backend.
#[derive(Debug, Default)]
pub(crate) struct Rotation {
    sources: std::sync::Mutex<std::collections::HashMap<String, usize>>,
    addresses: std::sync::atomic::AtomicUsize,
}

impl Rotation {
    fn next_source(&self, stream_id: &str) -> usize {
        let mut sources = self
            .sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = sources.entry(stream_id.to_string()).or_default();
        let current = *n;
        *n = n.wrapping_add(1);
        current
    }

    fn next_address(&self) -> usize {
        self.addresses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn retain(&self, table: &StreamTable) {
        self.sources
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
    }
}

/// One connection's view of its connect phase.
pub(crate) struct Request<'a> {
    pub(crate) stream: &'a Stream,
    pub(crate) table: &'a StreamTable,
    pub(crate) listen_port: u16,
    pub(crate) client: IpAddr,
    pub(crate) accepted_at: std::time::Instant,
    pub(crate) bound: &'a BoundPorts,
    pub(crate) stats: &'a StreamStats,
}

/// An established backend connection.
pub(crate) struct Connected {
    pub(crate) backend: Arc<Backend>,
    pub(crate) address: SocketAddr,
    pub(crate) socket: TcpStream,
    pub(crate) latency: Duration,
}

struct Eligible<'a> {
    link: &'a LinkedBackend,
    addresses: Arc<[IpAddr]>,
    port: u16,
}

enum AttemptError {
    /// Nothing about the backend: no socket, or the source bind failed.
    Local(io::Error, bool),
    /// The backend did not take the connection.
    Backend(ConnectFailureKind, Option<io::Error>),
}

fn failure_kind(error: &io::Error) -> ConnectFailureKind {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => ConnectFailureKind::Refused,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
            ConnectFailureKind::Reset
        }
        io::ErrorKind::TimedOut => ConnectFailureKind::Timeout,
        _ => ConnectFailureKind::Unreachable,
    }
}

/// The port a connection to `backend` uses: its own, or the listen port
/// for a portless backend of a range stream.
fn backend_port(backend: &Backend, listen_port: u16) -> u16 {
    backend_address_port(&backend.address)
        .ok()
        .flatten()
        .unwrap_or(listen_port)
}

impl Shared {
    async fn eligible<'a>(
        &self,
        request: &Request<'a>,
        excluded: &HashSet<String>,
        resolve_deadline: Instant,
    ) -> Vec<Eligible<'a>> {
        let mut eligible = Vec::new();
        for link in request.table.linked_backends(&request.stream.id) {
            let backend = &link.backend;
            if excluded.contains(&backend.id)
                || backend.health_status == HealthStatus::Down
                || backend.lifecycle_state != LifecycleState::Normal
            {
                continue;
            }
            let host = backend_address_host(&backend.address);
            let addresses = match self.resolver.cached(host) {
                Some(known) => Some(known),
                None => {
                    let left = resolve_deadline.saturating_duration_since(Instant::now());
                    self.resolver.addresses(host, left).await
                }
            };
            if let Some(addresses) = addresses.filter(|a| !a.is_empty()) {
                eligible.push(Eligible {
                    link,
                    addresses,
                    port: backend_port(backend, request.listen_port),
                });
            }
        }
        let has_primary = eligible.iter().any(|e| !e.link.backup);
        eligible.retain(|e| e.link.backup != has_primary);
        eligible
    }

    /// Run the connect phase. `attempts` counts the attempts made, so a
    /// caller that drops the future still knows them.
    pub(crate) async fn connect(
        &self,
        request: &Request<'_>,
        attempts: &mut u32,
    ) -> Result<Connected, StreamEndReason> {
        let stream = request.stream;
        let connect_timeout = Duration::from_millis(u64::from(stream.connect_timeout_ms));
        let max_attempts = u32::from(stream.max_connect_attempts);
        let mut excluded: HashSet<String> = HashSet::new();
        let end = |attempts: u32| {
            if attempts == 0 {
                StreamEndReason::NoHealthyBackend
            } else {
                StreamEndReason::ConnectFailed
            }
        };
        loop {
            if *attempts >= max_attempts {
                return Err(end(*attempts));
            }
            let eligible = self
                .eligible(request, &excluded, Instant::now() + connect_timeout)
                .await;
            if eligible.is_empty() {
                return Err(end(*attempts));
            }
            let candidates: Vec<Candidate<'_>> = eligible
                .iter()
                .map(|e| Candidate {
                    backend: &e.link.backend,
                    ring_address: SocketAddr::new(e.addresses[0], e.port),
                })
                .collect();
            let index = self
                .selector
                .select(&SelectionRequest {
                    stream,
                    candidates: &candidates,
                    client: request.client,
                    accepted_at: request.accepted_at,
                })
                .min(candidates.len() - 1);
            let chosen = &eligible[index];
            let backend = Arc::clone(&chosen.link.backend);
            excluded.insert(backend.id.clone());

            let Some(destinations) = self.destinations(request, chosen) else {
                continue;
            };
            let (address, source) = match self.pick_source(request, &destinations) {
                Some(pair) => pair,
                None => {
                    request.stats.source_family_mismatch();
                    debug!(stream_id = %stream.id, backend_id = %backend.id,
                           "no source address of the backend's family: candidate skipped");
                    continue;
                }
            };

            let admission = self.breaker.admit(&stream.id, &backend).await;
            if admission == Admission::Deny {
                request.stats.breaker_denied();
                continue;
            }
            let was_probe = admission == Admission::AllowProbe;

            *attempts += 1;
            request.stats.connect_attempt(*attempts == 1);
            let started = Instant::now();
            match open(stream, address, source, connect_timeout).await {
                Ok(socket) => {
                    self.breaker
                        .record(&stream.id, &backend, true, was_probe)
                        .await;
                    return Ok(Connected {
                        backend,
                        address,
                        socket,
                        latency: started.elapsed(),
                    });
                }
                Err(AttemptError::Local(e, bind)) => {
                    if bind {
                        request.stats.source_bind_failed();
                    }
                    warn!(stream_id = %stream.id, backend_id = %backend.id, %address,
                          source = ?source, error = %e,
                          "stream backend socket not opened");
                }
                Err(AttemptError::Backend(kind, e)) => {
                    self.counters
                        .link(&stream.id, &backend.id)
                        .connect_failed(kind);
                    self.breaker
                        .record(&stream.id, &backend, false, was_probe)
                        .await;
                    debug!(stream_id = %stream.id, backend_id = %backend.id, %address,
                           kind = kind.as_str(), error = ?e,
                           "stream backend connect failed");
                }
            }
        }
    }

    /// The destinations of `chosen` the local check lets through, in
    /// rotating order; `None` when it refuses them all, which excludes
    /// the backend from this connection and is reported once per
    /// transition (IV4).
    fn destinations(
        &self,
        request: &Request<'_>,
        chosen: &Eligible<'_>,
    ) -> Option<Vec<SocketAddr>> {
        let interfaces = self.resolver.interfaces();
        let node = NodeLocality {
            interfaces: &interfaces,
            reserved: self.reserved.as_ref(),
            bound: request.bound,
        };
        let stream = request.stream;
        let backend = &chosen.link.backend;
        let count = chosen.addresses.len();
        let offset = self.rotation.next_address();
        let mut refusal: Option<LocalRefusal> = None;
        let allowed: Vec<SocketAddr> = (0..count)
            .map(|i| SocketAddr::new(chosen.addresses[(offset + i) % count], chosen.port))
            .filter(
                |destination| match node.check(*destination, stream.allow_local_backend) {
                    Ok(()) => true,
                    Err(r) => {
                        refusal = Some(r);
                        false
                    }
                },
            )
            .collect();
        if allowed.is_empty() {
            request.stats.local_destination_refused();
            if self.exclusions.set(&stream.id, &backend.id, true) {
                self.counters.backend(&backend.id).dns_local_excluded();
                warn!(stream_id = %stream.id, stream = %stream.name,
                      backend_id = %backend.id, backend = %backend.name,
                      addresses = ?chosen.addresses,
                      rule = refusal.map_or("", |r| r.as_str()),
                      "stream backend resolves to a refused local address: excluded from the stream");
            }
            return None;
        }
        self.exclusions.set(&stream.id, &backend.id, false);
        Some(allowed)
    }

    /// The first destination with a source address of its family, and
    /// that source (the stream's next in turn); `None` source when the
    /// stream sets no source address.
    fn pick_source(
        &self,
        request: &Request<'_>,
        destinations: &[SocketAddr],
    ) -> Option<(SocketAddr, Option<IpAddr>)> {
        let sources = &request.stream.source_addresses;
        if sources.is_empty() {
            return destinations.first().map(|d| (*d, None));
        }
        destinations.iter().find_map(|destination| {
            let family: Vec<IpAddr> = sources
                .iter()
                .copied()
                .filter(|s| s.is_ipv4() == destination.is_ipv4())
                .collect();
            if family.is_empty() {
                return None;
            }
            let turn = self.rotation.next_source(&request.stream.id);
            Some((*destination, Some(family[turn % family.len()])))
        })
    }
}

/// Open one backend connection: socket, source bind, connect within
/// `timeout`, `TCP_NODELAY`, keepalive.
async fn open(
    stream: &Stream,
    destination: SocketAddr,
    source: Option<IpAddr>,
    timeout: Duration,
) -> Result<TcpStream, AttemptError> {
    let socket = if destination.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(|e| AttemptError::Local(e, false))?;
    if let Some(source) = source {
        lorica_worker::stream_sockets::set_bind_address_no_port(&socket)
            .map_err(|e| AttemptError::Local(e.into(), true))?;
        socket
            .bind(SocketAddr::new(source, 0))
            .map_err(|e| AttemptError::Local(e, true))?;
    }
    let connected = match tokio::time::timeout(timeout, socket.connect(destination)).await {
        Err(_) => return Err(AttemptError::Backend(ConnectFailureKind::Timeout, None)),
        Ok(Err(e)) => return Err(AttemptError::Backend(failure_kind(&e), Some(e))),
        Ok(Ok(connected)) => connected,
    };
    // Interactive protocols must not wait on Nagle (nginx `stream`'s
    // `tcp_nodelay on`). A socket that refuses either option is still a
    // working connection.
    if let Err(e) = connected.set_nodelay(true) {
        debug!(error = %e, "TCP_NODELAY not set on a stream backend socket");
    }
    if stream.backend_keepalive {
        let keepalive = TcpKeepalive::new()
            .with_time(Duration::from_secs(u64::from(
                stream.backend_keepalive_idle_s,
            )))
            .with_interval(BACKEND_KEEPALIVE_INTERVAL)
            .with_retries(BACKEND_KEEPALIVE_PROBES);
        if let Err(e) = SockRef::from(&connected).set_tcp_keepalive(&keepalive) {
            debug!(error = %e, "keepalive not set on a stream backend socket");
        }
    }
    Ok(connected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_errors_map_to_their_kinds() {
        for (kind, expected) in [
            (
                io::ErrorKind::ConnectionRefused,
                ConnectFailureKind::Refused,
            ),
            (io::ErrorKind::ConnectionReset, ConnectFailureKind::Reset),
            (io::ErrorKind::TimedOut, ConnectFailureKind::Timeout),
            (
                io::ErrorKind::HostUnreachable,
                ConnectFailureKind::Unreachable,
            ),
            (
                io::ErrorKind::NetworkUnreachable,
                ConnectFailureKind::Unreachable,
            ),
        ] {
            assert_eq!(failure_kind(&io::Error::from(kind)), expected, "{kind:?}");
        }
    }
}
