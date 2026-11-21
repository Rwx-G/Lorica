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
//!
//! On a TLS stream (Story 12.4) the candidates are the matched rule's
//! links. With upstream TLS an attempt is TCP connect, the PROXY header
//! in plaintext, then the TLS handshake, all under the one connect
//! timeout, and it is connected when the handshake completes (Interface
//! edits I1 and I4): a failed handshake is a failed attempt and the next
//! candidate is tried, no client byte having been forwarded.
//!
//! A link at its `max_active` on the node (Story 12.6 D-h, nginx's
//! `max_conns`) leaves the candidates before selection, so backups serve
//! once every primary is at its cap. The chosen backend's place is
//! claimed before its first attempt and held to the end of the
//! connection, given back on a failed attempt; a claim that loses the
//! race for the last place passes over the backend, which is neither an
//! attempt nor reported to the breaker. No candidate left, with a cap
//! among the reasons and no attempt made: `refused(backend_cap)`.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    backend_address_host, Backend, Stream, StreamEndReason, StreamRefusal, StreamUpstreamTls,
};
use lorica_shmem::{BackendSlot, WorkerCaps};
use lorica_tls::{ClientConfig, ClientTlsStream};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::admission::{backend_at_cap, claim_backend};
use crate::counters::{ConnectFailureKind, StreamCounters, StreamStats, UpstreamTlsFailure};
use crate::local::BoundPorts;
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{Admission, BackendSelector, BreakerGate};
pub(crate) use crate::selection::Rotation;
use crate::selection::{choose, is_candidate, primaries_or_backups, Eligible, LocalCheck};
use crate::table::StreamTable;
use crate::tls::upstream;

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

/// One connection's view of its connect phase.
pub(crate) struct Request<'a> {
    pub(crate) stream: &'a Stream,
    pub(crate) table: &'a StreamTable,
    pub(crate) listen_port: u16,
    pub(crate) client: IpAddr,
    pub(crate) accepted_at: std::time::Instant,
    pub(crate) bound: &'a BoundPorts,
    pub(crate) stats: &'a StreamStats,
    /// The rule the ClientHello matched on a TLS stream: only its links
    /// are candidates. `None` on a stream that reads no ClientHello,
    /// whose links serve no rule.
    pub(crate) rule: Option<&'a str>,
    /// The stream's upstream TLS, when it originates TLS.
    pub(crate) upstream_tls: Option<UpstreamAttempt<'a>>,
    /// The region the connection is counted in, under this worker's
    /// slot: where its link caps are counted.
    pub(crate) backend_caps: Option<&'a WorkerCaps>,
}

/// What an attempt with upstream TLS needs.
pub(crate) struct UpstreamAttempt<'a> {
    /// The stream's settings.
    pub(crate) settings: &'a StreamUpstreamTls,
    /// Its client config, or why it has none on this node.
    pub(crate) config: Result<Arc<ClientConfig>, &'a str>,
    /// The client's SNI as matched, for `server_name = client`.
    pub(crate) client_sni: Option<&'a str>,
    /// The PROXY header, written in plaintext before the handshake.
    pub(crate) proxy_header: Option<&'a [u8]>,
}

/// The backend side of a connection: a socket, or TLS Lorica originates
/// over one.
pub(crate) enum Upstream {
    Plain(TcpStream),
    Tls(Box<ClientTlsStream<TcpStream>>),
}

impl Upstream {
    /// The socket under it.
    pub(crate) fn socket(&self) -> &TcpStream {
        match self {
            Upstream::Plain(socket) => socket,
            Upstream::Tls(tls) => tls.get_ref().0,
        }
    }

    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Upstream::Tls(_))
    }
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(socket) => Pin::new(socket).poll_read(cx, buf),
            Upstream::Tls(tls) => Pin::new(tls.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Upstream::Plain(socket) => Pin::new(socket).poll_write(cx, buf),
            Upstream::Tls(tls) => Pin::new(tls.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(socket) => Pin::new(socket).poll_flush(cx),
            Upstream::Tls(tls) => Pin::new(tls.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Plain(socket) => Pin::new(socket).poll_shutdown(cx),
            Upstream::Tls(tls) => Pin::new(tls.as_mut()).poll_shutdown(cx),
        }
    }
}

/// An established backend connection.
pub(crate) struct Connected {
    pub(crate) backend: Arc<Backend>,
    pub(crate) address: SocketAddr,
    pub(crate) socket: Upstream,
    pub(crate) latency: Duration,
    /// The connection's place on its link's `max_active`, if the link
    /// has one; held to the end of the connection.
    pub(crate) backend_slot: Option<BackendSlot>,
}

enum AttemptError {
    /// Nothing about the backend: no socket, or the source bind failed.
    Local(io::Error, bool),
    /// The backend did not take the connection.
    Backend(ConnectFailureKind, Option<io::Error>),
}

/// A failed upstream handshake, with what the breaker needs to judge it.
struct TlsFailure {
    kind: UpstreamTlsFailure,
    /// The name sent was the client's SNI (`server_name = client`).
    named_by_client: bool,
    was_probe: bool,
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

impl Shared {
    /// The candidates of the next selection. Sets `capped` when a link
    /// at its `max_active` was left out.
    async fn eligible<'a>(
        &self,
        request: &Request<'a>,
        excluded: &HashSet<String>,
        resolve_deadline: Instant,
        capped: &mut bool,
    ) -> Vec<Eligible<'a>> {
        let mut eligible = Vec::new();
        for link in request.table.linked_backends(&request.stream.id) {
            if link.rule.as_deref() != request.rule || !is_candidate(link, excluded) {
                continue;
            }
            if backend_at_cap(request.backend_caps, link) {
                *capped = true;
                continue;
            }
            let host = backend_address_host(&link.backend.address);
            let addresses = match self.resolver.cached(host) {
                Some(known) => Some(known),
                None => {
                    let left = resolve_deadline.saturating_duration_since(Instant::now());
                    self.resolver.addresses(host, left).await
                }
            };
            if let Some(addresses) = addresses.filter(|a| !a.is_empty()) {
                eligible.push(Eligible::new(link, addresses, request.listen_port));
            }
        }
        primaries_or_backups(&mut eligible);
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
        let mut capped = false;
        let end = |attempts: u32, capped: bool| {
            if attempts > 0 {
                StreamEndReason::ConnectFailed
            } else if capped {
                request.stats.refused(StreamRefusal::BackendCap);
                StreamEndReason::Refused(StreamRefusal::BackendCap)
            } else {
                StreamEndReason::NoHealthyBackend
            }
        };
        loop {
            if *attempts >= max_attempts {
                return Err(end(*attempts, capped));
            }
            let eligible = self
                .eligible(
                    request,
                    &excluded,
                    Instant::now() + connect_timeout,
                    &mut capped,
                )
                .await;
            if eligible.is_empty() {
                return Err(end(*attempts, capped));
            }
            let index = choose(
                self.selector.as_ref(),
                stream,
                &eligible,
                request.client,
                request.accepted_at,
            );
            let chosen = &eligible[index];
            let backend = Arc::clone(&chosen.link.backend);
            excluded.insert(backend.id.clone());
            let Ok(backend_slot) = claim_backend(request.backend_caps, chosen.link) else {
                capped = true;
                debug!(stream_id = %stream.id, backend_id = %backend.id,
                       "backend reached its max_active meanwhile: candidate skipped");
                continue;
            };

            let Some(destinations) =
                self.local_check()
                    .destinations(stream, request.bound, request.stats, chosen)
            else {
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

            // A stream whose upstream TLS has no config on this node opens
            // nothing: each attempt ends `no_trust` at once, and the
            // breaker, which judges backends, is never asked.
            let tls = match &request.upstream_tls {
                None => None,
                Some(attempt) => match (
                    &attempt.config,
                    upstream::server_name(
                        &attempt.settings.server_name,
                        &backend,
                        attempt.client_sni,
                    ),
                ) {
                    (Ok(config), Ok(name)) => Some((
                        attempt,
                        Arc::clone(config),
                        name,
                        upstream::named_by_client(
                            &attempt.settings.server_name,
                            attempt.client_sni,
                        ),
                    )),
                    (config, name) => {
                        *attempts += 1;
                        request.stats.connect_attempt(*attempts == 1);
                        self.counters
                            .link(&stream.id, &backend.id)
                            .upstream_tls_failed(UpstreamTlsFailure::NoTrust);
                        debug!(stream_id = %stream.id, backend_id = %backend.id,
                               config = ?config.as_ref().err(), name = ?name.err(),
                               "stream upstream TLS not configured: attempt ended no_trust");
                        continue;
                    }
                },
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
                    let socket = match tls {
                        None => Upstream::Plain(socket),
                        Some((attempt, config, name, named_by_client)) => {
                            let left = connect_timeout.saturating_sub(started.elapsed());
                            let established = tokio::time::timeout(
                                left,
                                originate(socket, attempt.proxy_header, config, name),
                            )
                            .await
                            .unwrap_or(Err(UpstreamTlsFailure::Timeout));
                            match established {
                                Ok(tls) => Upstream::Tls(Box::new(tls)),
                                Err(kind) => {
                                    let failure = TlsFailure {
                                        kind,
                                        named_by_client,
                                        was_probe,
                                    };
                                    self.upstream_tls_failed(stream, &backend, address, failure)
                                        .await;
                                    continue;
                                }
                            }
                        }
                    };
                    if socket.is_tls() {
                        self.counters
                            .link(&stream.id, &backend.id)
                            .upstream_tls_verified();
                    }
                    self.breaker
                        .record(&stream.id, &backend, true, was_probe)
                        .await;
                    return Ok(Connected {
                        backend,
                        address,
                        socket,
                        latency: started.elapsed(),
                        backend_slot,
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

    /// Count a failed upstream handshake and tell the breaker what it
    /// means. A reset, an alert or a timeout says the backend does not
    /// serve TLS correctly and counts against it. A certificate that does
    /// not verify says the configuration and the backend disagree: it is
    /// not counted, or one wrong bundle would trip every backend's
    /// breaker. Nor is a handshake refused on a name the client chose
    /// (`server_name = client`, Phase 1 audit C3): a strict-SNI backend
    /// refuses the names it does not serve, and a wildcard rule lets the
    /// client pick any, so counting it would let five clients open the
    /// circuit for all; a timeout still counts. A failure not counted
    /// answers only a half-open breaker's probe, as a success, since the
    /// backend did answer.
    async fn upstream_tls_failed(
        &self,
        stream: &Stream,
        backend: &Backend,
        address: SocketAddr,
        failure: TlsFailure,
    ) {
        let TlsFailure {
            kind,
            named_by_client,
            was_probe,
        } = failure;
        let first = self
            .counters
            .link(&stream.id, &backend.id)
            .upstream_tls_failed(kind);
        let client_chosen = named_by_client && kind == UpstreamTlsFailure::Handshake;
        if kind.is_backend_failure() && !client_chosen {
            self.breaker
                .record(&stream.id, backend, false, was_probe)
                .await;
        } else if was_probe {
            self.breaker.record(&stream.id, backend, true, true).await;
        }
        if first {
            warn!(stream_id = %stream.id, stream = %stream.name,
                  backend_id = %backend.id, backend = %backend.name, %address,
                  "stream backend's certificate does not verify against the stream's \
                   upstream TLS trust; logged once until a handshake verifies");
        } else {
            debug!(stream_id = %stream.id, backend_id = %backend.id, %address,
                   kind = kind.as_str(), "stream upstream TLS handshake failed");
        }
    }

    fn local_check(&self) -> LocalCheck<'_> {
        LocalCheck {
            resolver: &self.resolver,
            reserved: self.reserved.as_ref(),
            exclusions: &self.exclusions,
            counters: &self.counters,
            rotation: &self.rotation,
        }
    }

    /// The first destination with a source address of its family, and
    /// that source (the stream's next in turn); `None` source when the
    /// stream sets no source address.
    fn pick_source(
        &self,
        request: &Request<'_>,
        destinations: &[SocketAddr],
    ) -> Option<(SocketAddr, Option<IpAddr>)> {
        self.rotation
            .sources(request.stream, destinations)
            .map(|(destination, sources)| (destination, sources.first().copied()))
    }
}

/// The TLS half of an attempt on an open `socket`: the PROXY header in
/// plaintext first, as HAProxy's `send-proxy` with `ssl` and nginx's
/// `proxy_protocol` with `proxy_ssl` send it, then the handshake.
async fn originate(
    mut socket: TcpStream,
    proxy_header: Option<&[u8]>,
    config: Arc<ClientConfig>,
    name: lorica_tls::ServerName<'static>,
) -> Result<ClientTlsStream<TcpStream>, UpstreamTlsFailure> {
    if let Some(header) = proxy_header {
        socket
            .write_all(header)
            .await
            .map_err(|_| UpstreamTlsFailure::Handshake)?;
    }
    upstream::connect(config, name, socket).await
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
