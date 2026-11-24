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

//! The TCP engine and its connection pipeline (Story 12.3 D-b):
//!
//! 1. **Admit** (Story 12.6 D-a): canonicalise the peer and run the
//!    admission sequence of [`crate::admission`] before the socket is
//!    read: the stream's region, the node's and the stream's source
//!    controls, the open rates, the stream cap and, when phase 2 has
//!    work, the pending cap; then the source cap and the source's share
//!    of the pending cap. A trusted PROXY peer is admitted for the
//!    stream only; its carried client gets the source checks once the
//!    header is read (D-b).
//! 2. **Pre-forwarding**: reads that must finish before a backend is
//!    chosen, bounded in bytes and time, keeping what they read past
//!    their need as the preamble. Here, a trusted peer's PROXY header,
//!    then on a TLS stream the ClientHello, the rule it matches and, on
//!    a terminating stream, the handshake (Story 12.4); Story 12.15 adds
//!    detection. The whole phase holds one pending slot, given back when
//!    phase 3 starts or the connection ends.
//! 3. **Connect** ([`super::connect`]) over the matched rule's links,
//!    then the PROXY header to the backend in plaintext, before anything
//!    else on the socket; with upstream TLS the header and the handshake
//!    are part of the attempt.
//! 4. **Forward** ([`super::forward`]).
//! 5. **End**: the end reason; the record to the observer, or, for a
//!    connection that ends `refused(_)`, a row through the refusal log
//!    and no record (Story 12.6 D-j); a connection that ended before
//!    forwarding hands its record through the same log (Story 12.9 D-c);
//!    the region's counts and the gauges released by drop.
//!
//! The observer also hears how phase 3 resolved, once, when it does
//! ([`ConnectOutcome`], Story 12.9 D-g).
//!
//! The tracker's close and the total timeout are watched beside every
//! await of phases 2 to 4, so a drain ends a connection in any phase.
//! Closing means `shutdown(Both)` on both sockets, then drop: the peers
//! see a FIN.
//!
//! **Phase 2 on a TLS stream** (Story 12.4 D-b, D-e, D-f). Everything it
//! does ends by `accept + clienthello_timeout_ms`, the PROXY header
//! included. The ClientHello is read into one buffer of
//! [`CLIENTHELLO_BUFFER`] bytes, the PROXY read's leftover copied in
//! first; no rule matching it ends `refused(no_match)` before any byte is
//! forwarded or any handshake starts. In passthrough the whole buffer,
//! the hello and whatever followed it, is the preamble replayed to the
//! backend unchanged. In termination the buffer is replayed to rustls
//! through [`Rewind`], on the rule's config from the process's resolver,
//! and the server name rustls read must be the one the rule was chosen
//! by.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    Stream, StreamEndReason, StreamProtocol, StreamRefusal, StreamTlsMode,
};
use lorica_config::route_selection::canonical_hostname;
use lorica_core::protocols::proxy_protocol::{
    classify_prefix, Prefix, HEADER_READ_TIMEOUT, MAX_HEADER_LEN,
};
use lorica_tls::ClientConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::debug;

use super::connect::{Connected, Request, Rotation, Shared, UpstreamAttempt};
use super::forward::{close, Forwarder};
use super::proxy_header::{read_trusted, send_header, HeaderRead, TrustedPeers};
use crate::admission::{AdmissionControl, Admitted};
use crate::counters::{
    ClientHelloOutcome, HandshakeOutcome, ProxyHeaderOutcome, StreamCounters, StreamStats,
};
use crate::handler::{
    AcceptedConnection, ConnectOutcome, ConnectionObserver, ConnectionRecord, HandlerFuture,
    RefusalRecord, StreamHandler, TlsRecord,
};
use crate::local::BoundPorts;
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{BackendSelector, BreakerGate, SourceGate};
use crate::table::StreamTable;
use crate::tls::client_hello::{
    parse, ClientHelloError, InvalidClientHello, Parsed, CLIENTHELLO_BUFFER,
};
use crate::tls::rewind::Rewind;
use crate::tls::{client_auth, matcher, server, TlsContext, TlsParts};
use crate::tracker::TrackedConnection;
use crate::{canonical, sleep_until_opt};

// What a trusted peer's PROXY read leaves past its header always fits in
// the ClientHello buffer it is copied into.
const _: () = assert!(MAX_HEADER_LEN <= CLIENTHELLO_BUFFER);

/// What the TCP engine is built from. The selector, the breaker gate
/// and the resolver cache are the process's, shared with the UDP engine
/// (Story 12.5 Interface edit E3); `counters` is the `Arc` the runtime's
/// [`crate::Engines::counters`] holds.
pub struct TcpEngineParts {
    /// Backend selection.
    pub selector: Arc<dyn BackendSelector>,
    /// The circuit breaker.
    pub breaker: Arc<dyn BreakerGate>,
    /// Host names and the node's interface addresses.
    pub resolver: Arc<ResolverCache>,
    /// The process's stream counters.
    pub counters: Arc<StreamCounters>,
    /// Where each connection's record and each admitted refusal goes.
    pub observer: Arc<dyn ConnectionObserver>,
    /// The node's reserved ports, for the connect-time local check;
    /// `None` until the process knows them (rule B then covers the
    /// stream listen ports only).
    pub reserved_ports: Option<ReservedPorts>,
    /// The node's source controls (Story 12.6 D-d), shared with the UDP
    /// engine.
    pub source_gate: Arc<dyn SourceGate>,
}

/// The TCP stream engine, a [`StreamHandler`].
#[derive(Clone)]
pub struct TcpEngine {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TcpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpEngine").finish_non_exhaustive()
    }
}

struct Inner {
    shared: Shared,
    observer: Arc<dyn ConnectionObserver>,
    admission: AdmissionControl,
    tls: TlsContext,
    /// The trust lists of the streams that accept PROXY headers, parsed
    /// once per table rather than on every accept.
    trusted_peers: Mutex<HashMap<String, Arc<TrustedPeers>>>,
}

impl TcpEngine {
    /// An engine over `parts`, with no certificate and no public roots
    /// ([`TlsParts::without_certificates`]): its terminating streams
    /// refuse every handshake `no_certificate`, and upstream TLS on the
    /// public roots ends `no_trust`. A process serving TLS streams builds
    /// its engine with [`TcpEngine::with_tls`].
    pub fn new(parts: TcpEngineParts) -> Self {
        Self::with_tls(parts, TlsParts::without_certificates())
    }

    /// An engine over `parts` whose TLS streams terminate with the
    /// certificates of `tls.resolver` and verify upstream TLS against
    /// `tls.public_roots` (Story 12.4 D-a).
    pub fn with_tls(parts: TcpEngineParts, tls: TlsParts) -> Self {
        TcpEngine {
            inner: Arc::new(Inner {
                shared: Shared {
                    selector: parts.selector,
                    breaker: parts.breaker,
                    resolver: parts.resolver,
                    counters: parts.counters,
                    reserved: parts.reserved_ports,
                    exclusions: LocalExclusions::default(),
                    rotation: Rotation::default(),
                },
                admission: AdmissionControl::new(parts.source_gate, Arc::clone(&parts.observer)),
                observer: parts.observer,
                tls: TlsContext::new(tls),
                trusted_peers: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl StreamHandler for TcpEngine {
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.serve(conn).await })
    }

    fn table_changed(&self, table: &StreamTable) {
        let shared = &self.inner.shared;
        shared.resolver.track(table);
        shared.selector.table_changed(table);
        shared.counters.retain(table);
        shared.exclusions.retain(table);
        shared.rotation.retain(table);
        self.inner.admission.table_changed(table);
        self.inner.tls.table_changed(table);
        self.inner.trusted_peers_changed(table);
    }
}

/// Run `work` unless the tracker closes the connection or the total
/// timeout fires first; either gives the end reason. Dropping `work`
/// drops whatever it had in flight (a half-open backend socket among
/// them), which reports nothing to the breaker.
async fn guarded<T>(
    tracked: &mut TrackedConnection,
    total: Option<Instant>,
    work: impl std::future::Future<Output = T>,
) -> Result<T, StreamEndReason> {
    tokio::select! {
        biased;
        reason = tracked.closed() => Err(reason),
        _ = sleep_until_opt(total) => Err(StreamEndReason::TotalTimeout),
        out = work => Ok(out),
    }
}

/// One connection while the engine serves it: the client socket, and
/// the rest apart, so a TLS stream wrapping the socket leaves the rest
/// usable.
struct Live {
    client: TcpStream,
    conn: Conn,
}

/// Everything of a live connection but its client socket.
struct Conn {
    tracked: TrackedConnection,
    table: Arc<StreamTable>,
    bound_ports: BoundPorts,
    accepted_at: Instant,
    total: Option<Instant>,
    record: ConnectionRecord,
    /// The connection's counts in its stream's region, given back when
    /// it ends; the pending slot is given back when phase 3 starts.
    admitted: Admitted,
}

impl Conn {
    fn tls_record(&mut self) -> Option<&mut TlsRecord> {
        self.record.tls.as_mut()
    }
}

/// A complete ClientHello and the buffer it was read into: the hello,
/// then whatever the client sent after it.
struct Hello {
    buf: Vec<u8>,
    parsed: Parsed,
}

/// What phases 3 and 4 need from phase 2.
struct Route<'a> {
    /// The rule matched, on a TLS stream.
    rule: Option<&'a str>,
    /// The destination the PROXY header sent to the backend names.
    destination: SocketAddr,
    /// Client bytes read before forwarding, replayed first; their
    /// buffer becomes the forwarder's upload buffer.
    preamble: Vec<u8>,
    /// Whether the forwarding loop checks the client's first bytes for a
    /// PROXY signature.
    classify: bool,
    /// The client's SNI as matched.
    client_sni: Option<&'a str>,
    /// The stream's upstream TLS config, or why it has none.
    upstream: Option<Result<Arc<ClientConfig>, &'a str>>,
}

impl Inner {
    fn trusted_peers_changed(&self, table: &StreamTable) {
        let lists = table
            .streams()
            .filter(|stream| stream.proxy_protocol_accept)
            .map(|stream| {
                (
                    stream.id.clone(),
                    Arc::new(TrustedPeers::of(&stream.proxy_protocol_trusted_cidrs)),
                )
            })
            .collect();
        *self
            .trusted_peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = lists;
    }

    /// Whether `peer` is a trusted PROXY peer of `stream`, from the list
    /// the last table parsed when it is the list of the connection's
    /// snapshot; a snapshot the engine has not seen parsed is read on
    /// the spot.
    fn trusts(&self, stream: &Stream, peer: IpAddr) -> bool {
        let parsed = self
            .trusted_peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream.id)
            .cloned();
        match parsed {
            Some(list) if list.lists(&stream.proxy_protocol_trusted_cidrs) => list.contains(peer),
            _ => TrustedPeers::of(&stream.proxy_protocol_trusted_cidrs).contains(peer),
        }
    }

    async fn serve(&self, conn: AcceptedConnection) {
        let accepted_at = Instant::now();
        let snapshot = Arc::clone(conn.tracked.snapshot());
        let stats = self.shared.counters.stream(&snapshot.id);
        let _active = stats.accept();
        let peer = canonical(conn.peer);
        let local = conn.stream.local_addr().map(canonical).unwrap_or(peer);
        let trusted = snapshot.proxy_protocol_accept && self.trusts(&snapshot, peer.ip());
        let pending = trusted || snapshot.tls_mode.reads_client_hello();
        let admitted = match self.admission.admit_connection(
            &conn.caps,
            &snapshot,
            &stats,
            peer.ip(),
            trusted,
            pending,
        ) {
            Ok(admitted) => admitted,
            Err(refusal) => {
                stats.refused(refusal);
                close(&conn.stream);
                // Reported before the entry leaves the tracker, so a
                // drain never ends with the refusal still in flight.
                conn.tracked
                    .finish(StreamEndReason::Refused(refusal), |reason| {
                        stats.ended(reason.kind());
                        self.admission.report(RefusalRecord::new(
                            &snapshot,
                            StreamProtocol::Tcp,
                            local.port(),
                            peer,
                            refusal,
                        ));
                    });
                return;
            }
        };
        // Both sockets of an admitted connection go without Nagle (D-c,
        // nginx `stream`'s `tcp_nodelay on`): an answer the backend sends
        // in two segments must not wait for the client's delayed ACK of
        // the first. A refused connection is closed before it matters.
        if let Err(e) = conn.stream.set_nodelay(true) {
            debug!(stream_id = %snapshot.id, error = %e,
                   "TCP_NODELAY not set on a stream client socket");
        }
        let mut record = ConnectionRecord::accepted(
            &snapshot,
            StreamProtocol::Tcp,
            conn.bind_gen,
            peer,
            local,
            Utc::now(),
        );
        record.tls = (snapshot.tls_mode != StreamTlsMode::None || snapshot.upstream_tls.is_some())
            .then(|| TlsRecord {
                mode: snapshot.tls_mode,
                server_name: None,
                offered_alpn: Vec::new(),
                negotiated_alpn: None,
                rule: None,
                ech_offered: false,
                client_certificate: None,
                upstream_tls: snapshot.upstream_tls.is_some(),
            });
        let mut live = Live {
            client: conn.stream,
            conn: Conn {
                tracked: conn.tracked,
                table: conn.table,
                bound_ports: conn.bound_ports,
                accepted_at,
                total: snapshot
                    .total_timeout_s
                    .map(|s| accepted_at + Duration::from_secs(u64::from(s))),
                record,
                admitted,
            },
        };

        let natural = self.pipeline(&mut live, trusted).await;
        close(&live.client);
        let Conn {
            tracked,
            mut record,
            admitted,
            ..
        } = live.conn;
        drop(admitted);
        // The record is handed over before the entry leaves the tracker
        // (Story 12.9 D-k): a drain waiting for an empty tracker then
        // never stops with a row still in flight.
        tracked.finish(natural, |reason| {
            stats.ended(reason.kind());
            record.end(reason);
            // A refused connection is a row through the refusal log, not
            // a record (D-j), and one that ended before forwarding passes
            // the same log (Story 12.9 D-c): whoever connects chooses how
            // often either happens.
            self.admission.ended(record);
        });
    }

    /// Phases 2 to 4; returns the natural end reason. `trusted`: the
    /// peer is a trusted PROXY peer, admitted for the stream only.
    async fn pipeline(&self, live: &mut Live, trusted: bool) -> StreamEndReason {
        let snapshot = Arc::clone(live.conn.tracked.snapshot());
        let stats = self.shared.counters.stream(&snapshot.id);
        let accepted_at = live.conn.accepted_at;
        let hello_deadline = snapshot.tls_mode.reads_client_hello().then(|| {
            accepted_at
                + Duration::from_millis(u64::from(snapshot.effective_clienthello_timeout_ms()))
        });

        // Phase 2: a trusted peer's PROXY header. On a TLS stream it is
        // bounded by the ClientHello deadline too: phase 2 as a whole
        // ends by that instant.
        let mut destination = live.conn.record.local;
        let mut preamble = Vec::new();
        if trusted {
            let header_deadline = accepted_at + HEADER_READ_TIMEOUT;
            let deadline = hello_deadline.map_or(header_deadline, |d| d.min(header_deadline));
            let read = guarded(
                &mut live.conn.tracked,
                live.conn.total,
                read_trusted(&mut live.client, deadline),
            )
            .await;
            match read {
                Err(reason) => return reason,
                Ok(HeaderRead::Refused(ProxyHeaderOutcome::RefusedTimeout))
                    if hello_deadline.is_some_and(|d| d <= header_deadline) =>
                {
                    stats.clienthello(ClientHelloOutcome::Timeout);
                    return StreamEndReason::ClienthelloTimeout;
                }
                Ok(HeaderRead::Refused(outcome)) => {
                    stats.proxy_header(outcome);
                    debug!(stream_id = %snapshot.id, peer = %live.conn.record.peer,
                           outcome = outcome.as_str(), "PROXY header refused");
                    return StreamEndReason::ProxyHeaderInvalid;
                }
                Ok(HeaderRead::Accepted {
                    outcome,
                    carried,
                    preamble: rest,
                }) => {
                    stats.proxy_header(outcome);
                    if let Some((source, carried_destination)) = carried {
                        live.conn.record.proxied_from = Some(live.conn.record.peer);
                        live.conn.record.client = source;
                        destination = carried_destination;
                    }
                    preamble = rest;
                    // The source checks the peer skipped, on the client
                    // the header carried (D-b), before any byte moves.
                    if let Err(refusal) = self.admission.admit_carried(
                        &mut live.conn.admitted,
                        &snapshot,
                        &stats,
                        live.conn.record.client.ip(),
                    ) {
                        stats.refused(refusal);
                        return StreamEndReason::Refused(refusal);
                    }
                }
            }
        }
        let classify = snapshot.proxy_protocol_accept && !trusted;

        // Phase 2 on a TLS stream: the ClientHello and the rule it
        // matches.
        let hello = match hello_deadline {
            None => None,
            Some(deadline) => {
                match self
                    .read_client_hello(live, std::mem::take(&mut preamble), deadline, classify)
                    .await
                {
                    Ok(hello) => Some(hello),
                    Err(reason) => return reason,
                }
            }
        };
        let rule: Option<String> = match &hello {
            None => None,
            Some(hello) => {
                let parsed = &hello.parsed;
                let Some(rule) = matcher::select(
                    &snapshot.match_rules,
                    parsed.server_name.as_deref(),
                    &parsed.alpn,
                ) else {
                    stats.refused(StreamRefusal::NoMatch);
                    debug!(stream_id = %snapshot.id, peer = %live.conn.record.peer,
                           server_name = ?parsed.server_name, "ClientHello matches no rule");
                    return StreamEndReason::Refused(StreamRefusal::NoMatch);
                };
                if parsed.server_name.is_none() {
                    stats.no_sni_matched();
                }
                self.shared
                    .counters
                    .rule(&snapshot.id, &rule.name)
                    .matched();
                if let Some(tls) = live.conn.tls_record() {
                    tls.rule = Some(rule.name.clone());
                }
                Some(rule.name.clone())
            }
        };

        let configs = (snapshot.tls_mode == StreamTlsMode::Terminate
            || snapshot.upstream_tls.is_some())
        .then(|| self.tls.configs(&snapshot, &live.conn.table));
        let upstream = configs.as_ref().and_then(|configs| {
            configs
                .upstream
                .as_ref()
                .map(|config| config.as_ref().map(Arc::clone).map_err(String::as_str))
        });
        let client_sni = hello
            .as_ref()
            .and_then(|hello| hello.parsed.server_name.clone());

        match (snapshot.tls_mode, hello) {
            (StreamTlsMode::Terminate, Some(hello)) => {
                let Some(Ok(terminate)) = configs.as_ref().and_then(|c| c.terminate.as_ref())
                else {
                    return handshake_refused(&stats, &snapshot, HandshakeOutcome::TlsHandshake);
                };
                let local_ip = live.conn.record.local.ip();
                let resolver = &self.tls.parts.resolver;
                let no_certificate = match &hello.parsed.server_name {
                    Some(name) => !resolver.serves_server_name(name),
                    None => !resolver.serves_local_ip(local_ip),
                };
                // A rule and the deadline exist on every stream that read
                // a hello, and the configs were built from this snapshot's
                // rules: the refusal below is never reached in practice.
                let Some(((rule, deadline), config)) = rule
                    .as_deref()
                    .zip(hello_deadline)
                    .and_then(|(rule, deadline)| {
                        terminate
                            .config(rule, local_ip)
                            .map(|config| ((rule, deadline), config))
                    })
                else {
                    return handshake_refused(&stats, &snapshot, HandshakeOutcome::TlsHandshake);
                };
                let Hello { buf, parsed } = hello;
                let accepted = guarded(
                    &mut live.conn.tracked,
                    live.conn.total,
                    tokio::time::timeout_at(
                        deadline,
                        server::accept(config, Rewind::new(buf, &mut live.client)),
                    ),
                )
                .await;
                let mut tls = match accepted {
                    Err(reason) => return reason,
                    Ok(handshake) => match handshake.unwrap_or(Err(HandshakeOutcome::TlsHandshake))
                    {
                        Ok(tls) => tls,
                        Err(_) if no_certificate => {
                            return handshake_refused(
                                &stats,
                                &snapshot,
                                HandshakeOutcome::NoCertificate,
                            )
                        }
                        Err(outcome) => return handshake_refused(&stats, &snapshot, outcome),
                    },
                };
                stats.handshake(HandshakeOutcome::Ok);
                let (_, connection) = tls.get_ref();
                let read_by_rustls = connection
                    .server_name()
                    .map(|name| canonical_hostname(name).into_owned());
                if read_by_rustls != parsed.server_name {
                    stats.sni_mismatch();
                    stats.refused(StreamRefusal::InvalidClientHello);
                    debug!(stream_id = %snapshot.id, parsed = ?parsed.server_name,
                           rustls = ?read_by_rustls,
                           "the two ClientHello readers disagree on the server name");
                    return StreamEndReason::Refused(StreamRefusal::InvalidClientHello);
                }
                let client_auth = snapshot
                    .tls_terminate
                    .as_ref()
                    .and_then(|terminate| terminate.client_auth.as_ref());
                let negotiated = connection.alpn_protocol().map(<[u8]>::to_vec);
                // `None` on a stream that does not verify: its row says
                // null there, not `absent` (Story 12.9 D-a).
                let certificate = match client_auth {
                    None => None,
                    Some(auth) => match client_auth::admit(auth, connection.peer_certificates()) {
                        Some(outcome) => Some(outcome),
                        None => {
                            stats.refused(StreamRefusal::ClientCertificate);
                            debug!(stream_id = %snapshot.id, peer = %live.conn.record.peer,
                                   "client certificate organization not admitted");
                            return StreamEndReason::Refused(StreamRefusal::ClientCertificate);
                        }
                    },
                };
                if let Some(record) = live.conn.tls_record() {
                    record.negotiated_alpn = negotiated;
                    record.client_certificate = certificate;
                }
                let route = Route {
                    rule: Some(rule),
                    destination,
                    preamble: Vec::new(),
                    classify: false,
                    client_sni: client_sni.as_deref(),
                    upstream,
                };
                self.connect_and_forward(&mut tls, &mut live.conn, &snapshot, &stats, route)
                    .await
            }
            (_, hello) => {
                // Passthrough replays the ClientHello and whatever
                // followed it; a stream without TLS replays what the
                // PROXY read left.
                let replayed = hello.map_or(preamble, |hello| hello.buf);
                let route = Route {
                    rule: rule.as_deref(),
                    destination,
                    preamble: replayed,
                    classify: classify && hello_deadline.is_none(),
                    client_sni: client_sni.as_deref(),
                    upstream,
                };
                self.connect_and_forward(&mut live.client, &mut live.conn, &snapshot, &stats, route)
                    .await
            }
        }
    }

    /// Read the ClientHello into the [`CLIENTHELLO_BUFFER`], `leftover`
    /// (the PROXY read's) first, complete by `deadline`.
    async fn read_client_hello(
        &self,
        live: &mut Live,
        leftover: Vec<u8>,
        deadline: Instant,
        classify: bool,
    ) -> Result<Hello, StreamEndReason> {
        let snapshot = Arc::clone(live.conn.tracked.snapshot());
        let stats = self.shared.counters.stream(&snapshot.id);
        let mut buf = vec![0u8; CLIENTHELLO_BUFFER];
        buf[..leftover.len()].copy_from_slice(&leftover);
        let mut filled = leftover.len();
        loop {
            match parse(&buf[..filled]) {
                Ok(parsed) => {
                    stats.clienthello(ClientHelloOutcome::Parsed);
                    if parsed.ech_offered {
                        stats.ech_offered();
                    }
                    if let Some(tls) = live.conn.tls_record() {
                        tls.server_name = parsed.server_name.clone();
                        tls.offered_alpn = parsed.alpn.clone();
                        tls.ech_offered = parsed.ech_offered;
                    }
                    buf.truncate(filled);
                    return Ok(Hello { buf, parsed });
                }
                Err(ClientHelloError::NeedMore) => {}
                Err(ClientHelloError::Invalid(kind)) => {
                    // An untrusted peer on an accepting stream opening
                    // with a PROXY signature is refused as such, as on a
                    // stream without TLS.
                    let prefix = if classify {
                        classify_prefix(&buf[..filled])
                    } else {
                        Prefix::NotProxy
                    };
                    match prefix {
                        Prefix::V1 | Prefix::V2 => {
                            stats.proxy_header(ProxyHeaderOutcome::RefusedUntrustedPeer);
                            return Err(StreamEndReason::ProxyHeaderInvalid);
                        }
                        Prefix::NeedMore => {}
                        Prefix::NotProxy => {
                            stats.clienthello(if kind == InvalidClientHello::Oversized {
                                ClientHelloOutcome::Oversized
                            } else {
                                ClientHelloOutcome::Invalid
                            });
                            stats.refused(StreamRefusal::InvalidClientHello);
                            debug!(stream_id = %snapshot.id, peer = %live.conn.record.peer,
                                   kind = kind.as_str(), "ClientHello refused");
                            return Err(StreamEndReason::Refused(
                                StreamRefusal::InvalidClientHello,
                            ));
                        }
                    }
                }
            }
            // A full buffer cannot be `NeedMore` (the reader refuses a
            // hello that would not fit); reading into no room gives 0,
            // which ends the connection as a close.
            let read = guarded(
                &mut live.conn.tracked,
                live.conn.total,
                tokio::time::timeout_at(deadline, live.client.read(&mut buf[filled..])),
            )
            .await;
            match read {
                Err(reason) => return Err(reason),
                Ok(Err(_elapsed)) => {
                    stats.clienthello(ClientHelloOutcome::Timeout);
                    return Err(StreamEndReason::ClienthelloTimeout);
                }
                Ok(Ok(Ok(0))) => return Err(StreamEndReason::ClientClose),
                // A reset or another error before the hello is complete:
                // the client's end, logged since nothing else says why.
                Ok(Ok(Err(e))) => {
                    debug!(stream_id = %snapshot.id, peer = %live.conn.record.peer,
                           error = %e, "ClientHello read failed");
                    return Err(StreamEndReason::ClientClose);
                }
                Ok(Ok(Ok(n))) => filled += n,
            }
        }
    }

    /// Phases 3 and 4 for a connection whose client side is `client`:
    /// the plain socket, or the TLS stream Lorica terminated over it.
    async fn connect_and_forward<C>(
        &self,
        client: &mut C,
        conn: &mut Conn,
        snapshot: &Arc<Stream>,
        stats: &Arc<StreamStats>,
        route: Route<'_>,
    ) -> StreamEndReason
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        // Phase 2 is over: its pending slot goes back before the connect,
        // whose own bound is the connect timeout.
        conn.admitted.end_pending();
        let backend_caps = conn.admitted.worker_caps();
        let header = send_header(
            snapshot.proxy_protocol_send,
            conn.record.client,
            route.destination,
        );
        let upstream_tls = snapshot
            .upstream_tls
            .as_ref()
            .map(|settings| UpstreamAttempt {
                settings,
                config: route
                    .upstream
                    .clone()
                    .unwrap_or(Err("the stream's upstream TLS has no config")),
                client_sni: route.client_sni,
                proxy_header: header.as_deref(),
            });

        // Phase 3: connect.
        let request = Request {
            stream: snapshot,
            table: &conn.table,
            listen_port: conn.record.local.port(),
            client: conn.record.client.ip(),
            accepted_at: conn.accepted_at.into_std(),
            bound: &conn.bound_ports,
            stats,
            rule: route.rule,
            upstream_tls,
            backend_caps: backend_caps.as_ref(),
        };
        let mut attempts = 0;
        let connect_started = Instant::now();
        let connected = guarded(
            &mut conn.tracked,
            conn.total,
            self.shared.connect(&request, &mut attempts),
        )
        .await;
        conn.record.attempts = attempts;
        let Connected {
            backend,
            address,
            socket: mut upstream,
            latency,
            backend_slot: _backend_slot,
        } = match connected {
            Err(reason) => return reason,
            Ok(Err(reason)) => {
                if let Some(outcome) = ConnectOutcome::for_unconnected(reason) {
                    self.observer
                        .connect_outcome(&snapshot.id, StreamProtocol::Tcp, outcome);
                }
                return reason;
            }
            Ok(Ok(connected)) => connected,
        };
        self.observer.connect_outcome(
            &snapshot.id,
            StreamProtocol::Tcp,
            ConnectOutcome::Connected {
                latency: connect_started.elapsed(),
            },
        );
        conn.tracked.set_backend(&backend.id);
        conn.record.backend_id = Some(backend.id.clone());
        conn.record.backend_address = Some(address);
        conn.record.connected_at = Some(Utc::now());
        self.shared
            .selector
            .connected(&snapshot.id, &backend, address, latency);
        let link = self.shared.counters.link(&snapshot.id, &backend.id);
        let _link_active = link.connected(latency);

        // The PROXY header goes first, in plaintext. Committed: a failure
        // here is the backend's close, never a retry. With upstream TLS
        // the attempt already sent it, before its handshake.
        let sent = match header.filter(|_| !upstream.is_tls()) {
            Some(header) => {
                match guarded(&mut conn.tracked, conn.total, upstream.write_all(&header)).await {
                    Err(reason) => Err(reason),
                    Ok(Err(_)) => Err(StreamEndReason::BackendClose),
                    Ok(Ok(())) => Ok(()),
                }
            }
            None => Ok(()),
        };

        // Phase 4: forward.
        let reason = match sent {
            Err(reason) => reason,
            Ok(()) => {
                let mut forwarder = Forwarder::new(
                    snapshot,
                    conn.accepted_at,
                    route.preamble,
                    route.classify,
                    Arc::clone(stats),
                )
                .counting_link(link);
                let reason = forwarder
                    .run(client, &mut upstream, &mut conn.tracked)
                    .await;
                conn.record.bytes_upload = forwarder.upload().forwarded();
                conn.record.bytes_download = forwarder.download().forwarded();
                reason
            }
        };
        close(upstream.socket());
        self.shared.selector.closed(&snapshot.id, &backend, address);
        reason
    }
}

/// Count a terminating handshake that failed with `outcome` and end the
/// connection with its refusal.
fn handshake_refused(
    stats: &StreamStats,
    snapshot: &Stream,
    outcome: HandshakeOutcome,
) -> StreamEndReason {
    stats.handshake(outcome);
    let refusal = outcome.refusal().unwrap_or(StreamRefusal::TlsHandshake);
    stats.refused(refusal);
    debug!(stream_id = %snapshot.id, outcome = outcome.as_str(), "TLS handshake refused");
    StreamEndReason::Refused(refusal)
}
