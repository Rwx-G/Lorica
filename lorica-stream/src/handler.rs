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

//! The traits the stream engines implement: [`StreamHandler`] for TCP
//! (Story 12.3), [`DatagramHandler`] for UDP (Story 12.5), and the
//! [`ConnectionObserver`] an engine hands each finished connection's
//! [`ConnectionRecord`] to (Story 12.3 D-r), each refusal the refusal
//! log admits as a [`RefusalRecord`] (Story 12.6 D-j, as Story 12.9 D-c
//! amends it), and each connect phase's [`ConnectOutcome`] (Story 12.9
//! D-g).
//!
//! Until an engine is installed, [`Engines`] holds `None` and the loops
//! close an accepted TCP connection at once and drop a datagram, both
//! logged at debug (D-b; no release carries that interim).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_config::models::{
    Stream, StreamEndKind, StreamEndReason, StreamProtocol, StreamRefusal, StreamTlsMode,
};
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::caps::CapsRegistry;
use crate::counters::StreamCounters;
use crate::local::BoundPorts;
use crate::table::StreamTable;
use crate::tracker::{ConnectionTracker, TrackedConnection};

/// The future a TCP handler returns; the runtime spawns it.
pub type HandlerFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// A TCP connection accepted on a stream listener.
#[derive(Debug)]
pub struct AcceptedConnection {
    /// The client socket.
    pub stream: TcpStream,
    /// The client's address. On a dual-stack `[::]` listener an IPv4
    /// client shows as IPv4-mapped (`::ffff:192.0.2.10`).
    pub peer: SocketAddr,
    /// The binding the connection arrived on.
    pub bind_gen: u64,
    /// The connection's tracker entry, holding the stream snapshot it
    /// was accepted with. The engine keeps it for the connection's life,
    /// closes the client on [`TrackedConnection::closed`], and ends it
    /// with [`TrackedConnection::finish`].
    pub tracked: TrackedConnection,
    /// The table the connection was accepted against: the backends, their
    /// links and their health as of the accept (Story 12.3 D-i).
    pub table: Arc<StreamTable>,
    /// The listen ports this process holds, the connect-time local check
    /// refuses a local destination on any of them (Story 12.3 D-m).
    pub bound_ports: BoundPorts,
    /// The stream-caps regions this worker was handed, by stream id: the
    /// connection is counted in its stream's current one (Story 12.6
    /// D-e), or refused `caps_unavailable` when there is none.
    pub caps: CapsRegistry,
}

/// What serves TCP connections (Story 12.3).
pub trait StreamHandler: Send + Sync + 'static {
    /// Serve one accepted connection. Runs as its own task.
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture;

    /// Told after every table load, including the first, from the
    /// runtime's thread, so the engine prunes the state it keeps per
    /// stream or backend and learns the host names it must resolve,
    /// without polling (Story 12.3 D-i). Must not block.
    fn table_changed(&self, _table: &StreamTable) {}
}

/// A datagram received on a stream's UDP socket, borrowed from the
/// receive loop for the length of one [`DatagramHandler::handle`] call
/// (Story 12.5 D-c). An engine that keeps anything past the call (a new
/// session's socket, snapshot or table) clones it then, never per
/// datagram.
#[derive(Debug)]
pub struct Datagram<'a> {
    /// The payload, in the runtime thread's receive buffer
    /// ([`crate::listener::with_receive_buffer`]): nothing is copied or
    /// allocated per datagram.
    pub payload: &'a [u8],
    /// Where it came from, as the socket reports it: on a dual-stack
    /// `[::]` socket an IPv4 client shows IPv4-mapped.
    pub source: SocketAddr,
    /// The local address and port the datagram reached: the socket's own
    /// address for a specific listen address, and for `0.0.0.0` or
    /// `[::]` the destination `IP_PKTINFO` / `IPV6_PKTINFO` reported
    /// (Story 12.5 D-g), in the socket's family (IPv4-mapped on a
    /// dual-stack `[::]` socket), so a reply sent with it as source
    /// leaves from the address the client targeted.
    pub local: SocketAddr,
    /// The worker slot's socket it arrived on, to answer from.
    pub socket: &'a Arc<UdpSocket>,
    /// The binding the socket belongs to.
    pub bind_gen: u64,
    /// The stream as the table holds it now. A session the engine
    /// creates keeps a clone of this `Arc` for its life.
    pub snapshot: &'a Arc<Stream>,
    /// The table the datagram was received against: the backends, their
    /// links and their health (Story 12.3 D-i).
    pub table: &'a Arc<StreamTable>,
    /// The worker's tracker, where the engine registers a session.
    pub tracker: &'a ConnectionTracker,
    /// The listen ports this process holds, for the connect-time local
    /// check (Story 12.3 D-m).
    pub bound_ports: &'a BoundPorts,
    /// The stream-caps regions this worker was handed, by stream id
    /// (Story 12.5 D-d).
    pub caps: &'a CapsRegistry,
    /// Whether the binding is draining (Story 12.5 D-m): a datagram of
    /// an existing session is still served; one that would open a
    /// session is dropped and counted `binding_draining`, and no session
    /// is created.
    pub draining: bool,
}

/// What serves UDP datagrams (Story 12.5).
pub trait DatagramHandler: Send + Sync + 'static {
    /// Take one datagram, synchronously: the receive loop reads the next
    /// datagram only when this returns, so it never waits. Everything it
    /// does is a non-blocking syscall or an atomic; whatever must wait on
    /// a backend runs in a task the engine spawns (D-c).
    fn handle(&self, datagram: Datagram<'_>);

    /// Told after every table load, including the first, from the
    /// runtime's thread, as [`StreamHandler::table_changed`]. Must not
    /// block.
    fn table_changed(&self, _table: &StreamTable) {}
}

/// What one stream connection did, built once when it ends (Story 12.3
/// D-r). Story 12.9 writes it as the access-log row; Story 12.16 carries
/// the same values across a transfer.
///
/// A UDP session (Story 12.5 D-n) is recorded in the same shape: its
/// peer is its client, `proxied_from` is always `None` (PROXY accept is
/// refused on UDP), `local` is the address the client targeted, the
/// instants are the first datagram and the upstream socket's connect,
/// and the datagram counts are set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    /// The stream's id.
    pub stream_id: String,
    /// The stream's name as the connection's snapshot had it.
    pub stream_name: String,
    /// The stream's protocol: a UDP session is a record too, and nothing
    /// else in it may stand for the protocol (Story 12.9 D-a).
    pub protocol: StreamProtocol,
    /// The binding the connection arrived on.
    pub bind_gen: u64,
    /// The client: the source a trusted PROXY header carried, otherwise
    /// the socket peer. Canonical (no IPv4-mapped form).
    pub client: SocketAddr,
    /// The socket peer, canonical.
    pub peer: SocketAddr,
    /// The socket peer when a PROXY header replaced it as the client.
    pub proxied_from: Option<SocketAddr>,
    /// The accepted socket's local address, canonical.
    pub local: SocketAddr,
    /// The backend connected, if any attempt connected.
    pub backend_id: Option<String>,
    /// The address connected, if any attempt connected.
    pub backend_address: Option<SocketAddr>,
    /// Connect attempts made, the one that connected included.
    pub attempts: u32,
    /// Client-to-backend bytes forwarded (preamble included, the PROXY
    /// header the engine wrote excluded).
    pub bytes_upload: u64,
    /// Backend-to-client bytes forwarded.
    pub bytes_download: u64,
    /// Client datagrams forwarded to the backend; `None` on TCP.
    pub datagrams_upload: Option<u64>,
    /// Backend datagrams forwarded to the client; `None` on TCP.
    pub datagrams_download: Option<u64>,
    /// When the connection was accepted.
    pub accepted_at: DateTime<Utc>,
    /// When an attempt connected.
    pub connected_at: Option<DateTime<Utc>>,
    /// When the connection ended.
    pub ended_at: DateTime<Utc>,
    /// How it ended.
    pub end_reason: StreamEndReason,
    /// What TLS the connection read, terminated or originated (Story
    /// 12.4 D-m); `None` on a stream with no TLS at all and on UDP.
    pub tls: Option<TlsRecord>,
    /// The application protocol detection named (Story 12.15); `None`
    /// until that story fills it, and on a stream that does not detect.
    pub detected_protocol: Option<String>,
}

/// The TLS side of a [`ConnectionRecord`] (Story 12.4 D-m). Story 12.9
/// decides which of it the access log writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    /// The stream's TLS mode as the connection's snapshot had it.
    pub mode: StreamTlsMode,
    /// The server name the ClientHello carried, canonical; `None` when
    /// it carried none or was not read.
    pub server_name: Option<String>,
    /// The ALPN protocols the client offered, in its order, as sent.
    pub offered_alpn: Vec<Vec<u8>>,
    /// The protocol a terminating handshake negotiated.
    pub negotiated_alpn: Option<Vec<u8>>,
    /// The rule the ClientHello matched.
    pub rule: Option<String>,
    /// Whether the ClientHello carried an `encrypted_client_hello`
    /// extension.
    pub ech_offered: bool,
    /// What a terminating handshake made of the client's certificate;
    /// `None` when the stream does not terminate, does not verify client
    /// certificates, or the handshake did not complete (Story 12.9 D-a:
    /// the row's `client_cert` is null on a stream that does not verify).
    pub client_certificate: Option<ClientCertificateOutcome>,
    /// Whether the connection to the backend is TLS Lorica originates.
    pub upstream_tls: bool,
}

/// The client certificate of a completed terminating handshake on a
/// stream that verifies them. The subject is not recorded: the HTTP
/// access log records none either (Story 12.9 D-a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCertificateOutcome {
    /// The client presented none.
    Absent,
    /// The client presented one that verified against the stream's
    /// bundle and its organization allowlist.
    Verified,
}

/// One refusal the refusal log admitted (Story 12.6 D-j, Story 12.9
/// D-c): what the engine knows when it refuses. A refused connection or
/// session hands no [`ConnectionRecord`]; at most one of these per
/// stream and refusal per [`crate::REFUSAL_LOG_WINDOW`] per process
/// reaches the observer, so whoever connects cannot choose the rate at
/// which they are written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalRecord {
    /// The stream's id.
    pub stream_id: String,
    /// The stream's name as the refusing snapshot had it.
    pub stream_name: String,
    /// The stream's protocol.
    pub protocol: StreamProtocol,
    /// The local port the connection or datagram arrived on.
    pub listen_port: u16,
    /// The address judged (Story 12.6 D-b): the client a trusted PROXY
    /// header carried, otherwise the socket peer or datagram source.
    /// Canonical.
    pub client: SocketAddr,
    /// The socket peer when a PROXY header replaced it as the client.
    pub proxied_from: Option<SocketAddr>,
    /// Why it was refused.
    pub refusal: StreamRefusal,
    /// When it was refused.
    pub at: DateTime<Utc>,
}

/// What the refusal log limits per stream (Story 12.9 D-c): the ends
/// whoever connects chooses before any backend work, so a row per end
/// would let them choose the write rate of the access log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamLogKey {
    /// A refusal, which hands a [`RefusalRecord`] instead of a record.
    Refused(StreamRefusal),
    /// An end before forwarding, which hands its [`ConnectionRecord`]
    /// when the limiter admits it.
    PreForwarding(StreamEndKind),
}

impl StreamLogKey {
    /// The key of a connection or session that ended `reason`; `None`
    /// for an end whose row is written unconditionally, its rate being
    /// bounded by the stream's own admission.
    pub fn of(reason: StreamEndReason) -> Option<StreamLogKey> {
        match reason {
            StreamEndReason::Refused(refusal) => Some(StreamLogKey::Refused(refusal)),
            StreamEndReason::ClienthelloTimeout
            | StreamEndReason::ProxyHeaderInvalid
            | StreamEndReason::DetectionTimeout => Some(StreamLogKey::PreForwarding(reason.kind())),
            StreamEndReason::ClientClose
            | StreamEndReason::BackendClose
            | StreamEndReason::IdleTimeout
            | StreamEndReason::TotalTimeout
            | StreamEndReason::ConnectFailed
            | StreamEndReason::NoHealthyBackend
            | StreamEndReason::RequestBoundReached
            | StreamEndReason::ResponseBoundReached
            | StreamEndReason::BackendDown
            | StreamEndReason::ConfigRemoved
            | StreamEndReason::DrainedByUpgrade
            | StreamEndReason::NodeShutdown => None,
        }
    }

    /// The end kind a row of this key carries: `refused`, or the
    /// pre-forwarding end itself.
    pub fn end_kind(&self) -> StreamEndKind {
        match self {
            StreamLogKey::Refused(_) => StreamEndKind::Refused,
            StreamLogKey::PreForwarding(kind) => *kind,
        }
    }

    /// The refusal, for a refusal's key.
    pub fn refusal(&self) -> Option<StreamRefusal> {
        match self {
            StreamLogKey::Refused(refusal) => Some(*refusal),
            StreamLogKey::PreForwarding(_) => None,
        }
    }
}

/// The rows one window of the refusal log held back (Story 12.6 D-j,
/// Story 12.9 D-c), reported once when the window closes, or with the
/// first row of the key after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressedRecord {
    /// The stream's id.
    pub stream_id: String,
    /// The stream's name.
    pub stream_name: String,
    /// The stream's protocol.
    pub protocol: StreamProtocol,
    /// What the window counted: a refusal, or a pre-forwarding end.
    pub key: StreamLogKey,
    /// Rows held back, at least 1.
    pub suppressed: u64,
    /// When the count was reported: the window's end, or the first row
    /// of the key after it.
    pub reported_at: DateTime<Utc>,
}

/// How the connect phase of a connection or session resolved (Story
/// 12.9 D-g), reported once at the decision, not at the end: a TCP
/// connection can last hours, and its availability belongs to the
/// minute it connected in.
///
/// A connection that never reaches backend selection (a refusal, a
/// pre-forwarding end, a drain before the connect) reports nothing, nor
/// does one whose connect phase a drain or the total timeout cut short:
/// neither says anything about the backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// TCP: a backend connected after `latency`, from the start of the
    /// connect phase to the attempt that connected, retries included.
    /// The pre-forwarding reads before it are paced by the client, not
    /// the backends, so they are not part of it.
    Connected {
        /// Connect-phase start to connected.
        latency: Duration,
    },
    /// The connect phase ended without a backend: the connection or
    /// session ends `connect_failed` or `no_healthy_backend`.
    NotConnected,
    /// UDP: the session's first backend datagram arrived.
    Answered,
    /// UDP: an ICMP error came back from the backend before any datagram.
    IcmpError,
    /// UDP: a session owed responses went idle without any.
    NoResponse,
}

impl ConnectOutcome {
    /// The outcome of a connect phase that ended `reason` without a
    /// backend: [`ConnectOutcome::NotConnected`] when the selection ended
    /// it (`connect_failed`, `no_healthy_backend`), `None` for any other
    /// end. Only the selection says something about the backends; a
    /// drain, the total timeout or a refusal does not.
    pub fn for_unconnected(reason: StreamEndReason) -> Option<ConnectOutcome> {
        matches!(
            reason,
            StreamEndReason::ConnectFailed | StreamEndReason::NoHealthyBackend
        )
        .then_some(ConnectOutcome::NotConnected)
    }
}

/// Where an engine hands each [`ConnectionRecord`], each admitted
/// [`RefusalRecord`], each [`SuppressedRecord`] and each
/// [`ConnectOutcome`]. The default `observe` logs at debug; the engine
/// has already logged refusals and suppressed counts at debug when it
/// calls them, so those defaults do nothing, as does `connect_outcome`'s.
/// Story 12.9 installs the access-log writer.
pub trait ConnectionObserver: Send + Sync + 'static {
    /// Take one refusal the refusal log admitted. Runs on the stream
    /// runtime's thread, so it must not block.
    fn refused(&self, _record: RefusalRecord) {}

    /// Take the count of rows one window of the refusal log held back.
    /// Runs on the stream runtime's thread, so it must not block.
    fn refusals_suppressed(&self, _record: SuppressedRecord) {}

    /// Take how the connect phase of a connection or session of
    /// `stream_id` resolved, once per connection or session at most.
    /// Runs on the stream runtime's thread, so it must not block.
    fn connect_outcome(
        &self,
        _stream_id: &str,
        _protocol: StreamProtocol,
        _outcome: ConnectOutcome,
    ) {
    }

    /// Take the record of a connection that just ended. A connection
    /// that ended before forwarding hands its record only when the
    /// refusal log admits it ([`StreamLogKey::PreForwarding`]). Runs on
    /// the stream runtime's thread, so it must not block.
    fn observe(&self, record: ConnectionRecord) {
        debug!(
            stream_id = %record.stream_id,
            stream = %record.stream_name,
            protocol = record.protocol.as_str(),
            bind_gen = record.bind_gen,
            client = %record.client,
            peer = %record.peer,
            proxied_from = ?record.proxied_from,
            local = %record.local,
            backend_id = ?record.backend_id,
            backend_address = ?record.backend_address,
            attempts = record.attempts,
            bytes_upload = record.bytes_upload,
            bytes_download = record.bytes_download,
            datagrams_upload = ?record.datagrams_upload,
            datagrams_download = ?record.datagrams_download,
            accepted_at = %record.accepted_at,
            connected_at = ?record.connected_at,
            ended_at = %record.ended_at,
            end_reason = record.end_reason.kind().as_str(),
            tls = ?record.tls,
            detected_protocol = ?record.detected_protocol,
            "stream connection ended"
        );
    }
}

/// The observer that only logs, at debug.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogObserver;

impl ConnectionObserver for LogObserver {}

/// The engines installed in a runtime, `None` until their story lands,
/// and the counters they share.
#[derive(Clone, Default)]
pub struct Engines {
    /// The TCP engine.
    pub tcp: Option<Arc<dyn StreamHandler>>,
    /// The UDP engine.
    pub udp: Option<Arc<dyn DatagramHandler>>,
    /// The process's stream counters, the same `Arc` the engines were
    /// built with; [`crate::StreamRuntimeHandle::counters`] reads it.
    pub counters: Arc<StreamCounters>,
}

impl std::fmt::Debug for Engines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engines")
            .field("tcp", &self.tcp.is_some())
            .field("udp", &self.udp.is_some())
            .finish()
    }
}
