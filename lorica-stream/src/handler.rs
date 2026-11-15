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
//! [`ConnectionRecord`] to (Story 12.3 D-r).
//!
//! Until an engine is installed, [`Engines`] holds `None` and the loops
//! close an accepted TCP connection at once and drop a datagram, both
//! logged at debug (D-b; no release carries that interim).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lorica_config::models::{Stream, StreamEndReason};
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
}

/// Where an engine hands each [`ConnectionRecord`]. The default method
/// logs it at debug; Story 12.9 installs the access-log writer.
pub trait ConnectionObserver: Send + Sync + 'static {
    /// Take the record of a connection that just ended. Runs on the
    /// stream runtime's thread, so it must not block.
    fn observe(&self, record: ConnectionRecord) {
        debug!(
            stream_id = %record.stream_id,
            stream = %record.stream_name,
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
