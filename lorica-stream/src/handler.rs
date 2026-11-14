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
//! (Story 12.3), [`DatagramHandler`] for UDP (Story 12.5).
//!
//! Until an engine is installed, [`Engines`] holds `None` and the loops
//! close an accepted TCP connection at once and drop a datagram, both
//! logged at debug (D-b; no release carries that interim).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use lorica_config::models::Stream;
use tokio::net::{TcpStream, UdpSocket};

use crate::tracker::{ConnectionTracker, TrackedConnection};

/// The future a handler returns; the runtime spawns it.
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
}

/// What serves TCP connections (Story 12.3).
pub trait StreamHandler: Send + Sync + 'static {
    /// Serve one accepted connection. Runs as its own task.
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture;
}

/// A datagram received on a stream's UDP socket.
#[derive(Debug)]
pub struct Datagram {
    /// The payload.
    pub payload: Vec<u8>,
    /// Where it came from.
    pub source: SocketAddr,
    /// The worker slot's socket it arrived on, to answer from.
    pub socket: Arc<UdpSocket>,
    /// The binding the socket belongs to.
    pub bind_gen: u64,
    /// The stream as the table holds it now. A session the engine
    /// creates keeps this `Arc` for its life.
    pub snapshot: Arc<Stream>,
    /// The worker's tracker, where the engine registers a session.
    pub tracker: ConnectionTracker,
}

/// What serves UDP datagrams (Story 12.5).
pub trait DatagramHandler: Send + Sync + 'static {
    /// Take one datagram. The receive loop awaits it before reading the
    /// next one on the same socket, so it must hand off rather than wait
    /// on a backend.
    fn handle(&self, datagram: Datagram) -> HandlerFuture;
}

/// The engines installed in a runtime, `None` until their story lands.
#[derive(Clone, Default)]
pub struct Engines {
    /// The TCP engine.
    pub tcp: Option<Arc<dyn StreamHandler>>,
    /// The UDP engine.
    pub udp: Option<Arc<dyn DatagramHandler>>,
}

impl std::fmt::Debug for Engines {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engines")
            .field("tcp", &self.tcp.is_some())
            .field("udp", &self.udp.is_some())
            .finish()
    }
}
