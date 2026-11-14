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

//! The per-socket loops: a TCP accept loop and a UDP receive loop, each
//! owning its socket and closing it when told to stop.
//!
//! A loop reads the stream's snapshot from the current table at each
//! accept or datagram, so a `refresh` reaches new connections and only
//! them.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use socket2::{SockRef, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing::{debug, warn};

use lorica_worker::fd_passing::StreamProto;

use crate::handler::{AcceptedConnection, Datagram, Engines};
use crate::table::SharedTable;
use crate::tracker::ConnectionTracker;

/// Pause after an accept or receive error, so a full fd table
/// (`EMFILE`) does not spin the loop while it lasts.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// Largest UDP payload a receive can return.
const DATAGRAM_BUF_SIZE: usize = 65_536;

/// What every loop of one binding shares.
#[derive(Debug, Clone)]
pub(crate) struct LoopContext {
    pub(crate) stream_id: String,
    pub(crate) bind_gen: u64,
    pub(crate) table: SharedTable,
    pub(crate) tracker: ConnectionTracker,
    pub(crate) engines: Engines,
}

/// A socket adopted from an `attach`, ready for its loop.
#[derive(Debug)]
pub(crate) enum AdoptedSocket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

/// Adopt a passed socket for `proto`, checking that the kernel agrees on
/// its type: a datagram socket handed in as a TCP listener would fail
/// every accept and spin. Must run inside a tokio runtime.
pub(crate) fn adopt(proto: StreamProto, fd: OwnedFd) -> io::Result<AdoptedSocket> {
    let expected = match proto {
        StreamProto::Tcp => Type::STREAM,
        StreamProto::Udp => Type::DGRAM,
    };
    let actual = SockRef::from(&fd).r#type()?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{proto} socket token on a socket of type {actual:?}"),
        ));
    }
    match proto {
        StreamProto::Tcp => {
            let std_listener = std::net::TcpListener::from(fd);
            std_listener.set_nonblocking(true)?;
            Ok(AdoptedSocket::Tcp(TcpListener::from_std(std_listener)?))
        }
        StreamProto::Udp => {
            let std_socket = std::net::UdpSocket::from(fd);
            std_socket.set_nonblocking(true)?;
            Ok(AdoptedSocket::Udp(Arc::new(UdpSocket::from_std(
                std_socket,
            )?)))
        }
    }
}

/// Serve `socket` until `stop` turns true or its sender goes away. The
/// socket is closed when this returns.
pub(crate) async fn run(socket: AdoptedSocket, ctx: LoopContext, stop: watch::Receiver<bool>) {
    match socket {
        AdoptedSocket::Tcp(listener) => accept_loop(listener, ctx, stop).await,
        AdoptedSocket::Udp(socket) => receive_loop(socket, ctx, stop).await,
    }
}

async fn stopped(stop: &mut watch::Receiver<bool>) {
    // `wait_for` errors when the sender is gone, which is a stop too.
    let _ = stop.wait_for(|s| *s).await;
}

async fn accept_loop(listener: TcpListener, ctx: LoopContext, mut stop: watch::Receiver<bool>) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = stopped(&mut stop) => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                warn!(stream_id = %ctx.stream_id, bind_gen = ctx.bind_gen, error = %e,
                      "stream accept failed");
                tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                continue;
            }
        };
        let Some(handler) = ctx.engines.tcp.clone() else {
            debug!(stream_id = %ctx.stream_id, %peer,
                   "no TCP stream engine installed: connection closed");
            continue;
        };
        let Some(snapshot) = ctx.table.current().stream(&ctx.stream_id) else {
            debug!(stream_id = %ctx.stream_id, %peer,
                   "stream not in the table: connection closed");
            continue;
        };
        let tracked = ctx.tracker.register(ctx.bind_gen, snapshot);
        tokio::spawn(handler.handle(AcceptedConnection {
            stream,
            peer,
            bind_gen: ctx.bind_gen,
            tracked,
        }));
    }
}

async fn receive_loop(socket: Arc<UdpSocket>, ctx: LoopContext, mut stop: watch::Receiver<bool>) {
    let mut buf = vec![0u8; DATAGRAM_BUF_SIZE];
    loop {
        let received = tokio::select! {
            biased;
            _ = stopped(&mut stop) => return,
            received = socket.recv_from(&mut buf) => received,
        };
        let (len, source) = match received {
            Ok(pair) => pair,
            Err(e) => {
                debug!(stream_id = %ctx.stream_id, bind_gen = ctx.bind_gen, error = %e,
                       "stream datagram receive failed");
                // ICMP errors surface here on Linux (`ECONNREFUSED`) and
                // concern one peer, not the socket; anything else pauses
                // so a broken socket does not spin the loop.
                if !matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                ) {
                    tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
                }
                continue;
            }
        };
        let Some(handler) = ctx.engines.udp.clone() else {
            debug!(stream_id = %ctx.stream_id, %source,
                   "no UDP stream engine installed: datagram dropped");
            continue;
        };
        let Some(snapshot) = ctx.table.current().stream(&ctx.stream_id) else {
            debug!(stream_id = %ctx.stream_id, %source,
                   "stream not in the table: datagram dropped");
            continue;
        };
        handler
            .handle(Datagram {
                payload: buf[..len].to_vec(),
                source,
                socket: Arc::clone(&socket),
                bind_gen: ctx.bind_gen,
                snapshot,
                tracker: ctx.tracker.clone(),
            })
            .await;
    }
}
