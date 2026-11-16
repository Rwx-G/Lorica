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
//!
//! The UDP loop reads into one buffer per runtime thread
//! ([`with_receive_buffer`]) and hands the engine a borrowed slice, so a
//! wide port range costs no buffer per socket and a datagram costs no
//! allocation (Story 12.5 D-h). It keeps serving while its binding
//! drains (D-m) and stops only when told to.

use std::cell::RefCell;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags, SockaddrStorage};
use socket2::{SockRef, Type};
use tokio::io::Interest;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;
use tracing::{debug, warn};

use lorica_worker::fd_passing::StreamProto;

use crate::caps::CapsRegistry;
use crate::handler::{AcceptedConnection, Datagram, Engines};
use crate::local::BoundPorts;
use crate::table::SharedTable;
use crate::tracker::ConnectionTracker;

/// Pause after an accept or receive error, so a full fd table
/// (`EMFILE`) does not spin the loop while it lasts.
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// The receive buffer's size: no UDP payload exceeds 65,507 bytes, so a
/// datagram is never truncated and the oversize check compares lengths.
pub const RECEIVE_BUFFER_SIZE: usize = 65_536;

thread_local! {
    static RECEIVE_BUFFER: RefCell<Box<[u8]>> =
        RefCell::new(vec![0u8; RECEIVE_BUFFER_SIZE].into_boxed_slice());
}

/// Run `f` on this thread's receive buffer, allocated once per thread on
/// first use. The stream runtime has one worker thread, so a worker
/// holds one buffer whatever its sockets and sessions: the receive loops
/// borrow it between two awaits, and so may an engine's session task for
/// a response. Never across an await.
///
/// # Panics
///
/// When called from inside another call on the same thread, which
/// includes a [`crate::DatagramHandler::handle`]: the handler already
/// holds the buffer through its payload.
pub fn with_receive_buffer<R>(f: impl FnOnce(&mut [u8]) -> R) -> R {
    RECEIVE_BUFFER.with(|buffer| f(&mut buffer.borrow_mut()))
}

/// What a binding's loops do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoopMode {
    /// Accept connections, admit new sessions.
    Serving,
    /// UDP only: keep the socket and serve existing sessions, open none
    /// (Story 12.5 D-m). A TCP loop stops.
    Draining,
    /// Close the socket.
    Stopped,
}

/// What every loop of one binding shares.
#[derive(Debug, Clone)]
pub(crate) struct LoopContext {
    pub(crate) stream_id: String,
    pub(crate) bind_gen: u64,
    pub(crate) table: SharedTable,
    pub(crate) tracker: ConnectionTracker,
    pub(crate) engines: Engines,
    pub(crate) bound_ports: BoundPorts,
    pub(crate) caps: CapsRegistry,
}

/// A socket adopted from an `attach`, ready for its loop.
#[derive(Debug)]
pub(crate) enum AdoptedSocket {
    Tcp(TcpListener),
    Udp(Arc<UdpSocket>),
}

impl AdoptedSocket {
    /// The port the socket listens on.
    pub(crate) fn port(&self) -> io::Result<u16> {
        match self {
            AdoptedSocket::Tcp(listener) => listener.local_addr().map(|a| a.port()),
            AdoptedSocket::Udp(socket) => socket.local_addr().map(|a| a.port()),
        }
    }
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

/// Serve `socket` until `mode` stops it or its sender goes away. The
/// socket is closed when this returns.
pub(crate) async fn run(socket: AdoptedSocket, ctx: LoopContext, mode: watch::Receiver<LoopMode>) {
    match socket {
        AdoptedSocket::Tcp(listener) => accept_loop(listener, ctx, mode).await,
        AdoptedSocket::Udp(socket) => receive_loop(socket, ctx, mode).await,
    }
}

/// Resolve once `mode` satisfies `until`, or once its sender is gone,
/// which is a stop too.
async fn reached(mode: &mut watch::Receiver<LoopMode>, until: impl FnMut(&LoopMode) -> bool) {
    let _ = mode.wait_for(until).await;
}

async fn accept_loop(listener: TcpListener, ctx: LoopContext, mut mode: watch::Receiver<LoopMode>) {
    loop {
        let accepted = tokio::select! {
            biased;
            _ = reached(&mut mode, |m| *m != LoopMode::Serving) => return,
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
        let table = ctx.table.current();
        let Some(snapshot) = table.stream(&ctx.stream_id) else {
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
            table,
            bound_ports: ctx.bound_ports.clone(),
            caps: ctx.caps.clone(),
        }));
    }
}

async fn receive_loop(
    socket: Arc<UdpSocket>,
    ctx: LoopContext,
    mut mode: watch::Receiver<LoopMode>,
) {
    let bound = match socket.local_addr() {
        Ok(addr) => addr,
        Err(e) => {
            warn!(stream_id = %ctx.stream_id, bind_gen = ctx.bind_gen, error = %e,
                  "stream UDP socket has no local address; not served");
            return;
        }
    };
    // Only a wildcard socket asked for the destination (Lot A sets
    // `IP_PKTINFO` / `IPV6_RECVPKTINFO` on unspecified addresses only).
    let wildcard = bound.ip().is_unspecified();
    loop {
        let ready = tokio::select! {
            biased;
            _ = reached(&mut mode, |m| *m == LoopMode::Stopped) => return,
            ready = socket.readable() => ready,
        };
        if let Err(e) = ready {
            warn!(stream_id = %ctx.stream_id, bind_gen = ctx.bind_gen, error = %e,
                  "stream UDP socket readiness failed");
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
            continue;
        }
        let draining = *mode.borrow() == LoopMode::Draining;
        let received = with_receive_buffer(|buf| {
            let (len, source, local) = receive(&socket, wildcard, bound, buf)?;
            deliver(&ctx, &socket, &buf[..len], source, local, draining);
            Ok::<(), io::Error>(())
        });
        let Err(e) = received else {
            continue;
        };
        if e.kind() == io::ErrorKind::WouldBlock {
            // A spurious readiness, cleared by the failed read.
            continue;
        }
        debug!(stream_id = %ctx.stream_id, bind_gen = ctx.bind_gen, error = %e,
               "stream datagram receive failed");
        // ICMP errors surface here on Linux (`ECONNREFUSED`) and concern
        // one peer, not the socket; anything else pauses so a broken
        // socket does not spin the loop.
        if !matches!(
            e.kind(),
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
        ) {
            tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
        }
    }
}

/// Read one datagram into `buf` without waiting: its length, its source,
/// and the local address it reached (`bound` itself unless the socket is
/// a wildcard one, which reads the destination from the packet info).
fn receive(
    socket: &UdpSocket,
    wildcard: bool,
    bound: SocketAddr,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    if !wildcard {
        let (len, source) = socket.try_recv_from(buf)?;
        return Ok((len, source, bound));
    }
    socket.try_io(Interest::READABLE, || {
        recv_with_destination(socket, bound, buf)
    })
}

fn recv_with_destination(
    socket: &UdpSocket,
    bound: SocketAddr,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsg = nix::cmsg_space!(nix::libc::in6_pktinfo, nix::libc::in_pktinfo);
    let msg = recvmsg::<SockaddrStorage>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::empty(),
    )?;
    let source = msg
        .address
        .as_ref()
        .and_then(socket_addr_of)
        .ok_or_else(|| io::Error::other("datagram without an IP source address"))?;
    let mut destination = None;
    for c in msg.cmsgs()? {
        match c {
            ControlMessageOwned::Ipv4PacketInfo(info) => {
                destination = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    info.ipi_addr.s_addr,
                ))));
            }
            ControlMessageOwned::Ipv6PacketInfo(info) => {
                destination = Some(IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)));
            }
            _ => {}
        }
    }
    // Without the packet info the reply leaves from the routing table's
    // choice, which is what the socket would do anyway.
    let local = SocketAddr::new(destination.unwrap_or(bound.ip()), bound.port());
    Ok((msg.bytes, source, local))
}

fn socket_addr_of(addr: &SockaddrStorage) -> Option<SocketAddr> {
    if let Some(v4) = addr.as_sockaddr_in() {
        return Some(SocketAddr::V4((*v4).into()));
    }
    addr.as_sockaddr_in6()
        .map(|v6| SocketAddr::V6((*v6).into()))
}

/// Hand one received datagram to the UDP engine, or drop it at debug
/// when there is none or its stream left the table.
fn deliver(
    ctx: &LoopContext,
    socket: &Arc<UdpSocket>,
    payload: &[u8],
    source: SocketAddr,
    local: SocketAddr,
    draining: bool,
) {
    let Some(handler) = ctx.engines.udp.as_ref() else {
        debug!(stream_id = %ctx.stream_id, %source,
               "no UDP stream engine installed: datagram dropped");
        return;
    };
    let table = ctx.table.current();
    let Some(snapshot) = table.stream(&ctx.stream_id) else {
        debug!(stream_id = %ctx.stream_id, %source,
               "stream not in the table: datagram dropped");
        return;
    };
    handler.handle(Datagram {
        payload,
        source,
        local,
        socket,
        bind_gen: ctx.bind_gen,
        snapshot: &snapshot,
        table: &table,
        tracker: &ctx.tracker,
        bound_ports: &ctx.bound_ports,
        caps: &ctx.caps,
        draining,
    });
}
