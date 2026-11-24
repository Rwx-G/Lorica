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

//! The TCP engine inside the stream runtime (Linux): a health flip that
//! reaches the table through `refresh` closes the connections whose
//! accepted snapshot sets `close_on_backend_down`, and only those
//! (Story 12.3 D-i, AC #7); the counters read through the runtime
//! handle.
//!
//! The runtime's death (Story 12.2 D-b, amended 2026-11-21): a loop or
//! control thread that panics is reported through the handle, a panic
//! in one connection's task is not, nor is a stop that was asked for.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Backend, HealthStatus, Stream, StreamBackend, StreamEndReason, StreamProtocol,
};
use lorica_stream::handler::HandlerFuture;
use lorica_stream::{
    AcceptedConnection, ControlTransport, Datagram, DatagramHandler, Engines, InProcessPeer,
    NodeCapsRegions, ResolverCache, StreamCounters, StreamDeath, StreamHandler, StreamRuntime,
    StreamRuntimeHandle, StreamTable, StreamTableSource, TcpEngine, TcpEngineParts,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{QuiesceReason, StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_tcp_stream_listener;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;

const WAIT: Duration = Duration::from_secs(10);
/// How soon a death must be reported.
const DEATH_REPORTED_WITHIN: Duration = Duration::from_secs(1);

mod common;

use common::{Breaker, Dns, Gate, Selector, Source};

fn stream(id: &str, close_on_backend_down: bool) -> Stream {
    let mut s = Stream::new(
        id.into(),
        id.into(),
        StreamProtocol::Tcp,
        "127.0.0.1".parse().unwrap(),
        1,
        1,
        Utc::now(),
    );
    s.allow_local_backend = true;
    s.close_on_backend_down = close_on_backend_down;
    s
}

fn backend(id: &str, address: SocketAddr, health_status: HealthStatus) -> Backend {
    let mut backend = common::backend(id, address);
    backend.name = id.into();
    backend.health_status = health_status;
    backend.health_check_enabled = true;
    backend
}

async fn echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn table(health: HealthStatus, addresses: [SocketAddr; 2]) -> StreamTable {
    let streams = vec![stream("follows", true), stream("stays", false)];
    let links = [
        StreamBackend {
            stream_id: "follows".into(),
            backend_id: "b-follows".into(),
            backup: false,
            rule: None,
            max_active: None,
        },
        StreamBackend {
            stream_id: "stays".into(),
            backend_id: "b-stays".into(),
            backup: false,
            rule: None,
            max_active: None,
        },
    ];
    let backends = vec![
        backend("b-follows", addresses[0], health.clone()),
        backend("b-stays", addresses[1], health),
    ];
    StreamTable::with_backends(streams, &links, backends)
}

async fn answer(peer: &mut InProcessPeer) -> StreamCtlMsg {
    tokio::time::timeout(WAIT, peer.from_runtime.recv())
        .await
        .expect("the runtime answers")
        .expect("the runtime is alive")
}

/// The stream's caps region, as the supervisor sends it ahead of the
/// stream's first `attach` (Story 12.6 D-e), then the `attach`.
async fn attach(
    peer: &mut InProcessPeer,
    node: &mut NodeCapsRegions,
    seq: u64,
    stream_id: &str,
) -> (OwnedFd, SocketAddr) {
    node.ensure(stream_id, u64::from(Stream::DEFAULT_MAX_CONNECTIONS), 0)
        .unwrap();
    let caps = node
        .caps_message(stream_id, seq * 100, 0)
        .unwrap()
        .expect("a region");
    peer.to_runtime.send(caps).await.unwrap();
    assert!(matches!(
        answer(peer).await,
        StreamCtlMsg::Ack { count: 1, .. }
    ));
    let fd = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = SockRef::from(&fd)
        .local_addr()
        .unwrap()
        .as_socket()
        .unwrap();
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq,
            stream_id: stream_id.into(),
            bind_gen: 1,
            sockets: vec![StreamSocket {
                proto: StreamProto::Tcp,
                addr,
                fd: fd.try_clone().unwrap(),
            }],
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(peer).await,
        StreamCtlMsg::Ack { count: 1, .. }
    ));
    (fd, addr)
}

async fn echo_once(client: &mut TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, client.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_going_down_closes_only_the_connections_that_follow_it() {
    let addresses = [echo().await, echo().await];
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = table(HealthStatus::Healthy, addresses);

    let counters = Arc::new(StreamCounters::new());
    let (observer, mut observed) = common::observer();
    let engine = TcpEngine::new(TcpEngineParts {
        selector: Arc::new(Selector::first()),
        breaker: Arc::new(Breaker::default()),
        resolver: ResolverCache::new(Arc::new(Dns::default()), Arc::clone(&counters)),
        counters: Arc::clone(&counters),
        observer,
        reserved_ports: None,
        source_gate: Arc::new(Gate::default()),
    });
    let (mut peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(
        transport,
        Engines {
            tcp: Some(Arc::new(engine)),
            counters,
            ..Engines::default()
        },
        Arc::clone(&source) as Arc<dyn StreamTableSource>,
    )
    .unwrap();
    let mut node = NodeCapsRegions::new(1);
    let (_follows_fd, follows_addr) = attach(&mut peer, &mut node, 1, "follows").await;
    let (_stays_fd, stays_addr) = attach(&mut peer, &mut node, 2, "stays").await;

    let mut follows = TcpStream::connect(follows_addr).await.unwrap();
    let mut stays = TcpStream::connect(stays_addr).await.unwrap();
    echo_once(&mut follows, b"one").await;
    echo_once(&mut stays, b"two").await;

    *source.0.lock().unwrap() = table(HealthStatus::Down, addresses);
    peer.to_runtime
        .send(StreamCtlMsg::Refresh {
            seq: 3,
            drain_ms: 60_000,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 3, count: 0 }
    ));

    let record = common::next(&mut observed.records, "the follower's record").await;
    assert_eq!(record.stream_id, "follows");
    assert_eq!(record.end_reason, StreamEndReason::BackendDown);
    let mut buf = [0u8; 8];
    let eof = tokio::time::timeout(WAIT, follows.read(&mut buf))
        .await
        .expect("closed at once");
    assert!(matches!(eof, Ok(0) | Err(_)));

    // The established connection of the stream without the flag is not
    // cut by its backend going down (AC #7).
    echo_once(&mut stays, b"still here").await;
    assert!(observed.records.try_recv().is_err());

    let snapshot = handle.counters();
    assert_eq!(snapshot.streams["follows"].accepted, 1);
    assert_eq!(snapshot.streams["stays"].accepted, 1);
    drop(stays);
    handle.stop();
}

/// A TCP engine whose first connection's task panics, and whose second
/// `handle` call panics in the accept loop itself.
#[derive(Default)]
struct PanickingTcp(AtomicUsize);

impl StreamHandler for PanickingTcp {
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            return Box::pin(async move {
                drop(conn);
                panic!("in the connection task");
            });
        }
        panic!("in the accept loop");
    }
}

/// A UDP engine that panics on the marker datagram, inline in the
/// receive loop as the real one runs, and counts the others.
#[derive(Default)]
struct PanickingUdp(AtomicUsize);

const MARKER: &[u8] = b"panic";

impl DatagramHandler for PanickingUdp {
    fn handle(&self, datagram: Datagram<'_>) {
        if datagram.payload == MARKER {
            panic!("on the marker datagram");
        }
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// A table source whose second load, the `refresh`'s, panics on the
/// control thread.
#[derive(Default)]
struct PanicsOnRefresh(AtomicUsize);

impl StreamTableSource for PanicsOnRefresh {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        if self.0.fetch_add(1, Ordering::SeqCst) > 0 {
            panic!("the table source broke");
        }
        Ok(StreamTable::default())
    }
}

fn table_of(id: &str, protocol: StreamProtocol) -> StreamTable {
    let s = Stream::new(
        id.into(),
        id.into(),
        protocol,
        "127.0.0.1".parse().unwrap(),
        1,
        1,
        Utc::now(),
    );
    StreamTable::with_backends(vec![s], &[], Vec::new())
}

fn spawn_runtime(
    engines: Engines,
    source: Arc<dyn StreamTableSource>,
) -> (InProcessPeer, StreamRuntimeHandle) {
    let (peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(transport, engines, source).unwrap();
    (peer, handle)
}

/// Attach one socket of `proto` on 127.0.0.1 to `stream_id`, without a
/// caps region: these engines read none.
async fn attach_one(
    peer: &mut InProcessPeer,
    seq: u64,
    stream_id: &str,
    proto: StreamProto,
) -> SocketAddr {
    let fd: OwnedFd = match proto {
        StreamProto::Tcp => bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap(),
        StreamProto::Udp => std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into(),
    };
    let addr = SockRef::from(&fd)
        .local_addr()
        .unwrap()
        .as_socket()
        .unwrap();
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq,
            stream_id: stream_id.into(),
            bind_gen: 1,
            sockets: vec![StreamSocket { proto, addr, fd }],
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(peer).await,
        StreamCtlMsg::Ack { count: 1, .. }
    ));
    addr
}

async fn reported_death(died: &mut watch::Receiver<Option<StreamDeath>>) -> StreamDeath {
    tokio::time::timeout(DEATH_REPORTED_WITHIN, died.wait_for(Option::is_some))
        .await
        .expect("the death is reported in time")
        .expect("the runtime still holds its death signal")
        .clone()
        .expect("a death")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_udp_receive_loop_is_reported_dead() {
    let udp = Arc::new(PanickingUdp::default());
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = table_of("udp", StreamProtocol::Udp);
    let (mut peer, handle) = spawn_runtime(
        Engines {
            udp: Some(Arc::clone(&udp) as Arc<dyn DatagramHandler>),
            ..Engines::default()
        },
        source,
    );
    let mut died = handle.died();
    let listen = attach_one(&mut peer, 1, "udp", StreamProto::Udp).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    client.send_to(b"fine", listen).await.unwrap();
    tokio::time::timeout(WAIT, async {
        while udp.0.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the first datagram is handled");
    assert!(died.borrow().is_none());

    client.send_to(MARKER, listen).await.unwrap();
    match reported_death(&mut died).await {
        StreamDeath::Loop {
            stream_id,
            bind_gen,
            proto,
            cause,
        } => {
            assert_eq!(stream_id, "udp");
            assert_eq!(bind_gen, 1);
            assert_eq!(proto, StreamProto::Udp);
            assert!(cause.contains("on the marker datagram"), "{cause}");
        }
        other => panic!("unexpected {other:?}"),
    }
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_accept_loop_is_reported_dead_and_a_connection_task_is_not() {
    let tcp = Arc::new(PanickingTcp::default());
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = table_of("tcp", StreamProtocol::Tcp);
    let (mut peer, handle) = spawn_runtime(
        Engines {
            tcp: Some(Arc::clone(&tcp) as Arc<dyn StreamHandler>),
            ..Engines::default()
        },
        source,
    );
    let mut died = handle.died();
    let listen = attach_one(&mut peer, 1, "tcp", StreamProto::Tcp).await;

    // The first connection's own task panics: that connection ends, the
    // runtime lives on.
    let mut first = TcpStream::connect(listen).await.unwrap();
    let eof = tokio::time::timeout(WAIT, first.read(&mut [0u8; 1]))
        .await
        .expect("the connection is closed");
    assert!(matches!(eof, Ok(0) | Err(_)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(died.borrow().is_none());

    let _second = TcpStream::connect(listen).await.unwrap();
    match reported_death(&mut died).await {
        StreamDeath::Loop { proto, cause, .. } => {
            assert_eq!(proto, StreamProto::Tcp);
            assert!(cause.contains("in the accept loop"), "{cause}");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(tcp.0.load(Ordering::SeqCst), 2);
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_control_thread_is_reported_dead() {
    let (peer, handle) = spawn_runtime(Engines::default(), Arc::new(PanicsOnRefresh::default()));
    let mut died = handle.died();
    peer.to_runtime
        .send(StreamCtlMsg::Refresh {
            seq: 1,
            drain_ms: 0,
        })
        .await
        .unwrap();
    match reported_death(&mut died).await {
        StreamDeath::Control { cause } => {
            assert!(cause.contains("the table source broke"), "{cause}")
        }
        other => panic!("unexpected {other:?}"),
    }
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_that_was_asked_for_is_no_death() {
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = table_of("tcp", StreamProtocol::Tcp);
    let (mut peer, handle) = spawn_runtime(
        Engines {
            tcp: Some(Arc::new(PanickingTcp::default()) as Arc<dyn StreamHandler>),
            udp: Some(Arc::new(PanickingUdp::default()) as Arc<dyn DatagramHandler>),
            ..Engines::default()
        },
        source,
    );
    let mut died = handle.died();
    attach_one(&mut peer, 1, "tcp", StreamProto::Tcp).await;
    attach_one(&mut peer, 2, "tcp", StreamProto::Udp).await;
    peer.to_runtime
        .send(StreamCtlMsg::Quiesce {
            seq: 3,
            reason: QuiesceReason::Shutdown,
            drain_ms: 0,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 3, .. }
    ));

    tokio::task::spawn_blocking(move || handle.stop())
        .await
        .unwrap();
    let after_stop = tokio::time::timeout(WAIT, died.wait_for(Option::is_some))
        .await
        .expect("the signal closes with the runtime");
    assert!(after_stop.is_err(), "a death was reported on a stop");
}
