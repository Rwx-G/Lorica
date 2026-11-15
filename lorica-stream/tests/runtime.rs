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

//! The stream runtime against real sockets (Linux): attach, accept,
//! detach and drain, refresh, quiesce, the interim no-engine behaviour,
//! both transports, a UDP `SO_REUSEPORT` group split across two
//! runtimes, and the UDP receive path of Story 12.5: one receive buffer
//! per runtime thread, the destination of a wildcard socket, caps
//! adoption, and drain mode with the sockets kept open.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{Stream, StreamBackend, StreamEndReason, StreamProtocol};
use lorica_stream::handler::HandlerFuture;
use lorica_stream::{
    AcceptedConnection, ControlTransport, Datagram, DatagramHandler, Engines, InProcessPeer,
    NodeCapsRegions, StreamHandler, StreamRuntime, StreamRuntimeHandle, StreamTable,
    StreamTableSource,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{
    create_seqpacket_pair, recv_msg, send_msg, NackReason, QuiesceReason, StreamCtlMsg,
    StreamSocket,
};
use lorica_worker::stream_sockets::{bind_tcp_stream_listener, bind_udp_group};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

fn stream(id: &str, protocol: StreamProtocol) -> Stream {
    Stream::new(
        id.into(),
        id.into(),
        protocol,
        "127.0.0.1".parse().unwrap(),
        1,
        1,
        Utc::now(),
    )
}

/// A table source the test rewrites between messages.
#[derive(Default)]
struct Source(Mutex<StreamTable>);

impl Source {
    fn with(streams: Vec<Stream>, links: &[StreamBackend]) -> Arc<Self> {
        let source = Arc::new(Source::default());
        source.set(streams, links);
        source
    }

    fn set(&self, streams: Vec<Stream>, links: &[StreamBackend]) {
        *self.0.lock().unwrap() = StreamTable::new(streams, links);
    }
}

impl StreamTableSource for Source {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Echoes until the client closes or the tracker closes the connection,
/// then records how the connection ended.
#[derive(Default)]
struct Echo {
    backend: Option<String>,
    ends: Arc<Mutex<Vec<StreamEndReason>>>,
}

impl StreamHandler for Echo {
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture {
        let ends = Arc::clone(&self.ends);
        let backend = self.backend.clone();
        Box::pin(async move {
            let AcceptedConnection {
                stream: mut client,
                mut tracked,
                ..
            } = conn;
            if let Some(b) = &backend {
                tracked.set_backend(b);
            }
            let mut buf = [0u8; 1024];
            let natural = loop {
                tokio::select! {
                    reason = tracked.closed() => break reason,
                    read = client.read(&mut buf) => match read {
                        Ok(0) | Err(_) => break StreamEndReason::ClientClose,
                        Ok(n) => {
                            if client.write_all(&buf[..n]).await.is_err() {
                                break StreamEndReason::ClientClose;
                            }
                        }
                    },
                }
            };
            let reason = tracked.finish(natural);
            ends.lock().unwrap().push(reason);
        })
    }
}

fn tcp_engines(echo: Echo) -> Engines {
    Engines {
        tcp: Some(Arc::new(echo)),
        ..Engines::default()
    }
}

fn local_addr(fd: &OwnedFd) -> SocketAddr {
    SockRef::from(fd).local_addr().unwrap().as_socket().unwrap()
}

fn tcp_socket(fd: &OwnedFd) -> StreamSocket {
    StreamSocket {
        proto: StreamProto::Tcp,
        addr: local_addr(fd),
        fd: fd.try_clone().unwrap(),
    }
}

async fn answer(peer: &mut InProcessPeer) -> StreamCtlMsg {
    tokio::time::timeout(ANSWER_TIMEOUT, peer.from_runtime.recv())
        .await
        .expect("the runtime answers")
        .expect("the runtime is alive")
}

async fn echo_once(client: &mut tokio::net::TcpStream, payload: &[u8]) {
    client.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(ANSWER_TIMEOUT, client.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(got, payload);
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + ANSWER_TIMEOUT;
    while !cond() {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detach_stops_new_accepts_while_an_established_echo_drains() {
    let echo = Echo::default();
    let ends = Arc::clone(&echo.ends);
    let (mut peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(
        transport,
        tcp_engines(echo),
        Source::with(vec![stream("s1", StreamProtocol::Tcp)], &[]),
    )
    .unwrap();

    let supervisor_copy = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = local_addr(&supervisor_copy);
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq: 1,
            stream_id: "s1".into(),
            bind_gen: 7,
            sockets: vec![tcp_socket(&supervisor_copy)],
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 1, count: 1 }
    ));

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    echo_once(&mut client, b"hello").await;
    assert_eq!(handle.tracker().len(), 1);

    // Release, as the supervisor does: its own copy first, then detach.
    drop(supervisor_copy);
    peer.to_runtime
        .send(StreamCtlMsg::Detach {
            seq: 2,
            stream_id: "s1".into(),
            bind_gen: 7,
            drain_ms: 600,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 2, count: 1 }
    ));

    // The port is closed in every holder once the ack is read.
    let refused = tokio::net::TcpStream::connect(addr).await;
    assert!(refused.is_err(), "a detached port still accepts");

    // The established connection keeps working until its deadline...
    echo_once(&mut client, b"again").await;
    assert!(ends.lock().unwrap().is_empty());

    // ...then the tracker closes it with config_removed.
    let mut buf = [0u8; 8];
    let eof = tokio::time::timeout(ANSWER_TIMEOUT, client.read(&mut buf))
        .await
        .expect("closed at the deadline");
    assert!(matches!(eof, Ok(0) | Err(_)));
    wait_until("the end reason", || !ends.lock().unwrap().is_empty()).await;
    assert_eq!(*ends.lock().unwrap(), vec![StreamEndReason::ConfigRemoved]);
    assert!(handle.tracker().is_empty());

    // A second detach of the same binding is refused.
    peer.to_runtime
        .send(StreamCtlMsg::Detach {
            seq: 3,
            stream_id: "s1".into(),
            bind_gen: 7,
            drain_ms: 0,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Nack {
            seq: 3,
            reason: NackReason::UnknownBinding
        }
    ));
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_an_engine_an_accepted_connection_is_closed_at_once() {
    let (mut peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(
        transport,
        Engines::default(),
        Source::with(vec![stream("s1", StreamProtocol::Tcp)], &[]),
    )
    .unwrap();
    let listener = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = local_addr(&listener);
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq: 1,
            stream_id: "s1".into(),
            bind_gen: 1,
            sockets: vec![tcp_socket(&listener)],
        })
        .await
        .unwrap();
    assert!(matches!(answer(&mut peer).await, StreamCtlMsg::Ack { .. }));

    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(ANSWER_TIMEOUT, client.read(&mut buf))
        .await
        .expect("closed at once");
    assert!(matches!(read, Ok(0) | Err(_)));
    assert!(handle.tracker().is_empty());
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refresh_drains_what_the_new_table_no_longer_holds() {
    let echo = Echo {
        backend: Some("b1".into()),
        ..Echo::default()
    };
    let ends = Arc::clone(&echo.ends);
    // The table is empty at start: the attach must load the new stream.
    let source = Source::with(Vec::new(), &[]);
    let (mut peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(
        transport,
        tcp_engines(echo),
        Arc::clone(&source) as Arc<dyn StreamTableSource>,
    )
    .unwrap();
    let link = StreamBackend {
        stream_id: "s1".into(),
        backend_id: "b1".into(),
        backup: false,
        rule: None,
    };
    source.set(
        vec![stream("s1", StreamProtocol::Tcp)],
        std::slice::from_ref(&link),
    );

    let listener = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = local_addr(&listener);
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq: 1,
            stream_id: "s1".into(),
            bind_gen: 1,
            sockets: vec![tcp_socket(&listener)],
        })
        .await
        .unwrap();
    assert!(matches!(answer(&mut peer).await, StreamCtlMsg::Ack { .. }));
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    echo_once(&mut client, b"hi").await;

    // An edit outside the backends drains nothing.
    let mut renamed = stream("s1", StreamProtocol::Tcp);
    renamed.name = "renamed".into();
    source.set(vec![renamed.clone()], std::slice::from_ref(&link));
    peer.to_runtime
        .send(StreamCtlMsg::Refresh {
            seq: 2,
            drain_ms: 0,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 2, count: 0 }
    ));
    echo_once(&mut client, b"still").await;

    // Unlinking the connection's backend drains it.
    source.set(vec![renamed], &[]);
    peer.to_runtime
        .send(StreamCtlMsg::Refresh {
            seq: 3,
            drain_ms: 0,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 3, count: 1 }
    ));
    wait_until("the end reason", || !ends.lock().unwrap().is_empty()).await;
    assert_eq!(*ends.lock().unwrap(), vec![StreamEndReason::ConfigRemoved]);
    handle.stop();
}

/// The supervisor's side of a real stream control channel, blocking.
struct Supervisor(OwnedFd);

impl Supervisor {
    fn exchange(&self, msg: StreamCtlMsg) -> StreamCtlMsg {
        send_msg(&self.0, &msg).unwrap();
        recv_msg(&self.0).expect("an answer before the read timeout")
    }
}

#[test]
fn the_seqpacket_channel_attaches_refuses_and_quiesces() {
    let (sup_end, worker_end) = create_seqpacket_pair().unwrap();
    SockRef::from(&sup_end)
        .set_read_timeout(Some(ANSWER_TIMEOUT))
        .unwrap();
    let supervisor = Supervisor(sup_end);
    let echo = Echo::default();
    let ends = Arc::clone(&echo.ends);
    let handle = StreamRuntime::spawn(
        ControlTransport::Seqpacket(worker_end),
        tcp_engines(echo),
        Source::with(vec![stream("s1", StreamProtocol::Tcp)], &[]),
    )
    .unwrap();

    let listener = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = local_addr(&listener);
    assert!(matches!(
        supervisor.exchange(StreamCtlMsg::Attach {
            seq: 1,
            stream_id: "s1".into(),
            bind_gen: 3,
            sockets: vec![tcp_socket(&listener)],
        }),
        StreamCtlMsg::Ack { seq: 1, count: 1 }
    ));

    // A UDP socket under a TCP token is not adopted.
    let udp = bind_udp_group("127.0.0.1:0".parse().unwrap(), 1)
        .unwrap()
        .remove(0);
    assert!(matches!(
        supervisor.exchange(StreamCtlMsg::Attach {
            seq: 2,
            stream_id: "s1".into(),
            bind_gen: 4,
            sockets: vec![StreamSocket {
                proto: StreamProto::Tcp,
                addr: local_addr(&udp),
                fd: udp,
            }],
        }),
        StreamCtlMsg::Nack {
            seq: 2,
            reason: NackReason::AdoptFailed
        }
    ));
    assert!(matches!(
        supervisor.exchange(StreamCtlMsg::Detach {
            seq: 3,
            stream_id: "nope".into(),
            bind_gen: 3,
            drain_ms: 0,
        }),
        StreamCtlMsg::Nack {
            seq: 3,
            reason: NackReason::UnknownBinding
        }
    ));

    let mut client = std::net::TcpStream::connect(addr).unwrap();
    client.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
    client.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    client.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");

    let quiesced = handle.quiesced();
    assert!(matches!(
        supervisor.exchange(StreamCtlMsg::Quiesce {
            seq: 4,
            reason: QuiesceReason::Shutdown,
            drain_ms: 0,
        }),
        StreamCtlMsg::Ack { seq: 4, count: 1 }
    ));
    assert_eq!(*quiesced.borrow(), Some(Duration::ZERO));
    let mut rest = [0u8; 4];
    assert!(matches!(client.read(&mut rest), Ok(0) | Err(_)));
    let deadline = std::time::Instant::now() + ANSWER_TIMEOUT;
    while ends.lock().unwrap().is_empty() {
        assert!(std::time::Instant::now() < deadline, "no end reason");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*ends.lock().unwrap(), vec![StreamEndReason::NodeShutdown]);

    // Quiesced: no new binding.
    let late = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    assert!(matches!(
        supervisor.exchange(StreamCtlMsg::Attach {
            seq: 5,
            stream_id: "s1".into(),
            bind_gen: 5,
            sockets: vec![tcp_socket(&late)],
        }),
        StreamCtlMsg::Nack {
            seq: 5,
            reason: NackReason::ShuttingDown
        }
    ));
    handle.stop();
}

#[test]
fn terminate_quiesces_without_a_message() {
    let (_sup_end, worker_end) = create_seqpacket_pair().unwrap();
    let handle = StreamRuntime::spawn(
        ControlTransport::Seqpacket(worker_end),
        Engines::default(),
        Source::with(Vec::new(), &[]),
    )
    .unwrap();
    let mut quiesced = handle.quiesced();
    handle.terminate(Duration::from_secs(7));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let drain = rt.block_on(async {
        tokio::time::timeout(ANSWER_TIMEOUT, quiesced.wait_for(Option::is_some))
            .await
            .expect("quiesced in time")
            .map(|d| *d)
            .unwrap()
    });
    assert_eq!(drain, Some(Duration::from_secs(7)));
    handle.stop();
}

/// Records which runtime received each source's datagrams.
struct Recorder {
    runtime: usize,
    seen: Arc<Mutex<Vec<(usize, SocketAddr)>>>,
}

impl DatagramHandler for Recorder {
    fn handle(&self, datagram: Datagram<'_>) {
        self.seen
            .lock()
            .unwrap()
            .push((self.runtime, datagram.source));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_runtimes_sharing_a_udp_group_each_receive_only_their_slot() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr: SocketAddr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
    let group = bind_udp_group(addr, 2).unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut peers = Vec::new();
    let mut handles = Vec::new();
    for (slot, fd) in group.iter().enumerate() {
        let (mut peer, transport) = ControlTransport::in_process_pair(8);
        let handle = StreamRuntime::spawn(
            transport,
            Engines {
                udp: Some(Arc::new(Recorder {
                    runtime: slot,
                    seen: Arc::clone(&seen),
                })),
                ..Engines::default()
            },
            Source::with(vec![stream("dns", StreamProtocol::Udp)], &[]),
        )
        .unwrap();
        peer.to_runtime
            .send(StreamCtlMsg::Attach {
                seq: 1,
                stream_id: "dns".into(),
                bind_gen: 1,
                sockets: vec![StreamSocket {
                    proto: StreamProto::Udp,
                    addr,
                    fd: fd.try_clone().unwrap(),
                }],
            })
            .await
            .unwrap();
        assert!(matches!(
            answer(&mut peer).await,
            StreamCtlMsg::Ack { seq: 1, count: 1 }
        ));
        peers.push(peer);
        handles.push(handle);
    }

    const CLIENTS: usize = 32;
    const PER_CLIENT: usize = 3;
    let clients: Vec<std::net::UdpSocket> = (0..CLIENTS)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect();
    for client in &clients {
        for _ in 0..PER_CLIENT {
            client.send_to(b"q", addr).unwrap();
        }
    }
    wait_until("every datagram", || {
        seen.lock().unwrap().len() == CLIENTS * PER_CLIENT
    })
    .await;

    let mut runtimes_of: BTreeMap<SocketAddr, BTreeSet<usize>> = BTreeMap::new();
    for (runtime, source) in seen.lock().unwrap().iter() {
        runtimes_of.entry(*source).or_default().insert(*runtime);
    }
    assert_eq!(runtimes_of.len(), CLIENTS);
    for (source, runtimes) in &runtimes_of {
        assert_eq!(runtimes.len(), 1, "{source} reached both slots");
    }
    let used: BTreeSet<usize> = runtimes_of.values().flatten().copied().collect();
    // 32 clients all hashed to one of two slots has odds of 2^-31.
    assert_eq!(used.len(), 2, "one slot received nothing");
    for handle in handles {
        handle.stop();
    }
}

/// A source whose store cannot be read.
struct Unreadable;

impl StreamTableSource for Unreadable {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Err("store unreadable".into())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_that_cannot_load_the_table_is_refused() {
    let (mut peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(transport, Engines::default(), Arc::new(Unreadable)).unwrap();
    peer.to_runtime
        .send(StreamCtlMsg::Refresh {
            seq: 4,
            drain_ms: 0,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Nack {
            seq: 4,
            reason: NackReason::TableUnavailable
        }
    ));
    handle.stop();
}

/// What the UDP test engine saw of one datagram.
#[derive(Debug, Clone)]
struct Seen {
    /// Where the payload lies: the receive buffer's address.
    buffer: usize,
    source: SocketAddr,
    local: SocketAddr,
    draining: bool,
    /// The worker slot of the stream's caps region, if it has one.
    caps_slot: Option<u32>,
}

/// A minimal session engine: one session per source, registered in the
/// tracker, answering each datagram with its payload from the slot
/// socket; `bye` ends the session. While its binding drains, a datagram
/// from a source without a session is dropped and counted, as the
/// engine counts `binding_draining`.
#[derive(Default)]
struct SessionEcho {
    sessions: Mutex<HashMap<SocketAddr, oneshot::Sender<()>>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    dropped_draining: Arc<AtomicUsize>,
    ends: Arc<Mutex<Vec<StreamEndReason>>>,
}

impl DatagramHandler for SessionEcho {
    fn handle(&self, d: Datagram<'_>) {
        self.seen.lock().unwrap().push(Seen {
            buffer: d.payload.as_ptr() as usize,
            source: d.source,
            local: d.local,
            draining: d.draining,
            caps_slot: d.caps.get(&d.snapshot.id).map(|c| c.current().slot()),
        });
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, end| !end.is_closed());
        if d.payload == b"bye" {
            if let Some(end) = sessions.remove(&d.source) {
                let _ = end.send(());
            }
            return;
        }
        if !sessions.contains_key(&d.source) {
            if d.draining {
                self.dropped_draining.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let (end_tx, end_rx) = oneshot::channel();
            let mut tracked = d.tracker.register(d.bind_gen, Arc::clone(d.snapshot));
            let ends = Arc::clone(&self.ends);
            tokio::spawn(async move {
                let natural = tokio::select! {
                    reason = tracked.closed() => reason,
                    _ = end_rx => StreamEndReason::ClientClose,
                };
                ends.lock().unwrap().push(tracked.finish(natural));
            });
            sessions.insert(d.source, end_tx);
        }
        let _ = d.socket.try_send_to(d.payload, d.source);
    }
}

/// The parts of a [`SessionEcho`] a test reads once the runtime owns it.
struct EchoProbe {
    seen: Arc<Mutex<Vec<Seen>>>,
    dropped_draining: Arc<AtomicUsize>,
    ends: Arc<Mutex<Vec<StreamEndReason>>>,
}

/// A runtime serving UDP stream `dns` with a [`SessionEcho`].
fn udp_runtime() -> (InProcessPeer, StreamRuntimeHandle, EchoProbe) {
    let engine = SessionEcho::default();
    let probe = EchoProbe {
        seen: Arc::clone(&engine.seen),
        dropped_draining: Arc::clone(&engine.dropped_draining),
        ends: Arc::clone(&engine.ends),
    };
    let (peer, transport) = ControlTransport::in_process_pair(8);
    let handle = StreamRuntime::spawn(
        transport,
        Engines {
            udp: Some(Arc::new(engine)),
            ..Engines::default()
        },
        Source::with(vec![stream("dns", StreamProtocol::Udp)], &[]),
    )
    .unwrap();
    (peer, handle, probe)
}

/// A one-slot UDP group on `ip`, port chosen by the kernel.
fn udp_slot(ip: &str) -> (SocketAddr, OwnedFd) {
    let fd = bind_udp_group(SocketAddr::new(ip.parse().unwrap(), 0), 1)
        .unwrap()
        .remove(0);
    (local_addr(&fd), fd)
}

async fn attach_udp(peer: &mut InProcessPeer, seq: u64, bind_gen: u64, fds: Vec<OwnedFd>) -> u32 {
    let sockets = fds
        .into_iter()
        .map(|fd| StreamSocket {
            proto: StreamProto::Udp,
            addr: local_addr(&fd),
            fd,
        })
        .collect();
    peer.to_runtime
        .send(StreamCtlMsg::Attach {
            seq,
            stream_id: "dns".into(),
            bind_gen,
            sockets,
        })
        .await
        .unwrap();
    match answer(peer).await {
        StreamCtlMsg::Ack { count, .. } => count,
        other => panic!("attach refused: {other:?}"),
    }
}

async fn udp_client() -> tokio::net::UdpSocket {
    tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

/// Send `payload` to `to` and read the echo.
async fn echoed(client: &tokio::net::UdpSocket, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    client.send_to(payload, to).await.unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(ANSWER_TIMEOUT, client.recv_from(&mut buf))
        .await
        .expect("an echo in time")
        .unwrap();
    buf[..n].to_vec()
}

/// Whether nothing holds UDP `addr` any more: a socket without
/// `SO_REUSEPORT` binds only once every member of the group is closed.
fn udp_port_free(addr: SocketAddr) -> bool {
    std::net::UdpSocket::bind(addr).is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_receive_buffer_serves_a_64_port_range() {
    let (mut peer, handle, probe) = udp_runtime();
    let slots: Vec<(SocketAddr, OwnedFd)> = (0..64).map(|_| udp_slot("127.0.0.1")).collect();
    let addrs: Vec<SocketAddr> = slots.iter().map(|(a, _)| *a).collect();
    let fds = slots.into_iter().map(|(_, fd)| fd).collect();
    assert_eq!(attach_udp(&mut peer, 1, 1, fds).await, 64);

    let client = udp_client().await;
    for addr in &addrs {
        assert_eq!(echoed(&client, *addr, b"q").await, b"q");
    }
    let seen = probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 64);
    let buffers: BTreeSet<usize> = seen.iter().map(|s| s.buffer).collect();
    assert_eq!(
        buffers.len(),
        1,
        "every socket of the range reads into the one buffer of the runtime thread"
    );
    let locals: BTreeSet<SocketAddr> = seen.iter().map(|s| s.local).collect();
    assert_eq!(locals, addrs.iter().copied().collect());
    assert!(seen.iter().all(|s| !s.draining && s.caps_slot.is_none()));
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_socket_reports_the_address_the_client_targeted() {
    let (mut peer, handle, probe) = udp_runtime();
    let (bound, fd) = udp_slot("0.0.0.0");
    assert_eq!(attach_udp(&mut peer, 1, 1, vec![fd]).await, 1);

    let client = udp_client().await;
    for target in ["127.0.0.2", "127.0.0.1"] {
        let to = SocketAddr::new(target.parse().unwrap(), bound.port());
        client.send_to(b"q", to).await.unwrap();
        wait_until("the datagram", || {
            probe.seen.lock().unwrap().iter().any(|s| s.local == to)
        })
        .await;
    }
    let seen = probe.seen.lock().unwrap().clone();
    assert!(seen
        .iter()
        .all(|s| s.source == client.local_addr().unwrap()));
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caps_region_is_adopted_and_a_bad_one_is_refused() {
    let (mut peer, handle, probe) = udp_runtime();
    let mut node = NodeCapsRegions::new(2);
    assert_eq!(node.ensure("dns", 64).unwrap(), Some(1));

    let caps = node.caps_message("dns", 1, 1).unwrap().expect("a region");
    peer.to_runtime.send(caps).await.unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 1, count: 1 }
    ));

    // Not a region at all: a socket has no stream-caps header.
    let (_, not_a_region) = udp_slot("127.0.0.1");
    let Some(StreamCtlMsg::Caps { stream_id, .. }) = node.caps_message("dns", 2, 1).unwrap() else {
        panic!("a caps message");
    };
    let refused = [
        StreamCtlMsg::Caps {
            seq: 2,
            stream_id,
            caps_gen: 1,
            slot: 1,
            region: not_a_region,
        },
        // Another generation than the region's.
        match node.caps_message("dns", 3, 1).unwrap() {
            Some(StreamCtlMsg::Caps {
                seq,
                stream_id,
                slot,
                region,
                ..
            }) => StreamCtlMsg::Caps {
                seq,
                stream_id,
                caps_gen: 9,
                slot,
                region,
            },
            other => panic!("a caps message, got {other:?}"),
        },
        // A slot the two-worker region does not have.
        node.caps_message("dns", 4, 2).unwrap().expect("a region"),
    ];
    for (msg, seq) in refused.into_iter().zip(2..) {
        peer.to_runtime.send(msg).await.unwrap();
        match answer(&mut peer).await {
            StreamCtlMsg::Nack { seq: got, reason } => {
                assert_eq!((got, reason), (seq, NackReason::AdoptFailed));
            }
            other => panic!("caps {seq} accepted: {other:?}"),
        }
    }

    // The adopted region is the one the engine reads, under slot 1.
    let (addr, fd) = udp_slot("127.0.0.1");
    assert_eq!(attach_udp(&mut peer, 5, 1, vec![fd]).await, 1);
    let client = udp_client().await;
    assert_eq!(echoed(&client, addr, b"q").await, b"q");
    assert_eq!(probe.seen.lock().unwrap()[0].caps_slot, Some(1));
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_detached_udp_binding_serves_its_sessions_and_closes_at_the_last_one() {
    let (mut peer, handle, probe) = udp_runtime();
    let (addr, fd) = udp_slot("127.0.0.1");
    assert_eq!(attach_udp(&mut peer, 1, 7, vec![fd]).await, 1);
    let known = udp_client().await;
    assert_eq!(echoed(&known, addr, b"q1").await, b"q1");
    assert_eq!(handle.tracker().len(), 1);

    peer.to_runtime
        .send(StreamCtlMsg::Detach {
            seq: 2,
            stream_id: "dns".into(),
            bind_gen: 7,
            drain_ms: 30_000,
        })
        .await
        .unwrap();
    assert!(
        matches!(
            answer(&mut peer).await,
            StreamCtlMsg::Ack { seq: 2, count: 1 }
        ),
        "the ack counts the sockets put in drain, at once"
    );

    // The existing session is still served through its slot socket...
    assert_eq!(echoed(&known, addr, b"q2").await, b"q2");
    assert!(probe.seen.lock().unwrap().last().unwrap().draining);
    // ...a new client opens nothing...
    let newcomer = udp_client().await;
    newcomer.send_to(b"new", addr).await.unwrap();
    wait_until("the newcomer's drop", || {
        probe.dropped_draining.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(handle.tracker().len(), 1);
    assert!(!udp_port_free(addr), "a draining binding keeps its socket");

    // ...and the socket closes with the last session, long before the
    // deadline.
    known.send_to(b"bye", addr).await.unwrap();
    wait_until("the socket closed", || udp_port_free(addr)).await;
    assert_eq!(
        *probe.ends.lock().unwrap(),
        vec![StreamEndReason::ClientClose]
    );
    assert!(handle.tracker().is_empty());
    handle.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_quiesced_udp_binding_drains_open_until_its_deadline() {
    let (mut peer, handle, probe) = udp_runtime();
    let (addr, fd) = udp_slot("127.0.0.1");
    assert_eq!(attach_udp(&mut peer, 1, 1, vec![fd]).await, 1);
    let client = udp_client().await;
    assert_eq!(echoed(&client, addr, b"q").await, b"q");

    peer.to_runtime
        .send(StreamCtlMsg::Quiesce {
            seq: 2,
            reason: QuiesceReason::Shutdown,
            drain_ms: 500,
        })
        .await
        .unwrap();
    assert!(matches!(
        answer(&mut peer).await,
        StreamCtlMsg::Ack { seq: 2, count: 1 }
    ));
    assert_eq!(echoed(&client, addr, b"again").await, b"again");
    assert!(!udp_port_free(addr));

    wait_until("the socket closed at the deadline", || udp_port_free(addr)).await;
    wait_until("the session ended", || {
        !probe.ends.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        *probe.ends.lock().unwrap(),
        vec![StreamEndReason::NodeShutdown]
    );
    handle.stop();
}
