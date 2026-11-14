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
//! both transports, and a UDP `SO_REUSEPORT` group split across two
//! runtimes.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{Stream, StreamBackend, StreamEndReason, StreamProtocol};
use lorica_stream::handler::HandlerFuture;
use lorica_stream::{
    AcceptedConnection, ControlTransport, Datagram, DatagramHandler, Engines, InProcessPeer,
    StreamHandler, StreamRuntime, StreamTable, StreamTableSource,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{
    create_seqpacket_pair, recv_msg, send_msg, NackReason, QuiesceReason, StreamCtlMsg,
    StreamSocket,
};
use lorica_worker::stream_sockets::{bind_tcp_stream_listener, bind_udp_group};
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ANSWER_TIMEOUT: Duration = Duration::from_secs(5);

fn stream(id: &str, protocol: StreamProtocol) -> Stream {
    Stream {
        id: id.into(),
        name: id.into(),
        group_name: String::new(),
        protocol,
        enabled: true,
        listen_address: "127.0.0.1".parse().unwrap(),
        port_first: 1,
        port_last: 1,
        node_selector: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
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
        udp: None,
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
    fn handle(&self, datagram: Datagram) -> HandlerFuture {
        self.seen
            .lock()
            .unwrap()
            .push((self.runtime, datagram.source));
        Box::pin(async {})
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
                tcp: None,
                udp: Some(Arc::new(Recorder {
                    runtime: slot,
                    seen: Arc::clone(&seen),
                })),
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
