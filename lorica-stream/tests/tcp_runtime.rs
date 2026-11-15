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

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, Stream, StreamBackend, StreamEndReason,
    StreamProtocol,
};
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    Admission, BackendSelector, BreakerGate, ConnectionObserver, ConnectionRecord,
    ControlTransport, Engines, InProcessPeer, Resolve, ResolveError, Resolved, ResolverCache,
    SelectionRequest, StreamCounters, StreamRuntime, StreamTable, StreamTableSource, TcpEngine,
    TcpEngineParts,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_tcp_stream_listener;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(10);

struct FirstCandidate;

impl BackendSelector for FirstCandidate {
    fn select(&self, _request: &SelectionRequest<'_>) -> usize {
        0
    }
    fn connected(&self, _: &str, _: &Backend, _: SocketAddr, _: Duration) {}
    fn closed(&self, _: &str, _: &Backend, _: SocketAddr) {}
}

struct Open;

impl BreakerGate for Open {
    fn admit<'a>(&'a self, _: &'a str, _: &'a Backend) -> SeamFuture<'a, Admission> {
        Box::pin(async { Admission::Allow })
    }
    fn record<'a>(&'a self, _: &'a str, _: &'a Backend, _: bool, _: bool) -> SeamFuture<'a, ()> {
        Box::pin(async {})
    }
}

struct NoDns;

impl Resolve for NoDns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        Box::pin(async move { Err(ResolveError(format!("{host}: no resolver in this test"))) })
    }
}

struct Records(mpsc::UnboundedSender<ConnectionRecord>);

impl ConnectionObserver for Records {
    fn observe(&self, record: ConnectionRecord) {
        let _ = self.0.send(record);
    }
}

#[derive(Default)]
struct Source(Mutex<StreamTable>);

impl StreamTableSource for Source {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

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
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: id.into(),
        group_name: String::new(),
        weight: 1,
        health_status,
        health_check_enabled: true,
        health_check_interval_s: 10,
        health_check_path: None,
        health_check: HealthCheck::default(),
        lifecycle_state: LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: false,
        tls_skip_verify: false,
        tls_sni: None,
        h2_upstream: false,
        managed_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
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
        },
        StreamBackend {
            stream_id: "stays".into(),
            backend_id: "b-stays".into(),
            backup: false,
            rule: None,
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

async fn attach(peer: &mut InProcessPeer, seq: u64, stream_id: &str) -> (OwnedFd, SocketAddr) {
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
    let (tx, mut records) = mpsc::unbounded_channel();
    let engine = TcpEngine::new(TcpEngineParts {
        selector: Arc::new(FirstCandidate),
        breaker: Arc::new(Open),
        resolver: ResolverCache::new(Arc::new(NoDns), Arc::clone(&counters)),
        counters: Arc::clone(&counters),
        observer: Arc::new(Records(tx)),
        reserved_ports: None,
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
    let (_follows_fd, follows_addr) = attach(&mut peer, 1, "follows").await;
    let (_stays_fd, stays_addr) = attach(&mut peer, 2, "stays").await;

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

    let record = tokio::time::timeout(WAIT, records.recv())
        .await
        .unwrap()
        .unwrap();
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
    assert!(records.try_recv().is_err());

    let snapshot = handle.counters();
    assert_eq!(snapshot.streams["follows"].accepted, 1);
    assert_eq!(snapshot.streams["stays"].accepted, 1);
    drop(stays);
    handle.stop();
}
