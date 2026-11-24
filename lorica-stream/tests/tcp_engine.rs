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

//! The TCP engine against real sockets (Linux), with fake seams: the
//! selector always takes the first candidate (backend id order), the
//! breaker admits unless told to deny, the resolver answers from a map
//! and hangs on any other name, the source gate refuses the addresses it
//! is given and places the ones it has a country for.
//!
//! Every stream gets its caps region on a node of one worker, as the
//! supervisor would hand it. Clients connect from distinct loopback
//! addresses (`127.0.0.N`) where a test needs several sources.
//!
//! The 64 MiB backpressure case lives beside the forwarding loop
//! (`tcp::forward` unit tests), where the direction states are readable
//! while the loop is parked.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    Backend, GeoIpConfig, GeoIpMode, HealthStatus, LifecycleState, Stream, StreamBackend,
    StreamEndKind, StreamEndReason, StreamProtocol, StreamProxyProtocol, StreamRefusal,
    StreamTlsMode,
};
use lorica_core::protocols::proxy_protocol::{
    encode_v2, encode_v2_dgram, parse, Addresses, Parsed, V2_SIGNATURE,
};
use lorica_stream::counters::{ConnectFailureKind, ProxyHeaderOutcome, StreamCountersSnapshot};
use lorica_stream::{
    AcceptedConnection, BackendSelector, BoundPorts, BreakerGate, CapsRegistry, ConnectOutcome,
    ConnectionRecord, ConnectionTracker, NodeCapsRegions, RefusalRecord, Resolve, ResolverCache,
    SourceGate, StreamCounters, StreamHandler, StreamLogKey, StreamTable, SuppressedRecord,
    TcpEngine, TcpEngineParts,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

const STREAM_ID: &str = "s";
/// How long an expected event may take before the test calls it lost. It
/// bounds a hang, never a duration: a loaded machine (a full gate run on
/// a busy host, parallel test binaries) delays every event, and no
/// assertion here may depend on how much.
const WAIT: Duration = Duration::from_secs(60);

mod common;

use common::{backend, Breaker, Dns, Gate, Outcome, Selector};

// ---- fixtures --------------------------------------------------------

/// A TCP stream on loopback, local backends allowed (every fixture
/// backend is on loopback); a test that checks the local rule turns the
/// flag off.
fn stream() -> Stream {
    let mut s = Stream::new(
        STREAM_ID.into(),
        "pg".into(),
        StreamProtocol::Tcp,
        "127.0.0.1".parse().unwrap(),
        1,
        1,
        Utc::now(),
    );
    s.allow_local_backend = true;
    s
}

struct Harness {
    engine: TcpEngine,
    tracker: ConnectionTracker,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    refusals: mpsc::UnboundedReceiver<RefusalRecord>,
    suppressed: mpsc::UnboundedReceiver<SuppressedRecord>,
    outcomes: Arc<Mutex<Vec<Outcome>>>,
    counters: Arc<StreamCounters>,
    breaker: Arc<Breaker>,
    dns: Arc<Dns>,
    selector: Arc<Selector>,
    gate: Arc<Gate>,
    bound: BoundPorts,
    table: Arc<Mutex<Arc<StreamTable>>>,
    /// The supervisor's side of the stream's region, on a node of one
    /// worker, and the worker's.
    node: Mutex<NodeCapsRegions>,
    caps: CapsRegistry,
    listen: SocketAddr,
    /// The tracker's entry count at each record and refusal the
    /// observer took.
    tracked_at_report: Arc<Mutex<Vec<usize>>>,
}

impl Harness {
    async fn new() -> Self {
        Self::with_reserved(None).await
    }

    async fn with_reserved(reserved_ports: Option<ReservedPorts>) -> Self {
        let counters = Arc::new(StreamCounters::new());
        let breaker = Arc::new(Breaker::default());
        let dns = Arc::new(Dns::default());
        let selector = Arc::new(Selector::first());
        let gate = Arc::new(Gate::default());
        let (observer, observed) = common::observer();
        let tracker = ConnectionTracker::new();
        let _ = observed.tracker.set(tracker.clone());
        let engine = TcpEngine::new(TcpEngineParts {
            selector: Arc::clone(&selector) as Arc<dyn BackendSelector>,
            breaker: Arc::clone(&breaker) as Arc<dyn BreakerGate>,
            resolver: ResolverCache::new(
                Arc::clone(&dns) as Arc<dyn Resolve>,
                Arc::clone(&counters),
            ),
            counters: Arc::clone(&counters),
            observer,
            reserved_ports,
            source_gate: Arc::clone(&gate) as Arc<dyn SourceGate>,
        });
        let bound = BoundPorts::new();
        let table: Arc<Mutex<Arc<StreamTable>>> = Arc::default();
        let caps = CapsRegistry::new();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        {
            let (engine, tracker, bound, table, caps) = (
                engine.clone(),
                tracker.clone(),
                bound.clone(),
                Arc::clone(&table),
                caps.clone(),
            );
            tokio::spawn(async move {
                loop {
                    let (stream, peer) = listener.accept().await.unwrap();
                    let table = Arc::clone(&table.lock().unwrap());
                    let snapshot = table.stream(STREAM_ID).expect("test setup: a stream");
                    let tracked = tracker.register(1, snapshot);
                    tokio::spawn(engine.handle(AcceptedConnection {
                        stream,
                        peer,
                        bind_gen: 1,
                        tracked,
                        table,
                        bound_ports: bound.clone(),
                        caps: caps.clone(),
                    }));
                }
            });
        }
        Harness {
            engine,
            tracker,
            records: observed.records,
            refusals: observed.refusals,
            suppressed: observed.suppressed,
            outcomes: observed.outcomes,
            counters,
            breaker,
            dns,
            selector,
            gate,
            bound,
            table,
            node: Mutex::new(NodeCapsRegions::new(1)),
            caps,
            listen,
            tracked_at_report: observed.tracked_at_report,
        }
    }

    /// Serve `stream` with `backends`, each `(row, backup)`.
    fn set(&self, stream: Stream, backends: Vec<(Backend, bool)>) {
        self.set_links(
            stream,
            backends
                .into_iter()
                .map(|(backend, backup)| (backend, backup, None))
                .collect(),
        );
    }

    /// Serve `stream` with `backends`, each `(row, backup, max_active)`,
    /// in its region, created or replaced as the supervisor would.
    fn set_links(&self, stream: Stream, backends: Vec<(Backend, bool, Option<u32>)>) {
        let links: Vec<StreamBackend> = backends
            .iter()
            .map(|(b, backup, max_active)| {
                let mut link = StreamBackend::primary(&stream.id, &b.id);
                link.backup = *backup;
                link.max_active = *max_active;
                link
            })
            .collect();
        self.ensure_region(&stream);
        let rows = backends.into_iter().map(|(b, _, _)| b).collect();
        let table = StreamTable::with_backends(vec![stream], &links, rows);
        self.engine.table_changed(&table);
        *self.table.lock().unwrap() = Arc::new(table);
    }

    fn ensure_region(&self, stream: &Stream) {
        common::adopt_region(&mut self.node.lock().unwrap(), &self.caps, stream);
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.listen).await.unwrap()
    }

    /// A connection from `127.0.0.<n>`, another source than the default
    /// client's `127.0.0.1`.
    async fn connect_from(&self, n: u8) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, n)), 0))
            .unwrap();
        socket.connect(self.listen).await.unwrap()
    }

    async fn record(&mut self) -> ConnectionRecord {
        common::next(&mut self.records, "a connection record").await
    }

    /// The next refusal row the refusal log admitted.
    async fn refusal(&mut self) -> RefusalRecord {
        common::next(&mut self.refusals, "a refusal row").await
    }

    /// The connect outcomes heard so far. The engine reports one before
    /// it hands the connection's record, so once a record is in, its
    /// outcome is too.
    fn outcomes(&mut self) -> Vec<ConnectOutcome> {
        let heard = std::mem::take(&mut *self.outcomes.lock().unwrap());
        heard
            .into_iter()
            .map(|(stream_id, protocol, outcome)| {
                assert_eq!(
                    (stream_id.as_str(), protocol),
                    (STREAM_ID, StreamProtocol::Tcp)
                );
                outcome
            })
            .collect()
    }

    fn refused(&self, refusal: StreamRefusal) -> u64 {
        self.stats().refused.get(&refusal).copied().unwrap_or(0)
    }

    fn stats(&self) -> StreamCountersSnapshot {
        self.counters
            .snapshot()
            .streams
            .get(STREAM_ID)
            .cloned()
            .unwrap_or_default()
    }

    fn drain_now(&self, reason: StreamEndReason) {
        let now = Instant::now();
        self.tracker.drain_all(now, reason);
        self.tracker.close_expired(now);
    }
}

// ---- backends --------------------------------------------------------

/// Echoes each connection until EOF, then closes its write side.
async fn echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                let _ = socket.shutdown().await;
            });
        }
    });
    (addr, accepted)
}

/// Collects each connection's bytes until EOF and hands them over.
async fn sink() -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = socket.read_to_end(&mut all).await;
                let _ = tx.send(all);
            });
        }
    });
    (addr, rx)
}

/// An address nothing listens on, for as long as the value lives: its
/// socket stays bound and never listens, so a connect to it is refused,
/// and no other socket, of this test binary or of another process, can
/// bind the port and answer in its place. A port bound and released at
/// once is free for the next `bind(0)` anywhere on the host: under load
/// another test's listener took it, and a connect meant to be refused
/// reached a stranger.
struct Refusing(socket2::Socket);

impl Refusing {
    fn addr(&self) -> SocketAddr {
        self.0.local_addr().unwrap().as_socket().unwrap()
    }
}

fn refusing() -> Refusing {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    Refusing(socket)
}

/// A listener whose accept queue is full: a SYN to it is dropped, so a
/// connect waits for its timeout.
fn black_hole() -> (SocketAddr, socket2::Socket, Vec<std::net::TcpStream>) {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    socket.listen(0).unwrap();
    let addr = socket.local_addr().unwrap().as_socket().unwrap();
    let mut held = Vec::new();
    while let Ok(s) = std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(300)) {
        held.push(s);
        assert!(held.len() < 64, "test setup: the accept queue never filled");
    }
    (addr, socket, held)
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

async fn read_to_end(client: &mut TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut all))
        .await
        .expect("EOF in time")
        .ok();
    all
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn ended(stats: &StreamCountersSnapshot, kind: StreamEndKind) -> u64 {
    stats.ended.get(&kind).copied().unwrap_or(0)
}

// ---- forwarding ------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn echo_through_the_engine_both_ways_with_its_record() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    h.set(stream(), vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    echo_once(&mut client, b"ping").await;
    echo_once(&mut client, b"pong!").await;
    client.shutdown().await.unwrap();
    assert!(read_to_end(&mut client).await.is_empty());

    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ClientClose);
    assert_eq!(record.stream_id, STREAM_ID);
    assert_eq!(record.stream_name, "pg");
    assert_eq!(record.protocol, StreamProtocol::Tcp);
    assert_eq!(record.detected_protocol, None);
    assert_eq!(record.tls, None);
    assert_eq!(record.bind_gen, 1);
    assert_eq!(record.client, client.local_addr().unwrap());
    assert_eq!(record.peer, record.client);
    assert_eq!(record.proxied_from, None);
    assert_eq!(record.local, h.listen);
    assert_eq!(record.backend_id.as_deref(), Some("b1"));
    assert_eq!(record.backend_address, Some(addr));
    assert_eq!(record.attempts, 1);
    assert_eq!((record.bytes_upload, record.bytes_download), (9, 9));
    assert!(record.connected_at.is_some());
    assert!(record.accepted_at <= record.ended_at);

    let stats = h.stats();
    assert_eq!(stats.accepted, 1);
    assert_eq!(ended(&stats, StreamEndKind::ClientClose), 1);
    assert_eq!((stats.bytes_upload, stats.bytes_download), (9, 9));
    assert_eq!(stats.connect_attempts, 1);
    assert_eq!(stats.retries, 0);
    let link = &h.counters.snapshot().links[&(STREAM_ID.to_string(), "b1".to_string())];
    assert_eq!(link.connects, 1);
    assert_eq!(link.connect_latency.count, 1);
    assert_eq!((link.bytes_upload, link.bytes_download), (9, 9));
    wait_until("the gauges released", || {
        let snap = h.counters.snapshot();
        snap.streams[STREAM_ID].active == 0
            && snap.links[&(STREAM_ID.to_string(), "b1".to_string())].active == 0
    })
    .await;
    assert_eq!(*h.selector.connected.lock().unwrap(), vec!["b1"]);
    assert_eq!(*h.selector.closed.lock().unwrap(), vec!["b1"]);
    assert_eq!(
        *h.breaker.records.lock().unwrap(),
        vec![("b1".to_string(), true, false)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_fin_still_lets_the_backend_answer() {
    let mut h = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        socket.read_to_end(&mut request).await.unwrap();
        socket.write_all(b"after your FIN: ").await.unwrap();
        socket.write_all(&request).await.unwrap();
    });
    h.set(stream(), vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(read_to_end(&mut client).await, b"after your FIN: request");
    assert_eq!(h.record().await.end_reason, StreamEndReason::ClientClose);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_fin_still_lets_the_client_send() {
    let mut h = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (got_tx, mut got_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.write_all(b"banner").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).await.unwrap();
        got_tx.send(rest).unwrap();
    });
    h.set(stream(), vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    assert_eq!(read_to_end(&mut client).await, b"banner");
    client.write_all(b"late words").await.unwrap();
    client.shutdown().await.unwrap();
    let got = tokio::time::timeout(WAIT, got_rx.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"late words".as_slice()));
    assert_eq!(h.record().await.end_reason, StreamEndReason::BackendClose);
}

/// An answer the backend writes in two segments, 2 ms apart, reaches the
/// client whole without waiting on Nagle: the engine's second write to
/// the client goes out before the client acknowledges the first. With
/// Nagle on the client socket, the rounds where the client delays that
/// acknowledgement (Linux holds it up to 40 ms) take about 40 ms each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_two_segment_answer_does_not_wait_on_nagle_toward_the_client() {
    const ROUNDS: u32 = 20;
    let mut h = Harness::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        socket.set_nodelay(true).unwrap();
        let mut request = [0u8; 8];
        while socket.read_exact(&mut request).await.is_ok() {
            socket.write_all(&[1u8; 64]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(2)).await;
            socket.write_all(&[2u8; 64]).await.unwrap();
        }
    });
    h.set(stream(), vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    client.set_nodelay(true).unwrap();
    let mut answer = [0u8; 128];
    let started = Instant::now();
    for _ in 0..ROUNDS {
        client.write_all(b"request!").await.unwrap();
        tokio::time::timeout(WAIT, client.read_exact(&mut answer))
            .await
            .expect("an answer in time")
            .unwrap();
    }
    let took = started.elapsed();
    assert!(
        took < Duration::from_millis(15) * ROUNDS,
        "{ROUNDS} rounds took {took:?}"
    );
    client.shutdown().await.unwrap();
    assert_eq!(h.record().await.end_reason, StreamEndReason::ClientClose);
}

// ---- timers ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_ends_with_idle_timeout() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.idle_timeout_s = 1;
    h.set(s, vec![(backend("b1", addr), false)]);

    // Nothing is sent: an echo first would have to land within the idle
    // second, which a loaded host does not promise.
    let started = Instant::now();
    let mut client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::IdleTimeout);
    assert_eq!(
        record.backend_id.as_deref(),
        Some("b1"),
        "it was forwarding"
    );
    // Never before the idle timeout. How soon after it is pinned on a
    // paused clock beside the forwarder: here it is the host's load.
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1), "{took:?}");
    assert!(read_to_end(&mut client).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_busy_connection_ends_with_total_timeout() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.total_timeout_s = Some(1);
    h.set(s, vec![(backend("b1", addr), false)]);

    let started = Instant::now();
    let mut client = h.connect().await;
    let chatter = tokio::spawn(async move {
        for _ in 0..50 {
            if client.write_all(b"tick").await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::TotalTimeout);
    // Never before the total timeout; how soon after is pinned on a
    // paused clock beside the forwarder.
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1), "{took:?}");
    chatter.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_silent_backend_ends_with_the_connect_timeout() {
    let mut h = Harness::new().await;
    let (addr, _listener, _held) = black_hole();
    let mut s = stream();
    s.connect_timeout_ms = 200;
    s.max_connect_attempts = 1;
    h.set(s, vec![(backend("b1", addr), false)]);

    let started = Instant::now();
    let _client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConnectFailed);
    assert_eq!(record.attempts, 1);
    // The kernel's own SYN retries would take minutes; the record came
    // within WAIT, so the 200 ms connect timeout ended the attempt.
    assert!(started.elapsed() < WAIT);
    let link = &h.counters.snapshot().links[&(STREAM_ID.to_string(), "b1".to_string())];
    assert_eq!(
        link.connect_failures.get(&ConnectFailureKind::Timeout),
        Some(&1)
    );
    assert_eq!(
        *h.breaker.records.lock().unwrap(),
        vec![("b1".to_string(), false, false)]
    );
}

// ---- selection, retry, backups, breaker -------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_attempt_retries_and_the_early_bytes_arrive_once() {
    let mut h = Harness::new().await;
    let (good, mut received) = sink().await;
    let dead = refusing();
    h.set(
        stream(),
        vec![
            (backend("b1", dead.addr()), false),
            (backend("b2", good), false),
        ],
    );

    let mut client = h.connect().await;
    client.write_all(b"sent before any connect").await.unwrap();
    client.shutdown().await.unwrap();
    let got = tokio::time::timeout(WAIT, received.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"sent before any connect".as_slice()));

    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b2"));
    assert_eq!(record.attempts, 2);
    let stats = h.stats();
    assert_eq!((stats.connect_attempts, stats.retries), (2, 1));
    let link = &h.counters.snapshot().links[&(STREAM_ID.to_string(), "b1".to_string())];
    assert_eq!(
        link.connect_failures.get(&ConnectFailureKind::Refused),
        Some(&1)
    );
    assert_eq!(
        *h.breaker.records.lock().unwrap(),
        vec![
            ("b1".to_string(), false, false),
            ("b2".to_string(), true, false)
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_refusal_is_connect_failed_and_no_candidate_is_no_healthy_backend() {
    let mut h = Harness::new().await;
    let (dead, dead_too) = (refusing(), refusing());
    h.set(
        stream(),
        vec![
            (backend("b1", dead.addr()), false),
            (backend("b2", dead_too.addr()), false),
        ],
    );
    let _client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConnectFailed);
    assert_eq!(record.attempts, 2);
    assert_eq!(record.backend_id, None);

    let (addr, accepted) = echo().await;
    let mut down = backend("b1", addr);
    down.health_status = HealthStatus::Down;
    let mut closing = backend("b2", addr);
    closing.lifecycle_state = LifecycleState::Closing;
    h.set(stream(), vec![(down, false), (closing, false)]);
    let _client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::NoHealthyBackend);
    assert_eq!(record.attempts, 0);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backups_serve_only_once_the_primaries_are_exhausted() {
    let mut h = Harness::new().await;
    let (backup_addr, backup_hits) = echo().await;
    let (primary_addr, primary_hits) = echo().await;

    // `b0` sorts first, so only its backup flag keeps it out.
    h.set(
        stream(),
        vec![
            (backend("b0", backup_addr), true),
            (backend("b2", primary_addr), false),
        ],
    );
    let mut client = h.connect().await;
    echo_once(&mut client, b"primary").await;
    drop(client);
    assert_eq!(h.record().await.backend_id.as_deref(), Some("b2"));
    assert_eq!(primary_hits.load(Ordering::SeqCst), 1);
    assert_eq!(backup_hits.load(Ordering::SeqCst), 0);

    let dead = refusing();
    h.set(
        stream(),
        vec![
            (backend("b0", backup_addr), true),
            (backend("b1", dead.addr()), false),
        ],
    );
    let mut client = h.connect().await;
    echo_once(&mut client, b"backup").await;
    drop(client);
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b0"));
    assert_eq!(record.attempts, 2);
    assert_eq!(backup_hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_breaker_deny_reselects_without_an_attempt() {
    let mut h = Harness::new().await;
    let (denied_addr, denied_hits) = echo().await;
    let (addr, _) = echo().await;
    h.breaker.deny.lock().unwrap().insert("b1".into());
    h.set(
        stream(),
        vec![
            (backend("b1", denied_addr), false),
            (backend("b2", addr), false),
        ],
    );
    let mut client = h.connect().await;
    echo_once(&mut client, b"x").await;
    drop(client);
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b2"));
    assert_eq!(record.attempts, 1);
    let stats = h.stats();
    assert_eq!((stats.breaker_denied, stats.connect_attempts), (1, 1));
    assert_eq!(denied_hits.load(Ordering::SeqCst), 0);
}

// ---- PROXY protocol ---------------------------------------------------

fn accepting(trusted: &[&str], send: StreamProxyProtocol) -> Stream {
    let mut s = stream();
    s.proxy_protocol_accept = true;
    s.proxy_protocol_trusted_cidrs = trusted.iter().map(|c| c.to_string()).collect();
    s.proxy_protocol_send = send;
    s
}

fn carried(wire: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
    let Ok(Parsed::Complete { header, consumed }) = parse(wire) else {
        panic!("the backend got a PROXY header: {wire:?}");
    };
    let Addresses::Tcp {
        source,
        destination,
    } = header.addresses
    else {
        panic!("TCP addresses: {:?}", header.addresses);
    };
    (source, destination, wire[consumed..].to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_header_carries_the_client_into_the_record_and_the_send() {
    let mut h = Harness::new().await;
    let (addr, mut received) = sink().await;
    let source: SocketAddr = "192.0.2.10:51000".parse().unwrap();
    let destination: SocketAddr = "198.51.100.1:443".parse().unwrap();

    // v1 in, v2 out.
    h.set(
        accepting(&["127.0.0.0/8"], StreamProxyProtocol::V2),
        vec![(backend("b1", addr), false)],
    );
    let mut client = h.connect().await;
    let peer = client.local_addr().unwrap();
    client
        .write_all(b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\nhello")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let wire = tokio::time::timeout(WAIT, received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(wire[..12], V2_SIGNATURE[..]);
    assert_eq!(carried(&wire), (source, destination, b"hello".to_vec()));
    let record = h.record().await;
    assert_eq!(record.client, source);
    assert_eq!(record.peer, peer);
    assert_eq!(record.proxied_from, Some(peer));
    assert_eq!(record.bytes_upload, 5);

    // v2 in, v1 out.
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::V1),
        vec![(backend("b1", addr), false)],
    );
    let mut client = h.connect().await;
    let mut header = encode_v2(source, destination);
    header.extend_from_slice(b"world");
    client.write_all(&header).await.unwrap();
    client.shutdown().await.unwrap();
    let wire = tokio::time::timeout(WAIT, received.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(wire.starts_with(b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n"));
    assert_eq!(carried(&wire), (source, destination, b"world".to_vec()));
    assert_eq!(h.record().await.client, source);

    let stats = h.stats();
    assert_eq!(
        stats.proxy_header.get(&ProxyHeaderOutcome::AcceptedV1),
        Some(&1)
    );
    assert_eq!(
        stats.proxy_header.get(&ProxyHeaderOutcome::AcceptedV2),
        Some(&1)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_send_without_accept_carries_the_socket_addresses() {
    let mut h = Harness::new().await;
    let (addr, mut received) = sink().await;
    let mut s = stream();
    s.proxy_protocol_send = StreamProxyProtocol::V2;
    h.set(s, vec![(backend("b1", addr), false)]);
    let mut client = h.connect().await;
    let peer = client.local_addr().unwrap();
    client.write_all(b"data").await.unwrap();
    client.shutdown().await.unwrap();
    let wire = tokio::time::timeout(WAIT, received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(carried(&wire), (peer, h.listen, b"data".to_vec()));
    assert_eq!(h.record().await.bytes_upload, 4);
}

/// A trusted peer sending `bytes` ends `proxy_header_invalid`, counted
/// with `outcome`, before any backend: the `nth` such end of the test.
/// Only the first of a window hands a record (Story 12.9 D-c), so the
/// end is read from the counters.
async fn refused_header(h: &mut Harness, bytes: &[u8], outcome: ProxyHeaderOutcome, nth: u64) {
    let mut client = h.connect().await;
    client.write_all(bytes).await.unwrap();
    wait_until("the end counted", || {
        ended(&h.stats(), StreamEndKind::ProxyHeaderInvalid) == nth
    })
    .await;
    assert_eq!(
        h.stats().proxy_header.get(&outcome),
        Some(&1),
        "{outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_peer_header_that_is_oversized_or_dgram_is_refused() {
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );

    let mut oversized = V2_SIGNATURE.to_vec();
    oversized.extend_from_slice(&[0x21, 0x11]);
    oversized.extend_from_slice(&u16::try_from(4_097 - 16).unwrap().to_be_bytes());
    oversized.resize(4_097, 0);
    refused_header(&mut h, &oversized, ProxyHeaderOutcome::RefusedOversized, 1).await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ProxyHeaderInvalid);
    assert_eq!(record.backend_id, None);

    let dgram = encode_v2_dgram(
        "192.0.2.10:53".parse().unwrap(),
        "198.51.100.1:53".parse().unwrap(),
    );
    refused_header(&mut h, &dgram, ProxyHeaderOutcome::RefusedUnsupported, 2).await;

    refused_header(
        &mut h,
        b"PROXY TCP4 nonsense\r\n",
        ProxyHeaderOutcome::RefusedMalformed,
        3,
    )
    .await;
    assert!(
        h.records.try_recv().is_err(),
        "the window's first end was its one record"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(h.outcomes().is_empty(), "no connect phase, no outcome");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trickled_header_ends_at_five_seconds() {
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );
    let started = Instant::now();
    let mut client = h.connect().await;
    let trickle = tokio::spawn(async move {
        for byte in b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\n" {
            if client.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ProxyHeaderInvalid);
    // The header's five seconds, never fewer: the trickle never completes
    // it, so the refusal below is the deadline's.
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(5), "{took:?}");
    assert_eq!(
        h.stats()
            .proxy_header
            .get(&ProxyHeaderOutcome::RefusedTimeout),
        Some(&1)
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    trickle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untrusted_peer_header_forwards_nothing_and_ping_is_forwarded() {
    let mut h = Harness::new().await;
    let (addr, mut received) = sink().await;
    h.set(
        accepting(&["192.0.2.0/24"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );

    let mut client = h.connect().await;
    client
        .write_all(b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\nGET /")
        .await
        .unwrap();
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::ProxyHeaderInvalid
    );
    let got = tokio::time::timeout(WAIT, received.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"".as_slice()));

    // A v2 signature split across two writes is held, then refused.
    let header = encode_v2(
        "192.0.2.10:1".parse().unwrap(),
        "192.0.2.11:2".parse().unwrap(),
    );
    let mut client = h.connect().await;
    client.write_all(&header[..5]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.write_all(&header[5..]).await.unwrap();
    // The second end of the window: counted, its record held back.
    wait_until("the second end counted", || {
        ended(&h.stats(), StreamEndKind::ProxyHeaderInvalid) == 2
    })
    .await;
    let got = tokio::time::timeout(WAIT, received.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"".as_slice()));
    assert_eq!(
        h.stats()
            .proxy_header
            .get(&ProxyHeaderOutcome::RefusedUntrustedPeer),
        Some(&2)
    );

    // A direct client opening with `P` is not a PROXY header.
    let mut client = h.connect().await;
    client.write_all(b"PING").await.unwrap();
    client.shutdown().await.unwrap();
    let got = tokio::time::timeout(WAIT, received.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"PING".as_slice()));
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ClientClose);
    assert_eq!(record.proxied_from, None);
}

// ---- local backends -----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_destination_needs_the_flag_and_never_a_node_port() {
    let (addr, accepted) = echo().await;
    let held = [refusing(), refusing(), refusing()];
    let reserved = ReservedPorts {
        management: held[0].addr().port(),
        http: held[1].addr().port(),
        https: held[2].addr().port(),
        cluster: None,
        enrollment: None,
        automation: None,
    };
    let mut h = Harness::with_reserved(Some(reserved)).await;

    let mut flagless = stream();
    flagless.allow_local_backend = false;
    h.set(flagless, vec![(backend("b1", addr), false)]);
    let _client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::NoHealthyBackend);
    assert_eq!(record.attempts, 0);
    assert_eq!(h.stats().local_destination_refused, 1);
    assert_eq!(h.counters.snapshot().backends["b1"].dns_local_excluded, 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    h.set(stream(), vec![(backend("b1", addr), false)]);
    let mut client = h.connect().await;
    echo_once(&mut client, b"flagged").await;
    drop(client);
    assert_eq!(h.record().await.backend_id.as_deref(), Some("b1"));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // On a port this process listens on for a stream: refused, flag or
    // not.
    h.bound.add(addr.port());
    let _client = h.connect().await;
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::NoHealthyBackend
    );
    h.bound.remove(addr.port());

    // On a reserved port of the node: refused, flag or not.
    let management = SocketAddr::new(addr.ip(), reserved.management);
    h.set(stream(), vec![(backend("b1", management), false)]);
    let _client = h.connect().await;
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::NoHealthyBackend
    );
    assert_eq!(h.stats().local_destination_refused, 3);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_resolving_to_loopback_is_excluded_and_never_connected() {
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    h.dns
        .answer("db.example.com", vec!["127.0.0.1".parse().unwrap()]);
    let named = backend("b1", format!("db.example.com:{}", addr.port()));

    let mut flagless = stream();
    flagless.allow_local_backend = false;
    h.set(flagless, vec![(named.clone(), false)]);
    let _client = h.connect().await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::NoHealthyBackend);
    assert_eq!(h.counters.snapshot().backends["b1"].dns_local_excluded, 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    // The same name on a stream that allows local backends connects:
    // the exclusion is the stream's, not the backend's.
    h.set(stream(), vec![(named, false)]);
    let mut client = h.connect().await;
    echo_once(&mut client, b"named").await;
    drop(client);
    let record = h.record().await;
    assert_eq!(record.backend_address, Some(addr));
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

// ---- bandwidth, cap ------------------------------------------------------

/// The limit holds end to end, each way: 64 KiB at 16 KiB/s cannot take
/// less than the three seconds the bucket allows after its one-second
/// burst. Each clock starts before the connect, so it can only read
/// long. How close to three seconds the forwarder keeps is pinned on a
/// paused clock beside it, where the host's load cannot add to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixty_four_kib_at_sixteen_kib_per_second_take_three_seconds_or_more_each_way() {
    const SIZE: usize = 64 * 1024;
    let mut limited = stream();
    limited.upload_rate_bps = Some(16 * 1024);
    limited.download_rate_bps = Some(16 * 1024);

    let up = async {
        let h = Harness::new().await;
        let (addr, mut received) = sink().await;
        h.set(limited.clone(), vec![(backend("b1", addr), false)]);
        let started = Instant::now();
        let mut client = h.connect().await;
        client.write_all(&vec![1u8; SIZE]).await.unwrap();
        client.shutdown().await.unwrap();
        let got = tokio::time::timeout(WAIT, received.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), SIZE);
        started.elapsed()
    };
    let down = async {
        let h = Harness::new().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&vec![2u8; SIZE]).await.unwrap();
        });
        h.set(limited.clone(), vec![(backend("b1", addr), false)]);
        let started = Instant::now();
        let mut client = h.connect().await;
        let got = read_to_end(&mut client).await;
        assert_eq!(got.len(), SIZE);
        started.elapsed()
    };
    let (up, down) = tokio::join!(up, down);
    for (way, took) in [("upload", up), ("download", down)] {
        assert!(took >= Duration::from_millis(2_900), "{way}: {took:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_1025_of_a_1024_cap_is_refused_and_counted() {
    let mut h = Harness::new().await;
    let (addr, _received) = sink().await;
    let s = stream();
    assert_eq!(s.max_connections, Stream::DEFAULT_MAX_CONNECTIONS);
    let cap = s.max_connections as usize;
    h.set(s, vec![(backend("b1", addr), false)]);

    let mut clients = Vec::with_capacity(cap);
    for _ in 0..cap {
        clients.push(h.connect().await);
    }
    let link = (STREAM_ID.to_string(), "b1".to_string());
    wait_until("every connection established", || {
        h.counters
            .snapshot()
            .links
            .get(&link)
            .is_some_and(|l| l.active == cap as u64)
    })
    .await;

    // A refusal is a row through the refusal log, never a record (Story
    // 12.6 D-j).
    let mut refused = h.connect().await;
    let row = h.refusal().await;
    assert_eq!(row.refusal, StreamRefusal::ConnectionCap);
    assert_eq!(row.client, refused.local_addr().unwrap());
    assert_eq!(row.listen_port, h.listen.port());
    assert!(read_to_end(&mut refused).await.is_empty());
    let stats = h.stats();
    assert_eq!(stats.refused.get(&StreamRefusal::ConnectionCap), Some(&1));
    assert_eq!(ended(&stats, StreamEndKind::Refused), 1);
    assert!(h.records.try_recv().is_err(), "no record for a refusal");

    // A slot freed is a slot taken again.
    drop(clients.pop());
    assert_eq!(h.record().await.end_reason, StreamEndReason::ClientClose);
    let _again = h.connect().await;
    wait_until("the freed slot reused", || {
        h.counters.snapshot().links[&link].connects == cap as u64 + 1
    })
    .await;
    assert_eq!(
        h.stats().refused.get(&StreamRefusal::ConnectionCap),
        Some(&1)
    );
}

// ---- drains in every phase ---------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drain_ends_a_connection_in_each_phase_with_the_drain_reason() {
    // A configuration change, and a hot upgrade (Story 12.11 D-c).
    for reason in [
        StreamEndReason::ConfigRemoved,
        StreamEndReason::DrainedByUpgrade,
    ] {
        let mut h = Harness::new().await;
        let (addr, _) = echo().await;

        // Phase 2: a trusted peer that has not sent its header yet.
        h.set(
            accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
            vec![(backend("b1", addr), false)],
        );
        let mut client = h.connect().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        h.drain_now(reason);
        let record = h.record().await;
        assert_eq!(record.end_reason, reason);
        assert_eq!(record.attempts, 0);
        assert!(read_to_end(&mut client).await.is_empty());

        // Phase 3: a name whose resolution never answers.
        h.set(
            stream(),
            vec![(backend("b1", "never.example.com:5432"), false)],
        );
        let mut client = h.connect().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        h.drain_now(reason);
        let record = h.record().await;
        assert_eq!(record.end_reason, reason);
        assert_eq!(record.backend_id, None);
        assert!(read_to_end(&mut client).await.is_empty());

        // Phase 4: an established echo.
        h.set(stream(), vec![(backend("b1", addr), false)]);
        let mut client = h.connect().await;
        echo_once(&mut client, b"live").await;
        h.drain_now(reason);
        let record = h.record().await;
        assert_eq!(record.end_reason, reason);
        assert_eq!(record.backend_id.as_deref(), Some("b1"));
        assert!(read_to_end(&mut client).await.is_empty());
        assert_eq!(ended(&h.stats(), reason.kind()), 3);
    }
}

// ---- admission (Story 12.6) ---------------------------------------------

fn loopback(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
}

/// `client` is refused `refusal` at accept: closed before any byte is
/// forwarded, one row naming it, the refusal counted once.
async fn refused_at_accept(h: &mut Harness, mut client: TcpStream, refusal: StreamRefusal) {
    let from = client.local_addr().unwrap();
    let _ = client.write_all(b"never forwarded").await;
    assert!(read_to_end(&mut client).await.is_empty(), "{refusal:?}");
    let row = h.refusal().await;
    assert_eq!((row.refusal, row.client), (refusal, from));
    assert_eq!(row.protocol, StreamProtocol::Tcp);
    assert_eq!(row.proxied_from, None);
    assert_eq!(h.refused(refusal), 1, "{refusal:?} counted once");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_source_control_refuses_at_accept_and_an_unknown_country_passes() {
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    h.gate.filtered.lock().unwrap().insert(loopback(2));
    h.gate.blocked.lock().unwrap().insert(loopback(3));
    h.gate
        .countries
        .lock()
        .unwrap()
        .extend([(loopback(5), *b"US"), (loopback(7), *b"FR")]);
    let mut s = stream();
    s.source_deny_cidrs = vec!["127.0.0.4".into()];
    s.geoip = Some(GeoIpConfig {
        mode: GeoIpMode::Denylist,
        countries: vec!["US".into()],
    });
    h.set(s, vec![(backend("b1", addr), false)]);

    for (n, refusal) in [
        (2, StreamRefusal::ConnectionFilter),
        (3, StreamRefusal::IpBlocklist),
        (4, StreamRefusal::SourceDenied),
        (5, StreamRefusal::Geoip),
    ] {
        let client = h.connect_from(n).await;
        refused_at_accept(&mut h, client, refusal).await;
    }
    assert_eq!(accepted.load(Ordering::SeqCst), 0, "no backend was opened");

    // A country the list does not name passes; one the database does not
    // know passes too, counted.
    for n in [7, 6] {
        let mut client = h.connect_from(n).await;
        echo_once(&mut client, b"served").await;
    }
    assert_eq!(h.stats().geoip_unknown, 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_without_its_region_refuses_caps_unavailable() {
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    let s = stream();
    let links = vec![StreamBackend::primary(&s.id, "b1")];
    let table = StreamTable::with_backends(vec![s], &links, vec![backend("b1", addr)]);
    h.engine.table_changed(&table);
    *h.table.lock().unwrap() = Arc::new(table);
    let client = h.connect().await;
    refused_at_accept(&mut h, client, StreamRefusal::CapsUnavailable).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
}

/// IV1 at this level: a source over its new-connection rate is refused
/// at accept while another source of the same stream is served, and its
/// refusals are rows or counted once in a suppressed row, never both.
///
/// The bucket holds one second of burst and refills at the rate, so how
/// many connections of a burst it admits depends on how long the burst
/// took to arrive, which a loaded host stretches: the bound is read from
/// the clock, and the test connects until it has refusals to count.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_over_its_open_rate_is_refused_while_another_is_served() {
    const RATE: u32 = 5;
    const BURST: u64 = 10;
    let mut h = Harness::new().await;
    let (addr, backend_hits) = echo().await;
    let mut s = stream();
    s.source_open_rate = Some(RATE);
    h.set(s, vec![(backend("b1", addr), false)]);

    // A connection is settled once the backend accepted it or its refusal
    // is counted. The `active` gauge cannot tell: it holds a connection
    // from its accept, so one being refused reads as admitted until then.
    let admitted = || backend_hits.load(Ordering::SeqCst) as u64;
    let started = Instant::now();
    let mut held = Vec::new();
    let mut refused = 0;
    while refused < 2 {
        for _ in 0..BURST {
            held.push(h.connect_from(2).await);
        }
        let total = held.len() as u64;
        wait_until("every connection admitted or refused", || {
            admitted() + h.stats().refused.values().sum::<u64>() == total
        })
        .await;
        refused = h.refused(StreamRefusal::SourceOpenRate);
        assert!(Instant::now() < started + WAIT, "no burst outran the rate");
    }
    let took = started.elapsed();
    let admitted = admitted();
    assert_eq!(admitted + refused, held.len() as u64);
    let refill = (took.as_secs_f64() * f64::from(RATE)).ceil() as u64;
    assert!(
        admitted >= u64::from(RATE) && admitted <= u64::from(RATE) + refill,
        "{admitted} admitted in {took:?} at {RATE} per second with one second of burst"
    );

    let row = h.refusal().await;
    assert_eq!(row.refusal, StreamRefusal::SourceOpenRate);
    assert_eq!(row.client.ip(), loopback(2));
    let mut other = h.connect_from(3).await;
    echo_once(&mut other, b"another source").await;

    // Every refusal is a row or counted in one suppressed row, once. A
    // window opens per row, so the rows are at most the windows the
    // refusals spanned.
    let (mut rows, mut counted) = (1, 0);
    let deadline = Instant::now() + lorica_stream::REFUSAL_LOG_WINDOW + WAIT;
    while rows + counted < refused {
        tokio::select! {
            Some(row) = h.refusals.recv() => {
                assert_eq!(row.refusal, StreamRefusal::SourceOpenRate);
                rows += 1;
            }
            Some(held_back) = h.suppressed.recv() => {
                assert_eq!(
                    held_back.key,
                    StreamLogKey::Refused(StreamRefusal::SourceOpenRate)
                );
                counted += held_back.suppressed;
            }
            _ = tokio::time::sleep_until(deadline) => {
                panic!("{rows} rows and {counted} suppressed for {refused} refusals")
            }
        }
    }
    assert_eq!(rows + counted, refused);
    let windows = 1 + took.as_secs() / lorica_stream::REFUSAL_LOG_WINDOW.as_secs();
    assert!(rows <= windows, "{rows} rows over {windows} windows");
    assert!(h.refusals.try_recv().is_err());
    assert!(h.suppressed.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stream_open_rate_refuses_every_source_past_it() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.open_rate = Some(1);
    h.set(s, vec![(backend("b1", addr), false)]);
    let mut first = h.connect_from(2).await;
    echo_once(&mut first, b"first").await;
    let second = h.connect_from(3).await;
    refused_at_accept(&mut h, second, StreamRefusal::OpenRate).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_at_source_max_connections_is_refused_and_another_served() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.source_max_connections = Some(1);
    h.set(s, vec![(backend("b1", addr), false)]);
    let mut first = h.connect_from(2).await;
    echo_once(&mut first, b"held").await;
    let second = h.connect_from(2).await;
    refused_at_accept(&mut h, second, StreamRefusal::SourceConnectionCap).await;
    let mut other = h.connect_from(3).await;
    echo_once(&mut other, b"another source").await;
}

/// A TLS stream: every connection reads a ClientHello, so it is pending
/// from accept. The deadline is the longest, so no read expires during a
/// test.
fn tls_passthrough() -> Stream {
    let mut s = stream();
    s.tls_mode = StreamTlsMode::Passthrough;
    s.clienthello_timeout_ms = Some(60_000);
    s
}

fn region_pending(h: &Harness) -> u64 {
    h.caps
        .get(STREAM_ID)
        .expect("test setup: a region")
        .current()
        .region()
        .pending()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_at_its_pending_share_is_refused_while_another_is_admitted() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = tls_passthrough();
    s.max_pending_connections = 16;
    let share = u64::from(s.source_pending_share());
    assert_eq!(share, 2);
    h.set(s, vec![(backend("b1", addr), false)]);

    let mut silent = Vec::new();
    for _ in 0..share {
        silent.push(h.connect_from(2).await);
    }
    wait_until("the source's share pending", || region_pending(&h) == share).await;
    let over = h.connect_from(2).await;
    refused_at_accept(&mut h, over, StreamRefusal::SourcePendingCap).await;
    silent.push(h.connect_from(3).await);
    wait_until("another source admitted", || {
        region_pending(&h) == share + 1
    })
    .await;
    assert_eq!(h.stats().pending, share + 1);
    drop(silent);
    wait_until("every pending slot given back", || {
        region_pending(&h) == 0 && h.stats().pending == 0
    })
    .await;
}

/// IV3 at this level: 2,000 silent connections never take more than the
/// pending cap, and the ones past it are refused at accept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_thousand_silent_connections_never_pass_the_pending_cap() {
    const SOURCES: u8 = 100;
    const PER_SOURCE: usize = 20;
    let h = Harness::new().await;
    let (addr, _) = echo().await;
    let s = tls_passthrough();
    let cap = u64::from(s.effective_pending_connections());
    assert!(PER_SOURCE as u64 <= u64::from(s.source_pending_share()));
    h.set(s, vec![(backend("b1", addr), false)]);

    let mut silent = Vec::with_capacity(usize::from(SOURCES) * PER_SOURCE);
    for n in 0..SOURCES {
        for _ in 0..PER_SOURCE {
            silent.push(h.connect_from(n + 2).await);
        }
        assert!(region_pending(&h) <= cap, "past the cap after source {n}");
    }
    let total = silent.len() as u64;
    wait_until("every connection admitted or refused", || {
        let stats = h.stats();
        stats.accepted == total
            && stats.refused.get(&StreamRefusal::PendingCap).copied() == Some(total - cap)
    })
    .await;
    assert_eq!(region_pending(&h), cap);
    assert_eq!(h.stats().pending, cap);
    drop(silent);
    wait_until("every pending slot given back", || region_pending(&h) == 0).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_peer_is_not_judged_and_its_carried_client_is() {
    let mut h = Harness::new().await;
    let (addr, mut received) = sink().await;
    // The load balancer's own range is denied: as a trusted peer it is
    // never judged as a source.
    let mut s = accepting(&["127.0.0.0/8"], StreamProxyProtocol::Off);
    s.source_deny_cidrs = vec!["127.0.0.0/8".into(), "192.0.2.66".into()];
    h.set(s, vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    client
        .write_all(b"PROXY TCP4 192.0.2.10 198.51.100.1 51000 443\r\nhello")
        .await
        .unwrap();
    client.shutdown().await.unwrap();
    let got = tokio::time::timeout(WAIT, received.recv()).await.unwrap();
    assert_eq!(got.as_deref(), Some(b"hello".as_slice()));
    assert_eq!(h.record().await.client.ip().to_string(), "192.0.2.10");

    let mut client = h.connect().await;
    let peer = client.local_addr().unwrap();
    client
        .write_all(b"PROXY TCP4 192.0.2.66 198.51.100.1 51000 443\r\nhello")
        .await
        .unwrap();
    assert!(read_to_end(&mut client).await.is_empty());
    let row = h.refusal().await;
    assert_eq!(row.refusal, StreamRefusal::SourceDenied);
    assert_eq!(row.client, "192.0.2.66:51000".parse().unwrap());
    assert_eq!(row.proxied_from, Some(peer));

    // A header carrying no client leaves the peer the source judged.
    let mut client = h.connect().await;
    client.write_all(b"PROXY UNKNOWN\r\nhello").await.unwrap();
    assert!(read_to_end(&mut client).await.is_empty());
    assert_eq!(
        h.refused(StreamRefusal::SourceDenied),
        2,
        "the LOCAL header's peer refused too"
    );
    assert!(received.try_recv().is_err(), "nothing forwarded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_backend_at_its_cap_is_skipped_and_all_at_cap_refuse_backend_cap() {
    let mut h = Harness::new().await;
    let (first, first_hits) = echo().await;
    let (second, second_hits) = echo().await;
    h.set_links(
        stream(),
        vec![
            (backend("b1", first), false, Some(1)),
            (backend("b2", second), false, Some(1)),
        ],
    );

    let mut a = h.connect().await;
    echo_once(&mut a, b"a").await;
    let mut b = h.connect().await;
    echo_once(&mut b, b"b").await;
    assert_eq!(
        (
            first_hits.load(Ordering::SeqCst),
            second_hits.load(Ordering::SeqCst)
        ),
        (1, 1),
        "b1 at its cap left the candidates, b2 took the second"
    );

    let c = h.connect().await;
    refused_at_accept(&mut h, c, StreamRefusal::BackendCap).await;
    assert_eq!(
        h.stats().connect_attempts,
        2,
        "a backend at its cap is no attempt"
    );
    assert_eq!(
        *h.breaker.records.lock().unwrap(),
        vec![
            ("b1".to_string(), true, false),
            ("b2".to_string(), true, false)
        ],
        "nor a breaker report"
    );

    drop(a);
    assert_eq!(h.record().await.backend_id.as_deref(), Some("b1"));
    let mut d = h.connect().await;
    echo_once(&mut d, b"d").await;
    assert_eq!(first_hits.load(Ordering::SeqCst), 2, "b1's place came back");
}

// ---- what the access log is handed (Story 12.9 Lot A) --------------------

/// Each connection that reaches backend selection reports its connect
/// outcome once, before its record; one that never does reports none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_connection_reaching_selection_reports_one_connect_outcome() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;

    h.set(stream(), vec![(backend("b1", addr), false)]);
    let mut client = h.connect().await;
    echo_once(&mut client, b"x").await;
    drop(client);
    assert_eq!(h.record().await.end_reason, StreamEndReason::ClientClose);
    let heard = h.outcomes();
    assert!(
        matches!(heard.as_slice(), [ConnectOutcome::Connected { .. }]),
        "{heard:?}"
    );

    let dead = refusing();
    h.set(stream(), vec![(backend("b1", dead.addr()), false)]);
    let _client = h.connect().await;
    assert_eq!(h.record().await.end_reason, StreamEndReason::ConnectFailed);
    assert_eq!(h.outcomes(), vec![ConnectOutcome::NotConnected]);

    let mut down = backend("b1", addr);
    down.health_status = HealthStatus::Down;
    h.set(stream(), vec![(down, false)]);
    let _client = h.connect().await;
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::NoHealthyBackend
    );
    assert_eq!(h.outcomes(), vec![ConnectOutcome::NotConnected]);

    // Refused at accept, or ended before forwarding: no connect phase.
    let mut denied = stream();
    denied.source_deny_cidrs = vec!["127.0.0.2".into()];
    h.set(denied, vec![(backend("b1", addr), false)]);
    let client = h.connect_from(2).await;
    refused_at_accept(&mut h, client, StreamRefusal::SourceDenied).await;
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );
    let mut client = h.connect().await;
    client.write_all(b"PROXY TCP4 nonsense\r\n").await.unwrap();
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::ProxyHeaderInvalid
    );
    assert!(h.outcomes().is_empty());
}

/// A flood of ends before forwarding is one record per window and one
/// suppressed row counting the rest, keyed by the end; every end is
/// still counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_pre_forwarding_ends_is_one_record_and_one_suppressed_row() {
    const FLOOD: u64 = 20;
    let mut h = Harness::new().await;
    let (addr, accepted) = echo().await;
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );
    for nth in 1..=FLOOD {
        let mut client = h.connect().await;
        client.write_all(b"PROXY TCP4 nonsense\r\n").await.unwrap();
        wait_until("the end counted", || {
            ended(&h.stats(), StreamEndKind::ProxyHeaderInvalid) == nth
        })
        .await;
    }
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ProxyHeaderInvalid);
    assert!(h.records.try_recv().is_err(), "one record for the window");
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    let held_back = tokio::time::timeout(
        lorica_stream::REFUSAL_LOG_WINDOW + WAIT,
        h.suppressed.recv(),
    )
    .await
    .expect("a suppressed row when the window closes")
    .expect("the engine is alive");
    assert_eq!(
        held_back.key,
        StreamLogKey::PreForwarding(StreamEndKind::ProxyHeaderInvalid)
    );
    assert_eq!(held_back.key.end_kind(), StreamEndKind::ProxyHeaderInvalid);
    assert_eq!(held_back.key.refusal(), None);
    assert_eq!(held_back.suppressed, FLOOD - 1);
    assert_eq!(held_back.protocol, StreamProtocol::Tcp);
    assert!(h.suppressed.try_recv().is_err());
    assert!(h.refusals.try_recv().is_err(), "not a refusal row");
}

/// The bytes of a stream are the sum of its backends', each counted on
/// the backend that carried them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_backend_bytes_add_up_to_the_streams() {
    let mut h = Harness::new().await;
    let (first, _) = echo().await;
    let (second, _) = echo().await;
    h.set(
        stream(),
        vec![
            (backend("b1", first), false),
            (backend("b2", second), false),
        ],
    );
    let mut client = h.connect().await;
    echo_once(&mut client, b"to the first").await;
    drop(client);
    assert_eq!(h.record().await.backend_id.as_deref(), Some("b1"));

    // `b1` down: the next connection is `b2`'s, `b1`'s link is kept.
    let mut down = backend("b1", first);
    down.health_status = HealthStatus::Down;
    h.set(
        stream(),
        vec![(down, false), (backend("b2", second), false)],
    );
    let mut client = h.connect().await;
    echo_once(&mut client, b"to the second, longer").await;
    drop(client);
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b2"));

    let snapshot = h.counters.snapshot();
    let link = |id: &str| &snapshot.links[&(STREAM_ID.to_string(), id.to_string())];
    assert_eq!(link("b1").bytes_upload, 12);
    assert_eq!(link("b2").bytes_upload, 21);
    let stream = &snapshot.streams[STREAM_ID];
    let upload: u64 = snapshot.links.values().map(|l| l.bytes_upload).sum();
    let download: u64 = snapshot.links.values().map(|l| l.bytes_download).sum();
    assert_eq!(
        (upload, download),
        (stream.bytes_upload, stream.bytes_download)
    );
}

/// Story 12.9 D-k: the observer takes a connection's record, and a
/// refused one's row, while the connection is still in the tracker, so
/// a drain that waits for an empty tracker cannot stop with either in
/// flight. Read at the moment of the report, not after, so the check
/// depends on no timing: with the entry gone first it reads 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_record_and_a_refusal_reach_the_observer_before_their_entry_leaves_the_tracker() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.source_deny_cidrs = vec!["127.0.0.4".into()];
    h.set(s, vec![(backend("b1", addr), false)]);

    let mut client = h.connect().await;
    echo_once(&mut client, b"ping").await;
    client.shutdown().await.unwrap();
    assert!(read_to_end(&mut client).await.is_empty());
    h.record().await;
    let client = h.connect_from(4).await;
    refused_at_accept(&mut h, client, StreamRefusal::SourceDenied).await;

    let tracked = h.tracked_at_report.lock().unwrap().clone();
    assert_eq!(tracked.len(), 2, "one record and one refusal: {tracked:?}");
    assert!(
        tracked.iter().all(|&entries| entries >= 1),
        "a report found its connection already out of the tracker: {tracked:?}"
    );
    wait_until("the entries left", || h.tracker.is_empty()).await;
}
