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
//! and hangs on any other name.
//!
//! The 64 MiB backpressure case lives beside the forwarding loop
//! (`tcp::forward` unit tests), where the direction states are readable
//! while the loop is parked.

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, Stream, StreamBackend, StreamEndKind,
    StreamEndReason, StreamProtocol, StreamProxyProtocol, StreamRefusal,
};
use lorica_core::protocols::proxy_protocol::{
    encode_v2, encode_v2_dgram, parse, Addresses, Parsed, V2_SIGNATURE,
};
use lorica_stream::counters::{ConnectFailureKind, ProxyHeaderOutcome, StreamCountersSnapshot};
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    AcceptedConnection, Admission, BackendSelector, BoundPorts, BreakerGate, ConnectionObserver,
    ConnectionRecord, ConnectionTracker, Resolve, ResolveError, Resolved, ResolverCache,
    SelectionRequest, StreamCounters, StreamHandler, StreamTable, TcpEngine, TcpEngineParts,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

const STREAM_ID: &str = "s";
const WAIT: Duration = Duration::from_secs(10);

// ---- fake seams ------------------------------------------------------

#[derive(Default)]
struct FirstCandidate {
    connected: Mutex<Vec<String>>,
    closed: Mutex<Vec<String>>,
}

impl BackendSelector for FirstCandidate {
    fn select(&self, _request: &SelectionRequest<'_>) -> usize {
        0
    }

    fn connected(&self, _stream_id: &str, backend: &Backend, _: SocketAddr, _: Duration) {
        self.connected.lock().unwrap().push(backend.id.clone());
    }

    fn closed(&self, _stream_id: &str, backend: &Backend, _: SocketAddr) {
        self.closed.lock().unwrap().push(backend.id.clone());
    }
}

#[derive(Default)]
struct Breaker {
    deny: Mutex<HashSet<String>>,
    records: Mutex<Vec<(String, bool, bool)>>,
}

impl BreakerGate for Breaker {
    fn admit<'a>(&'a self, _stream_id: &'a str, backend: &'a Backend) -> SeamFuture<'a, Admission> {
        let denied = self.deny.lock().unwrap().contains(&backend.id);
        Box::pin(async move {
            if denied {
                Admission::Deny
            } else {
                Admission::Allow
            }
        })
    }

    fn record<'a>(
        &'a self,
        _stream_id: &'a str,
        backend: &'a Backend,
        success: bool,
        was_probe: bool,
    ) -> SeamFuture<'a, ()> {
        self.records
            .lock()
            .unwrap()
            .push((backend.id.clone(), success, was_probe));
        Box::pin(async {})
    }
}

/// Answers the names it holds, hangs on any other.
#[derive(Default)]
struct Dns(Mutex<HashMap<String, Vec<IpAddr>>>);

impl Resolve for Dns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        let answer = self.0.lock().unwrap().get(host).cloned();
        Box::pin(async move {
            match answer {
                Some(addresses) => Ok(Resolved {
                    addresses,
                    ttl: Duration::from_secs(30),
                }),
                None => std::future::pending().await,
            }
        })
    }
}

struct Records(mpsc::UnboundedSender<ConnectionRecord>);

impl ConnectionObserver for Records {
    fn observe(&self, record: ConnectionRecord) {
        let _ = self.0.send(record);
    }
}

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

fn backend(id: &str, address: impl ToString) -> Backend {
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: format!("backend-{id}"),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
        health_check_enabled: false,
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

struct Harness {
    engine: TcpEngine,
    tracker: ConnectionTracker,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    counters: Arc<StreamCounters>,
    breaker: Arc<Breaker>,
    dns: Arc<Dns>,
    selector: Arc<FirstCandidate>,
    bound: BoundPorts,
    table: Arc<Mutex<Arc<StreamTable>>>,
    listen: SocketAddr,
}

impl Harness {
    async fn new() -> Self {
        Self::with_reserved(None).await
    }

    async fn with_reserved(reserved_ports: Option<ReservedPorts>) -> Self {
        let counters = Arc::new(StreamCounters::new());
        let breaker = Arc::new(Breaker::default());
        let dns = Arc::new(Dns::default());
        let selector = Arc::new(FirstCandidate::default());
        let (tx, records) = mpsc::unbounded_channel();
        let engine = TcpEngine::new(TcpEngineParts {
            selector: Arc::clone(&selector) as Arc<dyn BackendSelector>,
            breaker: Arc::clone(&breaker) as Arc<dyn BreakerGate>,
            resolver: ResolverCache::new(
                Arc::clone(&dns) as Arc<dyn Resolve>,
                Arc::clone(&counters),
            ),
            counters: Arc::clone(&counters),
            observer: Arc::new(Records(tx)),
            reserved_ports,
        });
        let tracker = ConnectionTracker::new();
        let bound = BoundPorts::new();
        let table: Arc<Mutex<Arc<StreamTable>>> = Arc::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen = listener.local_addr().unwrap();
        {
            let (engine, tracker, bound, table) = (
                engine.clone(),
                tracker.clone(),
                bound.clone(),
                Arc::clone(&table),
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
                    }));
                }
            });
        }
        Harness {
            engine,
            tracker,
            records,
            counters,
            breaker,
            dns,
            selector,
            bound,
            table,
            listen,
        }
    }

    /// Serve `stream` with `backends`, each `(row, backup)`.
    fn set(&self, stream: Stream, backends: Vec<(Backend, bool)>) {
        let links: Vec<StreamBackend> = backends
            .iter()
            .map(|(b, backup)| StreamBackend {
                stream_id: stream.id.clone(),
                backend_id: b.id.clone(),
                backup: *backup,
            })
            .collect();
        let rows = backends.into_iter().map(|(b, _)| b).collect();
        let table = StreamTable::with_backends(vec![stream], &links, rows);
        self.engine.table_changed(&table);
        *self.table.lock().unwrap() = Arc::new(table);
    }

    async fn connect(&self) -> TcpStream {
        TcpStream::connect(self.listen).await.unwrap()
    }

    async fn record(&mut self) -> ConnectionRecord {
        tokio::time::timeout(WAIT, self.records.recv())
            .await
            .expect("a connection record in time")
            .expect("the engine is alive")
    }

    fn stats(&self) -> StreamCountersSnapshot {
        self.counters
            .snapshot()
            .streams
            .get(STREAM_ID)
            .cloned()
            .unwrap_or_default()
    }

    fn drain_now(&self) {
        let now = Instant::now();
        self.tracker.drain_all(now, StreamEndReason::ConfigRemoved);
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

/// An address nothing listens on.
fn refusing() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
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

// ---- timers ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_ends_with_idle_timeout() {
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;
    let mut s = stream();
    s.idle_timeout_s = 1;
    h.set(s, vec![(backend("b1", addr), false)]);

    let started = Instant::now();
    let mut client = h.connect().await;
    echo_once(&mut client, b"x").await;
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::IdleTimeout);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(3),
        "{took:?}"
    );
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
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(2),
        "{took:?}"
    );
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
    assert!(started.elapsed() < Duration::from_secs(2));
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
    h.set(
        stream(),
        vec![
            (backend("b1", refusing()), false),
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
    h.set(
        stream(),
        vec![
            (backend("b1", refusing()), false),
            (backend("b2", refusing()), false),
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

    h.set(
        stream(),
        vec![
            (backend("b0", backup_addr), true),
            (backend("b1", refusing()), false),
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

async fn refused_header(h: &mut Harness, bytes: &[u8], outcome: ProxyHeaderOutcome) {
    let mut client = h.connect().await;
    client.write_all(bytes).await.unwrap();
    let record = h.record().await;
    assert_eq!(
        record.end_reason,
        StreamEndReason::ProxyHeaderInvalid,
        "{outcome:?}"
    );
    assert_eq!(record.backend_id, None, "{outcome:?}");
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
    refused_header(&mut h, &oversized, ProxyHeaderOutcome::RefusedOversized).await;

    let dgram = encode_v2_dgram(
        "192.0.2.10:53".parse().unwrap(),
        "198.51.100.1:53".parse().unwrap(),
    );
    refused_header(&mut h, &dgram, ProxyHeaderOutcome::RefusedUnsupported).await;

    refused_header(
        &mut h,
        b"PROXY TCP4 nonsense\r\n",
        ProxyHeaderOutcome::RefusedMalformed,
    )
    .await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
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
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(5) && took < Duration::from_secs(6),
        "{took:?}"
    );
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
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::ProxyHeaderInvalid
    );
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
    let reserved = ReservedPorts {
        management: refusing().port(),
        http: refusing().port(),
        https: refusing().port(),
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
        .0
        .lock()
        .unwrap()
        .insert("db.example.com".into(), vec!["127.0.0.1".parse().unwrap()]);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixty_four_kib_at_sixteen_kib_per_second_take_three_to_five_seconds_each_way() {
    const SIZE: usize = 64 * 1024;
    let mut limited = stream();
    limited.upload_rate_bps = Some(16 * 1024);
    limited.download_rate_bps = Some(16 * 1024);

    let up = async {
        let h = Harness::new().await;
        let (addr, mut received) = sink().await;
        h.set(limited.clone(), vec![(backend("b1", addr), false)]);
        let mut client = h.connect().await;
        let started = Instant::now();
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
        let mut client = h.connect().await;
        let started = Instant::now();
        let got = read_to_end(&mut client).await;
        assert_eq!(got.len(), SIZE);
        started.elapsed()
    };
    let (up, down) = tokio::join!(up, down);
    for (way, took) in [("upload", up), ("download", down)] {
        assert!(
            took >= Duration::from_millis(2_900) && took <= Duration::from_secs(5),
            "{way}: {took:?}"
        );
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

    let mut refused = h.connect().await;
    let record = h.record().await;
    assert_eq!(
        record.end_reason,
        StreamEndReason::Refused(StreamRefusal::ConnectionCap)
    );
    assert_eq!(record.attempts, 0);
    assert!(read_to_end(&mut refused).await.is_empty());
    let stats = h.stats();
    assert_eq!(stats.refused.get(&StreamRefusal::ConnectionCap), Some(&1));
    assert_eq!(ended(&stats, StreamEndKind::Refused), 1);

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
    let mut h = Harness::new().await;
    let (addr, _) = echo().await;

    // Phase 2: a trusted peer that has not sent its header yet.
    h.set(
        accepting(&["127.0.0.1"], StreamProxyProtocol::Off),
        vec![(backend("b1", addr), false)],
    );
    let mut client = h.connect().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.drain_now();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConfigRemoved);
    assert_eq!(record.attempts, 0);
    assert!(read_to_end(&mut client).await.is_empty());

    // Phase 3: a name whose resolution never answers.
    h.set(
        stream(),
        vec![(backend("b1", "never.example.com:5432"), false)],
    );
    let mut client = h.connect().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.drain_now();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConfigRemoved);
    assert_eq!(record.backend_id, None);
    assert!(read_to_end(&mut client).await.is_empty());

    // Phase 4: an established echo.
    h.set(stream(), vec![(backend("b1", addr), false)]);
    let mut client = h.connect().await;
    echo_once(&mut client, b"live").await;
    h.drain_now();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConfigRemoved);
    assert_eq!(record.backend_id.as_deref(), Some("b1"));
    assert!(read_to_end(&mut client).await.is_empty());
    assert_eq!(ended(&h.stats(), StreamEndKind::ConfigRemoved), 3);
}
