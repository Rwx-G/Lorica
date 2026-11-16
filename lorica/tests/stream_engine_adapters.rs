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

//! The binary's stream-engine seams (Story 12.3 Lot D2) on their own
//! and inside a real TCP engine and stream runtime, on Linux sockets:
//!
//! - the selector keeps per-stream round-robin state and counts what
//!   the engine reports connected and closed;
//! - the hickory adapter returns the record TTL of an in-test DNS
//!   responder;
//! - IV4 at this level: a hostname resolving to `127.0.0.1` on a stream
//!   without `allow_local_backend` is never connected, and a backend on
//!   the node's management port is never connected even with the flag;
//! - IV2's stream half: a backend going down leaves selection while a
//!   connection established to it stays open. The HTTP half (a route
//!   skips a `Down` backend) is `upstream_peer`'s eligibility filter,
//!   unchanged by this story; Lot G runs both halves on one backend.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
    ResolverOpts,
};
use lorica::proxy_wiring::BreakerEngine;
use lorica::stream_engine::{HickoryResolve, StreamBreakerGate, StreamSelector};
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, LoadBalancing, Stream, StreamBackend,
    StreamEndReason, StreamProtocol, StreamRefusal,
};
use lorica_stream::{
    BackendSelector, Candidate, ConnectionObserver, ConnectionRecord, ControlTransport, Engines,
    InProcessPeer, NodeCapsRegions, Resolve, ResolverCache, SelectionRequest, SourceGate,
    StreamCounters, StreamRuntime, StreamRuntimeHandle, StreamTable, StreamTableSource, TcpEngine,
    TcpEngineParts,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_tcp_stream_listener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const WAIT: Duration = Duration::from_secs(10);
const STREAM_ID: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
/// The name the in-test DNS responder answers.
const TEST_HOST: &str = "db.stream-engine.test";
/// The TTL it answers with.
const TEST_TTL_S: u32 = 42;

fn stream(id: &str, load_balancing: LoadBalancing) -> Stream {
    let mut s = Stream::new(
        id.into(),
        id.into(),
        StreamProtocol::Tcp,
        "127.0.0.1".parse().unwrap(),
        1,
        1,
        Utc::now(),
    );
    s.load_balancing = load_balancing;
    s.connect_timeout_ms = 2_000;
    s
}

fn backend(id: &str, address: impl ToString, health_status: HealthStatus) -> Backend {
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: id.into(),
        group_name: String::new(),
        weight: 1,
        health_status,
        health_check_enabled: false,
        health_check_interval_s: 10,
        health_check_path: None,
        health_check: HealthCheck::TcpConnect,
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

fn candidates(backends: &[Backend]) -> Vec<Candidate<'_>> {
    backends
        .iter()
        .map(|b| Candidate {
            backend: b,
            ring_address: b.address.parse().unwrap(),
        })
        .collect()
}

fn select(selector: &StreamSelector, s: &Stream, cands: &[Candidate<'_>]) -> usize {
    selector.select(&SelectionRequest {
        stream: s,
        candidates: cands,
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        accepted_at: Instant::now(),
    })
}

#[test]
fn round_robin_state_is_per_stream_and_pruned_with_the_stream() {
    let selector = StreamSelector::new(0);
    let backends = [
        backend("a", "192.0.2.1:5432", HealthStatus::Healthy),
        backend("b", "192.0.2.2:5432", HealthStatus::Healthy),
    ];
    let cands = candidates(&backends);
    let one = stream("one", LoadBalancing::RoundRobin);
    let two = stream("two", LoadBalancing::RoundRobin);

    let first_of_one = select(&selector, &one, &cands);
    let second_of_one = select(&selector, &one, &cands);
    assert_ne!(first_of_one, second_of_one, "round robin alternates");
    assert_eq!(
        select(&selector, &two, &cands),
        first_of_one,
        "another stream starts its own rotation"
    );

    let links = [StreamBackend {
        stream_id: "two".into(),
        backend_id: "a".into(),
        backup: false,
        rule: None,
        max_active: None,
    }];
    selector.table_changed(&StreamTable::with_backends(
        vec![two.clone()],
        &links,
        backends.to_vec(),
    ));
    assert!(!selector.holds_round_robin("one"));
    assert!(selector.holds_round_robin("two"));
}

#[test]
fn least_conn_counts_what_the_engine_reports_and_ewma_learns_connect_latency() {
    let selector = StreamSelector::new(0);
    let backends = [
        backend("a", "192.0.2.1:5432", HealthStatus::Healthy),
        backend("b", "192.0.2.2:5432", HealthStatus::Healthy),
    ];
    let cands = candidates(&backends);
    let s = stream(STREAM_ID, LoadBalancing::LeastConn);
    let address: SocketAddr = backends[0].address.parse().unwrap();

    selector.connected(STREAM_ID, &backends[0], address, Duration::from_millis(3));
    assert_eq!(selector.open_connections(&backends[0]), 1);
    assert_eq!(
        select(&selector, &s, &cands),
        1,
        "the backend with none open"
    );
    assert_eq!(selector.latency_score(&backends[0]), Some(3_000.0));
    assert_eq!(selector.latency_score(&backends[1]), None);

    selector.closed(STREAM_ID, &backends[0], address);
    assert_eq!(selector.open_connections(&backends[0]), 0);
    assert_eq!(select(&selector, &s, &cands), 0, "a tie goes to the first");
}

#[test]
fn consistent_hash_keeps_a_client_on_one_backend() {
    let selector = StreamSelector::new(0);
    let backends: Vec<Backend> = (1..=5)
        .map(|i| {
            backend(
                &format!("b{i}"),
                format!("192.0.2.{i}:5432"),
                HealthStatus::Healthy,
            )
        })
        .collect();
    let cands = candidates(&backends);
    let s = stream(STREAM_ID, LoadBalancing::ConsistentHash);
    let first = select(&selector, &s, &cands);
    for _ in 0..20 {
        assert_eq!(select(&selector, &s, &cands), first);
    }
}

/// The question section of `query` and its type, or `None` for a
/// message that is not one question.
fn question(query: &[u8]) -> Option<(&[u8], u16)> {
    let mut at = 12;
    loop {
        let len = usize::from(*query.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        at += len;
    }
    let end = at + 4;
    let qtype = u16::from_be_bytes([*query.get(at)?, *query.get(at + 1)?]);
    Some((query.get(12..end)?, qtype))
}

/// A DNS server on loopback answering every A question with `ip` and
/// [`TEST_TTL_S`], and every other question with no record.
async fn dns_responder(ip: Ipv4Addr) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let query = &buf[..n];
            let Some((question, qtype)) = question(query) else {
                continue;
            };
            let is_a = qtype == 1;
            let mut answer = Vec::with_capacity(64);
            answer.extend_from_slice(&query[..2]);
            // QR, the query's opcode and RD, AA; RA, NOERROR.
            answer.push(0x80 | (query[2] & 0x79) | 0x04);
            answer.push(0x80);
            answer.extend_from_slice(&[0, 1, 0, u8::from(is_a), 0, 0, 0, 0]);
            answer.extend_from_slice(question);
            if is_a {
                answer.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
                answer.extend_from_slice(&TEST_TTL_S.to_be_bytes());
                answer.extend_from_slice(&[0, 4]);
                answer.extend_from_slice(&ip.octets());
            }
            let _ = socket.send_to(&answer, from).await;
        }
    });
    addr
}

fn resolver_for(server: SocketAddr) -> HickoryResolve {
    let mut connection = ConnectionConfig::udp();
    connection.port = server.port();
    let config = ResolverConfig::from_name_servers(vec![NameServerConfig::new(
        server.ip(),
        true,
        vec![connection],
    )]);
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    HickoryResolve::with_config(config, opts)
}

#[tokio::test]
async fn the_hickory_adapter_returns_the_record_ttl() {
    let server = dns_responder(Ipv4Addr::new(192, 0, 2, 44)).await;
    let resolver = resolver_for(server);

    let resolved = resolver
        .lookup(TEST_HOST)
        .await
        .expect("the responder answers");

    assert_eq!(
        resolved.addresses,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44))]
    );
    let ttl = Duration::from_secs(u64::from(TEST_TTL_S));
    assert!(
        resolved.ttl <= ttl && resolved.ttl > ttl - Duration::from_secs(2),
        "{:?}",
        resolved.ttl
    );
}

#[tokio::test]
async fn a_name_no_server_answers_is_a_resolve_error() {
    // A port nothing listens on: the lookup times out or is refused.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = silent.local_addr().unwrap();
    drop(silent);
    let resolver = resolver_for(addr);
    assert!(resolver.lookup(TEST_HOST).await.is_err());
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

/// An echo server counting the connections it accepted.
async fn counting_echo() -> (SocketAddr, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicU64::new(0));
    let count = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
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
    (addr, accepted)
}

/// No node-wide source control: these tests exercise selection, the
/// breaker and resolution.
struct Ungated;

impl SourceGate for Ungated {
    fn global(&self, _: IpAddr) -> Option<StreamRefusal> {
        None
    }

    fn country(&self, _: IpAddr) -> Option<[u8; 2]> {
        None
    }
}

/// A real TCP engine over the binary's seams, in a stream runtime fed
/// from `source`.
struct Harness {
    peer: InProcessPeer,
    /// The streams' caps regions, as the supervisor holds them.
    node: NodeCapsRegions,
    runtime: Option<StreamRuntimeHandle>,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    seq: u64,
    _listeners: Vec<OwnedFd>,
}

impl Harness {
    fn start(
        source: &Arc<Source>,
        resolver: Arc<dyn Resolve>,
        reserved_ports: Option<ReservedPorts>,
    ) -> Self {
        let counters = Arc::new(StreamCounters::new());
        let (tx, records) = mpsc::unbounded_channel();
        let engine = TcpEngine::new(TcpEngineParts {
            selector: Arc::new(StreamSelector::new(0)),
            breaker: Arc::new(StreamBreakerGate::with_engine(BreakerEngine::local(5, 10))),
            resolver: ResolverCache::new(resolver, Arc::clone(&counters)),
            counters: Arc::clone(&counters),
            observer: Arc::new(Records(tx)),
            reserved_ports,
            source_gate: Arc::new(Ungated),
        });
        let (peer, transport) = ControlTransport::in_process_pair(8);
        let runtime = StreamRuntime::spawn(
            transport,
            Engines {
                tcp: Some(Arc::new(engine)),
                counters,
                ..Engines::default()
            },
            Arc::clone(source) as Arc<dyn StreamTableSource>,
        )
        .unwrap();
        Harness {
            peer,
            node: NodeCapsRegions::new(1),
            runtime: Some(runtime),
            records,
            seq: 0,
            _listeners: Vec::new(),
        }
    }

    async fn answer(&mut self) -> StreamCtlMsg {
        tokio::time::timeout(WAIT, self.peer.from_runtime.recv())
            .await
            .expect("the runtime answers")
            .expect("the runtime is alive")
    }

    /// Hand `stream_id` its caps region, then attach a fresh listener to
    /// it, as the supervisor does (Story 12.6 D-e); returns its address.
    async fn attach(&mut self, stream_id: &str) -> SocketAddr {
        self.node
            .ensure(stream_id, u64::from(Stream::DEFAULT_MAX_CONNECTIONS), 0)
            .unwrap();
        self.seq += 1;
        let caps = self
            .node
            .caps_message(stream_id, self.seq, 0)
            .unwrap()
            .expect("a region");
        self.peer.to_runtime.send(caps).await.unwrap();
        assert!(matches!(
            self.answer().await,
            StreamCtlMsg::Ack { count: 1, .. }
        ));
        let fd = bind_tcp_stream_listener("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = std::net::TcpListener::from(fd.try_clone().unwrap())
            .local_addr()
            .unwrap();
        self.seq += 1;
        self.peer
            .to_runtime
            .send(StreamCtlMsg::Attach {
                seq: self.seq,
                stream_id: stream_id.into(),
                bind_gen: self.seq,
                sockets: vec![StreamSocket {
                    proto: StreamProto::Tcp,
                    addr,
                    fd: fd.try_clone().unwrap(),
                }],
            })
            .await
            .unwrap();
        assert!(matches!(
            self.answer().await,
            StreamCtlMsg::Ack { count: 1, .. }
        ));
        self._listeners.push(fd);
        addr
    }

    async fn refresh(&mut self) {
        self.seq += 1;
        let seq = self.seq;
        self.peer
            .to_runtime
            .send(StreamCtlMsg::Refresh {
                seq,
                drain_ms: 60_000,
            })
            .await
            .unwrap();
        assert!(matches!(self.answer().await, StreamCtlMsg::Ack { seq: s, .. } if s == seq));
    }

    async fn record(&mut self) -> ConnectionRecord {
        tokio::time::timeout(WAIT, self.records.recv())
            .await
            .expect("the connection ends in time")
            .expect("the engine is alive")
    }

    fn stop(mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop();
        }
    }
}

fn one_link(s: &Stream, b: &Backend) -> StreamTable {
    let links = [StreamBackend {
        stream_id: s.id.clone(),
        backend_id: b.id.clone(),
        backup: false,
        rule: None,
        max_active: None,
    }];
    StreamTable::with_backends(vec![s.clone()], &links, vec![b.clone()])
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

/// The client side closed by the engine: EOF or a reset, in time.
async fn closed_by_lorica(client: &mut TcpStream) {
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(WAIT, client.read(&mut buf))
        .await
        .expect("closed in time");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iv4_a_name_resolving_to_loopback_is_never_connected() {
    let (echo, accepted) = counting_echo().await;
    let dns = dns_responder(Ipv4Addr::LOCALHOST).await;
    let s = stream(STREAM_ID, LoadBalancing::RoundRobin);
    let b = backend(
        "named",
        format!("{TEST_HOST}:{}", echo.port()),
        HealthStatus::Healthy,
    );
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = one_link(&s, &b);
    let mut h = Harness::start(&source, Arc::new(resolver_for(dns)), None);
    let listen = h.attach(STREAM_ID).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    closed_by_lorica(&mut client).await;
    let record = h.record().await;

    assert_eq!(record.end_reason, StreamEndReason::NoHealthyBackend);
    assert_eq!(record.attempts, 0);
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "nothing connected to the loopback address the name resolved to"
    );
    h.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iv4_a_backend_on_the_management_port_is_never_connected_even_with_the_flag() {
    let (echo, accepted) = counting_echo().await;
    let mut s = stream(STREAM_ID, LoadBalancing::RoundRobin);
    s.allow_local_backend = true;
    let b = backend("local", echo, HealthStatus::Healthy);
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = one_link(&s, &b);
    let reserved = ReservedPorts {
        management: echo.port(),
        http: 1,
        https: 2,
        cluster: None,
        enrollment: None,
        automation: None,
    };
    let mut h = Harness::start(
        &source,
        Arc::new(resolver_for("127.0.0.1:9".parse().unwrap())),
        Some(reserved),
    );
    let listen = h.attach(STREAM_ID).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    closed_by_lorica(&mut client).await;
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::NoHealthyBackend
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    h.stop();

    // The control: the same local backend on a port that is no node
    // port is connected, the flag allowing it.
    let mut h = Harness::start(
        &source,
        Arc::new(resolver_for("127.0.0.1:9".parse().unwrap())),
        Some(ReservedPorts {
            management: 3,
            ..reserved
        }),
    );
    let listen = h.attach(STREAM_ID).await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    echo_once(&mut client, b"allowed").await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    drop(client);
    h.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iv2_a_backend_marked_down_leaves_selection_and_keeps_its_connection() {
    let (echo, accepted) = counting_echo().await;
    let mut s = stream(STREAM_ID, LoadBalancing::RoundRobin);
    s.allow_local_backend = true;
    let up = backend("shared", echo, HealthStatus::Healthy);
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = one_link(&s, &up);
    let mut h = Harness::start(
        &source,
        Arc::new(resolver_for("127.0.0.1:9".parse().unwrap())),
        None,
    );
    let listen = h.attach(STREAM_ID).await;
    let mut established = TcpStream::connect(listen).await.unwrap();
    echo_once(&mut established, b"before").await;

    let mut down = up.clone();
    down.health_status = HealthStatus::Down;
    *source.0.lock().unwrap() = one_link(&s, &down);
    h.refresh().await;

    let mut late = TcpStream::connect(listen).await.unwrap();
    closed_by_lorica(&mut late).await;
    assert_eq!(
        h.record().await.end_reason,
        StreamEndReason::NoHealthyBackend
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "no new connection reached it"
    );

    echo_once(&mut established, b"still open").await;
    drop(established);
    h.stop();
}
