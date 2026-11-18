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

//! The UDP engine (Story 12.5 Lot E) against real loopback sockets
//! (Linux), served by a stream runtime over the in-process transport:
//! the stream-caps region arrives by a `caps` message and the slot
//! socket by an `attach`, as Lot F will send them. The seams are fakes:
//! the selector picks the first candidate, the fewest sessions or a hash
//! of the client; the breaker admits unless told to deny or to hang; no
//! name is ever resolved (every backend is an IP literal); the source
//! gate refuses the addresses it is given and places the ones it has a
//! country for. Clients send from `127.0.0.N` where a test needs several
//! sources.

#![cfg(target_os = "linux")]

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Backend, DatagramDropReason, GeoIpConfig, GeoIpMode, HealthCheck, HealthStatus, LifecycleState,
    Stream, StreamBackend, StreamEndKind, StreamEndReason, StreamProtocol, StreamProxyProtocol,
    StreamRefusal, UdpSettings,
};
use lorica_core::protocols::proxy_protocol::V2_SIGNATURE;
use lorica_shmem::{RateLimits, SourceKey, StreamCapsRegion};
use lorica_stream::counters::{ConnectFailureKind, LinkCountersSnapshot, StreamCountersSnapshot};
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    Admission, BackendSelector, BreakerGate, ConnectOutcome, ConnectionObserver, ConnectionRecord,
    ConnectionTracker, ControlTransport, Engines, InProcessPeer, NodeCapsRegions, RefusalRecord,
    Resolve, ResolveError, Resolved, ResolverCache, SelectionRequest, SourceGate, StreamCounters,
    StreamRuntime, StreamRuntimeHandle, StreamTable, StreamTableSource, UdpEngine, UdpEngineParts,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_udp_group;
use socket2::SockRef;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::Instant;

// A UDP socket with `SO_REUSEPORT` bound to port 0 may be handed a port
// another `SO_REUSEPORT` socket of the same user already holds: the
// kernel then joins the two in one group and splits the datagrams
// between them, so a test's slot shares its traffic with another test's,
// in this binary or in another process. And a port released goes back
// to the ephemeral pool while datagrams may still be on their way to it
// (the ICMP tests send to a closed port on purpose; a late answer
// reaches an ended session's port): whatever autobinds it next receives
// them. Every socket a test reads from here (slot, backend, client)
// binds a port of the shared reservation scheme instead, below the
// ephemeral range and locked across processes, which no autobind ever
// reaches and nobody else is handed.
#[path = "../../lorica/tests/common/mod.rs"]
mod common;

use common::reserve_port;

/// How long an expected event may take before the test calls it lost. It
/// bounds a hang, never a duration: a loaded host delays every event,
/// and no assertion here may depend on how much.
const WAIT: Duration = Duration::from_secs(60);
const QUIET: Duration = Duration::from_millis(300);

// ---- fake seams ------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    First,
    FewestSessions,
    ClientHash,
}

struct Selector {
    pick: Pick,
    clients: Mutex<Vec<IpAddr>>,
    sessions: Mutex<HashMap<String, i64>>,
    connected: Mutex<Vec<String>>,
    closed: Mutex<Vec<String>>,
}

impl Selector {
    fn new(pick: Pick) -> Self {
        Selector {
            pick,
            clients: Mutex::default(),
            sessions: Mutex::default(),
            connected: Mutex::default(),
            closed: Mutex::default(),
        }
    }
}

impl BackendSelector for Selector {
    fn select(&self, request: &SelectionRequest<'_>) -> usize {
        self.clients.lock().unwrap().push(request.client);
        match self.pick {
            Pick::First => 0,
            Pick::FewestSessions => {
                let sessions = self.sessions.lock().unwrap();
                (0..request.candidates.len())
                    .min_by_key(|&i| {
                        sessions
                            .get(&request.candidates[i].backend.id)
                            .copied()
                            .unwrap_or(0)
                    })
                    .unwrap()
            }
            Pick::ClientHash => {
                let mut hasher = DefaultHasher::new();
                request.client.to_string().hash(&mut hasher);
                (hasher.finish() % request.candidates.len() as u64) as usize
            }
        }
    }

    fn connected(&self, _stream_id: &str, backend: &Backend, _: SocketAddr, _: Duration) {
        *self
            .sessions
            .lock()
            .unwrap()
            .entry(backend.id.clone())
            .or_default() += 1;
        self.connected.lock().unwrap().push(backend.id.clone());
    }

    fn closed(&self, _stream_id: &str, backend: &Backend, _: SocketAddr) {
        *self
            .sessions
            .lock()
            .unwrap()
            .entry(backend.id.clone())
            .or_default() -= 1;
        self.closed.lock().unwrap().push(backend.id.clone());
    }
}

#[derive(Default)]
struct Breaker {
    deny: HashSet<String>,
    hang: HashSet<String>,
    records: Mutex<Vec<(String, bool, bool)>>,
}

impl BreakerGate for Breaker {
    fn admit<'a>(&'a self, _stream_id: &'a str, backend: &'a Backend) -> SeamFuture<'a, Admission> {
        let (denied, hangs) = (
            self.deny.contains(&backend.id),
            self.hang.contains(&backend.id),
        );
        Box::pin(async move {
            if hangs {
                std::future::pending::<()>().await;
            }
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

/// Every backend of these tests is an IP literal: a lookup is a bug.
struct NoDns;

impl Resolve for NoDns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        Box::pin(async move { Err(ResolveError(format!("unexpected lookup of {host}"))) })
    }
}

struct Records {
    ended: mpsc::UnboundedSender<ConnectionRecord>,
    refused: mpsc::UnboundedSender<RefusalRecord>,
    outcomes: Arc<Mutex<Vec<(String, StreamProtocol, ConnectOutcome)>>>,
    /// The runtime's tracker, known once the runtime is spawned.
    tracker: Arc<std::sync::OnceLock<ConnectionTracker>>,
    /// The entries the tracker held when each record arrived.
    tracked_at_report: Arc<Mutex<Vec<usize>>>,
}

impl ConnectionObserver for Records {
    fn observe(&self, record: ConnectionRecord) {
        if let Some(tracker) = self.tracker.get() {
            self.tracked_at_report.lock().unwrap().push(tracker.len());
        }
        let _ = self.ended.send(record);
    }

    fn connect_outcome(&self, stream_id: &str, protocol: StreamProtocol, outcome: ConnectOutcome) {
        self.outcomes
            .lock()
            .unwrap()
            .push((stream_id.to_string(), protocol, outcome));
    }

    fn refused(&self, record: RefusalRecord) {
        let _ = self.refused.send(record);
    }
}

/// Refuses the addresses it holds; knows the countries it is told.
#[derive(Default)]
struct Gate {
    filtered: Mutex<HashSet<IpAddr>>,
    blocked: Mutex<HashSet<IpAddr>>,
    countries: Mutex<HashMap<IpAddr, [u8; 2]>>,
}

impl SourceGate for Gate {
    fn global(&self, client: IpAddr) -> Option<StreamRefusal> {
        if self.filtered.lock().unwrap().contains(&client) {
            Some(StreamRefusal::ConnectionFilter)
        } else if self.blocked.lock().unwrap().contains(&client) {
            Some(StreamRefusal::IpBlocklist)
        } else {
            None
        }
    }

    fn country(&self, client: IpAddr) -> Option<[u8; 2]> {
        self.countries.lock().unwrap().get(&client).copied()
    }
}

struct FixedTable(StreamTable);

impl StreamTableSource for FixedTable {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.clone())
    }
}

// ---- fixtures --------------------------------------------------------

/// A UDP stream on `listen` with local backends allowed (every backend
/// here is on loopback).
fn udp_stream(id: &str, listen: &str) -> Stream {
    let mut s = Stream::new(
        id.into(),
        id.into(),
        StreamProtocol::Udp,
        listen.parse().unwrap(),
        1,
        1,
        Utc::now(),
    );
    s.allow_local_backend = true;
    s
}

fn udp(stream: &mut Stream) -> &mut UdpSettings {
    stream
        .udp
        .as_mut()
        .expect("a UDP stream carries its settings")
}

fn backend(id: &str, address: SocketAddr) -> Backend {
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

type Seen = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

/// A UDP backend on loopback recording what it receives (from which
/// upstream port) and answering each datagram with what `answer` gives.
struct UdpBackend {
    addr: SocketAddr,
    seen: Seen,
}

/// A UDP socket on `ip`, on a reserved port.
async fn reserved_socket(ip: IpAddr) -> UdpSocket {
    UdpSocket::bind(SocketAddr::new(ip, reserve_port()))
        .await
        .unwrap()
}

impl UdpBackend {
    async fn spawn(answer: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> Self {
        let socket = reserved_socket(loopback(1)).await;
        let addr = socket.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 70_000];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                log.lock().unwrap().push((peer, buf[..n].to_vec()));
                for reply in answer(&buf[..n]) {
                    let _ = socket.send_to(&reply, peer).await;
                }
            }
        });
        UdpBackend { addr, seen }
    }

    async fn echo() -> Self {
        Self::spawn(|p| vec![p.to_vec()]).await
    }

    async fn sink() -> Self {
        Self::spawn(|_| Vec::new()).await
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, d)| d.clone())
            .collect()
    }

    fn peers(&self) -> HashSet<SocketAddr> {
        self.seen.lock().unwrap().iter().map(|(p, _)| *p).collect()
    }
}

/// A loopback UDP port nothing listens on: a datagram to it draws an
/// ICMP port unreachable. Reserved, so nothing binds it later either: a
/// port bound and released at once goes back to the ephemeral pool, and
/// a socket another test bound there would take the datagram instead.
fn closed_port() -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse().unwrap(), reserve_port())
}

struct Harness {
    peer: InProcessPeer,
    handle: StreamRuntimeHandle,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    refusals: mpsc::UnboundedReceiver<RefusalRecord>,
    outcomes: Arc<Mutex<Vec<(String, StreamProtocol, ConnectOutcome)>>>,
    selector: Arc<Selector>,
    breaker: Arc<Breaker>,
    gate: Arc<Gate>,
    node: NodeCapsRegions,
    listens: Vec<SocketAddr>,
    seq: u64,
    /// The tracker's entry count at each record the observer took.
    tracked_at_report: Arc<Mutex<Vec<usize>>>,
}

impl Harness {
    async fn one(stream: Stream, backends: Vec<Backend>) -> Self {
        Self::start(vec![(stream, backends)], Pick::First, Breaker::default()).await
    }

    /// A runtime serving `streams`, each with its region and one slot
    /// socket on its listen address (port chosen by the kernel).
    async fn start(streams: Vec<(Stream, Vec<Backend>)>, pick: Pick, breaker: Breaker) -> Self {
        Self::start_capped(streams, pick, breaker, &[], &[]).await
    }

    /// [`Harness::start`] with the links of `capped` backend ids at the
    /// given `max_active`, and no region sent for the streams of
    /// `without_region`.
    async fn start_capped(
        streams: Vec<(Stream, Vec<Backend>)>,
        pick: Pick,
        breaker: Breaker,
        capped: &[(&str, u32)],
        without_region: &[&str],
    ) -> Self {
        let counters = Arc::new(StreamCounters::new());
        let selector = Arc::new(Selector::new(pick));
        let breaker = Arc::new(breaker);
        let gate = Arc::new(Gate::default());
        let (ended, records) = mpsc::unbounded_channel();
        let (refused, refusals) = mpsc::unbounded_channel();
        let outcomes = Arc::default();
        let tracker: Arc<std::sync::OnceLock<ConnectionTracker>> = Arc::default();
        let tracked_at_report = Arc::default();
        let engine = UdpEngine::new(UdpEngineParts {
            selector: Arc::clone(&selector) as Arc<dyn BackendSelector>,
            breaker: Arc::clone(&breaker) as Arc<dyn BreakerGate>,
            resolver: ResolverCache::new(Arc::new(NoDns), Arc::clone(&counters)),
            counters: Arc::clone(&counters),
            observer: Arc::new(Records {
                ended,
                refused,
                outcomes: Arc::clone(&outcomes),
                tracker: Arc::clone(&tracker),
                tracked_at_report: Arc::clone(&tracked_at_report),
            }),
            reserved_ports: None,
            source_gate: Arc::clone(&gate) as Arc<dyn SourceGate>,
        });
        let mut links = Vec::new();
        let mut rows = Vec::new();
        for (stream, backends) in &streams {
            for b in backends {
                let mut link = StreamBackend::primary(&stream.id, &b.id);
                link.max_active = capped
                    .iter()
                    .find(|(id, _)| *id == b.id)
                    .map(|(_, cap)| *cap);
                links.push(link);
                rows.push(b.clone());
            }
        }
        let table = StreamTable::with_backends(
            streams.iter().map(|(s, _)| s.clone()).collect(),
            &links,
            rows,
        );
        let (peer, transport) = ControlTransport::in_process_pair(8);
        let handle = StreamRuntime::spawn(
            transport,
            Engines {
                tcp: None,
                udp: Some(Arc::new(engine)),
                counters,
            },
            Arc::new(FixedTable(table)),
        )
        .unwrap();
        let _ = tracker.set(handle.tracker().clone());
        let mut harness = Harness {
            peer,
            handle,
            records,
            refusals,
            outcomes,
            selector,
            breaker,
            gate,
            node: NodeCapsRegions::new(1),
            listens: Vec::new(),
            seq: 0,
            tracked_at_report,
        };
        for (n, (stream, _)) in streams.iter().enumerate() {
            if !without_region.contains(&stream.id.as_str()) {
                let max_sessions = u64::from(stream.udp.as_ref().unwrap().max_sessions);
                harness.node.ensure(&stream.id, max_sessions, 0).unwrap();
                let seq = harness.next_seq();
                let caps = harness
                    .node
                    .caps_message(&stream.id, seq, 0)
                    .unwrap()
                    .expect("a region");
                harness.exchange(caps).await;
            }
            let fd = bind_udp_group(SocketAddr::new(stream.listen_address, reserve_port()), 1)
                .unwrap()
                .remove(0);
            let addr = SockRef::from(&fd)
                .local_addr()
                .unwrap()
                .as_socket()
                .unwrap();
            let seq = harness.next_seq();
            harness
                .exchange(StreamCtlMsg::Attach {
                    seq,
                    stream_id: stream.id.clone(),
                    bind_gen: n as u64 + 1,
                    sockets: vec![StreamSocket {
                        proto: StreamProto::Udp,
                        addr,
                        fd,
                    }],
                })
                .await;
            harness.listens.push(addr);
        }
        harness
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    /// Send `msg` and expect an `ack`.
    async fn exchange(&mut self, msg: StreamCtlMsg) {
        self.peer.to_runtime.send(msg).await.unwrap();
        let answer = tokio::time::timeout(WAIT, self.peer.from_runtime.recv())
            .await
            .expect("the runtime answers")
            .expect("the runtime is alive");
        assert!(
            matches!(answer, StreamCtlMsg::Ack { .. }),
            "refused: {answer:?}"
        );
    }

    /// The first stream's listen address, as a client sends to it.
    fn listen(&self) -> SocketAddr {
        self.listens[0]
    }

    async fn record(&mut self) -> ConnectionRecord {
        tokio::time::timeout(WAIT, self.records.recv())
            .await
            .expect("a session record in time")
            .expect("the engine is alive")
    }

    /// The next refusal row the refusal log admitted.
    async fn refusal(&mut self) -> RefusalRecord {
        tokio::time::timeout(WAIT, self.refusals.recv())
            .await
            .expect("a refusal row in time")
            .expect("the engine is alive")
    }

    fn stats(&self, stream_id: &str) -> StreamCountersSnapshot {
        self.handle
            .counters()
            .streams
            .get(stream_id)
            .cloned()
            .unwrap_or_default()
    }

    fn link(&self, stream_id: &str, backend_id: &str) -> LinkCountersSnapshot {
        self.handle
            .counters()
            .links
            .get(&(stream_id.to_string(), backend_id.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// The connect outcomes `stream_id` reported so far, each a UDP one.
    fn outcomes(&self, stream_id: &str) -> Vec<ConnectOutcome> {
        self.outcomes
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _, _)| id == stream_id)
            .map(|(_, protocol, outcome)| {
                assert_eq!(*protocol, StreamProtocol::Udp);
                *outcome
            })
            .collect()
    }

    fn breaker_records(&self) -> Vec<(String, bool, bool)> {
        self.breaker.records.lock().unwrap().clone()
    }

    fn stop(self) {
        self.handle.stop();
    }
}

fn dropped(stats: &StreamCountersSnapshot, reason: DatagramDropReason) -> u64 {
    stats.dropped.get(&reason).copied().unwrap_or(0)
}

async fn client() -> UdpSocket {
    reserved_socket(loopback(1)).await
}

async fn reply(client: &UdpSocket) -> Vec<u8> {
    let mut buf = vec![0u8; 70_000];
    let (n, _) = tokio::time::timeout(WAIT, client.recv_from(&mut buf))
        .await
        .expect("a reply in time")
        .unwrap();
    buf.truncate(n);
    buf
}

async fn assert_silent(client: &UdpSocket) {
    let mut buf = [0u8; 2048];
    assert!(
        tokio::time::timeout(QUIET, client.recv_from(&mut buf))
            .await
            .is_err(),
        "nothing reaches the client"
    );
}

async fn wait_until(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !cond() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---- the session lifecycle of D-b -------------------------------------

#[tokio::test]
async fn a_query_closes_on_its_answer_and_its_record_counts_datagrams() {
    let b1 = UdpBackend::echo().await;
    let mut h = Harness::one(udp_stream("dns", "127.0.0.1"), vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    c.send_to(b"query", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"query");

    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ResponseBoundReached);
    assert_eq!(record.datagrams_upload, Some(1));
    assert_eq!(record.datagrams_download, Some(1));
    assert_eq!((record.bytes_upload, record.bytes_download), (5, 5));
    assert_eq!(record.proxied_from, None);
    assert_eq!(record.client, c.local_addr().unwrap());
    assert_eq!(record.peer, record.client);
    assert_eq!(record.local, h.listen());
    assert_eq!(record.backend_id.as_deref(), Some("b1"));
    assert_eq!(record.backend_address, Some(b1.addr));
    assert_eq!(record.attempts, 1);
    assert!(record.connected_at.is_some());
    assert_eq!(record.protocol, StreamProtocol::Udp);
    assert_eq!(record.detected_protocol, None);
    assert_eq!(h.breaker_records(), vec![("b1".to_string(), true, false)]);
    assert_eq!(h.outcomes("dns"), vec![ConnectOutcome::Answered]);

    let stats = h.stats("dns");
    assert_eq!((stats.accepted, stats.active), (1, 0));
    assert_eq!(stats.ended[&StreamEndKind::ResponseBoundReached], 1);
    assert_eq!((stats.datagrams_upload, stats.datagrams_download), (1, 1));
    let link = h.link("dns", "b1");
    assert_eq!((link.connects, link.active), (1, 0));
    assert_eq!(
        (link.bytes_upload, link.bytes_download),
        (stats.bytes_upload, stats.bytes_download),
        "the one backend carried every byte"
    );
    assert_eq!((link.bytes_upload, link.bytes_download), (5, 5));
    assert_eq!(*h.selector.connected.lock().unwrap(), vec!["b1"]);
    assert_eq!(*h.selector.closed.lock().unwrap(), vec!["b1"]);

    // The next query from the same port opens a new session.
    c.send_to(b"again", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"again");
    h.record().await;
    assert_eq!(h.stats("dns").accepted, 2);
    h.stop();
}

/// Story 12.9 D-k: a session's record reaches the observer while the
/// session is still in the tracker, so a drain waiting for an empty
/// tracker cannot stop with the row in flight. Read at the moment of the
/// report: with the entry gone first it reads 0, whatever the timing.
#[tokio::test]
async fn a_session_record_reaches_the_observer_before_its_entry_leaves_the_tracker() {
    let b1 = UdpBackend::echo().await;
    let mut h = Harness::one(udp_stream("dns", "127.0.0.1"), vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    c.send_to(b"query", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"query");
    h.record().await;
    assert_eq!(*h.tracked_at_report.lock().unwrap(), vec![1]);
}

#[tokio::test]
async fn the_request_bound_retires_a_session_and_a_pipelined_client_opens_a_second() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    udp(&mut stream).requests_per_session = Some(2);
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    for q in [b"q1", b"q2", b"q3"] {
        c.send_to(q, h.listen()).await.unwrap();
    }
    let mut answers = vec![reply(&c).await, reply(&c).await, reply(&c).await];
    answers.sort();
    assert_eq!(
        answers,
        vec![b"q1".to_vec(), b"q2".to_vec(), b"q3".to_vec()]
    );

    let mut records = [h.record().await, h.record().await];
    records.sort_by_key(|r| r.datagrams_upload);
    assert_eq!(records[0].datagrams_upload, Some(1));
    assert_eq!(records[0].end_reason, StreamEndReason::ResponseBoundReached);
    assert_eq!(records[1].datagrams_upload, Some(2));
    assert_eq!(records[1].end_reason, StreamEndReason::RequestBoundReached);
    assert_eq!(h.stats("dns").accepted, 2);
    assert_eq!(b1.peers().len(), 2, "one upstream socket per session");
    h.stop();
}

#[tokio::test]
async fn without_expected_responses_a_session_ends_at_its_request_bound() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("syslog", "127.0.0.1");
    udp(&mut stream).responses_per_request = 0;
    udp(&mut stream).requests_per_session = Some(3);
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    for m in [b"m1", b"m2", b"m3"] {
        c.send_to(m, h.listen()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::RequestBoundReached);
    assert_eq!(record.datagrams_upload, Some(3));
    assert_eq!(record.datagrams_download, Some(0));
    // The record follows the third send; the backend's own task logs
    // the datagram when it gets to it.
    wait_until("the backend got all three", || b1.received().len() == 3).await;
    assert_silent(&c).await;
    assert!(
        dropped(&h.stats("syslog"), DatagramDropReason::ResponseCountBound) >= 1,
        "the echoes were dropped and counted"
    );
    h.stop();
}

#[tokio::test]
async fn a_response_over_the_byte_allowance_is_dropped_and_ends_the_session() {
    let b1 = UdpBackend::spawn(|p| vec![[p, p].concat()]).await;
    let mut stream = udp_stream("radius", "127.0.0.1");
    udp(&mut stream).response_bytes_ratio = 1;
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    c.send_to(&[7u8; 100], h.listen()).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ResponseBoundReached);
    assert_eq!(record.datagrams_download, Some(0));
    assert_silent(&c).await;
    assert_eq!(
        dropped(&h.stats("radius"), DatagramDropReason::ResponseByteBound),
        1
    );
    h.stop();
}

#[tokio::test]
async fn unbounded_responses_lift_both_bounds() {
    let b1 = UdpBackend::spawn(|p| vec![[p, p].concat(); 3]).await;
    let mut stream = udp_stream("game", "127.0.0.1");
    udp(&mut stream).response_bytes_ratio = 1;
    udp(&mut stream).unbounded_responses = true;
    let h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    c.send_to(b"move", h.listen()).await.unwrap();
    for _ in 0..3 {
        assert_eq!(reply(&c).await, b"movemove");
    }
    let stats = h.stats("game");
    assert!(stats.dropped.is_empty(), "{:?}", stats.dropped);
    assert_eq!(stats.active, 1, "the session stays open");
    h.stop();
}

#[tokio::test]
async fn a_silent_backend_ends_the_session_idle_and_reports_one_failure() {
    let b1 = UdpBackend::sink().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.idle_timeout_s = 1;
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    let started = Instant::now();
    c.send_to(b"query", h.listen()).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::IdleTimeout);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(h.breaker_records(), vec![("b1".to_string(), false, false)]);
    assert_eq!(h.outcomes("dns"), vec![ConnectOutcome::NoResponse]);
    assert_eq!(
        h.link("dns", "b1").connect_failures[&ConnectFailureKind::NoResponse],
        1
    );
    h.stop();
}

#[tokio::test]
async fn the_total_timeout_ends_a_session_that_never_idles() {
    let b1 = UdpBackend::sink().await;
    let mut stream = udp_stream("syslog", "127.0.0.1");
    udp(&mut stream).responses_per_request = 0;
    udp(&mut stream).requests_per_session = None;
    stream.total_timeout_s = Some(1);
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    let started = Instant::now();
    c.send_to(b"m", h.listen()).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::TotalTimeout);
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert!(
        h.breaker_records().is_empty(),
        "no response was expected, so silence is no failure"
    );
    assert!(
        h.outcomes("syslog").is_empty(),
        "judged at its end from the record, not at a connect"
    );
    assert!(h.records.try_recv().is_err(), "one record for the session");
    h.stop();
}

#[tokio::test]
async fn an_icmp_refusal_before_any_answer_fails_the_session() {
    let mut h = Harness::one(
        udp_stream("dns", "127.0.0.1"),
        vec![backend("b1", closed_port())],
    )
    .await;
    let c = client().await;
    c.send_to(b"query", h.listen()).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConnectFailed);
    assert_eq!(h.breaker_records(), vec![("b1".to_string(), false, false)]);
    assert_eq!(h.outcomes("dns"), vec![ConnectOutcome::IcmpError]);
    assert_eq!(
        h.link("dns", "b1").connect_failures[&ConnectFailureKind::Refused],
        1
    );
    h.stop();
}

#[tokio::test]
async fn an_icmp_refusal_after_an_answer_is_the_backends_close() {
    // Answers the first datagram, then closes its socket.
    let socket = reserved_socket(loopback(1)).await;
    let addr = socket.local_addr().unwrap();
    let answering = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        socket.send_to(&buf[..n], peer).await.unwrap();
    });
    let mut stream = udp_stream("dns", "127.0.0.1");
    udp(&mut stream).responses_per_request = 2;
    let mut h = Harness::one(stream, vec![backend("b1", addr)]).await;
    let c = client().await;
    c.send_to(b"q1", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"q1");
    // The backend's task has ended once joined, its socket dropped with
    // it; the port is reserved, so nothing binds it again.
    answering.await.unwrap();
    c.send_to(b"q2", h.listen()).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::BackendClose);
    assert_eq!(
        h.breaker_records(),
        vec![("b1".to_string(), true, false)],
        "one outcome per session: its first response"
    );
    h.stop();
}

// ---- size, PROXY v2, reply source --------------------------------------

#[tokio::test]
async fn oversize_datagrams_are_dropped_both_ways() {
    let b1 = UdpBackend::spawn(|_| vec![vec![1u8; 600]]).await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    udp(&mut stream).max_datagram_bytes = 512;
    stream.idle_timeout_s = 1;
    let h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    c.send_to(&[0u8; 600], h.listen()).await.unwrap();
    wait_until("the request drop", || {
        dropped(&h.stats("dns"), DatagramDropReason::RequestOversize) == 1
    })
    .await;
    assert_eq!(h.stats("dns").accepted, 0, "no session for it");

    c.send_to(&[0u8; 100], h.listen()).await.unwrap();
    wait_until("the response drop", || {
        dropped(&h.stats("dns"), DatagramDropReason::ResponseOversize) == 1
    })
    .await;
    assert_silent(&c).await;
    h.stop();
}

/// The v2 `DGRAM` header over `AF_INET` the backend must receive in front
/// of every payload.
fn v2_dgram_v4(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let (IpAddr::V4(from), IpAddr::V4(to)) = (source.ip(), destination.ip()) else {
        panic!("test setup: IPv4 addresses");
    };
    let mut header = V2_SIGNATURE.to_vec();
    header.extend_from_slice(&[0x21, 0x12, 0x00, 12]);
    header.extend_from_slice(&from.octets());
    header.extend_from_slice(&to.octets());
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

#[tokio::test]
async fn every_datagram_carries_the_exact_proxy_v2_header_up_to_the_udp_maximum() {
    let b1 = UdpBackend::sink().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.proxy_protocol_send = StreamProxyProtocol::V2;
    udp(&mut stream).max_datagram_bytes = 65_507;
    udp(&mut stream).source_byte_rate = 1_073_741_824;
    udp(&mut stream).responses_per_request = 0;
    udp(&mut stream).requests_per_session = None;
    let h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let c = client().await;
    let header = v2_dgram_v4(c.local_addr().unwrap(), h.listen());
    assert_eq!(header.len(), 28);

    c.send_to(b"one", h.listen()).await.unwrap();
    c.send_to(b"two", h.listen()).await.unwrap();
    wait_until("two datagrams", || b1.received().len() == 2).await;
    assert_eq!(
        b1.received(),
        vec![
            [&header[..], b"one"].concat(),
            [&header[..], b"two"].concat()
        ]
    );

    let largest = 65_507 - header.len();
    c.send_to(&vec![9u8; largest + 1], h.listen())
        .await
        .unwrap();
    c.send_to(&vec![9u8; largest], h.listen()).await.unwrap();
    wait_until("the largest datagram", || b1.received().len() == 3).await;
    assert_eq!(b1.received()[2].len(), 65_507);
    assert_eq!(
        dropped(&h.stats("dns"), DatagramDropReason::RequestOversize),
        1
    );
    h.stop();
}

#[tokio::test]
async fn a_dual_stack_streams_header_carries_ipv4_for_an_ipv4_client() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("dns", "::");
    stream.proxy_protocol_send = StreamProxyProtocol::V2;
    let h = Harness::start(
        vec![(stream, vec![backend("b1", b1.addr)])],
        Pick::First,
        Breaker::default(),
    )
    .await;
    let target = SocketAddr::new("127.0.0.1".parse().unwrap(), h.listen().port());
    let c = client().await;
    c.send_to(b"q", target).await.unwrap();
    // The echo carries the header back as payload: the client sees it.
    let echoed = reply(&c).await;
    let header = v2_dgram_v4(c.local_addr().unwrap(), target);
    assert_eq!(echoed, [&header[..], b"q"].concat());
    h.stop();
}

#[tokio::test]
async fn a_reply_leaves_from_the_address_the_client_targeted() {
    let b1 = UdpBackend::echo().await;
    let h = Harness::one(udp_stream("dns", "0.0.0.0"), vec![backend("b1", b1.addr)]).await;
    for target in ["127.0.0.2", "127.0.0.1"] {
        let to = SocketAddr::new(target.parse().unwrap(), h.listen().port());
        // A connected client takes datagrams from `to` only.
        let c = client().await;
        c.connect(to).await.unwrap();
        c.send(b"q").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(WAIT, c.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("a reply from {to}"))
            .unwrap();
        assert_eq!(&buf[..n], b"q");
    }
    h.stop();
}

// ---- admission on the stream-caps region -------------------------------

#[tokio::test]
async fn the_stream_session_cap_refuses_once_and_raises_the_ceiling_edge() {
    let b1 = UdpBackend::sink().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    udp(&mut stream).max_sessions = 1;
    let h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let first = client().await;
    first.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the first session", || h.stats("dns").accepted == 1).await;
    let second = client().await;
    second.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the refusal", || {
        h.stats("dns").refused.get(&StreamRefusal::SessionCap) == Some(&1)
    })
    .await;
    let stats = h.stats("dns");
    assert_eq!(stats.accepted, 1);
    assert!(stats.dropped.is_empty(), "counted once, as the refusal");
    assert_eq!(stats.ceiling_reached, 1);
    h.stop();
}

#[tokio::test]
async fn the_per_source_cap_refuses_a_second_port_of_one_address() {
    let b1 = UdpBackend::sink().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    udp(&mut stream).source_session_cap = Some(1);
    let h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let first = client().await;
    first.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the first session", || h.stats("dns").accepted == 1).await;
    let second = client().await;
    second.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the refusal", || {
        h.stats("dns").refused.get(&StreamRefusal::SourceSessionCap) == Some(&1)
    })
    .await;
    assert_eq!(h.stats("dns").ceiling_reached, 0);
    h.stop();
}

#[tokio::test]
async fn a_full_rate_table_refuses_new_sources_on_that_stream_only() {
    let b1 = UdpBackend::echo().await;
    // 64 sessions: the smallest rate table, 1,024 cells.
    let mut flooded = udp_stream("flooded", "127.0.0.1");
    udp(&mut flooded).max_sessions = 64;
    let other = udp_stream("other", "127.0.0.1");
    let h = Harness::start(
        vec![
            (flooded, vec![backend("b1", b1.addr)]),
            (other, vec![backend("b1", b1.addr)]),
        ],
        Pick::First,
        Breaker::default(),
    )
    .await;
    // A random-source flood claims every rate cell of the stream's region.
    let Some(StreamCtlMsg::Caps { region, .. }) = h.node.caps_message("flooded", 99, 0).unwrap()
    else {
        panic!("a caps message");
    };
    let region = StreamCapsRegion::open(region).unwrap();
    let limits = RateLimits {
        datagrams_per_s: 1_000,
        bytes_per_s: 1_000_000,
    };
    for n in 0..50_000u32 {
        let spoofed = IpAddr::from((0x0a00_0000 + n).to_be_bytes());
        region.charge_rate(SourceKey::of(spoofed), 1, limits, lorica_shmem::now_ns());
    }

    let c = client().await;
    c.send_to(b"q", h.listens[0]).await.unwrap();
    wait_until("the refusal", || {
        h.stats("flooded")
            .refused
            .get(&StreamRefusal::SessionTableFull)
            == Some(&1)
    })
    .await;
    c.send_to(b"q", h.listens[1]).await.unwrap();
    assert_eq!(reply(&c).await, b"q", "the other stream still serves");
    h.stop();
}

// ---- source controls, open rates, link caps (Story 12.6) ---------------

fn loopback(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, n))
}

/// A client sending from `127.0.0.<n>`.
async fn client_from(n: u8) -> UdpSocket {
    reserved_socket(loopback(n)).await
}

/// `c`'s first datagram is refused `refusal`: no session, no answer, one
/// row naming the client, the refusal counted once and as nothing else.
async fn refused_session(h: &mut Harness, c: &UdpSocket, refusal: StreamRefusal) {
    c.send_to(b"q", h.listen()).await.unwrap();
    refused_as(h, c, refusal).await;
}

/// `c`'s datagram, already sent, was refused `refusal`: no answer, one
/// row naming the client, the refusal counted once and as nothing else.
async fn refused_as(h: &mut Harness, c: &UdpSocket, refusal: StreamRefusal) {
    let row = h.refusal().await;
    assert_eq!(row.refusal, refusal);
    assert_eq!(row.client, c.local_addr().unwrap());
    assert_eq!(row.protocol, StreamProtocol::Udp);
    assert_eq!(
        h.stats("dns").refused.get(&refusal).copied(),
        Some(1),
        "{refusal:?} counted once"
    );
    assert_silent(c).await;
}

#[tokio::test]
async fn every_source_control_refuses_a_new_session_and_an_unknown_country_passes() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.source_deny_cidrs = vec!["127.0.0.4".into()];
    stream.geoip = Some(GeoIpConfig {
        mode: GeoIpMode::Denylist,
        countries: vec!["US".into()],
    });
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    h.gate.filtered.lock().unwrap().insert(loopback(2));
    h.gate.blocked.lock().unwrap().insert(loopback(3));
    h.gate.countries.lock().unwrap().insert(loopback(5), *b"US");

    for (n, refusal) in [
        (2, StreamRefusal::ConnectionFilter),
        (3, StreamRefusal::IpBlocklist),
        (4, StreamRefusal::SourceDenied),
        (5, StreamRefusal::Geoip),
    ] {
        let c = client_from(n).await;
        refused_session(&mut h, &c, refusal).await;
    }
    assert!(b1.received().is_empty(), "no session was opened");
    let stats = h.stats("dns");
    assert_eq!(stats.accepted, 0);
    assert!(stats.dropped.is_empty(), "a refusal is not also a drop");

    let c = client_from(6).await;
    c.send_to(b"unknown country", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"unknown country");
    assert_eq!(h.stats("dns").geoip_unknown, 1);
    h.stop();
}

#[tokio::test]
async fn a_datagram_before_the_region_is_refused_caps_unavailable_and_counted() {
    let b1 = UdpBackend::echo().await;
    let mut h = Harness::start_capped(
        vec![(udp_stream("dns", "127.0.0.1"), vec![backend("b1", b1.addr)])],
        Pick::First,
        Breaker::default(),
        &[],
        &["dns"],
    )
    .await;
    let c = client().await;
    refused_session(&mut h, &c, StreamRefusal::CapsUnavailable).await;
    assert!(b1.received().is_empty());
    h.stop();
}

/// Open sessions from `addresses` in turn, each a new client, until the
/// open rate refuses one; returns how many were served first, how long
/// it took, and the refused client.
///
/// The rate holds one second of burst and refills as it goes, so how many
/// sessions it serves before a refusal depends on how long they took to
/// arrive, which a loaded host stretches: the caller bounds the count by
/// the time it measured, never by an assumed one.
async fn open_until_refused(
    h: &Harness,
    mut addresses: impl Iterator<Item = u8>,
    refusal: StreamRefusal,
) -> (u64, Duration, UdpSocket) {
    let refused = || h.stats("dns").refused.get(&refusal).copied().unwrap_or(0);
    let started = Instant::now();
    let mut served = 0;
    loop {
        let c = client_from(addresses.next().expect("test setup: an address")).await;
        c.send_to(b"q", h.listen()).await.unwrap();
        tokio::select! {
            answer = reply(&c) => {
                assert_eq!(answer, b"q");
                served += 1;
            }
            () = wait_until("the refusal", || refused() == 1) => {
                return (served, started.elapsed(), c);
            }
        }
        assert!(started.elapsed() < WAIT, "no session outran the rate");
    }
}

/// At most the burst, plus what the rate refilled over `took`.
fn within_the_rate(served: u64, took: Duration, per_second: u32) {
    let refill = (took.as_secs_f64() * f64::from(per_second)).ceil() as u64;
    assert!(
        served >= u64::from(per_second) && served <= u64::from(per_second) + refill,
        "{served} served in {took:?} at {per_second} per second with one second of burst"
    );
}

#[tokio::test]
async fn the_source_open_rate_refuses_one_address_and_serves_another() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.source_open_rate = Some(2);
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    // Sessions from new ports of one address.
    let (served, took, refused) =
        open_until_refused(&h, std::iter::repeat(2), StreamRefusal::SourceOpenRate).await;
    within_the_rate(served, took, 2);
    refused_as(&mut h, &refused, StreamRefusal::SourceOpenRate).await;
    let other = client_from(3).await;
    other.send_to(b"q", h.listen()).await.unwrap();
    assert_eq!(reply(&other).await, b"q", "another source is served");
    h.stop();
}

#[tokio::test]
async fn the_stream_open_rate_refuses_every_source_past_it() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.open_rate = Some(1);
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    // Each session from another address: the stream's rate is everyone's.
    let (served, took, refused) = open_until_refused(&h, 2..=250, StreamRefusal::OpenRate).await;
    within_the_rate(served, took, 1);
    refused_as(&mut h, &refused, StreamRefusal::OpenRate).await;
    h.stop();
}

#[tokio::test]
async fn a_backend_at_its_cap_is_skipped_and_all_at_cap_refuse_backend_cap() {
    let b1 = UdpBackend::sink().await;
    let b2 = UdpBackend::sink().await;
    let mut h = Harness::start_capped(
        vec![(
            udp_stream("dns", "127.0.0.1"),
            vec![backend("b1", b1.addr), backend("b2", b2.addr)],
        )],
        Pick::First,
        Breaker::default(),
        &[("b1", 1), ("b2", 1)],
        &[],
    )
    .await;
    let (first, second) = (client().await, client().await);
    first.send_to(b"one", h.listen()).await.unwrap();
    wait_until("b1 holds a session", || b1.received().len() == 1).await;
    second.send_to(b"two", h.listen()).await.unwrap();
    wait_until("b2 took the second", || b2.received().len() == 1).await;

    let third = client().await;
    third.send_to(b"three", h.listen()).await.unwrap();
    let row = h.refusal().await;
    assert_eq!(row.refusal, StreamRefusal::BackendCap);
    assert_eq!(row.client, third.local_addr().unwrap());
    assert_eq!(
        h.stats("dns").refused.get(&StreamRefusal::BackendCap),
        Some(&1)
    );
    assert!(h.breaker_records().is_empty(), "no breaker report");
    assert_eq!((b1.received().len(), b2.received().len()), (1, 1));
    h.stop();
}

// ---- selection, breaker, drain -----------------------------------------

#[tokio::test]
async fn consistent_hash_keeps_one_client_address_on_one_backend() {
    let b1 = UdpBackend::echo().await;
    let b2 = UdpBackend::echo().await;
    let h = Harness::start(
        vec![(
            udp_stream("dns", "::"),
            vec![backend("b1", b1.addr), backend("b2", b2.addr)],
        )],
        Pick::ClientHash,
        Breaker::default(),
    )
    .await;
    let target = SocketAddr::new("127.0.0.1".parse().unwrap(), h.listen().port());
    for _ in 0..4 {
        let c = client().await;
        c.send_to(b"q", target).await.unwrap();
        assert_eq!(reply(&c).await, b"q");
    }
    let (on_b1, on_b2) = (b1.received().len(), b2.received().len());
    assert!(
        (on_b1, on_b2) == (4, 0) || (on_b1, on_b2) == (0, 4),
        "{on_b1} and {on_b2}"
    );
    let clients = h.selector.clients.lock().unwrap().clone();
    assert!(
        clients
            .iter()
            .all(|ip| *ip == "127.0.0.1".parse::<IpAddr>().unwrap()),
        "the canonical client address, never IPv4-mapped: {clients:?}"
    );
    h.stop();
}

#[tokio::test]
async fn least_sessions_counts_each_session_once() {
    let b1 = UdpBackend::sink().await;
    let b2 = UdpBackend::sink().await;
    // The first session must still be open when the second picks its
    // backend: no idle timeout ends it on its own, however long the
    // host takes; a detach ends both once the second has opened.
    let mut stream = udp_stream("dns", "127.0.0.1");
    stream.idle_timeout_s = 3_600;
    let mut h = Harness::start(
        vec![(stream, vec![backend("b1", b1.addr), backend("b2", b2.addr)])],
        Pick::FewestSessions,
        Breaker::default(),
    )
    .await;
    let first = client().await;
    first.send_to(b"q", h.listen()).await.unwrap();
    first.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the first session", || b1.received().len() == 2).await;
    let second = client().await;
    second.send_to(b"q", h.listen()).await.unwrap();
    wait_until("the second session", || b2.received().len() == 1).await;
    let seq = h.next_seq();
    h.exchange(StreamCtlMsg::Detach {
        seq,
        stream_id: "dns".into(),
        bind_gen: 1,
        drain_ms: 0,
    })
    .await;
    h.record().await;
    h.record().await;
    let mut connected = h.selector.connected.lock().unwrap().clone();
    let mut closed = h.selector.closed.lock().unwrap().clone();
    connected.sort();
    closed.sort();
    assert_eq!(
        connected,
        vec!["b1", "b2"],
        "once per session, not per datagram"
    );
    assert_eq!(closed, connected);
    h.stop();
}

#[tokio::test]
async fn a_breaker_deny_reselects_without_opening_a_socket() {
    let b1 = UdpBackend::echo().await;
    let b2 = UdpBackend::echo().await;
    let mut h = Harness::start(
        vec![(
            udp_stream("dns", "127.0.0.1"),
            vec![backend("b1", b1.addr), backend("b2", b2.addr)],
        )],
        Pick::First,
        Breaker {
            deny: ["b1".to_string()].into(),
            ..Breaker::default()
        },
    )
    .await;
    let c = client().await;
    c.send_to(b"q", h.listen()).await.unwrap();
    assert_eq!(reply(&c).await, b"q");
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b2"));
    assert!(b1.received().is_empty());
    assert_eq!(h.stats("dns").breaker_denied, 1);
    assert_eq!(*h.selector.connected.lock().unwrap(), vec!["b2"]);
    h.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_receive_loop_never_waits_on_a_session() {
    // Stream `hung`: the breaker never answers for its backend, so its
    // sessions never open. Stream `flood`: a black-holing backend fed as
    // fast as the client can send. Stream `served` must answer all along.
    let hung_backend = UdpBackend::echo().await;
    let black_hole = UdpBackend::sink().await;
    let served_backend = UdpBackend::echo().await;
    let mut flood = udp_stream("flood", "127.0.0.1");
    udp(&mut flood).responses_per_request = 0;
    udp(&mut flood).requests_per_session = None;
    udp(&mut flood).source_datagram_rate = 1_000_000;
    udp(&mut flood).source_byte_rate = 1_073_741_824;
    let h = Harness::start(
        vec![
            (
                udp_stream("hung", "127.0.0.1"),
                vec![backend("bh", hung_backend.addr)],
            ),
            (flood, vec![backend("bf", black_hole.addr)]),
            (
                udp_stream("served", "127.0.0.1"),
                vec![backend("bs", served_backend.addr)],
            ),
        ],
        Pick::First,
        Breaker {
            hang: ["bh".to_string()].into(),
            ..Breaker::default()
        },
    )
    .await;
    let (hung, flooded, served) = (h.listens[0], h.listens[1], h.listens[2]);

    let stuck = client().await;
    stuck.send_to(b"q", hung).await.unwrap();
    let flooder = client().await;
    for _ in 0..2_000 {
        flooder.send_to(&[0u8; 1024], flooded).await.unwrap();
    }
    let c = client().await;
    c.send_to(b"q", served).await.unwrap();
    assert_eq!(reply(&c).await, b"q");

    // The hung stream's own loop keeps taking datagrams too.
    let second = client().await;
    second.send_to(b"q", hung).await.unwrap();
    stuck.send_to(&[0u8; 9_000], hung).await.unwrap();
    wait_until("the hung stream's loop", || {
        let stats = h.stats("hung");
        stats.accepted == 2 && dropped(&stats, DatagramDropReason::RequestOversize) == 1
    })
    .await;
    assert!(hung_backend.received().is_empty());
    h.stop();
}

#[tokio::test]
async fn a_draining_binding_serves_its_sessions_and_opens_none() {
    let b1 = UdpBackend::echo().await;
    let mut stream = udp_stream("game", "127.0.0.1");
    udp(&mut stream).unbounded_responses = true;
    udp(&mut stream).requests_per_session = None;
    let mut h = Harness::one(stream, vec![backend("b1", b1.addr)]).await;
    let known = client().await;
    known.send_to(b"q1", h.listen()).await.unwrap();
    assert_eq!(reply(&known).await, b"q1");

    let seq = h.next_seq();
    h.exchange(StreamCtlMsg::Detach {
        seq,
        stream_id: "game".into(),
        bind_gen: 1,
        drain_ms: 30_000,
    })
    .await;
    known.send_to(b"q2", h.listen()).await.unwrap();
    assert_eq!(reply(&known).await, b"q2");
    let newcomer = client().await;
    newcomer.send_to(b"new", h.listen()).await.unwrap();
    wait_until("the newcomer's drop", || {
        dropped(&h.stats("game"), DatagramDropReason::BindingDraining) == 1
    })
    .await;
    assert_silent(&newcomer).await;
    assert_eq!(h.stats("game").accepted, 1);
    h.stop();
}

// ---- what the access log is handed (Story 12.9 Lot A) --------------------

/// A session with no backend to open reports one `not_connected`; one
/// that expects no response and ends normally reports nothing but its
/// record.
#[tokio::test]
async fn no_healthy_backend_is_not_connected_and_a_silent_stream_reports_only_its_record() {
    let b1 = UdpBackend::sink().await;
    let mut down = backend("b1", b1.addr);
    down.health_status = HealthStatus::Down;
    let mut syslog = udp_stream("syslog", "127.0.0.1");
    udp(&mut syslog).responses_per_request = 0;
    udp(&mut syslog).requests_per_session = Some(1);
    let mut h = Harness::start(
        vec![
            (udp_stream("dns", "127.0.0.1"), vec![down]),
            (syslog, vec![backend("b2", b1.addr)]),
        ],
        Pick::First,
        Breaker::default(),
    )
    .await;
    let c = client().await;
    c.send_to(b"query", h.listens[0]).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::NoHealthyBackend);
    assert_eq!(h.outcomes("dns"), vec![ConnectOutcome::NotConnected]);

    c.send_to(b"<13>message", h.listens[1]).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.stream_id, "syslog");
    assert_eq!(record.end_reason, StreamEndReason::RequestBoundReached);
    assert_eq!(record.protocol, StreamProtocol::Udp);
    assert!(h.outcomes("syslog").is_empty());
    assert!(h.records.try_recv().is_err(), "one record per session");
    let link = h.link("syslog", "b2");
    assert_eq!((link.bytes_upload, link.bytes_download), (11, 0));
    h.stop();
}
