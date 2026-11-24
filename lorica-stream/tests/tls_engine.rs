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

//! The TLS side of the TCP engine (Story 12.4 Lot D) against real
//! sockets (Linux), with `rcgen` certificates and fake seams: the
//! selector takes the first candidate, the breaker admits and records,
//! the resolver answers `localhost` only.
//!
//! Passthrough backends report the bytes they received, compared byte
//! for byte with what the client sent; terminating streams answer from a
//! real `CertResolver`; upstream TLS backends report the server name and
//! client certificate they saw.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, MtlsConfig, Stream, StreamBackend,
    StreamEndReason, StreamMatchRule, StreamMatcher, StreamProtocol, StreamProxyProtocol,
    StreamRefusal, StreamTlsMode, StreamTlsTerminate, StreamUpstreamTls, UpstreamServerName,
};
use lorica_core::protocols::proxy_protocol::{encode_v2, parse, Addresses, Parsed};
use lorica_shmem::StreamCapsRegion;
use lorica_stream::caps::admitted_cap;
use lorica_stream::counters::{
    ClientHelloOutcome, HandshakeOutcome, StreamCountersSnapshot, UpstreamTlsFailure,
};
use lorica_stream::seams::SeamFuture;
use lorica_stream::tls::rewind::Rewind;
use lorica_stream::tls::server::{accept, TerminateConfigs};
use lorica_stream::{
    AcceptedConnection, Admission, BackendSelector, BoundPorts, BreakerGate, CapsRegistry,
    ClientCertificateOutcome, ClientIdentity, ConnectionObserver, ConnectionRecord,
    ConnectionTracker, NodeCapsRegions, RefusalRecord, Resolve, ResolveError, Resolved,
    ResolverCache, SelectionRequest, SourceGate, StreamCounters, StreamHandler, StreamTable,
    TcpEngine, TcpEngineParts, TlsParts,
};
use lorica_tls::cert_resolver::{CertData, CertResolver, ResolvesServerCertByLocalIp};
use lorica_tls::http_client::{config_builder, crypto_provider};
use lorica_tls::{
    CertificateDer, ClientTlsStream, PrivateKeyDer, RootCertStore, ServerConfig, ServerName,
    TlsAcceptor, TlsConnector, WebPkiClientVerifier,
};
use lorica_worker::stream_ctl::StreamCtlMsg;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::HandshakeKind;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

const WAIT: Duration = Duration::from_secs(10);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

// ---- fake seams ------------------------------------------------------

struct FirstCandidate;

impl BackendSelector for FirstCandidate {
    fn select(&self, _request: &SelectionRequest<'_>) -> usize {
        0
    }

    fn connected(&self, _: &str, _: &Backend, _: SocketAddr, _: Duration) {}

    fn closed(&self, _: &str, _: &Backend, _: SocketAddr) {}
}

#[derive(Default)]
struct Breaker {
    records: Mutex<Vec<(String, bool, bool)>>,
}

impl Breaker {
    fn recorded(&self, backend_id: &str) -> Vec<bool> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _, _)| id == backend_id)
            .map(|(_, success, _)| *success)
            .collect()
    }
}

impl BreakerGate for Breaker {
    fn admit<'a>(&'a self, _: &'a str, _: &'a Backend) -> SeamFuture<'a, Admission> {
        Box::pin(async { Admission::Allow })
    }

    fn record<'a>(
        &'a self,
        _: &'a str,
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

/// Answers `localhost` with loopback, hangs on any other name.
struct Dns;

impl Resolve for Dns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        Box::pin(async move {
            if host == "localhost" {
                Ok(Resolved {
                    addresses: vec![LOOPBACK],
                    ttl: Duration::from_secs(30),
                })
            } else {
                std::future::pending().await
            }
        })
    }
}

struct Records {
    ended: mpsc::UnboundedSender<ConnectionRecord>,
    refused: mpsc::UnboundedSender<RefusalRecord>,
}

impl ConnectionObserver for Records {
    fn observe(&self, record: ConnectionRecord) {
        let _ = self.ended.send(record);
    }

    fn refused(&self, record: RefusalRecord) {
        let _ = self.refused.send(record);
    }
}

/// No node-wide source control.
struct Ungated;

impl SourceGate for Ungated {
    fn global(&self, _: IpAddr) -> Option<StreamRefusal> {
        None
    }

    fn country(&self, _: IpAddr) -> Option<[u8; 2]> {
        None
    }
}

// ---- certificates ----------------------------------------------------

/// A CA that issues server and client certificates.
struct Ca {
    pem: String,
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

/// A certificate issued by a [`Ca`], with its key.
struct Issued {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

impl Ca {
    fn new(name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca {
            pem: cert.pem(),
            der: cert.der().clone(),
            issuer: Issuer::new(params, key),
        }
    }

    /// A leaf for `names` (DNS names and IP literals), with an `O=` when
    /// `organization` is set.
    fn issue(&self, names: &[&str], organization: Option<&str>) -> Issued {
        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        params.distinguished_name.push(
            DnType::CommonName,
            names.first().copied().unwrap_or("client"),
        );
        if let Some(organization) = organization {
            params
                .distinguished_name
                .push(DnType::OrganizationName, organization);
        }
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Issued {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.der.clone()).unwrap();
        roots
    }

    fn pem(&self) -> String {
        self.pem.clone()
    }
}

impl Issued {
    fn chain(&self) -> Vec<CertificateDer<'static>> {
        vec![self.der.clone()]
    }

    fn key(&self) -> PrivateKeyDer<'static> {
        lorica_tls::load_first_private_key(self.key_pem.as_bytes()).unwrap()
    }

    fn identity(&self) -> ClientIdentity {
        ClientIdentity::from_pem(&self.cert_pem, &self.key_pem).unwrap()
    }

    /// The resolver row serving `names` with this certificate.
    fn cert_data(&self, names: &[&str]) -> CertData {
        CertData {
            domain: names[0].to_string(),
            san_domains: names[1..].iter().map(|n| n.to_string()).collect(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            not_after_epoch: 4_102_444_800,
            ocsp_response: None,
        }
    }
}

// ---- streams, backends, table ----------------------------------------

fn rule(name: &str, server_names: &[&str], alpn: &[&str]) -> StreamMatchRule {
    StreamMatchRule {
        name: name.into(),
        matcher: StreamMatcher::Tls {
            server_names: server_names.iter().map(|n| n.to_string()).collect(),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
        },
    }
}

fn no_sni_rule(name: &str) -> StreamMatchRule {
    StreamMatchRule {
        name: name.into(),
        matcher: StreamMatcher::NoSni { alpn: Vec::new() },
    }
}

/// A TCP stream on loopback with local backends allowed.
fn stream(id: &str, mode: StreamTlsMode, rules: Vec<StreamMatchRule>) -> Stream {
    let mut s = Stream::new(
        id.into(),
        id.into(),
        StreamProtocol::Tcp,
        LOOPBACK,
        1,
        1,
        Utc::now(),
    );
    s.allow_local_backend = true;
    s.no_sni_acknowledged = rules
        .iter()
        .any(|r| matches!(r.matcher, StreamMatcher::NoSni { .. }));
    s.tls_mode = mode;
    s.match_rules = rules;
    s
}

/// A terminating stream presenting the resolver's certificates.
fn terminating(id: &str, rules: Vec<StreamMatchRule>, client_auth: Option<MtlsConfig>) -> Stream {
    let mut s = stream(id, StreamTlsMode::Terminate, rules);
    s.tls_terminate = Some(StreamTlsTerminate {
        certificate_ids: vec!["server".into()],
        client_auth,
    });
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

/// `streams` with `links` of (stream id, backend, rule).
fn table(streams: Vec<Stream>, links: Vec<(&str, Backend, Option<&str>)>) -> StreamTable {
    let rows: Vec<StreamBackend> = links
        .iter()
        .map(|(stream_id, backend, rule)| {
            let mut link = StreamBackend::primary(stream_id, &backend.id);
            link.rule = rule.map(str::to_string);
            link
        })
        .collect();
    let backends = links.into_iter().map(|(_, backend, _)| backend).collect();
    StreamTable::with_backends(streams, &rows, backends)
}

// ---- the harness -----------------------------------------------------

struct Harness {
    engine: TcpEngine,
    tracker: ConnectionTracker,
    records: mpsc::UnboundedReceiver<ConnectionRecord>,
    refusals: mpsc::UnboundedReceiver<RefusalRecord>,
    /// Every stream's caps region, on a node of one worker.
    node: Mutex<NodeCapsRegions>,
    caps: CapsRegistry,
    counters: Arc<StreamCounters>,
    breaker: Arc<Breaker>,
    resolver: Arc<CertResolver>,
    table: Arc<Mutex<Arc<StreamTable>>>,
}

impl Harness {
    fn new(public_roots: Option<RootCertStore>) -> Self {
        let counters = Arc::new(StreamCounters::new());
        let breaker = Arc::new(Breaker::default());
        let resolver = Arc::new(CertResolver::new());
        let (ended, records) = mpsc::unbounded_channel();
        let (refused, refusals) = mpsc::unbounded_channel();
        let engine = TcpEngine::with_tls(
            TcpEngineParts {
                selector: Arc::new(FirstCandidate),
                breaker: Arc::clone(&breaker) as Arc<dyn BreakerGate>,
                resolver: ResolverCache::new(Arc::new(Dns), Arc::clone(&counters)),
                counters: Arc::clone(&counters),
                observer: Arc::new(Records { ended, refused }),
                reserved_ports: None,
                source_gate: Arc::new(Ungated),
            },
            TlsParts {
                resolver: Arc::clone(&resolver) as Arc<dyn ResolvesServerCertByLocalIp>,
                public_roots: public_roots.map(Arc::new),
            },
        );
        Harness {
            engine,
            tracker: ConnectionTracker::new(),
            records,
            refusals,
            node: Mutex::new(NodeCapsRegions::new(1)),
            caps: CapsRegistry::new(),
            counters,
            breaker,
            resolver,
            table: Arc::default(),
        }
    }

    fn set(&self, table: StreamTable) {
        let mut node = self.node.lock().unwrap();
        for stream in table.streams() {
            let created = node
                .ensure(&stream.id, admitted_cap(stream).unwrap(), 0)
                .unwrap();
            if created.is_some() {
                let Some(StreamCtlMsg::Caps { region, slot, .. }) =
                    node.caps_message(&stream.id, 1, 0).unwrap()
                else {
                    panic!("test setup: a caps message");
                };
                let region = Arc::new(StreamCapsRegion::open(region).unwrap());
                self.caps.adopt(&stream.id, region.worker(slot).unwrap());
            }
        }
        self.engine.table_changed(&table);
        *self.table.lock().unwrap() = Arc::new(table);
    }

    /// A listener for `stream_id`, accepting against the current table.
    async fn listen(&self, stream_id: &str) -> SocketAddr {
        let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (engine, tracker, table, caps) = (
            self.engine.clone(),
            self.tracker.clone(),
            Arc::clone(&self.table),
            self.caps.clone(),
        );
        let stream_id = stream_id.to_string();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let table = Arc::clone(&table.lock().unwrap());
                let snapshot = table.stream(&stream_id).expect("test setup: a stream");
                let tracked = tracker.register(1, snapshot);
                tokio::spawn(engine.handle(AcceptedConnection {
                    stream,
                    peer,
                    bind_gen: 1,
                    tracked,
                    table,
                    bound_ports: BoundPorts::new(),
                    caps: caps.clone(),
                }));
            }
        });
        addr
    }

    async fn record(&mut self) -> ConnectionRecord {
        tokio::time::timeout(WAIT, self.records.recv())
            .await
            .expect("a connection record in time")
            .expect("the engine is alive")
    }

    /// The next refusal row: a refused connection hands no record (Story
    /// 12.6 D-j), and the refusal log writes one row per stream and
    /// refusal per window.
    async fn refusal(&mut self) -> RefusalRecord {
        tokio::time::timeout(WAIT, self.refusals.recv())
            .await
            .expect("a refusal row in time")
            .expect("the engine is alive")
    }

    fn stats(&self, stream_id: &str) -> StreamCountersSnapshot {
        self.counters
            .snapshot()
            .streams
            .get(stream_id)
            .cloned()
            .unwrap_or_default()
    }
}

// ---- backends --------------------------------------------------------

/// Hands over each connection's bytes, read until EOF.
async fn sink() -> (SocketAddr, mpsc::UnboundedReceiver<Vec<u8>>) {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
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

async fn echo_on<S: AsyncRead + AsyncWrite + Unpin>(mut io: S) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        match io.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if io.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        }
    }
    let _ = io.shutdown().await;
}

/// Echoes each connection until EOF.
async fn echo() -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(echo_on(socket));
        }
    });
    addr
}

/// Reads until EOF, then answers `bye:<bytes read>` and closes.
async fn replier() -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut all = Vec::new();
                let _ = socket.read_to_end(&mut all).await;
                let _ = socket
                    .write_all(format!("bye:{}", all.len()).as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    addr
}

/// What a TLS backend saw of one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    proxy_header: Option<Addresses>,
    server_name: Option<String>,
    client_certificate: Option<CertificateDer<'static>>,
    alpn: Option<Vec<u8>>,
}

/// A TLS echo backend presenting `cert`, asking for a client certificate
/// of `client_ca` when set, and reading a PROXY header first when
/// `proxy` is set.
async fn tls_backend(
    cert: &Issued,
    client_ca: Option<&Ca>,
    proxy: bool,
) -> (SocketAddr, mpsc::UnboundedReceiver<Seen>) {
    let builder = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap();
    let builder = match client_ca {
        Some(ca) => builder.with_client_cert_verifier(
            WebPkiClientVerifier::builder_with_provider(Arc::new(ca.roots()), crypto_provider())
                .allow_unauthenticated()
                .build()
                .unwrap(),
        ),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder.with_single_cert(cert.chain(), cert.key()).unwrap();
    config.alpn_protocols = vec![b"postgresql".to_vec(), b"h2".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let mut proxy_header = None;
                let mut leftover = Vec::new();
                if proxy {
                    let mut buf = vec![0u8; 4096];
                    let mut filled = 0;
                    loop {
                        match parse(&buf[..filled]) {
                            Ok(Parsed::Complete { header, consumed }) => {
                                proxy_header = Some(header.addresses);
                                leftover = buf[consumed..filled].to_vec();
                                break;
                            }
                            Ok(Parsed::Incomplete) => {}
                            Err(_) => return,
                        }
                        match socket.read(&mut buf[filled..]).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => filled += n,
                        }
                    }
                }
                let Ok(tls) = acceptor.accept(Rewind::new(leftover, socket)).await else {
                    return;
                };
                let (_, connection) = tls.get_ref();
                let _ = tx.send(Seen {
                    proxy_header,
                    server_name: connection.server_name().map(str::to_string),
                    client_certificate: connection
                        .peer_certificates()
                        .and_then(|chain| chain.first().cloned()),
                    alpn: connection.alpn_protocol().map(<[u8]>::to_vec),
                });
                echo_on(tls).await;
            });
        }
    });
    (addr, rx)
}

/// Accepts TCP and closes at once: a backend that does not speak TLS.
async fn closer() -> SocketAddr {
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
        }
    });
    addr
}

// ---- clients ---------------------------------------------------------

fn client_config(
    roots: RootCertStore,
    identity: Option<&Issued>,
    alpn: &[&str],
) -> Arc<lorica_tls::ClientConfig> {
    let builder = config_builder().with_root_certificates(roots);
    let mut config = match identity {
        Some(identity) => builder
            .with_client_auth_cert(identity.chain(), identity.key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(config)
}

fn name(n: &str) -> ServerName<'static> {
    ServerName::try_from(n.to_string()).unwrap()
}

/// The ClientHello rustls' client sends for `server` (no SNI for an IP)
/// offering `alpn`, as it goes on the wire.
fn client_hello(server: &str, alpn: &[&str]) -> Vec<u8> {
    let config = client_config(RootCertStore::empty(), None, alpn);
    let mut connection = rustls::ClientConnection::new(config, name(server)).unwrap();
    let mut wire = Vec::new();
    connection.write_tls(&mut wire).unwrap();
    wire
}

/// `hello` (one record) re-framed over `records` records.
fn in_records(hello: &[u8], records: usize) -> Vec<u8> {
    let body = &hello[5..];
    let size = body.len().div_ceil(records);
    body.chunks(size)
        .flat_map(|chunk| {
            let mut record = vec![22, hello[1], hello[2]];
            record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            record.extend_from_slice(chunk);
            record
        })
        .collect()
}

async fn tls_connect(
    addr: SocketAddr,
    server: &str,
    config: Arc<lorica_tls::ClientConfig>,
) -> io::Result<ClientTlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    tokio::time::timeout(WAIT, TlsConnector::from(config).connect(name(server), tcp))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}

/// Write `payload` and read it back.
async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    payload: &[u8],
) -> io::Result<()> {
    io.write_all(payload).await?;
    io.flush().await?;
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, io.read_exact(&mut got))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    assert_eq!(got, payload);
    Ok(())
}

/// Send `bytes` raw, close the write side, and wait for the engine to
/// close the connection.
async fn send_raw(addr: SocketAddr, bytes: &[u8]) {
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(bytes).await.unwrap();
    client.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(WAIT, client.read_to_end(&mut rest)).await;
}

async fn next(rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("backend bytes in time")
        .expect("backend alive")
}

// ---- passthrough -----------------------------------------------------

/// IV1 in-crate: one port, two names, two backends, each receiving the
/// client's ClientHello and what followed it byte for byte; a third name
/// is refused with nothing forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passthrough_routes_two_names_and_replays_the_hello_unchanged() {
    let mut h = Harness::new(None);
    let (a, mut a_rx) = sink().await;
    let (b, mut b_rx) = sink().await;
    h.set(table(
        vec![stream(
            "s",
            StreamTlsMode::Passthrough,
            vec![
                rule("a", &["a.example.com"], &[]),
                rule("b", &["b.example.com"], &[]),
            ],
        )],
        vec![
            ("s", backend("ba", a), Some("a")),
            ("s", backend("bb", b), Some("b")),
        ],
    ));
    let listen = h.listen("s").await;

    for (server, rx, backend_id, rule_name) in [
        ("a.example.com", &mut a_rx, "ba", "a"),
        ("b.example.com", &mut b_rx, "bb", "b"),
    ] {
        let mut sent = client_hello(server, &["h2", "http/1.1"]);
        sent.extend_from_slice(b"and the bytes after the hello");
        send_raw(listen, &sent).await;
        assert_eq!(next(rx).await, sent, "{server}");
        let record = h.record().await;
        assert_eq!(record.backend_id.as_deref(), Some(backend_id));
        assert_eq!(record.bytes_upload, sent.len() as u64);
        let tls = record.tls.expect("a TLS record");
        assert_eq!(tls.mode, StreamTlsMode::Passthrough);
        assert_eq!(tls.server_name.as_deref(), Some(server));
        assert_eq!(tls.rule.as_deref(), Some(rule_name));
        assert_eq!(tls.offered_alpn, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    send_raw(listen, &client_hello("c.example.com", &[])).await;
    assert_eq!(h.refusal().await.refusal, StreamRefusal::NoMatch);
    assert!(a_rx.try_recv().is_err() && b_rx.try_recv().is_err());
    let stats = h.stats("s");
    assert_eq!(stats.refused[&StreamRefusal::NoMatch], 1);
    assert_eq!(stats.clienthello[&ClientHelloOutcome::Parsed], 3);
    let rules = h.counters.snapshot().rules;
    assert_eq!(rules[&("s".to_string(), "a".to_string())].matched, 1);
    assert_eq!(rules[&("s".to_string(), "b".to_string())].matched, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wildcards_match_any_depth_most_specific_first_and_alpn_by_client_preference() {
    let mut h = Harness::new(None);
    let (broad, _broad_rx) = sink().await;
    let (narrow, _narrow_rx) = sink().await;
    let (grpc, _grpc_rx) = sink().await;
    let (web, _web_rx) = sink().await;
    h.set(table(
        vec![stream(
            "s",
            StreamTlsMode::Passthrough,
            vec![
                rule("broad", &["*.example.com"], &[]),
                rule("narrow", &["*.eu.example.com"], &[]),
                rule("grpc", &["api.example.com"], &["h2"]),
                rule("web", &["api.example.com"], &["http/1.1"]),
            ],
        )],
        vec![
            ("s", backend("broad", broad), Some("broad")),
            ("s", backend("narrow", narrow), Some("narrow")),
            ("s", backend("grpc", grpc), Some("grpc")),
            ("s", backend("web", web), Some("web")),
        ],
    ));
    let listen = h.listen("s").await;
    for (server, alpn, expected) in [
        ("a.b.eu.example.com", &[][..], "narrow"),
        ("a.b.us.example.com", &[][..], "broad"),
        ("api.example.com", &["h2", "http/1.1"][..], "grpc"),
        ("api.example.com", &["http/1.1", "h2"][..], "web"),
        // No rule of the exact level holds `smtp`: the wildcard does.
        ("api.example.com", &["smtp"][..], "broad"),
    ] {
        send_raw(listen, &client_hello(server, alpn)).await;
        let record = h.record().await;
        assert_eq!(
            record.backend_id.as_deref(),
            Some(expected),
            "{server} {alpn:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_without_sni_is_refused_without_a_no_sni_rule_and_routed_with_one() {
    let mut h = Harness::new(None);
    let (addr, mut rx) = sink().await;
    let named = stream(
        "named",
        StreamTlsMode::Passthrough,
        vec![rule("all", &["*.example.com"], &[])],
    );
    let bare = stream(
        "bare",
        StreamTlsMode::Passthrough,
        vec![rule("all", &["*.example.com"], &[]), no_sni_rule("bare")],
    );
    h.set(table(
        vec![named, bare],
        vec![
            ("named", backend("b-named", addr), Some("all")),
            ("bare", backend("b-bare", addr), Some("bare")),
        ],
    ));
    let named_listen = h.listen("named").await;
    let bare_listen = h.listen("bare").await;
    let hello = client_hello("127.0.0.1", &[]);

    send_raw(named_listen, &hello).await;
    assert_eq!(h.refusal().await.refusal, StreamRefusal::NoMatch);

    send_raw(bare_listen, &hello).await;
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("b-bare"));
    assert_eq!(next(&mut rx).await, hello);
    assert_eq!(record.tls.unwrap().server_name, None);
    assert_eq!(h.stats("bare").no_sni_matched, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trickled_hello_ends_clienthello_timeout_counted_from_accept() {
    let mut h = Harness::new(None);
    let (addr, _rx) = sink().await;
    let mut s = stream(
        "s",
        StreamTlsMode::Passthrough,
        vec![rule("a", &["a.example.com"], &[])],
    );
    s.clienthello_timeout_ms = Some(1_000);
    h.set(table(vec![s], vec![("s", backend("b", addr), Some("a"))]));
    let listen = h.listen("s").await;

    let hello = client_hello("a.example.com", &[]);
    let started = Instant::now();
    let mut client = TcpStream::connect(listen).await.unwrap();
    let trickle = tokio::spawn(async move {
        for byte in hello {
            if client.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });
    let record = h.record().await;
    let took = started.elapsed();
    assert_eq!(record.end_reason, StreamEndReason::ClienthelloTimeout);
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_millis(3_000),
        "{took:?}"
    );
    assert_eq!(h.stats("s").clienthello[&ClientHelloOutcome::Timeout], 1);
    trickle.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hello_in_three_records_is_replayed_whole() {
    let mut h = Harness::new(None);
    let (addr, mut rx) = sink().await;
    h.set(table(
        vec![stream(
            "s",
            StreamTlsMode::Passthrough,
            vec![rule("a", &["a.example.com"], &[])],
        )],
        vec![("s", backend("b", addr), Some("a"))],
    ));
    let listen = h.listen("s").await;
    let fragmented = in_records(&client_hello("a.example.com", &["h2"]), 3);
    send_raw(listen, &fragmented).await;
    assert_eq!(next(&mut rx).await, fragmented);
    assert_eq!(h.record().await.backend_id.as_deref(), Some("b"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_proxy_header_and_the_hello_in_one_segment_route_and_replay_the_hello() {
    let mut h = Harness::new(None);
    let (addr, mut rx) = sink().await;
    let mut s = stream(
        "s",
        StreamTlsMode::Passthrough,
        vec![rule("a", &["a.example.com"], &[])],
    );
    s.proxy_protocol_accept = true;
    s.proxy_protocol_trusted_cidrs = vec!["127.0.0.1/32".into()];
    h.set(table(vec![s], vec![("s", backend("b", addr), Some("a"))]));
    let listen = h.listen("s").await;

    let source: SocketAddr = "192.0.2.10:40000".parse().unwrap();
    let hello = client_hello("a.example.com", &[]);
    let mut segment = encode_v2(source, listen);
    segment.extend_from_slice(&hello);
    send_raw(listen, &segment).await;
    assert_eq!(next(&mut rx).await, hello);
    let record = h.record().await;
    assert_eq!(record.client, source);
    assert_eq!(
        record.tls.unwrap().server_name.as_deref(),
        Some("a.example.com")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bytes_that_are_no_hello_are_refused_and_counted() {
    let mut h = Harness::new(None);
    let (addr, _rx) = sink().await;
    h.set(table(
        vec![stream(
            "s",
            StreamTlsMode::Passthrough,
            vec![rule("a", &["a.example.com"], &[])],
        )],
        vec![("s", backend("b", addr), Some("a"))],
    ));
    let listen = h.listen("s").await;
    send_raw(listen, b"GET / HTTP/1.1\r\n\r\n").await;
    assert_eq!(h.refusal().await.refusal, StreamRefusal::InvalidClientHello);
    assert_eq!(h.stats("s").clienthello[&ClientHelloOutcome::Invalid], 1);
}

// ---- termination -----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn termination_serves_the_named_certificate_and_the_ip_certificate_without_sni() {
    let mut h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let named = ca.issue(&["app.example.com"], None);
    let by_ip = ca.issue(&["127.0.0.1"], None);
    h.resolver
        .reload(vec![
            named.cert_data(&["app.example.com"]),
            by_ip.cert_data(&["ip.invalid"]),
        ])
        .unwrap();
    let app = echo().await;
    let bare = echo().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![
                rule("app", &["app.example.com"], &["h2"]),
                no_sni_rule("bare"),
            ],
            None,
        )],
        vec![
            ("s", backend("app", app), Some("app")),
            ("s", backend("bare", bare), Some("bare")),
        ],
    ));
    let listen = h.listen("s").await;

    let mut client = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &["h2"]),
    )
    .await
    .unwrap();
    assert_eq!(
        client.get_ref().1.peer_certificates().unwrap()[0],
        named.der
    );
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    round_trip(&mut client, b"ping").await.unwrap();
    client.shutdown().await.unwrap();
    let record = h.record().await;
    assert_eq!(record.backend_id.as_deref(), Some("app"));
    assert_eq!(record.end_reason, StreamEndReason::ClientClose);
    let tls = record.tls.unwrap();
    assert_eq!(tls.negotiated_alpn.as_deref(), Some(&b"h2"[..]));
    assert_eq!(
        tls.client_certificate, None,
        "a stream that does not verify records no outcome (Story 12.9 D-a)"
    );
    assert_eq!(record.bytes_upload, 4, "plaintext is counted");

    let mut client = tls_connect(listen, "127.0.0.1", client_config(ca.roots(), None, &[]))
        .await
        .unwrap();
    assert_eq!(
        client.get_ref().1.peer_certificates().unwrap()[0],
        by_ip.der
    );
    round_trip(&mut client, b"pong").await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(h.record().await.backend_id.as_deref(), Some("bare"));
    assert_eq!(h.stats("s").handshakes[&HandshakeOutcome::Ok], 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_no_certificate_serves_is_refused_no_certificate() {
    let mut h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let app = echo().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![rule("app", &["nocert.example.com"], &[])],
            None,
        )],
        vec![("s", backend("app", app), Some("app"))],
    ));
    let listen = h.listen("s").await;
    let outcome = tls_connect(
        listen,
        "nocert.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await;
    assert!(outcome.is_err());
    assert_eq!(h.refusal().await.refusal, StreamRefusal::NoCertificate);
    assert_eq!(h.stats("s").handshakes[&HandshakeOutcome::NoCertificate], 1);
}

/// AC #5: two terminating streams trusting different CAs, on two ports.
/// A client certificate of one CA is accepted on its own stream only;
/// a client with none passes where the certificate is optional and is
/// refused where it is required.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_streams_trusting_different_cas_never_admit_each_other_s_clients() {
    let mut h = Harness::new(None);
    let server_ca = Ca::new("Server CA");
    let server = server_ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![server.cert_data(&["app.example.com"])])
        .unwrap();
    let (ca_a, ca_b) = (Ca::new("CA A"), Ca::new("CA B"));
    let client_a = ca_a.issue(&["client-a"], Some("Alpha"));
    let client_b = ca_b.issue(&["client-b"], Some("Beta"));
    let auth = |ca: &Ca, required: bool| MtlsConfig {
        ca_cert_pem: ca.pem(),
        required,
        allowed_organizations: Vec::new(),
    };
    let app = echo().await;
    let rules = || vec![rule("app", &["app.example.com"], &[])];
    h.set(table(
        vec![
            terminating("a", rules(), Some(auth(&ca_a, true))),
            terminating("b", rules(), Some(auth(&ca_b, true))),
            terminating("optional", rules(), Some(auth(&ca_a, false))),
        ],
        vec![
            ("a", backend("app-a", app), Some("app")),
            ("b", backend("app-b", app), Some("app")),
            ("optional", backend("app-o", app), Some("app")),
        ],
    ));
    let a = h.listen("a").await;
    let b = h.listen("b").await;
    let optional = h.listen("optional").await;

    let mut refused_count = 0u64;
    for (listen, identity, admitted) in [
        (a, Some(&client_a), true),
        (b, Some(&client_a), false),
        (b, Some(&client_b), true),
        (a, Some(&client_b), false),
        (optional, None, true),
        (a, None, false),
    ] {
        let config = client_config(server_ca.roots(), identity, &[]);
        let served = match tls_connect(listen, "app.example.com", config).await {
            Ok(mut client) => {
                let served = round_trip(&mut client, b"hello").await.is_ok();
                let _ = client.shutdown().await;
                served
            }
            Err(_) => false,
        };
        assert_eq!(served, admitted, "{listen}");
        if admitted {
            let record = h.record().await;
            let expected = if identity.is_some() {
                ClientCertificateOutcome::Verified
            } else {
                ClientCertificateOutcome::Absent
            };
            assert_eq!(record.tls.unwrap().client_certificate, Some(expected));
        } else {
            // A second refusal of a stream within the window writes no
            // row: the counter is what counts every one.
            refused_count += 1;
            let deadline = Instant::now() + WAIT;
            while ["a", "b"]
                .iter()
                .map(|id| {
                    h.stats(id)
                        .refused
                        .get(&StreamRefusal::ClientCertificate)
                        .copied()
                        .unwrap_or(0)
                })
                .sum::<u64>()
                < refused_count
            {
                assert!(Instant::now() < deadline, "{listen}: refusal not counted");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_organization_allowlist_admits_a_listed_o_and_refuses_another() {
    let mut h = Harness::new(None);
    let server_ca = Ca::new("Server CA");
    let server = server_ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![server.cert_data(&["app.example.com"])])
        .unwrap();
    let ca = Ca::new("Client CA");
    let app = echo().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![rule("app", &["app.example.com"], &[])],
            Some(MtlsConfig {
                ca_cert_pem: ca.pem(),
                required: true,
                allowed_organizations: vec!["Acme".into()],
            }),
        )],
        vec![("s", backend("app", app), Some("app"))],
    ));
    let listen = h.listen("s").await;
    for (organization, admitted) in [("Acme", true), ("Other", false)] {
        let identity = ca.issue(&["client"], Some(organization));
        let config = client_config(server_ca.roots(), Some(&identity), &[]);
        let mut client = tls_connect(listen, "app.example.com", config)
            .await
            .unwrap();
        let served = round_trip(&mut client, b"hello").await.is_ok();
        let _ = client.shutdown().await;
        assert_eq!(served, admitted, "{organization}");
        if admitted {
            assert_eq!(h.record().await.backend_id.as_deref(), Some("app"));
        } else {
            assert_eq!(h.refusal().await.refusal, StreamRefusal::ClientCertificate);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_travels_both_ways_over_tls() {
    let mut h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let server = ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![server.cert_data(&["app.example.com"])])
        .unwrap();
    let backend_addr = replier().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![rule("app", &["app.example.com"], &[])],
            None,
        )],
        vec![("s", backend("app", backend_addr), Some("app"))],
    ));
    let listen = h.listen("s").await;
    let mut client = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    client.write_all(b"hello").await.unwrap();
    // close_notify then FIN: the backend sees EOF, answers, and closes.
    client.shutdown().await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(WAIT, client.read_to_end(&mut answer))
        .await
        .unwrap()
        .expect("the answer ends with close_notify, not a bare FIN");
    assert_eq!(answer, b"bye:5");
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ClientClose);
    assert_eq!((record.bytes_upload, record.bytes_download), (5, 5));
}

/// IV2's mechanism: a reload of the shared resolver reaches the next
/// handshake, while a connection opened before it keeps working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resolver_reload_reaches_new_handshakes_and_spares_open_connections() {
    let h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let first = ca.issue(&["app.example.com"], None);
    let renewed = ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![first.cert_data(&["app.example.com"])])
        .unwrap();
    let app = echo().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![rule("app", &["app.example.com"], &[])],
            None,
        )],
        vec![("s", backend("app", app), Some("app"))],
    ));
    let listen = h.listen("s").await;
    // Each connection gets its own client config: a shared one would
    // resume the first session, and a resumed handshake presents no
    // certificate at all.
    let mut open = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    assert_eq!(open.get_ref().1.peer_certificates().unwrap()[0], first.der);
    round_trip(&mut open, b"before").await.unwrap();

    h.resolver
        .reload(vec![renewed.cert_data(&["app.example.com"])])
        .unwrap();
    let mut fresh = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    assert_eq!(
        fresh.get_ref().1.peer_certificates().unwrap()[0],
        renewed.der
    );
    round_trip(&mut fresh, b"fresh").await.unwrap();
    round_trip(&mut open, b"after").await.unwrap();
}

/// A table load that changes nothing a terminating stream is built from
/// keeps its server configs, and with them the session cache: a client
/// resumes across the refresh. A certificate renewed in the resolver
/// still reaches the next full handshake through those kept configs
/// (Phase 1 audit C16).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_keeps_resumption_and_a_renewal_still_reaches_new_handshakes() {
    let h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let first = ca.issue(&["app.example.com"], None);
    let renewed = ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![first.cert_data(&["app.example.com"])])
        .unwrap();
    let app = echo().await;
    let load = || {
        table(
            vec![terminating(
                "s",
                vec![rule("app", &["app.example.com"], &[])],
                None,
            )],
            vec![("s", backend("app", app), Some("app"))],
        )
    };
    h.set(load());
    let listen = h.listen("s").await;
    let returning = client_config(ca.roots(), None, &[]);
    let mut full = tls_connect(listen, "app.example.com", Arc::clone(&returning))
        .await
        .unwrap();
    // The round trip also reads the session ticket the server sends.
    round_trip(&mut full, b"full").await.unwrap();
    assert_eq!(full.get_ref().1.handshake_kind(), Some(HandshakeKind::Full));

    h.set(load());
    let mut resumed = tls_connect(listen, "app.example.com", returning)
        .await
        .unwrap();
    round_trip(&mut resumed, b"resumed").await.unwrap();
    assert_eq!(
        resumed.get_ref().1.handshake_kind(),
        Some(HandshakeKind::Resumed)
    );

    h.resolver
        .reload(vec![renewed.cert_data(&["app.example.com"])])
        .unwrap();
    h.set(load());
    let mut fresh = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    assert_eq!(
        fresh.get_ref().1.peer_certificates().unwrap()[0],
        renewed.der
    );
    round_trip(&mut fresh, b"fresh").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_drain_in_the_middle_of_a_handshake_ends_with_the_drain_reason() {
    let mut h = Harness::new(None);
    let ca = Ca::new("Server CA");
    let server = ca.issue(&["app.example.com"], None);
    h.resolver
        .reload(vec![server.cert_data(&["app.example.com"])])
        .unwrap();
    let app = echo().await;
    h.set(table(
        vec![terminating(
            "s",
            vec![rule("app", &["app.example.com"], &[])],
            None,
        )],
        vec![("s", backend("app", app), Some("app"))],
    ));
    let listen = h.listen("s").await;

    // The hello alone: the server answers and waits for a Finished that
    // never comes.
    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(&client_hello("app.example.com", &[]))
        .await
        .unwrap();
    let mut server_flight = [0u8; 5];
    tokio::time::timeout(WAIT, client.read_exact(&mut server_flight))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(server_flight[0], 22, "the server's handshake has started");
    let now = Instant::now();
    h.tracker.drain_all(now, StreamEndReason::ConfigRemoved);
    h.tracker.close_expired(now);
    assert_eq!(h.record().await.end_reason, StreamEndReason::ConfigRemoved);
}

/// rustls refuses a handshake whose offered ALPN misses the rule's list;
/// the matcher never lets that happen, so it is pinned here on the
/// config alone.
#[tokio::test]
async fn a_rule_config_refuses_a_client_offering_none_of_its_protocols() {
    let ca = Ca::new("Server CA");
    let server = ca.issue(&["app.example.com"], None);
    let resolver = Arc::new(CertResolver::new());
    resolver
        .reload(vec![server.cert_data(&["app.example.com"])])
        .unwrap();
    let resolver: Arc<dyn ResolvesServerCertByLocalIp> = resolver;
    let rules = [rule("app", &["app.example.com"], &["h2"])];
    let configs = TerminateConfigs::build(&rules, None, &resolver).unwrap();
    let config = configs.config("app", LOOPBACK).unwrap();
    assert_eq!(config.max_early_data_size, 0);

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client = TlsConnector::from(client_config(ca.roots(), None, &["http/1.1"]))
        .connect(name("app.example.com"), client_io);
    let (client, served) = tokio::join!(client, accept(config, server_io));
    assert!(client.is_err());
    assert_eq!(served.err(), Some(HandshakeOutcome::TlsHandshake));
}

// ---- upstream TLS ----------------------------------------------------

/// A stream without TLS on the client side originating TLS to `backend`
/// with `settings`.
fn originating(id: &str, settings: StreamUpstreamTls) -> Stream {
    let mut s = stream(id, StreamTlsMode::None, Vec::new());
    s.upstream_tls = Some(settings);
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_tls_names_its_server_in_each_mode_and_verifies_on_the_public_roots() {
    let ca = Ca::new("Public-style CA");
    let mut h = Harness::new(Some(ca.roots()));
    h.resolver
        .reload(vec![ca
            .issue(&["app.example.com"], None)
            .cert_data(&["app.example.com"])])
        .unwrap();
    let cert = ca.issue(
        &[
            "localhost",
            "app.example.com",
            "fixed.example.com",
            "127.0.0.1",
        ],
        None,
    );
    let (addr, mut seen) = tls_backend(&cert, None, false).await;
    let by_name = format!("localhost:{}", addr.port());

    let fixed = StreamUpstreamTls {
        server_name: UpstreamServerName::Fixed {
            name: "fixed.example.com".into(),
        },
        alpn: vec!["postgresql".into()],
        ..StreamUpstreamTls::default()
    };
    let client_mode = StreamUpstreamTls {
        server_name: UpstreamServerName::Client {},
        ..StreamUpstreamTls::default()
    };
    let mut reencrypting =
        terminating("client", vec![rule("app", &["app.example.com"], &[])], None);
    reencrypting.upstream_tls = Some(client_mode);
    h.set(table(
        vec![
            originating("address", StreamUpstreamTls::default()),
            originating("ip", StreamUpstreamTls::default()),
            originating("fixed", fixed),
            reencrypting,
        ],
        vec![
            ("address", backend("b-address", &by_name), None),
            ("ip", backend("b-ip", addr), None),
            ("fixed", backend("b-fixed", addr), None),
            ("client", backend("b-client", addr), Some("app")),
        ],
    ));

    for (id, expected_name, alpn) in [
        ("address", Some("localhost"), None),
        ("ip", None, None),
        (
            "fixed",
            Some("fixed.example.com"),
            Some(b"postgresql".to_vec()),
        ),
    ] {
        let listen = h.listen(id).await;
        let mut client = TcpStream::connect(listen).await.unwrap();
        round_trip(&mut client, b"plain in, TLS out").await.unwrap();
        let seen = tokio::time::timeout(WAIT, seen.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(seen.server_name.as_deref(), expected_name, "{id}");
        assert_eq!(seen.alpn, alpn, "{id}");
        drop(client);
        let record = h.record().await;
        assert!(record.tls.unwrap().upstream_tls, "{id}");
    }

    let listen = h.listen("client").await;
    let mut client = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    round_trip(&mut client, b"re-encrypted").await.unwrap();
    let seen = tokio::time::timeout(WAIT, seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen.server_name.as_deref(), Some("app.example.com"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_tls_presents_the_client_identity_the_table_holds() {
    let ca = Ca::new("Backend CA");
    let h = Harness::new(None);
    let cert = ca.issue(&["localhost"], None);
    let client_ca = Ca::new("Client CA");
    let identity = client_ca.issue(&["lorica"], Some("Lorica"));
    let (addr, mut seen) = tls_backend(&cert, Some(&client_ca), false).await;
    let settings = StreamUpstreamTls {
        ca_cert_pem: Some(ca.pem()),
        client_certificate_id: Some("client-cert".into()),
        ..StreamUpstreamTls::default()
    };
    h.set(
        table(
            vec![originating("s", settings)],
            vec![(
                "s",
                backend("b", format!("localhost:{}", addr.port())),
                None,
            )],
        )
        .with_client_identities([("client-cert".to_string(), identity.identity())]),
    );
    let listen = h.listen("s").await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    round_trip(&mut client, b"mutual").await.unwrap();
    let seen = tokio::time::timeout(WAIT, seen.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(seen.client_certificate, Some(identity.der.clone()));
    let printed = format!("{:?}", h.table.lock().unwrap());
    assert!(printed.contains(r#""client-cert": ..."#), "{printed}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_verify_accepts_a_backend_no_root_trusts() {
    let h = Harness::new(Some(Ca::new("Public-style CA").roots()));
    let unknown = Ca::new("Unknown CA").issue(&["localhost"], None);
    let (addr, mut seen) = tls_backend(&unknown, None, false).await;
    let settings = StreamUpstreamTls {
        skip_verify: true,
        ..StreamUpstreamTls::default()
    };
    h.set(table(
        vec![originating("s", settings)],
        vec![("s", backend("b", addr), None)],
    ));
    let listen = h.listen("s").await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    round_trip(&mut client, b"unverified").await.unwrap();
    assert!(tokio::time::timeout(WAIT, seen.recv())
        .await
        .unwrap()
        .is_some());
}

/// A certificate that does not verify is a failed attempt the breaker
/// does not count; a backend that drops the handshake is one it counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verification_failure_is_not_counted_by_the_breaker_while_a_reset_is() {
    let mut h = Harness::new(Some(Ca::new("Public-style CA").roots()));
    let unknown = Ca::new("Unknown CA").issue(&["localhost"], None);
    let (untrusted, _seen) = tls_backend(&unknown, None, false).await;
    let dropping = closer().await;
    let mut s = originating("s", StreamUpstreamTls::default());
    s.max_connect_attempts = 1;
    let mut t = originating("t", StreamUpstreamTls::default());
    t.max_connect_attempts = 1;
    h.set(table(
        vec![s, t],
        vec![
            ("s", backend("untrusted", untrusted), None),
            ("t", backend("dropping", dropping), None),
        ],
    ));

    for (id, backend_id, kind) in [
        ("s", "untrusted", UpstreamTlsFailure::Verify),
        ("t", "dropping", UpstreamTlsFailure::Handshake),
    ] {
        let listen = h.listen(id).await;
        let mut client = TcpStream::connect(listen).await.unwrap();
        let _ = client.write_all(b"never forwarded").await;
        assert_eq!(h.record().await.end_reason, StreamEndReason::ConnectFailed);
        let links = h.counters.snapshot().links;
        assert_eq!(
            links[&(id.to_string(), backend_id.to_string())].upstream_tls_failures[&kind],
            1,
            "{id}"
        );
    }
    assert_eq!(h.breaker.recorded("untrusted"), Vec::<bool>::new());
    assert_eq!(h.breaker.recorded("dropping"), vec![false]);
}

/// Serves `names` only: a ClientHello naming anything else draws a fatal
/// alert, as nginx's `ssl_reject_handshake` or HAProxy's `strict-sni`
/// answer a name they do not serve.
#[derive(Debug)]
struct StrictSni {
    names: Vec<String>,
    key: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for StrictSni {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello.server_name()?;
        self.names
            .iter()
            .any(|served| served == name)
            .then(|| Arc::clone(&self.key))
    }
}

/// A TLS echo backend presenting `cert` for `names` and refusing every
/// other server name.
async fn strict_sni_backend(cert: &Issued, names: &[&str]) -> SocketAddr {
    let key = crypto_provider()
        .key_provider
        .load_private_key(cert.key())
        .unwrap();
    let resolver = StrictSni {
        names: names.iter().map(|n| n.to_string()).collect(),
        key: Arc::new(rustls::sign::CertifiedKey::new(cert.chain(), key)),
    };
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(socket).await {
                    echo_on(tls).await;
                }
            });
        }
    });
    addr
}

/// Phase 1 audit C3: with `server_name = client` behind a wildcard rule,
/// the name sent upstream is the client's choice, and a strict-SNI
/// backend refuses the names it does not serve. Six such handshakes,
/// more than the breaker's threshold, count on the link and report
/// nothing to the breaker; the name the backend serves still connects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handshake_refused_on_a_client_chosen_name_never_reaches_the_breaker() {
    let ca = Ca::new("Server CA");
    let mut h = Harness::new(None);
    h.resolver
        .reload(vec![ca
            .issue(&["*.example.com"], None)
            .cert_data(&["*.example.com"])])
        .unwrap();
    let served = ca.issue(&["app.example.com"], None);
    let addr = strict_sni_backend(&served, &["app.example.com"]).await;
    let mut s = terminating("s", vec![rule("any", &["*.example.com"], &[])], None);
    s.max_connect_attempts = 1;
    s.upstream_tls = Some(StreamUpstreamTls {
        server_name: UpstreamServerName::Client {},
        ca_cert_pem: Some(ca.pem()),
        ..StreamUpstreamTls::default()
    });
    h.set(table(vec![s], vec![("s", backend("b", addr), Some("any"))]));
    let listen = h.listen("s").await;

    for n in 0..6 {
        let label = format!("zz{n}.example.com");
        let mut client = tls_connect(listen, &label, client_config(ca.roots(), None, &[]))
            .await
            .unwrap();
        let _ = client.write_all(b"never forwarded").await;
        assert_eq!(
            h.record().await.end_reason,
            StreamEndReason::ConnectFailed,
            "{label}"
        );
    }
    let links = h.counters.snapshot().links;
    assert_eq!(
        links[&("s".to_string(), "b".to_string())].upstream_tls_failures
            [&UpstreamTlsFailure::Handshake],
        6
    );
    assert_eq!(h.breaker.recorded("b"), Vec::<bool>::new());

    let mut client = tls_connect(
        listen,
        "app.example.com",
        client_config(ca.roots(), None, &[]),
    )
    .await
    .unwrap();
    round_trip(&mut client, b"served").await.unwrap();
    assert_eq!(h.breaker.recorded("b"), vec![true]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_header_goes_in_plaintext_before_the_backend_s_tls() {
    let ca = Ca::new("Backend CA");
    let h = Harness::new(Some(ca.roots()));
    let cert = ca.issue(&["localhost"], None);
    let (addr, mut seen) = tls_backend(&cert, None, true).await;
    let mut s = originating("s", StreamUpstreamTls::default());
    s.proxy_protocol_send = StreamProxyProtocol::V2;
    h.set(table(
        vec![s],
        vec![(
            "s",
            backend("b", format!("localhost:{}", addr.port())),
            None,
        )],
    ));
    let listen = h.listen("s").await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    round_trip(&mut client, b"after the header").await.unwrap();
    let seen = tokio::time::timeout(WAIT, seen.recv())
        .await
        .unwrap()
        .unwrap();
    let Some(Addresses::Tcp {
        source,
        destination,
    }) = seen.proxy_header
    else {
        panic!("a TCP PROXY header before the handshake: {seen:?}");
    };
    assert_eq!(source, client.local_addr().unwrap());
    assert_eq!(destination, listen);
    assert_eq!(seen.server_name.as_deref(), Some("localhost"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_public_roots_every_attempt_ends_no_trust_and_opens_nothing() {
    let mut h = Harness::new(None);
    let cert = Ca::new("Backend CA").issue(&["localhost"], None);
    let (addr, mut seen) = tls_backend(&cert, None, false).await;
    h.set(table(
        vec![originating("s", StreamUpstreamTls::default())],
        vec![("s", backend("b", addr), None)],
    ));
    let listen = h.listen("s").await;
    let _client = TcpStream::connect(listen).await.unwrap();
    let record = h.record().await;
    assert_eq!(record.end_reason, StreamEndReason::ConnectFailed);
    assert_eq!(record.attempts, 1);
    let links = h.counters.snapshot().links;
    assert_eq!(
        links[&("s".to_string(), "b".to_string())].upstream_tls_failures
            [&UpstreamTlsFailure::NoTrust],
        1
    );
    assert!(h.breaker.recorded("b").is_empty());
    assert!(seen.try_recv().is_err());
}
