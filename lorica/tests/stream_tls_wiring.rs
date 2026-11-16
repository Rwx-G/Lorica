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

//! The binary's TLS wiring of the stream engines (Story 12.4 Lot E), on
//! Linux sockets:
//!
//! - IV2's mechanism in-process: a terminating stream over the engines
//!   `stream_engines` builds, on a resolver loaded and reloaded by
//!   `reload_cert_resolver`, the path an ACME renewal takes. A
//!   certificate only the stream names (no route) is served, a
//!   replacement written to its row is presented by the next handshake,
//!   and a connection opened before it keeps working;
//! - the selector keeps round-robin state per (stream, rule) (I3);
//! - the client identities a stream table carries are read from the
//!   referenced rows, a row without a key held back.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica::stream_engine::{
    stream_client_identities, stream_engines, StreamBreakerGate, StreamSelector,
};
use lorica_config::models::{
    Backend, Certificate, HealthCheck, HealthStatus, LifecycleState, LoadBalancing, Stream,
    StreamBackend, StreamMatchRule, StreamMatcher, StreamProtocol, StreamRefusal, StreamTlsMode,
    StreamTlsTerminate, StreamUpstreamTls,
};
use lorica_config::ConfigStore;
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    BackendSelector, Candidate, ControlTransport, InProcessPeer, NodeCapsRegions, Resolve,
    ResolveError, Resolved, SelectionRequest, SourceGate, StreamRuntime, StreamRuntimeHandle,
    StreamTable, StreamTableSource, TlsParts,
};
use lorica_tls::cert_resolver::{CertResolver, ResolvesServerCertByLocalIp};
use lorica_tls::RootCertStore;
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_tcp_stream_listener;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const WAIT: Duration = Duration::from_secs(10);
const STREAM_ID: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
const BACKEND_ID: &str = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
const CERT_ID: &str = "3c9d2f4e-8a1b-4c5d-9e6f-0a1b2c3d4e5f";
const SERVER_NAME: &str = "t.stream-tls.test";
const RULE: &str = "app";

type ClientTls = tokio_rustls::client::TlsStream<TcpStream>;

/// A CA the client trusts, and the leaves it issues.
struct Pki {
    ca_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Pki {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Pki {
            ca_der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A stored certificate row `id` for `name`, and its leaf's DER.
    fn row(&self, id: &str, name: &str) -> (Certificate, CertificateDer<'static>) {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .signed_by(&key, &self.issuer)
            .unwrap();
        let now = Utc::now();
        let row = Certificate {
            id: id.into(),
            domain: name.into(),
            san_domains: vec![name.into()],
            fingerprint: String::new(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            issuer: "test CA".into(),
            not_before: now - chrono::Duration::days(1),
            not_after: now + chrono::Duration::days(30),
            is_acme: true,
            acme_auto_renew: true,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
            adcs_authority_id: None,
            adcs_template: None,
            adcs_template_oid: None,
            adcs_request_id: None,
        };
        (row, cert.der().clone())
    }

    fn client(&self) -> tokio_rustls::TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        let config = lorica_tls::http_client::config_builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

fn backend(id: &str, address: impl ToString) -> Backend {
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: id.into(),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
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

fn tls_rule(name: &str, server_name: &str) -> StreamMatchRule {
    StreamMatchRule {
        name: name.into(),
        matcher: StreamMatcher::Tls {
            server_names: vec![server_name.into()],
            alpn: Vec::new(),
        },
    }
}

/// A stream terminating `SERVER_NAME` with the certificate `CERT_ID`.
fn terminating_stream() -> Stream {
    let mut stream = Stream::new(
        STREAM_ID.into(),
        "terminate".into(),
        StreamProtocol::Tcp,
        "127.0.0.1".parse().unwrap(),
        5432,
        5432,
        Utc::now(),
    );
    stream.allow_local_backend = true;
    stream.connect_timeout_ms = 2_000;
    stream.tls_mode = StreamTlsMode::Terminate;
    stream.match_rules = vec![tls_rule(RULE, SERVER_NAME)];
    stream.tls_terminate = Some(StreamTlsTerminate {
        certificate_ids: vec![CERT_ID.into()],
        client_auth: None,
    });
    stream
}

/// A resolver the test never needs: every backend is an IP literal.
struct NoDns;

impl Resolve for NoDns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        Box::pin(async move { Err(ResolveError(format!("{host}: no DNS in this test"))) })
    }
}

/// No node-wide source control: these tests exercise TLS.
struct Ungated;

impl SourceGate for Ungated {
    fn global(&self, _: IpAddr) -> Option<StreamRefusal> {
        None
    }

    fn country(&self, _: IpAddr) -> Option<[u8; 2]> {
        None
    }
}

#[derive(Default)]
struct Source(Mutex<StreamTable>);

impl StreamTableSource for Source {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// The table of `store`, as `StoreStreamTable` reads it.
fn table_of(store: &ConfigStore) -> StreamTable {
    let streams = store.list_streams().unwrap();
    let identities = stream_client_identities(&streams, |id| store.get_certificate(id)).unwrap();
    StreamTable::with_backends(
        streams,
        &store.list_stream_backends().unwrap(),
        store.list_backends().unwrap(),
    )
    .with_client_identities(identities)
}

async fn echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
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

/// A stream runtime over the binary's engines, fed from `source`.
struct Harness {
    peer: InProcessPeer,
    /// The streams' caps regions, as the supervisor holds them.
    node: NodeCapsRegions,
    runtime: Option<StreamRuntimeHandle>,
    seq: u64,
    _listeners: Vec<OwnedFd>,
}

impl Harness {
    fn start(source: &Arc<Source>, resolver: Arc<CertResolver>) -> Self {
        let engines = stream_engines(
            Arc::new(StreamBreakerGate::new()),
            Arc::new(NoDns),
            None,
            TlsParts {
                resolver: resolver as Arc<dyn ResolvesServerCertByLocalIp>,
                public_roots: None,
            },
            Arc::new(Ungated),
        );
        let (peer, transport) = ControlTransport::in_process_pair(8);
        let runtime = StreamRuntime::spawn(
            transport,
            engines,
            Arc::clone(source) as Arc<dyn StreamTableSource>,
        )
        .unwrap();
        Harness {
            peer,
            node: NodeCapsRegions::new(1),
            runtime: Some(runtime),
            seq: 0,
            _listeners: Vec::new(),
        }
    }

    /// Hand `stream_id` its caps region, then attach a fresh listener to
    /// it, as the supervisor does (Story 12.6 D-e).
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
        let adopted = tokio::time::timeout(WAIT, self.peer.from_runtime.recv())
            .await
            .expect("the runtime answers")
            .expect("the runtime is alive");
        assert!(
            matches!(adopted, StreamCtlMsg::Ack { count: 1, .. }),
            "{adopted:?}"
        );
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
        let answer = tokio::time::timeout(WAIT, self.peer.from_runtime.recv())
            .await
            .expect("the runtime answers")
            .expect("the runtime is alive");
        assert!(
            matches!(answer, StreamCtlMsg::Ack { count: 1, .. }),
            "{answer:?}"
        );
        self._listeners.push(fd);
        addr
    }

    fn stop(mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.stop();
        }
    }
}

/// A verified TLS connection to the stream for `SERVER_NAME`, and the
/// leaf the stream presented.
async fn connect(pki: &Pki, listen: SocketAddr) -> (ClientTls, CertificateDer<'static>) {
    let socket = TcpStream::connect(listen).await.unwrap();
    let tls = tokio::time::timeout(
        WAIT,
        pki.client()
            .connect(ServerName::try_from(SERVER_NAME).unwrap(), socket),
    )
    .await
    .expect("the handshake ends in time")
    .expect("the stream completes the handshake");
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .expect("the stream presents a certificate")
        .clone()
        .into_owned();
    (tls, leaf)
}

async fn echo_once(tls: &mut ClientTls, payload: &[u8]) {
    tls.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(WAIT, tls.read_exact(&mut got))
        .await
        .expect("echo in time")
        .unwrap();
    assert_eq!(got, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn iv2_a_renewed_certificate_reaches_the_next_handshake_of_a_terminating_stream() {
    let pki = Pki::new();
    let echo = echo_backend().await;
    let (first, first_leaf) = pki.row(CERT_ID, SERVER_NAME);
    let (renewed, renewed_leaf) = pki.row(CERT_ID, SERVER_NAME);
    let store = ConfigStore::open_in_memory().unwrap();
    // No route names the certificate: the stream alone keeps it in the
    // resolver across a reload.
    store.create_certificate(&first).unwrap();
    store.create_backend(&backend(BACKEND_ID, echo)).unwrap();
    store.create_stream(&terminating_stream()).unwrap();
    let mut link = StreamBackend::primary(STREAM_ID, BACKEND_ID);
    link.rule = Some(RULE.into());
    store.set_stream_links(STREAM_ID, &[link]).unwrap();
    let source = Arc::new(Source::default());
    *source.0.lock().unwrap() = table_of(&store);
    let store = Arc::new(tokio::sync::Mutex::new(store));
    let resolver = Arc::new(CertResolver::new());
    lorica::reload::reload_cert_resolver(&store, &resolver).await;

    let mut h = Harness::start(&source, Arc::clone(&resolver));
    let listen = h.attach(STREAM_ID).await;
    let (mut before, presented) = connect(&pki, listen).await;
    assert_eq!(presented, first_leaf);
    echo_once(&mut before, b"before the renewal").await;

    // What a renewal does: the row is rewritten in place, then the
    // resolver reloaded from the store.
    store.lock().await.update_certificate(&renewed).unwrap();
    lorica::reload::reload_cert_resolver(&store, &resolver).await;

    let (mut after, presented) = connect(&pki, listen).await;
    assert_eq!(
        presented, renewed_leaf,
        "the next handshake presents the renewal"
    );
    echo_once(&mut after, b"after the renewal").await;
    echo_once(&mut before, b"the open connection keeps working").await;
    drop((before, after));
    h.stop();
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

fn select(selector: &StreamSelector, stream: &Stream, cands: &[Candidate<'_>]) -> usize {
    selector.select(&SelectionRequest {
        stream,
        candidates: cands,
        client: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        accepted_at: Instant::now(),
    })
}

#[test]
fn round_robin_state_is_per_rule_and_pruned_with_the_rule() {
    let selector = StreamSelector::new(0);
    let mut stream = terminating_stream();
    stream.tls_mode = StreamTlsMode::Passthrough;
    stream.tls_terminate = None;
    stream.load_balancing = LoadBalancing::RoundRobin;
    stream.match_rules = vec![
        tls_rule("one", "a.example.test"),
        tls_rule("two", "b.example.test"),
    ];
    let rule_one = [
        backend("a1", "192.0.2.1:443"),
        backend("a2", "192.0.2.2:443"),
    ];
    let rule_two = [
        backend("b1", "192.0.2.3:443"),
        backend("b2", "192.0.2.4:443"),
    ];
    let linked = |stream: &Stream| {
        let links: Vec<StreamBackend> = rule_one
            .iter()
            .map(|b| (b, "one"))
            .chain(rule_two.iter().map(|b| (b, "two")))
            .filter(|(_, rule)| stream.match_rule(rule).is_some())
            .map(|(b, rule)| {
                let mut link = StreamBackend::primary(&stream.id, &b.id);
                link.rule = Some(rule.into());
                link
            })
            .collect();
        let rows = rule_one.iter().chain(rule_two.iter()).cloned().collect();
        StreamTable::with_backends(vec![stream.clone()], &links, rows)
    };
    selector.table_changed(&linked(&stream));
    let (one, two) = (candidates(&rule_one), candidates(&rule_two));

    let first_of_one = select(&selector, &stream, &one);
    let first_of_two = select(&selector, &stream, &two);
    let second_of_one = select(&selector, &stream, &one);
    assert_ne!(first_of_one, second_of_one, "rule one alternates");
    assert_eq!(
        first_of_two, first_of_one,
        "rule two starts its own rotation, not rule one's"
    );
    assert!(selector.holds_rule_round_robin(STREAM_ID, Some("one")));
    assert!(selector.holds_rule_round_robin(STREAM_ID, Some("two")));
    assert!(!selector.holds_rule_round_robin(STREAM_ID, None));

    stream.match_rules.truncate(1);
    selector.table_changed(&linked(&stream));
    assert!(selector.holds_rule_round_robin(STREAM_ID, Some("one")));
    assert!(
        !selector.holds_rule_round_robin(STREAM_ID, Some("two")),
        "a rule's state goes with the rule"
    );

    selector.table_changed(&StreamTable::default());
    assert!(!selector.holds_round_robin(STREAM_ID));
}

#[test]
fn client_identities_are_read_from_the_rows_the_streams_name() {
    let pki = Pki::new();
    let with_key = "c-with-key";
    let keyless = "c-keyless";
    let mut rows: HashMap<&str, Certificate> = HashMap::new();
    let (row, leaf) = pki.row(with_key, "client.example.test");
    rows.insert(with_key, row);
    let (mut row, _) = pki.row(keyless, "other.example.test");
    row.key_pem.clear();
    rows.insert(keyless, row);
    let streams: Vec<Stream> = [with_key, keyless, "c-missing", with_key]
        .into_iter()
        .map(|id| {
            let mut stream = Stream::new(
                format!("stream-{id}"),
                id.into(),
                StreamProtocol::Tcp,
                "127.0.0.1".parse().unwrap(),
                5432,
                5432,
                Utc::now(),
            );
            stream.upstream_tls = Some(StreamUpstreamTls {
                client_certificate_id: Some(id.into()),
                ..StreamUpstreamTls::default()
            });
            stream
        })
        .collect();
    let mut read: Vec<String> = Vec::new();

    let identities = stream_client_identities(&streams, |id| {
        read.push(id.to_string());
        Ok::<_, std::convert::Infallible>(rows.get(id).cloned())
    })
    .unwrap();

    read.sort();
    assert_eq!(
        read,
        ["c-keyless", "c-missing", "c-with-key"],
        "each referenced row read once"
    );
    assert_eq!(
        identities.len(),
        1,
        "the keyless and missing rows are left out"
    );
    assert_eq!(identities[0].0, with_key);
    assert_eq!(identities[0].1.chain()[0], leaf);
    let failed =
        stream_client_identities(&streams, |_| Err::<Option<Certificate>, _>("unreadable"));
    assert_eq!(failed.err(), Some("unreadable"));
}
