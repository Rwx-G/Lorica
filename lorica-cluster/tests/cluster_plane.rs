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

//! Integration tests for the cluster listeners, admission gate and
//! dialer (Story 9.2 AC #2/#3/#4/#9/#10) over real mTLS on 127.0.0.1.
//!
//! Test hygiene: every await that depends on another task sits under
//! an explicit timeout so a regression fails in seconds instead of
//! hanging a CI run.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use lorica_cluster::handshake::{client_handshake, HandshakeConfig};
use lorica_cluster::listener::{
    EnrollmentListener, EnrollmentStats, OperationalConfig, OperationalListener,
    OperationalStats, PreAuthBudgets,
};
use lorica_cluster::messages::{cluster_request, ClusterFrame, ClusterRequest, Heartbeat};
use lorica_cluster::{
    client_config, enrollment_server_config, operational_server_config, AdmissionGate, ClusterCa,
    ClusterStatus, Dialer, DialerConfig, HandshakeError, SwappableAcceptor, BODY_KIND_HELLO,
};
use lorica_command::RpcEndpoint;

const CP_HOST: &str = "cp.cluster.internal";
const WAIT: Duration = Duration::from_secs(10);

fn install_ring() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

struct Pki {
    ca: ClusterCa,
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
}

fn pki() -> Pki {
    let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
    let (server_cert, server_key) = ca.issue_server_leaf(CP_HOST).expect("server leaf");
    let (client_cert, client_key) = ca.issue_client_leaf("node-a").expect("client leaf");
    Pki {
        ca,
        server_cert,
        server_key,
        client_cert,
        client_key,
    }
}

fn cfg(schema: u32) -> HandshakeConfig {
    HandshakeConfig::new(schema)
}

fn roots(p: &Pki) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(p.ca.cert_pem().as_bytes()).flatten() {
        roots.add(cert.into_owned()).expect("ca root");
    }
    roots
}

/// An operational listener on a fresh 127.0.0.1 port with test-sized
/// defaults; `tune` adjusts the config before spawn.
async fn spawn_operational(
    p: &Pki,
    tune: impl FnOnce(&mut OperationalConfig),
) -> (
    SocketAddr,
    Arc<OperationalStats>,
    Arc<SwappableAcceptor>,
    lorica_cluster::listener::OperationalHandle,
) {
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("config");
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(server_config)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let mut config = OperationalConfig::new(listener, Arc::clone(&acceptor), cfg(49));
    config.fleet_size = Arc::new(AtomicU32::new(3));
    config.admission = Arc::new(AdmissionGate::new(8, 8, 5));
    config.max_sessions = 64;
    tune(&mut config);
    let stats = Arc::clone(&config.stats);
    let handle = OperationalListener::spawn(config);
    (addr, stats, acceptor, handle)
}

/// mTLS client connector presenting the node leaf, with the cluster
/// ALPN.
fn node_client(p: &Pki) -> TlsConnector {
    let tls_cfg = client_config(p.ca.cert_pem(), &p.client_cert, &p.client_key).expect("client");
    TlsConnector::from(Arc::new(tls_cfg))
}

/// Same identity, but a client that offers NO ALPN at all.
fn node_client_without_alpn(p: &Pki) -> TlsConnector {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(p.client_cert.as_bytes())
            .flatten()
            .map(|c| c.into_owned())
            .collect();
    let key = PrivateKeyDer::from_pem_slice(p.client_key.as_bytes()).expect("client key");
    let config = ClientConfig::builder()
        .with_root_certificates(roots(p))
        .with_client_auth_cert(certs, key)
        .expect("client config");
    TlsConnector::from(Arc::new(config))
}

async fn mtls_connect(
    connector: &TlsConnector,
    addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    tokio::time::timeout(WAIT, connector.connect(name, tcp))
        .await
        .expect("tls in time")
        .expect("mTLS")
}

/// A free 127.0.0.1 port: bind, read, drop. Racy in principle,
/// fine for tests.
async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    l.local_addr().expect("addr")
}

/// Poll `f` every 50 ms until it returns true, panicking after `WAIT`.
async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn enrollment_acceptor(p: &Pki) -> Arc<SwappableAcceptor> {
    let config = enrollment_server_config(&p.server_cert, &p.server_key).expect("config");
    Arc::new(SwappableAcceptor::new(Arc::new(config)))
}

/// TLS client with NO client certificate (an enrolling node) that
/// still verifies the control plane against the cluster CA.
fn anonymous_client(p: &Pki) -> TlsConnector {
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots(p))
        .with_no_client_auth();
    // The enrollment listener drops peers that do not negotiate the
    // cluster ALPN before any budget can be exercised.
    config.alpn_protocols = vec![lorica_cluster::CLUSTER_ALPN.to_vec()];
    TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn enrollment_listener_follows_token_liveness() {
    install_ring();
    let p = pki();
    let addr = free_addr().await;
    let (tokens_tx, tokens_rx) = watch::channel(0u32);
    let stats = Arc::new(EnrollmentStats::default());
    let handle = EnrollmentListener::spawn(
        addr,
        enrollment_acceptor(&p),
        tokens_rx,
        PreAuthBudgets::default(),
        Arc::clone(&stats),
    );
    let mut bound = handle.bound.clone();

    // No live token: never bound, connects are refused.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(bound.borrow().is_none(), "must stay closed with 0 tokens");
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "closed listener must refuse connections"
    );

    // One live token: the socket opens.
    tokens_tx.send(1).expect("liveness send");
    eventually("listener to open", || bound.borrow_and_update().is_some()).await;
    let probe = tokio::time::timeout(WAIT, tokio::net::TcpStream::connect(addr))
        .await
        .expect("connect within budget")
        .expect("open listener must accept");
    drop(probe);

    // Last token gone: auto-close, subsequent connects refused.
    tokens_tx.send(0).expect("liveness send");
    eventually("listener to close", || bound.borrow_and_update().is_none()).await;
    eventually("connects to be refused again", || {
        // Poll: the OS frees the port a beat after the drop.
        futures_connect_refused(addr)
    })
    .await;

    assert!(stats.lifecycle_opens.load(Ordering::Relaxed) >= 1);
    assert!(stats.lifecycle_closes.load(Ordering::Relaxed) >= 1);
    handle.shutdown();
}

/// Synchronous-ish connect probe: true when the connection is refused.
fn futures_connect_refused(addr: SocketAddr) -> bool {
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err()
}

#[tokio::test]
async fn enrollment_budgets_drop_and_count() {
    install_ring();
    let p = pki();
    let addr = free_addr().await;
    let (tokens_tx, tokens_rx) = watch::channel(1u32);
    let stats = Arc::new(EnrollmentStats::default());
    let budgets = PreAuthBudgets {
        handshake_timeout: Duration::from_millis(200),
        per_conn_max_bytes: 512,
        ..PreAuthBudgets::default()
    };
    let handle = EnrollmentListener::spawn(
        addr,
        enrollment_acceptor(&p),
        tokens_rx,
        budgets,
        Arc::clone(&stats),
    );
    let mut bound = handle.bound.clone();
    eventually("listener to open", || bound.borrow_and_update().is_some()).await;

    // Budget 1: TCP connect, then silence. The TLS handshake budget
    // must drop us.
    let silent = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    eventually("handshake-timeout drop to be counted", || {
        stats.rejected_handshake_timeout.load(Ordering::Relaxed) >= 1
    })
    .await;
    drop(silent);

    // Budget 2: real TLS, then a frame announcing more bytes than the
    // per-connection budget.
    let connector = anonymous_client(&p);
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    let mut tls = tokio::time::timeout(WAIT, connector.connect(name, tcp))
        .await
        .expect("tls within budget")
        .expect("enrollment TLS accepts anonymous peers");
    let oversized = (513u64).to_le_bytes();
    let _ = tls.write_all(&oversized).await;
    let _ = tls.flush().await;
    eventually("byte-budget drop to be counted", || {
        stats.rejected_byte_budget.load(Ordering::Relaxed) >= 1
    })
    .await;

    drop(tokens_tx);
    handle.shutdown();
}

#[tokio::test]
async fn enrollment_per_source_cap_drops_the_excess_before_tls() {
    install_ring();
    let p = pki();
    let addr = free_addr().await;
    let (tokens_tx, tokens_rx) = watch::channel(1u32);
    let stats = Arc::new(EnrollmentStats::default());
    let budgets = PreAuthBudgets {
        max_per_source: 1,
        handshake_timeout: Duration::from_secs(5),
        ..PreAuthBudgets::default()
    };
    let handle = EnrollmentListener::spawn(
        addr,
        enrollment_acceptor(&p),
        tokens_rx,
        budgets,
        Arc::clone(&stats),
    );
    let mut bound = handle.bound.clone();
    eventually("listener to open", || bound.borrow_and_update().is_some()).await;

    // One silent connection holds 127.0.0.1's only slot; the second
    // from the same source is dropped at accept, before any TLS.
    let first = tokio::net::TcpStream::connect(addr).await.expect("tcp 1");
    eventually("first connection to be counted", || {
        stats.connections_total.load(Ordering::Relaxed) >= 1
    })
    .await;
    let second = tokio::net::TcpStream::connect(addr).await.expect("tcp 2");
    eventually("per-source drop to be counted", || {
        stats.rejected_per_source.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(stats.rejected_concurrent_handshakes.load(Ordering::Relaxed), 0);
    drop(second);
    drop(first);
    drop(tokens_tx);
    handle.shutdown();
}

#[tokio::test]
async fn session_cap_answers_retry_later_end_to_end() {
    install_ring();
    let p = pki();
    // One established session allowed; the gate's retry hint is what
    // the cap advertises.
    let (addr, stats, _acceptor, handle) = spawn_operational(&p, |c| {
        c.admission = Arc::new(AdmissionGate::new(8, 8, 7));
        c.max_sessions = 1;
    })
    .await;
    let connector = node_client(&p);

    // Client 1 completes the full handshake and keeps its session.
    let tls1 = mtls_connect(&connector, addr).await;
    let (ep1, _in1) = RpcEndpoint::<ClusterFrame>::from_stream(tls1);
    tokio::time::timeout(
        WAIT,
        client_handshake(&ep1, &cfg(49), "node-a", Duration::from_secs(5)),
    )
    .await
    .expect("handshake 1 in time")
    .expect("first session admitted");

    // Client 2 must get RETRY_LATER with the configured delay.
    let tls2 = mtls_connect(&connector, addr).await;
    let (ep2, in2) = RpcEndpoint::<ClusterFrame>::from_stream(tls2);
    let err = tokio::time::timeout(
        WAIT,
        client_handshake(&ep2, &cfg(49), "node-b", Duration::from_secs(5)),
    )
    .await
    .expect("handshake answered in time")
    .expect_err("second convergence must be told to retry");
    match err {
        HandshakeError::RetryLater { retry_after_s } => assert_eq!(retry_after_s, 7),
        other => panic!("expected RetryLater, got {other:?}"),
    }
    assert_eq!(stats.sessions_rejected_full.load(Ordering::Relaxed), 1);
    assert_eq!(stats.sessions_admitted.load(Ordering::Relaxed), 1);

    drop(ep2);
    drop(in2);
    drop(ep1);
    handle.shutdown();
}

#[tokio::test]
async fn authenticated_peer_without_the_cluster_alpn_is_dropped_and_counted() {
    install_ring();
    let p = pki();
    let (addr, stats, _acceptor, handle) = spawn_operational(&p, |_| {}).await;

    let tls = mtls_connect(&node_client_without_alpn(&p), addr).await;
    assert!(
        tls.get_ref().1.alpn_protocol().is_none(),
        "the test client must not have negotiated the token"
    );
    eventually("ALPN refusal to be counted", || {
        stats.alpn_refusals.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(stats.sessions_admitted.load(Ordering::Relaxed), 0);
    drop(tls);
    handle.shutdown();
}

#[tokio::test]
async fn silent_authenticated_peer_is_counted_and_holds_no_session_slot() {
    install_ring();
    let p = pki();
    let (addr, stats, _acceptor, handle) = spawn_operational(&p, |c| {
        c.opener_timeout = Duration::from_millis(300);
        c.max_sessions = 1;
    })
    .await;
    let connector = node_client(&p);

    // mTLS, then silence: dropped at the opener budget, counted, and
    // the single session slot is still free for a real peer.
    let silent = mtls_connect(&connector, addr).await;
    eventually("opener timeout to be counted", || {
        stats.opener_timeouts.load(Ordering::Relaxed) >= 1
    })
    .await;
    drop(silent);

    let tls = mtls_connect(&connector, addr).await;
    let (ep, _inc) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    tokio::time::timeout(
        WAIT,
        client_handshake(&ep, &cfg(49), "node-a", Duration::from_secs(5)),
    )
    .await
    .expect("handshake in time")
    .expect("the session slot was never taken by the silent peer");
    assert_eq!(stats.sessions_rejected_full.load(Ordering::Relaxed), 0);
    drop(ep);
    handle.shutdown();
}

#[tokio::test]
async fn per_source_cap_bounds_pre_session_connections_on_the_operational_listener() {
    install_ring();
    let p = pki();
    let (addr, stats, _acceptor, handle) = spawn_operational(&p, |c| {
        c.budgets.max_per_source = 1;
        c.budgets.handshake_timeout = Duration::from_secs(5);
    })
    .await;

    let first = tokio::net::TcpStream::connect(addr).await.expect("tcp 1");
    // Give the accept loop a beat to take the slot for the first.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let second = tokio::net::TcpStream::connect(addr).await.expect("tcp 2");
    eventually("per-source drop to be counted", || {
        stats.rejected_per_source.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(stats.rejected_concurrent_handshakes.load(Ordering::Relaxed), 0);
    drop(second);
    drop(first);
    handle.shutdown();
}

#[tokio::test]
async fn unsupported_method_is_refused_and_the_session_kept() {
    install_ring();
    let p = pki();
    let (addr, stats, _acceptor, handle) = spawn_operational(&p, |_| {}).await;

    let tls = mtls_connect(&node_client(&p), addr).await;
    let (ep, _inc) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    tokio::time::timeout(
        WAIT,
        client_handshake(&ep, &cfg(49), "node-a", Duration::from_secs(5)),
    )
    .await
    .expect("handshake in time")
    .expect("session admitted");

    // A newer peer's method: well-formed shape, unknown body_kind.
    let newer = ClusterRequest {
        sequence: 0,
        body_kind: 25,
        body: None,
    };
    let resp = tokio::time::timeout(WAIT, ep.request(newer, Duration::from_secs(5)))
        .await
        .expect("answered in time")
        .expect("answered, not dropped");
    assert_eq!(resp.cluster_status(), ClusterStatus::UnsupportedMethod);

    // The session is intact: a heartbeat still flows.
    let hb = ClusterRequest::heartbeat(Heartbeat { timestamp_ms: 42 });
    let resp = tokio::time::timeout(WAIT, ep.request(hb, Duration::from_secs(5)))
        .await
        .expect("answered in time")
        .expect("heartbeat served after the refusal");
    assert_eq!(resp.cluster_status(), ClusterStatus::Ok);
    assert_eq!(stats.unsupported_methods.load(Ordering::Relaxed), 1);
    assert_eq!(stats.heartbeats_served.load(Ordering::Relaxed), 1);

    // A forged discriminator (Hello's tag on a Heartbeat body) is a
    // violation: answered as such, then the session is dropped.
    let forged = ClusterRequest {
        sequence: 0,
        body_kind: BODY_KIND_HELLO,
        body: Some(cluster_request::Body::Heartbeat(Heartbeat {
            timestamp_ms: 1,
        })),
    };
    let resp = tokio::time::timeout(WAIT, ep.request(forged, Duration::from_secs(5)))
        .await
        .expect("answered in time")
        .expect("violation is answered before the drop");
    assert_eq!(resp.cluster_status(), ClusterStatus::ProtocolViolation);
    eventually("session to be torn down server-side", || {
        stats.sessions_ended.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(stats.protocol_violations.load(Ordering::Relaxed), 1);
    // The connection is gone: the next request cannot be served (the
    // endpoint learns of the drop the way the dialer does, by failing
    // a request, not by polling).
    let hb = ClusterRequest::heartbeat(Heartbeat { timestamp_ms: 43 });
    assert!(
        ep.request(hb, Duration::from_secs(2)).await.is_err(),
        "a request after the violation must fail"
    );

    drop(ep);
    handle.shutdown();
}

#[tokio::test]
async fn dialer_reconnects_after_control_plane_restart() {
    install_ring();
    let p = pki();
    let (addr, _stats, acceptor, handle) = spawn_operational(&p, |_| {}).await;

    // Dial by NAME so resolution is exercised on every attempt.
    let mut dialer_config = DialerConfig::new(
        &format!("localhost:{}", addr.port()),
        CP_HOST,
        p.ca.cert_pem(),
        &p.client_cert,
        &p.client_key,
        49,
    )
    .with_node_name("node-a");
    dialer_config.heartbeat_interval = Duration::from_millis(100);
    dialer_config.request_timeout = Duration::from_secs(1);
    dialer_config.connect_timeout = Duration::from_secs(2);
    dialer_config.base_backoff = Duration::from_millis(50);
    dialer_config.default_backoff_cap = Duration::from_millis(400);
    let dialer = Dialer::spawn(dialer_config).expect("dialer spawns");
    let connection = dialer.connection();

    eventually("dialer to establish", || connection.current().is_some()).await;
    let first_generation = connection.current().expect("session").generation;
    let dialer_stats = dialer.stats();
    eventually("heartbeats to flow", || {
        dialer_stats.heartbeats_ok.load(Ordering::Relaxed) >= 2
    })
    .await;

    // Control-plane restart: tear the listener (and its sessions)
    // down; the connection slot must empty.
    handle.shutdown();
    eventually("connection slot to empty", || connection.current().is_none()).await;

    // Restart on the SAME address; the dialer must come back on its
    // own, with a new session generation, and heartbeats must resume.
    let listener = tokio::net::TcpListener::bind(addr).await.expect("rebind");
    let handle2 = OperationalListener::spawn(OperationalConfig::new(listener, acceptor, cfg(49)));
    eventually("dialer to reconnect", || connection.current().is_some()).await;
    assert!(connection.current().expect("session").generation > first_generation);
    let resumed_floor = dialer_stats.heartbeats_ok.load(Ordering::Relaxed) + 2;
    eventually("heartbeats to resume", || {
        dialer_stats.heartbeats_ok.load(Ordering::Relaxed) >= resumed_floor
    })
    .await;
    assert!(dialer_stats.disconnects.load(Ordering::Relaxed) >= 1);

    dialer.shutdown();
    handle2.shutdown();
}
