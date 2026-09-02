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
//! dialer (Story 9.2 AC #2/#3/#9/#10) over real mTLS on 127.0.0.1.
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
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use lorica_cluster::handshake::{client_handshake, HandshakeConfig};
use lorica_cluster::listener::{
    EnrollmentListener, EnrollmentStats, OperationalListener, OperationalStats, PreAuthBudgets,
};
use lorica_cluster::messages::ClusterFrame;
use lorica_cluster::{
    client_config, enrollment_server_config, operational_server_config, AdmissionGate, ClusterCa,
    Dialer, DialerConfig, HandshakeError, SwappableAcceptor, PROTOCOL_MIN_COMPATIBLE,
    PROTOCOL_VERSION,
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
    HandshakeConfig {
        protocol_min: PROTOCOL_MIN_COMPATIBLE,
        protocol_max: PROTOCOL_VERSION,
        schema_version: schema,
    }
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
    let mut roots = RootCertStore::empty();
    use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer};
    for cert in CertificateDer::pem_slice_iter(p.ca.cert_pem().as_bytes()).flatten() {
        roots.add(cert.into_owned()).expect("ca root");
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
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
async fn admission_gate_answers_retry_later_end_to_end() {
    install_ring();
    let p = pki();
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("config");
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(server_config)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stats = Arc::new(OperationalStats::default());
    let handle = OperationalListener::spawn(
        listener,
        acceptor,
        cfg(49),
        Arc::new(AtomicU32::new(2)),
        Arc::new(AdmissionGate::new(1, 0, 7)),
        Arc::clone(&stats),
    );

    // Client 1 completes TLS and then sits on its admission permit by
    // never sending a Hello.
    let tls_cfg = client_config(p.ca.cert_pem(), &p.client_cert, &p.client_key).expect("client");
    let connector = TlsConnector::from(Arc::new(tls_cfg));
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    let tcp1 = tokio::net::TcpStream::connect(addr).await.expect("tcp1");
    let tls1 = tokio::time::timeout(WAIT, connector.connect(name.clone(), tcp1))
        .await
        .expect("tls1 in time")
        .expect("mTLS 1");
    let (_ep1, _in1) = RpcEndpoint::<ClusterFrame>::from_stream(tls1);
    // Give the server a beat to take the only admission slot.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Client 2 must get RETRY_LATER with the configured delay.
    let tcp2 = tokio::net::TcpStream::connect(addr).await.expect("tcp2");
    let tls2 = tokio::time::timeout(WAIT, connector.connect(name, tcp2))
        .await
        .expect("tls2 in time")
        .expect("mTLS 2");
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
    assert_eq!(stats.sessions_retry_later.load(Ordering::Relaxed), 1);

    drop(ep2);
    drop(in2);
    handle.shutdown();
}

#[tokio::test]
async fn dialer_reconnects_after_control_plane_restart() {
    install_ring();
    let p = pki();
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("config");
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(server_config)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stats = Arc::new(OperationalStats::default());
    let handle = OperationalListener::spawn(
        listener,
        Arc::clone(&acceptor),
        cfg(49),
        Arc::new(AtomicU32::new(3)),
        Arc::new(AdmissionGate::new(8, 8, 5)),
        Arc::clone(&stats),
    );

    let dialer = Dialer::spawn(DialerConfig {
        control_plane_addr: addr.to_string(),
        server_name: CP_HOST.to_string(),
        ca_pem: p.ca.cert_pem().to_string(),
        client_cert_pem: p.client_cert.clone(),
        client_key_pem: p.client_key.clone(),
        handshake: cfg(49),
        node_name: "node-a".to_string(),
        heartbeat_interval: Duration::from_millis(100),
        request_timeout: Duration::from_secs(1),
        base_backoff: Duration::from_millis(50),
        default_backoff_cap: Duration::from_millis(400),
    })
    .expect("dialer spawns");
    let connection = dialer.connection();

    eventually("dialer to establish", || connection.current().is_some()).await;
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
    // own and heartbeats must resume.
    let listener = tokio::net::TcpListener::bind(addr).await.expect("rebind");
    let handle2 = OperationalListener::spawn(
        listener,
        acceptor,
        cfg(49),
        Arc::new(AtomicU32::new(3)),
        Arc::new(AdmissionGate::new(8, 8, 5)),
        Arc::new(OperationalStats::default()),
    );
    eventually("dialer to reconnect", || connection.current().is_some()).await;
    let resumed_floor = dialer_stats.heartbeats_ok.load(Ordering::Relaxed) + 2;
    eventually("heartbeats to resume", || {
        dialer_stats.heartbeats_ok.load(Ordering::Relaxed) >= resumed_floor
    })
    .await;
    assert!(dialer_stats.disconnects.load(Ordering::Relaxed) >= 1);

    dialer.shutdown();
    handle2.shutdown();
}
