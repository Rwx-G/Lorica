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

//! In-process mutual-TLS integration tests for the cluster plane
//! (Story 9.2 AC #2/#4/#5): a real tokio-rustls handshake over a real
//! TCP socket on 127.0.0.1, then the cluster session handshake over an
//! `RpcEndpoint<ClusterFrame>`.
//!
//! The EKU split (Story 9.3 AC #2) is asserted behaviourally here: a
//! `clientAuth`-only leaf cannot pass server verification, and a
//! `serverAuth`-only leaf cannot pass the client verifier.

use std::sync::Arc;
use std::time::Duration;

use lorica_cluster::handshake::{client_handshake, serve_hello, HandshakeConfig};
use lorica_cluster::messages::ClusterFrame;
use lorica_cluster::{
    client_config, operational_server_config, ClusterCa, ClusterStatus, HandshakeError,
    PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION,
};
use lorica_command::RpcEndpoint;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const CP_HOST: &str = "cp.cluster.internal";

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

fn local_cfg(schema: u32) -> HandshakeConfig {
    HandshakeConfig {
        protocol_min: PROTOCOL_MIN_COMPATIBLE,
        protocol_max: PROTOCOL_VERSION,
        schema_version: schema,
    }
}

/// Accept one TLS connection and serve one Hello with the given
/// server-side config; returns the server's view of the outcome.
async fn one_shot_server(
    listener: tokio::net::TcpListener,
    acceptor: TlsAcceptor,
    server_cfg: HandshakeConfig,
    fleet_size_hint: u32,
) -> Result<Result<lorica_cluster::messages::HelloAck, ClusterStatus>, String> {
    let (tcp, _peer) = listener.accept().await.map_err(|e| e.to_string())?;
    let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    let (_endpoint, mut incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    let first = incoming
        .recv()
        .await
        .ok_or_else(|| "no opener".to_string())?;
    let outcome = serve_hello(first, &server_cfg, fleet_size_hint)
        .await
        .map_err(|e| e.to_string())?;
    // Dropping the endpoint aborts its writer task, which may still
    // hold the queued reply; stay alive until the CLIENT hangs up
    // (recv() returns None on peer EOF) so the reply is flushed.
    while incoming.recv().await.is_some() {}
    Ok(outcome)
}

async fn connect_client(
    addr: std::net::SocketAddr,
    p: &Pki,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let cfg = client_config(p.ca.cert_pem(), &p.client_cert, &p.client_key)
        .map_err(|e| e.to_string())?;
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(CP_HOST.to_string()).map_err(|e| e.to_string())?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())
}

#[tokio::test]
async fn full_mtls_session_handshake_round_trips() {
    install_ring();
    let p = pki();
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("cfg");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server = tokio::spawn(one_shot_server(listener, acceptor, local_cfg(49), 3));

    let tls = connect_client(addr, &p).await.expect("mTLS connect");
    let (endpoint, incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    let ack = client_handshake(&endpoint, &local_cfg(49), "node-a", Duration::from_secs(5))
        .await
        .expect("handshake admitted");
    assert_eq!(ack.negotiated_version, PROTOCOL_VERSION);
    assert_eq!(ack.schema_version, 49);
    assert_eq!(ack.fleet_size_hint, 3);

    // The one-shot server holds its endpoint until CLIENT EOF (so its
    // reply is flushed before the writer aborts); hang up before
    // awaiting it or both sides wait on each other.
    drop(endpoint);
    drop(incoming);
    let server_outcome = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must exit once the client hangs up")
        .expect("server task")
        .expect("server side");
    assert!(server_outcome.is_ok(), "server must have admitted");
}

#[tokio::test]
async fn client_without_certificate_fails_the_tls_handshake() {
    install_ring();
    let p = pki();
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("cfg");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    // Server side: the accept must fail (certificate required).
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        acceptor.accept(tcp).await.map(|_| ())
    });

    // Client WITHOUT a certificate: trusts the CA but presents nothing.
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer};
    for cert in CertificateDer::pem_slice_iter(p.ca.cert_pem().as_bytes()) {
        roots.add(cert.expect("ca der")).expect("root add");
    }
    let no_cert_cfg = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(no_cert_cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    let client_result = connector.connect(name, tcp).await;

    // rustls surfaces the refusal on at least one side (the server
    // always refuses; the client may see the close before or after its
    // own handshake future resolves depending on timing).
    let server_result = server.await.expect("server task");
    assert!(
        server_result.is_err() || client_result.is_err(),
        "an unauthenticated client must not complete the operational handshake"
    );
    assert!(
        server_result.is_err(),
        "the operational acceptor must refuse a certificate-less peer"
    );
}

#[tokio::test]
async fn client_leaf_cannot_serve_and_server_leaf_cannot_dial() {
    install_ring();
    let p = pki();

    // A clientAuth-only leaf on the SERVER side: the dialer's webpki
    // verification must refuse it (EKU serverAuth missing).
    let swapped_server_config =
        operational_server_config(p.ca.cert_pem(), &p.client_cert, &p.client_key).expect("cfg");
    let acceptor = TlsAcceptor::from(Arc::new(swapped_server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        acceptor.accept(tcp).await.map(|_| ())
    });
    let client_result = connect_client(addr, &p).await;
    assert!(
        client_result.is_err(),
        "a clientAuth-only leaf must fail server-name verification"
    );
    let _ = server.await;

    // A serverAuth-only leaf on the CLIENT side: the operational
    // verifier must refuse it (EKU clientAuth missing).
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("cfg");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.expect("tcp accept");
        acceptor.accept(tcp).await.map(|_| ())
    });
    let bad_client_cfg = client_config(p.ca.cert_pem(), &p.server_cert, &p.server_key)
        .expect("config builds; refusal happens in the handshake");
    let connector = TlsConnector::from(Arc::new(bad_client_cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("tcp");
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    let client_result = connector.connect(name, tcp).await;
    let server_result = server.await.expect("server task");
    assert!(
        server_result.is_err() || client_result.is_err(),
        "a serverAuth-only leaf must not pass the client verifier"
    );
    assert!(
        server_result.is_err(),
        "the operational verifier must refuse a serverAuth-only client leaf"
    );
}

#[tokio::test]
async fn schema_and_version_refusals_reach_the_dialer_distinctly() {
    install_ring();
    let p = pki();
    let server_config =
        operational_server_config(p.ca.cert_pem(), &p.server_cert, &p.server_key).expect("cfg");

    // Follower schema BELOW the control plane's: SchemaTooOld.
    let acceptor = TlsAcceptor::from(Arc::new(server_config.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(one_shot_server(listener, acceptor, local_cfg(50), 1));
    let tls = connect_client(addr, &p).await.expect("mTLS connect");
    let (endpoint, incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    let err = client_handshake(&endpoint, &local_cfg(49), "node-a", Duration::from_secs(5))
        .await
        .expect_err("must be refused");
    assert!(
        matches!(err, HandshakeError::Refused(ClusterStatus::SchemaTooOld)),
        "got {err:?}"
    );
    // Hang up so the EOF-waiting one-shot server can exit (see the
    // round-trip test).
    drop(endpoint);
    drop(incoming);
    let server_outcome = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must exit once the client hangs up")
        .expect("task")
        .expect("served");
    assert_eq!(server_outcome, Err(ClusterStatus::SchemaTooOld));
}
