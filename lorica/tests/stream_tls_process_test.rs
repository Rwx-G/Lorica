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

//! The real binary carries TLS stream traffic (Story 12.4 Lot E), in
//! single-process mode and in worker mode, for two streams written to
//! the store before the node starts:
//!
//! - a passthrough stream routing two server names to two loopback TLS
//!   backends, each presenting a certificate for its own name only, so a
//!   client that verifies the name it asked for completed its handshake
//!   with the backend of that name; a third name is refused;
//! - a terminating stream whose certificate is in the store, answering a
//!   verifying client and forwarding its plaintext to an echo backend.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use lorica_config::crypto::EncryptionKey;
use lorica_config::models::{
    Backend, Certificate, HealthCheck, HealthStatus, LifecycleState, Stream, StreamBackend,
    StreamMatchRule, StreamMatcher, StreamProtocol, StreamTlsMode, StreamTlsTerminate,
};
use lorica_config::ConfigStore;
use lorica_tls::RootCertStore;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

/// Longer than the startup of an empty node, which runs its migrations
/// and generates the management certificate before it binds.
const START_DEADLINE: Duration = Duration::from_secs(90);
const STOP_DEADLINE: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const PASSTHROUGH_ID: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
const TERMINATE_ID: &str = "7a2d2b63-6c1f-4a8e-8b62-2b8d6b2c3d4e";
const BACKEND_A_ID: &str = "0b7e3c2a-1d4f-4e5a-8b6c-7d8e9f0a1b2c";
const BACKEND_B_ID: &str = "1c8f4d3b-2e5a-4f6b-9c7d-8e9f0a1b2c3d";
const ECHO_ID: &str = "2d9a5e4c-3f6b-4a7c-8d8e-9f0a1b2c3d4e";
const CERT_ID: &str = "3c9d2f4e-8a1b-4c5d-9e6f-0a1b2c3d4e5f";

const NAME_A: &str = "a.stream-tls.test";
const NAME_B: &str = "b.stream-tls.test";
const NAME_UNROUTED: &str = "c.stream-tls.test";
const NAME_TERMINATED: &str = "t.stream-tls.test";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("test setup: a free port")
        .port()
}

fn crypto() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A CA the clients trust, and the leaves it issues.
struct Pki {
    ca_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Pki {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("test setup: CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().expect("test setup: CA key");
        let cert = params
            .self_signed(&key)
            .expect("test setup: CA certificate");
        Pki {
            ca_der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A leaf for `name` alone: its certificate and its key.
    fn leaf(&self, name: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("test setup: leaf key");
        let cert = CertificateParams::new(vec![name.to_string()])
            .expect("test setup: leaf params")
            .signed_by(&key, &self.issuer)
            .expect("test setup: leaf certificate");
        (cert, key)
    }

    /// A client verifying the server's certificate against this CA.
    fn client(&self) -> Arc<rustls::ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).expect("test setup: root");
        Arc::new(
            lorica_tls::http_client::config_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

/// A TLS backend on loopback presenting a certificate for `name` only.
/// On each connection it first writes its name, then echoes.
fn tls_backend(pki: &Pki, name: &'static str) -> SocketAddr {
    let (cert, key) = pki.leaf(name);
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(crypto())
            .with_safe_default_protocol_versions()
            .expect("test setup: versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .expect("test setup: backend certificate"),
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("test setup: backend bind");
    let addr = listener.local_addr().expect("test setup: backend addr");
    std::thread::spawn(move || {
        for socket in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let Ok(connection) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(connection, socket);
                if tls.write_all(name.as_bytes()).is_err() || tls.flush().is_err() {
                    return;
                }
                let mut buf = [0u8; 1024];
                while let Ok(n) = tls.read(&mut buf) {
                    if n == 0 || tls.write_all(&buf[..n]).is_err() || tls.flush().is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A plaintext echo backend on loopback.
fn echo_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test setup: echo bind");
    let addr = listener.local_addr().expect("test setup: echo addr");
    std::thread::spawn(move || {
        for mut socket in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = socket.read(&mut buf) {
                    if n == 0 || socket.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn backend(id: &str, address: SocketAddr) -> Backend {
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: id.into(),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Unknown,
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

fn rule(name: &str, server_name: &str) -> StreamMatchRule {
    StreamMatchRule {
        name: name.into(),
        matcher: StreamMatcher::Tls {
            server_names: vec![server_name.into()],
            alpn: Vec::new(),
        },
    }
}

fn tcp_stream(id: &str, name: &str, port: u16) -> Stream {
    let mut stream = Stream::new(
        id.into(),
        name.into(),
        StreamProtocol::Tcp,
        "127.0.0.1".parse().expect("an address"),
        port,
        port,
        Utc::now(),
    );
    // Every backend is on loopback, on no port of this node.
    stream.allow_local_backend = true;
    // Small enough for the fd budget of any test container.
    stream.max_connections = 16;
    stream
}

fn link(stream_id: &str, backend_id: &str, rule: &str) -> StreamBackend {
    let mut link = StreamBackend::primary(stream_id, backend_id);
    link.rule = Some(rule.into());
    link
}

/// The ports of the two streams.
struct Ports {
    passthrough: u16,
    terminate: u16,
}

/// Write both streams, their backends and the terminating stream's
/// certificate into the store of `data_dir`, keyed as the node will
/// open it.
fn seed(data_dir: &Path, pki: &Pki, avoid: &[u16]) -> Ports {
    let key = EncryptionKey::load_or_create(&data_dir.join("encryption.key"))
        .expect("test setup: encryption key");
    let store =
        ConfigStore::open(&data_dir.join("lorica.db"), Some(key)).expect("test setup: store");
    // The backends hold their ports from here, so no stream port can be
    // one of theirs: an answer can only come through the node.
    let backend_a = tls_backend(pki, NAME_A);
    let backend_b = tls_backend(pki, NAME_B);
    let echo = echo_backend();
    let mut free = std::iter::repeat_with(free_port).filter(|port| !avoid.contains(port));
    let passthrough = free.next().expect("a free port");
    let ports = Ports {
        passthrough,
        terminate: free.find(|port| *port != passthrough).expect("a free port"),
    };
    for (id, addr) in [
        (BACKEND_A_ID, backend_a),
        (BACKEND_B_ID, backend_b),
        (ECHO_ID, echo),
    ] {
        store
            .create_backend(&backend(id, addr))
            .expect("test setup: backend");
    }

    let mut passthrough = tcp_stream(PASSTHROUGH_ID, "passthrough", ports.passthrough);
    passthrough.tls_mode = StreamTlsMode::Passthrough;
    passthrough.match_rules = vec![rule("a", NAME_A), rule("b", NAME_B)];
    store
        .create_stream(&passthrough)
        .expect("test setup: passthrough stream");
    store
        .set_stream_links(
            PASSTHROUGH_ID,
            &[
                link(PASSTHROUGH_ID, BACKEND_A_ID, "a"),
                link(PASSTHROUGH_ID, BACKEND_B_ID, "b"),
            ],
        )
        .expect("test setup: passthrough links");

    let (cert, cert_key) = pki.leaf(NAME_TERMINATED);
    let now = Utc::now();
    store
        .create_certificate(&Certificate {
            id: CERT_ID.into(),
            domain: NAME_TERMINATED.into(),
            san_domains: vec![NAME_TERMINATED.into()],
            fingerprint: String::new(),
            cert_pem: cert.pem(),
            key_pem: cert_key.serialize_pem(),
            issuer: "test CA".into(),
            not_before: now - chrono::Duration::days(1),
            not_after: now + chrono::Duration::days(30),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
            adcs_authority_id: None,
            adcs_template: None,
            adcs_template_oid: None,
            adcs_request_id: None,
        })
        .expect("test setup: certificate");
    let mut terminate = tcp_stream(TERMINATE_ID, "terminate", ports.terminate);
    terminate.tls_mode = StreamTlsMode::Terminate;
    terminate.match_rules = vec![rule("t", NAME_TERMINATED)];
    terminate.tls_terminate = Some(StreamTlsTerminate {
        certificate_ids: vec![CERT_ID.into()],
        client_auth: None,
    });
    store
        .create_stream(&terminate)
        .expect("test setup: terminating stream");
    store
        .set_stream_links(TERMINATE_ID, &[link(TERMINATE_ID, ECHO_ID, "t")])
        .expect("test setup: terminating link");
    ports
}

/// One verified TLS exchange with the stream on `port` for `name`: the
/// payload written, then `expected` read back, or why not.
fn exchange(
    client: &Arc<rustls::ClientConfig>,
    port: u16,
    name: &str,
    payload: &[u8],
    expected: &[u8],
) -> Result<Vec<u8>, String> {
    let server_name = ServerName::try_from(name.to_string()).map_err(|e| e.to_string())?;
    let connection = rustls::ClientConnection::new(Arc::clone(client), server_name)
        .map_err(|e| e.to_string())?;
    let socket = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(connection, socket);
    tls.write_all(payload).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())?;
    let mut got = vec![0u8; expected.len()];
    tls.read_exact(&mut got).map_err(|e| e.to_string())?;
    Ok(got)
}

fn stop(node: &mut Child) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", node.id()))
        .status();
    let started = Instant::now();
    while started.elapsed() < STOP_DEADLINE {
        if let Ok(Some(_)) = node.try_wait() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = node.kill();
    let _ = node.wait();
}

/// What each exchange gave.
#[derive(Debug, Default)]
struct Outcomes {
    terminated: Option<Result<Vec<u8>, String>>,
    name_a: Option<Result<Vec<u8>, String>>,
    name_b: Option<Result<Vec<u8>, String>>,
    unrouted: Option<Result<Vec<u8>, String>>,
}

fn a_node_carries_tls_streams(workers: &str) {
    let data_dir = tempfile::tempdir().expect("test setup: data dir");
    let pki = Pki::new();
    let client = pki.client();
    let management = free_port();
    let http = free_port();
    let https = free_port();
    let ports = seed(data_dir.path(), &pki, &[management, http, https]);
    let log_path = data_dir.path().join("node.log");
    let log = std::fs::File::create(&log_path).expect("test setup: log file");

    let mut node = Command::new(env!("CARGO_BIN_EXE_lorica"))
        .arg("--data-dir")
        .arg(data_dir.path())
        .args(["--workers", workers])
        .args(["--management-port", &management.to_string()])
        .args(["--http-port", &http.to_string()])
        .args(["--https-port", &https.to_string()])
        .args(["--log-format", "text"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().expect("test setup: log handle"))
        .stderr(log)
        .spawn()
        .expect("test setup: the node starts");

    let mut outcomes = Outcomes::default();
    let started = Instant::now();
    // Both streams are bound in the same reconcile pass; waiting on the
    // terminating one first also proves its certificate is served.
    let terminated = loop {
        if let Ok(Some(status)) = node.try_wait() {
            break Err(format!("the node exited: {status}"));
        }
        match exchange(
            &client,
            ports.terminate,
            NAME_TERMINATED,
            b"terminated by the node",
            b"terminated by the node",
        ) {
            Ok(got) => break Ok(got),
            Err(e) if started.elapsed() > START_DEADLINE => break Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    };
    let up = terminated.is_ok();
    outcomes.terminated = Some(terminated);
    if up {
        let expected_a = [NAME_A.as_bytes(), b"to a"].concat();
        let expected_b = [NAME_B.as_bytes(), b"to b"].concat();
        outcomes.name_a = Some(exchange(
            &client,
            ports.passthrough,
            NAME_A,
            b"to a",
            &expected_a,
        ));
        outcomes.name_b = Some(exchange(
            &client,
            ports.passthrough,
            NAME_B,
            b"to b",
            &expected_b,
        ));
        outcomes.unrouted = Some(exchange(
            &client,
            ports.passthrough,
            NAME_UNROUTED,
            b"to nobody",
            b"to nobody",
        ));
    }
    stop(&mut node);

    let mut output = String::new();
    let _ = std::fs::File::open(&log_path).and_then(|mut f| f.read_to_string(&mut output));
    let got = outcomes
        .terminated
        .take()
        .expect("the terminating stream was tried")
        .unwrap_or_else(|e| panic!("no echo through the terminating stream ({e}):\n{output}"));
    assert_eq!(got, b"terminated by the node", "{output}");
    assert_eq!(
        outcomes.name_a.take().expect("name a was tried"),
        Ok([NAME_A.as_bytes(), b"to a"].concat()),
        "{output}"
    );
    assert_eq!(
        outcomes.name_b.take().expect("name b was tried"),
        Ok([NAME_B.as_bytes(), b"to b"].concat()),
        "{output}"
    );
    assert!(
        outcomes
            .unrouted
            .take()
            .expect("the unrouted name was tried")
            .is_err(),
        "a name no rule matches is refused:\n{output}"
    );
}

#[test]
fn a_single_process_node_carries_passthrough_and_terminating_streams() {
    a_node_carries_tls_streams("0");
}

#[test]
fn a_worker_mode_node_carries_passthrough_and_terminating_streams() {
    a_node_carries_tls_streams("2");
}
