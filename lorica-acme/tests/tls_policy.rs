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

//! The ACME client verifies the CA with the shared outbound TLS policy.
//!
//! The directory is a local TLS server whose self-signed certificate is
//! trusted only through `SSL_CERT_FILE`, the way the e2e Pebble profile
//! gets its fixture CA trusted: the platform half of
//! `lorica_tls::http_client::public` reads it. The same certificate is
//! refused while `SSL_CERT_FILE` names another one, and once trusted the
//! client offers what the policy offers (`http/1.1` alone) to a server
//! that would have taken `h2`.
//!
//! One test, alone in its binary, because it sets process environment
//! variables: nothing else runs beside it to read them.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use lorica_acme::{begin_manual_dns01, AcmeConfig, AcmeError};
use lorica_tls::{CertificateDer, PrivateKeyDer, ServerConfig, TlsAcceptor};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct Identity {
    pem: String,
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// A self-signed certificate for `127.0.0.1`. `subject` tells two of
/// them apart, so one is never taken for the issuer of the other.
fn self_signed(subject: &str) -> Identity {
    let key: rcgen::KeyPair = rcgen::KeyPair::generate().expect("test setup: key");
    let mut params: rcgen::CertificateParams = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(Ipv4Addr::LOCALHOST.into())];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, subject);
    let signed: rcgen::Certificate = params.self_signed(&key).expect("test setup: certificate");
    Identity {
        pem: signed.pem(),
        certificate: signed.der().clone(),
        key: PrivateKeyDer::try_from(key.serialize_der()).expect("test setup: key der"),
    }
}

fn acceptor(server: &Identity) -> TlsAcceptor {
    let mut config: ServerConfig =
        ServerConfig::builder_with_provider(lorica_tls::http_client::crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("test setup: versions")
            .with_no_client_auth()
            .with_single_cert(vec![server.certificate.clone()], server.key.clone_key())
            .expect("test setup: server config");
    // Both, so the client's offer is what decides.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

/// What the directory server saw of the one connection it accepted.
#[derive(Debug)]
enum Seen {
    /// The handshake failed, with the server's error.
    Refused(String),
    /// A request came through: its head, and the protocol ALPN settled.
    Request { head: String, alpn: Option<Vec<u8>> },
}

/// Accept one connection and answer its request with a 503, which ends
/// the ACME flow on the directory fetch.
async fn serve_one(listener: TcpListener, acceptor: TlsAcceptor) -> Seen {
    let (tcp, _) = listener.accept().await.expect("test setup: accept");
    let mut tls = match acceptor.accept(tcp).await {
        Ok(tls) => tls,
        Err(err) => return Seen::Refused(format!("{err:?}")),
    };
    let alpn: Option<Vec<u8>> = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let mut head: Vec<u8> = Vec::new();
    let mut chunk: [u8; 1024] = [0; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read: usize = tls.read(&mut chunk).await.expect("test setup: read");
        if read == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..read]);
    }
    tls.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
    )
    .await
    .expect("test setup: write");
    let _ = tls.shutdown().await;
    Seen::Request {
        head: String::from_utf8_lossy(&head).into_owned(),
        alpn,
    }
}

/// Start a manual DNS-01 order against a directory served with
/// `server`'s certificate, `SSL_CERT_FILE` naming `trusted`.
async fn attempt(server: &Identity, trusted: &Path) -> (Result<(), AcmeError>, Seen) {
    let listener: TcpListener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("test setup: bind");
    let port: u16 = listener.local_addr().expect("test setup: addr").port();
    std::env::set_var("SSL_CERT_FILE", trusted);
    std::env::set_var(
        "LORICA_ACME_DIRECTORY_URL",
        format!("https://127.0.0.1:{port}/dir"),
    );
    let served = tokio::spawn(serve_one(listener, acceptor(server)));
    let outcome: Result<(), AcmeError> =
        begin_manual_dns01(&AcmeConfig::default(), &["www.example.com".to_owned()])
            .await
            .map(|_| ());
    let seen: Seen = tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("the ACME client never reached the directory")
        .expect("test setup: server task");
    (outcome, seen)
}

#[tokio::test]
async fn the_acme_directory_is_verified_with_the_shared_policy() {
    let directory: Identity = self_signed("ACME directory");
    let unrelated: Identity = self_signed("another CA");
    let dir: PathBuf =
        std::env::temp_dir().join(format!("lorica-acme-tls-policy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("test setup: temp dir");
    let directory_pem: PathBuf = dir.join("directory.pem");
    let unrelated_pem: PathBuf = dir.join("unrelated.pem");
    std::fs::write(&directory_pem, &directory.pem).expect("test setup: write pem");
    std::fs::write(&unrelated_pem, &unrelated.pem).expect("test setup: write pem");

    let (outcome, seen) = attempt(&directory, &unrelated_pem).await;
    assert!(matches!(outcome, Err(AcmeError::Account(_))), "{outcome:?}");
    match seen {
        Seen::Refused(err) => assert!(err.contains("UnknownCA"), "{err}"),
        Seen::Request { .. } => panic!("an untrusted directory was sent a request: {seen:?}"),
    }

    let (outcome, seen) = attempt(&directory, &directory_pem).await;
    // The directory answered 503, so the flow stops right after it.
    assert!(matches!(outcome, Err(AcmeError::Account(_))), "{outcome:?}");
    match seen {
        Seen::Request { head, alpn } => {
            assert!(head.starts_with("GET /dir HTTP/1.1\r\n"), "{head}");
            assert!(
                head.to_ascii_lowercase()
                    .contains("\r\nuser-agent: instant-acme/"),
                "{head}"
            );
            assert_eq!(alpn.as_deref(), Some(b"http/1.1".as_slice()));
        }
        Seen::Refused(err) => {
            panic!("a directory trusted through SSL_CERT_FILE was refused: {err}")
        }
    }

    let _ = std::fs::remove_dir_all(&dir);
}
