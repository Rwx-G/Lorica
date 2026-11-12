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

//! Real handshakes against an HTTPS listener for a client dialing an IP.
//!
//! RFC 6066 forbids an IP literal in SNI, so a browser opening
//! `https://192.0.2.10` sends a ClientHello without SNI. The listener is
//! built as `startup/single.rs` and `startup/worker.rs` build it,
//! `TlsSettings::with_resolver` over the shared `CertResolver`, and every
//! accepted socket carries the socket digest `Listener::accept` gives it,
//! from which the acceptor reads the local address. The client is rustls
//! dialing `ServerName::IpAddress`, which sends no SNI and verifies the
//! certificate against an `iPAddress` SAN.

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Once};
use std::time::Duration;

use lorica_core::listeners::tls::{Acceptor, TlsSettings};
use lorica_core::protocols::l4::stream::Stream;
use lorica_core::protocols::{GetSocketDigest, SocketDigest};
use lorica_tls::cert_resolver::{CertData, CertResolver};
use lorica_tls::RootCertStore;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};
use rustls::ClientConfig as RusTlsClientConfig;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::{TcpListener, TcpStream};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A CA the client trusts, and the leaves it issues.
struct Pki {
    ca_der: CertificateDer<'static>,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Pki {
        let mut params: CertificateParams = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key: KeyPair = KeyPair::generate().unwrap();
        let cert: rcgen::Certificate = params.self_signed(&key).unwrap();
        Pki {
            ca_der: cert.der().clone(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    /// A leaf for `domain` carrying `dns` and `ips` as SAN entries, the
    /// row the resolver loads, and the leaf's DER.
    fn leaf(&self, domain: &str, dns: &[&str], ips: &[IpAddr]) -> (CertData, Vec<u8>) {
        let mut params: CertificateParams = CertificateParams::new(
            dns.iter()
                .map(|d: &&str| d.to_string())
                .collect::<Vec<String>>(),
        )
        .unwrap();
        params
            .subject_alt_names
            .extend(ips.iter().map(|ip: &IpAddr| SanType::IpAddress(*ip)));
        let key: KeyPair = KeyPair::generate().unwrap();
        let cert: rcgen::Certificate = params.signed_by(&key, &self.issuer).unwrap();
        let data = CertData {
            domain: domain.to_string(),
            san_domains: dns.iter().map(|d: &&str| d.to_string()).collect(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            not_after_epoch: 9_999_999_999,
            ocsp_response: None,
        };
        (data, cert.der().to_vec())
    }

    fn client(&self) -> Arc<RusTlsClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        Arc::new(
            lorica_tls::http_client::config_builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }
}

/// An HTTPS listener on the loopback, built through
/// `TlsSettings::with_resolver` with h2 enabled as in production, that
/// handshakes every connection it accepts.
async fn listener(resolver: Arc<CertResolver>) -> SocketAddr {
    init_crypto();
    let mut settings: TlsSettings = TlsSettings::with_resolver(resolver);
    settings.enable_h2();
    let acceptor: Arc<Acceptor> = Arc::new(settings.build());
    let tcp: TcpListener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr: SocketAddr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = tcp.accept().await else {
                return;
            };
            let acceptor: Arc<Acceptor> = Arc::clone(&acceptor);
            tokio::spawn(async move {
                // What `Listener::accept` does with every socket.
                let mut stream: Stream = socket.into();
                let digest: SocketDigest = SocketDigest::from_raw_fd(stream.as_raw_fd());
                stream.set_socket_digest(digest);
                let _ = acceptor.tls_handshake(stream).await;
            });
        }
    });
    addr
}

/// The leaf the listener presented to a client naming `server_name`, or
/// the handshake error.
async fn presented_leaf(
    addr: SocketAddr,
    client: Arc<RusTlsClientConfig>,
    server_name: ServerName<'static>,
) -> Result<Vec<u8>, String> {
    let tcp: TcpStream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(client);
    let tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
        .await
        .map_err(|_| "handshake timeout".to_string())?
        .map_err(|e| format!("handshake: {e}"))?;
    let leaf: Vec<u8> = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain: &[CertificateDer<'_>]| chain.first())
        .map(|der: &CertificateDer<'_>| der.to_vec())
        .ok_or("no certificate presented")?;
    Ok(leaf)
}

fn by_ip() -> ServerName<'static> {
    ServerName::IpAddress(LOOPBACK.into())
}

fn by_name(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_string()).unwrap()
}

#[tokio::test]
async fn a_client_dialing_an_ip_gets_the_certificate_carrying_that_ip() {
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let (other_cert, _) = pki.leaf("example.test", &["example.test"], &[]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert, other_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;

    assert_eq!(
        presented_leaf(addr, pki.client(), by_ip()).await,
        Ok(ip_leaf.clone()),
        "no SNI: the certificate for the local address"
    );
    assert_eq!(
        presented_leaf(addr, pki.client(), by_name("localhost")).await,
        Ok(ip_leaf),
        "SNI still resolves by name on a connection to that address"
    );
    assert!(
        presented_leaf(addr, pki.client(), by_name("unknown.example.test"))
            .await
            .is_err(),
        "an SNI the resolver does not know never falls back to the address"
    );
}

#[tokio::test]
async fn a_client_dialing_an_ip_no_certificate_carries_still_fails() {
    let pki = Pki::new();
    let (dns_cert, dns_leaf) = pki.leaf("localhost", &["localhost"], &[]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![dns_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;

    assert!(presented_leaf(addr, pki.client(), by_ip()).await.is_err());
    assert_eq!(
        presented_leaf(addr, pki.client(), by_name("localhost")).await,
        Ok(dns_leaf),
        "the SNI path is unchanged"
    );
}

/// The per-address acceptor resolves against the hot-swapped resolver on
/// every handshake, so a reload that drops or brings back the address is
/// seen by the next connection.
#[tokio::test]
async fn a_reload_reaches_the_ip_path() {
    let pki = Pki::new();
    let (ip_cert, _) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let (dns_cert, _) = pki.leaf("localhost", &["localhost"], &[]);
    let (renewed_cert, renewed_leaf) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;
    assert!(presented_leaf(addr, pki.client(), by_ip()).await.is_ok());

    resolver.reload(vec![dns_cert]).unwrap();
    assert!(presented_leaf(addr, pki.client(), by_ip()).await.is_err());

    resolver.reload(vec![renewed_cert]).unwrap();
    assert_eq!(
        presented_leaf(addr, pki.client(), by_ip()).await,
        Ok(renewed_leaf)
    );
}
