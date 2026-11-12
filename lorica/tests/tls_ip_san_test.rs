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
//! from which the acceptor reads the local address.
//!
//! Two kinds of client. A verifying one dials `ServerName::IpAddress`,
//! which sends no SNI and checks the certificate against an `iPAddress`
//! SAN, as a browser does. A permissive one accepts any certificate and
//! records the leaf it was shown: a verifying client refuses a wrong
//! certificate on its own, so only the permissive one can tell "the
//! listener presented no certificate" from "it presented the wrong one".

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use lorica_core::listeners::tls::{Acceptor, TlsSettings};
use lorica_core::protocols::l4::stream::Stream;
use lorica_core::protocols::{GetSocketDigest, SocketDigest};
use lorica_tls::cert_resolver::{CertData, CertResolver};
use lorica_tls::{
    version, ClientCertVerifier, DigitallySignedStruct, HandshakeSignatureValid, RootCertStore,
    ServerCertVerified, ServerCertVerifier, SignatureScheme, WebPkiClientVerifier,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig as RusTlsClientConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// What the listener writes on a connection whose handshake it completed.
const REPLY: &[u8] = b"ok";

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

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_der.clone()).unwrap();
        roots
    }

    /// A verifying client offering `alpn`.
    fn client(&self, alpn: &[&[u8]]) -> Arc<RusTlsClientConfig> {
        let mut config: RusTlsClientConfig = lorica_tls::http_client::config_builder()
            .with_root_certificates(self.roots())
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p: &&[u8]| p.to_vec()).collect();
        Arc::new(config)
    }

    /// A verifying client presenting a client certificate this CA issued.
    fn client_with_identity(&self) -> Arc<RusTlsClientConfig> {
        let mut params: CertificateParams = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let key: KeyPair = KeyPair::generate().unwrap();
        let cert: rcgen::Certificate = params.signed_by(&key, &self.issuer).unwrap();
        let key_der: PrivateKeyDer<'static> =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        Arc::new(
            lorica_tls::http_client::config_builder()
                .with_root_certificates(self.roots())
                .with_client_auth_cert(vec![cert.der().clone()], key_der)
                .unwrap(),
        )
    }

    /// A server-side verifier that demands a client certificate this CA
    /// issued.
    fn client_cert_verifier(&self) -> Arc<dyn ClientCertVerifier> {
        WebPkiClientVerifier::builder_with_provider(
            Arc::new(self.roots()),
            lorica_tls::http_client::crypto_provider(),
        )
        .build()
        .unwrap()
    }
}

/// A server certificate verifier that accepts anything and records the
/// leaf it was shown. Signatures are still checked, so the handshake
/// proceeds as far as the server lets it.
#[derive(Debug)]
struct RecordingVerifier {
    provider: Arc<CryptoProvider>,
    presented: Mutex<Option<Vec<u8>>>,
}

impl RecordingVerifier {
    fn presented(&self) -> Option<Vec<u8>> {
        self.presented.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.presented.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The leaf the listener at `addr` presented to a client that accepts
/// any certificate, offering `versions` and naming `server_name`; `None`
/// when it presented none.
async fn presented_to_any_client(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    versions: &[&'static SupportedProtocolVersion],
) -> Option<Vec<u8>> {
    let provider: Arc<CryptoProvider> = lorica_tls::http_client::crypto_provider();
    let verifier = Arc::new(RecordingVerifier {
        provider: Arc::clone(&provider),
        presented: Mutex::new(None),
    });
    let client: RusTlsClientConfig = RusTlsClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::clone(&verifier) as Arc<dyn ServerCertVerifier>)
        .with_no_client_auth();
    let _ = connect(addr, Arc::new(client), server_name).await;
    verifier.presented()
}

/// The HTTPS listener's settings over `resolver`, h2 enabled as in
/// production.
fn https_settings(resolver: Arc<CertResolver>) -> TlsSettings {
    let mut settings: TlsSettings = TlsSettings::with_resolver(resolver);
    settings.enable_h2();
    settings
}

/// Serve `settings` on `tcp`: handshake every accepted connection and
/// write [`REPLY`] on each that completes.
fn serve(settings: TlsSettings, tcp: TcpListener) -> SocketAddr {
    init_crypto();
    let acceptor: Arc<Acceptor> = Arc::new(settings.build());
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
                if let Ok(mut tls) = acceptor.tls_handshake(stream).await {
                    let _ = tls.write_all(REPLY).await;
                    let _ = tls.shutdown().await;
                }
            });
        }
    });
    addr
}

/// An HTTPS listener on the loopback over `resolver`.
async fn listener(resolver: Arc<CertResolver>) -> SocketAddr {
    serve(
        https_settings(resolver),
        TcpListener::bind((LOOPBACK, 0)).await.unwrap(),
    )
}

/// What a client saw of a connection whose handshake it completed.
#[derive(Debug)]
struct Connected {
    leaf: Vec<u8>,
    alpn: Option<Vec<u8>>,
    /// What the listener sent after the handshake, or the error that
    /// ended the connection instead (a server that refused the client
    /// after the client's side of a TLS 1.3 handshake was done).
    reply: Result<Vec<u8>, String>,
}

/// Connect `client` to `addr` naming `server_name`, or the handshake
/// error.
async fn connect(
    addr: SocketAddr,
    client: Arc<RusTlsClientConfig>,
    server_name: ServerName<'static>,
) -> Result<Connected, String> {
    let tcp: TcpStream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(client);
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
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
    let alpn: Option<Vec<u8>> = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
    let mut reply: Vec<u8> = Vec::new();
    let reply: Result<Vec<u8>, String> =
        match tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut reply)).await {
            Ok(Ok(_)) => Ok(reply),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("reply timeout".to_string()),
        };
    Ok(Connected { leaf, alpn, reply })
}

/// The leaf a verifying client was presented, or the handshake error.
async fn verified_leaf(
    addr: SocketAddr,
    client: Arc<RusTlsClientConfig>,
    server_name: ServerName<'static>,
) -> Result<Vec<u8>, String> {
    connect(addr, client, server_name)
        .await
        .map(|connected: Connected| connected.leaf)
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
        verified_leaf(addr, pki.client(&[]), by_ip()).await,
        Ok(ip_leaf.clone()),
        "no SNI: the certificate for the local address"
    );
    assert_eq!(
        verified_leaf(addr, pki.client(&[]), by_name("localhost")).await,
        Ok(ip_leaf),
        "SNI still resolves by name on a connection to that address"
    );
}

/// `docs/security.md`: a name no certificate covers fails the handshake
/// and never falls back to the address, even on a connection to an
/// address a certificate carries.
#[tokio::test]
async fn an_sni_no_certificate_covers_never_falls_back_to_the_address() {
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;

    assert_eq!(
        presented_to_any_client(addr, by_ip(), rustls::ALL_VERSIONS).await,
        Some(ip_leaf),
        "the recording client sees the certificate when there is one"
    );
    assert_eq!(
        presented_to_any_client(addr, by_name("unknown.example.test"), rustls::ALL_VERSIONS).await,
        None,
        "an unknown SNI is presented no certificate at all"
    );
}

#[tokio::test]
async fn a_client_dialing_an_ip_no_certificate_carries_is_presented_none() {
    let pki = Pki::new();
    let (dns_cert, dns_leaf) = pki.leaf("localhost", &["localhost"], &[]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![dns_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;

    assert_eq!(
        presented_to_any_client(addr, by_ip(), rustls::ALL_VERSIONS).await,
        None
    );
    assert_eq!(
        verified_leaf(addr, pki.client(&[]), by_name("localhost")).await,
        Ok(dns_leaf),
        "the SNI path is unchanged"
    );
}

/// The per-address config resolves against the hot-swapped resolver on
/// every handshake, so a reload that drops or brings back the address is
/// seen by the next connection.
#[tokio::test]
async fn a_reload_reaches_the_ip_path() {
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let (dns_cert, _) = pki.leaf("localhost", &["localhost"], &[]);
    let (renewed_cert, renewed_leaf) = pki.leaf("localhost", &["localhost"], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;
    assert_eq!(
        presented_to_any_client(addr, by_ip(), rustls::ALL_VERSIONS).await,
        Some(ip_leaf)
    );

    resolver.reload(vec![dns_cert]).unwrap();
    assert_eq!(
        presented_to_any_client(addr, by_ip(), rustls::ALL_VERSIONS).await,
        None
    );

    resolver.reload(vec![renewed_cert]).unwrap();
    assert_eq!(
        presented_to_any_client(addr, by_ip(), rustls::ALL_VERSIONS).await,
        Some(renewed_leaf)
    );
}

/// The per-address config is a copy of the listener's: it keeps the
/// listener's ALPN.
#[tokio::test]
async fn the_ip_path_negotiates_h2() {
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &[], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;

    let connected: Connected = connect(addr, pki.client(&[b"h2", b"http/1.1"]), by_ip())
        .await
        .unwrap();
    assert_eq!(connected.leaf, ip_leaf);
    assert_eq!(connected.alpn.as_deref(), Some(&b"h2"[..]));
}

/// The per-address config keeps the listener's client certificate
/// verifier: a connection to the address is still refused without a
/// client certificate, and accepted with one.
#[tokio::test]
async fn the_ip_path_still_demands_a_client_certificate() {
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &[], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let mut settings: TlsSettings = https_settings(Arc::clone(&resolver));
    settings.set_client_cert_verifier(pki.client_cert_verifier());
    let addr: SocketAddr = serve(settings, TcpListener::bind((LOOPBACK, 0)).await.unwrap());

    let with_identity: Connected = connect(addr, pki.client_with_identity(), by_ip())
        .await
        .unwrap();
    assert_eq!(with_identity.leaf, ip_leaf, "served on the IP path");
    assert_eq!(with_identity.reply, Ok(REPLY.to_vec()));

    let without_identity: Result<Connected, String> = connect(addr, pki.client(&[]), by_ip()).await;
    assert!(
        !matches!(without_identity, Ok(Connected { reply: Ok(_), .. })),
        "a client without a certificate must be refused: {without_identity:?}"
    );
}

/// A TCP relay to `upstream` that overwrites `from` with `to`, of the
/// same length, in the first TLS record the client sends (its
/// ClientHello), and copies everything else unchanged.
async fn rewriting_relay(
    upstream: SocketAddr,
    from: &'static [u8],
    to: &'static [u8],
) -> SocketAddr {
    assert_eq!(from.len(), to.len(), "test setup: a same-length rewrite");
    let tcp: TcpListener = TcpListener::bind((LOOPBACK, 0)).await.unwrap();
    let addr: SocketAddr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        let Ok((mut client, _)) = tcp.accept().await else {
            return;
        };
        let mut server: TcpStream = TcpStream::connect(upstream).await.unwrap();
        let mut header: [u8; 5] = [0; 5];
        client.read_exact(&mut header).await.unwrap();
        let mut record: Vec<u8> = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        client.read_exact(&mut record).await.unwrap();
        let at: usize = record
            .windows(from.len())
            .position(|window: &[u8]| window == from)
            .expect("test setup: the placeholder name in the ClientHello");
        record[at..at + to.len()].copy_from_slice(to);
        server.write_all(&header).await.unwrap();
        server.write_all(&record).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    addr
}

/// `LocalIpResolver` relies on rustls reporting no SNI for an IP literal
/// a client sends as SNI anyway, against RFC 6066. rustls clients never
/// send one, so a relay rewrites a same-length placeholder name into
/// `127.0.0.1` in the ClientHello. TLS 1.2 only: its Certificate message
/// is in clear, so the client is shown the leaf although the rewrite
/// breaks the transcript and the handshake fails later.
#[tokio::test]
async fn rustls_reports_no_sni_for_an_ip_literal_sent_as_sni() {
    const PLACEHOLDER: &[u8] = b"abcde.xyz";
    const LITERAL: &[u8] = b"127.0.0.1";
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &[], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let addr: SocketAddr = listener(Arc::clone(&resolver)).await;
    let placeholder: ServerName<'static> = by_name(std::str::from_utf8(PLACEHOLDER).unwrap());

    assert_eq!(
        presented_to_any_client(addr, placeholder.clone(), &[&version::TLS12]).await,
        None,
        "the placeholder, sent as written, is an unknown name"
    );
    let relay: SocketAddr = rewriting_relay(addr, PLACEHOLDER, LITERAL).await;
    assert_eq!(
        presented_to_any_client(relay, placeholder, &[&version::TLS12]).await,
        Some(ip_leaf),
        "an IP literal in SNI is answered as no SNI"
    );
}

/// A dual-stack `[::]` listener reports an IPv4 client's local address
/// as `::ffff:127.0.0.1`; that client dialed `127.0.0.1` and must get the
/// certificate carrying it as an IPv4 SAN. Skipped when the host has no
/// IPv6 to bind.
#[tokio::test]
async fn a_dual_stack_listener_serves_an_ipv4_client_the_ipv4_san_certificate() {
    let Ok(tcp) = TcpListener::bind((Ipv6Addr::UNSPECIFIED, 0)).await else {
        eprintln!("skipped: this host cannot bind [::]");
        return;
    };
    let pki = Pki::new();
    let (ip_cert, ip_leaf) = pki.leaf("localhost", &[], &[LOOPBACK]);
    let resolver = Arc::new(CertResolver::new());
    resolver.reload(vec![ip_cert]).unwrap();
    let port: u16 = serve(https_settings(Arc::clone(&resolver)), tcp).port();

    assert_eq!(
        verified_leaf(SocketAddr::new(LOOPBACK, port), pki.client(&[]), by_ip()).await,
        Ok(ip_leaf)
    );
}
