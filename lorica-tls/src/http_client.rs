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

//! The TLS configuration every outbound HTTP client of the workspace is
//! built on.
//!
//! Every `reqwest` client is handed a finished rustls [`ClientConfig`]
//! from here (`ClientBuilder::tls_backend_preconfigured`) instead of
//! letting reqwest assemble one. Left to itself, reqwest 0.13 verifies
//! through `rustls-platform-verifier` on the process-wide default crypto
//! provider, and panics in `Client::build` when no default is installed.
//! A preconfigured client does neither: the provider is `ring`, named
//! here rather than read from the process, the roots are the ones listed
//! below, and the protocol versions are rustls' safe defaults.
//!
//! [`public_roots`] is the trust every client had under reqwest 0.12 with
//! the features the shipped binaries unified onto it: the webpki bundle
//! and the platform store (which honours `SSL_CERT_FILE` and
//! `SSL_CERT_DIR`). The variants a call site needs are separate
//! functions, so that relaxing verification is a word at the call site
//! and never a flag that defaults to off.
//!
//! ALPN offers `http/1.1` alone, as reqwest 0.12 did with its `http2`
//! feature off: no product client speaks HTTP/2. reqwest never rewrites
//! the ALPN of a preconfigured configuration, so this holds even when a
//! test build unifies `http2` onto reqwest; [`offering_http2`] is for the
//! client that wants it.
//!
//! ```
//! let tls: lorica_tls::ClientConfig = lorica_tls::http_client::public()?;
//! assert_eq!(tls.alpn_protocols, vec![b"http/1.1".to_vec()]);
//! # Ok::<(), Box<lorica_error::Error>>(())
//! ```

use std::fmt::Write as _;
use std::sync::Arc;

use lorica_error::{Error, ErrorType, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WantsClientCert;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

const HTTP_1_1: &[u8] = b"http/1.1";
const H2: &[u8] = b"h2";

/// The crypto provider of every outbound HTTP client: `ring`, the one
/// stack the workspace links (audit M-6).
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The webpki bundle and the platform store.
///
/// Reads the platform store from disk on every call, as reqwest did on
/// every `Client::build`. A platform store whose certificates the root
/// store rejects one and all is an error; an empty or unreadable one
/// leaves the webpki bundle alone, which is what reqwest 0.12 did.
///
/// # Errors
///
/// [`ErrorType::InvalidCert`] when the platform store offered
/// certificates and not one of them was usable.
pub fn public_roots() -> Result<RootCertStore> {
    let mut roots: RootCertStore = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let native: rustls_native_certs::CertificateResult = rustls_native_certs::load_native_certs();
    let (valid, invalid): (usize, usize) = roots.add_parsable_certificates(native.certs);
    if valid == 0 && invalid > 0 {
        let mut reasons: String = String::new();
        for error in &native.errors {
            let _ = write!(reasons, "; {error}");
        }
        return Error::e_explain(
            ErrorType::InvalidCert,
            format!("no usable certificate in the platform trust store{reasons}"),
        );
    }
    Ok(roots)
}

/// Verify against [`public_roots`]: what every client trusts unless its
/// call site says otherwise.
///
/// # Errors
///
/// Those of [`public_roots`].
pub fn public() -> Result<ClientConfig> {
    Ok(verified(public_roots()?))
}

/// Verify the server's certificate and name against `roots` and nothing
/// else. A site that adds to the public trust builds `roots` from
/// [`public_roots`]; one that replaces it starts from an empty store.
pub fn verified(roots: RootCertStore) -> ClientConfig {
    finish(builder().with_root_certificates(roots))
}

/// Verify with `verifier`, for a site whose check is not a chain to a
/// set of roots (a pinned leaf, a pinned endpoint certificate).
pub fn with_verifier(verifier: Arc<dyn ServerCertVerifier>) -> ClientConfig {
    finish(
        builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier),
    )
}

/// Accept any certificate for any name, without checking the handshake
/// signature either, as reqwest's `danger_accept_invalid_certs(true)`
/// did. For probes of operator backends and for tests, never for a
/// client that carries a credential.
pub fn unverified() -> ClientConfig {
    with_verifier(Arc::new(AcceptAnything {
        schemes: crypto_provider()
            .signature_verification_algorithms
            .supported_schemes(),
    }))
}

/// `config`, offering `h2` before `http/1.1`, for a client built with
/// reqwest's `http2` feature that must be able to negotiate HTTP/2.
/// reqwest leaves the ALPN of a preconfigured configuration alone, so
/// without this such a client speaks HTTP/1.1 to every TLS server.
pub fn offering_http2(mut config: ClientConfig) -> ClientConfig {
    config.alpn_protocols = vec![H2.to_vec(), HTTP_1_1.to_vec()];
    config
}

fn builder() -> ConfigBuilder<ClientConfig, rustls::WantsVerifier> {
    ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        // The ring provider ships suites and key exchange groups for both
        // TLS 1.2 and 1.3, so the only error this can return is
        // unreachable; `the_provider_is_ring` builds it on every run.
        .expect("the ring provider supports rustls' default protocol versions")
}

fn finish(builder: ConfigBuilder<ClientConfig, WantsClientCert>) -> ClientConfig {
    let mut config: ClientConfig = builder.with_no_client_auth();
    config.alpn_protocols = vec![HTTP_1_1.to_vec()];
    config
}

#[derive(Debug)]
struct AcceptAnything {
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnything {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair};
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ClientConnection, ServerConfig, ServerConnection};

    const SERVER_NAME: &str = "origin.internal.example.org";

    struct Server {
        certificate: CertificateDer<'static>,
        config: Arc<ServerConfig>,
    }

    /// A self-signed server for `SERVER_NAME`, on the same provider so
    /// no test of this module depends on a process default. `subject`
    /// tells two servers apart, so one is never taken for the issuer of
    /// the other.
    fn server_named(subject: &str) -> Server {
        let key: KeyPair = KeyPair::generate().expect("test setup: key");
        let mut params: CertificateParams =
            CertificateParams::new(vec![SERVER_NAME.into()]).expect("test setup: params");
        params.distinguished_name.push(DnType::CommonName, subject);
        let certificate: CertificateDer<'static> = params
            .self_signed(&key)
            .expect("test setup: certificate")
            .der()
            .clone();
        let mut config: ServerConfig = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .expect("test setup: versions")
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::try_from(key.serialize_der()).expect("test setup: key der"),
            )
            .expect("test setup: server config");
        // Both, as the proxy's own listeners offer them, so the client's
        // offer is what decides.
        config.alpn_protocols = vec![H2.to_vec(), HTTP_1_1.to_vec()];
        Server {
            certificate,
            config: Arc::new(config),
        }
    }

    fn server() -> Server {
        server_named("origin")
    }

    /// Run a whole handshake in memory and return how the client ended
    /// it: the protocol ALPN settled on, or the client's refusal.
    fn handshake(
        client: ClientConfig,
        server: &Server,
        name: &str,
    ) -> std::result::Result<Option<Vec<u8>>, rustls::Error> {
        let mut client = ClientConnection::new(
            Arc::new(client),
            ServerName::try_from(name.to_owned()).expect("test setup: name"),
        )?;
        let mut server = ServerConnection::new(Arc::clone(&server.config))?;
        while client.is_handshaking() || server.is_handshaking() {
            let mut wire: Vec<u8> = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut wire).expect("in memory");
            }
            let mut flight: &[u8] = &wire;
            while !flight.is_empty() {
                server.read_tls(&mut flight).expect("in memory");
            }
            if let Err(err) = server.process_new_packets() {
                // The server's alert carries the client's refusal back.
                let mut alert: Vec<u8> = Vec::new();
                let _ = server.write_tls(&mut alert);
                let _ = client.read_tls(&mut alert.as_slice());
                client.process_new_packets()?;
                return Err(err);
            }
            let mut wire: Vec<u8> = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut wire).expect("in memory");
            }
            let mut flight: &[u8] = &wire;
            while !flight.is_empty() {
                client.read_tls(&mut flight).expect("in memory");
            }
            client.process_new_packets()?;
        }
        Ok(client.alpn_protocol().map(<[u8]>::to_vec))
    }

    fn only(certificate: &CertificateDer<'static>) -> RootCertStore {
        let mut roots: RootCertStore = RootCertStore::empty();
        roots.add(certificate.clone()).expect("test setup: root");
        roots
    }

    #[test]
    fn the_provider_is_ring() {
        let ring: CryptoProvider = rustls::crypto::ring::default_provider();
        let suites = |provider: &CryptoProvider| -> Vec<rustls::CipherSuite> {
            provider.cipher_suites.iter().map(|s| s.suite()).collect()
        };
        for config in [public().expect("public roots"), unverified()] {
            assert_eq!(suites(config.crypto_provider()), suites(&ring));
            assert_eq!(
                config.crypto_provider().kx_groups.len(),
                ring.kx_groups.len()
            );
        }
        assert_eq!(suites(&crypto_provider()), suites(&ring));
    }

    #[test]
    fn the_public_roots_hold_the_webpki_bundle() {
        let roots: RootCertStore = public_roots().expect("public roots");
        assert!(!roots.is_empty());
        assert!(roots.len() >= webpki_roots::TLS_SERVER_ROOTS.len());
    }

    #[test]
    fn every_variant_offers_http_1_1_alone() {
        let origin: Server = server();
        for config in [
            public().expect("public roots"),
            verified(only(&origin.certificate)),
            unverified(),
            with_verifier(Arc::new(AcceptAnything { schemes: vec![] })),
        ] {
            assert_eq!(config.alpn_protocols, vec![HTTP_1_1.to_vec()]);
            assert!(config.enable_sni);
        }
        assert_eq!(
            handshake(unverified(), &origin, SERVER_NAME).expect("handshake"),
            Some(HTTP_1_1.to_vec()),
            "a server offering h2 still gets http/1.1"
        );
    }

    #[test]
    fn offering_http2_negotiates_h2_and_keeps_the_verification() {
        let origin: Server = server();
        let config: ClientConfig = offering_http2(verified(only(&origin.certificate)));
        assert_eq!(config.alpn_protocols, vec![H2.to_vec(), HTTP_1_1.to_vec()]);
        assert_eq!(
            handshake(config, &origin, SERVER_NAME).expect("handshake"),
            Some(H2.to_vec())
        );
        let refused = handshake(
            offering_http2(public().expect("public roots")),
            &origin,
            SERVER_NAME,
        )
        .expect_err("offering h2 relaxes nothing");
        assert!(
            matches!(refused, rustls::Error::InvalidCertificate(_)),
            "{refused:?}"
        );
    }

    #[test]
    fn the_public_trust_refuses_a_self_signed_server() {
        let origin: Server = server();
        let refused = handshake(public().expect("public roots"), &origin, SERVER_NAME)
            .expect_err("a self-signed certificate is not publicly trusted");
        assert!(
            matches!(
                refused,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn a_named_root_is_trusted_for_its_name_only() {
        let origin: Server = server();
        handshake(verified(only(&origin.certificate)), &origin, SERVER_NAME)
            .expect("the named root signed this certificate");
        let refused = handshake(
            verified(only(&origin.certificate)),
            &origin,
            "elsewhere.example.net",
        )
        .expect_err("the certificate does not name this host");
        assert!(
            matches!(refused, rustls::Error::InvalidCertificate(_)),
            "{refused:?}"
        );
    }

    #[test]
    fn a_named_root_replaces_the_others() {
        let origin: Server = server();
        let other: Server = server_named("another origin");
        let refused = handshake(verified(only(&other.certificate)), &origin, SERVER_NAME)
            .expect_err("another root does not vouch for this server");
        assert!(
            matches!(
                refused,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            ),
            "{refused:?}"
        );
    }

    #[test]
    fn only_unverified_accepts_anything() {
        let origin: Server = server();
        handshake(unverified(), &origin, "elsewhere.example.net")
            .expect("verification is off, the name and issuer are not checked");
    }
}
