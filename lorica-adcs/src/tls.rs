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

//! The TLS side of the exchange: which certificates the endpoint's is
//! checked against, and the pin that keeps the bound token on the
//! certificate its channel binding was computed from.
//!
//! The binding (RFC 5929 `tls-server-end-point`) is computed from the
//! certificate the unauthenticated probe met. The server checks that the
//! token's binding matches the certificate of the connection the token
//! arrives on, which protects the server; nothing in it protects the
//! client from sending that token on another connection. If a later
//! connection of the operation met another certificate the client also
//! trusts, whoever holds it could relay the token to the real endpoint
//! over its own connection there, where the binding matches. So every
//! connection after the probe must present the very certificate the
//! binding was computed from, and one that does not is refused during
//! its handshake, before a request, let alone a token, is written to it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use x509_parser::pem::Pem;

use crate::AdcsError;

fn tls_error(reason: String) -> AdcsError {
    AdcsError::Tls { reason }
}

/// The certificate every connection of a session must present once the
/// probe has met it, and whether a handshake was refused for presenting
/// another one.
#[derive(Debug, Default)]
pub(crate) struct CertificatePin {
    pinned: Mutex<Option<Vec<u8>>>,
    refused: AtomicBool,
}

impl CertificatePin {
    /// From now on, every handshake must present `certificate_der`.
    pub(crate) fn pin(&self, certificate_der: Vec<u8>) {
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner) = Some(certificate_der);
    }

    /// Whether a handshake was refused since the last call. The refusal
    /// reaches the caller only as a connection error, so the verifier
    /// records it here for the error to be named.
    pub(crate) fn take_refusal(&self) -> bool {
        self.refused.swap(false, Ordering::SeqCst)
    }

    fn admits(&self, end_entity: &[u8]) -> bool {
        match &*self.pinned.lock().unwrap_or_else(PoisonError::into_inner) {
            Some(pinned) => pinned.as_slice() == end_entity,
            None => true,
        }
    }
}

/// The normal verification, then the pin.
#[derive(Debug)]
struct PinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: Arc<CertificatePin>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified: ServerCertVerified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        if !self.pin.admits(end_entity.as_ref()) {
            self.pin.refused.store(true, Ordering::SeqCst);
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The roots the endpoint's certificate must chain to: the PEM
/// `trust_bundle` alone when set (Epic 13 D12), else the public trust of
/// every outbound HTTP client, the webpki bundle and the system store
/// (`lorica_tls::http_client::public_roots`).
///
/// Reads the system store from disk: run it on a blocking thread.
fn root_store(trust_bundle: Option<&str>) -> Result<RootCertStore, AdcsError> {
    match trust_bundle {
        Some(pem) => {
            let mut roots: RootCertStore = RootCertStore::empty();
            for block in Pem::iter_from_buffer(pem.as_bytes()) {
                let block: Pem = block.map_err(|err| {
                    tls_error(format!("the endpoint trust bundle cannot be read: {err}"))
                })?;
                if block.label != "CERTIFICATE" {
                    continue;
                }
                roots
                    .add(CertificateDer::from(block.contents))
                    .map_err(|err: rustls::Error| {
                        tls_error(format!("the endpoint trust bundle cannot be read: {err}"))
                    })?;
            }
            if roots.is_empty() {
                return Err(tls_error(
                    "the endpoint trust bundle holds no PEM certificate".to_owned(),
                ));
            }
            Ok(roots)
        }
        None => lorica_tls::http_client::public_roots()
            .map_err(|err| tls_error(format!("the system trust store is unusable: {err}"))),
    }
}

/// The TLS configuration of a session: the normal verification against
/// [`root_store`], then `pin`.
///
/// Session resumption is off: a resumed handshake skips certificate
/// verification, and the pin must hold for every connection without a
/// reasoning about which earlier session a ticket came from. HTTP/1.1
/// only, as every outbound client offers it.
pub(crate) fn client_config(
    trust_bundle: Option<&str>,
    pin: Arc<CertificatePin>,
) -> Result<ClientConfig, AdcsError> {
    let roots: RootCertStore = root_store(trust_bundle)?;
    let inner: Arc<WebPkiServerVerifier> = WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        lorica_tls::http_client::crypto_provider(),
    )
    .build()
    .map_err(|err| tls_error(format!("the certificate verifier cannot be built: {err}")))?;
    let mut config: ClientConfig =
        lorica_tls::http_client::with_verifier(Arc::new(PinnedVerifier { inner, pin }));
    config.resumption = Resumption::disabled();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};

    fn self_signed() -> (Vec<u8>, String) {
        let key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let cert = CertificateParams::new(vec!["ces.corp.example.org".to_owned()])
            .expect("params")
            .self_signed(&key)
            .expect("certificate");
        (cert.der().to_vec(), cert.pem())
    }

    #[test]
    fn a_bundle_is_trusted_alone() {
        let (_, first) = self_signed();
        let (_, second) = self_signed();
        let bundle: String = format!("ignored preamble\n{first}{second}");
        assert_eq!(root_store(Some(&bundle)).expect("roots").len(), 2);
        for empty in ["", "not a PEM bundle"] {
            assert!(
                matches!(root_store(Some(empty)), Err(AdcsError::Tls { reason }) if reason.contains("no PEM certificate")),
                "{empty:?}"
            );
        }
    }

    #[test]
    fn without_a_bundle_the_public_roots_are_trusted() {
        let roots: RootCertStore = root_store(None).expect("roots");
        let public: RootCertStore = lorica_tls::http_client::public_roots().expect("public roots");
        assert!(!roots.is_empty());
        assert_eq!(roots.len(), public.len());
    }

    #[test]
    fn a_session_offers_http_1_1_alone() {
        let config: ClientConfig =
            client_config(None, Arc::new(CertificatePin::default())).expect("configuration");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn the_pin_admits_anything_until_set_then_only_its_certificate() {
        let (first, _) = self_signed();
        let (second, _) = self_signed();
        let pin: CertificatePin = CertificatePin::default();
        assert!(pin.admits(&first) && pin.admits(&second));
        pin.pin(first.clone());
        assert!(pin.admits(&first));
        assert!(!pin.admits(&second));
        assert!(!pin.take_refusal(), "admits() records nothing");
    }
}
