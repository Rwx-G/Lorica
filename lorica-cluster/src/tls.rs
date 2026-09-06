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

//! Cluster-plane TLS configurations (Story 9.2 AC #2, crypto half).
//!
//! Three distinct configs, none reusing the proxy's mTLS helper (whose
//! `build_verifier` hardcodes `.allow_unauthenticated()` and reads
//! per-route CAs - see the story's Dev Notes):
//!
//! - **Operational server**: client authentication is MANDATORY.
//!   `WebPkiClientVerifier::builder(cluster_ca).build()` - a peer with
//!   no certificate, or one not chaining to the cluster CA, fails the
//!   TLS handshake itself; nothing is deferred to the message layer.
//! - **Enrollment server**: accepts peers holding no certificate. It
//!   is the only unauthenticated surface in the product; its listener
//!   lifecycle (token-gated open/close, pre-auth budgets) is enforced
//!   by the listener layer, not here.
//! - **Dialer client**: verifies the control plane against the
//!   cluster CA ONLY (no system roots) and presents the node's
//!   `clientAuth` leaf.
//!
//! Everything runs on the ring provider, matching the management
//! listener so exactly one rustls crypto provider exists per process.
//!
//! # TLS 1.3 only, ALPN `lorica-cluster/1`
//!
//! The cluster plane is a closed protocol between identical rustls
//! builds, the one place in the codebase where TLS 1.3-only costs
//! nothing and removes a whole negotiation surface. Every config also
//! carries the [`CLUSTER_ALPN`] token. rustls does NOT refuse a peer
//! that offers no ALPN at all (it only fails when the peer offers a
//! non-overlapping list), so "ALPN required" is enforced by the
//! listeners and the dialer after the handshake via
//! [`negotiated_cluster_alpn`]: a peer that did not negotiate the
//! token is dropped before any frame is read.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::WebPkiSupportedAlgorithms;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{
    version, CertificateError, ClientConfig, CommonState, DigitallySignedStruct, Error as TlsError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

/// ALPN protocol token every cluster connection must negotiate.
pub const CLUSTER_ALPN: &[u8] = b"lorica-cluster/1";

/// Whether `conn` negotiated the cluster ALPN token. Both listeners
/// and the dialer check this right after the handshake (see the
/// module doc for why rustls alone cannot enforce it).
pub fn negotiated_cluster_alpn(conn: &CommonState) -> bool {
    conn.alpn_protocol() == Some(CLUSTER_ALPN)
}

/// Lowercase-hex SHA-256 of the peer's leaf certificate DER, if the
/// TLS layer exposed one. The identity Story 9.3 records at
/// enrollment and matches on every session; captured by the
/// operational listener before the stream is split into an endpoint.
pub fn peer_fingerprint(conn: &CommonState) -> Option<String> {
    let leaf = conn.peer_certificates()?.first()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    Some(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

/// Failure modes while assembling a cluster TLS config.
#[derive(Debug, thiserror::Error)]
pub enum ClusterTlsError {
    /// PEM material contained no usable certificate or key.
    #[error("cluster TLS PEM parse failed: {0}")]
    Parse(String),
    /// rustls rejected the material or the verifier could not build.
    #[error("cluster TLS config rejected: {0}")]
    Rustls(String),
}

fn certs_from_pem(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, ClusterTlsError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .filter_map(Result::ok)
        .map(|c| c.into_owned())
        .collect();
    if certs.is_empty() {
        return Err(ClusterTlsError::Parse(format!(
            "no certificate found in {what} PEM"
        )));
    }
    Ok(certs)
}

fn key_from_pem(pem: &str, what: &str) -> Result<PrivateKeyDer<'static>, ClusterTlsError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| ClusterTlsError::Parse(format!("no private key in {what} PEM: {e}")))
}

fn ca_root_store(ca_pem: &str) -> Result<Arc<RootCertStore>, ClusterTlsError> {
    let mut roots = RootCertStore::empty();
    for cert in certs_from_pem(ca_pem, "cluster CA")? {
        roots
            .add(cert)
            .map_err(|e| ClusterTlsError::Rustls(format!("cluster CA rejected: {e}")))?;
    }
    Ok(Arc::new(roots))
}

/// Server config for the OPERATIONAL cluster listener: client
/// authentication is mandatory (Story 9.2 AC #2). There is
/// deliberately no `allow_unauthenticated()` here - an unenrolled
/// peer must fail the handshake, not reach the message layer.
pub fn operational_server_config(
    ca_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<ServerConfig, ClusterTlsError> {
    operational_server_config_with_crl(ca_pem, server_cert_pem, server_key_pem, None)
}

/// [`operational_server_config`] with a revocation list (Story 9.3
/// AC #7): when `crl` is `Some`, every client leaf is checked against
/// it at the handshake and a revoked serial fails TLS itself. Only
/// the end entity is checked (the CA is the anchor); with no CRL, no
/// revocation check runs (so an empty fleet never sees phantom
/// "unknown status" failures).
pub fn operational_server_config_with_crl(
    ca_pem: &str,
    server_cert_pem: &str,
    server_key_pem: &str,
    crl: Option<CertificateRevocationListDer<'static>>,
) -> Result<ServerConfig, ClusterTlsError> {
    let roots = ca_root_store(ca_pem)?;
    let builder = WebPkiClientVerifier::builder(roots);
    let builder = match crl {
        Some(crl) => builder
            .with_crls([crl])
            .only_check_end_entity_revocation(),
        None => builder,
    };
    let verifier = builder
        .build()
        .map_err(|e| ClusterTlsError::Rustls(format!("client verifier: {e}")))?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certs_from_pem(server_cert_pem, "cluster server cert")?,
            key_from_pem(server_key_pem, "cluster server key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))?;
    config.alpn_protocols = vec![CLUSTER_ALPN.to_vec()];
    Ok(config)
}

/// Server config for the ENROLLMENT listener: no client authentication
/// (a joining node has no certificate yet). This is the only
/// unauthenticated surface in the product; the listener layer gates
/// its lifecycle on live join tokens and enforces the pre-auth
/// budgets (Story 9.2 AC #2/#3).
pub fn enrollment_server_config(
    server_cert_pem: &str,
    server_key_pem: &str,
) -> Result<ServerConfig, ClusterTlsError> {
    let mut config = ServerConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_no_client_auth()
        .with_single_cert(
            certs_from_pem(server_cert_pem, "cluster server cert")?,
            key_from_pem(server_key_pem, "cluster server key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))?;
    config.alpn_protocols = vec![CLUSTER_ALPN.to_vec()];
    Ok(config)
}

/// Client config for the follower dialer (Story 9.2 AC #9): the
/// control plane is verified against the cluster CA ONLY (no system
/// roots - a public CA must never be able to impersonate the control
/// plane), and the node's `clientAuth` leaf is presented.
pub fn client_config(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<ClientConfig, ClusterTlsError> {
    let roots = ca_root_store(ca_pem)?;
    let mut config = ClientConfig::builder_with_protocol_versions(&[&version::TLS13])
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certs_from_pem(client_cert_pem, "node client cert")?,
            key_from_pem(client_key_pem, "node client key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))?;
    config.alpn_protocols = vec![CLUSTER_ALPN.to_vec()];
    Ok(config)
}

/// Lowercase-hex SHA-256 of a certificate's SubjectPublicKeyInfo:
/// what join tokens pin (Story 9.3 AC #2). Takes the first
/// certificate in `cert_pem`.
pub fn leaf_spki_sha256(cert_pem: &str) -> Result<[u8; 32], ClusterTlsError> {
    let der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .map_err(|e| ClusterTlsError::Parse(format!("leaf PEM: {e}")))?;
    spki_sha256_of_der(der.as_ref())
}

fn spki_sha256_of_der(der: &[u8]) -> Result<[u8; 32], ClusterTlsError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|e| ClusterTlsError::Parse(format!("leaf DER: {e}")))?;
    let digest = ring::digest::digest(&ring::digest::SHA256, cert.public_key().raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    Ok(out)
}

/// The joiner's server verifier (Story 9.3 AC #2): a node that has no
/// CA yet authenticates the control plane by the SPKI digest carried
/// in its join token, plus the same checks a CA-based verifier would
/// make on the leaf itself - validity window, `serverAuth` EKU, and a
/// SAN matching the `--control-plane` host. The CA is deliberately
/// NOT an input: pinning the CA would admit any certificate the
/// cluster CA ever issued, i.e. a compromised follower posing as the
/// control plane.
#[derive(Debug)]
struct SpkiPinVerifier {
    pin: [u8; 32],
    expected_host: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl SpkiPinVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>, now: UnixTime) -> Result<(), &'static str> {
        let (_, cert) = X509Certificate::from_der(end_entity.as_ref())
            .map_err(|_| "control-plane certificate is not valid DER")?;
        let at = x509_parser::time::ASN1Time::from_timestamp(
            i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
        )
        .map_err(|_| "clock out of range")?;
        if !cert.validity().is_valid_at(at) {
            return Err("control-plane certificate is outside its validity window");
        }
        match cert.extended_key_usage() {
            Ok(Some(eku)) if eku.value.server_auth => {}
            _ => return Err("control-plane certificate lacks the serverAuth EKU"),
        }
        let san = cert
            .subject_alternative_name()
            .map_err(|_| "control-plane certificate has a malformed SAN")?
            .ok_or("control-plane certificate has no SAN")?;
        let host_matches = match self.expected_host.parse::<IpAddr>() {
            Ok(ip) => san.value.general_names.iter().any(|name| match name {
                GeneralName::IPAddress(bytes) => match (ip, bytes.len()) {
                    (IpAddr::V4(v4), 4) => v4.octets()[..] == bytes[..],
                    (IpAddr::V6(v6), 16) => v6.octets()[..] == bytes[..],
                    _ => false,
                },
                _ => false,
            }),
            Err(_) => san.value.general_names.iter().any(|name| match name {
                GeneralName::DNSName(dns) => dns.eq_ignore_ascii_case(&self.expected_host),
                _ => false,
            }),
        };
        if !host_matches {
            return Err("control-plane certificate SAN does not match the --control-plane host");
        }
        let digest = ring::digest::digest(&ring::digest::SHA256, cert.public_key().raw);
        // Constant-time is irrelevant here (public values), plain
        // comparison is fine.
        if digest.as_ref() != self.pin {
            return Err("control-plane leaf SPKI does not match the token's pin");
        }
        Ok(())
    }
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.check(end_entity, now) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(reason) => {
                tracing::warn!(reason, "join: control plane refused by the pinning verifier");
                Err(TlsError::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General(
            "TLS 1.2 is not enabled on the cluster plane".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        tokio_rustls::rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Client config for `lorica cluster join` (Story 9.3 AC #2): no
/// client certificate (the node has none yet), no CA (the node has
/// none yet), the control plane verified by the token's SPKI pin plus
/// the leaf checks in [`SpkiPinVerifier`]. This is the one
/// `dangerous()` builder in the crate and it is confined to the
/// enrollment dial.
pub fn join_client_config(pin: &[u8; 32], expected_host: &str) -> Result<ClientConfig, ClusterTlsError> {
    if expected_host.is_empty() {
        return Err(ClusterTlsError::Parse(
            "the control-plane host must not be empty".into(),
        ));
    }
    let provider = tokio_rustls::rustls::crypto::ring::default_provider();
    let verifier = SpkiPinVerifier {
        pin: *pin,
        expected_host: expected_host.to_string(),
        algorithms: provider.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&version::TLS13])
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.alpn_protocols = vec![CLUSTER_ALPN.to_vec()];
    Ok(config)
}

/// Hot-swappable holder for the operational listener's
/// [`ServerConfig`].
///
/// A rustls `ServerConfig` is immutable once built, and the codebase's
/// historical answer to a changed client CA was "warn and restart".
/// The cluster plane cannot afford that: Story 9.3's revocation
/// rebuilds the config `with_crls(...)` and swaps it here, so every
/// accept AFTER a revocation uses the new CRL without dropping the
/// listener. Reads are lock-free (`arc-swap`), one load per accept.
pub struct SwappableAcceptor {
    config: ArcSwap<ServerConfig>,
}

impl SwappableAcceptor {
    /// Wrap an initial config.
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config: ArcSwap::from(config),
        }
    }

    /// The config to use for the NEXT accept.
    pub fn current(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    /// Replace the config (Story 9.3: rebuilt with a fresh CRL after a
    /// revocation). In-flight sessions are unaffected; the caller is
    /// responsible for tearing those down separately.
    pub fn swap(&self, config: Arc<ServerConfig>) {
        self.config.store(config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::ClusterCa;

    fn install_ring() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn all_three_configs_build_from_ca_material() {
        install_ring();
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
        let (server_pem, server_key) = ca.issue_server_leaf("cp.internal").expect("server leaf");
        let (client_pem, client_key) = ca.issue_client_leaf("node-a").expect("client leaf");

        operational_server_config(ca.cert_pem(), &server_pem, &server_key)
            .expect("operational config");
        enrollment_server_config(&server_pem, &server_key).expect("enrollment config");
        client_config(ca.cert_pem(), &client_pem, &client_key).expect("client config");
    }

    #[test]
    fn garbage_pem_is_rejected() {
        install_ring();
        assert!(matches!(
            enrollment_server_config("not a cert", "not a key"),
            Err(ClusterTlsError::Parse(_))
        ));
    }

    #[test]
    fn pin_verifier_accepts_the_pinned_leaf_and_refuses_everything_else() {
        install_ring();
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
        let (server_pem, _key) = ca.issue_server_leaf("cp.internal").expect("server leaf");
        let (other_pem, _key) = ca.issue_server_leaf("cp.internal").expect("other leaf");
        let (client_pem, _key) = ca.issue_client_leaf("node-a").expect("client leaf");
        let (ip_pem, _key) = ca.issue_server_leaf("192.0.2.10").expect("ip leaf");
        let pin = leaf_spki_sha256(&server_pem).expect("pin");
        let algorithms = tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms;
        let der = |pem: &str| {
            CertificateDer::from_pem_slice(pem.as_bytes())
                .expect("der")
                .into_owned()
        };
        let now = UnixTime::now();
        let verifier = SpkiPinVerifier {
            pin,
            expected_host: "cp.internal".to_string(),
            algorithms,
        };
        assert!(verifier.check(&der(&server_pem), now).is_ok());
        // Same host, different key: pin mismatch.
        assert!(verifier.check(&der(&other_pem), now).is_err());
        // A clientAuth leaf from the same CA never passes.
        assert!(verifier.check(&der(&client_pem), now).is_err());
        // Right key, wrong expected host.
        let wrong_host = SpkiPinVerifier {
            pin,
            expected_host: "evil.internal".to_string(),
            algorithms,
        };
        assert!(wrong_host.check(&der(&server_pem), now).is_err());
        // IP SANs match IP hosts (and not names).
        let ip_pin = leaf_spki_sha256(&ip_pem).expect("pin");
        let by_ip = SpkiPinVerifier {
            pin: ip_pin,
            expected_host: "192.0.2.10".to_string(),
            algorithms,
        };
        assert!(by_ip.check(&der(&ip_pem), now).is_ok());
        assert!(SpkiPinVerifier {
            pin: ip_pin,
            expected_host: "192.0.2.11".to_string(),
            algorithms,
        }
        .check(&der(&ip_pem), now)
        .is_err());
        // Garbage and the empty host are refused at config time / check.
        assert!(verifier.check(&CertificateDer::from(vec![1u8, 2, 3]), now).is_err());
        assert!(join_client_config(&pin, "").is_err());
        join_client_config(&pin, "cp.internal").expect("join config builds");
    }

    #[test]
    fn crl_backed_operational_config_builds() {
        install_ring();
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
        let (server_pem, server_key) = ca.issue_server_leaf("cp.internal").expect("leaf");
        let crl = ca
            .mint_crl(&[crate::ca::RevokedEntry {
                serial_hex: "4A".repeat(16),
                revoked_at: chrono::Utc::now(),
                superseded: false,
            }])
            .expect("crl");
        operational_server_config_with_crl(ca.cert_pem(), &server_pem, &server_key, Some(crl))
            .expect("config with CRL");
    }

    #[test]
    fn swappable_acceptor_serves_the_latest_config() {
        install_ring();
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
        let (server_pem, server_key) = ca.issue_server_leaf("cp.internal").expect("leaf");
        let first =
            Arc::new(enrollment_server_config(&server_pem, &server_key).expect("config one"));
        let acceptor = SwappableAcceptor::new(first.clone());
        assert!(Arc::ptr_eq(&acceptor.current(), &first));

        let second =
            Arc::new(enrollment_server_config(&server_pem, &server_key).expect("config two"));
        acceptor.swap(second.clone());
        assert!(Arc::ptr_eq(&acceptor.current(), &second));
    }
}
