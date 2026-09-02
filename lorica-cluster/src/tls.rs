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

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};

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
    let roots = ca_root_store(ca_pem)?;
    let verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .map_err(|e| ClusterTlsError::Rustls(format!("client verifier: {e}")))?;
    ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            certs_from_pem(server_cert_pem, "cluster server cert")?,
            key_from_pem(server_key_pem, "cluster server key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))
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
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            certs_from_pem(server_cert_pem, "cluster server cert")?,
            key_from_pem(server_key_pem, "cluster server key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))
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
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            certs_from_pem(client_cert_pem, "node client cert")?,
            key_from_pem(client_key_pem, "node client key")?,
        )
        .map_err(|e| ClusterTlsError::Rustls(e.to_string()))
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
