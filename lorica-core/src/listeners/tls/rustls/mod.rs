// Copyright 2026 Cloudflare, Inc.
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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{server::handshake, server::handshake_with_callback, TlsStream};
use log::debug;
use lorica_error::ErrorType::InternalError;
use lorica_error::{Error, OrErr, Result};
use lorica_tls::cert_resolver::{LocalIpResolver, ResolvesServerCertByLocalIp};
use lorica_tls::load_certs_and_key_files;
use lorica_tls::ClientCertVerifier;
use lorica_tls::ServerConfig;
use lorica_tls::{version, TlsAcceptor as RusTlsAcceptor};

use crate::protocols::{ALPN, IO};
use parking_lot::RwLock;

/// Certificate source for a TLS listener.
enum CertSource {
    /// Single certificate from file paths (original behavior).
    Files { cert_path: String, key_path: String },
    /// Dynamic certificate resolver (SNI-based, supports hot-swap), which
    /// also answers a ClientHello without SNI by the local address.
    Resolver(Arc<dyn ResolvesServerCertByLocalIp>),
}

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_source: CertSource,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
    local_ip_acceptors: Option<LocalIpAcceptors>,
}

/// Lorica: the acceptors for connections whose local address some
/// certificate carries as an `iPAddress` SAN.
///
/// rustls resolves a certificate from the ClientHello alone, and a client
/// dialing an IP sends no SNI (RFC 6066), so the local address is decided
/// before the handshake: such a connection gets a copy of the listener's
/// config whose resolver is a [`LocalIpResolver`] for that address.
/// Everything else in the copy (ALPN, client certificate verifier,
/// session storage, ticketer) is the listener's own.
struct LocalIpAcceptors {
    resolver: Arc<dyn ResolvesServerCertByLocalIp>,
    base_config: Arc<ServerConfig>,
    /// One acceptor per canonical local address, built on first use. An
    /// entry is added only for an address a loaded certificate carries
    /// and that an accepted socket reported as its local address, so the
    /// map is bounded by the addresses the host has bound. It never goes
    /// stale: each [`LocalIpResolver`] reads the hot-swapped resolver on
    /// every handshake.
    by_ip: RwLock<HashMap<IpAddr, RusTlsAcceptor>>,
}

impl LocalIpAcceptors {
    /// The acceptor for `local_ip`, `None` when no certificate carries it
    /// (the listener's own acceptor then applies, unchanged).
    fn for_local_ip(&self, local_ip: IpAddr) -> Option<RusTlsAcceptor> {
        let local_ip: IpAddr = local_ip.to_canonical();
        self.resolver.resolve_by_local_ip(local_ip)?;
        if let Some(acceptor) = self.by_ip.read().get(&local_ip) {
            return Some(acceptor.clone());
        }
        let mut config: ServerConfig = (*self.base_config).clone();
        config.cert_resolver = Arc::new(LocalIpResolver::new(Arc::clone(&self.resolver), local_ip));
        let acceptor = RusTlsAcceptor::from(Arc::new(config));
        Some(
            self.by_ip
                .write()
                .entry(local_ip)
                .or_insert(acceptor)
                .clone(),
        )
    }
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    ///
    /// _NOTE_ This function will panic if there is an error in loading
    /// certificate files or constructing the builder
    ///
    /// Todo: Return a result instead of panicking XD
    pub fn build(self) -> Acceptor {
        let builder =
            ServerConfig::builder_with_protocol_versions(&[&version::TLS12, &version::TLS13]);
        let builder = if let Some(verifier) = self.client_cert_verifier {
            builder.with_client_cert_verifier(verifier)
        } else {
            builder.with_no_client_auth()
        };

        // Lorica: the resolver, kept for the per-local-address acceptors.
        let mut ip_resolver = None;
        let mut config = match self.cert_source {
            CertSource::Files {
                cert_path,
                key_path,
            } => {
                let Ok(Some((certs, key))) = load_certs_and_key_files(&cert_path, &key_path) else {
                    panic!(
                        "Failed to load provided certificates \"{cert_path}\" or key \"{key_path}\".",
                    )
                };
                builder
                    .with_single_cert(certs, key)
                    .explain_err(InternalError, |e| {
                        format!("Failed to create server listener config: {e}")
                    })
                    .unwrap()
            }
            CertSource::Resolver(resolver) => {
                ip_resolver = Some(Arc::clone(&resolver));
                builder.with_cert_resolver(resolver)
            }
        };

        if let Some(alpn_protocols) = self.alpn_protocols {
            config.alpn_protocols = alpn_protocols;
        }

        let config = Arc::new(config);
        Acceptor {
            acceptor: RusTlsAcceptor::from(Arc::clone(&config)),
            callbacks: None,
            local_ip_acceptors: ip_resolver.map(|resolver| LocalIpAcceptors {
                resolver,
                base_config: config,
                by_ip: RwLock::new(HashMap::new()),
            }),
        }
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    pub fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    /// Configure mTLS by providing a rustls client certificate verifier.
    pub fn set_client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) {
        self.client_cert_verifier = Some(verifier);
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::Files {
                cert_path: cert_path.to_string(),
                key_path: key_path.to_string(),
            },
            client_cert_verifier: None,
        })
    }

    /// Create TLS settings with a dynamic certificate resolver.
    ///
    /// The resolver is called during each TLS handshake to select the
    /// appropriate certificate based on the SNI hostname. A ClientHello
    /// without SNI, on a connection whose local address the resolver has
    /// a certificate for, gets that certificate.
    pub fn with_resolver(resolver: Arc<dyn ResolvesServerCertByLocalIp>) -> Self {
        TlsSettings {
            alpn_protocols: None,
            cert_source: CertSource::Resolver(resolver),
            client_cert_verifier: None,
        }
    }

    pub fn with_callbacks() -> Result<Self>
    where
        Self: Sized,
    {
        // TODO: verify if/how callback in handshake can be done using Rustls
        Error::e_explain(
            InternalError,
            "Certificate callbacks are not supported with feature \"rustls\".",
        )
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // Lorica: a connection to an address a certificate carries gets
        // that address's acceptor (see `LocalIpAcceptors`).
        let local_ip_acceptor = self.local_ip_acceptor(&stream);
        let acceptor = local_ip_acceptor.as_ref().unwrap_or(self);
        // TODO: be able to offload this handshake in a thread pool
        if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(acceptor, stream, cb).await
        } else {
            handshake(acceptor, stream).await
        }
    }

    /// Lorica: the acceptor dedicated to the local address `stream` was
    /// accepted on, when a certificate carries that address (see
    /// [`LocalIpAcceptors`]).
    fn local_ip_acceptor<S: IO>(&self, stream: &S) -> Option<Acceptor> {
        let local_ip_acceptors = self.local_ip_acceptors.as_ref()?;
        let digest = stream.get_socket_digest()?;
        let local_ip: IpAddr = digest.local_addr()?.as_inet()?.ip();
        Some(Acceptor {
            acceptor: local_ip_acceptors.for_local_ip(local_ip)?,
            callbacks: None,
            local_ip_acceptors: None,
        })
    }
}
