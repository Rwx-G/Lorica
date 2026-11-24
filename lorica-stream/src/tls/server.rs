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

//! Termination (Story 12.4 D-f): the server configs of a terminating
//! stream, one per rule, and the handshake with its classification.
//!
//! Certificates come from the process's resolver, the instance the HTTPS
//! listener answers from and every reload (an ACME, AD CS or manual
//! renewal) swaps in place: a config built over it serves a renewed
//! certificate and a refreshed OCSP staple on its next handshake, with no
//! stream-side reload. A client without SNI gets, through
//! [`LocalIpConfigs`], the certificate whose `iPAddress` SAN is the
//! address it dialed, as on the HTTPS listener; whether such a client is
//! served at all is the matcher's decision (the `no_sni` rule), taken
//! before any handshake.
//!
//! Each config takes the HTTPS listener's choices: TLS 1.2 and 1.3, no
//! 0-RTT (a replayable first flight to a backend that cannot know it was
//! replayed), rustls' default in-memory session cache for stateful
//! resumption and no stateless ticketer (the TLS 1.3 tickets rustls
//! sends by default only name a cache entry); its ALPN is the rule's
//! list, so rustls negotiates the first of the rule's protocols the
//! client offered.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use lorica_config::models::{MtlsConfig, StreamMatchRule};
use lorica_tls::cert_resolver::{LocalIpConfigs, ResolvesServerCertByLocalIp};
use lorica_tls::http_client::crypto_provider;
use lorica_tls::{version, RusTlsError, ServerConfig, ServerTlsStream, TlsAcceptor};
use tokio::io::{AsyncRead, AsyncWrite};

use super::client_auth;
use crate::counters::HandshakeOutcome;
use crate::tcp::FORWARD_BUFFER_SIZE;

/// One rule's config, and its copies per local address.
struct RuleConfig {
    base: Arc<ServerConfig>,
    by_local_ip: LocalIpConfigs,
}

/// The server configs of one terminating stream, built when the engine
/// sees the stream in its table and kept until what they are built from
/// changes, never per connection.
pub struct TerminateConfigs {
    rules: HashMap<String, RuleConfig>,
}

impl TerminateConfigs {
    /// The configs of a stream's match `rules` over `resolver`, sharing
    /// the stream's one client verifier when `client_auth` is set.
    ///
    /// # Errors
    ///
    /// A sentence when the client verifier cannot be built; the stream's
    /// handshakes are then refused, never run without the verification
    /// the operator asked for.
    pub fn build(
        rules: &[StreamMatchRule],
        client_auth: Option<&MtlsConfig>,
        resolver: &Arc<dyn ResolvesServerCertByLocalIp>,
    ) -> Result<TerminateConfigs, String> {
        let verifier = client_auth.map(client_auth::verifier).transpose()?;
        let mut configs = HashMap::new();
        for rule in rules {
            let builder = ServerConfig::builder_with_provider(crypto_provider())
                .with_protocol_versions(&[&version::TLS12, &version::TLS13])
                .map_err(|e| format!("the TLS versions are refused: {e}"))?;
            let builder = match &verifier {
                Some(verifier) => builder.with_client_cert_verifier(Arc::clone(verifier)),
                None => builder.with_no_client_auth(),
            };
            let shared: Arc<dyn ResolvesServerCertByLocalIp> = Arc::clone(resolver);
            let mut config = builder.with_cert_resolver(shared);
            config.alpn_protocols = rule
                .matcher
                .alpn()
                .iter()
                .map(|protocol| protocol.as_bytes().to_vec())
                .collect();
            config.max_early_data_size = 0;
            let base = Arc::new(config);
            configs.insert(
                rule.name.clone(),
                RuleConfig {
                    base: Arc::clone(&base),
                    by_local_ip: LocalIpConfigs::new(base, Arc::clone(resolver)),
                },
            );
        }
        Ok(TerminateConfigs { rules: configs })
    }

    /// The config a connection matched to `rule` and accepted on
    /// `local_ip` handshakes on: the rule's own, or its copy answering a
    /// client without SNI with the certificate of `local_ip`.
    pub fn config(&self, rule: &str, local_ip: IpAddr) -> Option<Arc<ServerConfig>> {
        let rule = self.rules.get(rule)?;
        Some(
            rule.by_local_ip
                .for_connection(|| Some(local_ip))
                .unwrap_or_else(|| Arc::clone(&rule.base)),
        )
    }
}

/// Run the server handshake on `io` with `config`, rustls' plaintext
/// send buffer capped at one forwarding buffer so a terminated
/// connection never grows a queue. The caller bounds it in time.
///
/// # Errors
///
/// [`HandshakeOutcome::ClientCertificate`] when rustls refused the
/// client's certificate or its absence, [`HandshakeOutcome::TlsHandshake`]
/// for any other failure. Whether a failure was for want of a
/// certificate is the caller's to tell, before the handshake.
pub async fn accept<S>(
    config: Arc<ServerConfig>,
    io: S,
) -> Result<ServerTlsStream<S>, HandshakeOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    TlsAcceptor::from(config)
        .accept_with(io, |connection| {
            connection.set_buffer_limit(Some(FORWARD_BUFFER_SIZE));
        })
        .await
        .map_err(|e| classify(&e))
}

fn classify(error: &io::Error) -> HandshakeOutcome {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<RusTlsError>())
    {
        Some(RusTlsError::NoCertificatesPresented | RusTlsError::InvalidCertificate(_)) => {
            HandshakeOutcome::ClientCertificate
        }
        _ => HandshakeOutcome::TlsHandshake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_tls::CertificateError;

    #[test]
    fn client_certificate_errors_are_told_apart_from_the_rest() {
        let wrap = |e: RusTlsError| io::Error::new(io::ErrorKind::InvalidData, e);
        assert_eq!(
            classify(&wrap(RusTlsError::NoCertificatesPresented)),
            HandshakeOutcome::ClientCertificate
        );
        assert_eq!(
            classify(&wrap(RusTlsError::InvalidCertificate(
                CertificateError::UnknownIssuer
            ))),
            HandshakeOutcome::ClientCertificate
        );
        assert_eq!(
            classify(&wrap(RusTlsError::NoApplicationProtocol)),
            HandshakeOutcome::TlsHandshake
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::UnexpectedEof)),
            HandshakeOutcome::TlsHandshake
        );
    }
}
