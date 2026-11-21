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

//! Upstream TLS (Story 12.4 D-i): the client config of a stream that
//! originates or re-encrypts TLS towards its backends, the name each
//! attempt sends and verifies, and the handshake with its
//! classification.
//!
//! The config starts from the outbound policy's
//! `http_client::config_builder()` (the `ring` provider, rustls' safe
//! default versions), never from the finished HTTP configs, whose
//! `http/1.1` ALPN a backend with its own list would refuse. Verification
//! is on by default against the public roots, built once per process, or
//! against the stream's own bundle, which replaces them. `skip_verify`
//! accepts any certificate and is refused beside a client certificate
//! (the policy `http_client` states for an unverified client: never one
//! that carries a credential) or a bundle.

use std::io;
use std::sync::Arc;

use lorica_config::models::{backend_address_host, Backend, StreamUpstreamTls, UpstreamServerName};
use lorica_tls::http_client::{accept_any_server, config_builder, pem_roots};
use lorica_tls::{
    ClientConfig, ClientTlsStream, RootCertStore, RusTlsError, ServerName, TlsConnector,
};
use tokio::net::TcpStream;

use crate::counters::UpstreamTlsFailure;
use crate::table::StreamTable;
use crate::tcp::FORWARD_BUFFER_SIZE;

/// The client config of a stream's upstream TLS `settings`.
/// `public_roots` is the process's store, `None` when it did not load;
/// `table` holds the client identities.
///
/// # Errors
///
/// A sentence naming why the stream's upstream TLS cannot be configured
/// on this node: `skip_verify` beside a credential or a bundle, a bundle
/// that does not load in full, public roots that did not load, a client
/// identity whose key is not held here. Every attempt of the stream then
/// ends `upstream_tls(no_trust)`.
pub fn client_config(
    settings: &StreamUpstreamTls,
    public_roots: Option<&Arc<RootCertStore>>,
    table: &StreamTable,
) -> Result<Arc<ClientConfig>, String> {
    if settings.skip_verify && settings.client_certificate_id.is_some() {
        return Err("skip_verify is refused beside a client certificate".into());
    }
    if settings.skip_verify && settings.ca_cert_pem.is_some() {
        return Err("skip_verify is refused beside a CA bundle".into());
    }
    let builder = config_builder();
    let builder = if settings.skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(accept_any_server())
    } else {
        let roots: Arc<RootCertStore> = match &settings.ca_cert_pem {
            Some(pem) => Arc::new(
                pem_roots(pem.as_bytes())
                    .map_err(|e| format!("the upstream CA bundle does not load: {e}"))?,
            ),
            None => Arc::clone(public_roots.ok_or("the public roots did not load")?),
        };
        builder.with_root_certificates(roots)
    };
    let mut config = match &settings.client_certificate_id {
        Some(id) => {
            let identity = table
                .client_identity(id)
                .ok_or_else(|| format!("client certificate `{id}` is not held on this node"))?;
            builder
                .with_client_auth_cert(identity.chain().to_vec(), identity.key())
                .map_err(|e| format!("client certificate `{id}` is refused: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(Arc::new(config))
}

/// The name an attempt on `backend` sends as SNI and verifies:
/// the backend's host part, the client's SNI as matched (`client_sni`,
/// falling back to the backend's host for a client without one), or the
/// fixed name. An IP literal sends no SNI and is verified against an
/// `iPAddress` SAN.
///
/// # Errors
///
/// A sentence when the name is neither a DNS name nor an IP literal.
pub fn server_name(
    mode: &UpstreamServerName,
    backend: &Backend,
    client_sni: Option<&str>,
) -> Result<ServerName<'static>, String> {
    let backend_host = || backend_address_host(&backend.address);
    let name: &str = match mode {
        UpstreamServerName::BackendAddress {} => backend_host(),
        UpstreamServerName::Client {} => client_sni.unwrap_or_else(backend_host),
        UpstreamServerName::Fixed { name } => name,
    };
    ServerName::try_from(name.to_string())
        .map_err(|_| format!("`{name}` is not a server name upstream TLS can verify"))
}

/// Whether the name [`server_name`] gives for `mode` is the client's
/// choice: its SNI, which a wildcard rule lets it pick. A backend that
/// refuses such a name says nothing about its health, so the breaker
/// does not count that refusal (Phase 1 audit C3).
pub fn named_by_client(mode: &UpstreamServerName, client_sni: Option<&str>) -> bool {
    matches!(mode, UpstreamServerName::Client {}) && client_sni.is_some()
}

/// Run the client handshake on `socket`, rustls' plaintext send buffer
/// capped at one forwarding buffer. The caller bounds it in time.
///
/// # Errors
///
/// [`UpstreamTlsFailure::Verify`] when the backend's certificate did not
/// verify, [`UpstreamTlsFailure::Handshake`] for any other failure.
pub async fn connect(
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
    socket: TcpStream,
) -> Result<ClientTlsStream<TcpStream>, UpstreamTlsFailure> {
    TlsConnector::from(config)
        .connect_with(name, socket, |connection| {
            connection.set_buffer_limit(Some(FORWARD_BUFFER_SIZE));
        })
        .await
        .map_err(|e| classify(&e))
}

fn classify(error: &io::Error) -> UpstreamTlsFailure {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<RusTlsError>())
    {
        Some(RusTlsError::InvalidCertificate(_)) => UpstreamTlsFailure::Verify,
        _ => UpstreamTlsFailure::Handshake,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::{HealthCheck, HealthStatus, LifecycleState};
    use lorica_tls::CertificateError;

    fn backend(address: &str) -> Backend {
        Backend {
            id: "b".into(),
            address: address.into(),
            name: "b".into(),
            group_name: String::new(),
            weight: 1,
            health_status: HealthStatus::Healthy,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            health_check: HealthCheck::default(),
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

    #[test]
    fn each_mode_names_its_server() {
        let dns = backend("db.internal.example:5432");
        let ip = backend("[2001:db8::1]:5432");
        let address = UpstreamServerName::BackendAddress {};
        let client = UpstreamServerName::Client {};
        let fixed = UpstreamServerName::Fixed {
            name: "pinned.example.com".into(),
        };
        let named = |n: &str| ServerName::try_from(n.to_string()).unwrap();
        assert_eq!(
            server_name(&address, &dns, Some("app.example.com")).unwrap(),
            named("db.internal.example")
        );
        assert_eq!(
            server_name(&address, &ip, None).unwrap(),
            named("2001:db8::1")
        );
        assert!(matches!(
            server_name(&address, &ip, None).unwrap(),
            ServerName::IpAddress(_)
        ));
        assert_eq!(
            server_name(&client, &dns, Some("app.example.com")).unwrap(),
            named("app.example.com")
        );
        assert_eq!(
            server_name(&client, &dns, None).unwrap(),
            named("db.internal.example")
        );
        assert_eq!(
            server_name(&fixed, &ip, Some("app.example.com")).unwrap(),
            named("pinned.example.com")
        );
    }

    #[test]
    fn only_a_client_sni_sent_in_client_mode_is_the_clients_choice() {
        let client = UpstreamServerName::Client {};
        assert!(named_by_client(&client, Some("zz.example.com")));
        assert!(
            !named_by_client(&client, None),
            "the fallback is the backend's own host"
        );
        assert!(!named_by_client(
            &UpstreamServerName::BackendAddress {},
            Some("zz.example.com")
        ));
        assert!(!named_by_client(
            &UpstreamServerName::Fixed {
                name: "pinned.example.com".into()
            },
            Some("zz.example.com")
        ));
    }

    #[test]
    fn skip_verify_beside_a_credential_or_a_bundle_is_refused() {
        let table = StreamTable::default();
        let with_identity = StreamUpstreamTls {
            skip_verify: true,
            client_certificate_id: Some("c".into()),
            ..StreamUpstreamTls::default()
        };
        assert!(client_config(&with_identity, None, &table)
            .unwrap_err()
            .contains("client certificate"));
        let with_bundle = StreamUpstreamTls {
            skip_verify: true,
            ca_cert_pem: Some("x".into()),
            ..StreamUpstreamTls::default()
        };
        assert!(client_config(&with_bundle, None, &table).is_err());
        let bare = StreamUpstreamTls {
            skip_verify: true,
            alpn: vec!["postgresql".into()],
            ..StreamUpstreamTls::default()
        };
        let config = client_config(&bare, None, &table).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"postgresql".to_vec()]);
    }

    #[test]
    fn missing_trust_or_identity_leaves_the_stream_unconfigured() {
        let table = StreamTable::default();
        let public = StreamUpstreamTls::default();
        assert!(client_config(&public, None, &table)
            .unwrap_err()
            .contains("public roots"));
        assert!(client_config(&public, Some(&Arc::new(RootCertStore::empty())), &table).is_ok());
        let identity = StreamUpstreamTls {
            client_certificate_id: Some("absent".into()),
            ..StreamUpstreamTls::default()
        };
        assert!(
            client_config(&identity, Some(&Arc::new(RootCertStore::empty())), &table)
                .unwrap_err()
                .contains("not held")
        );
    }

    #[test]
    fn a_verification_failure_is_told_apart_from_the_rest() {
        let wrap = |e: RusTlsError| io::Error::new(io::ErrorKind::InvalidData, e);
        assert_eq!(
            classify(&wrap(RusTlsError::InvalidCertificate(
                CertificateError::NotValidForName
            ))),
            UpstreamTlsFailure::Verify
        );
        assert_eq!(
            classify(&io::Error::from(io::ErrorKind::ConnectionReset)),
            UpstreamTlsFailure::Handshake
        );
    }
}
