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

//! TLS at layer 4 (Story 12.4): what a TCP stream in `passthrough` or
//! `terminate` mode reads and decides before it forwards, and the TLS a
//! stream originates towards its backends.
//!
//! [`client_hello`] is the bounded ClientHello reader both modes share,
//! and Story 12.15's TLS matcher with them: it reads the record layer and
//! the hello only far enough to route (server name, offered ALPN, whether
//! Encrypted Client Hello is offered) and does no I/O, so the engine owns
//! the socket, the buffer and the deadline. [`matcher`] picks the rule;
//! [`server`] and [`client_auth`] terminate; [`rewind`] replays the hello
//! to rustls; [`upstream`] originates.
//!
//! The TCP engine runs all of it from its phase 2 and its connect step
//! (`crate::tcp`). What it needs from the binary is [`TlsParts`], handed
//! to [`crate::TcpEngine::with_tls`]: the process's certificate resolver
//! and its public roots. The configs built from them are kept per
//! stream across table changes, rebuilt only when what they are built
//! from changes, so a refresh keeps rustls' session cache; never per
//! connection unless the connection's own snapshot differs.

pub mod client_auth;
pub mod client_hello;
pub mod matcher;
pub mod rewind;
pub mod server;
pub mod upstream;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use lorica_config::models::{
    MtlsConfig, Stream, StreamMatchRule, StreamTlsMode, StreamUpstreamTls,
};
use lorica_tls::cert_resolver::{CertResolver, ResolvesServerCertByLocalIp};
use lorica_tls::{ClientConfig, RootCertStore};
use tracing::warn;

use crate::table::{ClientIdentity, StreamTable};
use server::TerminateConfigs;

/// What the TLS side of the TCP engine needs from the binary.
#[derive(Clone)]
pub struct TlsParts {
    /// The process's certificate resolver, the one the HTTPS listener
    /// answers from and every certificate reload swaps.
    pub resolver: Arc<dyn ResolvesServerCertByLocalIp>,
    /// The public roots, built once per process ([`load_public_roots`]);
    /// `None` when they did not load, which ends the attempts of every
    /// stream that needs them `upstream_tls(no_trust)`.
    pub public_roots: Option<Arc<RootCertStore>>,
}

impl TlsParts {
    /// No certificate and no public roots: a terminating stream's
    /// handshakes fail `no_certificate`, and upstream TLS on the public
    /// roots ends `no_trust`. What [`crate::TcpEngine::new`] runs with
    /// until the binary hands the engine its own.
    pub fn without_certificates() -> TlsParts {
        TlsParts {
            resolver: Arc::new(CertResolver::new()),
            public_roots: None,
        }
    }
}

impl std::fmt::Debug for TlsParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsParts")
            .field("public_roots", &self.public_roots.as_ref().map(|r| r.len()))
            .finish_non_exhaustive()
    }
}

/// The public roots of upstream TLS, read once per process: the webpki
/// bundle and the platform store, through the outbound policy's
/// `http_client::public_roots`. A failure is logged here, once, and
/// gives `None`.
pub fn load_public_roots() -> Option<Arc<RootCertStore>> {
    match lorica_tls::http_client::public_roots() {
        Ok(roots) => Some(Arc::new(roots)),
        Err(e) => {
            warn!(error = %e,
                  "public roots for stream upstream TLS did not load: streams verifying \
                   against them will refuse every backend (upstream_tls no_trust)");
            None
        }
    }
}

/// Everything a stream's TLS configs are built from besides the
/// process's [`TlsParts`], which every build shares. The build reads
/// nothing else, so two equal inputs give interchangeable configs: a
/// table load that leaves them equal keeps the built configs, and with
/// them rustls' session cache (Phase 1 audit C16).
#[derive(PartialEq)]
struct TlsInputs {
    /// Set on a terminating stream.
    terminate: Option<TerminateInputs>,
    /// Set on a stream with upstream TLS.
    upstream: Option<UpstreamInputs>,
}

#[derive(PartialEq)]
struct TerminateInputs {
    rules: Vec<StreamMatchRule>,
    client_auth: Option<MtlsConfig>,
}

struct UpstreamInputs {
    settings: StreamUpstreamTls,
    /// What the table holds for `settings.client_certificate_id`. A
    /// renewal keeps the id and changes this.
    identity: Option<Arc<ClientIdentity>>,
}

impl PartialEq for UpstreamInputs {
    fn eq(&self, other: &Self) -> bool {
        self.settings == other.settings
            && match (&self.identity, &other.identity) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    Arc::ptr_eq(a, b)
                        || (a.chain() == b.chain() && a.key().secret_der() == b.key().secret_der())
                }
                _ => false,
            }
    }
}

impl TlsInputs {
    fn of(stream: &Stream, table: &StreamTable) -> TlsInputs {
        TlsInputs {
            terminate: (stream.tls_mode == StreamTlsMode::Terminate).then(|| TerminateInputs {
                rules: stream.match_rules.clone(),
                client_auth: stream
                    .tls_terminate
                    .as_ref()
                    .and_then(|terminate| terminate.client_auth.clone()),
            }),
            upstream: stream.upstream_tls.as_ref().map(|settings| UpstreamInputs {
                settings: settings.clone(),
                identity: settings
                    .client_certificate_id
                    .as_deref()
                    .and_then(|id| table.client_identity(id))
                    .cloned(),
            }),
        }
    }

    fn needed(&self) -> bool {
        self.terminate.is_some() || self.upstream.is_some()
    }
}

/// The TLS configs of one stream.
pub(crate) struct StreamTlsConfigs {
    /// The server configs of a terminating stream.
    pub(crate) terminate: Option<Result<TerminateConfigs, String>>,
    /// The client config of a stream with upstream TLS.
    pub(crate) upstream: Option<Result<Arc<ClientConfig>, String>>,
}

impl StreamTlsConfigs {
    fn build(inputs: &TlsInputs, parts: &TlsParts) -> StreamTlsConfigs {
        StreamTlsConfigs {
            terminate: inputs.terminate.as_ref().map(|terminate| {
                TerminateConfigs::build(
                    &terminate.rules,
                    terminate.client_auth.as_ref(),
                    &parts.resolver,
                )
            }),
            upstream: inputs.upstream.as_ref().map(|upstream| {
                upstream::client_config(
                    &upstream.settings,
                    parts.public_roots.as_ref(),
                    upstream.identity.as_deref(),
                )
            }),
        }
    }

    fn report(&self, stream: &Stream) {
        if let Some(Err(e)) = &self.terminate {
            warn!(stream_id = %stream.id, stream = %stream.name, error = %e,
                  "terminating stream not configured: its handshakes are refused");
        }
        if let Some(Err(e)) = &self.upstream {
            warn!(stream_id = %stream.id, stream = %stream.name, error = %e,
                  "stream upstream TLS not configured: its attempts end upstream_tls no_trust");
        }
    }
}

/// A stream's configs in the current table: the snapshot they serve and
/// what they were built from.
struct Cached {
    stream: Arc<Stream>,
    inputs: TlsInputs,
    configs: Arc<StreamTlsConfigs>,
}

/// The engine's TLS state: its parts and the configs of the streams of
/// the current table.
pub(crate) struct TlsContext {
    pub(crate) parts: TlsParts,
    configs: Mutex<HashMap<String, Arc<Cached>>>,
}

impl TlsContext {
    pub(crate) fn new(parts: TlsParts) -> TlsContext {
        TlsContext {
            parts,
            configs: Mutex::new(HashMap::new()),
        }
    }

    fn build(&self, stream: &Stream, inputs: &TlsInputs) -> Arc<StreamTlsConfigs> {
        let configs = StreamTlsConfigs::build(inputs, &self.parts);
        configs.report(stream);
        Arc::new(configs)
    }

    /// Hold the configs of every stream of `table` that terminates or
    /// originates TLS, and drop the others'. A stream whose inputs are
    /// unchanged keeps its built configs; any other is rebuilt, so a
    /// renewed client identity or an edited bundle reaches the next
    /// connection.
    pub(crate) fn table_changed(&self, table: &StreamTable) {
        let previous = self
            .configs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let held: HashMap<String, Arc<Cached>> = table
            .streams()
            .filter_map(|stream| {
                let inputs = TlsInputs::of(stream, table);
                if !inputs.needed() {
                    return None;
                }
                let configs = match previous.get(&stream.id) {
                    Some(kept) if kept.inputs == inputs => Arc::clone(&kept.configs),
                    _ => self.build(stream, &inputs),
                };
                let cached = Cached {
                    stream: Arc::clone(stream),
                    inputs,
                    configs,
                };
                Some((stream.id.clone(), Arc::new(cached)))
            })
            .collect();
        *self.configs.lock().unwrap_or_else(PoisonError::into_inner) = held;
    }

    /// The configs for a connection holding `snapshot`, accepted against
    /// `table`: the held ones when `snapshot` is the current table's or
    /// has the same inputs in `table`, otherwise ones built for it now,
    /// so a connection is served by the stream as it was accepted (Story
    /// 12.2 AC #8).
    pub(crate) fn configs(
        &self,
        snapshot: &Arc<Stream>,
        table: &StreamTable,
    ) -> Arc<StreamTlsConfigs> {
        let held = self
            .configs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&snapshot.id)
            .cloned();
        if let Some(held) = held
            .as_ref()
            .filter(|held| Arc::ptr_eq(&held.stream, snapshot))
        {
            return Arc::clone(&held.configs);
        }
        let inputs = TlsInputs::of(snapshot, table);
        match held {
            Some(held) if held.inputs == inputs => Arc::clone(&held.configs),
            _ => self.build(snapshot, &inputs),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::{
        MtlsConfig, StreamMatchRule, StreamMatcher, StreamProtocol, StreamTlsTerminate,
        StreamUpstreamTls,
    };
    use lorica_tls::CertificateDer;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::SignatureScheme;

    use crate::table::ClientIdentity;

    /// A self-signed certificate for `name`: its PEM, its key's PEM and
    /// its DER.
    struct Issued {
        pem: String,
        key_pem: String,
        der: CertificateDer<'static>,
    }

    fn issue(name: &str) -> Issued {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec![name.into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Issued {
            pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    /// Stream `s`, terminating with client authentication against
    /// `client_ca` and originating TLS with the client certificate
    /// `client`.
    fn stream(client_ca: &Issued) -> Stream {
        let mut stream = Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            1,
            1,
            Utc::now(),
        );
        stream.tls_mode = StreamTlsMode::Terminate;
        stream.match_rules = vec![StreamMatchRule {
            name: "app".into(),
            matcher: StreamMatcher::Tls {
                server_names: vec!["app.example.com".into()],
                alpn: vec!["h2".into()],
            },
        }];
        stream.tls_terminate = Some(StreamTlsTerminate {
            certificate_ids: vec!["server".into()],
            client_auth: Some(MtlsConfig {
                ca_cert_pem: client_ca.pem.clone(),
                required: true,
                allowed_organizations: Vec::new(),
            }),
        });
        stream.upstream_tls = Some(StreamUpstreamTls {
            client_certificate_id: Some("client".into()),
            ..StreamUpstreamTls::default()
        });
        stream
    }

    /// A fresh table load of `stream`, holding `identity` as the client
    /// certificate: every `Arc` in it is new, as after a store read.
    fn table(stream: Stream, identity: &Issued) -> StreamTable {
        StreamTable::new(vec![stream], &[]).with_client_identities([(
            "client".to_string(),
            ClientIdentity::from_pem(&identity.pem, &identity.key_pem).unwrap(),
        )])
    }

    fn context() -> TlsContext {
        TlsContext::new(TlsParts {
            resolver: Arc::new(CertResolver::new()),
            public_roots: Some(Arc::new(RootCertStore::empty())),
        })
    }

    /// The configs a connection accepted against `table` gets.
    fn served(context: &TlsContext, table: &StreamTable) -> Arc<StreamTlsConfigs> {
        context.configs(&table.stream("s").unwrap(), table)
    }

    /// The certificate the upstream config presents to a backend.
    fn presented(configs: &StreamTlsConfigs) -> CertificateDer<'static> {
        let Some(Ok(config)) = &configs.upstream else {
            panic!("the upstream config did not build");
        };
        config
            .client_auth_cert_resolver
            .resolve(&[], &[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("a client certificate")
            .cert[0]
            .clone()
    }

    /// A refresh that changes nothing a stream's TLS is built from keeps
    /// its configs, and with them rustls' session cache, for new
    /// connections and for those accepted before the refresh.
    #[test]
    fn an_equal_table_keeps_the_built_configs() {
        let (client_ca, identity) = (issue("client-ca"), issue("lorica"));
        let context = context();
        let first = table(stream(&client_ca), &identity);
        context.table_changed(&first);
        let built = served(&context, &first);
        assert!(matches!(built.terminate, Some(Ok(_))));
        assert!(matches!(built.upstream, Some(Ok(_))));

        let mut renamed = stream(&client_ca);
        renamed.name = "renamed".into();
        let again = table(renamed, &identity);
        context.table_changed(&again);
        assert!(Arc::ptr_eq(&built, &served(&context, &again)));
        assert!(
            Arc::ptr_eq(&built, &served(&context, &first)),
            "a connection accepted before the refresh"
        );
    }

    /// A rotated client certificate, or an edited client CA, rebuilds:
    /// new connections present and verify the new ones, a connection
    /// accepted before keeps what its own table held.
    #[test]
    fn a_rotated_certificate_or_an_edited_bundle_rebuilds() {
        let (client_ca, identity) = (issue("client-ca"), issue("lorica"));
        let context = context();
        let first = table(stream(&client_ca), &identity);
        context.table_changed(&first);
        let built = served(&context, &first);
        assert_eq!(presented(&built), identity.der);

        let rotated_identity = issue("lorica");
        let rotated = table(stream(&client_ca), &rotated_identity);
        context.table_changed(&rotated);
        let rebuilt = served(&context, &rotated);
        assert!(!Arc::ptr_eq(&built, &rebuilt));
        assert_eq!(presented(&rebuilt), rotated_identity.der);
        assert_eq!(presented(&served(&context, &first)), identity.der);

        let edited = table(stream(&issue("other-ca")), &rotated_identity);
        context.table_changed(&edited);
        assert!(!Arc::ptr_eq(&rebuilt, &served(&context, &edited)));
    }
}
