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
//! stream, rebuilt when the engine sees the table change, never per
//! connection.

pub mod client_auth;
pub mod client_hello;
pub mod matcher;
pub mod rewind;
pub mod server;
pub mod upstream;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use lorica_config::models::{Stream, StreamTlsMode};
use lorica_tls::cert_resolver::{CertResolver, ResolvesServerCertByLocalIp};
use lorica_tls::{ClientConfig, RootCertStore};
use tracing::warn;

use crate::table::StreamTable;
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

/// The TLS configs of one stream, built from one snapshot of it.
pub(crate) struct StreamTlsConfigs {
    stream: Arc<Stream>,
    /// The server configs of a terminating stream.
    pub(crate) terminate: Option<Result<TerminateConfigs, String>>,
    /// The client config of a stream with upstream TLS.
    pub(crate) upstream: Option<Result<Arc<ClientConfig>, String>>,
}

impl StreamTlsConfigs {
    fn build(stream: &Arc<Stream>, table: &StreamTable, parts: &TlsParts) -> StreamTlsConfigs {
        StreamTlsConfigs {
            stream: Arc::clone(stream),
            terminate: (stream.tls_mode == StreamTlsMode::Terminate)
                .then(|| TerminateConfigs::build(stream, &parts.resolver)),
            upstream: stream.upstream_tls.as_ref().map(|settings| {
                upstream::client_config(settings, parts.public_roots.as_ref(), table)
            }),
        }
    }

    fn needed(stream: &Stream) -> bool {
        stream.tls_mode == StreamTlsMode::Terminate || stream.upstream_tls.is_some()
    }

    fn report(&self) {
        let stream = &self.stream;
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

/// The engine's TLS state: its parts and the configs of the streams of
/// the current table.
pub(crate) struct TlsContext {
    pub(crate) parts: TlsParts,
    configs: Mutex<HashMap<String, Arc<StreamTlsConfigs>>>,
}

impl TlsContext {
    pub(crate) fn new(parts: TlsParts) -> TlsContext {
        TlsContext {
            parts,
            configs: Mutex::new(HashMap::new()),
        }
    }

    /// Build the configs of every stream of `table` that terminates or
    /// originates TLS, and drop the others'. Runs on every table load:
    /// a renewed client identity or an edited bundle reaches the next
    /// connection.
    pub(crate) fn table_changed(&self, table: &StreamTable) {
        let built: HashMap<String, Arc<StreamTlsConfigs>> = table
            .streams()
            .filter(|stream| StreamTlsConfigs::needed(stream))
            .map(|stream| {
                let configs = StreamTlsConfigs::build(stream, table, &self.parts);
                configs.report();
                (stream.id.clone(), Arc::new(configs))
            })
            .collect();
        *self.configs.lock().unwrap_or_else(PoisonError::into_inner) = built;
    }

    /// The configs for a connection holding `snapshot`, accepted against
    /// `table`: the ones built for that snapshot, or, when the table
    /// moved on since the accept, ones built for it now, so a connection
    /// is served by the stream as it was accepted (Story 12.2 AC #8).
    pub(crate) fn configs(
        &self,
        snapshot: &Arc<Stream>,
        table: &StreamTable,
    ) -> Arc<StreamTlsConfigs> {
        let cached = self
            .configs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&snapshot.id)
            .filter(|configs| Arc::ptr_eq(&configs.stream, snapshot))
            .cloned();
        cached.unwrap_or_else(|| {
            let configs = StreamTlsConfigs::build(snapshot, table, &self.parts);
            configs.report();
            Arc::new(configs)
        })
    }
}
