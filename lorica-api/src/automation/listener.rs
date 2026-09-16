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

//! The automation listener: its own socket, its own TLS, and the
//! bounds a caller crosses before any of it.
//!
//! The accept loop mirrors [`crate::server::start_server`] - manual
//! `TcpListener` accept, a `tokio-rustls` acceptor, `hyper-util`'s
//! auto builder - because that is the shape this project serves axum
//! on. What it adds, in order, before the TLS handshake:
//!
//! 1. the source allowlist,
//! 2. the global handshake permit,
//! 3. the per-source concurrency slot,
//! 4. the per-source attempt window.
//!
//! Steps 2 to 4 are [`lorica_cluster::preauth`], the same budgets the
//! enrollment listener applies and in the same order, held across the
//! handshake and released when the connection ends.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use ipnet::IpNet;
use lorica_cluster::preauth::{AttemptWindow, PreAuthBudgets, SourceGate};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::server::AppState;

/// Why the automation listener could not start.
#[derive(Debug, thiserror::Error)]
pub enum AutomationListenerError {
    /// `automation_allowed_cidrs` was empty, or every entry in it was
    /// unparseable. The listener is never started without a source
    /// allowlist: an automation credential is a machine credential,
    /// and the set of machines that may present one is part of the
    /// configuration, not an afterthought.
    #[error("automation listener needs a non-empty source allowlist: {0}")]
    EmptyAllowlist(String),
    /// One `automation_allowed_cidrs` entry was neither a CIDR nor a
    /// bare address. Refused rather than skipped with a warning: a
    /// typo in an allowlist that silently narrows the allowlist is the
    /// failure an operator discovers during an incident.
    #[error("automation listener source allowlist entry {entry:?} is not a CIDR or an address")]
    InvalidCidr {
        /// The offending entry, as the operator wrote it.
        entry: String,
    },
    /// The management TLS material could not be assembled.
    #[error("automation listener TLS setup failed: {0}")]
    Tls(String),
    /// The socket could not be bound, or the socket inherited from an
    /// outgoing supervisor could not be adopted.
    #[error("automation listener could not bind {addr}: {source}")]
    Bind {
        /// The address that was asked for.
        addr: SocketAddr,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

/// Everything the automation listener needs to run.
#[derive(Debug, Clone)]
pub struct AutomationListenerConfig {
    /// The `host:port` to bind. Unlike the management listener, which
    /// is loopback by construction, this one is told exactly where to
    /// sit: an automation usually runs on another host, and the CLI
    /// refuses a wildcard host without an explicit flag.
    pub addr: SocketAddr,
    /// The source networks allowed to reach the socket. Mandatory and
    /// non-empty; see [`AutomationListenerError::EmptyAllowlist`].
    pub allowed_cidrs: Vec<IpNet>,
    /// Pre-authentication budgets, shared with the cluster listeners.
    pub budgets: PreAuthBudgets,
}

impl AutomationListenerConfig {
    /// Build a config from the operator's strings.
    ///
    /// Bare addresses are promoted to single-host networks, the same
    /// contract `trusted_proxies` and `connection_allow_cidrs` use.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationListenerError::EmptyAllowlist`] when
    /// `allowed_cidrs` has no usable entry, and
    /// [`AutomationListenerError::InvalidCidr`] when one entry does not
    /// parse.
    pub fn new(
        addr: SocketAddr,
        allowed_cidrs: &[String],
    ) -> Result<Self, AutomationListenerError> {
        let mut nets: Vec<IpNet> = Vec::with_capacity(allowed_cidrs.len());
        for entry in allowed_cidrs {
            let trimmed: &str = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(net) = trimmed.parse::<IpNet>() {
                nets.push(net);
            } else if let Ok(ip) = trimmed.parse::<IpAddr>() {
                nets.push(IpNet::from(ip));
            } else {
                return Err(AutomationListenerError::InvalidCidr {
                    entry: entry.clone(),
                });
            }
        }
        if nets.is_empty() {
            return Err(AutomationListenerError::EmptyAllowlist(
                "no entry was supplied".to_string(),
            ));
        }
        Ok(Self {
            addr,
            allowed_cidrs: nets,
            budgets: PreAuthBudgets::default(),
        })
    }

    /// Whether `ip` is inside the allowlist.
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.allowed_cidrs.iter().any(|net| net.contains(&ip))
    }
}

/// Start the automation API on its own socket, over TLS.
///
/// Differs from [`crate::server::start_server`] in three ways: it
/// binds the operator's address instead of loopback, it takes no
/// `SessionStore` and no `RateLimiter` (the plane has no session and
/// no cookie), and it filters the peer address and takes the pre-auth
/// budgets before the handshake.
///
/// `inherited_listener` follows that function's contract exactly:
/// `Some` serves the pre-bound socket an outgoing supervisor handed
/// over on a hot upgrade, so the automation port is served on the SAME
/// kernel listening socket with no rebind gap and no `EADDRINUSE`
/// during the overlap; `None` binds `config.addr` fresh. The caller
/// sets non-blocking mode before handing the socket over.
///
/// TLS material is the management plane's: the same self-signed leaf
/// or operator-supplied pair, from
/// [`crate::management_tls::build_management_server_config`]. One node
/// presents one identity, and a second certificate to renew is a
/// second thing to let expire.
///
/// # Errors
///
/// Returns [`AutomationListenerError`] when the TLS material cannot be
/// assembled or the socket cannot be bound. Once the loop is running
/// it never returns: per-connection failures are logged and dropped.
pub async fn start_automation_server(
    config: AutomationListenerConfig,
    state: AppState,
    inherited_listener: Option<std::net::TcpListener>,
) -> Result<(), AutomationListenerError> {
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder as HyperAutoBuilder;
    use hyper_util::service::TowerToHyperService;
    use tower::Service;

    let data_dir: std::path::PathBuf = state.data_dir.clone();
    let (cert_override, key_override): (Option<String>, Option<String>) = {
        let store = state.store.lock().await;
        match store.get_global_settings() {
            Ok(settings) => (
                settings.management_cert_pem_path,
                settings.management_key_pem_path,
            ),
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to read global settings for automation TLS; using self-signed certificate"
                );
                (None, None)
            }
        }
    };
    let acceptor: TlsAcceptor = TlsAcceptor::from(Arc::new(tls_config(
        &data_dir,
        cert_override.as_deref(),
        key_override.as_deref(),
    )?));

    let mut make_service = super::router::build_automation_router(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener: tokio::net::TcpListener = match inherited_listener {
        Some(std_listener) => {
            info!(
                addr = %config.addr,
                "automation listener adopting the inherited socket (hot upgrade)"
            );
            tokio::net::TcpListener::from_std(std_listener)
        }
        None => tokio::net::TcpListener::bind(config.addr).await,
    }
    .map_err(|source| AutomationListenerError::Bind {
        addr: config.addr,
        source,
    })?;
    info!(
        addr = %config.addr,
        allowed_cidrs = config.allowed_cidrs.len(),
        "automation API listening (bearer tokens only, source-filtered)"
    );

    let handshakes = Arc::new(Semaphore::new(config.budgets.max_concurrent_handshakes));
    let sources = SourceGate::new(config.budgets.max_per_source);
    let attempts = Arc::new(AttemptWindow::new(
        config.budgets.attempt_window,
        config.budgets.max_attempts_per_window,
        config.budgets.attempt_map_cap,
    ));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                warn!(error = %e, "automation listener accept failed");
                continue;
            }
        };

        // The source check sits HERE, before the acceptor ever sees the
        // socket: a caller outside the allowlist gets no handshake, no
        // certificate, and no byte read from them.
        //
        // This is the first axum listener in the project to filter by
        // source, and the check is open-coded rather than reused.
        // `lorica::connection_filter::GlobalConnectionFilter` is the
        // pingora L4 filter: it implements
        // `lorica_core::listeners::ConnectionFilter`, which only that
        // accept path calls, it lives in the `lorica` binary crate
        // (which depends on THIS crate, so referencing it back would
        // be a dependency cycle), and it enforces a different policy -
        // the proxy's hot-reloaded allow/deny lists, default-allow when
        // empty. This allowlist is default-deny and is not reloadable.
        if !config.allows(peer.ip()) {
            drop(tcp);
            tracing::debug!(peer = %peer, "automation connection refused: source not allowed");
            continue;
        }

        // Then the pre-auth budgets, in the enrollment listener's
        // order, all taken before the handshake and held across it.
        let Ok(handshake_permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        let Some(source_slot) = sources.try_enter(peer.ip()) else {
            drop(tcp);
            continue;
        };
        if !attempts.allow(peer.ip()) {
            drop(tcp);
            continue;
        }

        // `make_service` is always ready and its error type is
        // `Infallible`, so the `Err` arm is an empty match on an
        // uninhabited type.
        let tower_service = match make_service.call(peer).await {
            Ok(service) => service,
            Err(err) => match err {},
        };
        let acceptor = acceptor.clone();
        let handshake_timeout = config.budgets.handshake_timeout;

        tokio::spawn(async move {
            // Both guards live to the end of this task: the permit and
            // the slot are released when the connection ends, never
            // when the handshake completes.
            let _handshake_permit = handshake_permit;
            let _source_slot = source_slot;

            let handshake = tokio::time::timeout(handshake_timeout, acceptor.accept(tcp)).await;
            let tls_stream = match handshake {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => {
                    tracing::debug!(peer = %peer, error = %e, "automation TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(peer = %peer, "automation TLS handshake timed out");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let hyper_service = TowerToHyperService::new(tower_service);
            if let Err(e) = HyperAutoBuilder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(io, hyper_service)
                .await
            {
                tracing::debug!(peer = %peer, error = %e, "automation connection ended with error");
            }
        });
    }
}

/// The automation listener's rustls config, borrowed from the
/// management plane.
fn tls_config(
    data_dir: &Path,
    cert_override: Option<&str>,
    key_override: Option<&str>,
) -> Result<tokio_rustls::rustls::ServerConfig, AutomationListenerError> {
    crate::management_tls::build_management_server_config(data_dir, cert_override, key_override)
        .map_err(|e| AutomationListenerError::Tls(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 9443))
    }

    #[test]
    fn an_empty_allowlist_is_refused() {
        assert!(matches!(
            AutomationListenerConfig::new(addr(), &[]),
            Err(AutomationListenerError::EmptyAllowlist(_))
        ));
        // Blank entries are not entries.
        assert!(matches!(
            AutomationListenerConfig::new(addr(), &["   ".to_string()]),
            Err(AutomationListenerError::EmptyAllowlist(_))
        ));
    }

    #[test]
    fn a_typo_in_the_allowlist_is_refused_not_skipped() {
        let result = AutomationListenerConfig::new(
            addr(),
            &["10.0.0.0/8".to_string(), "10.0.0.0/33".to_string()],
        );
        assert!(matches!(
            result,
            Err(AutomationListenerError::InvalidCidr { .. })
        ));
    }

    #[test]
    fn the_allowlist_is_default_deny() {
        let config = AutomationListenerConfig::new(
            addr(),
            &["10.0.0.0/8".to_string(), "192.0.2.10".to_string()],
        )
        .expect("test config");

        assert!(config.allows("10.4.5.6".parse().expect("test ip")));
        assert!(config.allows("192.0.2.10".parse().expect("test ip")));
        assert!(!config.allows("192.0.2.11".parse().expect("test ip")));
        assert!(!config.allows("127.0.0.1".parse().expect("test ip")));
        assert!(!config.allows("::1".parse().expect("test ip")));
    }
}
