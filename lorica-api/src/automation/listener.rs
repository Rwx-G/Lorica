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
//! Steps 2 to 4 are [`lorica_cluster::preauth`], the enrollment
//! listener's machinery in the same order, held across the handshake
//! and released when the connection ends. The NUMBERS are this plane's
//! own, [`automation_preauth_budgets`]: a pipeline is not an
//! enrollment, and the defaults sized for one node making one attempt
//! dropped a CI runner's twenty-first `curl` before TLS.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use ipnet::IpNet;
use lorica_cluster::preauth::{AttemptWindow, PreAuthBudgets, SourceGate};
use lorica_config::connection_filter::{parse_cidr, ConnectionFilterPolicy};
use parking_lot::RwLock;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

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

/// The source allowlist the accept loop consults, swappable while the
/// listener runs.
///
/// Read once at process start, the allowlist was a fact an operator
/// could not change without a restart: narrowing it during an incident
/// had no effect until the service bounced, and nothing said so. It is
/// held here behind a lock over an `Arc` instead, the shape
/// `lorica::connection_filter::GlobalConnectionFilter` uses for the
/// TCP pre-filter, so a settings write followed by a config reload
/// takes effect on the NEXT accepted connection. Connections already
/// established are not dropped: this is an allowlist on accept, not a
/// session killer.
///
/// The read happens once per TCP accept, not once per request, so an
/// uncontended read lock is not worth a new dependency to avoid; the
/// swap itself is a single pointer store under the write lock.
#[derive(Debug)]
pub struct AutomationSourcePolicy {
    policy: RwLock<Arc<ConnectionFilterPolicy>>,
}

impl AutomationSourcePolicy {
    /// Wrap already-parsed networks. Private because the only way in
    /// is [`AutomationListenerConfig::new`], which refuses an empty
    /// set; a policy with no entry would read as default-allow.
    fn from_nets(nets: Vec<IpNet>) -> Self {
        Self {
            policy: RwLock::new(Arc::new(ConnectionFilterPolicy::from_nets(
                nets,
                Vec::new(),
            ))),
        }
    }

    /// Whether `ip` is inside the allowlist as it stands right now.
    pub fn allows(&self, ip: IpAddr) -> bool {
        let snapshot: Arc<ConnectionFilterPolicy> = Arc::clone(&self.policy.read());
        snapshot.accepts(ip)
    }

    /// How many networks the live allowlist holds, for the operator
    /// log lines that report the shape of the listener.
    pub fn entries(&self) -> usize {
        self.policy.read().allow.len()
    }

    /// Replace the allowlist with `allowed_cidrs`.
    ///
    /// # Errors
    ///
    /// The same two refusals [`AutomationListenerConfig::new`] applies
    /// at start, and for the same reasons. On either one the PREVIOUS
    /// allowlist stands: an empty or unreadable list must never widen
    /// the listener to every source, and a reload is not a place to
    /// fail open. The caller logs the refusal.
    pub fn reload(&self, allowed_cidrs: &[String]) -> Result<usize, AutomationListenerError> {
        let nets: Vec<IpNet> = parse_allowlist(allowed_cidrs)?;
        let count: usize = nets.len();
        *self.policy.write() = Arc::new(ConnectionFilterPolicy::from_nets(nets, Vec::new()));
        Ok(count)
    }
}

/// The policy the listener running in THIS process consults, published
/// by the startup path so the config-reload path can reach it.
///
/// A process-global rather than an argument threaded through the
/// reload signature, because of where the two sides live: the listener
/// is started from the `lorica` binary API task, and the commit half
/// of a config reload runs in `lorica::reload`, which cannot borrow
/// anything that task owns. A worker process never starts the
/// listener, so the slot stays empty there and
/// [`reload_automation_source_policy`] is a no-op.
static LIVE_SOURCE_POLICY: OnceLock<Arc<AutomationSourcePolicy>> = OnceLock::new();

/// Publish the policy of the listener this process is about to start.
///
/// Called once, before the accept loop is spawned. A second call is
/// ignored: one process serves at most one automation listener.
pub fn publish_automation_source_policy(policy: &Arc<AutomationSourcePolicy>) {
    let _ = LIVE_SOURCE_POLICY.set(Arc::clone(policy));
}

/// Apply `automation_allowed_cidrs` to the running listener.
///
/// A no-op when this process runs no automation listener, which is
/// every worker and every node that did not pass
/// `--automation-listen`.
///
/// A refused list (empty, or carrying an entry that is not an address)
/// leaves the previous allowlist in place and is logged at ERROR: an
/// operator who emptied the setting expecting the socket to close
/// needs to read that it did not, and the alternative, an empty
/// allowlist read as default-allow, would turn a narrowing into the
/// widest possible opening. The listener refuses to OPEN on an empty
/// allowlist and refuses to ADOPT one live, which is the same rule
/// said twice on purpose.
pub fn reload_automation_source_policy(allowed_cidrs: &[String]) {
    let Some(live) = LIVE_SOURCE_POLICY.get() else {
        return;
    };
    match live.reload(allowed_cidrs) {
        Ok(count) => info!(
            allowed_cidrs = count,
            "automation listener source allowlist reloaded"
        ),
        Err(e) => error!(
            error = %e,
            allowed_cidrs = live.entries(),
            "automation listener source allowlist NOT reloaded; the previous allowlist still \
             applies. The listener will not accept an empty or unreadable allowlist live, the \
             same way it will not open on one. To stop serving automation, drop \
             --automation-listen and restart"
        ),
    }
}

/// Parse an allowlist into networks, refusing an empty set and any
/// entry that is not an address.
///
/// One function for both doors, the start-time build and the live
/// reload, so the two can never drift into accepting different lists.
fn parse_allowlist(allowed_cidrs: &[String]) -> Result<Vec<IpNet>, AutomationListenerError> {
    let mut nets: Vec<IpNet> = Vec::with_capacity(allowed_cidrs.len());
    for entry in allowed_cidrs {
        if entry.trim().is_empty() {
            continue;
        }
        let net: IpNet = parse_cidr(entry).map_err(|_| AutomationListenerError::InvalidCidr {
            entry: entry.clone(),
        })?;
        nets.push(net);
    }
    if nets.is_empty() {
        return Err(AutomationListenerError::EmptyAllowlist(
            "no entry was supplied".to_string(),
        ));
    }
    Ok(nets)
}

/// Accepted connections one source may open inside
/// [`AUTOMATION_ATTEMPT_WINDOW`] before the listener drops it.
pub const AUTOMATION_MAX_ATTEMPTS_PER_WINDOW: usize = 300;

/// Pre-session connections one source may hold at once.
pub const AUTOMATION_MAX_PER_SOURCE: usize = 32;

/// Pre-session connections the whole listener may hold at once.
pub const AUTOMATION_MAX_CONCURRENT_HANDSHAKES: usize = 256;

/// The sliding window [`AUTOMATION_MAX_ATTEMPTS_PER_WINDOW`] counts in.
pub const AUTOMATION_ATTEMPT_WINDOW: Duration = Duration::from_secs(60);

/// The pre-authentication budgets the automation listener applies.
///
/// Deliberately NOT [`PreAuthBudgets::default`]. Those defaults are the
/// enrollment listener's, and they are sized for the traffic an
/// enrollment sees: one node makes one attempt, so 20 attempts per
/// source per minute and 8 concurrent connections per source are
/// already generous there.
///
/// The automation plane sees the opposite shape. A CI runner opens one
/// connection per `curl`, and a pipeline that declares an environment,
/// uploads a certificate and polls for the result makes tens of calls
/// from ONE address inside a minute. Under the enrollment numbers the
/// twenty-first connection was dropped before TLS, so the runner saw a
/// connection reset rather than a 429 and had nothing to retry against.
/// 300 attempts per minute and 32 concurrent connections per source
/// leave room for a busy pipeline while staying a hard floor against a
/// source that opens connections in a loop: past it the connection is
/// dropped exactly as before, and
/// `lorica_automation_rejected_attempt_window_total` says so.
///
/// The remaining fields keep the shared defaults: the 3-second
/// handshake timeout and the 4096-source map bound are not
/// workload-specific, and the enrollment-only fields
/// (`max_inflight_enrollments`, `per_conn_max_bytes`,
/// `per_conn_max_duration`) are unread on this path.
pub fn automation_preauth_budgets() -> PreAuthBudgets {
    PreAuthBudgets {
        max_concurrent_handshakes: AUTOMATION_MAX_CONCURRENT_HANDSHAKES,
        max_per_source: AUTOMATION_MAX_PER_SOURCE,
        max_attempts_per_window: AUTOMATION_MAX_ATTEMPTS_PER_WINDOW,
        attempt_window: AUTOMATION_ATTEMPT_WINDOW,
        ..PreAuthBudgets::default()
    }
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
    ///
    /// Held as an [`AutomationSourcePolicy`] over a
    /// [`ConnectionFilterPolicy`] with an empty deny list, so an
    /// operator can narrow it during an incident without a restart.
    /// The underlying type reads an EMPTY allow list as default-allow,
    /// which this listener must never do; neither
    /// [`AutomationListenerConfig::new`] nor
    /// [`AutomationSourcePolicy::reload`] will build one, so the
    /// default-allow branch is unreachable here and the policy is
    /// default-deny in practice.
    pub allowed_cidrs: Arc<AutomationSourcePolicy>,
    /// Pre-authentication budgets. The cluster listeners' type, sized
    /// for this plane's traffic: see [`automation_preauth_budgets`].
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
        let nets: Vec<IpNet> = parse_allowlist(allowed_cidrs)?;
        Ok(Self {
            addr,
            allowed_cidrs: Arc::new(AutomationSourcePolicy::from_nets(nets)),
            budgets: automation_preauth_budgets(),
        })
    }

    /// Whether `ip` is inside the allowlist as it stands right now.
    pub fn allows(&self, ip: IpAddr) -> bool {
        self.allowed_cidrs.allows(ip)
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
        allowed_cidrs = config.allowed_cidrs.entries(),
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
        // The RULE is shared: `ConnectionFilterPolicy` in
        // `lorica-config` decides both this allowlist and the proxy's
        // TCP pre-filter, so one definition of an address entry serves
        // both. The RUNTIME is not:
        // `lorica::connection_filter::GlobalConnectionFilter` carries
        // the `ArcSwap`, the per-IP counters and the pingora
        // `lorica_core::listeners::ConnectionFilter` implementation,
        // it lives in the `lorica` binary crate (which depends on THIS
        // crate, so referencing it back would be a dependency cycle),
        // and it is default-allow when empty. This allowlist is
        // default-deny, and it is hot-reloaded too: the read below
        // goes through `AutomationSourcePolicy`, so narrowing
        // `automation_allowed_cidrs` bites on the next accept instead
        // of on the next restart.
        if !config.allows(peer.ip()) {
            drop(tcp);
            crate::metrics::inc_automation_source_refused();
            tracing::debug!(peer = %peer, "automation connection refused: source not allowed");
            continue;
        }

        // Then the pre-auth budgets, in the enrollment listener's
        // order, all taken before the handshake and held across it.
        // Each refusal has its own counter: they answer different
        // questions (is the node saturated, is one source hammering,
        // is one source retrying too fast) and one shared counter
        // would hide which budget is the one biting.
        let Ok(handshake_permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            drop(tcp);
            crate::metrics::inc_automation_rejected_concurrent_handshakes();
            continue;
        };
        let Some(source_slot) = sources.try_enter(peer.ip()) else {
            drop(tcp);
            crate::metrics::inc_automation_rejected_per_source();
            continue;
        };
        if !attempts.allow(peer.ip()) {
            drop(tcp);
            crate::metrics::inc_automation_rejected_attempt_window();
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
                    crate::metrics::inc_automation_tls_handshake_failed();
                    tracing::debug!(peer = %peer, error = %e, "automation TLS handshake failed");
                    return;
                }
                Err(_) => {
                    crate::metrics::inc_automation_tls_handshake_failed();
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

    /// Story 10.3, audit M5: narrowing the allowlist during an
    /// incident must bite on the next accept, not on the next restart,
    /// and no reload may ever widen it by accident.
    #[test]
    fn a_swap_narrows_the_set_the_accept_check_consults() {
        let config = AutomationListenerConfig::new(addr(), &["10.0.0.0/8".to_string()])
            .expect("test config");
        let inside: IpAddr = "10.4.5.6".parse().expect("test ip");
        let outside: IpAddr = "10.9.9.9".parse().expect("test ip");
        assert!(config.allows(inside));
        assert!(config.allows(outside));

        // The narrowing an operator does mid-incident.
        assert_eq!(
            config
                .allowed_cidrs
                .reload(&["10.4.0.0/16".to_string()])
                .expect("a narrower allowlist applies"),
            1
        );
        assert!(config.allows(inside));
        assert!(
            !config.allows(outside),
            "the accept check must read the narrowed allowlist, not the one from process start"
        );

        // An emptied setting keeps the previous allowlist: an empty
        // allow list reads as default-allow, so adopting it would turn
        // the narrowing into the widest possible opening.
        assert!(matches!(
            config.allowed_cidrs.reload(&[]),
            Err(AutomationListenerError::EmptyAllowlist(_))
        ));
        assert!(config.allows(inside));
        assert!(!config.allows(outside));

        // A typo is refused whole, for the same reason it is refused
        // at start: a partially applied allowlist is the failure an
        // operator discovers during an incident.
        assert!(matches!(
            config
                .allowed_cidrs
                .reload(&["10.0.0.0/8".to_string(), "10.0.0.0/33".to_string()]),
            Err(AutomationListenerError::InvalidCidr { .. })
        ));
        assert!(!config.allows(outside));
        assert_eq!(config.allowed_cidrs.entries(), 1);
    }

    #[test]
    fn a_reload_without_a_listener_in_this_process_is_a_no_op() {
        // Every worker process and every node without
        // `--automation-listen` reaches the commit half of a config
        // reload with nothing published. It must not panic there.
        reload_automation_source_policy(&["10.0.0.0/8".to_string()]);
        reload_automation_source_policy(&[]);
    }

    #[test]
    fn the_pre_auth_budgets_are_sized_for_pipelines_not_for_enrolment() {
        let budgets: PreAuthBudgets = automation_preauth_budgets();
        assert_eq!(budgets.max_attempts_per_window, 300);
        assert_eq!(budgets.max_per_source, 32);
        assert_eq!(budgets.max_concurrent_handshakes, 256);
        assert_eq!(budgets.attempt_window, Duration::from_secs(60));
        // The enrolment defaults are what a thirty-call pipeline used
        // to run into, so the two must not be the same number.
        assert_ne!(
            budgets.max_attempts_per_window,
            PreAuthBudgets::default().max_attempts_per_window
        );
        // And the listener actually takes them.
        let config = AutomationListenerConfig::new(addr(), &["10.0.0.0/8".to_string()])
            .expect("test config");
        assert_eq!(config.budgets.max_attempts_per_window, 300);
        assert_eq!(config.budgets.max_per_source, 32);
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
