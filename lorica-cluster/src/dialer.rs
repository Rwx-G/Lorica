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

//! Follower dialer (Story 9.2 AC #9): one long-lived OUTBOUND mutual
//! TLS connection to the control plane, so a follower never exposes an
//! inbound port.
//!
//! The reconnect loop: resolve the control-plane name, TCP + TLS
//! connect under `connect_timeout`, session handshake, publish the
//! endpoint (tagged with a session generation) into an
//! [`arc_swap::ArcSwapOption`] read lock-free by the rest of the
//! process, heartbeat until the connection dies, clear the slot, back
//! off and retry. Every transition is logged: a follower that cannot
//! reach its control plane is the epic's most common support case and
//! must be debuggable from its own journal.
//!
//! # The connection is bidirectional (Story 9.4)
//!
//! Story 9.2 dropped the endpoint's incoming half: nothing was
//! server-initiated. Since Story 9.4 the control plane PUSHES
//! configuration down this same connection, and since Story 9.5 it
//! pushes certificate material down it too, so the dialer serves that
//! half for the life of the session: every inbound request goes through
//! [`translate_control_plane_request`], the three configuration pushes,
//! the certificate push and the HTTP-01 challenge pair reach the
//! [`FollowerHandler`], an unknown method is refused without dropping
//! the session, and anything else is a protocol violation that ends it.
//! A node without a [`FollowerHandler`] answers every push
//! `UNSUPPORTED_METHOD`, which keeps the transport-only tests honest.
//!
//! # The dial target is a NAME, resolved on every attempt
//!
//! `control_plane` is kept as an unresolved `host:port` and resolved
//! inside each attempt (every address the name resolves to is tried
//! in order). A control plane that fails over, is re-provisioned or
//! is rescheduled onto another address is followed by the fleet on
//! its next reconnect; pinning one `SocketAddr` at spawn time would
//! turn every such event into a fleet-wide, silent, restart-only
//! outage. The certificate identity (`server_name`) is independent of
//! the address.
//!
//! # Backoff
//!
//! Exponential with equal jitter: after `n` consecutive failures the
//! nominal delay is `base * 2^n` clamped to the cap, and the actual
//! delay is `nominal/2 + uniform(0..nominal/2)` so a fleet does not
//! reconnect in lockstep while every node still retries within its
//! nominal bound. The cap starts at `default_backoff_cap` and, once a
//! `HelloAck`/`HeartbeatAck` supplies `fleet_size_hint`, becomes
//! `clamp(default_backoff_cap + hint seconds, default_backoff_cap,
//! 300s)`: a 200-node fleet spreads its reconvergence over minutes, a
//! 3-node lab stays snappy. A `RETRY_LATER` answer sets the next delay
//! to the server-provided `retry_after_s` (AC #10), clamped to the
//! same 300 s ceiling so a buggy or hostile control plane cannot park
//! a follower for years, and floored by the exponential schedule so
//! a control plane answering `retry_after_s = 0` forever cannot keep
//! a follower in a one-second full-mTLS reconnect loop either.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::task::JoinHandle;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use lorica_command::{IncomingRequest, IncomingRequests, RpcEndpoint};

use crate::bridge::{translate_control_plane_request, FollowerAction, FollowerBridgeOutcome};
use crate::certs::{CertBundle, CertInstallReport};
use crate::enroll::BoxFuture;
use crate::handshake::{client_handshake, HandshakeConfig, HandshakeError};
use crate::limits::cluster_rpc_limits;
use crate::messages::{
    cluster_response, config_hash_is_valid, BanPushAck, CertPushAck, CertRefusal,
    ChallengePublishAck, ChallengeRetractAck, ClusterFrame, ClusterRequest, ClusterResponse,
    ClusterStatus, ConfigAbortAck, ConfigCommitAck, ConfigPrepareAck, Heartbeat, HelloAck,
    NodeResources,
};
use crate::replication::{AppliedConfig, ConfigPayload, ConfigVersion};
use crate::tls::{client_config, negotiated_cluster_alpn, ClusterTlsError};

/// Hard ceiling on every reconnect delay: the scaled backoff cap AND
/// a server-provided `retry_after_s`.
pub const BACKOFF_CAP_CEILING: Duration = Duration::from_secs(300);

/// Grace period for a refusal to flush before the session is dropped.
const REFUSAL_FLUSH_GRACE: Duration = Duration::from_secs(1);

/// Why a dialer could not be spawned.
#[derive(Debug, thiserror::Error)]
pub enum DialerError {
    /// The TLS material or server name was unusable.
    #[error(transparent)]
    Tls(#[from] ClusterTlsError),
    /// `control_plane` is not a `host:port`.
    #[error("invalid control-plane address {0:?}: expected host:port")]
    Address(String),
}

/// Dialer counters (bridged to Prometheus by the binary, AC #12).
#[derive(Debug, Default)]
pub struct DialerStats {
    /// TCP+TLS connection attempts.
    pub connect_attempts: AtomicU64,
    /// Attempts that failed before the session handshake (resolution,
    /// TCP, TLS, `connect_timeout`, missing ALPN).
    pub connect_failures: AtomicU64,
    /// Sessions admitted by the control plane.
    pub handshakes_ok: AtomicU64,
    /// Handshakes refused (version/schema/violation).
    pub handshake_refusals: AtomicU64,
    /// RETRY_LATER answers honoured (AC #10).
    pub retry_later: AtomicU64,
    /// Heartbeats acknowledged.
    pub heartbeats_ok: AtomicU64,
    /// Heartbeats that failed (and tore the connection down).
    pub heartbeat_failures: AtomicU64,
    /// Times an established connection was lost.
    pub disconnects: AtomicU64,
    /// `ConfigPrepare` requests served on the incoming half (Story 9.4).
    pub config_prepares: AtomicU64,
    /// `ConfigCommit` requests served.
    pub config_commits: AtomicU64,
    /// `ConfigAbort` requests served.
    pub config_aborts: AtomicU64,
    /// `CertPush` requests served on the incoming half (Story 9.5).
    pub cert_pushes: AtomicU64,
    /// Certificates installed from a push.
    pub certs_installed: AtomicU64,
    /// Certificates a push offered that this node would not or could
    /// not install. Never fatal: the node asks for them again on its
    /// next certificate pull (Story 9.5 D2).
    pub cert_install_refusals: AtomicU64,
    /// HTTP-01 challenge tokens this node was asked to serve
    /// (Story 9.5 AC #6).
    pub challenges_published: AtomicU64,
    /// Publications this node could not take. Each one stops an ACME
    /// order on the control plane, so it is the counter to alert on.
    pub challenge_publish_failures: AtomicU64,
    /// HTTP-01 challenge tokens this node was asked to stop serving.
    pub challenges_retracted: AtomicU64,
    /// Fleet-wide bans applied on this node (Story 9.6 AC #10).
    pub bans_applied: AtomicU64,
    /// Times an ack revealed the control plane is on another
    /// configuration version and a pull was started (AC #7).
    pub behind_detected: AtomicU64,
    /// Control-plane requests refused by the follower whitelist; each
    /// one also dropped the session.
    pub protocol_violations: AtomicU64,
}

/// The follower runtime the dialer serves control-plane pushes to
/// (Story 9.4 D5, Story 9.5 AC #7).
///
/// Implemented by the binary over the configuration store and the
/// reload trigger; a node without one (the transport-only tests)
/// answers every push `UNSUPPORTED_METHOD`. Boxed futures keep
/// `async-trait` out of the dependency set, like the Story 9.3 hooks.
pub trait FollowerHandler: Send + Sync + 'static {
    /// What this node runs, for the `Hello` and every `Heartbeat`.
    fn applied_config(&self) -> AppliedConfig;

    /// What this node is currently using, for the control plane's node
    /// drawer (Story 9.7 AC #3).
    ///
    /// Defaulted, unlike the push handlers, and the asymmetry is
    /// deliberate. A missing push handler would silently drop work the
    /// control plane believes was done, so those have no default; a
    /// missing sampler reports `None`, the dashboard renders a dash,
    /// and nothing downstream is misled. The transport-only tests want
    /// exactly that.
    fn resources(&self) -> Option<NodeResources> {
        None
    }

    /// A `ConfigPrepare` arrived: validate and stage it, do not apply
    /// it. `Err` is the SEMANTIC rejection the control plane aborts the
    /// whole round on (AC #5), so its reason must name the cause
    /// without echoing configuration values.
    fn on_prepare(&self, payload: ConfigPayload) -> BoxFuture<'_, Result<(), String>>;

    /// Apply the staged generation and report what is now applied.
    fn on_commit(&self, generation: u64) -> BoxFuture<'_, Result<AppliedConfig, String>>;

    /// Drop the staged generation (another follower rejected it).
    fn on_abort(&self, generation: u64) -> BoxFuture<'_, ()>;

    /// The control plane's version differs from what this node applied
    /// (learned from a `HelloAck` or a `HeartbeatAck`): pull over
    /// `session` and apply (AC #7). At most one call is in flight per
    /// session; the dialer skips the check while a previous pull runs.
    fn on_behind(&self, session: SessionHandle, current: ConfigVersion) -> BoxFuture<'_, ()>;

    /// Install certificate material the control plane pushed (AC #7).
    ///
    /// Infallible by signature on purpose: a certificate push is best
    /// effort (D2), so a per-certificate problem belongs in the
    /// returned [`CertInstallReport`] and never ends the session. The
    /// bundles are already bounded and well formed
    /// ([`crate::certs::cert_bundle_defect`]); what remains for the
    /// implementation is checking `key_digest` against `key_pem` and
    /// writing through the store's encrypt-on-write path.
    ///
    /// Never refuses for break-glass: a key overwrites no operator
    /// edit, so the reason Story 9.4 excludes a break-glass node from
    /// replication does not apply, and suspending delivery could
    /// expire a certificate in the middle of the incident the window
    /// was opened for (D9).
    fn on_cert_push(&self, bundles: Vec<CertBundle>) -> BoxFuture<'_, CertInstallReport>;

    /// Publish an HTTP-01 challenge token so this node's data plane can
    /// answer the certificate authority for `identifier` (AC #6).
    ///
    /// Fallible, unlike [`FollowerHandler::on_cert_push`], and the
    /// asymmetry is the point: an ACME order is about to be validated
    /// against this node, so `Err` here must stop the order rather
    /// than be counted. The reason names the cause without echoing the
    /// key authorization.
    ///
    /// The entry's DEADLINE is stamped by this implementation from
    /// this node's own clock. Nothing on the wire carries one, and
    /// nothing should: see the note on
    /// [`crate::messages::ChallengePublish`].
    fn on_challenge_publish(
        &self,
        identifier: String,
        token: String,
        key_authorization: String,
    ) -> BoxFuture<'_, Result<(), String>>;

    /// Retract a token. Infallible by contract, like the driver
    /// cleanup it mirrors: it runs on both the success and the failure
    /// path of an order, has nothing useful to report, and the entry's
    /// own deadline removes it anyway.
    fn on_challenge_retract(&self, token: String) -> BoxFuture<'_, ()>;

    /// Apply an operator-issued fleet-wide ban (Story 9.6 AC #10).
    ///
    /// `Ok(true)` means the ban is now live on this node. `Ok(false)`
    /// means it could not be applied right now (in worker mode, no
    /// worker is up to receive it), which is a legitimate answer
    /// rather than a failure: a worker starting later picks the ban
    /// up from the store. `Err` is a local failure, answered with the
    /// opaque refusal, session kept.
    ///
    /// Only ever operator-issued: automatic per-node auto-ban is not
    /// replicated, because one node's reflex to its own traffic would
    /// otherwise become a fleet-wide outage for that client.
    fn on_ban_push(
        &self,
        client_ip: String,
        duration_s: u64,
        reason: String,
    ) -> BoxFuture<'_, Result<bool, String>>;
}

/// Inputs for [`Dialer::spawn`]. Construct with [`DialerConfig::new`];
/// every field stays public so callers (and tests) can tune it.
#[derive(Clone)]
pub struct DialerConfig {
    /// Control-plane `host:port`, resolved on EVERY attempt (see the
    /// module doc).
    pub control_plane: String,
    /// Name the control-plane certificate must verify as (its SAN).
    pub server_name: String,
    /// Cluster CA bundle (the ONLY trust root).
    pub ca_pem: String,
    /// This node's `clientAuth` leaf.
    pub client_cert_pem: String,
    /// This node's private key.
    pub client_key_pem: String,
    /// Protocol/schema inputs for the session handshake.
    pub handshake: HandshakeConfig,
    /// Display name sent in the Hello (identity is the certificate).
    /// Default: empty.
    pub node_name: String,
    /// Interval between liveness probes on an established session.
    /// Default 15 s (must stay below the transport's 30 s
    /// `frame_read_timeout`).
    pub heartbeat_interval: Duration,
    /// Per-request timeout (handshake and heartbeats). Default 10 s.
    pub request_timeout: Duration,
    /// Bound on name resolution + TCP connect + TLS handshake
    /// together. Default 10 s: a peer that accepts TCP and then
    /// stalls must not wedge the loop.
    pub connect_timeout: Duration,
    /// First-failure backoff delay. Default 1 s.
    pub base_backoff: Duration,
    /// Backoff cap before any fleet-size hint arrives; also the floor
    /// of the scaled cap (see the module doc). Default 60 s.
    pub default_backoff_cap: Duration,
    /// The follower runtime that serves configuration pushes on the
    /// incoming half (Story 9.4 D5). Default `None`: Prepare, Commit
    /// and Abort are answered `UNSUPPORTED_METHOD`, which is the
    /// transport-only mode the 9.2 tests exercise.
    pub follower: Option<Arc<dyn FollowerHandler>>,
}

impl DialerConfig {
    /// A config with the documented defaults for every timing knob.
    /// `control_plane` is a `host:port` (validated at spawn).
    pub fn new(
        control_plane: &str,
        server_name: &str,
        ca_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
        local_schema_version: u32,
    ) -> Self {
        Self {
            control_plane: control_plane.to_string(),
            server_name: server_name.to_string(),
            ca_pem: ca_pem.to_string(),
            client_cert_pem: client_cert_pem.to_string(),
            client_key_pem: client_key_pem.to_string(),
            handshake: HandshakeConfig::new(local_schema_version),
            node_name: String::new(),
            heartbeat_interval: Duration::from_secs(15),
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            base_backoff: Duration::from_secs(1),
            default_backoff_cap: Duration::from_secs(60),
            follower: None,
        }
    }

    /// Set the display name sent in the Hello.
    pub fn with_node_name(mut self, node_name: &str) -> Self {
        self.node_name = node_name.to_string();
        self
    }

    /// Install the follower runtime that serves configuration pushes.
    pub fn with_follower(mut self, follower: Arc<dyn FollowerHandler>) -> Self {
        self.follower = Some(follower);
        self
    }
}

/// What this node is using, or `None` when no follower runtime is
/// installed to sample it.
fn node_resources(config: &DialerConfig) -> Option<NodeResources> {
    config.follower.as_ref().and_then(|f| f.resources())
}

/// What this node runs, or the empty state when no follower runtime is
/// installed.
fn applied_config(config: &DialerConfig) -> AppliedConfig {
    config
        .follower
        .as_ref()
        .map(|follower| follower.applied_config())
        .unwrap_or_default()
}

/// Split a `host:port` into its parts, refusing a bare host, a bare
/// port and a non-numeric port. IPv6 literals must be bracketed.
pub fn split_host_port(value: &str) -> Result<(&str, u16), DialerError> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| DialerError::Address(value.to_string()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| DialerError::Address(value.to_string()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(DialerError::Address(value.to_string()));
    }
    Ok((host, port))
}

/// One established session: the endpoint plus a generation that
/// increments on every successful handshake, so a consumer running a
/// multi-step exchange (Story 9.4's Prepare/Commit) can tell that a
/// reconnect happened in between and must not mix the two sessions.
#[derive(Clone)]
pub struct SessionHandle {
    /// Monotonic per dialer; starts at 1.
    pub generation: u64,
    /// The live endpoint.
    pub endpoint: Arc<RpcEndpoint<ClusterFrame>>,
}

/// Lock-free view of the follower's current control-plane connection.
///
/// `None` whenever the dialer is between connections; consumers must
/// treat that as "control plane unreachable right now" and not queue.
#[derive(Clone)]
pub struct ClusterConnection {
    slot: Arc<ArcSwapOption<SessionHandle>>,
}

impl ClusterConnection {
    /// A slot holding no session: what a follower's consumers see
    /// before the first connect and between reconnects.
    ///
    /// [`Dialer::spawn`] creates and drives its own; this constructor
    /// is for a caller that must name the state before a dialer
    /// exists.
    pub fn disconnected() -> Self {
        Self {
            slot: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// The live session, if one is currently established.
    pub fn current(&self) -> Option<SessionHandle> {
        self.slot.load_full().map(|s| (*s).clone())
    }
}

/// Handle to a running dialer.
pub struct DialerHandle {
    connection: ClusterConnection,
    stats: Arc<DialerStats>,
    connector: Arc<ArcSwap<TlsConnector>>,
    ca_pem: String,
    reconnect: Arc<tokio::sync::Notify>,
    task: JoinHandle<()>,
}

impl DialerHandle {
    /// The connection slot consumers read.
    pub fn connection(&self) -> ClusterConnection {
        self.connection.clone()
    }

    /// The dialer's counters.
    pub fn stats(&self) -> Arc<DialerStats> {
        Arc::clone(&self.stats)
    }

    /// Swap in a renewed identity (Story 9.3 AC #12): the NEXT
    /// connection presents the new leaf; the established session is
    /// untouched.
    pub fn update_identity(
        &self,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> Result<(), ClusterTlsError> {
        let tls = client_config(&self.ca_pem, client_cert_pem, client_key_pem)?;
        self.connector.store(Arc::new(TlsConnector::from(Arc::new(tls))));
        Ok(())
    }

    /// Drop the established session and dial again immediately (no
    /// backoff): after a renewal, so the control plane sees the new
    /// certificate now and retires the superseded one, instead of
    /// whenever the old session happens to end.
    pub fn reconnect(&self) {
        // `notify_one` stores a permit when nobody is waiting, which
        // would tear down the NEXT session for nothing: only a live
        // session can be asked to reconnect. (A session ending between
        // the check and the notify costs one spurious reconnect, which
        // is the harmless direction.)
        if self.connection.current().is_some() {
            self.reconnect.notify_one();
        }
    }

    /// Stop dialing and clear the connection slot.
    pub fn shutdown(self) {
        self.task.abort();
        self.connection.slot.store(None);
    }
}

/// The follower's reconnecting dialer (AC #9).
pub struct Dialer;

impl Dialer {
    /// Validate the address shape and the TLS material, then spawn the
    /// reconnect loop.
    pub fn spawn(config: DialerConfig) -> Result<DialerHandle, DialerError> {
        split_host_port(&config.control_plane)?;
        let tls = client_config(&config.ca_pem, &config.client_cert_pem, &config.client_key_pem)?;
        let server_name: ServerName<'static> = ServerName::try_from(config.server_name.clone())
            .map_err(|e| ClusterTlsError::Parse(format!("invalid server name: {e}")))?;
        let connector: Arc<ArcSwap<TlsConnector>> =
            Arc::new(ArcSwap::from_pointee(TlsConnector::from(Arc::new(tls))));

        let slot: Arc<ArcSwapOption<SessionHandle>> = Arc::new(ArcSwapOption::empty());
        let stats = Arc::new(DialerStats::default());
        let connection = ClusterConnection {
            slot: Arc::clone(&slot),
        };
        let ca_pem = config.ca_pem.clone();

        let reconnect = Arc::new(tokio::sync::Notify::new());
        let loop_slot = Arc::clone(&slot);
        let loop_stats = Arc::clone(&stats);
        let loop_connector = Arc::clone(&connector);
        let loop_reconnect = Arc::clone(&reconnect);
        let task = tokio::spawn(async move {
            dial_loop(
                config,
                loop_connector,
                server_name,
                loop_slot,
                loop_stats,
                loop_reconnect,
            )
            .await;
        });

        Ok(DialerHandle {
            connection,
            stats,
            connector,
            ca_pem,
            reconnect,
            task,
        })
    }
}

async fn dial_loop(
    config: DialerConfig,
    connector: Arc<ArcSwap<TlsConnector>>,
    server_name: ServerName<'static>,
    slot: Arc<ArcSwapOption<SessionHandle>>,
    stats: Arc<DialerStats>,
    reconnect: Arc<tokio::sync::Notify>,
) {
    let mut failures: u32 = 0;
    let mut fleet_hint: u32 = 0;
    let mut generation: u64 = 0;
    let mut jitter = Jitter::seeded();
    // Set when the control plane answered RETRY_LATER: the next delay
    // is at least this long.
    let mut server_delay: Option<Duration> = None;
    // Sticky refusal state: the FIRST refusal of a given status logs
    // at error, repeats at debug, so a mis-ordered fleet upgrade is one
    // loud line rather than a silent retry loop or a log flood.
    let mut sticky_refusal: Option<ClusterStatus> = None;
    let mut was_connected = false;

    loop {
        stats.connect_attempts.fetch_add(1, Ordering::Relaxed);
        // Loaded per attempt so a renewed identity takes effect on
        // the next connection.
        let current_connector = connector.load_full();
        match connect_once(&config, &current_connector, &server_name).await {
            Ok((endpoint, mut incoming, ack, addr)) => {
                stats.handshakes_ok.fetch_add(1, Ordering::Relaxed);
                failures = 0;
                server_delay = None;
                sticky_refusal = None;
                fleet_hint = ack.fleet_size_hint;
                generation += 1;
                was_connected = true;
                tracing::info!(
                    control_plane = %config.control_plane,
                    resolved = %addr,
                    generation,
                    protocol = ack.negotiated_version,
                    fleet_size_hint = fleet_hint,
                    current_generation = ack.current_generation,
                    "cluster session established with the control plane"
                );
                let session = SessionHandle {
                    generation,
                    endpoint: Arc::new(endpoint),
                };
                slot.store(Some(Arc::new(session.clone())));

                // One convergence pull at a time per session, so a
                // slow apply cannot stack pulls behind every heartbeat.
                let pull_in_flight = Arc::new(AtomicBool::new(false));
                // AC #7's handshake half: converge at reconnect rather
                // than waiting for the first heartbeat.
                start_pull_if_behind(
                    &config,
                    &session,
                    &stats,
                    &pull_in_flight,
                    ConfigVersion {
                        generation: ack.current_generation,
                        hash: ack.current_hash.clone(),
                    },
                );

                let (hint, requested) = tokio::select! {
                    hint = heartbeat_until_dead(&config, &session, fleet_hint, &stats, &pull_in_flight) => (hint, false),
                    // The incoming half: the control plane's
                    // configuration pushes. It returns when the peer
                    // hangs up or commits a protocol violation, and
                    // either way the session is over.
                    _ = serve_control_plane(&config, &mut incoming, &stats) => (fleet_hint, false),
                    _ = reconnect.notified() => (fleet_hint, true),
                };
                fleet_hint = hint;
                slot.store(None);
                stats.disconnects.fetch_add(1, Ordering::Relaxed);
                if requested {
                    tracing::info!(
                        control_plane = %config.control_plane,
                        generation,
                        "cluster session dropped on request; reconnecting now"
                    );
                    continue;
                }
                tracing::warn!(
                    control_plane = %config.control_plane,
                    generation,
                    "cluster session lost; reconnecting"
                );
            }
            Err(DialFailure::RetryLater(retry_after_s)) => {
                stats.retry_later.fetch_add(1, Ordering::Relaxed);
                // Counted as a failure so the exponential schedule
                // floors a control plane that keeps saying "now".
                failures = failures.saturating_add(1);
                let delay = Duration::from_secs(u64::from(retry_after_s.max(1)))
                    .min(BACKOFF_CAP_CEILING);
                tracing::info!(
                    control_plane = %config.control_plane,
                    retry_in = ?delay,
                    "control plane admission is full; retrying later"
                );
                server_delay = Some(delay);
            }
            Err(DialFailure::Refused(status)) => {
                stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
                if sticky_refusal != Some(status) {
                    sticky_refusal = Some(status);
                    tracing::error!(
                        control_plane = %config.control_plane,
                        ?status,
                        "control plane refused the session; will keep retrying on the capped \
                         schedule but this needs an operator (version or schema mismatch, or a \
                         protocol fault)"
                    );
                } else {
                    tracing::debug!(control_plane = %config.control_plane, ?status, "session still refused");
                }
            }
            Err(DialFailure::Transport(reason)) => {
                stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                failures = failures.saturating_add(1);
                // First failure after a connected period (or at boot)
                // is the transition worth a warning; the rest of the
                // storm stays at debug.
                if failures == 1 || was_connected {
                    was_connected = false;
                    tracing::warn!(
                        control_plane = %config.control_plane,
                        reason = %reason,
                        "cannot reach the control plane; backing off"
                    );
                } else {
                    tracing::debug!(control_plane = %config.control_plane, reason = %reason, failures, "connect failed");
                }
            }
        }

        let scheduled = backoff_delay(
            config.base_backoff,
            backoff_cap(config.default_backoff_cap, fleet_hint),
            failures,
            &mut jitter,
        );
        let delay = match server_delay.take() {
            Some(server) => server.max(scheduled),
            None => scheduled,
        };
        tokio::time::sleep(delay).await;
    }
}

enum DialFailure {
    /// Resolution/TCP/TLS/transport-level failure, with the cause for
    /// the log.
    Transport(String),
    /// The control plane refused the session outright.
    Refused(ClusterStatus),
    /// The admission gate asked us to come back later (AC #10).
    RetryLater(u32),
}

/// Resolve a `host:port` and connect to the first address that
/// answers, in resolution order. Shared by the dialer, the joiner and
/// the CLI so "how the fleet reaches a name" has one definition. The
/// caller bounds it with a timeout.
pub async fn resolve_and_connect(
    target: &str,
) -> Result<(tokio::net::TcpStream, SocketAddr), String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target)
        .await
        .map_err(|e| format!("resolve {target}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolve {target}: no addresses"));
    }
    let mut last_error = String::new();
    for addr in addrs {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(tcp) => return Ok((tcp, addr)),
            Err(e) => last_error = format!("tcp connect {addr}: {e}"),
        }
    }
    Err(last_error)
}

type Connected = (
    RpcEndpoint<ClusterFrame>,
    IncomingRequests<ClusterFrame>,
    HelloAck,
    SocketAddr,
);

async fn connect_once(
    config: &DialerConfig,
    connector: &TlsConnector,
    server_name: &ServerName<'static>,
) -> Result<Connected, DialFailure> {
    // Resolution + TCP + TLS under one budget: a peer that answers TCP
    // and then stalls (route hijack, stale address) must not wedge the
    // loop.
    let (tls, addr) = tokio::time::timeout(config.connect_timeout, async {
        let (tcp, addr) = resolve_and_connect(&config.control_plane)
            .await
            .map_err(DialFailure::Transport)?;
        let tls = connector
            .connect(server_name.clone(), tcp)
            .await
            .map_err(|e| DialFailure::Transport(format!("tls connect {addr}: {e}")))?;
        Ok::<_, DialFailure>((tls, addr))
    })
    .await
    .map_err(|_| DialFailure::Transport("connect timed out".to_string()))??;
    if !negotiated_cluster_alpn(tls.get_ref().1) {
        return Err(DialFailure::Transport(
            "server did not negotiate the cluster ALPN".to_string(),
        ));
    }
    // The incoming half is KEPT: since Story 9.4 the control plane
    // initiates configuration pushes down this connection.
    let (endpoint, incoming) = RpcEndpoint::<ClusterFrame>::with_limits(tls, cluster_rpc_limits());
    match client_handshake(
        &endpoint,
        &config.handshake,
        &config.node_name,
        &applied_config(config),
        config.request_timeout,
    )
    .await
    {
        Ok(ack) => Ok((endpoint, incoming, ack, addr)),
        Err(HandshakeError::RetryLater { retry_after_s }) => {
            Err(DialFailure::RetryLater(retry_after_s))
        }
        Err(HandshakeError::Refused(status)) => Err(DialFailure::Refused(status)),
        Err(HandshakeError::ProtocolViolation) => {
            Err(DialFailure::Refused(ClusterStatus::ProtocolViolation))
        }
        Err(HandshakeError::Transport(e)) => {
            Err(DialFailure::Transport(format!("handshake transport: {e}")))
        }
    }
}

/// Heartbeat until the session dies; returns the freshest fleet-size
/// hint so the next backoff cap reflects roster growth.
///
/// Every probe carries what this node runs, and every ack is checked
/// against it: a follower that missed a commit converges within one
/// interval (AC #6/#7).
async fn heartbeat_until_dead(
    config: &DialerConfig,
    session: &SessionHandle,
    mut fleet_hint: u32,
    stats: &DialerStats,
    pull_in_flight: &Arc<AtomicBool>,
) -> u32 {
    loop {
        tokio::time::sleep(config.heartbeat_interval).await;
        if session.endpoint.is_closed() {
            tracing::debug!("cluster session endpoint closed");
            return fleet_hint;
        }
        let applied = applied_config(config);
        let probe = ClusterRequest::heartbeat(Heartbeat {
            timestamp_ms: unix_millis(),
            applied_generation: applied.generation,
            applied_hash: applied.hash.clone(),
            break_glass: applied.break_glass,
            resources: node_resources(config),
        });
        match session.endpoint.request(probe, config.request_timeout).await {
            Ok(resp) => match resp.body {
                Some(cluster_response::Body::HeartbeatAck(ack)) => {
                    stats.heartbeats_ok.fetch_add(1, Ordering::Relaxed);
                    fleet_hint = ack.fleet_size_hint;
                    start_pull_if_behind(
                        config,
                        session,
                        stats,
                        pull_in_flight,
                        ConfigVersion {
                            generation: ack.current_generation,
                            hash: ack.current_hash,
                        },
                    );
                }
                _ => {
                    stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(status = ?resp.cluster_status(), "heartbeat answered without an ack; dropping the session");
                    return fleet_hint;
                }
            },
            Err(e) => {
                stats.heartbeat_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(error = %e, "heartbeat failed; dropping the session");
                return fleet_hint;
            }
        }
    }
}

/// Compare the control plane's version with what this node applied and,
/// when they differ, hand the session to the follower runtime so it can
/// pull and apply (AC #7).
///
/// Skipped entirely in break-glass (AC #11: local mutations stand until
/// the window ends) and while a previous pull is still running, so a
/// slow apply cannot stack one pull per heartbeat.
fn start_pull_if_behind(
    config: &DialerConfig,
    session: &SessionHandle,
    stats: &DialerStats,
    pull_in_flight: &Arc<AtomicBool>,
    current: ConfigVersion,
) {
    let Some(handler) = config.follower.as_ref() else {
        return;
    };
    let applied = handler.applied_config();
    if applied.break_glass {
        return;
    }
    // Peer-supplied, so bounded before it can reach a log line or the
    // follower's store.
    if !config_hash_is_valid(&current.hash) {
        tracing::warn!("control plane advertised a malformed configuration hash; ignored");
        return;
    }
    if !current.is_behind(&applied) {
        return;
    }
    if pull_in_flight.swap(true, Ordering::AcqRel) {
        tracing::debug!(
            current_generation = current.generation,
            "a convergence pull is already running; skipping this one"
        );
        return;
    }
    stats.behind_detected.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        applied_generation = applied.generation,
        current_generation = current.generation,
        "this node is behind the control plane's configuration; pulling"
    );
    let handler = Arc::clone(handler);
    let session = session.clone();
    let gate = Arc::clone(pull_in_flight);
    tokio::spawn(async move {
        handler.on_behind(session, current).await;
        gate.store(false, Ordering::Release);
    });
}

/// Serve the incoming half of an established session: the control
/// plane's configuration pushes (Story 9.4 D5).
///
/// Returns when the peer hangs up or commits a protocol violation; the
/// caller ends the session either way.
async fn serve_control_plane(
    config: &DialerConfig,
    incoming: &mut IncomingRequests<ClusterFrame>,
    stats: &DialerStats,
) {
    while let Some(request) = incoming.recv().await {
        match translate_control_plane_request(request.request()) {
            FollowerBridgeOutcome::Serve(action) => {
                if !serve_follower_action(config, stats, request, action).await {
                    return;
                }
            }
            FollowerBridgeOutcome::Unsupported { body_kind } => {
                tracing::info!(
                    body_kind,
                    "control plane asked for a method this build does not implement; refused, \
                     session kept"
                );
                if request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            FollowerBridgeOutcome::ProtocolViolation => {
                stats.protocol_violations.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    control_plane = %config.control_plane,
                    "the control plane sent a request no control plane may send; dropping the \
                     session"
                );
                let _ = request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::ProtocolViolation))
                    .await;
                // Let the refusal flush before the session is torn down.
                tokio::time::sleep(REFUSAL_FLUSH_GRACE).await;
                return;
            }
        }
    }
}

/// Serve one whitelisted control-plane push. `false` means the reply
/// could not be sent and the session is over.
async fn serve_follower_action(
    config: &DialerConfig,
    stats: &DialerStats,
    request: IncomingRequest<ClusterFrame>,
    action: FollowerAction,
) -> bool {
    let Some(handler) = config.follower.as_ref() else {
        // The method exists but this node has no runtime to serve it.
        return request
            .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
            .await
            .is_ok();
    };
    let reply = match action {
        FollowerAction::Prepare(payload) => {
            stats.config_prepares.fetch_add(1, Ordering::Relaxed);
            let generation = payload.generation;
            match handler.on_prepare(payload).await {
                Ok(()) => ClusterResponse::ok(cluster_response::Body::ConfigPrepareAck(
                    ConfigPrepareAck {
                        accepted: true,
                        reason: String::new(),
                    },
                )),
                Err(reason) => {
                    tracing::warn!(
                        generation,
                        %reason,
                        "refusing to stage the pushed configuration; the round aborts fleet-wide"
                    );
                    ClusterResponse::ok(cluster_response::Body::ConfigPrepareAck(
                        ConfigPrepareAck {
                            accepted: false,
                            reason,
                        },
                    ))
                }
            }
        }
        FollowerAction::Commit { generation } => {
            stats.config_commits.fetch_add(1, Ordering::Relaxed);
            match handler.on_commit(generation).await {
                Ok(applied) => {
                    tracing::info!(generation = applied.generation, "applied a pushed configuration");
                    ClusterResponse::ok(cluster_response::Body::ConfigCommitAck(ConfigCommitAck {
                        applied_generation: applied.generation,
                        applied_hash: applied.hash,
                    }))
                }
                Err(reason) => {
                    tracing::error!(
                        generation,
                        %reason,
                        "could not apply the staged configuration; this node is now out of step \
                         with the fleet and converges on its next pull"
                    );
                    ClusterResponse::refusal(ClusterStatus::Unspecified)
                }
            }
        }
        FollowerAction::Abort { generation } => {
            stats.config_aborts.fetch_add(1, Ordering::Relaxed);
            handler.on_abort(generation).await;
            tracing::info!(generation, "dropped a staged configuration on the control plane's abort");
            ClusterResponse::ok(cluster_response::Body::ConfigAbortAck(ConfigAbortAck {}))
        }
        FollowerAction::InstallCerts(bundles) => {
            stats.cert_pushes.fetch_add(1, Ordering::Relaxed);
            let offered = bundles.len();
            let report = handler.on_cert_push(bundles).await;
            stats
                .certs_installed
                .fetch_add(report.installed.len() as u64, Ordering::Relaxed);
            stats
                .cert_install_refusals
                .fetch_add(report.refused.len() as u64, Ordering::Relaxed);
            if report.refused.is_empty() {
                tracing::info!(
                    offered,
                    installed = report.installed.len(),
                    "installed certificate material pushed by the control plane"
                );
            } else {
                // Not an error: the push is best effort, and whatever
                // was refused is asked for again on the next pull.
                tracing::warn!(
                    offered,
                    installed = report.installed.len(),
                    refused = report.refused.len(),
                    "part of a pushed certificate batch was not installed; it is requested again \
                     on the next certificate pull"
                );
            }
            ClusterResponse::ok(cluster_response::Body::CertPushAck(CertPushAck {
                installed: report.installed,
                refused: report
                    .refused
                    .into_iter()
                    .map(|(cert_id, reason)| CertRefusal { cert_id, reason })
                    .collect(),
            }))
        }
        FollowerAction::PublishChallenge {
            identifier,
            token,
            key_authorization,
        } => {
            stats.challenges_published.fetch_add(1, Ordering::Relaxed);
            match handler
                .on_challenge_publish(identifier.clone(), token, key_authorization)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        %identifier,
                        "serving an HTTP-01 challenge for the control plane's order"
                    );
                    ClusterResponse::ok(cluster_response::Body::ChallengePublishAck(
                        ChallengePublishAck {},
                    ))
                }
                Err(reason) => {
                    stats
                        .challenge_publish_failures
                        .fetch_add(1, Ordering::Relaxed);
                    // The control plane's order stops on this refusal
                    // rather than telling the authority to validate
                    // against a node that would answer nothing.
                    tracing::error!(
                        %identifier,
                        %reason,
                        "cannot serve the HTTP-01 challenge; the control plane's order fails here \
                         instead of failing opaquely at the certificate authority"
                    );
                    ClusterResponse::refusal(ClusterStatus::Unspecified)
                }
            }
        }
        FollowerAction::RetractChallenge { token } => {
            stats.challenges_retracted.fetch_add(1, Ordering::Relaxed);
            handler.on_challenge_retract(token).await;
            ClusterResponse::ok(cluster_response::Body::ChallengeRetractAck(
                ChallengeRetractAck {},
            ))
        }
        FollowerAction::ApplyBan {
            client_ip,
            duration_s,
            reason,
        } => {
            stats.bans_applied.fetch_add(1, Ordering::Relaxed);
            match handler.on_ban_push(client_ip, duration_s, reason).await {
                Ok(applied) => {
                    ClusterResponse::ok(cluster_response::Body::BanPushAck(BanPushAck { applied }))
                }
                Err(reason) => {
                    tracing::warn!(%reason, "could not apply a fleet-wide ban");
                    ClusterResponse::refusal(ClusterStatus::Unspecified)
                }
            }
        }
    };
    request.reply_frame(reply).await.is_ok()
}

/// The scaled backoff cap (see the module doc formula). An operator
/// configuring `default_cap` above the ceiling keeps their value
/// (`clamp` would panic on an inverted range).
fn backoff_cap(default_cap: Duration, fleet_hint: u32) -> Duration {
    let scaled = default_cap + Duration::from_secs(u64::from(fleet_hint));
    scaled.min(BACKOFF_CAP_CEILING).max(default_cap.min(BACKOFF_CAP_CEILING))
}

/// Exponential delay with equal jitter.
fn backoff_delay(base: Duration, cap: Duration, failures: u32, jitter: &mut Jitter) -> Duration {
    let exp = failures.min(16); // 2^16 * any sane base saturates the cap
    let nominal = base.saturating_mul(1u32 << exp).min(cap);
    let half = nominal / 2;
    half + jitter.uniform(half)
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Small xorshift PRNG for backoff jitter: not security-relevant, and
/// keeps `rand` out of the crate's dependency set.
struct Jitter(u64);

impl Jitter {
    fn seeded() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
            .unwrap_or(0x9e37_79b9_7f4a_7c15)
            | 1;
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform-ish duration in `[0, bound]`.
    fn uniform(&mut self, bound: Duration) -> Duration {
        let bound_ms = bound.as_millis() as u64;
        if bound_ms == 0 {
            return Duration::ZERO;
        }
        Duration::from_millis(self.next() % (bound_ms + 1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_cap_scales_with_the_fleet_hint_within_bounds() {
        let default_cap = Duration::from_secs(60);
        assert_eq!(backoff_cap(default_cap, 0), default_cap);
        assert_eq!(backoff_cap(default_cap, 30), Duration::from_secs(90));
        assert_eq!(backoff_cap(default_cap, 100_000), BACKOFF_CAP_CEILING);
    }

    #[test]
    fn backoff_delay_grows_and_respects_the_cap() {
        let mut jitter = Jitter::seeded();
        let base = Duration::from_millis(500);
        let cap = Duration::from_secs(30);
        let first = backoff_delay(base, cap, 0, &mut jitter);
        assert!(first >= base / 2 && first <= base, "got {first:?}");
        let capped = backoff_delay(base, cap, 12, &mut jitter);
        assert!(capped >= cap / 2 && capped <= cap, "got {capped:?}");
    }

    #[test]
    fn jitter_stays_within_its_bound() {
        let mut jitter = Jitter::seeded();
        let bound = Duration::from_millis(250);
        for _ in 0..1000 {
            assert!(jitter.uniform(bound) <= bound);
        }
    }

    #[test]
    fn config_defaults_keep_heartbeats_inside_the_frame_read_timeout() {
        let cfg = DialerConfig::new("cp.example.com:9444", "cp", "", "", "", 49);
        assert!(cfg.heartbeat_interval < cluster_rpc_limits().frame_read_timeout);
        assert!(cfg.connect_timeout > Duration::ZERO);
        assert_eq!(cfg.with_node_name("edge-1").node_name, "edge-1");
    }

    #[test]
    fn host_port_shapes_are_validated_at_spawn() {
        assert_eq!(
            split_host_port("cp.example.com:9444").expect("dns name"),
            ("cp.example.com", 9444)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:9444").expect("v6 literal"),
            ("2001:db8::1", 9444)
        );
        for bad in ["cp.example.com", "9444", ":9444", "cp.example.com:port"] {
            assert!(
                matches!(split_host_port(bad), Err(DialerError::Address(_))),
                "{bad} must be refused"
            );
        }
    }
}
