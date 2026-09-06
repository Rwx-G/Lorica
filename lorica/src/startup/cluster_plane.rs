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

//! Control-plane side of the cluster plane (Stories 9.2 and 9.3):
//! validates the binds, loads the cluster CA, mints this node's server
//! leaf from a persisted keypair, builds the fleet runtime (roster,
//! session registry, CRL-backed acceptor) and spawns the two listeners
//! with the binary's redemption and lifecycle hooks.
//!
//! Opt-in: nothing here runs unless `--cluster-listen` is set. The
//! enrollment listener binds `cluster port + 1` on the same host by
//! default (or `--cluster-enrollment-listen`) and only exists while at
//! least one join token is live; a liveness publisher task recounts
//! live tokens on every mutation and at every expiry edge.
//!
//! # The store lock and the signing path
//!
//! The configuration store is one async mutex shared with the reload
//! path and every management handler. Redemption and renewal
//! therefore hold it only for the reads and the writes: the atomic
//! burn or the eligibility check first, then the certificate is signed
//! on the blocking pool with NO store lock, then a second short lock
//! persists the result. A fleet enrolling or renewing in a burst
//! never serializes the data plane's reload behind rcgen.
//!
//! Hot upgrade: the operational SOCKET is handed to the next
//! supervisor through Story 9.1's cluster FD slot, so there is no
//! rebind gap and no EADDRINUSE against the outgoing process. The
//! sessions on it do not survive: the outgoing supervisor stops its
//! cluster plane as soon as the new one is confirmed up, and followers
//! reconnect once, to the new process, under the new takeover epoch.
//! The socket is adopted only when the inherited bind equals the
//! configured one; a mismatch is logged and the socket bound fresh.
//! The enrollment socket is deliberately not handed off - it is bound
//! only inside an enrollment window and rebinds on the next liveness
//! edge, which is the honest lifecycle for a socket that usually does
//! not exist.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use lorica_api::audit::{record_with_store, AuditContext};
use lorica_api::cluster::{publish_token_liveness, refresh_control_plane, revoke_node_fully};
use lorica_api::db::db_blocking;
use lorica_api::error::ApiError;
use lorica_api::log_store::LogStore;
use lorica_cluster::enroll::{
    BoxFuture, EnrollGrant, EnrollRefusal, EnrollRequest, EnrollmentHandler, RenewGrant,
    RenewRequest, SessionHandler,
};
use lorica_cluster::{
    token, ClusterCa, ControlPlane, EnrollmentHandle, EnrollmentListener, EnrollmentStats,
    FleetHooks, HandshakeConfig, IssuedLeaf, OperationalConfig, OperationalHandle,
    OperationalListener, OperationalStats, PreAuthBudgets, SwappableAcceptor,
};
use lorica_config::models::{ClusterNode, NodeStatus};
use lorica_config::store::{ConfigStore, LiveNodeFacts};
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::AlertSender;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::cli::{validate_cluster_listen, ReservedPorts};
use crate::startup::hot_upgrade::ClusterListenerRole;

/// How often live-session facts (last seen, address, version) are
/// persisted to `cluster_nodes` and expired revoked serials are
/// pruned, and the longest the liveness publisher sleeps between
/// recounts.
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// A renewal is served only when this much (or less) of the
/// certificate's lifetime is left: the follower asks at 30 days
/// (with jitter down to 25), so anything asking earlier is not a
/// renewal (Story 9.3 AC #12).
const RENEWAL_ACCEPT_WINDOW: chrono::Duration = chrono::Duration::days(35);

/// One renewal grant per node per this interval; a second request
/// inside it is refused (a grant costs a signature and a CRL entry).
const RENEWAL_COOLDOWN: Duration = Duration::from_secs(3600);

/// Inputs for [`spawn_cluster_plane`], lifted from the CLI and the
/// process.
pub(crate) struct ClusterPlaneOptions {
    /// `--cluster-listen`; the plane is disabled when `None`.
    pub cluster_listen: Option<String>,
    /// `--cluster-enrollment-listen` (defaults to operational port + 1).
    pub enrollment_listen: Option<String>,
    /// `--cluster-advertise` (defaults to the operational host).
    pub advertise: Option<String>,
    /// `--cluster-listen-any`.
    pub listen_any: bool,
    /// `--cluster-auto-activate` (Story 9.3 AC #5): enrollments land
    /// `Active` instead of `Pending`.
    pub auto_activate: bool,
    /// Ports the cluster plane must never share.
    pub reserved: ReservedPorts,
    /// The operational listening socket inherited from an outgoing
    /// supervisor on `--hot-upgrade`, as `(bind, fd)`: adopted instead
    /// of binding when `bind` equals the configured operational bind,
    /// closed otherwise.
    pub inherited_operational: Option<(String, RawFd)>,
    /// The audit log the lifecycle hooks write to (`None` when the
    /// access-log store failed to open; events still reach the sinks).
    pub log_store: Option<Arc<LogStore>>,
    /// The alert dispatcher (`ClusterNodeLeft`).
    pub alert_sender: AlertSender,
}

/// Live handles for a running control-plane cluster plane. Dropping
/// the handles does not stop the listeners; `shutdown` does.
pub(crate) struct ClusterPlane {
    /// The mandatory-mTLS operational listener.
    pub operational: OperationalHandle,
    /// The token-gated enrollment listener.
    pub enrollment: EnrollmentHandle,
    /// The fleet runtime shared with the management API.
    pub control: Arc<ControlPlane>,
    /// Operational-listener counters, bridged into Prometheus at
    /// scrape time.
    pub operational_stats: Arc<OperationalStats>,
    /// Enrollment-listener counters, bridged into Prometheus at
    /// scrape time.
    pub enrollment_stats: Arc<EnrollmentStats>,
    /// The liveness publisher and the last-seen flush.
    tasks: Vec<JoinHandle<()>>,
    /// A long-lived dup of the operational socket, kept only so the
    /// next hot upgrade can hand the SAME kernel socket over.
    handoff_listener: std::net::TcpListener,
    /// The operational bind, the key the handoff table uses.
    operational_bind: std::net::SocketAddr,
}

impl ClusterPlane {
    /// The cluster entries for the hot-upgrade FD table: the
    /// operational socket under its role-qualified key.
    pub fn handoff_fds(&self) -> Vec<(ClusterListenerRole, String, RawFd)> {
        vec![(
            ClusterListenerRole::Operational,
            self.operational_bind.to_string(),
            self.handoff_listener.as_raw_fd(),
        )]
    }

    /// Stop both listeners, every established session and the
    /// background tasks.
    pub fn shutdown(self) {
        self.operational.shutdown();
        self.enrollment.shutdown();
        for task in self.tasks {
            task.abort();
        }
    }
}

/// Close an inherited descriptor this process will not use.
pub(crate) fn close_inherited_fd(fd: RawFd) {
    // SAFETY: `fd` was received via SCM_RIGHTS in
    // `pull_inherited_listeners`, is owned exclusively by this process
    // and is wrapped exactly once; dropping the `OwnedFd` closes it.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

/// A UUID v4 string from the process RNG (the node id every label and
/// audit entry uses).
fn new_node_id() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The audit identity of an event that arrived on the cluster plane
/// (no management session behind it): operator `cluster`, role
/// `node`, the peer address as the source.
fn plane_audit_ctx(peer: SocketAddr) -> AuditContext {
    AuditContext {
        username: "cluster".to_string(),
        role: "node".to_string(),
        ip: peer.ip().to_string(),
        user_agent: String::new(),
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// What phase one of a redemption decided under the store lock.
struct BurnedToken {
    node_id: String,
    public_id: String,
}

/// Sign on the blocking pool with no store lock held (the module doc's
/// rule).
async fn sign_node_leaf(
    control: &Arc<ControlPlane>,
    node_id: &str,
    spki_der: Vec<u8>,
) -> Result<IssuedLeaf, String> {
    let control = Arc::clone(control);
    let node_id = node_id.to_string();
    tokio::task::spawn_blocking(move || control.issue_node_leaf(&node_id, &spki_der))
        .await
        .map_err(|e| format!("signing task failed: {e}"))?
        .map_err(|e| e.to_string())
}

/// The redemption pipeline (Story 9.3 AC #1/#3/#4/#5), separable from
/// the audit and refresh side effects so it can be tested against a
/// real store:
///
/// 1. under the store lock: ONE indexed lookup and ONE constant-time
///    verification (a dummy digest when the id is unknown), the
///    mint-time bindings, the key allowlist, then the atomic burn;
/// 2. with no lock: the certificate is signed on a bare public key;
/// 3. under the store lock again: the registry row.
///
/// A signing failure after the burn leaves a burned token and a loud
/// error: the operator mints another. The `Ok(Err(reason))` layer is
/// the refusal diagnostic that stays in the journal.
pub(crate) async fn redeem_with_store(
    store: &Arc<Mutex<ConfigStore>>,
    control: &Arc<ControlPlane>,
    request: EnrollRequest,
    now: DateTime<Utc>,
) -> Result<EnrollGrant, EnrollRefusal> {
    let peer = request.peer;
    let public_key_der = request.public_key_der.clone();
    let node_name = request.node_name.clone();
    let build_version = request.build_version.clone();
    let schema_version = request.schema_version;

    // Phase 1: verify, bind, allowlist, burn.
    let burned = db_blocking(store, move |store| {
        let token_row = store.get_join_token(&request.public_id).map_err(internal)?;
        let key = store.token_hmac_key().map_err(internal)?;
        let stored = token_row
            .as_ref()
            .map(|t| t.secret_hmac.clone())
            .unwrap_or_else(token::dummy_secret_hmac_hex);
        let verified = token::verify_secret(&key, &request.secret, &stored);
        let Some(token_row) = token_row.filter(|_| verified) else {
            return Ok(Err("unknown token or wrong secret"));
        };
        if let Some(bound) = &token_row.bound_node_name {
            if *bound != request.node_name {
                return Ok(Err("node name does not match the token's binding"));
            }
        }
        if let Some(cidr) = &token_row.bound_source_cidr {
            let inside = cidr
                .parse::<ipnet::IpNet>()
                .map(|net| net.contains(&peer.ip()))
                .unwrap_or(false);
            if !inside {
                return Ok(Err("source address is outside the token's CIDR binding"));
            }
        }
        // The key must be acceptable BEFORE the burn: a bad key must
        // not consume a good token.
        if lorica_cluster::ca::check_public_key_allowlist(&request.public_key_der).is_err() {
            return Ok(Err(
                "public key is not on the allowlist (Ed25519, P-256, RSA-2048+)",
            ));
        }
        let node_id = new_node_id();
        if !store
            .burn_join_token(&token_row.public_id, &node_id, now)
            .map_err(internal)?
        {
            return Ok(Err("token expired, already redeemed or revoked"));
        }
        Ok::<_, ApiError>(Ok(BurnedToken {
            node_id,
            public_id: token_row.public_id,
        }))
    })
    .await
    .map_err(|e| EnrollRefusal::Internal(e.to_string()))?
    .map_err(EnrollRefusal::Refused)?;

    // Phase 2: sign, lock-free.
    let issued = sign_node_leaf(control, &burned.node_id, public_key_der)
        .await
        .map_err(|e| {
            error!(
                node_id = %burned.node_id,
                token_public_id = %burned.public_id,
                error = %e,
                "token burned but the node certificate could not be signed; mint another token"
            );
            EnrollRefusal::Internal(e)
        })?;

    // Phase 3: the registry row.
    let status = if control.auto_activate {
        NodeStatus::Active
    } else {
        NodeStatus::Pending
    };
    let node_id = burned.node_id.clone();
    let row = ClusterNode {
        node_id: node_id.clone(),
        name: node_name,
        cert_fingerprint: issued.fingerprint_sha256.clone(),
        cert_serial: issued.serial_hex.clone(),
        prev_cert_fingerprint: None,
        prev_cert_serial: None,
        address: peer.to_string(),
        version: build_version,
        schema_version: i64::from(schema_version),
        status,
        enrolled_at: now,
        last_seen_at: Some(now),
        applied_config_generation: 0,
        applied_config_hash: String::new(),
        cert_not_after: issued.not_after,
        revoked_at: None,
    };
    db_blocking(store, move |store| {
        store.create_cluster_node(&row).map_err(internal)
    })
    .await
    .map_err(|e| EnrollRefusal::Internal(e.to_string()))?;

    Ok(EnrollGrant {
        node_id,
        cert_pem: issued.cert_pem,
        ca_pem: control.ca_pem().to_string(),
        status: status.as_str().to_string(),
        cert_not_after: issued.not_after.to_rfc3339(),
    })
}

/// The binary's redemption and lifecycle hooks: the store, the CA
/// (through the control-plane handle), the audit log and the alert
/// dispatcher behind the transport crate's traits.
struct FleetHandlers {
    control: Arc<ControlPlane>,
    store: Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<LogStore>>,
    alert_sender: AlertSender,
    /// Last renewal grant per node, for [`RENEWAL_COOLDOWN`].
    renewals: StdMutex<HashMap<String, Instant>>,
}

impl FleetHandlers {
    async fn refresh(&self) {
        if let Err(e) = refresh_control_plane(&self.control, &self.store).await {
            error!(error = %e, "cluster plane: roster/CRL refresh failed");
        }
    }

    async fn audit(
        &self,
        peer: SocketAddr,
        action: &str,
        target: (&str, &str),
        after: Option<serde_json::Value>,
    ) {
        record_with_store(
            self.log_store.clone(),
            &plane_audit_ctx(peer),
            action,
            target,
            None,
            after.as_ref(),
        )
        .await;
    }

    /// Whether `node_id` may be granted a renewal now (and record
    /// that it was).
    fn renewal_allowed(&self, node_id: &str) -> bool {
        let mut renewals = self.renewals.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // Keep the map bounded by the fleet: drop entries past the
        // cooldown while we are here.
        renewals.retain(|_, granted| now.duration_since(*granted) < RENEWAL_COOLDOWN);
        if renewals.contains_key(node_id) {
            return false;
        }
        renewals.insert(node_id.to_string(), now);
        true
    }
}

impl EnrollmentHandler for FleetHandlers {
    fn redeem(&self, request: EnrollRequest) -> BoxFuture<'_, Result<EnrollGrant, EnrollRefusal>> {
        Box::pin(async move {
            let peer = request.peer;
            let node_name = request.node_name.clone();
            let public_id = request.public_id.clone();
            let grant = redeem_with_store(&self.store, &self.control, request, Utc::now()).await?;
            self.refresh().await;
            match publish_token_liveness(&self.control, &self.store).await {
                Ok(live) => info!(live_tokens = live, "join token redeemed"),
                Err(e) => error!(error = %e, "token liveness recount failed"),
            }
            self.audit(
                peer,
                "cluster.node.enroll",
                ("cluster_node", &grant.node_id),
                Some(serde_json::json!({
                    "name": node_name,
                    "status": grant.status,
                    "token_public_id": public_id,
                })),
            )
            .await;
            Ok(grant)
        })
    }
}

impl SessionHandler for FleetHandlers {
    fn on_session_established(
        &self,
        node_id: &str,
        via_previous_certificate: bool,
        peer: SocketAddr,
        build_version: &str,
        schema_version: u32,
    ) -> BoxFuture<'_, ()> {
        let node_id = node_id.to_string();
        let build_version = build_version.to_string();
        Box::pin(async move {
            let id = node_id.clone();
            let retired = db_blocking(&self.store, move |store| {
                store
                    .touch_cluster_node(
                        &id,
                        &peer.to_string(),
                        &build_version,
                        i64::from(schema_version),
                        Utc::now(),
                    )
                    .map_err(internal)?;
                if via_previous_certificate {
                    return Ok::<_, ApiError>(None);
                }
                // First session on a renewed certificate: the grace
                // window on the superseded one closes (AC #12).
                store
                    .retire_previous_cluster_certificate(&id, Utc::now())
                    .map_err(internal)
            })
            .await;
            match retired {
                Ok(Some(serial)) => {
                    info!(node_id, serial, "superseded node certificate retired to the CRL");
                    self.refresh().await;
                }
                Ok(None) => {}
                Err(e) => error!(node_id, error = %e, "session bookkeeping failed"),
            }
        })
    }

    fn on_renew(&self, request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>> {
        Box::pin(async move {
            let node_id = request.node_id.clone();
            let peer = request.peer;
            // Eligibility first (Active, inside the renewal window,
            // outside the cooldown), under a short lock; then sign
            // lock-free; then persist.
            let id = node_id.clone();
            let now = Utc::now();
            db_blocking(&self.store, move |store| {
                let node = store
                    .get_cluster_node(&id)
                    .map_err(internal)?
                    .ok_or_else(|| ApiError::NotFound("node not registered".into()))?;
                if node.status != NodeStatus::Active {
                    return Err(ApiError::Forbidden(format!(
                        "node is {}; only an active node renews (AC #5)",
                        node.status.as_str()
                    )));
                }
                if node.cert_not_after - now > RENEWAL_ACCEPT_WINDOW {
                    return Err(ApiError::Conflict(format!(
                        "certificate is valid until {}; renewal is not due",
                        node.cert_not_after.to_rfc3339()
                    )));
                }
                Ok::<_, ApiError>(())
            })
            .await
            .map_err(|e| e.to_string())?;
            if !self.renewal_allowed(&node_id) {
                return Err("renewal cooldown: one grant per hour per node".to_string());
            }
            let issued = sign_node_leaf(&self.control, &node_id, request.public_key_der).await?;
            let id = node_id.clone();
            let persisted = issued.clone();
            let recorded = db_blocking(&self.store, move |store| {
                store
                    .record_cluster_node_renewal(
                        &id,
                        &persisted.fingerprint_sha256,
                        &persisted.serial_hex,
                        persisted.not_after,
                        Utc::now(),
                    )
                    .map_err(internal)
            })
            .await
            .map_err(|e| e.to_string())?;
            if !recorded {
                return Err("node is no longer active".to_string());
            }
            self.refresh().await;
            self.audit(
                peer,
                "cluster.node.renew",
                ("cluster_node", &node_id),
                Some(serde_json::json!({
                    "cert_fingerprint": issued.fingerprint_sha256,
                    "cert_not_after": issued.not_after.to_rfc3339(),
                })),
            )
            .await;
            Ok(RenewGrant {
                cert_pem: issued.cert_pem,
                cert_not_after: issued.not_after.to_rfc3339(),
            })
        })
    }

    fn on_leave(&self, node_id: &str, peer: SocketAddr) -> BoxFuture<'_, Result<(), String>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            let outcome = revoke_node_fully(&self.control, &self.store, &node_id, Utc::now())
                .await?
                .ok_or_else(|| "node not registered".to_string())?;
            warn!(node_id, name = %outcome.node.name, %peer, "node left the fleet; revoked");
            self.alert_sender.send(
                AlertEvent::new(
                    AlertType::ClusterNodeLeft,
                    format!(
                        "cluster node {} ({}) left the fleet",
                        outcome.node.name, node_id
                    ),
                )
                .with_detail("node_id", node_id.clone())
                .with_detail("node_name", outcome.node.name.clone())
                .with_detail("peer", peer.to_string()),
            );
            self.audit(
                peer,
                "cluster.node.leave",
                ("cluster_node", &node_id),
                Some(serde_json::json!({ "name": outcome.node.name, "status": "revoked" })),
            )
            .await;
            Ok(())
        })
    }

    fn on_identity_refused(
        &self,
        fingerprint: &str,
        peer: SocketAddr,
        reason: &'static str,
    ) -> BoxFuture<'_, ()> {
        let fingerprint = fingerprint.to_string();
        Box::pin(async move {
            self.audit(
                peer,
                "cluster.identity.refused",
                ("cluster_certificate", &fingerprint),
                Some(serde_json::json!({ "reason": reason })),
            )
            .await;
        })
    }

    fn on_protocol_violation(&self, node_id: &str, peer: SocketAddr) -> BoxFuture<'_, ()> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            self.audit(
                peer,
                "cluster.protocol.violation",
                ("cluster_node", &node_id),
                None,
            )
            .await;
        })
    }
}

/// Recount live tokens on every expiry edge (and at most every
/// [`FLUSH_INTERVAL`]), so the enrollment listener closes the moment
/// the last token expires even when no mutation happens.
fn spawn_liveness_publisher(
    control: Arc<ControlPlane>,
    store: Arc<Mutex<ConfigStore>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let now = Utc::now();
            let counted = db_blocking(&store, move |store| {
                let live = store.count_live_join_tokens(now).map_err(internal)?;
                let next = store.next_join_token_expiry(now).map_err(internal)?;
                Ok::<_, ApiError>((live, next))
            })
            .await;
            let sleep_for = match counted {
                Ok((live, next)) => {
                    control.publish_token_liveness(live);
                    next.map(|t: DateTime<Utc>| {
                        (t - Utc::now())
                            .to_std()
                            .unwrap_or(Duration::from_secs(1))
                            .max(Duration::from_secs(1))
                    })
                    .unwrap_or(FLUSH_INTERVAL)
                    .min(FLUSH_INTERVAL)
                }
                Err(e) => {
                    error!(error = %e, "token liveness recount failed");
                    FLUSH_INTERVAL
                }
            };
            tokio::time::sleep(sleep_for).await;
        }
    })
}

/// Persist live-session facts every [`FLUSH_INTERVAL`] in one
/// transaction (AC #9's `last_seen_at`, `address`, `version`,
/// `schema_version`) and prune revoked serials whose certificate
/// expired (the CRL stays bounded by the live certificates).
fn spawn_session_flush(
    control: Arc<ControlPlane>,
    store: Arc<Mutex<ConfigStore>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(FLUSH_INTERVAL).await;
            let facts: Vec<LiveNodeFacts> = control
                .sessions
                .snapshot()
                .into_iter()
                .map(|s| LiveNodeFacts {
                    node_id: s.node_id,
                    address: s.peer_addr.to_string(),
                    version: s.build_version,
                    schema_version: i64::from(s.schema_version),
                    last_seen_at: DateTime::<Utc>::from_timestamp(
                        i64::try_from(s.last_seen_unix).unwrap_or(0),
                        0,
                    )
                    .unwrap_or_else(Utc::now),
                })
                .collect();
            let flushed = db_blocking(&store, move |store| {
                if !facts.is_empty() {
                    store.touch_cluster_nodes(&facts).map_err(internal)?;
                }
                store
                    .prune_cluster_revoked_serials(Utc::now())
                    .map_err(internal)
            })
            .await;
            match flushed {
                Ok(pruned) if pruned > 0 => {
                    info!(pruned, "expired revoked serials pruned from the CRL source");
                    if let Err(e) = refresh_control_plane(&control, &store).await {
                        error!(error = %e, "cluster plane: refresh after CRL prune failed");
                    }
                }
                Ok(_) => {}
                Err(e) => error!(error = %e, "cluster session flush failed"),
            }
        }
    })
}

/// Validate the CLI binds, load the CA, build the fleet runtime and
/// start the listeners. `Ok(None)` when `--cluster-listen` is absent
/// (plane disabled).
///
/// Refuses to start (typed error, caller exits) when a bind is
/// invalid or no cluster CA exists: a control plane without a CA
/// cannot authenticate anyone, and silently running without the
/// plane the operator asked for is the wrong failure mode.
pub(crate) async fn spawn_cluster_plane(
    opts: ClusterPlaneOptions,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<Option<ClusterPlane>, String> {
    let Some(value) = opts.cluster_listen.as_deref() else {
        if let Some((bind, fd)) = opts.inherited_operational {
            warn!(
                inherited = %bind,
                "hot upgrade: inherited a cluster listener but --cluster-listen is not set; closing it"
            );
            close_inherited_fd(fd);
        }
        return Ok(None);
    };
    let binds = validate_cluster_listen(
        value,
        opts.enrollment_listen.as_deref(),
        opts.advertise.as_deref(),
        opts.reserved,
        opts.listen_any,
    )?;

    let (ca, stored_leaf, schema_version, takeover_epoch, is_follower) = {
        let store = store.lock().await;
        let ca = store
            .get_cluster_ca()
            .map_err(|e| format!("cluster plane: failed to read the cluster CA: {e}"))?
            .ok_or_else(|| {
                "cluster plane: no cluster CA in the database; run `lorica cluster init` \
                 on this node first"
                    .to_string()
            })?;
        let leaf = store
            .get_control_plane_leaf()
            .map_err(|e| format!("cluster plane: failed to read the control-plane leaf: {e}"))?;
        let schema = store
            .schema_version()
            .map_err(|e| format!("cluster plane: failed to read the schema version: {e}"))?;
        let epoch = store
            .cluster_takeover_epoch()
            .map_err(|e| format!("cluster plane: failed to read the takeover epoch: {e}"))?;
        let follower = store
            .get_cluster_identity()
            .map_err(|e| format!("cluster plane: failed to read the fleet identity: {e}"))?
            .is_some();
        (ca, leaf, schema, epoch, follower)
    };
    if is_follower {
        return Err(
            "cluster plane: this node holds a follower identity (it joined a fleet) and \
             --cluster-listen was passed; a node cannot be both. Run `lorica cluster leave` first"
                .to_string(),
        );
    }
    let ca = ClusterCa::from_pem(&ca.0, &ca.1)
        .map_err(|e| format!("cluster plane: stored cluster CA is unusable: {e}"))?;

    // The leaf KEYPAIR is persisted and the certificate re-issued per
    // boot (90 days, comfortably beyond any process lifetime): join
    // tokens pin the leaf SPKI, so a keypair minted per boot would
    // invalidate every outstanding token on restart. The SAN is the
    // advertised name, which is what followers dial. The stored row is
    // refreshed with the certificate actually served.
    let host = binds.advertise_host.as_str();
    let (server_cert, server_key, first_boot) = match stored_leaf {
        Some((_, key_pem)) => {
            let cert = ca.issue_server_leaf_with_key(host, &key_pem).map_err(|e| {
                format!("cluster plane: failed to re-issue the control-plane leaf: {e}")
            })?;
            (cert, key_pem, false)
        }
        None => {
            let (cert, key) = ca.issue_server_leaf(host).map_err(|e| {
                format!("cluster plane: failed to issue the control-plane leaf: {e}")
            })?;
            (cert, key, true)
        }
    };
    store
        .lock()
        .await
        .set_control_plane_leaf(&server_cert, &server_key)
        .map_err(|e| format!("cluster plane: failed to persist the control-plane leaf: {e}"))?;
    if first_boot {
        info!("cluster plane: control-plane leaf keypair generated and persisted");
    }

    let operational_config =
        lorica_cluster::operational_server_config(ca.cert_pem(), &server_cert, &server_key)
            .map_err(|e| format!("cluster plane: operational TLS config: {e}"))?;
    let enrollment_config = lorica_cluster::enrollment_server_config(&server_cert, &server_key)
        .map_err(|e| format!("cluster plane: enrollment TLS config: {e}"))?;

    // Adopt the inherited socket on a hot upgrade (no rebind gap, no
    // EADDRINUSE against the outgoing supervisor) - but only the
    // socket bound where THIS process is configured to listen. A
    // divergent bind means the two binaries disagree; serving the old
    // socket while logging the new address would be undebuggable.
    let configured_bind = binds.operational.to_string();
    let adopted: Option<std::net::TcpListener> = match opts.inherited_operational {
        Some((bind, fd)) if bind == configured_bind => {
            // SAFETY: `fd` was received via SCM_RIGHTS in
            // `pull_inherited_listeners` and is owned exclusively here
            // (the supervisor closes every other inherited cluster
            // descriptor); it refers to the same kernel listening
            // socket the outgoing supervisor accepts cluster sessions
            // on, and it is wrapped exactly once.
            Some(unsafe { std::net::TcpListener::from_raw_fd(fd) })
        }
        Some((bind, fd)) => {
            warn!(
                inherited = %bind,
                configured = %configured_bind,
                "hot upgrade: inherited cluster listener bind differs from --cluster-listen; \
                 closing it and binding fresh"
            );
            close_inherited_fd(fd);
            None
        }
        None => None,
    };
    let adopted_bind: Option<&str> = adopted.as_ref().map(|_| configured_bind.as_str());
    let std_listener: std::net::TcpListener = match adopted {
        Some(listener) => listener,
        None => std::net::TcpListener::bind(binds.operational)
            .map_err(|e| format!("cluster plane: failed to bind {}: {e}", binds.operational))?,
    };
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("cluster plane: listener non-blocking: {e}"))?;
    let handoff_listener = std_listener
        .try_clone()
        .map_err(|e| format!("cluster plane: failed to dup the listener for handoff: {e}"))?;
    let listener = tokio::net::TcpListener::from_std(std_listener)
        .map_err(|e| format!("cluster plane: tokio listener: {e}"))?;

    // The fleet runtime: roster, session registry, CRL-backed acceptor.
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(operational_config)));
    let fleet_size = Arc::new(AtomicU32::new(0));
    let (token_liveness, liveness_rx) = watch::channel(0u32);
    let control = Arc::new(ControlPlane::new(
        ca,
        &server_cert,
        &server_key,
        Arc::clone(&acceptor),
        Arc::clone(&fleet_size),
        token_liveness,
        opts.auto_activate,
        host,
        env!("CARGO_PKG_VERSION"),
    ));
    refresh_control_plane(&control, store)
        .await
        .map_err(|e| format!("cluster plane: {e}"))?;
    let handlers = Arc::new(FleetHandlers {
        control: Arc::clone(&control),
        store: Arc::clone(store),
        log_store: opts.log_store,
        alert_sender: opts.alert_sender,
        renewals: StdMutex::new(HashMap::new()),
    });

    let operational_stats = Arc::new(OperationalStats::default());
    let mut operational_config = OperationalConfig::new(
        listener,
        acceptor,
        HandshakeConfig::new(u32::try_from(schema_version).unwrap_or(u32::MAX))
            .with_build_version(env!("CARGO_PKG_VERSION")),
    );
    operational_config.fleet_size = fleet_size;
    operational_config.stats = Arc::clone(&operational_stats);
    operational_config.takeover_epoch = takeover_epoch;
    operational_config.fleet = Some(FleetHooks {
        roster: Arc::clone(&control.roster),
        sessions: Arc::clone(&control.sessions),
        handler: Arc::clone(&handlers) as Arc<dyn SessionHandler>,
    });
    let operational = OperationalListener::spawn(operational_config);

    let enrollment_stats = Arc::new(EnrollmentStats::default());
    let enrollment = EnrollmentListener::spawn(
        binds.enrollment,
        Arc::new(SwappableAcceptor::new(Arc::new(enrollment_config))),
        liveness_rx,
        PreAuthBudgets::default(),
        Arc::clone(&enrollment_stats),
        Arc::clone(&handlers) as Arc<dyn EnrollmentHandler>,
    );

    let tasks = vec![
        spawn_liveness_publisher(Arc::clone(&control), Arc::clone(store)),
        spawn_session_flush(Arc::clone(&control), Arc::clone(store)),
    ];

    // WARN, not INFO (AC #11): exposing a fleet listener is the kind
    // of fact an operator must be able to spot in the journal.
    warn!(
        operational = %binds.operational,
        enrollment = %binds.enrollment,
        advertise = %binds.advertise_host,
        adopted_bind = adopted_bind.unwrap_or("-"),
        auto_activate = opts.auto_activate,
        enrolled_nodes = control.roster.len(),
        takeover_epoch,
        "cluster plane enabled: operational listener bound (mTLS mandatory); \
         enrollment listener opens only while a join token is live"
    );
    if opts.auto_activate {
        warn!("cluster plane: --cluster-auto-activate is set; enrolled nodes become Active without operator review");
    }

    Ok(Some(ClusterPlane {
        operational,
        enrollment,
        control,
        operational_stats,
        enrollment_stats,
        tasks,
        handoff_listener,
        operational_bind: binds.operational,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{JoinToken, TokenState};

    fn test_control(auto_activate: bool) -> Arc<ControlPlane> {
        let _ = lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider()
            .install_default();
        let ca = ClusterCa::generate("Test CA").expect("ca");
        let (leaf, key) = ca.issue_server_leaf("cp.internal").expect("leaf");
        let config = lorica_cluster::operational_server_config(ca.cert_pem(), &leaf, &key)
            .expect("config");
        let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(config)));
        let (liveness, _rx) = watch::channel(0u32);
        Arc::new(ControlPlane::new(
            ca,
            &leaf,
            &key,
            acceptor,
            Arc::new(AtomicU32::new(0)),
            liveness,
            auto_activate,
            "cp.internal",
            "test",
        ))
    }

    /// Mint a token straight into the store and return the request a
    /// joiner presenting it would send.
    fn minted_request(
        store: &ConfigStore,
        control: &ControlPlane,
        peer: &str,
        node_name: &str,
        bound_node_name: Option<&str>,
        bound_source_cidr: Option<&str>,
    ) -> (EnrollRequest, String) {
        let key = store.token_hmac_key().expect("hmac key");
        let pin = lorica_cluster::leaf_spki_sha256(&control.leaf_cert_pem).expect("pin");
        let minted = token::mint(&key, &pin).expect("mint");
        let now = Utc::now();
        store
            .create_join_token(&JoinToken {
                public_id: minted.public_id.clone(),
                secret_hmac: minted.secret_hmac.clone(),
                state: TokenState::Unused,
                created_at: now,
                expires_at: now + chrono::Duration::hours(1),
                created_by: "admin".to_string(),
                bound_node_name: bound_node_name.map(str::to_string),
                bound_source_cidr: bound_source_cidr.map(str::to_string),
                burned_at: None,
                burned_by_node_id: None,
            })
            .expect("token row");
        let parsed = token::parse(&minted.token).expect("parse");
        let (spki, _key_pem) = lorica_cluster::ca::generate_node_keypair().expect("keypair");
        (
            EnrollRequest {
                peer: peer.parse().expect("peer"),
                public_id: parsed.public_id,
                secret: parsed.secret.to_vec(),
                public_key_der: spki,
                node_name: node_name.to_string(),
                build_version: "test".to_string(),
                schema_version: 50,
            },
            minted.public_id,
        )
    }

    fn store_with_key() -> Arc<Mutex<ConfigStore>> {
        let key = lorica_config::crypto::EncryptionKey::generate().expect("key");
        Arc::new(Mutex::new(
            ConfigStore::open_in_memory_with_key(key).expect("store"),
        ))
    }

    #[tokio::test]
    async fn redemption_burns_once_and_registers_pending_or_active() {
        let store = store_with_key();
        let control = test_control(false);
        let (request, public_id) = {
            let s = store.lock().await;
            minted_request(&s, &control, "192.0.2.10:5000", "edge-1", None, None)
        };
        let replay = request.clone();
        let grant = redeem_with_store(&store, &control, request, Utc::now())
            .await
            .expect("redeemed");
        assert_eq!(grant.status, "pending");
        assert_eq!(grant.ca_pem, control.ca_pem());
        {
            let s = store.lock().await;
            let node = s.get_cluster_node(&grant.node_id).expect("read").expect("row");
            assert_eq!(node.status, NodeStatus::Pending);
            assert_eq!(node.name, "edge-1");
            let tok = s.get_join_token(&public_id).expect("read").expect("row");
            assert_eq!(tok.state, TokenState::Burned);
            assert_eq!(tok.burned_by_node_id.as_deref(), Some(grant.node_id.as_str()));
        }
        // Replay of the same token is refused, and refused the same
        // way as an unknown one.
        let replayed = redeem_with_store(&store, &control, replay, Utc::now()).await;
        assert!(matches!(replayed, Err(EnrollRefusal::Refused(_))));

        let auto = test_control(true);
        let (request, _) = {
            let s = store.lock().await;
            minted_request(&s, &auto, "192.0.2.11:5000", "edge-2", None, None)
        };
        let grant = redeem_with_store(&store, &auto, request, Utc::now())
            .await
            .expect("redeemed");
        assert_eq!(grant.status, "active");
    }

    #[tokio::test]
    async fn refusals_before_the_burn_keep_the_token_live() {
        let store = store_with_key();
        let control = test_control(false);
        let (good, public_id) = {
            let s = store.lock().await;
            minted_request(
                &s,
                &control,
                "192.0.2.10:5000",
                "edge-1",
                Some("edge-1"),
                Some("192.0.2.0/24"),
            )
        };
        // Wrong secret (unknown-id path shares it).
        let mut wrong_secret = good.clone();
        wrong_secret.secret = vec![0u8; 32];
        assert!(matches!(
            redeem_with_store(&store, &control, wrong_secret, Utc::now()).await,
            Err(EnrollRefusal::Refused("unknown token or wrong secret"))
        ));
        let mut unknown = good.clone();
        unknown.public_id = "0".repeat(24);
        assert!(matches!(
            redeem_with_store(&store, &control, unknown, Utc::now()).await,
            Err(EnrollRefusal::Refused("unknown token or wrong secret"))
        ));
        // Name binding.
        let mut wrong_name = good.clone();
        wrong_name.node_name = "edge-9".to_string();
        assert!(matches!(
            redeem_with_store(&store, &control, wrong_name, Utc::now()).await,
            Err(EnrollRefusal::Refused(r)) if r.contains("binding")
        ));
        // CIDR binding.
        let mut wrong_source = good.clone();
        wrong_source.peer = "198.51.100.7:5000".parse().expect("peer");
        assert!(matches!(
            redeem_with_store(&store, &control, wrong_source, Utc::now()).await,
            Err(EnrollRefusal::Refused(r)) if r.contains("CIDR")
        ));
        // Key allowlist, checked before the burn.
        let mut bad_key = good.clone();
        bad_key.public_key_der = vec![1, 2, 3];
        assert!(matches!(
            redeem_with_store(&store, &control, bad_key, Utc::now()).await,
            Err(EnrollRefusal::Refused(r)) if r.contains("allowlist")
        ));
        // None of that burned the token.
        {
            let s = store.lock().await;
            let tok = s.get_join_token(&public_id).expect("read").expect("row");
            assert_eq!(tok.state, TokenState::Unused);
        }
        // The right request still goes through.
        redeem_with_store(&store, &control, good, Utc::now())
            .await
            .expect("redeemed");
    }

    #[tokio::test]
    async fn three_simultaneous_redemptions_of_one_token_enroll_one_node() {
        let store = store_with_key();
        let control = test_control(false);
        let (request, _) = {
            let s = store.lock().await;
            minted_request(&s, &control, "192.0.2.10:5000", "edge-1", None, None)
        };
        let (a, b, c) = tokio::join!(
            redeem_with_store(&store, &control, request.clone(), Utc::now()),
            redeem_with_store(&store, &control, request.clone(), Utc::now()),
            redeem_with_store(&store, &control, request.clone(), Utc::now())
        );
        let granted = [&a, &b, &c].iter().filter(|o| o.is_ok()).count();
        assert_eq!(granted, 1);
        let s = store.lock().await;
        assert_eq!(s.list_cluster_nodes().expect("list").len(), 1);
    }
}
