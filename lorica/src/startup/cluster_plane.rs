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
use lorica_api::cluster::runtime::MAX_BREAK_GLASS_SECS;
use lorica_api::cluster::runtime::{publish_token_liveness, refresh_control_plane, revoke_node};
use lorica_api::cluster::ControlPlaneRuntime;
use lorica_api::cluster_telemetry_store::ClusterTelemetryStore;
use lorica_api::db::db_blocking;
use lorica_api::error::ApiError;
use lorica_api::log_store::LogStore;
use lorica_cluster::enroll::{
    BoxFuture, EnrollGrant, EnrollRefusal, EnrollRequest, EnrollmentHandler, RenewGrant,
    RenewRequest, SessionHandler,
};
use lorica_cluster::IngestQuota;
use lorica_cluster::{
    token, AppliedConfig, CertBundle, ClusterCa, ConfigPayload, ConfigVersion, ControlPlane,
    EnrollmentHandle, EnrollmentListener, EnrollmentStats, FleetHooks, HandshakeConfig, IssuedLeaf,
    OperationalConfig, OperationalHandle, OperationalListener, OperationalStats, PayloadSource,
    PreAuthBudgets, SwappableAcceptor,
};
use lorica_config::canonical::{restrict_for_recipient, CanonicalConfig, SelectorResolution};
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
/// recounts. A session's `last_seen_at` is therefore at most this
/// stale in the registry; the session hook does not write per session.
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

// ---- The renewal timing contract (Story 9.3 AC #12) ----
//
// Both sides of a renewal live here so their relation is checked by
// one test rather than remembered across two modules: the follower
// asks between RENEWAL_LEAD_MIN_DAYS and RENEWAL_LEAD_MAX_DAYS before
// expiry, checking every RENEWAL_CHECK_INTERVAL; the control plane
// serves only inside RENEWAL_ACCEPT_WINDOW and at most once per
// RENEWAL_COOLDOWN per node. Invariants: ACCEPT_WINDOW > LEAD_MAX (a
// due follower is never refused as "not due"), and a refused follower
// waits RENEWAL_RETRY_AFTER_REFUSAL >= COOLDOWN before asking again.

/// How often the follower's renewal task checks the certificate's
/// remaining lifetime.
pub(crate) const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// Lower bound of the follower's jittered renewal lead, in days
/// before expiry (a third of the 90-day lifetime at most).
pub(crate) const RENEWAL_LEAD_MIN_DAYS: i64 = 25;

/// Upper bound of the follower's jittered renewal lead, in days.
pub(crate) const RENEWAL_LEAD_MAX_DAYS: i64 = 30;

/// A renewal is served only when this much (or less) of the
/// certificate's lifetime is left; anything asking earlier is not a
/// renewal.
const RENEWAL_ACCEPT_WINDOW: chrono::Duration = chrono::Duration::days(35);

/// One renewal grant per node per this interval; a second request
/// inside it is refused (a grant costs a signature and a CRL entry).
const RENEWAL_COOLDOWN: Duration = Duration::from_secs(3600);

/// How long a follower waits after a refused renewal before asking
/// again, so a node behind the cooldown does not burn its per-session
/// refusal budget on the control plane.
pub(crate) const RENEWAL_RETRY_AFTER_REFUSAL: Duration = Duration::from_secs(3600);

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
    /// The alert dispatcher (`ClusterNodeLeft`, `ClusterDrift`).
    pub alert_sender: AlertSender,
    /// The proxy's configuration-reload signal. The control plane
    /// subscribes to it and replicates the new generation to the fleet
    /// after every local mutation (Story 9.4 AC #3).
    pub config_reload: watch::Sender<u64>,
    /// The data directory, where the fan-in database is created
    /// beside `lorica.db` and `access-log.db` (Story 9.6 AC #2).
    pub data_dir: std::path::PathBuf,
}

/// Live handles for a running control-plane cluster plane. Dropping
/// the handles does not stop the listeners; `shutdown` does.
pub(crate) struct ClusterPlane {
    /// The mandatory-mTLS operational listener.
    pub operational: OperationalHandle,
    /// The token-gated enrollment listener.
    pub enrollment: EnrollmentHandle,
    /// The transport crate's fleet handle (roster, sessions, CA, the
    /// replication coordinator).
    pub control: Arc<ControlPlane>,
    /// The same handle plus the drift bookkeeping, shared with the
    /// management API so the report an operator reads and the alert
    /// loop that suppresses per node are one object (Story 9.4 AC #12).
    pub runtime: Arc<ControlPlaneRuntime>,
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

    /// The operational bind's port, so another listener family's
    /// validator can refuse to share it (`ReservedPorts::cluster`).
    pub fn operational_port(&self) -> u16 {
        self.operational_bind.port()
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
        ip: peer.ip().to_string(),
        ..AuditContext::node("cluster")
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// Why a renewal request over a session was refused. No HTTP is
/// involved on this path (the peer gets the opaque status); the
/// variant is what the journal line carries.
#[derive(Debug)]
enum RenewRefusal {
    /// No registry row for the session's node id.
    NotRegistered,
    /// The node is not `Active` (AC #5: a pending or revoked node
    /// receives no certificate).
    NotActive(&'static str),
    /// The current certificate has more than the accept window left.
    NotDue(DateTime<Utc>),
    /// A grant was issued inside the cooldown.
    Cooldown,
    /// The store or the CA failed.
    Internal(String),
}

impl std::fmt::Display for RenewRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRegistered => write!(f, "node not registered"),
            Self::NotActive(status) => {
                write!(f, "node is {status}; only an active node renews (AC #5)")
            }
            Self::NotDue(not_after) => write!(
                f,
                "certificate is valid until {}; renewal is not due",
                not_after.to_rfc3339()
            ),
            Self::Cooldown => write!(f, "renewal cooldown: one grant per hour per node"),
            Self::Internal(reason) => write!(f, "{reason}"),
        }
    }
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
        // The binding is mandatory at mint time since the Story 9.5 QA
        // (D15), and it is enforced here as a REQUIREMENT rather than
        // as an optional check: an unbound row can only come from a
        // token minted by an older build, and honouring it would
        // reopen the path where a joiner claims a name a route already
        // selects. Failing closed costs that operator one new token.
        let Some(bound) = &token_row.bound_node_name else {
            return Ok(Err(
                "this token is not bound to a node name; mint a new one",
            ));
        };
        if *bound != request.node_name {
            return Ok(Err("node name does not match the token's binding"));
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
        // Node names are UNIQUE since Story 9.5 migration 53, because
        // the name is what an operator writes in a route's
        // `node_selector`. Checked BEFORE the burn and answered as a
        // refusal, so a colliding name costs the operator a retry with
        // a different name rather than a burned token and a constraint
        // error out of the store.
        //
        // The name is still not an authorization input: entitlement is
        // resolved to a node id on the control plane (Story 9.5 D3).
        // Uniqueness is for the operator, not for the security model.
        let taken = store
            .list_cluster_nodes()
            .map_err(internal)?
            .into_iter()
            .any(|node| node.name == request.node_name);
        if taken {
            return Ok(Err("a node with this name is already enrolled"));
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
/// Roughly what a batch will cost on disk, for the byte side of the
/// ingest quota (Story 9.6 AC #8).
///
/// Estimated from the decoded payload rather than measured from the
/// frame: the frame is gone by the time this runs, and what the quota
/// is protecting is disk, not bandwidth. The fixed addend per row
/// stands in for the row overhead SQLite adds on top of the strings.
/// What a batch's audit rows will cost on disk (Story 9.9).
///
/// Separate from [`estimated_bytes`] because the audit rows are taken
/// out of the batch before the quota is computed: they are exempt from
/// the shedding verdict, not from the accounting, and a node that
/// pushes only audit rows must still be charged for the work.
fn audit_bytes(rows: &[lorica_cluster::TelemetryAuditRow]) -> u64 {
    const ROW_OVERHEAD: u64 = 64;
    rows.iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.timestamp.len()
                    + r.operator_username.len()
                    + r.operator_role.len()
                    + r.action.len()
                    + r.target_type.len()
                    + r.target_id.len()
                    + r.before_payload_hash.len()
                    + r.after_payload_hash.len()
                    + r.ip.len()
                    + r.user_agent.len()
                    + r.prev_chain_hash.len()
                    + r.chain_hash.len()) as u64
        })
        .sum()
}

fn estimated_bytes(batch: &lorica_cluster::TelemetryPush) -> u64 {
    const ROW_OVERHEAD: u64 = 64;
    // Bans are counted too. They replace rather than append, so they
    // cannot grow the database without bound, but each snapshot is a
    // DELETE plus up to 256 INSERTs under the store lock: the WORK is
    // unbounded even where the storage is not, and a node sending
    // only bans would otherwise pay nothing for it.
    let bans: u64 = batch
        .bans
        .iter()
        .map(|b| ROW_OVERHEAD + (b.client_ip.len() + b.reason.len()) as u64)
        .sum();
    let access: u64 = batch
        .access
        .iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.timestamp.len()
                    + r.method.len()
                    + r.path.len()
                    + r.host.len()
                    + r.backend.len()
                    + r.error.len()
                    + r.client_ip.len()
                    + r.xff_proxy_ip.len()
                    + r.source.len()
                    + r.request_id.len()) as u64
        })
        .sum();
    let waf: u64 = batch
        .waf
        .iter()
        .map(|r| {
            ROW_OVERHEAD
                + (r.description.len()
                    + r.category.len()
                    + r.matched_field.len()
                    + r.matched_value.len()
                    + r.timestamp.len()
                    + r.client_ip.len()
                    + r.route_hostname.len()
                    + r.action.len()) as u64
        })
        .sum();
    access + waf + bans
}

/// How large the fan-in database and its write-ahead log currently
/// are, for the storage watermark (Story 9.6 AC #8).
///
/// The WAL counts: it is where recently ingested rows actually live
/// until a checkpoint, so ignoring it would let the watermark read
/// low exactly while ingest was at its heaviest.
///
/// Returns 0 when the files cannot be stated, which fails OPEN on
/// purpose: an unreadable stat must not shed the fleet's telemetry.
/// A genuine storage failure surfaces as a write error on the next
/// ingest, which is refused and logged rather than guessed at here.
fn telemetry_db_bytes(data_dir: &std::path::Path) -> u64 {
    ["cluster-telemetry.db", "cluster-telemetry.db-wal"]
        .iter()
        .filter_map(|name| std::fs::metadata(data_dir.join(name)).ok())
        .map(|meta| meta.len())
        .sum()
}

struct FleetHandlers {
    control: Arc<ControlPlane>,
    store: Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<LogStore>>,
    alert_sender: AlertSender,
    /// Last renewal grant per node, for [`RENEWAL_COOLDOWN`].
    renewals: StdMutex<HashMap<String, Instant>>,
    /// The fan-in database (Story 9.6 AC #2). `None` when it could
    /// not be opened, in which case telemetry is refused rather than
    /// silently dropped: a control plane that cannot store what its
    /// fleet reports should say so.
    telemetry: Option<Arc<ClusterTelemetryStore>>,
    /// Per-node ingest budgets and the storage watermark (AC #8).
    quota: IngestQuota,
    /// Where the fan-in database lives, for the storage watermark.
    data_dir: std::path::PathBuf,
    /// The same reload signal every configuration mutation fires, so a
    /// roster write that changes what a `node_selector` resolves to
    /// runs a replication round like any other configuration change
    /// (Story 10.0).
    config_reload: watch::Sender<u64>,
}

impl FleetHandlers {
    async fn refresh(&self) {
        if let Err(e) = refresh_control_plane(&self.control, &self.store).await {
            error!(error = %e, "cluster plane: roster/CRL refresh failed");
        }
    }

    /// Fire the reload signal, the way `ApiState::notify_config_changed`
    /// does for a configuration mutation.
    ///
    /// # Which roster writes need this, and which do not
    ///
    /// `SelectorResolution::from_rows` is built from the
    /// `(name, node_id)` rows of `cluster_nodes`, every status
    /// included, so only a write that ADDS, REMOVES or RENAMES a row
    /// can change what a selector entry resolves to. Enrolment
    /// (`create_cluster_node`, the one call below) is the only runtime
    /// write that does. Activation and revocation flip `status` and
    /// leave the name and the id alone, so they change no cut and
    /// firing for them would cost the whole fleet a reload for
    /// nothing. The migration-53 duplicate-name rename runs at boot,
    /// before any signal could be delivered, and is caught by
    /// [`seed_accepted_config`] instead.
    fn signal_fleet_change(&self) {
        let next = *self.config_reload.borrow() + 1;
        let _ = self.config_reload.send(next);
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

    /// Whether `node_id` may be granted a renewal now. The grant is
    /// recorded by [`Self::record_renewal_grant`] once it actually
    /// held, so a signing or store failure does not lock the node out
    /// for the cooldown.
    fn renewal_allowed(&self, node_id: &str) -> bool {
        let mut renewals = self.renewals.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        // Keep the map bounded by the fleet: drop entries past the
        // cooldown while we are here.
        renewals.retain(|_, granted| now.duration_since(*granted) < RENEWAL_COOLDOWN);
        !renewals.contains_key(node_id)
    }

    fn record_renewal_grant(&self, node_id: &str) {
        self.renewals
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(node_id.to_string(), Instant::now());
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
            // A new `(name, node_id)` row is a change to what every
            // `node_selector` resolves to, which is half of what a
            // per-recipient payload is a function of. Left unsignalled
            // it would move every cut without moving the generation.
            self.signal_fleet_change();
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
        _peer: SocketAddr,
        _build_version: &str,
        _schema_version: u32,
    ) -> BoxFuture<'_, ()> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            // The store is touched only when there is something to
            // retire: the first session on a renewed certificate closes
            // the grace window on the superseded one (AC #12). Live
            // facts (address, version, last seen) reach the registry
            // through the periodic flush, so an ordinary session, or a
            // node reconnecting in a loop, never takes the store lock.
            if via_previous_certificate || !self.control.roster.has_superseded_certificate(&node_id)
            {
                return;
            }
            let id = node_id.clone();
            let retired = db_blocking(&self.store, move |store| {
                store
                    .retire_previous_cluster_certificate(&id, Utc::now())
                    .map_err(internal)
            })
            .await;
            match retired {
                Ok(Some(serial)) => {
                    info!(
                        node_id,
                        serial, "superseded node certificate retired to the CRL"
                    );
                    self.refresh().await;
                }
                Ok(None) => {}
                Err(e) => error!(node_id, error = %e, "retiring the superseded certificate failed"),
            }
        })
    }

    fn on_renew(&self, request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>> {
        Box::pin(async move {
            self.renew(request)
                .await
                .map_err(|refusal| refusal.to_string())
        })
    }

    fn on_leave(&self, node_id: &str, peer: SocketAddr) -> BoxFuture<'_, Result<(), String>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            // A node id is a fresh UUID per enrolment, so a fleet
            // with churn would otherwise accumulate one spend entry
            // per historical node for the life of the process.
            self.quota.forget(&node_id);
            let outcome = revoke_node(&self.control, &self.store, &node_id, Utc::now())
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "node not registered".to_string())?;
            // The row flipped and the session is gone: alert and audit
            // that BEFORE surfacing a refresh failure (AC #13 says both
            // sides audit, and a revocation with no trail is worse than
            // a refused leave).
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
                .with_detail("peer", peer.to_string())
                // A cooperative leave wipes the node's copy of these
                // keys (Story 9.3 AC #13), but the wipe is the node's
                // word; the operator re-issues on the same evidence a
                // revocation gives them.
                .with_detail(
                    "certificates_to_reissue",
                    outcome.certificates_to_reissue.join(","),
                ),
            );
            self.audit(
                peer,
                "cluster.node.leave",
                ("cluster_node", &node_id),
                Some(serde_json::json!({
                    "name": outcome.node.name,
                    "status": "revoked",
                    "certificates_to_reissue": outcome.certificates_to_reissue,
                    "refresh_error": outcome.refresh_error.as_ref().map(|e| e.to_string()),
                })),
            )
            .await;
            match outcome.refresh_error {
                Some(e) => Err(e.to_string()),
                None => Ok(()),
            }
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

    fn on_telemetry_push(
        &self,
        node_id: &str,
        batch: lorica_cluster::TelemetryPush,
    ) -> BoxFuture<'_, Result<lorica_cluster::TelemetryPushAck, String>> {
        let node_id = node_id.to_string();
        let mut batch = batch;
        Box::pin(async move {
            let Some(telemetry) = self.telemetry.as_ref() else {
                // Refused rather than silently accepted: a control
                // plane that cannot store what its fleet reports must
                // not tell the fleet it did.
                return Err("the telemetry database is not open".to_string());
            };

            // Audit rows first, and outside every shedding decision
            // below (Story 9.9 AC #2). Losing an access row costs a
            // line of traffic; losing an audit row costs the record of
            // an operator action, on the one table whose entire purpose
            // is that the record exists. The watermark's own comment
            // already says audit writes keep the volume when telemetry
            // is dropped; this is that rule applied to the rows that
            // arrive over the fan-in rather than only to local ones.
            //
            // They land in `audit_log` beside the local rows, not in
            // the telemetry database: verify and retention operate on
            // one table, partitioned by node.
            //
            // Bounded on the wire by `MAX_TELEMETRY_AUDIT`, so exempt
            // from shedding is not the same as unbounded.
            // Measured BEFORE the take, because the quota is computed
            // from what remains in the batch. Without this the node
            // pays nothing for audit rows, which is not what the doc,
            // the proto comment and this story all say: they are
            // counted against the quota and exempt from its VERDICT,
            // which are different things. Charging them is what makes a
            // node flooding audit get a `retry_after_s` even though its
            // rows are stored.
            let audit_charge = audit_bytes(&batch.audit);
            let audit_count = batch.audit.len();
            let audit_rows = std::mem::take(&mut batch.audit);
            let accepted_audit = if audit_rows.is_empty() {
                0
            } else {
                let Some(log_store) = self.log_store.clone() else {
                    // Refused, not silently dropped, for the same
                    // reason the missing telemetry database is: a
                    // control plane that cannot store what its fleet
                    // reports must not tell the fleet it did.
                    return Err("the audit log is not open on this node".to_string());
                };
                let stamped = node_id.clone();
                // Refused rather than clamped. A row id that does not
                // fit is a peer sending something the schema cannot
                // hold, and clamping it to `i64::MAX` would insert a
                // row whose position in the chain is a lie, breaking
                // the ordering `verify` depends on with no diagnostic
                // pointing at the cause. Unreachable today, since the
                // sender's ids are positive rowids; the point is that
                // the next thing to touch this field cannot make it
                // silent.
                let rows: Vec<lorica_api::audit::FannedInAuditRow> = audit_rows
                    .into_iter()
                    .map(|r| {
                        let origin_id = i64::try_from(r.origin_id).map_err(|_| {
                            "a fanned-in audit row carries an out-of-range origin id".to_string()
                        })?;
                        Ok(lorica_api::audit::FannedInAuditRow {
                            origin_id,
                            timestamp: r.timestamp,
                            operator_username: r.operator_username,
                            operator_role: r.operator_role,
                            action: r.action,
                            target_type: r.target_type,
                            target_id: r.target_id,
                            before_payload_hash: r.before_payload_hash,
                            after_payload_hash: r.after_payload_hash,
                            ip: r.ip,
                            user_agent: r.user_agent,
                            prev_chain_hash: r.prev_chain_hash,
                            chain_hash: r.chain_hash,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                tokio::task::spawn_blocking(move || {
                    // `stamped` is the id the SESSION proved, like
                    // every other fanned-in row.
                    log_store.insert_fanned_in_audit(&stamped, &rows)
                })
                .await
                .map_err(|e| format!("the audit fan-in task failed: {e}"))??
            };

            // The storage watermark, which overrides every per-node
            // budget: when the disk is short, a node well inside its
            // quota is shed too. Telemetry is the first thing dropped
            // so configuration and audit writes are the last (AC #8).
            // Off the executor with the rest of the blocking work:
            // two stats are cheap, but this handler is careful to
            // offload everything else and an inconsistency here is a
            // regression magnet.
            let data_dir = self.data_dir.clone();
            let used = tokio::task::spawn_blocking(move || telemetry_db_bytes(&data_dir))
                .await
                .map_err(|e| format!("the storage watermark task failed: {e}"))?;
            let storage =
                lorica_cluster::storage_verdict(used, lorica_cluster::DEFAULT_STORAGE_CAP_BYTES);
            if matches!(storage, lorica_cluster::IngestVerdict::Shed { .. }) {
                warn!(
                    node_id,
                    used_bytes = used,
                    cap_bytes = lorica_cluster::DEFAULT_STORAGE_CAP_BYTES,
                    bans_shed = batch.bans.len(),
                    "shedding telemetry fleet-wide: the fan-in database is at its cap, which means retention is not keeping up. Configuration and audit writes keep the rest of the volume. The ban snapshot is shed too, so the fleet ban view goes stale until this clears"
                );
                // Bans are counted in the drop metric like everything
                // else. They ARE shed here, and saying nothing would
                // leave the fleet ban view silently stale during
                // exactly the incident this watermark fires in.
                lorica_api::metrics::inc_cluster_telemetry_dropped(
                    &node_id,
                    "storage_watermark",
                    (batch.access.len() + batch.waf.len() + batch.bans.len()) as u64,
                );
                return Ok(lorica_cluster::TelemetryPushAck {
                    retry_after_s: storage.retry_after_s(),
                    // Already stored: the watermark sheds telemetry,
                    // never the audit trail.
                    accepted_audit,
                    audit_cursor: batch.audit_cursor,
                    ..Default::default()
                });
            }

            // Bytes are estimated from the decoded payload rather than
            // the frame, because the frame is gone by now and what
            // matters is what this will cost on disk.
            let bytes = estimated_bytes(&batch) + audit_charge;
            // Bans are part of what the node offered, so they are
            // part of what it is charged for.
            let verdict = self.quota.admit(
                &node_id,
                batch.access.len(),
                batch.waf.len() + batch.bans.len() + audit_count,
                bytes,
            );
            let take_access = verdict.access_allowance(batch.access.len());
            let take_waf = verdict.waf_allowance(batch.waf.len());
            let shed = (batch.access.len() - take_access) + (batch.waf.len() - take_waf);
            if shed > 0 {
                warn!(
                    node_id,
                    shed,
                    offered = batch.access.len() + batch.waf.len(),
                    "the node is over its telemetry ingest quota; the excess is dropped and counted"
                );
                lorica_api::metrics::inc_cluster_telemetry_dropped(
                    &node_id,
                    "node_quota",
                    shed as u64,
                );
            }

            // The ban snapshot is authoritative for the node that sent
            // it: an address absent from it is no longer banned there
            // (decision D3).
            // A node whose quota is exhausted does NOT get its
            // snapshot applied, so ban spam cannot buy an unbounded
            // amount of work under the store lock.
            let ban_count = if matches!(verdict, lorica_cluster::IngestVerdict::Shed { .. }) {
                0
            } else {
                let telemetry_for_bans = Arc::clone(telemetry);
                let bans = std::mem::take(&mut batch.bans);
                let ban_node = node_id.clone();
                tokio::task::spawn_blocking(move || {
                    telemetry_for_bans.replace_ban_snapshot(&ban_node, &bans)
                })
                .await
                .map_err(|e| format!("the ban snapshot task failed: {e}"))??
            };

            let store = Arc::clone(telemetry);
            let stamped = node_id.clone();
            let access: Vec<_> = batch.access.into_iter().take(take_access).collect();
            let waf: Vec<_> = batch.waf.into_iter().take(take_waf).collect();
            let outcome = tokio::task::spawn_blocking(move || {
                // `stamped` is the id the SESSION proved. Nothing in
                // the batch names a node (decision D2).
                store.ingest(&stamped, &access, &waf, &[])
            })
            .await
            .map_err(|e| format!("the telemetry ingest task failed: {e}"))??;

            lorica_api::metrics::inc_cluster_telemetry_ingested(
                &node_id,
                outcome.access + outcome.waf,
            );
            Ok(lorica_cluster::TelemetryPushAck {
                accepted_access: outcome.access,
                accepted_waf: outcome.waf,
                accepted_bans: ban_count,
                retry_after_s: verdict.retry_after_s(),
                access_cursor: batch.access_cursor,
                waf_cursor: batch.waf_cursor,
                accepted_audit,
                audit_cursor: batch.audit_cursor,
            })
        })
    }

    /// A follower asks for certificate keys it lacks (Story 9.5 AC #8).
    ///
    /// The id list is a hint about what the node is missing, never an
    /// authorization input: entitlement is re-resolved here from the
    /// store for every id, and an id the node is not selected for is
    /// dropped in silence rather than refused, so the answer does not
    /// tell the node whether that certificate exists. Answering with
    /// fewer bundles than were asked for, or none, is the normal case.
    fn on_cert_pull(
        &self,
        node_id: &str,
        cert_ids: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<CertBundle>, String>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            let entitled_to = node_id.clone();
            let bundles = db_blocking(&self.store, move |store| {
                let mut out: Vec<CertBundle> = Vec::new();
                for cert_id in cert_ids.iter().take(lorica_cluster::MAX_CERT_BUNDLES) {
                    // Entitlement is resolved HERE, from the store, and
                    // never from what the peer asked for (Story 9.5
                    // D3). The id list is a hint about what the node is
                    // missing, not an authorization input.
                    let recipients = store.cert_key_recipients(cert_id).map_err(internal)?;
                    if !recipients.iter().any(|id| id == &entitled_to) {
                        continue;
                    }
                    let Some(cert) = store.get_certificate(cert_id).map_err(internal)? else {
                        continue;
                    };
                    if cert.key_pem.is_empty() {
                        continue;
                    }
                    out.push(lorica_api::cluster::runtime::cert_bundle(&cert));
                }
                Ok::<_, ApiError>(out)
            })
            .await
            .map_err(|e| e.to_string())?;
            // A node asking for something it is not selected for gets
            // silence on that id rather than a refusal: the answer must
            // not tell it whether the certificate exists at all.
            info!(node_id, sent = bundles.len(), "answered a certificate pull");
            lorica_api::metrics::inc_cluster_cert_push_by(&node_id, "served", bundles.len());
            Ok(bundles)
        })
    }

    fn on_config_pull(
        &self,
        node_id: &str,
        applied: AppliedConfig,
    ) -> BoxFuture<'_, Result<Option<ConfigPayload>, String>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            let accepted = &self.control.accepted;
            if !accepted.expected_for(&node_id).is_behind(&applied) {
                // The node is where the fleet is. If it was quarantined
                // for slow or refused Prepares, it has converged on its
                // own and belongs back in the commit set, which is the
                // release the documentation promises.
                if self.control.replication.release(&node_id) {
                    info!(
                        node_id,
                        "node released from replication quarantine: it converged"
                    );
                }
                return Ok(None);
            }
            // Served from the ACCEPTED source, never re-read from the
            // store. Three reasons: a pull must not be able to make the
            // control plane walk every replicated table under the store
            // lock, it must never hand out a generation the fleet
            // aborted, and what it hands out is the caller's own cut
            // (Story 10.0), not the fleet's configuration.
            let Some(payload) = accepted.payload_for(&node_id) else {
                return Err("no configuration has been accepted by the fleet yet".to_string());
            };
            info!(
                node_id,
                from_generation = applied.generation,
                to_generation = payload.generation,
                "serving a configuration pull"
            );
            lorica_api::metrics::inc_cluster_config_apply(&node_id, "pulled");
            Ok(Some(payload))
        })
    }
}

impl FleetHandlers {
    /// The renewal pipeline (AC #12): eligibility under a short lock,
    /// signing lock-free, persistence under a second short lock.
    ///
    /// A session on the superseded certificate skips the "is it due"
    /// check: the node holds a grant it never persisted (crash between
    /// the answer and the write), and re-issuing is the only way for it
    /// to leave the grace window on its own. The cooldown still applies.
    async fn renew(&self, request: RenewRequest) -> Result<RenewGrant, RenewRefusal> {
        let node_id = request.node_id.clone();
        let peer = request.peer;
        let id = node_id.clone();
        let now = Utc::now();
        let lost_grant = request.via_previous_certificate;
        // `Ok(Err(refusal))` is the eligibility verdict; the outer
        // error is the store failing.
        db_blocking(&self.store, move |store| {
            let Some(node) = store.get_cluster_node(&id).map_err(internal)? else {
                return Ok::<_, ApiError>(Err(RenewRefusal::NotRegistered));
            };
            if node.status != NodeStatus::Active {
                return Ok(Err(RenewRefusal::NotActive(node.status.as_str())));
            }
            if !lost_grant && node.cert_not_after - now > RENEWAL_ACCEPT_WINDOW {
                return Ok(Err(RenewRefusal::NotDue(node.cert_not_after)));
            }
            Ok(Ok(()))
        })
        .await
        .map_err(|e| RenewRefusal::Internal(e.to_string()))??;
        if !self.renewal_allowed(&node_id) {
            return Err(RenewRefusal::Cooldown);
        }
        if lost_grant {
            warn!(
                node_id,
                %peer,
                "renewal requested over the superseded certificate: re-issuing the lost grant"
            );
        }
        let issued = sign_node_leaf(&self.control, &node_id, request.public_key_der)
            .await
            .map_err(RenewRefusal::Internal)?;
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
        .map_err(|e| RenewRefusal::Internal(e.to_string()))?;
        if !recorded {
            return Err(RenewRefusal::NotActive("no longer active"));
        }
        self.record_renewal_grant(&node_id);
        self.refresh().await;
        self.audit(
            peer,
            "cluster.node.renew",
            ("cluster_node", &node_id),
            Some(serde_json::json!({
                "cert_fingerprint": issued.fingerprint_sha256,
                "cert_not_after": issued.not_after.to_rfc3339(),
                "via_previous_certificate": lost_grant,
            })),
        )
        .await;
        Ok(RenewGrant {
            cert_pem: issued.cert_pem,
            cert_not_after: issued.not_after.to_rfc3339(),
        })
    }
}

/// How often the drift evaluation runs on the control plane (Story
/// 9.4 AC #12). Alerts are additionally suppressed per node by the
/// runtime's exponential backoff, so this cadence bounds detection
/// latency, not alert volume.
const DRIFT_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Slack added to the break-glass window when looking for the
/// follower's own audit row: telemetry drains every ten seconds, so a
/// freshly opened window can be real and not yet corroborated.
const DRAIN_SLACK_SECS: i64 = 60;

/// Replicate the configuration this process just reloaded to the
/// fleet (Story 9.4 AC #3/#5/#6): increment the persisted generation,
/// encode the canonical blob and its hash, publish the new version so
/// every handshake and heartbeat advertises it, then run one
/// Prepare/Commit round over the connected active sessions.
///
/// Driven by [`spawn_replication_watch`] off the same signal the
/// local reload runs on. The store commits before that signal fires,
/// so the blob encoded here is the configuration this node owns
/// whether or not its own data plane has finished swapping. Failures
/// are logged and counted; they never fail the mutation that triggered
/// them, which is already committed locally.
pub(crate) async fn replicate_after_reload(
    runtime: &Arc<ControlPlaneRuntime>,
    store: &Arc<Mutex<ConfigStore>>,
) {
    let control = &runtime.control;
    // Encode and increment under ONE store lock. The pair
    // (generation, hash) is treated as atomic by every consumer, so
    // assembling it across two lock acquisitions would let a mutation
    // landing between them publish generation N stamped with the hash
    // of N-1.
    //
    // The encode comes first because the reload signal also fires for
    // changes that never replicate (an operator account, a session, a
    // GeoIP database downloaded by the auto-updater), and the fleet
    // identity hash is exactly the identity of what does replicate: an
    // unchanged identity means there is nothing for the fleet to
    // apply, so the generation does not move and no round runs.
    let accepted_hash = control.accepted.version().hash;
    let encoded = db_blocking(store, move |store| {
        let cfg = lorica_config::canonical::canonical_config(store).map_err(internal)?;
        let blob = lorica_config::canonical::encode_canonical(&cfg).map_err(internal)?;
        // From the bytes we already hold: `canonical_hash` would walk
        // every replicated table and serialise it a second time.
        let blob_hash = lorica_config::canonical::sha256_hex(&blob);
        let nodes = node_rows(store)?;
        // The ROSTER is part of what is compared, not just the blob.
        // A recipient's payload is a function of two sources since
        // Story 10.0: the configuration, and the roster that turns a
        // `node_selector` name into a node id. A node enrolling under
        // a name a route already selects changes every cut without
        // touching one byte of configuration, and comparing the blob
        // alone would call that "nothing to replicate". The fleet
        // would then hold cuts that the next boot, reading the roster
        // as it is THEN, recomputes differently at the same
        // generation, and every node would read as drifted. Folding
        // the roster in makes a roster change a configuration change,
        // so the generation advances with it.
        let hash = lorica_config::canonical::fleet_identity_hash(&blob_hash, &nodes);
        if hash == accepted_hash {
            return Ok::<_, ApiError>(None);
        }
        // A follower refuses a blob whose address lists do not parse
        // (backlog #88), which aborts the round for the whole fleet.
        // The API, the importer and the replica apply all validate, so
        // reaching this means a store written before they did; say so
        // HERE, where the setting and the node are known, instead of
        // leaving the operator with N identical refusals and no cause.
        if let Err(reason) = cfg.global.validate_cidr_lists() {
            warn!(
                %reason,
                "a replicated setting carries a malformed CIDR; every follower will refuse this \
                 configuration until it is corrected through the settings API"
            );
        }
        let generation = store
            .increment_cluster_config_generation()
            .map_err(internal)?;
        // Recorded under the same store lock as the increment, so the
        // pair a restart reads back is the pair this round is about to
        // publish. The increment comes FIRST on purpose: a crash
        // between the two leaves the persisted hash behind the
        // generation, which the boot seed reads as "a round is owed"
        // and repairs by publishing. The reverse order would leave a
        // hash claiming a generation that was never encoded, and the
        // seed would believe it.
        store
            .set_cluster_published_fleet_hash(&hash)
            .map_err(internal)?;
        Ok(Some(FleetPayloads::new(generation, hash, cfg, &nodes)))
    })
    .await;
    let payloads: Arc<FleetPayloads> = match encoded {
        Ok(Some(payloads)) => Arc::new(payloads),
        Ok(None) => {
            info!("configuration reload changed nothing the fleet replicates; no round");
            return;
        }
        Err(e) => {
            error!(error = %e, "cluster replication: could not encode the configuration");
            return;
        }
    };

    let generation = payloads.generation;
    // The round publishes the version itself, and only once Prepare
    // has succeeded fleet-wide: see `AcceptedConfig`.
    let report = control.replicate(payloads).await;
    for node_id in &report.committed {
        lorica_api::metrics::inc_cluster_config_apply(node_id, "committed");
    }
    for (node_id, _) in &report.evicted {
        lorica_api::metrics::inc_cluster_config_apply(node_id, "evicted");
    }
    for (node_id, _) in &report.rejected {
        lorica_api::metrics::inc_cluster_config_apply(node_id, "rejected");
    }
    for (node_id, _) in &report.commit_failed {
        lorica_api::metrics::inc_cluster_config_apply(node_id, "commit_failed");
    }
    if report.aborted {
        warn!(
            generation,
            rejected = report.rejected.len(),
            "cluster replication ABORTED: a follower refused the configuration semantically. The generation was not published, so the fleet stays on the previous one and does not pull this one; THIS node already serves it and is ahead of its own fleet. Fix what the follower refused, or revoke it, then change the configuration again"
        );
        return;
    }
    lorica_api::metrics::set_cluster_config_generation("control_plane", generation);
    if !report.commit_failed.is_empty() && !report.committed.is_empty() {
        warn!(
            generation,
            committed = report.committed.len(),
            commit_failed = report.commit_failed.len(),
            "cluster replication SPLIT FLEET: some nodes committed and others did not; the stragglers reconcile on their next heartbeat"
        );
    } else {
        info!(
            generation,
            committed = report.committed.len(),
            evicted = report.evicted.len(),
            skipped_break_glass = report.skipped_break_glass.len(),
            skipped_quarantined = report.skipped_quarantined.len(),
            "cluster configuration replicated"
        );
    }
}

/// The `(name, node_id)` rows a round resolves `node_selector`
/// against. Read under the same store lock as the configuration, so
/// the entitlement a payload is cut on matches the roster the
/// generation was encoded from.
fn node_rows(store: &ConfigStore) -> Result<Vec<(String, String)>, ApiError> {
    Ok(store
        .list_cluster_nodes()
        .map_err(internal)?
        .into_iter()
        .map(|node| (node.name, node.node_id))
        .collect())
}

/// Publish the generation the store already holds, so the accepted
/// configuration exists before the first session is admitted.
///
/// Two reasons it cannot wait: a follower that connects during startup
/// must not be told the control plane is at generation 0 and wipe
/// itself, and a convergence pull is answered from this payload rather
/// than from the store, so it has to exist before anyone can ask.
///
/// What the store holds at boot IS the accepted state: it is the
/// configuration this process is about to serve, and the fleet either
/// converged on it before the restart or converges on it now. That
/// holds only while the persisted generation still describes the
/// persisted content, which is what the fleet identity hash records
/// and what this repairs when it does not. Returns the generation
/// published.
async fn seed_accepted_config(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<u64, String> {
    let s = store.lock().await;
    let mut generation = s
        .cluster_config_generation()
        .map_err(|e| format!("cluster plane: configuration generation: {e}"))?;
    let cfg = lorica_config::canonical::canonical_config(&s)
        .map_err(|e| format!("cluster plane: canonical read: {e}"))?;
    let blob = lorica_config::canonical::encode_canonical(&cfg)
        .map_err(|e| format!("cluster plane: canonical encode: {e}"))?;
    let nodes = node_rows(&s).map_err(|e| format!("cluster plane: {e}"))?;
    let hash = lorica_config::canonical::fleet_identity_hash(
        &lorica_config::canonical::sha256_hex(&blob),
        &nodes,
    );
    // Is this seed FAITHFUL to what the fleet was last told? The
    // generation is a counter over changes to the fleet's identity,
    // and the seed rebuilds a generation's payloads from the store.
    // The two agree only if nothing moved the identity without moving
    // the counter, which is exactly what the persisted hash records. A
    // crash between a roster write and the round it owed is that
    // window, and so is the migration-53 duplicate-name rename, which
    // renames rows at boot before this runs.
    let published = s
        .cluster_published_fleet_hash()
        .map_err(|e| format!("cluster plane: published fleet hash: {e}"))?;
    if published.is_empty() {
        // Nothing to compare against: a control plane that has never
        // published, or a database written before the key existed.
        // Record what is being published rather than inventing a round
        // nobody owes.
        s.set_cluster_published_fleet_hash(&hash)
            .map_err(|e| format!("cluster plane: published fleet hash: {e}"))?;
    } else if published != hash {
        generation = s
            .increment_cluster_config_generation()
            .map_err(|e| format!("cluster plane: configuration generation: {e}"))?;
        s.set_cluster_published_fleet_hash(&hash)
            .map_err(|e| format!("cluster plane: published fleet hash: {e}"))?;
        warn!(
            generation,
            "cluster plane: what the fleet replicates changed since the last round was published, \
             so a round is OWED. Seeding the previous generation would tell every node it is in \
             sync while holding a cut this process no longer computes, so the generation is \
             advanced instead and the fleet converges by pull or on the next mutation"
        );
    }
    control
        .accepted
        .publish(Arc::new(FleetPayloads::new(generation, hash, cfg, &nodes)));
    Ok(generation)
}

/// One generation's payloads, cut per recipient (Story 10.0).
///
/// Holds the control plane's full canonical view plus the round's
/// name-to-id resolution, and encodes a recipient's cut on demand. The
/// memo matters because the same node is asked for more than once: the
/// Prepare, then the Commit, then every convergence pull answered from
/// this source until the next generation replaces it.
pub(crate) struct FleetPayloads {
    generation: u64,
    /// The fleet's IDENTITY: the canonical blob's hash folded with the
    /// roster rows `resolution` was built from
    /// (`lorica_config::canonical::fleet_identity_hash`).
    ///
    /// It is not the hash of any blob on the wire, and has not been
    /// since Story 10.0 made the payload per recipient. Its two jobs
    /// are change detection on the reload path and the "where the
    /// fleet is" header of `/cluster/drift` and `/cluster/replication`.
    /// The roster belongs in it because a cut is a function of the
    /// roster as much as of the configuration.
    fleet_hash: String,
    config: CanonicalConfig,
    resolution: SelectorResolution,
    /// Behind an `Arc` so the expectation path can read a generation
    /// and a hash off a cut without copying the cut's blob: at fleet
    /// scale that copy happened once per node per heartbeat, pull,
    /// handshake and dashboard render.
    memo: StdMutex<HashMap<String, Arc<ConfigPayload>>>,
}

impl FleetPayloads {
    fn new(
        generation: u64,
        fleet_hash: String,
        config: CanonicalConfig,
        node_rows: &[(String, String)],
    ) -> Self {
        let resolution = SelectorResolution::from_rows(node_rows.iter().cloned());
        // A selector entry naming no single node reaches nobody. That
        // is the safe direction, but silence would leave an operator
        // debugging a route that is simply never delivered, so the
        // round says so once per encode of the fleet's view.
        for route in &config.routes {
            for name in resolution.unresolvable(&route.node_selector) {
                warn!(
                    route_id = %route.id,
                    selector_entry = %name,
                    "node_selector entry resolves to no single node; this route is delivered to nobody through it"
                );
            }
        }
        Self {
            generation,
            fleet_hash,
            config,
            resolution,
            memo: StdMutex::new(HashMap::new()),
        }
    }

    /// One recipient's cut, encoded once and shared thereafter.
    ///
    /// The only place a cut is built. Both trait methods go through
    /// here, so the bytes a node is sent and the hash it is told to
    /// hold cannot come from two different computations.
    fn cut(&self, node_id: &str) -> Arc<ConfigPayload> {
        {
            let memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(found) = memo.get(node_id) {
                return Arc::clone(found);
            }
        }
        let cut = restrict_for_recipient(&self.config, node_id, &self.resolution);
        // An encode failure here would mean a configuration this
        // process just read cannot be serialised. The empty blob that
        // results is refused by the recipient's strict decode, which
        // fails the round, rather than applied as "nothing configured".
        let blob = lorica_config::canonical::encode_canonical(&cut).unwrap_or_default();
        let payload = Arc::new(ConfigPayload {
            generation: self.generation,
            hash: lorica_config::canonical::sha256_hex(&blob),
            blob,
        });
        self.memo
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(node_id.to_string(), Arc::clone(&payload));
        payload
    }
}

impl PayloadSource for FleetPayloads {
    fn generation(&self) -> u64 {
        self.generation
    }

    fn fleet_hash(&self) -> String {
        self.fleet_hash.clone()
    }

    fn payload_for(&self, node_id: &str) -> ConfigPayload {
        (*self.cut(node_id)).clone()
    }

    fn expected_version_for(&self, node_id: &str) -> ConfigVersion {
        self.cut(node_id).version()
    }
}

/// Replicate to the fleet after every local configuration mutation
/// (AC #3), driven by the same watch the local reload runs on.
///
/// The signal is a counter, not a queue: several mutations landing
/// while a round is in flight collapse into one round on the state
/// they all committed to, which is exactly the semantics wanted.
fn spawn_replication_watch(
    runtime: Arc<ControlPlaneRuntime>,
    store: Arc<Mutex<ConfigStore>>,
    mut reload: watch::Receiver<u64>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while reload.changed().await.is_ok() {
            replicate_after_reload(&runtime, &store).await;
        }
    })
}

/// Evaluate fleet drift every [`DRIFT_CHECK_INTERVAL`] (AC #12):
/// publish the drifted count as a gauge and raise one alert per node
/// whose suppression backoff has expired.
/// Whether the control plane holds a fanned-in `cluster.break_glass.open`
/// row for `node_id` inside the window a break-glass claim could still be
/// live ([`MAX_BREAK_GLASS_SECS`] plus one drain interval of slack).
///
/// A follower opens break-glass through its OWN management API, so the
/// only record the control plane can ever hold is the audit row that
/// follower fans in. A node that asserts the bit without ever sending the
/// row is either lagging by a drain cycle or lying, and the drift alert
/// says which of the two it cannot rule out (backlog #78).
async fn break_glass_is_corroborated(log_store: &Option<Arc<LogStore>>, node_id: &str) -> bool {
    let Some(log_store) = log_store.clone() else {
        return false;
    };
    let node_id = node_id.to_string();
    let from = (Utc::now()
        - chrono::Duration::seconds(MAX_BREAK_GLASS_SECS as i64 + DRAIN_SLACK_SECS))
    .to_rfc3339();
    tokio::task::spawn_blocking(move || {
        let query = lorica_api::audit::AuditQuery {
            action_prefix: Some("cluster.break_glass.open".to_string()),
            from: Some(from),
            limit: 1,
            node_id: Some(node_id),
            ..Default::default()
        };
        matches!(log_store.query_audit(&query), Ok((rows, _)) if !rows.is_empty())
    })
    .await
    .unwrap_or(false)
}

fn spawn_drift_watch(
    runtime: Arc<ControlPlaneRuntime>,
    store: Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<LogStore>>,
    alert_sender: AlertSender,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // The one task entitled to advance the alert backoff. Claimed
        // before the loop: if something else already holds it, this
        // process would be alerting twice on one budget, which is a
        // wiring bug and not a condition to paper over at runtime.
        let Some(alerter) = runtime.claim_drift_alerter() else {
            error!("drift alerter already claimed; this watch task will not run");
            return;
        };
        loop {
            tokio::time::sleep(DRIFT_CHECK_INTERVAL).await;
            let report = match lorica_api::cluster::runtime::drift_report(&runtime, &store).await {
                Ok(report) => report,
                Err(e) => {
                    error!(error = %e, "cluster drift evaluation failed");
                    continue;
                }
            };
            lorica_api::metrics::set_cluster_drift_nodes(report.drifted.len());
            let ids: Vec<String> = report.drifted.iter().map(|d| d.node_id.clone()).collect();
            for node_id in alerter.due(&ids, Utc::now()) {
                let Some(entry) = report.drifted.iter().find(|d| d.node_id == node_id) else {
                    continue;
                };
                // A node in break-glass is drifted BY DESIGN: the
                // operator opened the window. Say so instead of paging
                // as if it were a fault, but only when the control plane
                // holds the follower's own `cluster.break_glass.open`
                // row: the bit rides the heartbeat and a compromised
                // node could otherwise keep itself out of every commit
                // round and have the drift paged as operator action
                // (backlog #78).
                let corroborated =
                    entry.break_glass && break_glass_is_corroborated(&log_store, &node_id).await;
                let summary = if entry.break_glass && corroborated {
                    format!(
                        "cluster node {} ({}) is in break-glass and diverges from generation {}",
                        entry.name, node_id, report.current_generation
                    )
                } else if entry.break_glass {
                    format!(
                        "cluster node {} ({}) claims break-glass and diverges from generation \
                         {}, and no break-glass audit row from that node has reached the control \
                         plane: treat the claim as unverified",
                        entry.name, node_id, report.current_generation
                    )
                } else {
                    format!(
                        "cluster node {} ({}) applied generation {} while the control plane is \
                         at {}",
                        entry.name, node_id, entry.applied_generation, report.current_generation
                    )
                };
                alert_sender.send(
                    AlertEvent::new(AlertType::ClusterDrift, summary)
                        .with_detail("node_id", node_id.clone())
                        .with_detail("node_name", entry.name.clone())
                        .with_detail("applied_generation", entry.applied_generation.to_string())
                        .with_detail("current_generation", report.current_generation.to_string())
                        .with_detail("connected", entry.connected.to_string())
                        .with_detail("break_glass", entry.break_glass.to_string())
                        .with_detail("break_glass_corroborated", corroborated.to_string())
                        .with_detail(
                            "age_s",
                            entry.age_s.map(|a| a.to_string()).unwrap_or_default(),
                        ),
                );
            }
        }
    })
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
                    // Story 9.4: the generation each node reports is
                    // persisted here too, so the drift view survives a
                    // control-plane restart and a disconnected node
                    // still has a last-known applied version.
                    applied_config_generation: i64::try_from(s.applied.generation)
                        .unwrap_or(i64::MAX),
                    applied_config_hash: s.applied.hash,
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
    seed_accepted_config(&control, store).await?;
    let telemetry = match ClusterTelemetryStore::open(&opts.data_dir) {
        Ok(store) => Some(Arc::new(store)),
        Err(e) => {
            error!(error = %e, "could not open the cluster telemetry database; fan-in is refused and the fleet log endpoints report it");
            None
        }
    };
    // One store, shared: the rows an operator reads through the API
    // must be the rows the listener's ingest handler wrote.
    let runtime = Arc::new(ControlPlaneRuntime::with_telemetry(
        Arc::clone(&control),
        telemetry.clone(),
    ));
    let drift_alerts = opts.alert_sender.clone();
    let drift_log_store = opts.log_store.clone();
    let replication_reload = opts.config_reload.subscribe();
    let handlers = Arc::new(FleetHandlers {
        control: Arc::clone(&control),
        store: Arc::clone(store),
        log_store: opts.log_store,
        alert_sender: opts.alert_sender,
        renewals: StdMutex::new(HashMap::new()),
        telemetry,
        quota: IngestQuota::new(),
        data_dir: opts.data_dir.clone(),
        config_reload: opts.config_reload.clone(),
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
    // Story 9.4 AC #7: the HelloAck and every HeartbeatAck advertise
    // the version below, so a follower that is behind pulls instead of
    // drifting. One slot shared with the control-plane handle, swapped
    // by the coordinator after each round.
    operational_config.accepted = Arc::new(control.accepted.clone());
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
        spawn_drift_watch(
            Arc::clone(&runtime),
            Arc::clone(store),
            drift_log_store,
            drift_alerts,
        ),
        spawn_replication_watch(Arc::clone(&runtime), Arc::clone(store), replication_reload),
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
    // Backlog #58: eviction streaks, quarantine and the last round live
    // in this process. A restart or a hot upgrade therefore releases every
    // quarantined node and forgets a fleet that converged weeks ago. That
    // is the intended circuit-breaker behaviour, a restart being a fair
    // reason to re-probe, but an operator who quarantined a node yesterday
    // must not have to infer the release from silence.
    warn!(
        enrolled_nodes = control.roster.len(),
        "cluster plane: replication policy state starts empty (eviction \
         streaks, quarantine, last round). Any node quarantined before \
         this restart is released and will be probed again"
    );
    if opts.auto_activate {
        warn!("cluster plane: --cluster-auto-activate is set; enrolled nodes become Active without operator review");
    }

    Ok(Some(ClusterPlane {
        operational,
        enrollment,
        runtime,
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
    use lorica_cluster::messages::{ClusterResponse, ConfigCommitAck, ConfigPrepareAck};
    use lorica_cluster::{ClusterFrame, NodeIdentity, NodeState, SessionGuard};
    use lorica_command::RpcEndpoint;
    use lorica_config::models::{JoinToken, TokenState};

    fn test_control(auto_activate: bool) -> Arc<ControlPlane> {
        let _ = lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider()
            .install_default();
        let ca = ClusterCa::generate("Test CA").expect("ca");
        let (leaf, key) = ca.issue_server_leaf("cp.internal").expect("leaf");
        let config =
            lorica_cluster::operational_server_config(ca.cert_pem(), &leaf, &key).expect("config");
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

    #[test]
    fn renewal_timing_contract_holds_across_both_sides() {
        // A follower asking at its latest lead must land inside the
        // control plane's accept window, and a refused follower must
        // wait at least the cooldown before asking again.
        assert!(RENEWAL_ACCEPT_WINDOW > chrono::Duration::days(RENEWAL_LEAD_MAX_DAYS));
        assert!(
            chrono::Duration::days(RENEWAL_LEAD_MIN_DAYS)
                < chrono::Duration::days(RENEWAL_LEAD_MAX_DAYS)
        );
        assert!(RENEWAL_RETRY_AFTER_REFUSAL >= RENEWAL_COOLDOWN);
        assert!(RENEWAL_CHECK_INTERVAL < RENEWAL_COOLDOWN);
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
            minted_request(
                &s,
                &control,
                "192.0.2.10:5000",
                "edge-1",
                Some("edge-1"),
                None,
            )
        };
        let replay = request.clone();
        let grant = redeem_with_store(&store, &control, request, Utc::now())
            .await
            .expect("redeemed");
        assert_eq!(grant.status, "pending");
        assert_eq!(grant.ca_pem, control.ca_pem());
        {
            let s = store.lock().await;
            let node = s
                .get_cluster_node(&grant.node_id)
                .expect("read")
                .expect("row");
            assert_eq!(node.status, NodeStatus::Pending);
            assert_eq!(node.name, "edge-1");
            let tok = s.get_join_token(&public_id).expect("read").expect("row");
            assert_eq!(tok.state, TokenState::Burned);
            assert_eq!(
                tok.burned_by_node_id.as_deref(),
                Some(grant.node_id.as_str())
            );
        }
        // Replay of the same token is refused, and refused the same
        // way as an unknown one.
        let replayed = redeem_with_store(&store, &control, replay, Utc::now()).await;
        assert!(matches!(replayed, Err(EnrollRefusal::Refused(_))));

        let auto = test_control(true);
        let (request, _) = {
            let s = store.lock().await;
            minted_request(&s, &auto, "192.0.2.11:5000", "edge-2", Some("edge-2"), None)
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
    async fn a_token_with_no_name_binding_is_refused_rather_than_accepting_any_name() {
        // Story 9.5 D15. `bound_node_name` existed before this story
        // and was optional, so an unbound token meant "any name the
        // joiner picks". A route `node_selector` matches on that name
        // and decides which private keys the node receives, so an
        // unbound token is an entitlement the operator never granted.
        // It now fails closed instead.
        let store = store_with_key();
        let control = test_control(false);
        let (request, public_id) = {
            let s = store.lock().await;
            minted_request(&s, &control, "192.0.2.10:5000", "edge-1", None, None)
        };
        assert!(
            matches!(
                redeem_with_store(&store, &control, request, Utc::now()).await,
                Err(EnrollRefusal::Refused(_))
            ),
            "an unbound token must not enrol anything"
        );
        let s = store.lock().await;
        assert!(
            s.list_cluster_nodes().expect("list").is_empty(),
            "nothing is enrolled by a refused redemption"
        );
        assert_eq!(
            s.get_join_token(&public_id)
                .expect("read")
                .expect("row")
                .state,
            TokenState::Unused,
            "the refusal happens before the burn, so a corrected mint is not needed"
        );
    }

    #[tokio::test]
    async fn a_name_that_does_not_match_the_binding_is_refused() {
        let store = store_with_key();
        let control = test_control(false);
        let (mut request, _) = {
            let s = store.lock().await;
            minted_request(
                &s,
                &control,
                "192.0.2.10:5000",
                "edge-1",
                Some("edge-1"),
                None,
            )
        };
        request.node_name = "edge-2".to_string();
        assert!(matches!(
            redeem_with_store(&store, &control, request, Utc::now()).await,
            Err(EnrollRefusal::Refused(_))
        ));
    }

    #[tokio::test]
    async fn three_simultaneous_redemptions_of_one_token_enroll_one_node() {
        let store = store_with_key();
        let control = test_control(false);
        let (request, _) = {
            let s = store.lock().await;
            minted_request(
                &s,
                &control,
                "192.0.2.10:5000",
                "edge-1",
                Some("edge-1"),
                None,
            )
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
    /// One fanned-in audit row, for the break-glass corroboration test.
    fn fanned_in_row(action: &str, origin_id: i64) -> lorica_api::audit::FannedInAuditRow {
        lorica_api::audit::FannedInAuditRow {
            origin_id,
            timestamp: Utc::now().to_rfc3339(),
            operator_username: "admin".into(),
            operator_role: "super_admin".into(),
            action: action.into(),
            target_type: "cluster_node".into(),
            target_id: "edge-01".into(),
            before_payload_hash: String::new(),
            after_payload_hash: String::new(),
            ip: "192.0.2.10".into(),
            user_agent: "e2e".into(),
            prev_chain_hash: String::new(),
            chain_hash: "0".repeat(64),
        }
    }

    #[tokio::test]
    async fn break_glass_is_corroborated_only_by_that_node_s_own_audit_row() {
        // Backlog #78: the drift alert used to soften on the peer-supplied
        // bit alone, so a compromised follower could keep itself out of every
        // commit round and have the drift paged as operator action.
        // A plain unique directory: `lorica` does not depend on tempfile.
        let dir = std::env::temp_dir().join(format!(
            "lorica-break-glass-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log_store = Arc::new(LogStore::open(&dir).expect("log store"));

        // Nothing fanned in yet: a claim cannot be corroborated.
        assert!(!break_glass_is_corroborated(&Some(Arc::clone(&log_store)), "node-a").await);
        // No log store at all is not corroboration either.
        assert!(!break_glass_is_corroborated(&None, "node-a").await);

        // A different node's window says nothing about this one.
        log_store
            .insert_fanned_in_audit("node-b", &[fanned_in_row("cluster.break_glass.open", 1)])
            .expect("insert node-b");
        assert!(!break_glass_is_corroborated(&Some(Arc::clone(&log_store)), "node-a").await);

        // A different action from this node says nothing either.
        log_store
            .insert_fanned_in_audit("node-a", &[fanned_in_row("cluster.leave", 1)])
            .expect("insert wrong action");
        assert!(!break_glass_is_corroborated(&Some(Arc::clone(&log_store)), "node-a").await);

        // This node's own open row corroborates it.
        log_store
            .insert_fanned_in_audit("node-a", &[fanned_in_row("cluster.break_glass.open", 2)])
            .expect("insert node-a");
        assert!(break_glass_is_corroborated(&Some(Arc::clone(&log_store)), "node-a").await);

        drop(log_store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // Story 10.0 follow-up: the roster is part of the fleet's identity
    // -----------------------------------------------------------------

    /// A route carrying only the fields that have no serde default,
    /// plus the selector under test. Spelling out all seventy-odd of
    /// `Route`'s fields in a test that cares about one of them would
    /// bury what it asserts.
    fn route_selected_for(
        id: &str,
        hostname: &str,
        selector: &[&str],
    ) -> lorica_config::models::Route {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": hostname,
            "path_prefix": "/",
            "certificate_id": null,
            "load_balancing": "round_robin",
            "waf_enabled": false,
            "waf_mode": "detection",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "node_selector": selector,
        }))
        .expect("test setup: route")
    }

    /// A registry row, which is all a selector resolution reads: the
    /// name and the id.
    fn roster_row(node_id: &str, name: &str) -> ClusterNode {
        let now = Utc::now();
        ClusterNode {
            node_id: node_id.to_string(),
            name: name.to_string(),
            cert_fingerprint: format!("fp-{node_id}"),
            cert_serial: format!("serial-{node_id}"),
            prev_cert_fingerprint: None,
            prev_cert_serial: None,
            address: "192.0.2.10:9443".to_string(),
            version: "test".to_string(),
            schema_version: 50,
            status: NodeStatus::Active,
            enrolled_at: now,
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: now + chrono::Duration::days(30),
            revoked_at: None,
        }
    }

    async fn add_route(store: &Arc<Mutex<ConfigStore>>, id: &str, selector: &[&str]) {
        let s = store.lock().await;
        s.create_route(&route_selected_for(
            id,
            &format!("{id}.example.com"),
            selector,
        ))
        .expect("test setup: route");
    }

    async fn add_node(store: &Arc<Mutex<ConfigStore>>, node_id: &str, name: &str) {
        let s = store.lock().await;
        s.create_cluster_node(&roster_row(node_id, name))
            .expect("test setup: node");
    }

    #[tokio::test]
    async fn a_roster_change_alone_runs_a_round_and_an_unchanged_fleet_runs_none() {
        let store = store_with_key();
        let control = test_control(false);
        let runtime = Arc::new(ControlPlaneRuntime::new(Arc::clone(&control)));
        assert_eq!(
            seed_accepted_config(&control, &store).await.expect("seed"),
            0
        );

        // Nothing changed: no generation, no round.
        replicate_after_reload(&runtime, &store).await;
        assert_eq!(control.config_version().generation, 0);
        assert!(
            control.replication.last_report().is_none(),
            "an unchanged fleet must not be made to run a round"
        );

        // A configuration change with an unchanged roster: one round.
        add_route(&store, "route-a", &["edge-a"]).await;
        replicate_after_reload(&runtime, &store).await;
        assert_eq!(control.config_version().generation, 1);
        assert_eq!(
            control.replication.last_report().map(|r| r.generation),
            Some(1)
        );

        // A ROSTER change with an unchanged configuration: also one
        // round. Not one byte of the blob moves, but "edge-a" resolves
        // to a node now, so the cut of route-a changes for everyone.
        add_node(&store, "id-a", "edge-a").await;
        replicate_after_reload(&runtime, &store).await;
        assert_eq!(
            control.config_version().generation,
            2,
            "a roster change that can change a cut IS a configuration change"
        );
        assert_eq!(
            control.replication.last_report().map(|r| r.generation),
            Some(2)
        );

        // And nothing again is nothing again.
        replicate_after_reload(&runtime, &store).await;
        assert_eq!(control.config_version().generation, 2);
        assert_eq!(
            control.replication.last_report().map(|r| r.generation),
            Some(2)
        );
    }

    #[tokio::test]
    async fn the_boot_seed_bumps_only_when_a_change_landed_without_a_round() {
        let store = store_with_key();
        let control = test_control(false);
        let runtime = Arc::new(ControlPlaneRuntime::new(Arc::clone(&control)));
        seed_accepted_config(&control, &store).await.expect("seed");
        add_route(&store, "route-a", &["edge-a"]).await;
        replicate_after_reload(&runtime, &store).await;
        assert_eq!(control.config_version().generation, 1);

        // A restart with nothing moved under the generation: the seed
        // is faithful, so it publishes the stored generation unchanged
        // and no node reads as drifted.
        let restarted = test_control(false);
        assert_eq!(
            seed_accepted_config(&restarted, &store)
                .await
                .expect("seed"),
            1
        );

        // A roster row written with no round behind it: the shape a
        // crash between the registry write and the round leaves.
        add_node(&store, "id-a", "edge-a").await;
        let crashed = test_control(false);
        assert_eq!(
            seed_accepted_config(&crashed, &store).await.expect("seed"),
            2,
            "a change the fleet was never told about owes a round"
        );

        // The repair is recorded, so the boot after it is faithful
        // again rather than bumping on every start.
        let again = test_control(false);
        assert_eq!(seed_accepted_config(&again, &store).await.expect("seed"), 2);
    }

    /// The production `PayloadSource` against the canonical filter it
    /// is supposed to implement.
    ///
    /// The `lorica-cluster` suite asserts the round's contract against
    /// a hand-written double, which can only prove the double
    /// consistent with itself. This drives the real `Replicator` over
    /// a real `FleetPayloads` built from a real store, and checks the
    /// hash each node is OFFERED against `restrict_for_recipient`, so
    /// the two cannot diverge silently.
    #[tokio::test]
    async fn each_node_is_offered_the_hash_of_its_own_restricted_cut() {
        let store = store_with_key();
        let control = test_control(false);
        let runtime = Arc::new(ControlPlaneRuntime::new(Arc::clone(&control)));
        add_node(&store, "id-a", "edge-a").await;
        add_node(&store, "id-b", "edge-b").await;
        add_route(&store, "pinned", &["edge-a"]).await;
        add_route(&store, "fleetwide", &[]).await;
        seed_accepted_config(&control, &store).await.expect("seed");

        // Two live sessions, so the round addresses both and the
        // report carries what each one was offered.
        let a = spawn_scripted_follower(&control, "id-a");
        let b = spawn_scripted_follower(&control, "id-b");
        add_route(&store, "later", &["edge-b"]).await;
        replicate_after_reload(&runtime, &store).await;
        let report = control.replication.last_report().expect("a round ran");
        assert!(!report.aborted, "nothing rejected: {report:?}");
        assert_eq!(report.committed, vec!["id-a", "id-b"]);

        let (cfg, nodes) = {
            let s = store.lock().await;
            (
                lorica_config::canonical::canonical_config(&s).expect("canonical"),
                node_rows(&s).expect("rows"),
            )
        };
        let resolution = SelectorResolution::from_rows(nodes.iter().cloned());
        let offered: HashMap<String, String> = report.offered.into_iter().collect();
        for node_id in ["id-a", "id-b"] {
            let cut = restrict_for_recipient(&cfg, node_id, &resolution);
            let expected = lorica_config::canonical::sha256_hex(
                &lorica_config::canonical::encode_canonical(&cut).expect("encode"),
            );
            assert_eq!(
                offered.get(node_id),
                Some(&expected),
                "{node_id} was offered a blob the canonical filter does not produce"
            );
            assert_eq!(control.expected_config_version(node_id).hash, expected);
            assert_eq!(
                control
                    .accepted
                    .payload_for(node_id)
                    .expect("published")
                    .hash,
                expected
            );
        }
        assert_ne!(
            control.expected_config_version("id-a").hash,
            control.expected_config_version("id-b").hash,
            "each node is selected for a route the other is not"
        );
        assert_ne!(
            control.config_version().hash,
            control.expected_config_version("id-a").hash,
            "the fleet identity is not any recipient's cut"
        );
        drop((a, b));
    }

    /// A follower that stages and applies whatever it is sent, over an
    /// in-process duplex. Enough for a round to complete: what these
    /// assertions are about is what was OFFERED, not what a real node
    /// does with it.
    fn spawn_scripted_follower(
        control: &Arc<ControlPlane>,
        node_id: &str,
    ) -> (SessionGuard, RpcEndpoint<ClusterFrame>) {
        use lorica_cluster::messages::{cluster_request, cluster_response};
        let (cp_side, follower_side) = tokio::io::duplex(1024 * 1024);
        let (cp_endpoint, _cp_incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(cp_side, lorica_cluster::cluster_rpc_limits());
        let (follower_endpoint, mut incoming) = RpcEndpoint::<ClusterFrame>::with_limits(
            follower_side,
            lorica_cluster::cluster_rpc_limits(),
        );
        let identity = NodeIdentity {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            state: NodeState::Active,
            via_previous_certificate: false,
        };
        let peer: SocketAddr = "192.0.2.10:9443".parse().expect("test setup: peer");
        let guard = control.sessions.register(
            &identity,
            peer,
            cp_endpoint,
            "test",
            50,
            AppliedConfig::default(),
        );
        tokio::spawn(async move {
            let mut staged: Option<(u64, String)> = None;
            while let Some(request) = incoming.recv().await {
                let reply = match &request.request().body {
                    Some(cluster_request::Body::ConfigPrepare(prepare)) => {
                        staged = Some((prepare.generation, prepare.hash.clone()));
                        ClusterResponse::ok(cluster_response::Body::ConfigPrepareAck(
                            ConfigPrepareAck {
                                accepted: true,
                                reason: String::new(),
                            },
                        ))
                    }
                    Some(cluster_request::Body::ConfigCommit(commit)) => {
                        let (generation, hash) =
                            staged.clone().unwrap_or((commit.generation, String::new()));
                        ClusterResponse::ok(cluster_response::Body::ConfigCommitAck(
                            ConfigCommitAck {
                                applied_generation: generation,
                                applied_hash: hash,
                            },
                        ))
                    }
                    _ => ClusterResponse::refusal(lorica_cluster::ClusterStatus::UnsupportedMethod),
                };
                if request.reply_frame(reply).await.is_err() {
                    return;
                }
            }
        });
        (guard, follower_endpoint)
    }
}
