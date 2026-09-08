//! The fleet runtime layer (Story 9.3): what this process is in the
//! fleet, and the rule "the store is the truth; the roster, the
//! fleet-size hint and the CRL-backed acceptor are derived from it".
//!
//! No HTTP here. The control-plane binary and the API handlers both
//! act through these functions, so a mutation always goes store
//! first, then one serialized refresh, then the session registry.
//! Failures are typed ([`ClusterRuntimeError`]) so a caller can tell
//! "the store is unavailable" from "the acceptor could not be
//! rebuilt" without parsing a message.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use lorica_cluster::{
    AppliedConfig, CertBundle, ClusterConnection, ClusterTlsError, ConfigVersion, ControlPlane,
    NodeIdentity, NodeState, RevokedEntry,
};
use lorica_config::models::{ClusterNode, NodeStatus};
use lorica_config::{ConfigError, ConfigStore};
use serde::Serialize;
use tokio::sync::{watch, Mutex};

use crate::error::ApiError;

/// Why a fleet runtime operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ClusterRuntimeError {
    /// The configuration store refused or failed the read or write.
    #[error("cluster registry: {0}")]
    Store(#[from] ConfigError),
    /// The store task could not be joined (the blocking pool is gone).
    #[error("cluster registry: {0}")]
    StoreTask(String),
    /// The CRL could not be minted or the operational TLS acceptor
    /// could not be rebuilt over it; the roster was still swapped.
    #[error("acceptor rebuild: {0}")]
    Acceptor(#[from] ClusterTlsError),
}

impl From<ClusterRuntimeError> for ApiError {
    fn from(err: ClusterRuntimeError) -> Self {
        match err {
            ClusterRuntimeError::Store(inner) => inner.into(),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

/// Run a pure-store closure and keep its error typed: `db_blocking`
/// collapses everything into `ApiError`, which this layer must not
/// name on its way out.
async fn store_op<T, F>(
    store: &Arc<Mutex<ConfigStore>>,
    f: F,
) -> Result<T, ClusterRuntimeError>
where
    F: FnOnce(&mut ConfigStore) -> Result<T, ConfigError> + Send + 'static,
    T: Send + 'static,
{
    let mut guard = Arc::clone(store).lock_owned().await;
    tokio::task::spawn_blocking(move || f(&mut guard))
        .await
        .map_err(|e| ClusterRuntimeError::StoreTask(format!("store task join failed: {e}")))?
        .map_err(ClusterRuntimeError::Store)
}

/// What this process is in the fleet, as the API sees it.
#[derive(Clone)]
pub enum ClusterRuntime {
    /// No cluster role (the default install).
    Standalone,
    /// This process serves the cluster plane.
    ControlPlane(Arc<ControlPlaneRuntime>),
    /// This process dials a control plane.
    Follower(Arc<FollowerRuntime>),
}

/// The control-plane side's live handles: the transport crate's
/// [`ControlPlane`] plus what only the API and the binary track
/// (drift first-seen times and the per-node alert backoff, Story 9.4
/// AC #12).
pub struct ControlPlaneRuntime {
    /// The fleet runtime shared with the listeners.
    pub control: Arc<ControlPlane>,
    /// Drift bookkeeping.
    pub drift: DriftTracker,
}

impl ControlPlaneRuntime {
    /// Bundle a control plane with fresh drift bookkeeping.
    pub fn new(control: Arc<ControlPlane>) -> Self {
        Self {
            control,
            drift: DriftTracker::default(),
        }
    }
}

/// The follower side's live handles.
pub struct FollowerRuntime {
    /// This node's server-assigned id.
    pub node_id: String,
    /// This node's display name.
    pub node_name: String,
    /// The control plane's `host:port`.
    pub control_plane: String,
    /// The dialer's connection slot.
    pub connection: ClusterConnection,
    /// Flipped to `true` by `POST /api/v1/cluster/leave`; the follower
    /// runtime stops dialing when it sees it.
    pub left: watch::Sender<bool>,
    /// What this node currently runs (generation, hash, break-glass),
    /// shared with the replica handler that updates it.
    pub applied: Arc<StdMutex<AppliedConfig>>,
    /// The break-glass window's end (Story 9.4 AC #11), `None` when
    /// closed; the follower runtime watches it to reconcile when it
    /// closes.
    pub break_glass: watch::Sender<Option<DateTime<Utc>>>,
}

impl FollowerRuntime {
    /// The break-glass window's end, when one is open now.
    pub fn break_glass_until(&self) -> Option<DateTime<Utc>> {
        (*self.break_glass.borrow()).filter(|until| *until > Utc::now())
    }

    /// Whether local mutations are allowed right now (AC #10/#11).
    pub fn break_glass_active(&self) -> bool {
        self.break_glass_until().is_some()
    }

    /// What this node currently runs.
    pub fn applied(&self) -> AppliedConfig {
        self.applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// Longest break-glass window an operator may open (AC #11).
pub const MAX_BREAK_GLASS_SECS: u64 = 24 * 3600;

/// First suppression interval after a drift alert fires for a node;
/// doubles on every further alert up to [`DRIFT_BACKOFF_MAX`].
pub const DRIFT_BACKOFF_MIN: Duration = Duration::from_secs(60);
/// Cap on the per-node drift alert suppression.
pub const DRIFT_BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Per-node drift bookkeeping (AC #12): when a divergence was first
/// observed (its age in the report) and the exponential backoff that
/// keeps a flapping node from consuming the dispatcher's global
/// per-channel budget.
#[derive(Default)]
pub struct DriftTracker {
    first_seen: StdMutex<HashMap<String, DateTime<Utc>>>,
    backoff: StdMutex<HashMap<String, (Instant, Duration)>>,
}

impl DriftTracker {
    /// Record the set of drifted node ids observed now. Returns the
    /// ids whose alert is due (first observation, or the backoff
    /// expired); nodes back in sync are forgotten so their next drift
    /// starts from the shortest interval again.
    pub fn observe(&self, drifted: &[String], now: DateTime<Utc>) -> Vec<String> {
        let mut first_seen = self.first_seen.lock().unwrap_or_else(|p| p.into_inner());
        let mut backoff = self.backoff.lock().unwrap_or_else(|p| p.into_inner());
        first_seen.retain(|id, _| drifted.contains(id));
        // The suppression interval is kept, not dropped, when a node
        // returns to sync: a node that alternates in and out of sync
        // would otherwise restart at the shortest interval every time
        // and produce one alert per cycle forever. It expires on its
        // own once the node has been quiet longer than its current
        // interval, which is what "back to normal" should mean.
        let instant_now = Instant::now();
        backoff.retain(|id, (next_allowed, _)| {
            drifted.contains(id) || instant_now < *next_allowed
        });
        let mut due = Vec::new();
        for id in drifted {
            first_seen.entry(id.clone()).or_insert(now);
            let fire = match backoff.get(id) {
                Some((next_allowed, _)) => instant_now >= *next_allowed,
                None => true,
            };
            if fire {
                let interval = backoff
                    .get(id)
                    .map(|(_, last)| (*last * 2).min(DRIFT_BACKOFF_MAX))
                    .unwrap_or(DRIFT_BACKOFF_MIN);
                backoff.insert(id.clone(), (instant_now + interval, interval));
                due.push(id.clone());
            }
        }
        due
    }

    /// Record first-seen times for `drifted` (and forget nodes that
    /// are back in sync) without touching the alert backoff.
    pub fn record_first_seen(&self, drifted: &[String], now: DateTime<Utc>) {
        let mut first_seen = self.first_seen.lock().unwrap_or_else(|p| p.into_inner());
        first_seen.retain(|id, _| drifted.contains(id));
        for id in drifted {
            first_seen.entry(id.clone()).or_insert(now);
        }
    }

    /// When `node_id`'s current divergence was first observed.
    pub fn since(&self, node_id: &str) -> Option<DateTime<Utc>> {
        self.first_seen
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(node_id)
            .copied()
    }
}

/// One drifted node in [`DriftReport`].
#[derive(Debug, Clone, Serialize)]
pub struct DriftEntry {
    /// The node id.
    pub node_id: String,
    /// Display name.
    pub name: String,
    /// Lifecycle state.
    pub status: NodeStatus,
    /// Whether the node holds a session right now.
    pub connected: bool,
    /// The generation the node last reported applying.
    pub applied_generation: u64,
    /// The hash the node last reported applying.
    pub applied_hash: String,
    /// Whether the node is in a break-glass window (local edits).
    pub break_glass: bool,
    /// Whether the coordinator quarantined the node (slow Prepare).
    pub quarantined: bool,
    /// When the divergence was first observed, RFC 3339.
    pub since: Option<String>,
    /// Age of the divergence in seconds.
    pub age_s: Option<i64>,
}

/// Payload of `GET /api/v1/cluster/drift` (AC #12).
#[derive(Debug, Clone, Serialize)]
pub struct DriftReport {
    /// The control plane's current generation.
    pub current_generation: u64,
    /// The control plane's current canonical hash.
    pub current_hash: String,
    /// Active nodes whose applied generation or hash differs.
    pub drifted: Vec<DriftEntry>,
    /// Active nodes in sync.
    pub in_sync: usize,
    /// Nodes the coordinator excludes from commit sets.
    pub quarantined: Vec<String>,
}

/// Wrap a stored certificate for the wire (Story 9.5), stamping the
/// same digest shape the canonical blob carries so a receiver can tie
/// the key to the configuration that announced it.
pub fn cert_bundle(cert: &lorica_config::models::Certificate) -> CertBundle {
    CertBundle {
        cert_id: cert.id.clone(),
        domain: cert.domain.clone(),
        cert_pem: cert.cert_pem.clone(),
        key_pem: cert.key_pem.clone(),
        // The ONE function that owns this format, shared with the
        // canonical blob. A second expression of it here would drift.
        key_digest: lorica_config::canonical::secret_digest(&cert.key_pem),
    }
}

/// Push a certificate's key to the nodes entitled to it (Story 9.5
/// AC #7).
///
/// Best effort by decision D2, and that is the whole design: this is
/// the latency optimisation, not the guarantee. A node that is down,
/// slow or not yet connected is simply absent from the round and asks
/// for what it lacks after its next configuration apply. So every
/// failure here is counted and logged, and none of them fails the
/// issuance that triggered it.
///
/// Does nothing on a node that is not a control plane, which is what
/// makes it safe to call unconditionally from the issuance paths.
pub async fn distribute_certificate(
    cluster: &ClusterRuntime,
    store: &Arc<Mutex<ConfigStore>>,
    cert_id: &str,
) {
    let ClusterRuntime::ControlPlane(runtime) = cluster else {
        return;
    };
    let id = cert_id.to_string();
    let resolved = store_op(store, move |store| {
        let recipients = store.cert_key_recipients(&id)?;
        let cert = store.get_certificate(&id)?;
        Ok((recipients, cert))
    })
    .await;
    let (recipients, cert) = match resolved {
        Ok(resolved) => resolved,
        Err(e) => {
            tracing::error!(cert_id, error = %e,
                "could not resolve certificate recipients; the fleet converges by pull");
            return;
        }
    };
    // Three ways to have nothing to push, told apart because they mean
    // very different things to an operator watching an issuance.
    let Some(cert) = cert else {
        tracing::warn!(cert_id, "certificate vanished between issuance and distribution");
        return;
    };
    if cert.key_pem.is_empty() {
        tracing::error!(cert_id,
            "certificate carries no private key; nothing to distribute");
        return;
    }
    if recipients.is_empty() {
        tracing::info!(cert_id, domain = %cert.domain,
            "no node is selected for this certificate; nothing to distribute");
        return;
    }
    let report = runtime
        .control
        .distribute_certificates(&recipients, vec![cert_bundle(&cert)])
        .await;
    for (node_id, count) in &report.installed {
        crate::metrics::inc_cluster_cert_push_by(node_id, "pushed", *count);
        tracing::info!(node_id, cert_id, installed = count, "certificate key pushed");
    }
    for (node_id, reason) in &report.failed {
        // One certificate went into this round, so one certificate is
        // what failed to reach the node.
        crate::metrics::inc_cluster_cert_push(node_id, "push_failed");
        tracing::warn!(node_id, cert_id, %reason,
            "certificate push failed; the node asks for it after its next apply");
    }
}

/// Compute the drift view (AC #12): every `Active` node compared to
/// the current version, the live session's report when the node is
/// connected, the registry row's persisted `applied_config_*` columns
/// otherwise. Records first-seen times in the tracker.
pub async fn drift_report(
    runtime: &ControlPlaneRuntime,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<DriftReport, ClusterRuntimeError> {
    let nodes = store_op(store, |store| store.list_cluster_nodes()).await?;
    let current: ConfigVersion = runtime.control.config_version();
    let live: HashMap<String, (AppliedConfig, bool)> = runtime
        .control
        .sessions
        .snapshot()
        .into_iter()
        .map(|s| (s.node_id, (s.applied, true)))
        .collect();
    let quarantined = runtime.control.replication.quarantined();
    let mut drifted = Vec::new();
    let mut in_sync = 0usize;
    for node in nodes.into_iter().filter(|n| n.status == NodeStatus::Active) {
        let (applied, connected) = live.get(&node.node_id).cloned().unwrap_or_else(|| {
            (
                AppliedConfig {
                    generation: u64::try_from(node.applied_config_generation).unwrap_or(0),
                    hash: node.applied_config_hash.clone(),
                    break_glass: false,
                },
                false,
            )
        });
        if applied.generation == current.generation && applied.hash == current.hash {
            in_sync += 1;
            continue;
        }
        drifted.push(DriftEntry {
            quarantined: quarantined.contains(&node.node_id),
            node_id: node.node_id,
            name: node.name,
            status: node.status,
            connected,
            applied_generation: applied.generation,
            applied_hash: applied.hash,
            break_glass: applied.break_glass,
            since: None,
            age_s: None,
        });
    }
    let now = Utc::now();
    let ids: Vec<String> = drifted.iter().map(|d| d.node_id.clone()).collect();
    // Observe without firing: the alert decision belongs to the
    // periodic evaluation in the binary, which calls `observe` itself
    // and honours its return value. Here only the first-seen times
    // are needed, and `since` is read back after recording.
    runtime.drift.record_first_seen(&ids, now);
    for entry in &mut drifted {
        entry.since = runtime.drift.since(&entry.node_id).map(|t| t.to_rfc3339());
        entry.age_s = runtime
            .drift
            .since(&entry.node_id)
            .map(|t| (now - t).num_seconds().max(0));
    }
    Ok(DriftReport {
        current_generation: current.generation,
        current_hash: current.hash,
        drifted,
        in_sync,
        quarantined,
    })
}

impl ClusterRuntime {
    /// `snake_case` role name for responses.
    pub fn role_name(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::ControlPlane(_) => "control_plane",
            Self::Follower(_) => "follower",
        }
    }
}

/// Build the roster the transport crate consults from the registry:
/// one entry per current fingerprint, plus one flagged
/// `via_previous_certificate` for every superseded certificate still
/// in its grace window.
pub fn roster_from_nodes(nodes: &[ClusterNode]) -> HashMap<String, NodeIdentity> {
    let mut map = HashMap::with_capacity(nodes.len() * 2);
    for node in nodes {
        let state = match node.status {
            NodeStatus::Pending => NodeState::Pending,
            NodeStatus::Active => NodeState::Active,
            NodeStatus::Revoked => NodeState::Revoked,
        };
        map.insert(
            node.cert_fingerprint.clone(),
            NodeIdentity {
                node_id: node.node_id.clone(),
                name: node.name.clone(),
                state,
                via_previous_certificate: false,
            },
        );
        if let Some(prev) = &node.prev_cert_fingerprint {
            map.insert(
                prev.clone(),
                NodeIdentity {
                    node_id: node.node_id.clone(),
                    name: node.name.clone(),
                    state,
                    via_previous_certificate: true,
                },
            );
        }
    }
    map
}

/// Reload the roster, the fleet-size hint and the CRL-backed acceptor
/// from the store. Called after every registry mutation and at boot.
///
/// Serialized on the control plane's refresh guard across the read AND
/// the swaps: two refreshes racing could otherwise land a pre-revocation
/// snapshot after the revocation and silently reopen the door. The
/// acceptor is rebuilt only when the revoked-serial set changed, and
/// BEFORE the roster swap, so a revoked node fails TLS before its
/// roster entry flips. When the rebuild fails the roster is swapped
/// anyway (the revoked node then fails identity resolution instead of
/// TLS) and the error is returned.
pub async fn refresh_control_plane(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<(), ClusterRuntimeError> {
    let guard = control.refresh_guard().await;
    let now = Utc::now();
    let (nodes, revoked) = store_op(store, move |store| {
        let nodes = store.list_cluster_nodes()?;
        let revoked = store.list_cluster_revoked_serials(now)?;
        Ok((nodes, revoked))
    })
    .await?;
    let entries: Vec<RevokedEntry> = revoked
        .into_iter()
        .map(|r| RevokedEntry {
            serial_hex: r.serial,
            revoked_at: r.revoked_at,
            superseded: r.reason == "superseded",
        })
        .collect();
    let rebuilt = control.rebuild_acceptor(&guard, &entries);
    control.replace_roster(&guard, roster_from_nodes(&nodes));
    if rebuilt? {
        tracing::info!(
            revoked_serials = entries.len(),
            "cluster operational acceptor rebuilt over the current CRL"
        );
    } else {
        tracing::debug!("cluster refresh: revoked-serial set unchanged, acceptor kept");
    }
    Ok(())
}

/// Recount live tokens and publish the count to the enrollment
/// listener (opens or closes the window).
pub async fn publish_token_liveness(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<u32, ClusterRuntimeError> {
    let live = store_op(store, |store| store.count_live_join_tokens(Utc::now())).await?;
    control.publish_token_liveness(live);
    Ok(live)
}

/// Outcome of [`revoke_node`]: what changed, and whether the refresh
/// that followed held. The row flip and the session kill are facts
/// the caller must audit even when `refresh_error` is set.
#[derive(Debug)]
pub struct RevokeOutcome {
    /// The node as it was before this call (already `Revoked` on a
    /// retry).
    pub node: ClusterNode,
    /// Whether this call flipped the registry row (false on a retry).
    pub newly_revoked: bool,
    /// Whether a live session was ended.
    pub session_ended: bool,
    /// The roster/CRL refresh failure, if any: the revocation is
    /// recorded and the session is gone, but the acceptor may still
    /// admit the certificate until a retry succeeds.
    pub refresh_error: Option<ClusterRuntimeError>,
}

/// Revoke a node end to end (AC #7): registry row, CRL-backed
/// acceptor, live session. Idempotent: on an already-revoked node the
/// refresh and the kill run again, so an operator whose first attempt
/// failed half-way (acceptor rebuild error) can retry until every
/// step held. The session is ended even when the refresh fails: a
/// revoked node must not keep a session because the CRL could not be
/// rebuilt. `Ok(None)` when the node does not exist; the refresh
/// failure travels in the outcome so the caller audits what happened
/// before surfacing it.
pub async fn revoke_node(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
    node_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<RevokeOutcome>, ClusterRuntimeError> {
    let id = node_id.to_string();
    let before = store_op(store, move |store| {
        let Some(existing) = store.get_cluster_node(&id)? else {
            return Ok(None);
        };
        let flipped = store.revoke_cluster_node(&id, now)?;
        Ok(Some((existing, flipped.is_some())))
    })
    .await?;
    let Some((node, newly_revoked)) = before else {
        return Ok(None);
    };
    let refresh_error = refresh_control_plane(control, store).await.err();
    let session_ended = control.sessions.kill(node_id);
    Ok(Some(RevokeOutcome {
        node,
        newly_revoked,
        session_ended,
        refresh_error,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, fp: &str, prev: Option<&str>, status: NodeStatus) -> ClusterNode {
        let now = Utc::now();
        ClusterNode {
            node_id: id.to_string(),
            name: id.to_string(),
            cert_fingerprint: fp.to_string(),
            cert_serial: "01".to_string(),
            prev_cert_fingerprint: prev.map(str::to_string),
            prev_cert_serial: prev.map(|_| "00".to_string()),
            address: String::new(),
            version: String::new(),
            schema_version: 0,
            status,
            enrolled_at: now,
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: now,
            revoked_at: None,
        }
    }

    #[test]
    fn roster_maps_current_and_superseded_fingerprints() {
        let roster = roster_from_nodes(&[
            node("a", "fp-a", None, NodeStatus::Active),
            node("b", "fp-b", Some("fp-b-old"), NodeStatus::Pending),
            node("c", "fp-c", None, NodeStatus::Revoked),
        ]);
        assert_eq!(roster.len(), 4);
        assert_eq!(roster["fp-a"].state, NodeState::Active);
        assert!(!roster["fp-b"].via_previous_certificate);
        assert!(roster["fp-b-old"].via_previous_certificate);
        assert_eq!(roster["fp-b-old"].node_id, "b");
        assert_eq!(roster["fp-c"].state, NodeState::Revoked);
    }

    #[test]
    fn drift_alerts_back_off_per_node_and_a_flapping_node_cannot_reset_its_own_suppression() {
        let tracker = DriftTracker::default();
        let now = Utc::now();
        let a = vec!["a".to_string()];
        // First observation fires.
        assert_eq!(tracker.observe(&a, now), a);
        // Inside the backoff nothing fires, the first-seen time holds.
        assert!(tracker.observe(&a, now).is_empty());
        assert_eq!(tracker.since("a"), Some(now));
        // Back in sync: the divergence AGE is forgotten, because the
        // next one is a new divergence. The suppression interval is
        // not, or a node alternating in and out of sync would restart
        // at the shortest interval every cycle and alert forever.
        assert!(tracker.observe(&[], now).is_empty());
        assert_eq!(tracker.since("a"), None);
        let later = now + chrono::Duration::seconds(5);
        assert!(
            tracker.observe(&a, later).is_empty(),
            "a node that flaps back into drift is still suppressed"
        );
        assert_eq!(tracker.since("a"), Some(later));
        // Once the interval has genuinely elapsed, it fires again and
        // the interval doubles, up to the cap.
        let elapse = |tracker: &DriftTracker| {
            tracker.backoff.lock().expect("map").get_mut("a").expect("entry").0 = Instant::now();
        };
        elapse(&tracker);
        assert_eq!(tracker.observe(&a, later), a);
        assert_eq!(
            tracker.backoff.lock().expect("map")["a"].1,
            DRIFT_BACKOFF_MIN * 2
        );
        elapse(&tracker);
        assert_eq!(tracker.observe(&a, later), a);
        assert_eq!(
            tracker.backoff.lock().expect("map")["a"].1,
            DRIFT_BACKOFF_MIN * 4
        );
    }

    #[test]
    fn store_errors_keep_their_http_identity_through_the_runtime_error() {
        use axum::response::IntoResponse;
        let absent: ApiError = ClusterRuntimeError::Store(ConfigError::NotFound("node".into())).into();
        assert_eq!(
            absent.into_response().status(),
            axum::http::StatusCode::NOT_FOUND
        );
        let acceptor: ApiError =
            ClusterRuntimeError::Acceptor(ClusterTlsError::Rustls("crl".into())).into();
        assert_eq!(
            acceptor.into_response().status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
