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

//! The control plane's in-memory view of its fleet (Story 9.3 AC #7/#8):
//! the [`Roster`] that maps certificate fingerprints to identities,
//! the [`SessionRegistry`] of live sessions with their kill switches,
//! and the [`ControlPlane`] handle that bundles them with the acceptor
//! and the CA so the management API can act on the fleet.
//!
//! The store stays the source of truth; the binary reloads the roster
//! after every registry mutation (enroll, activate, revoke, renew), so
//! a connection never touches SQLite and the transport crate never
//! depends on it.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use lorica_command::RpcEndpoint;

use crate::ca::{CaError, ClusterCa, IssuedLeaf, RevokedEntry};
use crate::certs::{CertBundle, CertDistributor, CertPushReport};
use crate::challenge::{ChallengeFanout, ChallengeReport};
use crate::messages::ClusterFrame;
use crate::replication::{
    AcceptedConfig, AppliedConfig, ConfigPayload, ConfigVersion, ReplicationReport, Replicator,
};
use crate::tls::{operational_server_config_with_crl, ClusterTlsError, SwappableAcceptor};

/// Sliding window of the per-node session rate limit.
pub const SESSION_RATE_WINDOW: Duration = Duration::from_secs(60);

/// Sessions one node may establish per [`SESSION_RATE_WINDOW`]. A
/// follower opens one session, one more after a renewal, and a
/// handful across a flapping link; a node reconnecting at line rate
/// is paying for a TLS handshake and a registry write each time, and
/// is answered RETRY_LATER past this.
pub const MAX_SESSIONS_PER_NODE_PER_WINDOW: usize = 10;

/// Lifecycle state of a roster entry, mirroring the registry's
/// `status` column without depending on the config crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Enrolled, not yet activated: sessions are admitted (liveness,
    /// visibility) but no configuration or certificate flows.
    Pending,
    /// Full fleet member.
    Active,
    /// Refused: the certificate is on the CRL; a session that somehow
    /// reaches identity resolution is dropped and audited.
    Revoked,
}

/// One enrolled node as the transport sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Server-assigned node id (the only identity the plane uses).
    pub node_id: String,
    /// Display name (never an authorization input).
    pub name: String,
    /// Lifecycle state.
    pub state: NodeState,
    /// Whether the presented certificate is the superseded one a
    /// renewal left behind: the session layer retires it once the
    /// node connects with the new one.
    pub via_previous_certificate: bool,
}

/// Fingerprint -> identity map, swapped wholesale on every registry
/// change; reads are lock-free.
#[derive(Default)]
pub struct Roster {
    by_fingerprint: ArcSwap<HashMap<String, NodeIdentity>>,
}

impl Roster {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the whole map (the binary builds it from the store).
    pub fn replace(&self, entries: HashMap<String, NodeIdentity>) {
        self.by_fingerprint.store(Arc::new(entries));
    }

    /// The identity behind a certificate fingerprint, if enrolled.
    pub fn lookup(&self, fingerprint: &str) -> Option<NodeIdentity> {
        self.by_fingerprint.load().get(fingerprint).cloned()
    }

    /// Enrolled nodes (any state), for the fleet-size hint.
    pub fn len(&self) -> usize {
        self.by_fingerprint
            .load()
            .values()
            .filter(|n| !n.via_previous_certificate)
            .count()
    }

    /// Whether a superseded certificate is still on record for
    /// `node_id` (a renewal happened and the node has not yet
    /// connected on the new one). Lock-free; the session layer asks
    /// this before touching the store.
    pub fn has_superseded_certificate(&self, node_id: &str) -> bool {
        self.by_fingerprint
            .load()
            .values()
            .any(|n| n.via_previous_certificate && n.node_id == node_id)
    }

    /// Whether no node is enrolled.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Live facts about one established session, updated by the session
/// layer and read by the API and the persistence flush.
pub struct LiveSession {
    /// Monotonic per control plane; a newer session for the same node
    /// supersedes the older one.
    pub generation: u64,
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Unix seconds of the last heartbeat or session event.
    pub last_seen_unix: AtomicU64,
    /// The node's reported build version.
    pub build_version: String,
    /// The node's reported schema version.
    pub schema_version: u32,
    /// The roster state the node held when the session was admitted.
    /// The replication coordinator addresses [`NodeState::Active`]
    /// sessions only: a `Pending` node is visible and alive but no
    /// configuration flows to it (Story 9.3 AC #5).
    pub state: NodeState,
    /// A clone of the session's RPC endpoint, so the control plane can
    /// PUSH configuration down an established session (Story 9.4 D5)
    /// instead of waiting to be asked.
    pub endpoint: RpcEndpoint<ClusterFrame>,
    /// What the node reports as applied, refreshed by every heartbeat
    /// and by every commit acknowledgement.
    applied: Mutex<AppliedConfig>,
    /// Flipped to `true` to end the session synchronously (revocation,
    /// supersession).
    kill: watch::Sender<bool>,
}

/// Everything but the endpoint, which has no useful debug shape and
/// whose inner channels are not worth printing.
impl std::fmt::Debug for LiveSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveSession")
            .field("generation", &self.generation)
            .field("peer_addr", &self.peer_addr)
            .field("last_seen_unix", &self.last_seen_unix)
            .field("build_version", &self.build_version)
            .field("schema_version", &self.schema_version)
            .field("state", &self.state)
            .field("applied", &self.applied())
            .finish_non_exhaustive()
    }
}

impl LiveSession {
    /// Record activity now.
    pub fn touch(&self) {
        self.last_seen_unix.store(unix_now(), Ordering::Relaxed);
    }

    /// Replace what this node is known to run.
    pub fn record_applied(&self, applied: AppliedConfig) {
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = applied;
    }

    /// What this node is known to run.
    pub fn applied(&self) -> AppliedConfig {
        self.applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

/// A snapshot of one live session for the API.
#[derive(Debug, Clone)]
pub struct LiveSessionSnapshot {
    /// The node id.
    pub node_id: String,
    /// Session generation.
    pub generation: u64,
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Unix seconds of the last activity.
    pub last_seen_unix: u64,
    /// Reported build version.
    pub build_version: String,
    /// Reported schema version.
    pub schema_version: u32,
    /// The roster state the session was admitted under.
    pub state: NodeState,
    /// What the node reports as applied (Story 9.4 AC #12's drift
    /// input).
    pub applied: AppliedConfig,
}

/// Node id -> live session, with per-session kill switches so a
/// revocation ends the session NOW rather than at the next heartbeat
/// (AC #7).
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, Arc<LiveSession>>>,
    next_generation: AtomicU64,
    /// Session-establishment timestamps per node inside
    /// [`SESSION_RATE_WINDOW`] (entries vanish once their window
    /// empties, so the map is bounded by the nodes seen in one window).
    recent: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// What a session task holds while registered: its kill receiver and
/// the entry itself. Dropping the guard deregisters the session, but
/// only if a newer session has not already replaced it.
pub struct SessionGuard {
    registry: Arc<SessionRegistry>,
    node_id: String,
    entry: Arc<LiveSession>,
    killed: watch::Receiver<bool>,
}

impl SessionGuard {
    /// The live entry (for `touch`).
    pub fn entry(&self) -> &Arc<LiveSession> {
        &self.entry
    }

    /// Resolves when the session is told to end (revoked or superseded).
    pub async fn killed(&mut self) {
        while !*self.killed.borrow() {
            if self.killed.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.registry.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(current) = sessions.get(&self.node_id) {
            if Arc::ptr_eq(current, &self.entry) {
                sessions.remove(&self.node_id);
            }
        }
    }
}

impl SessionRegistry {
    /// An empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a session for `identity`, superseding (and killing) any
    /// older one for the same node: a node has exactly one operational
    /// session, and the newest connection wins (a reconnect after a
    /// network blip must not lose to its own zombie).
    ///
    /// `endpoint` is a clone of the session's RPC endpoint: it is what
    /// the replication coordinator pushes configuration down (Story 9.4
    /// D6). `applied` is what the node reported in its `Hello`.
    pub fn register(
        self: &Arc<Self>,
        identity: &NodeIdentity,
        peer_addr: SocketAddr,
        endpoint: RpcEndpoint<ClusterFrame>,
        build_version: &str,
        schema_version: u32,
        applied: AppliedConfig,
    ) -> SessionGuard {
        let (kill_tx, kill_rx) = watch::channel(false);
        let entry = Arc::new(LiveSession {
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed) + 1,
            peer_addr,
            last_seen_unix: AtomicU64::new(unix_now()),
            build_version: build_version.to_string(),
            schema_version,
            state: identity.state,
            endpoint,
            applied: Mutex::new(applied),
            kill: kill_tx,
        });
        let previous = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(identity.node_id.clone(), Arc::clone(&entry));
        if let Some(old) = previous {
            let _ = old.kill.send(true);
        }
        SessionGuard {
            registry: Arc::clone(self),
            node_id: identity.node_id.clone(),
            entry,
            killed: kill_rx,
        }
    }

    /// Every Active session's `(node_id, endpoint clone, applied)`, the
    /// input to one replication round (Story 9.4 D6).
    ///
    /// `Pending` sessions are excluded by construction: a node that has
    /// not been activated is visible and alive but never receives a
    /// configuration blob (Story 9.3 AC #5).
    pub fn active_sessions(&self) -> Vec<(String, RpcEndpoint<ClusterFrame>, AppliedConfig)> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|(_, session)| session.state == NodeState::Active)
            .map(|(node_id, session)| {
                (
                    node_id.clone(),
                    session.endpoint.clone(),
                    session.applied(),
                )
            })
            .collect()
    }

    /// Record what a node reports as applied. `true` iff it has a live
    /// session (a node that disconnected mid-round simply keeps the
    /// stale value in the store until it reconnects).
    pub fn record_applied(&self, node_id: &str, applied: AppliedConfig) -> bool {
        match self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(node_id)
        {
            Some(session) => {
                session.record_applied(applied);
                true
            }
            None => false,
        }
    }

    /// What a live node reports as applied, or `None` when it has no
    /// session.
    pub fn applied(&self, node_id: &str) -> Option<AppliedConfig> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(node_id)
            .map(|session| session.applied())
    }

    /// Whether `node_id` may establish another session now (at most
    /// [`MAX_SESSIONS_PER_NODE_PER_WINDOW`] per [`SESSION_RATE_WINDOW`]);
    /// the attempt is recorded only when admitted, so a refused node
    /// does not extend its own penalty.
    pub fn admit_session(&self, node_id: &str) -> bool {
        self.admit_session_at(node_id, Instant::now())
    }

    fn admit_session_at(&self, node_id: &str, now: Instant) -> bool {
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        recent.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= SESSION_RATE_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let times = recent.entry(node_id.to_string()).or_default();
        if times.len() >= MAX_SESSIONS_PER_NODE_PER_WINDOW {
            return false;
        }
        times.push_back(now);
        true
    }

    /// End the node's session synchronously (AC #7). `true` iff a
    /// session was live.
    pub fn kill(&self, node_id: &str) -> bool {
        let removed = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        match removed {
            Some(entry) => {
                let _ = entry.kill.send(true);
                true
            }
            None => false,
        }
    }

    /// Whether the node has a live session.
    pub fn is_connected(&self, node_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(node_id)
    }

    /// Snapshot of every live session.
    pub fn snapshot(&self) -> Vec<LiveSessionSnapshot> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(node_id, s)| LiveSessionSnapshot {
                node_id: node_id.clone(),
                generation: s.generation,
                peer_addr: s.peer_addr,
                last_seen_unix: s.last_seen_unix.load(Ordering::Relaxed),
                build_version: s.build_version.clone(),
                schema_version: s.schema_version,
                state: s.state,
                applied: s.applied(),
            })
            .collect()
    }

    /// Live sessions.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Proof that the control plane's refresh lock is held: the only way
/// to swap the roster or the acceptor. Obtained from
/// [`ControlPlane::refresh_guard`]; dropping it releases the lock.
pub struct RefreshGuard<'a> {
    _held: tokio::sync::MutexGuard<'a, ()>,
}

/// Everything the management API needs to act on the fleet, owned by
/// the control-plane runtime and shared with `AppState`.
pub struct ControlPlane {
    /// Fingerprint -> identity.
    pub roster: Arc<Roster>,
    /// Live sessions and their kill switches.
    pub sessions: Arc<SessionRegistry>,
    /// The operational acceptor, rebuilt with a fresh CRL on every
    /// revocation.
    pub acceptor: Arc<SwappableAcceptor>,
    /// The fleet CA. Private: signing reaches the API only through
    /// [`ControlPlane::issue_node_leaf`] and the CRL rebuild, never
    /// as a bare signer any handler could misuse.
    ca: ClusterCa,
    /// The serials the current acceptor's CRL covers, so a refresh
    /// that changes nothing revocation-related skips the mint and
    /// the rustls rebuild. Comparing serials alone is sound only
    /// because a revoked serial's `reason` and `revoked_at` never
    /// change once written (the store inserts them with `OR IGNORE`),
    /// so the same serial set always mints the same CRL.
    crl_serials: Mutex<Vec<String>>,
    /// Serializes "read the store, swap roster and acceptor" so two
    /// concurrent refreshes cannot land out of order and undo a
    /// revocation. Private: the swaps take a [`RefreshGuard`], so a
    /// caller cannot swap without holding it.
    refresh_lock: tokio::sync::Mutex<()>,
    /// The control plane's own leaf, PEM (its SPKI is what tokens pin).
    pub leaf_cert_pem: String,
    /// The control plane's own leaf key, PEM (for the acceptor rebuild).
    leaf_key_pem: String,
    /// Fleet-size hint handed to followers.
    pub fleet_size: Arc<AtomicU32>,
    /// Live join-token count driving the enrollment listener.
    pub token_liveness: watch::Sender<u32>,
    /// `--cluster-auto-activate`: enrollments land `Active` instead of
    /// `Pending`.
    pub auto_activate: bool,
    /// The name followers dial (the leaf SAN).
    pub advertise_host: String,
    /// This control plane's build version (reported in `cluster
    /// status`).
    pub build_version: String,
    /// The configuration the fleet has ACCEPTED (Story 9.4 AC #3/#6):
    /// the version advertised by every `HelloAck` and `HeartbeatAck`,
    /// and the encoded payload a convergence pull is answered from. A
    /// generation enters it when Prepare succeeds fleet-wide, never
    /// before; see [`AcceptedConfig`].
    pub accepted: AcceptedConfig,
    /// The replication coordinator (Story 9.4 D6): one round at a time,
    /// with the eviction and quarantine bookkeeping that survives it.
    pub replication: Replicator,
    /// The certificate distribution coordinator (Story 9.5 AC #7):
    /// one best-effort push round at a time, on a path deliberately
    /// independent of the configuration commit, so a slow follower
    /// cannot hold up a fleet renewal.
    pub distribution: CertDistributor,
    /// The HTTP-01 challenge fan-out (Story 9.5 AC #6). Stateless and
    /// deliberately unserialized: two orders for different hostnames
    /// have no reason to queue behind each other.
    pub challenges: ChallengeFanout,
}

impl ControlPlane {
    /// Bundle the runtime handles. `token_liveness` starts at 0; the
    /// binary's liveness publisher raises it.
    #[allow(clippy::too_many_arguments)] // one constructor for one bundle; the fields ARE the API
    pub fn new(
        ca: ClusterCa,
        leaf_cert_pem: &str,
        leaf_key_pem: &str,
        acceptor: Arc<SwappableAcceptor>,
        fleet_size: Arc<AtomicU32>,
        token_liveness: watch::Sender<u32>,
        auto_activate: bool,
        advertise_host: &str,
        build_version: &str,
    ) -> Self {
        Self {
            roster: Arc::new(Roster::new()),
            sessions: SessionRegistry::new(),
            acceptor,
            ca,
            crl_serials: Mutex::new(Vec::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
            leaf_cert_pem: leaf_cert_pem.to_string(),
            leaf_key_pem: leaf_key_pem.to_string(),
            fleet_size,
            token_liveness,
            auto_activate,
            advertise_host: advertise_host.to_string(),
            build_version: build_version.to_string(),
            accepted: AcceptedConfig::new(),
            replication: Replicator::new(),
            distribution: CertDistributor::new(),
            challenges: ChallengeFanout::new(),
        }
    }

    /// The configuration version the fleet must converge on.
    pub fn config_version(&self) -> ConfigVersion {
        self.accepted.version()
    }

    /// The shared version slot, handed to
    /// [`crate::listener::OperationalConfig::config_version`] so the
    /// handshake and the heartbeat answer the current value with no
    /// lock and no back-reference to this handle.
    pub fn config_version_handle(&self) -> Arc<ArcSwap<ConfigVersion>> {
        self.accepted.version_handle()
    }

    /// Run one replication round and publish the generation only if
    /// the fleet accepts it (Story 9.4 AC #6).
    pub async fn replicate(&self, payload: ConfigPayload) -> ReplicationReport {
        self.replication
            .replicate(&self.sessions, &self.accepted, payload)
            .await
    }

    /// Push certificate material to the nodes `recipients` names
    /// (Story 9.5 AC #7).
    ///
    /// `recipients` is resolved by the CALLER, control-plane side and
    /// down to a `node_id` (D3): certificate hostname, then the routes
    /// bound to it, then their `node_selector`, then names resolved
    /// against `cluster_nodes`. This method never widens that list and
    /// never resolves a name itself, because a node name is chosen by
    /// the joining node and is not an authorization input.
    ///
    /// Never fails and never blocks a caller's own work: a push is an
    /// optimisation, and every node it could not reach asks for what
    /// it lacks on the certificate pull path (D2).
    pub async fn distribute_certificates(
        &self,
        recipients: &[String],
        bundles: Vec<CertBundle>,
    ) -> CertPushReport {
        self.distribution
            .push(&self.sessions, recipients, bundles)
            .await
    }

    /// Publish an HTTP-01 challenge token to the nodes `recipients`
    /// names, and report PER NODE (Story 9.5 AC #6).
    ///
    /// `recipients` is resolved by the caller from `identifier` (the
    /// per-SAN hostname, not the order's primary domain) through the
    /// routes bound to it and their `node_selector`. This method never
    /// widens it and never addresses a non-Active session.
    ///
    /// It takes NO all-or-nothing decision. The caller is the ACME
    /// solver, and it is the layer that must refuse the whole order
    /// unless [`ChallengeReport::is_complete`] holds: telling the
    /// authority to validate while one node has nothing is the opaque
    /// failure AC #6 exists to remove, and only the caller knows an
    /// order is at stake.
    pub async fn publish_challenge(
        &self,
        recipients: &[String],
        identifier: &str,
        token: &str,
        key_authorization: &str,
    ) -> ChallengeReport {
        self.challenges
            .publish(
                &self.sessions,
                recipients,
                identifier,
                token,
                key_authorization,
            )
            .await
    }

    /// Stop serving `token` on the named nodes. Best effort and
    /// silent: it runs on both the success and the failure path of an
    /// order, and a node that never answers drops the entry on its own
    /// deadline.
    pub async fn retract_challenge(&self, recipients: &[String], token: &str) {
        self.challenges
            .retract(&self.sessions, recipients, token)
            .await;
    }

    /// Take the refresh lock: the guard is the proof
    /// [`ControlPlane::rebuild_acceptor`] and
    /// [`ControlPlane::replace_roster`] require, and it must be held
    /// from the store read to the last swap.
    pub async fn refresh_guard(&self) -> RefreshGuard<'_> {
        RefreshGuard {
            _held: self.refresh_lock.lock().await,
        }
    }

    /// Replace the roster and refresh the fleet-size hint.
    pub fn replace_roster(&self, _guard: &RefreshGuard<'_>, entries: HashMap<String, NodeIdentity>) {
        self.roster.replace(entries);
        let size = u32::try_from(self.roster.len()).unwrap_or(u32::MAX);
        self.fleet_size.store(size, Ordering::Relaxed);
    }

    /// The CA certificate PEM (what enrolled nodes verify the control
    /// plane with).
    pub fn ca_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// Issue a node leaf on a bare public key (AC #3), the only
    /// signing path the API and the redemption hooks get.
    pub fn issue_node_leaf(&self, node_id: &str, spki_der: &[u8]) -> Result<IssuedLeaf, CaError> {
        self.ca.issue_node_leaf_for_public_key(node_id, spki_der)
    }

    /// Rebuild the operational acceptor over `revoked` (AC #7): mints
    /// a CRL when the list is non-empty, swaps the config in, so every
    /// accept from now on refuses those serials. Established sessions
    /// are handled separately by [`SessionRegistry::kill`]. A call
    /// whose serial set equals the one already served is a no-op
    /// (`Ok(false)`); `Ok(true)` means the acceptor was swapped.
    pub fn rebuild_acceptor(
        &self,
        _guard: &RefreshGuard<'_>,
        revoked: &[RevokedEntry],
    ) -> Result<bool, ClusterTlsError> {
        let mut serials: Vec<String> = revoked.iter().map(|r| r.serial_hex.clone()).collect();
        serials.sort();
        {
            let current = self.crl_serials.lock().unwrap_or_else(|p| p.into_inner());
            if *current == serials {
                return Ok(false);
            }
        }
        let crl = if revoked.is_empty() {
            None
        } else {
            Some(
                self.ca
                    .mint_crl(revoked)
                    .map_err(|e| ClusterTlsError::Rustls(format!("CRL: {e}")))?,
            )
        };
        let config = operational_server_config_with_crl(
            self.ca.cert_pem(),
            &self.leaf_cert_pem,
            &self.leaf_key_pem,
            crl,
        )?;
        self.acceptor.swap(Arc::new(config));
        *self.crl_serials.lock().unwrap_or_else(|p| p.into_inner()) = serials;
        Ok(true)
    }

    /// Publish the live-token count to the enrollment listener.
    pub fn publish_token_liveness(&self, live: u32) {
        let _ = self.token_liveness.send(live);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::cluster_rpc_limits;

    fn identity(id: &str, state: NodeState) -> NodeIdentity {
        NodeIdentity {
            node_id: id.to_string(),
            name: id.to_string(),
            state,
            via_previous_certificate: false,
        }
    }

    /// An endpoint over an in-process duplex: the registry only ever
    /// clones and stores it, so the far half is never driven here.
    fn endpoint() -> RpcEndpoint<ClusterFrame> {
        let (near, _far) = tokio::io::duplex(1024);
        let (endpoint, _incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(near, cluster_rpc_limits());
        endpoint
    }

    fn register(
        registry: &Arc<SessionRegistry>,
        id: &str,
        state: NodeState,
        applied: AppliedConfig,
    ) -> SessionGuard {
        let peer: SocketAddr = "192.0.2.10:4000".parse().expect("addr");
        registry.register(&identity(id, state), peer, endpoint(), "1.7.0", 50, applied)
    }

    #[test]
    fn roster_lookup_and_size_ignore_superseded_entries() {
        let roster = Roster::new();
        assert!(roster.is_empty());
        let mut map = HashMap::new();
        map.insert("fp-a".to_string(), identity("a", NodeState::Active));
        map.insert("fp-b".to_string(), identity("b", NodeState::Pending));
        map.insert(
            "fp-b-old".to_string(),
            NodeIdentity {
                via_previous_certificate: true,
                ..identity("b", NodeState::Pending)
            },
        );
        roster.replace(map);
        assert_eq!(roster.len(), 2);
        assert_eq!(roster.lookup("fp-a").map(|n| n.node_id), Some("a".to_string()));
        assert!(roster.lookup("fp-b-old").is_some_and(|n| n.via_previous_certificate));
        assert!(roster.lookup("fp-zzz").is_none());
    }

    #[tokio::test]
    async fn a_newer_session_supersedes_and_kills_the_older_one() {
        let registry = SessionRegistry::new();
        let mut first = register(
            &registry,
            "node-a",
            NodeState::Active,
            AppliedConfig::default(),
        );
        assert!(registry.is_connected("node-a"));
        let second = register(
            &registry,
            "node-a",
            NodeState::Active,
            AppliedConfig::default(),
        );
        assert!(second.entry().generation > first.entry().generation);
        tokio::time::timeout(std::time::Duration::from_secs(1), first.killed())
            .await
            .expect("older session is told to end");
        // Dropping the superseded guard must not deregister the newer
        // session.
        drop(first);
        assert!(registry.is_connected("node-a"));
        assert_eq!(registry.len(), 1);
        drop(second);
        assert!(!registry.is_connected("node-a"));
    }

    #[test]
    fn roster_knows_which_nodes_still_carry_a_superseded_certificate() {
        let roster = Roster::new();
        let mut map = HashMap::new();
        map.insert("fp-a".to_string(), identity("a", NodeState::Active));
        map.insert("fp-b".to_string(), identity("b", NodeState::Active));
        map.insert(
            "fp-b-old".to_string(),
            NodeIdentity {
                via_previous_certificate: true,
                ..identity("b", NodeState::Active)
            },
        );
        roster.replace(map);
        assert!(!roster.has_superseded_certificate("a"));
        assert!(roster.has_superseded_certificate("b"));
        assert!(!roster.has_superseded_certificate("zzz"));
    }

    #[test]
    fn per_node_session_rate_slides_and_frees_the_entry() {
        let registry = SessionRegistry::new();
        let t0 = Instant::now();
        for i in 0..MAX_SESSIONS_PER_NODE_PER_WINDOW {
            assert!(
                registry.admit_session_at("node-a", t0 + Duration::from_secs(i as u64)),
                "session {i} inside the budget"
            );
        }
        assert!(!registry.admit_session_at("node-a", t0 + Duration::from_secs(30)));
        // Another node is unaffected.
        assert!(registry.admit_session_at("node-b", t0 + Duration::from_secs(30)));
        // The oldest attempt slides out of the window and frees a slot.
        assert!(registry.admit_session_at("node-a", t0 + SESSION_RATE_WINDOW));
        // Past the window with no activity, the entry is gone.
        assert!(registry.admit_session_at("node-c", t0 + SESSION_RATE_WINDOW * 3));
        let recent = registry.recent.lock().expect("map");
        assert!(!recent.contains_key("node-a"));
        assert!(!recent.contains_key("node-b"));
        assert_eq!(recent.len(), 1);
    }

    #[tokio::test]
    async fn kill_ends_a_live_session_synchronously() {
        let registry = SessionRegistry::new();
        let mut guard = register(
            &registry,
            "node-a",
            NodeState::Active,
            AppliedConfig::default(),
        );
        assert!(registry.kill("node-a"));
        tokio::time::timeout(std::time::Duration::from_secs(1), guard.killed())
            .await
            .expect("killed resolves");
        assert!(!registry.kill("node-a"), "nothing left to kill");
        assert!(registry.snapshot().is_empty());
    }

    #[tokio::test]
    async fn only_active_sessions_are_replication_targets_and_applied_state_round_trips() {
        let registry = SessionRegistry::new();
        let active = register(
            &registry,
            "node-a",
            NodeState::Active,
            AppliedConfig {
                generation: 3,
                hash: "abcd".to_string(),
                break_glass: false,
            },
        );
        // A pending node is visible and alive but never a target
        // (Story 9.3 AC #5).
        let pending = register(
            &registry,
            "node-b",
            NodeState::Pending,
            AppliedConfig::default(),
        );

        let targets: Vec<String> = registry
            .active_sessions()
            .into_iter()
            .map(|(node_id, _, _)| node_id)
            .collect();
        assert_eq!(targets, vec!["node-a".to_string()]);
        assert_eq!(
            registry.applied("node-a").map(|a| a.generation),
            Some(3),
            "the Hello's applied state is registered with the session"
        );

        let updated = AppliedConfig {
            generation: 4,
            hash: "beef".to_string(),
            break_glass: true,
        };
        assert!(registry.record_applied("node-a", updated.clone()));
        assert!(!registry.record_applied("node-zzz", updated.clone()));
        assert_eq!(registry.applied("node-a"), Some(updated.clone()));
        assert!(registry.applied("node-zzz").is_none());

        let snapshot = registry.snapshot();
        let a = snapshot
            .iter()
            .find(|s| s.node_id == "node-a")
            .expect("node-a is live");
        assert_eq!(a.state, NodeState::Active);
        assert_eq!(a.applied, updated);
        // Break-glass now excludes it from a round without changing
        // its state.
        assert_eq!(registry.active_sessions().len(), 1);
        drop((active, pending));
    }

    #[test]
    fn the_control_plane_publishes_and_shares_one_configuration_version() {
        // Building an acceptor needs the crate's pinned rustls
        // provider; installing it twice in one process is a no-op.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
        let (server_cert, server_key) = ca.issue_server_leaf("cp.example.com").expect("leaf");
        let tls = operational_server_config_with_crl(
            ca.cert_pem(),
            &server_cert,
            &server_key,
            None,
        )
        .expect("server config");
        let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(tls)));
        let (token_liveness, _rx) = watch::channel(0u32);
        let control_plane = ControlPlane::new(
            ca,
            &server_cert,
            &server_key,
            acceptor,
            Arc::new(AtomicU32::new(0)),
            token_liveness,
            false,
            "cp.example.com",
            "1.7.0",
        );
        assert_eq!(control_plane.config_version(), ConfigVersion::default());
        let shared = control_plane.config_version_handle();
        let next = ConfigPayload {
            generation: 12,
            hash: "abcd".to_string(),
            blob: b"{}".to_vec(),
        };
        control_plane.accepted.publish(next.clone());
        assert_eq!(control_plane.config_version(), next.version());
        assert_eq!(
            control_plane.accepted.payload().map(|p| (*p).clone()),
            Some(next.clone()),
            "a convergence pull is answered from the same slot"
        );
        let next = next.version();
        assert_eq!(
            **shared.load(),
            next,
            "the listener's handle sees the same value"
        );
        assert_eq!(control_plane.replication.in_flight(), None);
    }
}
