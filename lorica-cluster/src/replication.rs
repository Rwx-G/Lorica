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

//! Configuration replication (Story 9.4): the plain version types both
//! sides exchange, and the control-plane [`Replicator`] that drives one
//! two-phase round over the live sessions.
//!
//! # The guarantee, stated honestly (AC #6)
//!
//! All-or-none holds on PREPARE only. A semantic rejection from any
//! target aborts the round fleet-wide before a single node applies. A
//! COMMIT that fails after other nodes committed leaves the fleet
//! SPLIT: there is no rollback. The split is recorded in
//! [`ReplicationReport::commit_failed`] and reconciled by convergence
//! (the follower's next heartbeat carries an older generation, the
//! control plane answers with the current one, and the follower pulls).
//!
//! # Why a transport failure is not a veto (AC #5)
//!
//! A follower that completes mTLS and then stops reading its socket
//! would, if a Prepare timeout aborted the round, veto every
//! configuration change in the fleet from a single wedged node. So a
//! transport timeout or error EVICTS that node from the commit set and
//! the round proceeds; only a well-formed semantic rejection aborts.
//! Three consecutive evictions quarantine the node: it is skipped
//! entirely until it converges by pull or an operator releases it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::{ArcSwap, ArcSwapOption};

use lorica_command::RpcEndpoint;
use tokio::task::JoinSet;

use crate::messages::{
    cluster_response, config_hash_is_valid, ClusterFrame, ClusterRequest, ClusterStatus,
    ConfigPrepare,
};
use crate::roster::SessionRegistry;

/// Default per-node deadline for one Prepare or Commit exchange: the
/// Story 9.1 per-endpoint WAN value, not the same-host UDS default the
/// worker plane uses.
pub const DEFAULT_PER_NODE_DEADLINE: Duration = Duration::from_secs(10);

/// Default number of CONSECUTIVE transport evictions after which a node
/// is quarantined (skipped by later rounds until it converges by pull
/// or an operator releases it).
pub const DEFAULT_QUARANTINE_THRESHOLD: u32 = 3;

/// Longest a peer's asserted break-glass window is honoured: the cap
/// the management API enforces when an operator opens one (24 h), plus
/// nothing. Past it the node is addressed by replication again.
pub const MAX_HONOURED_BREAK_GLASS: Duration = Duration::from_secs(24 * 3600);

/// Longest peer-supplied rejection reason kept verbatim in a report.
/// Anything longer, or carrying control characters, is replaced: the
/// reason reaches operator-facing surfaces and must not become a
/// log-injection or a memory-amplification vector.
pub const MAX_REJECTION_REASON_BYTES: usize = 200;

/// What a follower reports about the configuration it runs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppliedConfig {
    /// The generation the follower has applied; `0` when it never
    /// applied one.
    pub generation: u64,
    /// Canonical hash of the applied configuration, lowercase hex;
    /// empty with generation `0`.
    pub hash: String,
    /// Whether the follower is in break-glass (AC #11): it is excluded
    /// from commit sets until the window ends.
    pub break_glass: bool,
}

/// The control plane's current configuration version.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigVersion {
    /// The persisted `cluster_config_generation`.
    pub generation: u64,
    /// Canonical hash of that generation, lowercase hex.
    pub hash: String,
}

impl ConfigVersion {
    /// Whether `applied` differs from this version and therefore needs
    /// to converge. A follower that has applied nothing while the
    /// control plane also has nothing is NOT behind.
    pub fn is_behind(&self, applied: &AppliedConfig) -> bool {
        self.generation != applied.generation || self.hash != applied.hash
    }
}

/// A replicable configuration: the version plus the canonical blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPayload {
    /// The generation this blob encodes.
    pub generation: u64,
    /// Canonical SHA-256 of `blob`, lowercase hex.
    pub hash: String,
    /// The canonical configuration blob (bounded by the 4 MiB frame
    /// cap).
    pub blob: Vec<u8>,
}

impl ConfigPayload {
    /// The version half of this payload.
    pub fn version(&self) -> ConfigVersion {
        ConfigVersion {
            generation: self.generation,
            hash: self.hash.clone(),
        }
    }
}

/// The configuration the fleet has ACCEPTED: the version advertised in
/// every `HelloAck` and `HeartbeatAck`, and the encoded payload a
/// convergence pull is answered from.
///
/// # Why the publication point is between the two phases
///
/// A generation enters here at the moment PREPARE succeeded
/// fleet-wide, which is exactly where the all-or-none guarantee is
/// made. Publishing earlier would make an abort meaningless: the
/// advertised version would still move, every follower would compute
/// itself behind on its next heartbeat, and the pull path would hand
/// out the generation the round had just rejected. Publishing later,
/// after the commits, would tell a node that has just applied the
/// generation that it is AHEAD of the control plane, and it would
/// converge backwards.
///
/// Serving pulls from this cache rather than re-encoding the store
/// also keeps a convergence pull off the store lock entirely: a
/// follower cannot make the control plane walk every replicated table
/// by asking often.
#[derive(Clone)]
pub struct AcceptedConfig {
    version: Arc<ArcSwap<ConfigVersion>>,
    payload: Arc<ArcSwapOption<ConfigPayload>>,
}

impl Default for AcceptedConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl AcceptedConfig {
    /// An empty slot: generation 0, no payload. A control plane that
    /// has never replicated advertises this until it is seeded from
    /// the store at boot.
    pub fn new() -> Self {
        Self {
            version: Arc::new(ArcSwap::from_pointee(ConfigVersion::default())),
            payload: Arc::new(ArcSwapOption::empty()),
        }
    }

    /// The version every handshake and heartbeat advertises.
    pub fn version(&self) -> ConfigVersion {
        (**self.version.load()).clone()
    }

    /// The encoded payload a convergence pull is answered from, or
    /// `None` before the first publication.
    pub fn payload(&self) -> Option<Arc<ConfigPayload>> {
        self.payload.load_full()
    }

    /// The shared version slot, handed to
    /// [`crate::listener::OperationalConfig::config_version`] so the
    /// accept path reads it with no lock.
    pub fn version_handle(&self) -> Arc<ArcSwap<ConfigVersion>> {
        Arc::clone(&self.version)
    }

    /// Publish a generation the fleet has accepted.
    ///
    /// The payload lands BEFORE the version, so a follower that learns
    /// version N from a heartbeat can always be served payload N; the
    /// reverse order would leave a window where a node is told it is
    /// behind and then handed the previous generation.
    pub fn publish(&self, payload: ConfigPayload) {
        let version = payload.version();
        self.payload.store(Some(Arc::new(payload)));
        self.version.store(Arc::new(version));
    }
}

/// The outcome of one replication round, published for
/// `GET /api/v1/cluster/replication` (AC #8) and the dashboard.
///
/// Every vector is sorted by node id, so two runs of the same round
/// produce byte-identical reports regardless of which follower answered
/// first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReplicationReport {
    /// The generation this round pushed.
    pub generation: u64,
    /// Canonical hash of that generation.
    pub hash: String,
    /// Unix seconds when the round started.
    pub started_unix: u64,
    /// Unix seconds when the round finished.
    pub finished_unix: u64,
    /// Node ids the round addressed (quarantined and break-glass nodes
    /// excluded).
    pub targets: Vec<String>,
    /// Nodes that staged the generation.
    pub prepared: Vec<String>,
    /// `(node_id, reason)`: a transport timeout or error on Prepare.
    /// The node keeps its old configuration and is marked drifted; the
    /// round proceeds without it (AC #5).
    pub evicted: Vec<(String, String)>,
    /// `(node_id, reason)`: a SEMANTIC rejection. Non-empty means the
    /// round aborted fleet-wide.
    pub rejected: Vec<(String, String)>,
    /// Nodes that applied the generation.
    pub committed: Vec<String>,
    /// `(node_id, reason)`: prepared, then failed to commit. The fleet
    /// is split on this generation (AC #6).
    pub commit_failed: Vec<(String, String)>,
    /// Nodes skipped because they are quarantined.
    pub skipped_quarantined: Vec<String>,
    /// Nodes skipped because they are in break-glass (AC #11).
    pub skipped_break_glass: Vec<String>,
    /// Whether the round aborted (a semantic rejection): no node
    /// applied this generation.
    pub aborted: bool,
}

/// Per-node outcome of one Prepare exchange.
enum PrepareOutcome {
    /// The node staged the generation.
    Prepared,
    /// The node refused for a semantic reason: the round aborts.
    Rejected(String),
    /// Transport timeout, transport error, refusal status or missing
    /// body: the node is evicted from the commit set.
    Evicted(String),
}

/// The control plane's replication coordinator (AC #4/#5/#6).
///
/// One round at a time: [`Replicator::replicate`] holds an internal
/// lock for its whole duration, so two generations can never interleave
/// their Prepare and Commit phases on the same fleet.
pub struct Replicator {
    /// Consecutive transport evictions per node; reset by a successful
    /// Prepare.
    evictions: Mutex<HashMap<String, u32>>,
    /// Consecutive SEMANTIC rejections per node; reset by a successful
    /// Prepare. A rejection aborts the round fleet-wide, so a node that
    /// rejects every generation would otherwise veto the fleet forever
    /// at no cost to itself: it answers well inside the deadline, so
    /// the transport eviction streak never moves.
    rejections: Mutex<HashMap<String, u32>>,
    /// Nodes excluded from every round until they converge by pull or
    /// an operator releases them.
    quarantined: Mutex<HashSet<String>>,
    /// When each node was first seen asserting break-glass, so the
    /// claim can be capped. `break_glass` is a bit the PEER sets: a
    /// compromised follower that asserts it forever would otherwise be
    /// skipped by every round, never evicted, never quarantined, and
    /// reported as the operator's own doing.
    break_glass_since: Mutex<HashMap<String, Instant>>,
    /// The last finished round.
    last: Mutex<Option<ReplicationReport>>,
    /// Generation of the round currently running; `0` means idle.
    in_flight: AtomicU64,
    /// Serializes rounds.
    round: tokio::sync::Mutex<()>,
    /// Bound on one Prepare, Commit or Abort exchange with one node.
    /// Default [`DEFAULT_PER_NODE_DEADLINE`].
    pub per_node_deadline: Duration,
    /// Consecutive evictions that quarantine a node. Default
    /// [`DEFAULT_QUARANTINE_THRESHOLD`].
    pub quarantine_threshold: u32,
}

impl Default for Replicator {
    fn default() -> Self {
        Self::new()
    }
}

impl Replicator {
    /// A coordinator with the documented defaults.
    pub fn new() -> Self {
        Self {
            evictions: Mutex::new(HashMap::new()),
            rejections: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
            break_glass_since: Mutex::new(HashMap::new()),
            last: Mutex::new(None),
            in_flight: AtomicU64::new(0),
            round: tokio::sync::Mutex::new(()),
            per_node_deadline: DEFAULT_PER_NODE_DEADLINE,
            quarantine_threshold: DEFAULT_QUARANTINE_THRESHOLD,
        }
    }

    /// The last finished round, or `None` before the first one.
    pub fn last_report(&self) -> Option<ReplicationReport> {
        self.last.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The generation of the round currently running, if any.
    ///
    /// Generation `0` is never replicated (the persisted generation
    /// starts at 1 on the first mutation), so `0` unambiguously means
    /// "idle".
    pub fn in_flight(&self) -> Option<u64> {
        match self.in_flight.load(Ordering::Relaxed) {
            0 => None,
            generation => Some(generation),
        }
    }

    /// Whether the node is currently excluded from rounds.
    pub fn is_quarantined(&self, node_id: &str) -> bool {
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(node_id)
    }

    /// Every quarantined node id, sorted.
    pub fn quarantined(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Clear a node's quarantine and its eviction streak: an operator
    /// lever, and what the pull path calls once the node converges on
    /// its own. `true` iff the node was quarantined.
    pub fn release(&self, node_id: &str) -> bool {
        self.evictions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        self.rejections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id)
    }

    /// Run one two-phase round over every Active session.
    ///
    /// Phase 1 sends `ConfigPrepare` to every target concurrently, each
    /// under [`Replicator::per_node_deadline`]. A semantic rejection
    /// aborts the round (an `ConfigAbort` goes to every prepared node,
    /// best effort). Otherwise phase 2 commits the prepared set and
    /// records what each node reports as applied.
    pub async fn replicate(
        &self,
        sessions: &SessionRegistry,
        accepted: &AcceptedConfig,
        payload: ConfigPayload,
    ) -> ReplicationReport {
        let _round = self.round.lock().await;
        self.in_flight.store(payload.generation, Ordering::Relaxed);
        let report = self.run_round(sessions, accepted, payload).await;
        self.in_flight.store(0, Ordering::Relaxed);
        *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(report.clone());
        report
    }

    async fn run_round(
        &self,
        sessions: &SessionRegistry,
        accepted: &AcceptedConfig,
        payload: ConfigPayload,
    ) -> ReplicationReport {
        let mut report = ReplicationReport {
            generation: payload.generation,
            hash: payload.hash.clone(),
            started_unix: unix_now(),
            ..ReplicationReport::default()
        };

        let mut targets: Vec<(String, RpcEndpoint<ClusterFrame>)> = Vec::new();
        for (node_id, endpoint, applied) in sessions.active_sessions() {
            if self.is_quarantined(&node_id) {
                report.skipped_quarantined.push(node_id);
            } else if applied.break_glass && self.honour_break_glass(&node_id) {
                report.skipped_break_glass.push(node_id);
            } else {
                self.clear_break_glass_claim(&node_id);
                report.targets.push(node_id.clone());
                targets.push((node_id, endpoint));
            }
        }

        let mut prepared: Vec<(String, RpcEndpoint<ClusterFrame>)> = Vec::new();
        let mut outcomes: JoinSet<(String, PrepareOutcome)> = JoinSet::new();
        for (node_id, endpoint) in &targets {
            let node_id = node_id.clone();
            let endpoint = endpoint.clone();
            let request = ClusterRequest::config_prepare(ConfigPrepare {
                generation: payload.generation,
                hash: payload.hash.clone(),
                blob: payload.blob.clone(),
            });
            let deadline = self.per_node_deadline;
            outcomes.spawn(async move {
                let outcome = prepare_one(&endpoint, request, deadline).await;
                (node_id, outcome)
            });
        }
        let by_id: HashMap<&str, &RpcEndpoint<ClusterFrame>> = targets
            .iter()
            .map(|(id, endpoint)| (id.as_str(), endpoint))
            .collect();
        while let Some(joined) = outcomes.join_next().await {
            let Ok((node_id, outcome)) = joined else {
                // A panicking Prepare task is a bug in this crate, not
                // a peer fact; the node simply gets no verdict and the
                // round proceeds without it.
                continue;
            };
            match outcome {
                PrepareOutcome::Prepared => {
                    self.note_prepared(&node_id);
                    if let Some(endpoint) = by_id.get(node_id.as_str()) {
                        prepared.push((node_id.clone(), (*endpoint).clone()));
                    }
                    report.prepared.push(node_id);
                }
                PrepareOutcome::Rejected(reason) => {
                    if self.note_rejection(&node_id) {
                        tracing::warn!(
                            node_id = %node_id,
                            threshold = self.quarantine_threshold,
                            "node quarantined from configuration replication after consecutive semantic rejections; it no longer aborts the fleet's rounds and converges by pull once it can take a generation"
                        );
                    }
                    report.rejected.push((node_id, reason));
                }
                PrepareOutcome::Evicted(reason) => {
                    if self.note_eviction(&node_id) {
                        tracing::warn!(
                            node_id = %node_id,
                            threshold = self.quarantine_threshold,
                            "node quarantined from configuration replication after consecutive \
                             transport failures; it converges by pull or an operator releases it"
                        );
                    }
                    report.evicted.push((node_id, reason));
                }
            }
        }

        if !report.rejected.is_empty() {
            // The generation is NOT published: it never becomes the
            // version the fleet converges on, so no follower learns it
            // from a heartbeat and pulls it behind the abort's back.
            // The control plane is now ahead of its own fleet, which is
            // the honest state and what the caller logs.
            report.aborted = true;
            abort_all(&prepared, payload.generation, self.per_node_deadline).await;
            finish(&mut report);
            return report;
        }

        // Prepare succeeded fleet-wide: this is the all-or-none point,
        // and the generation becomes the one the fleet converges on.
        // Every commit below, and every pull from here on, refers to
        // it.
        accepted.publish(payload.clone());

        let mut commits: JoinSet<(String, Result<AppliedConfig, String>)> = JoinSet::new();
        for (node_id, endpoint) in prepared {
            let deadline = self.per_node_deadline;
            let generation = payload.generation;
            let hash = payload.hash.clone();
            commits.spawn(async move {
                let outcome = commit_one(&endpoint, generation, &hash, deadline).await;
                (node_id, outcome)
            });
        }
        while let Some(joined) = commits.join_next().await {
            let Ok((node_id, outcome)) = joined else {
                continue;
            };
            match outcome {
                Ok(applied) => {
                    sessions.record_applied(&node_id, applied);
                    report.committed.push(node_id);
                }
                Err(reason) => report.commit_failed.push((node_id, reason)),
            }
        }

        finish(&mut report);
        report
    }

    /// Record a transport eviction; `true` when it just crossed the
    /// quarantine threshold.
    fn note_eviction(&self, node_id: &str) -> bool {
        let streak = {
            let mut evictions = self.evictions.lock().unwrap_or_else(|p| p.into_inner());
            let entry = evictions.entry(node_id.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        if streak < self.quarantine_threshold {
            return false;
        }
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(node_id.to_string())
    }

    /// Whether a node's asserted break-glass window is still inside
    /// the longest one an operator can legitimately open.
    ///
    /// A genuine window is capped by the API at
    /// `MAX_BREAK_GLASS_SECS`, so a node still claiming one well past
    /// that cap is either lying or has lost its own timer, and either
    /// way it stops being a reason to skip it. The clock starts at the
    /// first round that saw the claim, which over-counts by at most one
    /// round interval and never under-counts.
    fn honour_break_glass(&self, node_id: &str) -> bool {
        let mut since = self
            .break_glass_since
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let first = *since
            .entry(node_id.to_string())
            .or_insert_with(Instant::now);
        if first.elapsed() <= MAX_HONOURED_BREAK_GLASS {
            return true;
        }
        tracing::warn!(
            node_id = %node_id,
            cap_s = MAX_HONOURED_BREAK_GLASS.as_secs(),
            "node has claimed a break-glass window for longer than one can legitimately last; it is being addressed by replication again"
        );
        false
    }

    /// Forget a node's break-glass claim once it stops making it.
    ///
    /// This is also where the honour clock resets, which is worth a
    /// line: a node that stops claiming for one round and claims again
    /// starts a fresh `MAX_HONOURED_BREAK_GLASS`, so the cap bounds one
    /// continuous claim, not a node's lifetime out of replication. The
    /// round it did not claim in made it a target, and a refusal there
    /// counts toward quarantine, so the escape is not free; it is
    /// logged so an operator reading the drift alert can tell a
    /// legitimate close from a node cycling its claim (Epic 9 close,
    /// security audit).
    fn clear_break_glass_claim(&self, node_id: &str) {
        let removed = self
            .break_glass_since
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        if let Some(since) = removed {
            let claimed_s = since.elapsed().as_secs();
            if since.elapsed() > MAX_HONOURED_BREAK_GLASS / 2 {
                tracing::warn!(
                    node_id = %node_id,
                    claimed_s,
                    "node stopped claiming break-glass after most of the honoured window; \
                     its next claim starts a fresh window"
                );
            } else {
                tracing::info!(
                    node_id = %node_id,
                    claimed_s,
                    "node stopped claiming break-glass; it is addressed by replication again"
                );
            }
        }
    }

    /// Count one SEMANTIC rejection and quarantine the node past the
    /// threshold. `true` iff this call quarantined it.
    ///
    /// A rejection is cheap for the peer and expensive for everyone
    /// else: it aborts the round fleet-wide. Without a streak of its
    /// own a node could reject every generation forever, well inside
    /// the deadline, and never accrue a transport eviction. The
    /// threshold is the same one transport failures use, so "three
    /// strikes and you converge by pull" reads the same way whatever
    /// the node did.
    fn note_rejection(&self, node_id: &str) -> bool {
        let streak = {
            let mut rejections = self.rejections.lock().unwrap_or_else(|p| p.into_inner());
            let entry = rejections.entry(node_id.to_string()).or_insert(0);
            *entry = entry.saturating_add(1);
            *entry
        };
        if streak < self.quarantine_threshold {
            return false;
        }
        self.quarantined
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(node_id.to_string())
    }

    /// A node that staged the generation is healthy again.
    fn note_prepared(&self, node_id: &str) {
        self.evictions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        self.rejections
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
    }
}

/// Sort every list, stamp the finish time, and log the round.
fn finish(report: &mut ReplicationReport) {
    report.targets.sort();
    report.prepared.sort();
    report.committed.sort();
    report.skipped_quarantined.sort();
    report.skipped_break_glass.sort();
    report.evicted.sort();
    report.rejected.sort();
    report.commit_failed.sort();
    report.finished_unix = unix_now();
    tracing::info!(
        generation = report.generation,
        targets = report.targets.len(),
        prepared = report.prepared.len(),
        committed = report.committed.len(),
        evicted = report.evicted.len(),
        rejected = report.rejected.len(),
        commit_failed = report.commit_failed.len(),
        skipped_quarantined = report.skipped_quarantined.len(),
        skipped_break_glass = report.skipped_break_glass.len(),
        aborted = report.aborted,
        "cluster configuration replication round finished"
    );
}

/// One Prepare exchange with one node.
async fn prepare_one(
    endpoint: &RpcEndpoint<ClusterFrame>,
    request: ClusterRequest,
    deadline: Duration,
) -> PrepareOutcome {
    let response = match endpoint.request(request, deadline).await {
        Ok(response) => response,
        Err(e) => return PrepareOutcome::Evicted(format!("prepare transport failure: {e}")),
    };
    let status = response.cluster_status();
    if status != ClusterStatus::Ok {
        return PrepareOutcome::Evicted(format!("prepare refused with status {status:?}"));
    }
    match response.body {
        Some(cluster_response::Body::ConfigPrepareAck(ack)) if ack.accepted => {
            PrepareOutcome::Prepared
        }
        Some(cluster_response::Body::ConfigPrepareAck(ack)) => {
            PrepareOutcome::Rejected(safe_reason(&ack.reason))
        }
        _ => PrepareOutcome::Evicted("prepare answered without a verdict".to_string()),
    }
}

/// One Commit exchange with one prepared node.
async fn commit_one(
    endpoint: &RpcEndpoint<ClusterFrame>,
    generation: u64,
    hash: &str,
    deadline: Duration,
) -> Result<AppliedConfig, String> {
    let response = endpoint
        .request(ClusterRequest::config_commit(generation), deadline)
        .await
        .map_err(|e| format!("commit transport failure: {e}"))?;
    let status = response.cluster_status();
    if status != ClusterStatus::Ok {
        return Err(format!("commit refused with status {status:?}"));
    }
    match response.body {
        Some(cluster_response::Body::ConfigCommitAck(ack)) => {
            if !config_hash_is_valid(&ack.applied_hash) {
                return Err("commit acknowledged with a malformed hash".to_string());
            }
            // This is the one exchange where the control plane already
            // knows the right answer, so it checks instead of
            // believing. A node that acknowledges some other version
            // has not applied what was committed, and recording its
            // claim would make it permanently invisible to drift
            // detection.
            if ack.applied_generation != generation || ack.applied_hash != hash {
                return Err(format!(
                    "commit acknowledged generation {} instead of {generation}",
                    ack.applied_generation
                ));
            }
            Ok(AppliedConfig {
                generation: ack.applied_generation,
                hash: ack.applied_hash,
                break_glass: false,
            })
        }
        _ => Err("commit answered without an acknowledgement".to_string()),
    }
}

/// Best-effort Abort to every node that staged the generation.
async fn abort_all(
    prepared: &[(String, RpcEndpoint<ClusterFrame>)],
    generation: u64,
    deadline: Duration,
) {
    let mut aborts: JoinSet<()> = JoinSet::new();
    for (node_id, endpoint) in prepared {
        let node_id = node_id.clone();
        let endpoint = endpoint.clone();
        aborts.spawn(async move {
            if let Err(e) = endpoint
                .request(ClusterRequest::config_abort(generation), deadline)
                .await
            {
                tracing::warn!(
                    node_id = %node_id,
                    generation,
                    error = %e,
                    "abort of a staged generation was not acknowledged; the follower drops it \
                     when its session ends"
                );
            }
        });
    }
    while aborts.join_next().await.is_some() {}
}

/// A peer-supplied rejection reason, made safe to log and to publish.
///
/// Public because BOTH ends need it: the control plane bounds what a
/// follower says about a blob, and the follower bounds what a control
/// plane's blob makes it say. Either side's string reaches a journal
/// line and a notification channel.
pub fn safe_reason(reason: &str) -> String {
    if reason.is_empty() {
        return "no reason given".to_string();
    }
    if reason.len() > MAX_REJECTION_REASON_BYTES || reason.chars().any(char::is_control) {
        return "reason withheld (malformed)".to_string();
    }
    reason.to_string()
}

/// Unix seconds, saturating to `0` if the clock predates the epoch.
///
/// Crate-visible because [`crate::certs`] stamps its own reports the
/// same way; the two modules must not disagree about what "now" is.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use lorica_command::{IncomingRequests, RpcEndpoint};

    use super::*;
    use crate::limits::cluster_rpc_limits;
    use crate::messages::{
        cluster_request, ClusterResponse, ConfigAbortAck, ConfigCommitAck, ConfigPrepareAck,
    };
    use crate::roster::{NodeIdentity, NodeState, SessionGuard, SessionRegistry};

    const PEER: &str = "192.0.2.10:9444";
    const HASH: &str = "ab";

    fn identity(node_id: &str) -> NodeIdentity {
        NodeIdentity {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            state: NodeState::Active,
            via_previous_certificate: false,
        }
    }

    fn payload(generation: u64) -> ConfigPayload {
        ConfigPayload {
            generation,
            hash: HASH.to_string(),
            blob: vec![1, 2, 3],
        }
    }

    /// What a scripted follower does with a Prepare.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// Stage and commit.
        Accept,
        /// Refuse with a semantic reason.
        Reject,
        /// Never answer anything.
        Silent,
        /// Stage, then acknowledge the commit with a version it was
        /// never asked to apply.
        LieOnCommit,
    }

    /// A scripted follower over an in-process duplex pair, plus the
    /// tallies the assertions read.
    struct Follower {
        /// Kept alive: dropping it deregisters the session.
        _guard: SessionGuard,
        /// Kept alive: dropping it tears down the reader and writer
        /// tasks that carry the follower's replies.
        _endpoint: RpcEndpoint<ClusterFrame>,
        prepares: Arc<AtomicUsize>,
        commits: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    }

    /// Register a scripted follower in `registry` and return its
    /// tallies. The control-plane half of the duplex goes into the
    /// registry, the follower half is driven by a spawned task.
    fn spawn_follower(
        registry: &Arc<SessionRegistry>,
        node_id: &str,
        behaviour: Behaviour,
        applied: AppliedConfig,
    ) -> Follower {
        let (cp_side, follower_side) = tokio::io::duplex(64 * 1024);
        let (cp_endpoint, _cp_incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(cp_side, cluster_rpc_limits());
        let (follower_endpoint, follower_incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(follower_side, cluster_rpc_limits());
        let peer: SocketAddr = PEER.parse().expect("addr");
        let guard = registry.register(&identity(node_id), peer, cp_endpoint, "1.7.0", 50, applied);
        let prepares = Arc::new(AtomicUsize::new(0));
        let commits = Arc::new(AtomicUsize::new(0));
        let aborts = Arc::new(AtomicUsize::new(0));
        if behaviour != Behaviour::Silent {
            tokio::spawn(serve_follower(
                follower_incoming,
                behaviour,
                Arc::clone(&prepares),
                Arc::clone(&commits),
                Arc::clone(&aborts),
            ));
        }
        Follower {
            _guard: guard,
            _endpoint: follower_endpoint,
            prepares,
            commits,
            aborts,
        }
    }

    async fn serve_follower(
        mut incoming: IncomingRequests<ClusterFrame>,
        behaviour: Behaviour,
        prepares: Arc<AtomicUsize>,
        commits: Arc<AtomicUsize>,
        aborts: Arc<AtomicUsize>,
    ) {
        while let Some(request) = incoming.recv().await {
            let reply = match &request.request().body {
                Some(cluster_request::Body::ConfigPrepare(_)) => {
                    prepares.fetch_add(1, Ordering::SeqCst);
                    let accepted = behaviour != Behaviour::Reject;
                    ClusterResponse::ok(cluster_response::Body::ConfigPrepareAck(
                        ConfigPrepareAck {
                            accepted,
                            reason: if accepted {
                                String::new()
                            } else {
                                "unknown field in the blob".to_string()
                            },
                        },
                    ))
                }
                Some(cluster_request::Body::ConfigCommit(commit)) => {
                    commits.fetch_add(1, Ordering::SeqCst);
                    let applied_generation = match behaviour {
                        Behaviour::LieOnCommit => u64::MAX,
                        _ => commit.generation,
                    };
                    ClusterResponse::ok(cluster_response::Body::ConfigCommitAck(ConfigCommitAck {
                        applied_generation,
                        applied_hash: HASH.to_string(),
                    }))
                }
                Some(cluster_request::Body::ConfigAbort(_)) => {
                    aborts.fetch_add(1, Ordering::SeqCst);
                    ClusterResponse::ok(cluster_response::Body::ConfigAbortAck(ConfigAbortAck {}))
                }
                _ => ClusterResponse::refusal(ClusterStatus::UnsupportedMethod),
            };
            if request.reply_frame(reply).await.is_err() {
                return;
            }
        }
    }

    fn fast(replicator: &mut Replicator) {
        replicator.per_node_deadline = Duration::from_millis(300);
    }

    #[tokio::test]
    async fn a_full_round_prepares_commits_and_records_what_each_node_applied() {
        let registry = SessionRegistry::new();
        let a = spawn_follower(
            &registry,
            "node-a",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let b = spawn_follower(
            &registry,
            "node-b",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        let report = replicator.replicate(&registry, &accepted, payload(7)).await;
        assert_eq!(report.targets, vec!["node-a", "node-b"]);
        assert_eq!(report.prepared, vec!["node-a", "node-b"]);
        assert_eq!(report.committed, vec!["node-a", "node-b"]);
        assert!(!report.aborted);
        assert!(report.evicted.is_empty() && report.rejected.is_empty());
        assert_eq!(a.prepares.load(Ordering::SeqCst), 1);
        assert_eq!(b.commits.load(Ordering::SeqCst), 1);
        assert_eq!(a.aborts.load(Ordering::SeqCst), 0);

        // The registry now knows what each node runs.
        let applied = registry.applied("node-a").expect("node-a is live");
        assert_eq!(applied.generation, 7);
        assert_eq!(applied.hash, HASH);
        assert_eq!(replicator.last_report().expect("a round ran"), report);
        assert_eq!(replicator.in_flight(), None);
        drop((a, b));
    }

    #[tokio::test]
    async fn a_semantic_rejection_aborts_the_round_for_every_prepared_node() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let bad = spawn_follower(
            &registry,
            "node-b",
            Behaviour::Reject,
            AppliedConfig::default(),
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        let report = replicator.replicate(&registry, &accepted, payload(8)).await;
        assert!(report.aborted);
        assert_eq!(report.prepared, vec!["node-a"]);
        assert!(report.committed.is_empty());
        assert_eq!(
            report.rejected,
            vec![(
                "node-b".to_string(),
                "unknown field in the blob".to_string()
            )]
        );
        // The node that staged it is told to drop it; nobody committed.
        assert_eq!(good.commits.load(Ordering::SeqCst), 0);
        assert_eq!(good.aborts.load(Ordering::SeqCst), 1);
        assert!(registry
            .applied("node-a")
            .is_some_and(|a| a == AppliedConfig::default()));
        // And the generation is NOT published, so no follower learns it
        // from a heartbeat and pulls it behind the abort's back.
        assert_eq!(
            accepted.version(),
            ConfigVersion::default(),
            "an aborted generation must never become the version the fleet converges on"
        );
        assert!(
            accepted.payload().is_none(),
            "an aborted generation must not be servable by a convergence pull"
        );
        drop((good, bad));
    }

    #[tokio::test]
    async fn a_node_that_rejects_every_generation_is_quarantined_and_stops_aborting_the_fleet() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let bad = spawn_follower(
            &registry,
            "node-b",
            Behaviour::Reject,
            AppliedConfig::default(),
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        // A semantic rejection answers well inside the deadline, so it
        // never accrues a TRANSPORT eviction: without a streak of its
        // own, one node would veto every generation forever at no cost.
        for generation in 1..DEFAULT_QUARANTINE_THRESHOLD as u64 + 1 {
            let report = replicator
                .replicate(&registry, &accepted, payload(generation))
                .await;
            assert!(report.aborted, "generation {generation}");
        }
        assert!(replicator.is_quarantined("node-b"));

        // Quarantined, it is skipped and the fleet moves again.
        let report = replicator.replicate(&registry, &accepted, payload(9)).await;
        assert!(!report.aborted);
        assert_eq!(report.committed, vec!["node-a"]);
        assert_eq!(report.skipped_quarantined, vec!["node-b"]);
        assert_eq!(accepted.version().generation, 9);
        drop((good, bad));
    }

    #[tokio::test]
    async fn a_commit_acknowledging_another_generation_is_a_commit_failure() {
        let registry = SessionRegistry::new();
        let liar = spawn_follower(
            &registry,
            "node-a",
            Behaviour::LieOnCommit,
            AppliedConfig::default(),
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        let report = replicator.replicate(&registry, &accepted, payload(6)).await;
        assert_eq!(report.prepared, vec!["node-a"]);
        assert!(
            report.committed.is_empty(),
            "a node that acknowledges a version it was not asked to apply has not committed"
        );
        assert_eq!(report.commit_failed.len(), 1);
        // Its claim must not reach the registry, or it would read as
        // in sync forever and drift detection would never see it.
        assert_ne!(
            registry.applied("node-a").map(|a| a.generation),
            Some(u64::MAX)
        );
        drop(liar);
    }

    #[tokio::test]
    async fn a_silent_node_is_evicted_then_quarantined_and_release_clears_it() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let silent = spawn_follower(
            &registry,
            "node-b",
            Behaviour::Silent,
            AppliedConfig::default(),
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        for generation in 1..=2 {
            let report = replicator
                .replicate(&registry, &accepted, payload(generation))
                .await;
            assert!(!report.aborted, "a transport failure must not veto a round");
            assert_eq!(report.committed, vec!["node-a"]);
            assert_eq!(report.evicted.len(), 1, "generation {generation}");
            assert!(report.skipped_quarantined.is_empty());
        }
        assert!(!replicator.is_quarantined("node-b"));

        // Third consecutive eviction: quarantined.
        let report = replicator.replicate(&registry, &accepted, payload(3)).await;
        assert_eq!(report.evicted.len(), 1);
        assert!(replicator.is_quarantined("node-b"));
        assert_eq!(replicator.quarantined(), vec!["node-b"]);

        // From now on it is not even addressed.
        let report = replicator.replicate(&registry, &accepted, payload(4)).await;
        assert_eq!(report.targets, vec!["node-a"]);
        assert_eq!(report.skipped_quarantined, vec!["node-b"]);
        assert!(report.evicted.is_empty());

        assert!(replicator.release("node-b"));
        assert!(!replicator.release("node-b"), "already released");
        let report = replicator.replicate(&registry, &accepted, payload(5)).await;
        assert_eq!(report.targets, vec!["node-a", "node-b"]);
        assert_eq!(good.prepares.load(Ordering::SeqCst), 5);
        drop((good, silent));
    }

    #[tokio::test]
    async fn a_break_glass_node_is_skipped_without_being_evicted() {
        let registry = SessionRegistry::new();
        let normal = spawn_follower(
            &registry,
            "node-a",
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let broken_glass = spawn_follower(
            &registry,
            "node-b",
            Behaviour::Accept,
            AppliedConfig {
                generation: 2,
                hash: HASH.to_string(),
                break_glass: true,
            },
        );
        let mut replicator = Replicator::new();
        fast(&mut replicator);
        let accepted = AcceptedConfig::new();

        let report = replicator.replicate(&registry, &accepted, payload(9)).await;
        assert_eq!(report.targets, vec!["node-a"]);
        assert_eq!(report.skipped_break_glass, vec!["node-b"]);
        assert_eq!(report.committed, vec!["node-a"]);
        assert_eq!(broken_glass.prepares.load(Ordering::SeqCst), 0);
        assert!(!replicator.is_quarantined("node-b"));
        drop((normal, broken_glass));
    }

    #[test]
    fn a_peer_supplied_reason_never_reaches_a_report_verbatim_when_malformed() {
        assert_eq!(safe_reason("hash mismatch"), "hash mismatch");
        assert_eq!(safe_reason(""), "no reason given");
        assert_eq!(
            safe_reason("forged\nlog line"),
            "reason withheld (malformed)"
        );
        assert_eq!(
            safe_reason(&"x".repeat(MAX_REJECTION_REASON_BYTES + 1)),
            "reason withheld (malformed)"
        );
    }

    #[test]
    fn a_version_and_an_applied_state_agree_only_on_both_halves() {
        let current = ConfigVersion {
            generation: 4,
            hash: "abcd".to_string(),
        };
        assert!(!current.is_behind(&AppliedConfig {
            generation: 4,
            hash: "abcd".to_string(),
            break_glass: false,
        }));
        assert!(current.is_behind(&AppliedConfig {
            generation: 4,
            hash: "beef".to_string(),
            break_glass: false,
        }));
        assert!(current.is_behind(&AppliedConfig::default()));
        assert!(!ConfigVersion::default().is_behind(&AppliedConfig::default()));
    }

    #[test]
    fn a_payload_yields_its_version_half() {
        assert_eq!(
            payload(3).version(),
            ConfigVersion {
                generation: 3,
                hash: HASH.to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_round_with_no_live_session_is_an_empty_report() {
        let registry = SessionRegistry::new();
        let replicator = Replicator::new();
        let accepted = AcceptedConfig::new();
        assert_eq!(replicator.last_report(), None);
        let report = replicator.replicate(&registry, &accepted, payload(1)).await;
        assert!(report.targets.is_empty() && !report.aborted);
        assert_eq!(report.generation, 1);
        assert!(report.finished_unix >= report.started_unix);
        assert_eq!(replicator.last_report(), Some(report));
    }
}
