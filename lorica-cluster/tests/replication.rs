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

//! Story 9.4 end-to-end over real mTLS on 127.0.0.1: a real
//! `OperationalListener` with its fleet layer on one side, real
//! `Dialer`s carrying a `FollowerHandler` on the other, and the
//! `Replicator` driving the rounds between them.
//!
//! Covered: a Prepare/Commit round landing on the follower and in the
//! registry, a semantic rejection aborting the round for the node that
//! had already staged it, a follower behind the control plane pulling
//! at the handshake, and a break-glass follower being skipped.
//!
//! Test hygiene: every await that depends on another task sits under an
//! explicit timeout, so a regression fails in seconds instead of
//! hanging a CI run.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lorica_cluster::arc_swap::ArcSwap;
use lorica_cluster::enroll::{BoxFuture, RenewGrant, RenewRequest, SessionHandler};
use lorica_cluster::handshake::HandshakeConfig;
use lorica_cluster::listener::{
    FleetHooks, OperationalConfig, OperationalHandle, OperationalListener, OperationalStats,
};
use lorica_cluster::messages::cluster_response;
use lorica_cluster::replication::{
    AppliedConfig, ConfigPayload, ConfigVersion, ReplicationReport, Replicator,
};
use lorica_cluster::{
    operational_server_config, ClusterCa, ClusterRequest, ConfigPull, Dialer, DialerConfig,
    DialerHandle, FollowerHandler, NodeIdentity, NodeState, Roster, SessionHandle,
    SessionRegistry, SwappableAcceptor,
};

const CP_HOST: &str = "cp.cluster.internal";
const WAIT: Duration = Duration::from_secs(10);
const SCHEMA: u32 = 50;

/// A plausible canonical hash: 64 lowercase hex characters.
fn hash_for(generation: u64) -> String {
    format!("{generation:064x}")
}

fn payload(generation: u64) -> ConfigPayload {
    ConfigPayload {
        generation,
        hash: hash_for(generation),
        blob: vec![7, 8, 9],
    }
}

fn install_ring() {
    let _ = lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default();
}

struct ControlPlanePki {
    ca: ClusterCa,
    server_cert: String,
    server_key: String,
}

fn control_plane_pki() -> ControlPlanePki {
    let ca = ClusterCa::generate("Lorica Cluster CA").expect("ca");
    let (server_cert, server_key) = ca.issue_server_leaf(CP_HOST).expect("server leaf");
    ControlPlanePki {
        ca,
        server_cert,
        server_key,
    }
}

/// A node identity issued on a bare key, the way enrollment does it.
struct Node {
    node_id: String,
    cert_pem: String,
    key_pem: String,
    fingerprint: String,
}

fn issue_node(pki: &ControlPlanePki, node_id: &str) -> Node {
    let (spki, key_pem) = lorica_cluster::ca::generate_node_keypair().expect("keypair");
    let issued = pki
        .ca
        .issue_node_leaf_for_public_key(node_id, &spki)
        .expect("issue");
    Node {
        node_id: node_id.to_string(),
        cert_pem: issued.cert_pem,
        key_pem,
        fingerprint: issued.fingerprint_sha256,
    }
}

async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The control plane's lifecycle hooks. Only the convergence pull
/// matters here; the rest exist because the trait requires them.
#[derive(Default)]
struct ControlPlaneHooks {
    /// What a pull hands back. `None` answers "you are up to date".
    available: Mutex<Option<ConfigPayload>>,
    pulls: AtomicUsize,
}

impl SessionHandler for ControlPlaneHooks {
    fn on_session_established(
        &self,
        _node_id: &str,
        _via_previous_certificate: bool,
        _peer: SocketAddr,
        _build_version: &str,
        _schema_version: u32,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn on_renew(&self, _request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>> {
        Box::pin(async { Err("renewals are not part of this suite".to_string()) })
    }

    fn on_leave(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async { Err("leave is not part of this suite".to_string()) })
    }

    fn on_identity_refused(
        &self,
        _fingerprint: &str,
        _peer: SocketAddr,
        _reason: &'static str,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn on_protocol_violation(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async {})
    }

    fn on_config_pull(
        &self,
        _node_id: &str,
        _applied: AppliedConfig,
    ) -> BoxFuture<'_, Result<Option<ConfigPayload>, String>> {
        Box::pin(async move {
            self.pulls.fetch_add(1, Ordering::SeqCst);
            Ok(self.available.lock().expect("lock").clone())
        })
    }
}

/// A running control plane: listener, fleet layer, coordinator.
struct Fleet {
    addr: SocketAddr,
    stats: Arc<OperationalStats>,
    sessions: Arc<SessionRegistry>,
    hooks: Arc<ControlPlaneHooks>,
    config_version: Arc<ArcSwap<ConfigVersion>>,
    replicator: Replicator,
    handle: OperationalHandle,
}

impl Fleet {
    /// Publish a configuration version, the way the binary does after
    /// persisting a mutation.
    fn publish(&self, version: ConfigVersion) {
        self.config_version.store(Arc::new(version));
    }

    async fn replicate(&self, payload: ConfigPayload) -> ReplicationReport {
        tokio::time::timeout(WAIT, self.replicator.replicate(&self.sessions, payload))
            .await
            .expect("a replication round must finish inside the test budget")
    }
}

async fn spawn_control_plane(pki: &ControlPlanePki, nodes: &[&Node]) -> Fleet {
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(
        operational_server_config(pki.ca.cert_pem(), &pki.server_cert, &pki.server_key)
            .expect("server config"),
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");

    let roster = Arc::new(Roster::new());
    let entries: HashMap<String, NodeIdentity> = nodes
        .iter()
        .map(|node| {
            (
                node.fingerprint.clone(),
                NodeIdentity {
                    node_id: node.node_id.clone(),
                    name: node.node_id.clone(),
                    state: NodeState::Active,
                    via_previous_certificate: false,
                },
            )
        })
        .collect();
    roster.replace(entries);

    let sessions = SessionRegistry::new();
    let hooks = Arc::new(ControlPlaneHooks::default());
    let mut config =
        OperationalConfig::new(listener, acceptor, HandshakeConfig::new(SCHEMA));
    config.fleet = Some(FleetHooks {
        roster,
        sessions: Arc::clone(&sessions),
        handler: Arc::clone(&hooks) as Arc<dyn SessionHandler>,
    });
    let config_version = Arc::clone(&config.config_version);
    let stats = Arc::clone(&config.stats);
    let handle = OperationalListener::spawn(config);

    let mut replicator = Replicator::new();
    // A wedged follower must not stall the whole suite; the eviction
    // path is unit-tested at length in `src/replication.rs`.
    replicator.per_node_deadline = Duration::from_secs(5);
    Fleet {
        addr,
        stats,
        sessions,
        hooks,
        config_version,
        replicator,
        handle,
    }
}

/// A follower runtime that stages and applies in memory, and pulls
/// when the dialer tells it that it is behind.
struct TestFollower {
    /// Refuse every Prepare with a semantic reason (the abort path).
    reject: bool,
    applied: Mutex<AppliedConfig>,
    staged: Mutex<Option<ConfigPayload>>,
    prepares: AtomicUsize,
    commits: AtomicUsize,
    aborts: AtomicUsize,
    behind: AtomicUsize,
    pulled: Mutex<Option<ConfigPayload>>,
}

impl TestFollower {
    fn new(reject: bool, break_glass: bool) -> Arc<Self> {
        Arc::new(Self {
            reject,
            applied: Mutex::new(AppliedConfig {
                generation: 0,
                hash: String::new(),
                break_glass,
            }),
            staged: Mutex::new(None),
            prepares: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            behind: AtomicUsize::new(0),
            pulled: Mutex::new(None),
        })
    }

    fn applied(&self) -> AppliedConfig {
        self.applied.lock().expect("lock").clone()
    }
}

/// Read one of a follower's tallies.
fn count(counter: &AtomicUsize) -> usize {
    counter.load(Ordering::SeqCst)
}

impl FollowerHandler for TestFollower {
    fn applied_config(&self) -> AppliedConfig {
        self.applied()
    }

    fn on_prepare(&self, payload: ConfigPayload) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            if self.reject {
                return Err("unknown field in the pushed configuration".to_string());
            }
            *self.staged.lock().expect("lock") = Some(payload);
            Ok(())
        })
    }

    fn on_commit(&self, generation: u64) -> BoxFuture<'_, Result<AppliedConfig, String>> {
        Box::pin(async move {
            self.commits.fetch_add(1, Ordering::SeqCst);
            let staged = self.staged.lock().expect("lock").take();
            let Some(staged) = staged.filter(|s| s.generation == generation) else {
                return Err(format!("no generation {generation} staged"));
            };
            let mut applied = self.applied.lock().expect("lock");
            applied.generation = staged.generation;
            applied.hash = staged.hash;
            Ok(applied.clone())
        })
    }

    fn on_abort(&self, _generation: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            *self.staged.lock().expect("lock") = None;
        })
    }

    fn on_behind(&self, session: SessionHandle, _current: ConfigVersion) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.behind.fetch_add(1, Ordering::SeqCst);
            let applied = self.applied();
            let request = ClusterRequest::config_pull(ConfigPull {
                applied_generation: applied.generation,
                applied_hash: applied.hash,
            });
            let Ok(response) = session.endpoint.request(request, WAIT).await else {
                return;
            };
            let Some(cluster_response::Body::ConfigPullAck(ack)) = response.body else {
                return;
            };
            if ack.up_to_date {
                return;
            }
            let pulled = ConfigPayload {
                generation: ack.generation,
                hash: ack.hash,
                blob: ack.blob,
            };
            {
                let mut applied = self.applied.lock().expect("lock");
                applied.generation = pulled.generation;
                applied.hash = pulled.hash.clone();
            }
            *self.pulled.lock().expect("lock") = Some(pulled);
        })
    }
}

/// Spawn a real dialer for `node` carrying `follower`.
fn spawn_follower(
    pki: &ControlPlanePki,
    node: &Node,
    addr: SocketAddr,
    follower: Arc<TestFollower>,
    heartbeat_interval: Duration,
) -> DialerHandle {
    let mut config = DialerConfig::new(
        &format!("127.0.0.1:{}", addr.port()),
        CP_HOST,
        pki.ca.cert_pem(),
        &node.cert_pem,
        &node.key_pem,
        SCHEMA,
    )
    .with_node_name(&node.node_id)
    .with_follower(follower as Arc<dyn FollowerHandler>);
    config.heartbeat_interval = heartbeat_interval;
    config.request_timeout = Duration::from_secs(5);
    config.connect_timeout = Duration::from_secs(5);
    config.base_backoff = Duration::from_millis(50);
    config.default_backoff_cap = Duration::from_millis(400);
    Dialer::spawn(config).expect("dialer spawns")
}

/// Long enough that no heartbeat fires during a test that only cares
/// about the push path (the reader does not time out between frames).
const QUIET: Duration = Duration::from_secs(30);

#[tokio::test]
async fn a_prepare_commit_round_lands_the_generation_on_the_follower_and_in_the_registry() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    let fleet = spawn_control_plane(&pki, &[&node]).await;

    let follower = TestFollower::new(false, false);
    let dialer = spawn_follower(&pki, &node, fleet.addr, Arc::clone(&follower), QUIET);
    eventually("the follower to register", || {
        fleet.sessions.is_connected("node-a")
    })
    .await;

    let report = fleet.replicate(payload(1)).await;
    assert!(!report.aborted, "nothing rejected: {report:?}");
    assert_eq!(report.targets, vec!["node-a".to_string()]);
    assert_eq!(report.prepared, vec!["node-a".to_string()]);
    assert_eq!(report.committed, vec!["node-a".to_string()]);
    assert!(report.evicted.is_empty() && report.commit_failed.is_empty());

    // The follower applied it...
    assert_eq!(follower.applied().generation, 1);
    assert_eq!(follower.applied().hash, hash_for(1));
    assert_eq!(count(&follower.prepares), 1);
    assert_eq!(count(&follower.commits), 1);
    assert_eq!(count(&follower.aborts), 0);
    // ...and the control plane's registry knows it (the drift input).
    let recorded = fleet.sessions.applied("node-a").expect("node-a is live");
    assert_eq!(recorded.generation, 1);
    assert_eq!(recorded.hash, hash_for(1));
    assert_eq!(fleet.replicator.last_report(), Some(report));

    dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_rejecting_follower_aborts_the_round_for_the_node_that_had_staged_it() {
    install_ring();
    let pki = control_plane_pki();
    let good_node = issue_node(&pki, "node-a");
    let bad_node = issue_node(&pki, "node-b");
    let fleet = spawn_control_plane(&pki, &[&good_node, &bad_node]).await;

    let good = TestFollower::new(false, false);
    let bad = TestFollower::new(true, false);
    let good_dialer = spawn_follower(&pki, &good_node, fleet.addr, Arc::clone(&good), QUIET);
    let bad_dialer = spawn_follower(&pki, &bad_node, fleet.addr, Arc::clone(&bad), QUIET);
    eventually("both followers to register", || {
        fleet.sessions.is_connected("node-a") && fleet.sessions.is_connected("node-b")
    })
    .await;

    let report = fleet.replicate(payload(2)).await;
    assert!(report.aborted, "a semantic rejection aborts fleet-wide");
    assert_eq!(report.prepared, vec!["node-a".to_string()]);
    assert!(report.committed.is_empty(), "nobody applies an aborted round");
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].0, "node-b");
    assert_eq!(
        report.rejected[0].1,
        "unknown field in the pushed configuration"
    );

    // The node that staged it was told to drop it.
    eventually("the abort to reach the follower that staged it", || {
        count(&good.aborts) == 1
    })
    .await;
    assert_eq!(count(&good.commits), 0);
    assert_eq!(good.applied().generation, 0, "nothing was applied");
    assert_eq!(count(&bad.aborts), 0, "a rejecting node never staged it");

    good_dialer.shutdown();
    bad_dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_follower_behind_the_control_plane_pulls_and_the_pull_is_served() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    let fleet = spawn_control_plane(&pki, &[&node]).await;

    // The control plane is on generation 5 and can hand it over; the
    // follower has applied nothing, so the HelloAck alone makes it
    // pull (AC #7).
    let current = payload(5);
    fleet.publish(ConfigVersion {
        generation: current.generation,
        hash: current.hash.clone(),
    });
    *fleet.hooks.available.lock().expect("lock") = Some(current.clone());

    let follower = TestFollower::new(false, false);
    let dialer = spawn_follower(
        &pki,
        &node,
        fleet.addr,
        Arc::clone(&follower),
        Duration::from_millis(200),
    );

    eventually("the follower to notice it is behind", || {
        count(&follower.behind) >= 1
    })
    .await;
    eventually("the pull to be served and applied", || {
        follower.applied().generation == 5
    })
    .await;
    assert_eq!(follower.applied().hash, hash_for(5));
    assert_eq!(
        *follower.pulled.lock().expect("lock"),
        Some(current),
        "the follower received the blob, not just the version"
    );
    assert!(fleet.hooks.pulls.load(Ordering::SeqCst) >= 1);
    assert!(fleet.stats.config_pulls_served.load(Ordering::Relaxed) >= 1);
    assert_eq!(fleet.stats.config_pull_refusals.load(Ordering::Relaxed), 0);
    let stats = dialer.stats();
    assert!(stats.behind_detected.load(Ordering::Relaxed) >= 1);
    assert_eq!(stats.protocol_violations.load(Ordering::Relaxed), 0);

    // Converged: further heartbeats must not re-trigger a pull.
    let settled = count(&follower.behind);
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        count(&follower.behind),
        settled,
        "a converged follower must stop pulling"
    );

    dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_break_glass_follower_is_skipped_by_the_round() {
    install_ring();
    let pki = control_plane_pki();
    let normal_node = issue_node(&pki, "node-a");
    let broken_glass_node = issue_node(&pki, "node-b");
    let fleet = spawn_control_plane(&pki, &[&normal_node, &broken_glass_node]).await;

    let normal = TestFollower::new(false, false);
    let broken_glass = TestFollower::new(false, true);
    let normal_dialer = spawn_follower(&pki, &normal_node, fleet.addr, Arc::clone(&normal), QUIET);
    let broken_glass_dialer = spawn_follower(
        &pki,
        &broken_glass_node,
        fleet.addr,
        Arc::clone(&broken_glass),
        QUIET,
    );
    eventually("both followers to register", || {
        fleet.sessions.is_connected("node-a") && fleet.sessions.is_connected("node-b")
    })
    .await;

    let report = fleet.replicate(payload(3)).await;
    assert_eq!(report.targets, vec!["node-a".to_string()]);
    assert_eq!(report.skipped_break_glass, vec!["node-b".to_string()]);
    assert_eq!(report.committed, vec!["node-a".to_string()]);
    assert_eq!(normal.applied().generation, 3);
    // Untouched, and NOT quarantined: break-glass is a declared state,
    // not a failure.
    assert_eq!(count(&broken_glass.prepares), 0);
    assert_eq!(broken_glass.applied().generation, 0);
    assert!(!fleet.replicator.is_quarantined("node-b"));

    normal_dialer.shutdown();
    broken_glass_dialer.shutdown();
    fleet.handle.shutdown();
}
