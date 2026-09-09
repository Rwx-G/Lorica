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
//! had already staged it AND leaving the generation unpublished, a
//! follower behind the control plane pulling at the handshake, a
//! break-glass follower being skipped, and a node awaiting activation
//! being refused the configuration it asks for.
//!
//! Story 9.5 rides the SAME harness, deliberately: certificate
//! distribution is a second directed pair on the same sessions, and
//! the interesting assertions are about who receives key material, not
//! about the transport. Covered here: a push reaching only the
//! resolved recipients, a follower pull answered over the live
//! session, a node awaiting activation refused a certificate pull, and
//! a follower that pushes certificates UPWARDS losing its session.
//! Plus the HTTP-01 fan-out (AC #6): one node taking the token while
//! another refuses it, reported per node so the ACME solver can refuse
//! the order rather than let the authority fail opaquely.
//!
//! Test hygiene: every await that depends on another task sits under an
//! explicit timeout, so a regression fails in seconds instead of
//! hanging a CI run.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lorica_cluster::certs::{CertBundle, CertDistributor, CertInstallReport};
use lorica_cluster::challenge::ChallengeFanout;
use lorica_cluster::enroll::{BoxFuture, RenewGrant, RenewRequest, SessionHandler};
use lorica_cluster::handshake::HandshakeConfig;
use lorica_cluster::listener::{
    FleetHooks, OperationalConfig, OperationalHandle, OperationalListener, OperationalStats,
};
use lorica_cluster::messages::{
    cluster_response, CertMaterial, CertPull, CertPush, TelemetryPush, TelemetryPushAck,
    MAX_CONFIG_HASH_BYTES,
};
use lorica_cluster::replication::{
    AcceptedConfig, AppliedConfig, ConfigPayload, ConfigVersion, ReplicationReport, Replicator,
};
use lorica_cluster::{
    operational_server_config, ClusterCa, ClusterRequest, ConfigPull, Dialer, DialerConfig,
    DialerHandle, FollowerHandler, NodeIdentity, NodeState, Roster, SessionHandle, SessionRegistry,
    SwappableAcceptor,
};

const CP_HOST: &str = "cp.cluster.internal";
const WAIT: Duration = Duration::from_secs(10);
const SCHEMA: u32 = 50;

/// A plausible canonical hash: 64 lowercase hex characters.
fn hash_for(generation: u64) -> String {
    format!("{generation:064x}")
}

/// A plausible HTTP-01 challenge: the token is base64url, which the
/// decode boundary enforces because it becomes a path segment.
const IDENTIFIER: &str = "edge.example.com";
const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
const KEY_AUTH: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXd";

/// A well-formed bundle: the digest has the `sha256:` shape the
/// canonical blob carries, so it passes the decode boundary.
fn cert_bundle(cert_id: &str) -> CertBundle {
    CertBundle {
        cert_id: cert_id.to_string(),
        domain: format!("{cert_id}.example.com"),
        cert_pem: "-----BEGIN CERTIFICATE-----".to_string(),
        key_pem: format!("-----BEGIN PRIVATE KEY----- {cert_id}"),
        key_digest: format!("sha256:{}", "a".repeat(MAX_CONFIG_HASH_BYTES)),
    }
}

fn payload(generation: u64) -> ConfigPayload {
    ConfigPayload {
        generation,
        hash: hash_for(generation),
        blob: vec![7, 8, 9],
    }
}

fn install_ring() {
    let _ =
        lorica_cluster::tokio_rustls::rustls::crypto::ring::default_provider().install_default();
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
    /// What a certificate pull hands back, whatever was asked for:
    /// entitlement is resolved control-plane side (Story 9.5 D3), so
    /// the answer is deliberately not a function of the request.
    certs_available: Mutex<Vec<CertBundle>>,
    cert_pulls: AtomicUsize,
    /// The ids the last certificate pull carried, so a test can assert
    /// what actually crossed the wire.
    cert_pull_ids: Mutex<Vec<String>>,
    /// Story 9.6.
    telemetry_pushes: AtomicUsize,
    /// The last batch that crossed the wire.
    telemetry_seen: Mutex<Option<TelemetryPush>>,
    /// The node id the control plane WOULD stamp rows with: taken from
    /// the session, never from the batch (D2).
    telemetry_node: Mutex<Option<String>>,
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

    fn on_cert_pull(
        &self,
        _node_id: &str,
        cert_ids: Vec<String>,
    ) -> BoxFuture<'_, Result<Vec<CertBundle>, String>> {
        Box::pin(async move {
            self.cert_pulls.fetch_add(1, Ordering::SeqCst);
            *self.cert_pull_ids.lock().expect("lock") = cert_ids;
            Ok(self.certs_available.lock().expect("lock").clone())
        })
    }

    fn on_telemetry_push(
        &self,
        node_id: &str,
        batch: TelemetryPush,
    ) -> BoxFuture<'_, Result<TelemetryPushAck, String>> {
        let node_id = node_id.to_string();
        Box::pin(async move {
            self.telemetry_pushes.fetch_add(1, Ordering::SeqCst);
            // The identity a stored row would be stamped with comes
            // from the session, never from the batch (Story 9.6 D2).
            *self.telemetry_node.lock().expect("lock") = Some(node_id);
            let ack = TelemetryPushAck {
                accepted_access: batch.access.len() as u64,
                accepted_waf: batch.waf.len() as u64,
                accepted_bans: batch.bans.len() as u64,
                retry_after_s: 0,
                access_cursor: batch.access_cursor,
                waf_cursor: batch.waf_cursor,
                accepted_audit: batch.audit.len() as u64,
                audit_cursor: batch.audit_cursor,
            };
            *self.telemetry_seen.lock().expect("lock") = Some(batch);
            Ok(ack)
        })
    }
}

/// A running control plane: listener, fleet layer, coordinator.
struct Fleet {
    addr: SocketAddr,
    stats: Arc<OperationalStats>,
    sessions: Arc<SessionRegistry>,
    hooks: Arc<ControlPlaneHooks>,
    accepted: AcceptedConfig,
    replicator: Replicator,
    distributor: CertDistributor,
    challenges: ChallengeFanout,
    handle: OperationalHandle,
}

impl Fleet {
    /// Publish an accepted configuration, the way the binary does at
    /// boot from what the store already holds.
    fn publish(&self, payload: ConfigPayload) {
        self.accepted.publish(payload);
    }

    /// The version the handshake and every heartbeat advertise.
    fn advertised(&self) -> ConfigVersion {
        self.accepted.version()
    }

    async fn replicate(&self, payload: ConfigPayload) -> ReplicationReport {
        tokio::time::timeout(
            WAIT,
            self.replicator
                .replicate(&self.sessions, &self.accepted, payload),
        )
        .await
        .expect("a replication round must finish inside the test budget")
    }
}

async fn spawn_control_plane(pki: &ControlPlanePki, nodes: &[&Node]) -> Fleet {
    spawn_control_plane_with_state(pki, nodes, NodeState::Active).await
}

/// A control plane whose roster puts every node in `state`, so the
/// tests can exercise what a node awaiting activation is allowed to do.
async fn spawn_control_plane_with_state(
    pki: &ControlPlanePki,
    nodes: &[&Node],
    state: NodeState,
) -> Fleet {
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
                    state,
                    via_previous_certificate: false,
                },
            )
        })
        .collect();
    roster.replace(entries);

    let sessions = SessionRegistry::new();
    let hooks = Arc::new(ControlPlaneHooks::default());
    let mut config = OperationalConfig::new(listener, acceptor, HandshakeConfig::new(SCHEMA));
    config.fleet = Some(FleetHooks {
        roster,
        sessions: Arc::clone(&sessions),
        handler: Arc::clone(&hooks) as Arc<dyn SessionHandler>,
    });
    // The listener reads the SAME slot the coordinator publishes into,
    // exactly as `ControlPlane` wires it in the binary.
    let accepted = AcceptedConfig::new();
    config.config_version = accepted.version_handle();
    let stats = Arc::clone(&config.stats);
    let handle = OperationalListener::spawn(config);

    let mut replicator = Replicator::new();
    // A wedged follower must not stall the whole suite; the eviction
    // path is unit-tested at length in `src/replication.rs`.
    replicator.per_node_deadline = Duration::from_secs(5);
    let mut distributor = CertDistributor::new();
    distributor.per_node_deadline = Duration::from_secs(5);
    Fleet {
        addr,
        stats,
        sessions,
        hooks,
        accepted,
        replicator,
        distributor,
        challenges: ChallengeFanout {
            per_node_deadline: Duration::from_secs(5),
        },
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
    /// Story 9.5.
    behaviour: PushBehaviour,
    installed: Mutex<Vec<CertBundle>>,
    cert_pushes: AtomicUsize,
    pulled_certs: Mutex<Vec<CertBundle>>,
    /// `(identifier, token, key_authorization)` this node is serving.
    served: Mutex<Vec<(String, String, String)>>,
    challenge_publishes: AtomicUsize,
    challenge_retractions: AtomicUsize,
    /// Story 9.6: fleet-wide bans this node was told to apply.
    bans_applied: Mutex<Vec<(String, u64, String)>>,
}

/// What a test follower does on the Story 9.5 push paths.
#[derive(Clone, Default)]
struct PushBehaviour {
    /// Ids to ask for the next time the dialer says this node is
    /// behind; empty means it never asks.
    wants: Vec<String>,
    /// Refuse every pushed bundle instead of installing it.
    refuse: bool,
    /// Send a `CertPush` UPWARDS instead of pulling: the direction no
    /// follower may take, and the control plane must end the session.
    push_upward: bool,
    /// Refuse every HTTP-01 publication: the node the ACME solver must
    /// notice before it tells the authority to validate.
    refuse_challenge: bool,
}

impl TestFollower {
    fn new(reject: bool, break_glass: bool) -> Arc<Self> {
        Self::new_with(reject, break_glass, PushBehaviour::default())
    }

    fn new_with(reject: bool, break_glass: bool, behaviour: PushBehaviour) -> Arc<Self> {
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
            behaviour,
            installed: Mutex::new(Vec::new()),
            cert_pushes: AtomicUsize::new(0),
            pulled_certs: Mutex::new(Vec::new()),
            served: Mutex::new(Vec::new()),
            challenge_publishes: AtomicUsize::new(0),
            challenge_retractions: AtomicUsize::new(0),
            bans_applied: Mutex::new(Vec::new()),
        })
    }

    fn applied(&self) -> AppliedConfig {
        self.applied.lock().expect("lock").clone()
    }

    fn installed_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .installed
            .lock()
            .expect("lock")
            .iter()
            .map(|b| b.cert_id.clone())
            .collect();
        ids.sort();
        ids
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

    fn on_cert_push(&self, bundles: Vec<CertBundle>) -> BoxFuture<'_, CertInstallReport> {
        Box::pin(async move {
            self.cert_pushes.fetch_add(1, Ordering::SeqCst);
            if self.behaviour.refuse {
                return CertInstallReport {
                    installed: Vec::new(),
                    refused: bundles
                        .into_iter()
                        .map(|b| (b.cert_id, "no route binds this hostname here".to_string()))
                        .collect(),
                };
            }
            let installed = bundles.iter().map(|b| b.cert_id.clone()).collect();
            self.installed.lock().expect("lock").extend(bundles);
            CertInstallReport {
                installed,
                refused: Vec::new(),
            }
        })
    }

    fn on_challenge_publish(
        &self,
        identifier: String,
        token: String,
        key_authorization: String,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.challenge_publishes.fetch_add(1, Ordering::SeqCst);
            if self.behaviour.refuse_challenge {
                return Err("no data plane is listening on this node".to_string());
            }
            self.served
                .lock()
                .expect("lock")
                .push((identifier, token, key_authorization));
            Ok(())
        })
    }

    fn on_challenge_retract(&self, token: String) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.challenge_retractions.fetch_add(1, Ordering::SeqCst);
            self.served
                .lock()
                .expect("lock")
                .retain(|(_, t, _)| t != &token);
        })
    }

    fn on_ban_push(
        &self,
        client_ip: String,
        duration_s: u64,
        reason: String,
    ) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move {
            self.bans_applied
                .lock()
                .expect("lock")
                .push((client_ip, duration_s, reason));
            Ok(true)
        })
    }

    fn on_behind(&self, session: SessionHandle, _current: ConfigVersion) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.behind.fetch_add(1, Ordering::SeqCst);
            if self.behaviour.push_upward {
                // A follower offering key material to its control
                // plane. The session must not survive it.
                let request = ClusterRequest::cert_push(CertPush {
                    bundles: vec![CertMaterial {
                        cert_id: "cert-forged".to_string(),
                        domain: "forged.example.com".to_string(),
                        cert_pem: "-----BEGIN CERTIFICATE-----".to_string(),
                        key_pem: "-----BEGIN PRIVATE KEY-----".to_string(),
                        key_digest: format!("sha256:{}", "a".repeat(MAX_CONFIG_HASH_BYTES)),
                    }],
                });
                let _ = session.endpoint.request(request, WAIT).await;
                return;
            }
            if !self.behaviour.wants.is_empty() {
                // AC #8: the follower asks for exactly what it counted
                // as missing, and takes whatever subset it is given.
                let request = ClusterRequest::cert_pull(CertPull {
                    cert_ids: self.behaviour.wants.clone(),
                });
                if let Ok(response) = session.endpoint.request(request, WAIT).await {
                    if let Some(cluster_response::Body::CertPullAck(ack)) = response.body {
                        self.pulled_certs
                            .lock()
                            .expect("lock")
                            .extend(ack.bundles.into_iter().map(CertBundle::from_material));
                    }
                }
            }
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
    assert!(
        report.committed.is_empty(),
        "nobody applies an aborted round"
    );
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

    // The abort has to hold: the generation is not advertised, so no
    // heartbeat tells a follower it is behind and no pull hands the
    // rejected configuration out through the back door.
    assert_eq!(
        fleet.advertised(),
        ConfigVersion::default(),
        "an aborted generation must not become the version the fleet converges on"
    );
    let settled = count(&good.behind);
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        count(&good.behind),
        settled,
        "no follower may be told it is behind an aborted generation"
    );

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
    fleet.publish(current.clone());
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

#[tokio::test]
async fn a_certificate_push_reaches_the_resolved_recipient_and_nobody_else() {
    install_ring();
    let pki = control_plane_pki();
    let recipient = issue_node(&pki, "node-a");
    let bystander = issue_node(&pki, "node-b");
    let fleet = spawn_control_plane(&pki, &[&recipient, &bystander]).await;

    let wanted = TestFollower::new(false, false);
    let unwanted = TestFollower::new(false, false);
    let a = spawn_follower(&pki, &recipient, fleet.addr, Arc::clone(&wanted), QUIET);
    let b = spawn_follower(&pki, &bystander, fleet.addr, Arc::clone(&unwanted), QUIET);
    eventually("both followers to register", || {
        fleet.sessions.is_connected("node-a") && fleet.sessions.is_connected("node-b")
    })
    .await;

    // The recipient list is resolved control-plane side (D3) and this
    // call must not widen it, even though both sessions are Active and
    // live.
    let report = tokio::time::timeout(
        WAIT,
        fleet.distributor.push(
            &fleet.sessions,
            &["node-a".to_string()],
            vec![cert_bundle("cert-1"), cert_bundle("cert-2")],
        ),
    )
    .await
    .expect("a push round must finish inside the test budget");

    assert_eq!(report.targets, vec!["node-a".to_string()]);
    assert_eq!(report.installed, vec![("node-a".to_string(), 2)]);
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(
        wanted.installed_ids(),
        vec!["cert-1".to_string(), "cert-2".to_string()]
    );
    assert_eq!(
        unwanted.cert_pushes.load(Ordering::SeqCst),
        0,
        "need-to-know: a live session that was not resolved as a recipient sees no key material"
    );
    // The keys travelled on their own path: nothing about the
    // configuration generation moved (AC #7).
    assert_eq!(fleet.advertised(), ConfigVersion::default());
    assert_eq!(count(&wanted.prepares), 0);
    assert_eq!(a.stats().protocol_violations.load(Ordering::Relaxed), 0);

    a.shutdown();
    b.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_follower_pull_is_answered_with_what_the_control_plane_resolves() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    let fleet = spawn_control_plane(&pki, &[&node]).await;

    // The follower asks for two certificates; the control plane
    // resolves entitlement itself and hands back only one. A shorter
    // answer is the normal case, not an error (D3).
    *fleet.hooks.certs_available.lock().expect("lock") = vec![cert_bundle("cert-1")];
    fleet.publish(payload(5));
    *fleet.hooks.available.lock().expect("lock") = Some(payload(5));

    let follower = TestFollower::new_with(
        false,
        false,
        PushBehaviour {
            wants: vec!["cert-1".to_string(), "cert-2".to_string()],
            ..PushBehaviour::default()
        },
    );
    let dialer = spawn_follower(
        &pki,
        &node,
        fleet.addr,
        Arc::clone(&follower),
        Duration::from_millis(200),
    );

    eventually("the certificate pull to be served", || {
        fleet.hooks.cert_pulls.load(Ordering::SeqCst) >= 1
    })
    .await;
    eventually("the follower to hold the bundle", || {
        !follower.pulled_certs.lock().expect("lock").is_empty()
    })
    .await;
    let pulled = follower.pulled_certs.lock().expect("lock").clone();
    assert_eq!(pulled[0], cert_bundle("cert-1"));
    assert_eq!(
        *fleet.hooks.cert_pull_ids.lock().expect("lock"),
        vec!["cert-1".to_string(), "cert-2".to_string()],
        "the ids the follower named reach the handler verbatim, as a request and not as a grant"
    );
    assert_eq!(fleet.stats.cert_pull_refusals.load(Ordering::Relaxed), 0);
    assert!(fleet.stats.cert_pulls_served.load(Ordering::Relaxed) >= 1);
    assert_eq!(
        dialer.stats().protocol_violations.load(Ordering::Relaxed),
        0
    );

    dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_pending_node_is_refused_a_certificate_pull() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    // Enrolled, session admitted, but no operator has activated it.
    let fleet = spawn_control_plane_with_state(&pki, &[&node], NodeState::Pending).await;

    *fleet.hooks.certs_available.lock().expect("lock") = vec![cert_bundle("cert-1")];
    fleet.publish(payload(4));

    let follower = TestFollower::new_with(
        false,
        false,
        PushBehaviour {
            wants: vec!["cert-1".to_string()],
            ..PushBehaviour::default()
        },
    );
    let dialer = spawn_follower(
        &pki,
        &node,
        fleet.addr,
        Arc::clone(&follower),
        Duration::from_millis(200),
    );

    eventually("the certificate pull to be refused", || {
        fleet.stats.cert_pull_refusals.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(
        fleet.hooks.cert_pulls.load(Ordering::SeqCst),
        0,
        "a pending node's pull must not reach the handler that reads private keys"
    );
    assert_eq!(fleet.stats.cert_pulls_served.load(Ordering::Relaxed), 0);
    assert!(
        follower.pulled_certs.lock().expect("lock").is_empty(),
        "no key material reaches a node awaiting activation"
    );
    // Refused, not disconnected: an unactivated node stays visible.
    assert_eq!(
        dialer.stats().protocol_violations.load(Ordering::Relaxed),
        0
    );

    dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_follower_pushing_certificates_upwards_loses_its_session() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    let fleet = spawn_control_plane(&pki, &[&node]).await;

    // Generation 5 is advertised, so the dialer tells the follower it
    // is behind and the scripted follower takes that as its cue to
    // offer key material to its control plane.
    fleet.publish(payload(5));

    let follower = TestFollower::new_with(
        false,
        false,
        PushBehaviour {
            push_upward: true,
            ..PushBehaviour::default()
        },
    );
    let dialer = spawn_follower(
        &pki,
        &node,
        fleet.addr,
        Arc::clone(&follower),
        Duration::from_millis(200),
    );

    eventually("the control plane to record the violation", || {
        fleet.stats.protocol_violations.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(
        fleet.hooks.cert_pulls.load(Ordering::SeqCst),
        0,
        "a push travelling upwards must never be served as anything"
    );

    dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_node_that_will_not_take_the_token_is_reported_while_the_others_are_delivered() {
    install_ring();
    let pki = control_plane_pki();
    let good_node = issue_node(&pki, "node-a");
    let bad_node = issue_node(&pki, "node-b");
    let fleet = spawn_control_plane(&pki, &[&good_node, &bad_node]).await;

    let good = TestFollower::new(false, false);
    let bad = TestFollower::new_with(
        false,
        false,
        PushBehaviour {
            refuse_challenge: true,
            ..PushBehaviour::default()
        },
    );
    let good_dialer = spawn_follower(&pki, &good_node, fleet.addr, Arc::clone(&good), QUIET);
    let bad_dialer = spawn_follower(&pki, &bad_node, fleet.addr, Arc::clone(&bad), QUIET);
    eventually("both followers to register", || {
        fleet.sessions.is_connected("node-a") && fleet.sessions.is_connected("node-b")
    })
    .await;

    let recipients = vec!["node-a".to_string(), "node-b".to_string()];
    let report = tokio::time::timeout(
        WAIT,
        fleet
            .challenges
            .publish(&fleet.sessions, &recipients, IDENTIFIER, TOKEN, KEY_AUTH),
    )
    .await
    .expect("a challenge fan-out must finish inside the test budget");

    // The transport reports both halves and decides nothing. This is
    // what lets the solver refuse the order instead of telling the
    // authority to validate against a node serving nothing.
    assert_eq!(report.delivered, vec!["node-a".to_string()]);
    assert_eq!(report.failed.len(), 1, "{report:?}");
    assert_eq!(report.failed[0].0, "node-b");
    assert!(!report.is_complete());

    assert_eq!(
        *good.served.lock().expect("lock"),
        vec![(
            IDENTIFIER.to_string(),
            TOKEN.to_string(),
            KEY_AUTH.to_string()
        )]
    );
    assert!(bad.served.lock().expect("lock").is_empty());
    assert_eq!(
        count(&bad.challenge_publishes),
        1,
        "it was asked, and it refused"
    );
    // A refusal is not a protocol violation: the session stays up so
    // the order can be retried once the node is fixed.
    assert_eq!(fleet.stats.protocol_violations.load(Ordering::Relaxed), 0);
    assert_eq!(
        good_dialer
            .stats()
            .protocol_violations
            .load(Ordering::Relaxed),
        0
    );

    // Retraction is best effort and silent, and it reaches the node
    // that refused as readily as the one that took it.
    tokio::time::timeout(
        WAIT,
        fleet
            .challenges
            .retract(&fleet.sessions, &recipients, TOKEN),
    )
    .await
    .expect("a retraction must finish inside the test budget");
    eventually("both followers to be retracted", || {
        count(&good.challenge_retractions) == 1 && count(&bad.challenge_retractions) == 1
    })
    .await;
    assert!(good.served.lock().expect("lock").is_empty());

    good_dialer.shutdown();
    bad_dialer.shutdown();
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_pending_node_is_refused_the_configuration_it_asks_for() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-a");
    // Enrolled, session admitted, but no operator has activated it.
    let fleet = spawn_control_plane_with_state(&pki, &[&node], NodeState::Pending).await;

    let current = payload(4);
    fleet.publish(current.clone());
    *fleet.hooks.available.lock().expect("lock") = Some(current);

    let follower = TestFollower::new(false, false);
    let dialer = spawn_follower(
        &pki,
        &node,
        fleet.addr,
        Arc::clone(&follower),
        Duration::from_millis(200),
    );

    // The HelloAck advertises generation 4, so the follower asks. The
    // pull is refused before the handler is ever consulted, and the
    // node keeps asking rather than being told it is up to date, which
    // is the honest answer: it is behind and not allowed to catch up.
    eventually("the pull to be refused", || {
        fleet.stats.config_pull_refusals.load(Ordering::Relaxed) >= 1
    })
    .await;
    assert_eq!(
        fleet.hooks.pulls.load(Ordering::SeqCst),
        0,
        "a pending node's pull must not reach the handler that encodes the blob"
    );
    assert_eq!(fleet.stats.config_pulls_served.load(Ordering::Relaxed), 0);
    assert_eq!(
        follower.applied().generation,
        0,
        "no configuration reaches a node awaiting activation"
    );
    assert!(follower.pulled.lock().expect("lock").is_none());

    dialer.shutdown();
    fleet.handle.shutdown();
}
