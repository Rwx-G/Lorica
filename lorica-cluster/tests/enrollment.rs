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

//! Story 9.3 integration tests over real TLS on 127.0.0.1: token
//! redemption through the pinned joiner (IV1's concurrency shape),
//! identity from the certificate (IV3), revocation at the TLS
//! handshake and synchronous session teardown (IV2), and the renew /
//! leave exchanges on an established session.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use lorica_cluster::enroll::{
    BoxFuture, EnrollGrant, EnrollRefusal, EnrollRequest, EnrollmentHandler, RenewGrant,
    RenewRequest, SessionHandler,
};
use lorica_cluster::handshake::{client_handshake, HandshakeConfig};
use lorica_cluster::listener::{
    EnrollmentListener, EnrollmentStats, FleetHooks, OperationalConfig, OperationalListener,
    OperationalStats, PreAuthBudgets,
};
use lorica_cluster::messages::{cluster_response, Renew};
use lorica_cluster::{
    client_config, enrollment_server_config, join, leaf_spki_sha256, operational_server_config,
    operational_server_config_with_crl, token, ClusterCa, ClusterFrame, ClusterRequest,
    ClusterStatus, JoinError, JoinParams, NodeIdentity, NodeState, RevokedEntry, Roster,
    SessionRegistry, SwappableAcceptor,
};
use lorica_command::RpcEndpoint;

const CP_HOST: &str = "cp.cluster.internal";
const WAIT: Duration = Duration::from_secs(10);

fn install_ring() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
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
    serial_hex: String,
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
        serial_hex: issued.serial_hex,
    }
}

async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    l.local_addr().expect("addr")
}

async fn eventually<F: FnMut() -> bool>(what: &str, mut f: F) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !f() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for: {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A redemption handler with one token: grants once (compare-and-swap
/// burn, the store's conditional UPDATE in miniature), refuses every
/// other attempt.
struct OneTokenHandler {
    public_id: String,
    hmac_key: [u8; 32],
    secret_hmac: String,
    burned: AtomicBool,
    ca_pem: String,
    node_cert_pem: String,
    refused: AtomicUsize,
}

impl EnrollmentHandler for OneTokenHandler {
    fn redeem(&self, request: EnrollRequest) -> BoxFuture<'_, Result<EnrollGrant, EnrollRefusal>> {
        Box::pin(async move {
            let stored = if request.public_id == self.public_id {
                self.secret_hmac.clone()
            } else {
                token::dummy_secret_hmac_hex()
            };
            if request.public_id != self.public_id
                || !token::verify_secret(&self.hmac_key, &request.secret, &stored)
            {
                self.refused.fetch_add(1, Ordering::SeqCst);
                return Err(EnrollRefusal::Refused("unknown token or wrong secret"));
            }
            if self
                .burned
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                self.refused.fetch_add(1, Ordering::SeqCst);
                return Err(EnrollRefusal::Refused("token already redeemed"));
            }
            Ok(EnrollGrant {
                node_id: "node-1".to_string(),
                cert_pem: self.node_cert_pem.clone(),
                ca_pem: self.ca_pem.clone(),
                status: "pending".to_string(),
                cert_not_after: "2027-01-01T00:00:00+00:00".to_string(),
            })
        })
    }
}

#[tokio::test]
async fn one_token_three_simultaneous_joiners_exactly_one_enrolls() {
    install_ring();
    let pki = control_plane_pki();
    let node = issue_node(&pki, "node-1");
    let pin = leaf_spki_sha256(&pki.server_cert).expect("pin");
    let hmac_key = [9u8; 32];
    let minted = token::mint(&hmac_key, &pin).expect("mint");
    let handler = Arc::new(OneTokenHandler {
        public_id: minted.public_id.clone(),
        hmac_key,
        secret_hmac: minted.secret_hmac.clone(),
        burned: AtomicBool::new(false),
        ca_pem: pki.ca.cert_pem().to_string(),
        node_cert_pem: node.cert_pem.clone(),
        refused: AtomicUsize::new(0),
    });

    let addr = free_addr().await;
    let (tokens_tx, tokens_rx) = watch::channel(1u32);
    let stats = Arc::new(EnrollmentStats::default());
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(
        enrollment_server_config(&pki.server_cert, &pki.server_key).expect("config"),
    )));
    let handle = EnrollmentListener::spawn(
        addr,
        acceptor,
        tokens_rx,
        PreAuthBudgets::default(),
        Arc::clone(&stats),
        Arc::clone(&handler) as Arc<dyn EnrollmentHandler>,
    );
    let mut bound = handle.bound.clone();
    eventually("listener to open", || bound.borrow_and_update().is_some()).await;

    let parsed = token::parse(&minted.token).expect("parse");
    let params = |name: &str| JoinParams {
        enrollment_addr: addr.to_string(),
        expected_host: CP_HOST.to_string(),
        token: parsed.clone(),
        public_key_der: lorica_cluster::ca::generate_node_keypair()
            .expect("keypair")
            .0,
        node_name: name.to_string(),
        build_version: "test".to_string(),
        schema_version: 50,
        timeout: WAIT,
    };
    // IV1: three simultaneous redemptions of ONE token.
    let (a, b, c) = tokio::join!(
        join(params("joiner-a")),
        join(params("joiner-b")),
        join(params("joiner-c"))
    );
    let outcomes = [a, b, c];
    let granted = outcomes.iter().filter(|o| o.is_ok()).count();
    assert_eq!(granted, 1, "exactly one joiner wins: {outcomes:?}");
    assert!(outcomes
        .iter()
        .filter(|o| o.is_err())
        .all(|o| matches!(o, Err(JoinError::Refused))));
    let grant = outcomes.into_iter().find_map(Result::ok).expect("grant");
    assert_eq!(grant.node_id, "node-1");
    assert_eq!(grant.ca_pem, pki.ca.cert_pem());

    // Sequential replay after the win is refused too.
    assert!(matches!(join(params("joiner-d")).await, Err(JoinError::Refused)));
    assert_eq!(stats.enrollments_granted.load(Ordering::Relaxed), 1);
    assert_eq!(stats.enrollments_refused.load(Ordering::Relaxed), 3);
    assert_eq!(handler.refused.load(Ordering::SeqCst), 3);

    // A token pinning another key never reaches the handler: the TLS
    // layer refuses the control plane (AC #2).
    let other_pin = [0x42u8; 32];
    let rogue = token::mint(&hmac_key, &other_pin).expect("mint");
    let mut rogue_params = params("joiner-e");
    rogue_params.token = token::parse(&rogue.token).expect("parse");
    assert!(matches!(join(rogue_params).await, Err(JoinError::Transport(_))));
    // A wrong expected host is refused the same way.
    let mut wrong_host = params("joiner-f");
    wrong_host.expected_host = "other.internal".to_string();
    assert!(matches!(join(wrong_host).await, Err(JoinError::Transport(_))));
    assert_eq!(handler.refused.load(Ordering::SeqCst), 3, "TLS refusals never reach the handler");

    drop(tokens_tx);
    handle.shutdown();
}

/// Records lifecycle events; serves renewals with a fixed grant.
#[derive(Default)]
struct RecordingSessionHandler {
    established: AtomicUsize,
    identity_refused: AtomicUsize,
    renewals: AtomicUsize,
    leaves: AtomicUsize,
    violations: AtomicUsize,
    last_established_node: std::sync::Mutex<Option<(String, bool)>>,
}

impl SessionHandler for RecordingSessionHandler {
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
            self.established.fetch_add(1, Ordering::SeqCst);
            *self.last_established_node.lock().expect("lock") =
                Some((node_id, via_previous_certificate));
        })
    }

    fn on_renew(&self, request: RenewRequest) -> BoxFuture<'_, Result<RenewGrant, String>> {
        Box::pin(async move {
            self.renewals.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.node_id, "node-a", "identity comes from the certificate");
            assert!(request.peer.ip().is_loopback(), "the peer travels with the request");
            Ok(RenewGrant {
                cert_pem: "-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----"
                    .to_string(),
                cert_not_after: "2027-01-01T00:00:00+00:00".to_string(),
            })
        })
    }

    fn on_leave(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            self.leaves.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }

    fn on_identity_refused(
        &self,
        _fingerprint: &str,
        _peer: SocketAddr,
        _reason: &'static str,
    ) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.identity_refused.fetch_add(1, Ordering::SeqCst);
        })
    }

    fn on_protocol_violation(&self, _node_id: &str, _peer: SocketAddr) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.violations.fetch_add(1, Ordering::SeqCst);
        })
    }
}

struct Fleet {
    addr: SocketAddr,
    acceptor: Arc<SwappableAcceptor>,
    stats: Arc<OperationalStats>,
    roster: Arc<Roster>,
    sessions: Arc<SessionRegistry>,
    handler: Arc<RecordingSessionHandler>,
    handle: lorica_cluster::listener::OperationalHandle,
}

async fn spawn_fleet(pki: &ControlPlanePki, roster_entries: HashMap<String, NodeIdentity>) -> Fleet {
    let acceptor = Arc::new(SwappableAcceptor::new(Arc::new(
        operational_server_config(pki.ca.cert_pem(), &pki.server_cert, &pki.server_key)
            .expect("config"),
    )));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let roster = Arc::new(Roster::new());
    roster.replace(roster_entries);
    let sessions = SessionRegistry::new();
    let handler = Arc::new(RecordingSessionHandler::default());
    let mut config = OperationalConfig::new(listener, Arc::clone(&acceptor), HandshakeConfig::new(50));
    config.fleet = Some(FleetHooks {
        roster: Arc::clone(&roster),
        sessions: Arc::clone(&sessions),
        handler: Arc::clone(&handler) as Arc<dyn SessionHandler>,
    });
    let stats = Arc::clone(&config.stats);
    let handle = OperationalListener::spawn(config);
    Fleet {
        addr,
        acceptor,
        stats,
        roster,
        sessions,
        handler,
        handle,
    }
}

fn identity(node: &Node, state: NodeState) -> (String, NodeIdentity) {
    (
        node.fingerprint.clone(),
        NodeIdentity {
            node_id: node.node_id.clone(),
            name: node.node_id.clone(),
            state,
            via_previous_certificate: false,
        },
    )
}

async fn connect(
    pki: &ControlPlanePki,
    node: &Node,
    addr: SocketAddr,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, String> {
    let tls = client_config(pki.ca.cert_pem(), &node.cert_pem, &node.key_pem).expect("client");
    let connector = TlsConnector::from(Arc::new(tls));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let name = ServerName::try_from(CP_HOST.to_string()).expect("name");
    tokio::time::timeout(WAIT, connector.connect(name, tcp))
        .await
        .map_err(|_| "tls timeout".to_string())?
        .map_err(|e| e.to_string())
}

async fn open_session(
    pki: &ControlPlanePki,
    node: &Node,
    addr: SocketAddr,
) -> Result<RpcEndpoint<ClusterFrame>, String> {
    let tls = connect(pki, node, addr).await?;
    let (endpoint, _incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);
    tokio::time::timeout(
        WAIT,
        client_handshake(&endpoint, &HandshakeConfig::new(50), &node.node_id, WAIT),
    )
    .await
    .map_err(|_| "handshake timeout".to_string())?
    .map_err(|e| e.to_string())?;
    Ok(endpoint)
}

#[tokio::test]
async fn identity_comes_from_the_certificate_and_unknown_ones_are_dropped() {
    install_ring();
    let pki = control_plane_pki();
    let known = issue_node(&pki, "node-a");
    let stranger = issue_node(&pki, "node-stranger");
    let fleet = spawn_fleet(&pki, HashMap::from([identity(&known, NodeState::Pending)])).await;

    // A valid CA-issued certificate with no roster entry never gets
    // to speak (IV3, AC #8).
    let result = open_session(&pki, &stranger, fleet.addr).await;
    assert!(result.is_err(), "stranger must be dropped, got a session");
    eventually("identity refusal to be counted", || {
        fleet.stats.identity_refusals.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(fleet.handler.identity_refused.load(Ordering::SeqCst), 1);
    assert_eq!(fleet.stats.sessions_admitted.load(Ordering::Relaxed), 0);

    // A pending node is admitted and registered (AC #5: visible, no
    // configuration flows to it).
    let endpoint = open_session(&pki, &known, fleet.addr)
        .await
        .expect("pending node admitted");
    eventually("session to register", || fleet.sessions.is_connected("node-a")).await;
    assert_eq!(
        *fleet.handler.last_established_node.lock().expect("lock"),
        Some(("node-a".to_string(), false))
    );
    // A payload cannot rename the session: renew is served under the
    // certificate's node id (asserted inside the handler).
    let (_spki, _) = lorica_cluster::ca::generate_node_keypair().expect("keypair");
    let response = endpoint
        .request(
            ClusterRequest::renew(Renew {
                public_key_der: vec![1, 2, 3],
            }),
            WAIT,
        )
        .await
        .expect("renew answered");
    assert!(matches!(
        response.body,
        Some(cluster_response::Body::RenewAck(_))
    ));
    assert_eq!(fleet.handler.renewals.load(Ordering::SeqCst), 1);
    assert_eq!(fleet.stats.renewals_served.load(Ordering::Relaxed), 1);
    // A renewal flood is a protocol violation: the session is dropped.
    for _ in 0..2 {
        let _ = endpoint
            .request(
                ClusterRequest::renew(Renew {
                    public_key_der: vec![1, 2, 3],
                }),
                WAIT,
            )
            .await
            .expect("renewals within the budget are answered");
    }
    let flood = endpoint
        .request(
            ClusterRequest::renew(Renew {
                public_key_der: vec![1, 2, 3],
            }),
            WAIT,
        )
        .await
        .expect("the violation is answered before the drop");
    assert_eq!(flood.cluster_status(), ClusterStatus::ProtocolViolation);
    assert_eq!(fleet.handler.violations.load(Ordering::SeqCst), 1);
    eventually("flooding session to end", || {
        fleet.stats.sessions_ended.load(Ordering::Relaxed) == 1
    })
    .await;
    // Reconnect for the rest of the flow.
    let endpoint = open_session(&pki, &known, fleet.addr)
        .await
        .expect("re-admitted after the drop");
    eventually("session to register again", || fleet.sessions.is_connected("node-a")).await;

    // A reconnect supersedes the older session (newest wins).
    let second = open_session(&pki, &known, fleet.addr)
        .await
        .expect("reconnect admitted");
    eventually("older session to be killed", || {
        fleet.stats.sessions_killed.load(Ordering::Relaxed) == 1
    })
    .await;
    assert!(endpoint.request(ClusterRequest::leave(), Duration::from_secs(2)).await.is_err());
    assert!(fleet.sessions.is_connected("node-a"));

    // Leave: acknowledged, then the session ends.
    let response = second
        .request(ClusterRequest::leave(), WAIT)
        .await
        .expect("leave answered");
    assert_eq!(response.cluster_status(), ClusterStatus::Ok);
    assert!(matches!(
        response.body,
        Some(cluster_response::Body::LeaveAck(_))
    ));
    assert_eq!(fleet.handler.leaves.load(Ordering::SeqCst), 1);
    eventually("session to end after leave", || {
        !fleet.sessions.is_connected("node-a")
    })
    .await;
    drop(second);
    fleet.handle.shutdown();
}

#[tokio::test]
async fn revoked_node_is_refused_at_tls_and_its_session_ends_synchronously() {
    install_ring();
    let pki = control_plane_pki();
    let a = issue_node(&pki, "node-a");
    let b = issue_node(&pki, "node-b");
    let fleet = spawn_fleet(
        &pki,
        HashMap::from([identity(&a, NodeState::Active), identity(&b, NodeState::Active)]),
    )
    .await;

    let session_a = open_session(&pki, &a, fleet.addr).await.expect("a admitted");
    eventually("a to register", || fleet.sessions.is_connected("node-a")).await;

    // Revoke a: CRL on the acceptor, roster state, session kill.
    let crl = pki
        .ca
        .mint_crl(&[RevokedEntry {
            serial_hex: a.serial_hex.clone(),
            revoked_at: chrono::Utc::now(),
            superseded: false,
        }])
        .expect("crl");
    fleet.acceptor.swap(Arc::new(
        operational_server_config_with_crl(
            pki.ca.cert_pem(),
            &pki.server_cert,
            &pki.server_key,
            Some(crl),
        )
        .expect("config with CRL"),
    ));
    fleet.roster.replace(HashMap::from([
        identity(&a, NodeState::Revoked),
        identity(&b, NodeState::Active),
    ]));
    assert!(fleet.sessions.kill("node-a"), "a had a live session");

    // IV2 second half: the live session is gone NOW, not at the next
    // heartbeat.
    eventually("a's session to be torn down", || {
        fleet.stats.sessions_killed.load(Ordering::Relaxed) == 1
    })
    .await;
    assert!(session_a
        .request(ClusterRequest::heartbeat(lorica_cluster::Heartbeat { timestamp_ms: 1 }), Duration::from_secs(2))
        .await
        .is_err());
    assert!(!fleet.sessions.is_connected("node-a"));

    // IV2 first half: a's next attempt fails at the TLS handshake;
    // no application byte is processed, no identity resolution runs.
    let tls_failures_before = fleet.stats.tls_failures.load(Ordering::Relaxed);
    let refusals_before = fleet.stats.identity_refusals.load(Ordering::Relaxed);
    assert!(open_session(&pki, &a, fleet.addr).await.is_err());
    eventually("TLS refusal to be counted", || {
        fleet.stats.tls_failures.load(Ordering::Relaxed) == tls_failures_before + 1
    })
    .await;
    assert_eq!(fleet.stats.identity_refusals.load(Ordering::Relaxed), refusals_before);

    // b is unaffected by a's revocation.
    let session_b = open_session(&pki, &b, fleet.addr).await.expect("b admitted");
    eventually("b to register", || fleet.sessions.is_connected("node-b")).await;
    drop(session_b);
    drop(session_a);
    fleet.handle.shutdown();
}

#[tokio::test]
async fn a_superseded_certificate_is_accepted_until_the_new_one_connects() {
    install_ring();
    let pki = control_plane_pki();
    let old = issue_node(&pki, "node-a");
    let new = issue_node(&pki, "node-a");
    let mut roster = HashMap::from([identity(&new, NodeState::Active)]);
    roster.insert(
        old.fingerprint.clone(),
        NodeIdentity {
            node_id: "node-a".to_string(),
            name: "node-a".to_string(),
            state: NodeState::Active,
            via_previous_certificate: true,
        },
    );
    let fleet = spawn_fleet(&pki, roster).await;
    let via_old = open_session(&pki, &old, fleet.addr)
        .await
        .expect("superseded certificate still admitted in its grace window");
    eventually("session to register", || fleet.sessions.is_connected("node-a")).await;
    assert_eq!(
        *fleet.handler.last_established_node.lock().expect("lock"),
        Some(("node-a".to_string(), true))
    );
    drop(via_old);
    let via_new = open_session(&pki, &new, fleet.addr)
        .await
        .expect("new certificate admitted");
    eventually("handler to see the new-certificate session", || {
        fleet.handler.last_established_node.lock().expect("lock").as_ref()
            == Some(&("node-a".to_string(), false))
    })
    .await;
    assert_eq!(fleet.handler.established.load(Ordering::SeqCst), 2);
    drop(via_new);
    fleet.handle.shutdown();
}
