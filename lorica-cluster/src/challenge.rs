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

//! HTTP-01 challenge fan-out (Story 9.5 AC #6): the single
//! well-formedness rule the wire boundary enforces, and the
//! control-plane [`ChallengeFanout`] that publishes a token to the
//! nodes plausibly serving a hostname and retracts it afterwards.
//!
//! # Why this exists at all
//!
//! The control plane holds the ACME account and drives the order, but
//! the certificate authority validates HTTP-01 against the hostname,
//! which a FOLLOWER serves. Without a channel the authority is told to
//! validate while the nodes it will reach have nothing to answer with,
//! and the failure surfaces as an opaque `NotReady` with no indication
//! of which node broke. That is the failure AC #6 exists to remove.
//!
//! # The transport reports; it does not decide (AC #6)
//!
//! [`ChallengeFanout::publish`] returns a per-node
//! [`ChallengeReport`] and takes NO decision. The caller is the ACME
//! solver, and it is the one that decides whether an order may
//! proceed, because it is the only layer that knows an order is at
//! stake. Deciding here would put that judgement in a crate that
//! cannot see the order, and a later caller with a different tolerance
//! would have to work around it.
//!
//! What the report DOES do is tell the two misses apart
//! ([`ChallengeMiss`], decision D16): a node with no live session, and
//! a live node that refused. Only the second can make the authority
//! see a 404, so only the second blocks an order.
//!
//! Retraction is the mirror image and is best effort: it reports
//! nothing, because the driver calls it unconditionally on both the
//! success and the failure path and has nothing useful to do with a
//! per-node result. The entry's own deadline removes it on a node that
//! never answered.
//!
//! # The follower owns the deadline
//!
//! Nothing in this module carries an expiry. See the note on
//! [`crate::messages::ChallengePublish`]: the node that owns the clock
//! owns the deadline, and a cross-clock timestamp would produce, under
//! skew, either a token already expired on arrival or one outliving
//! its window on a node nobody is watching.
//!
//! # Same gates as certificate distribution
//!
//! Only [`crate::roster::NodeState::Active`] sessions are addressed,
//! the caller-resolved recipient list is never widened, and a node in
//! a break-glass window still receives the token: a challenge is not
//! configuration either, and suspending it would fail an order the
//! operator did not choose to fail.

use std::collections::HashSet;
use std::time::Duration;

use lorica_command::RpcEndpoint;
use tokio::task::JoinSet;

use crate::messages::{
    challenge_key_authorization_is_valid, challenge_token_is_valid, cert_domain_is_valid,
    cluster_response, ChallengePublish, ClusterFrame, ClusterRequest, ClusterStatus,
};
use crate::replication::DEFAULT_PER_NODE_DEADLINE;
use crate::roster::SessionRegistry;

/// Why a recipient is not serving the token.
///
/// The distinction is the caller's whole decision, so it is a type
/// rather than a reason string (decision D16). It mirrors
/// [`crate::replication::PrepareOutcome`]'s split between a node that
/// REFUSED and a node that was merely unreachable, for the same
/// reason: one is a fact about the fleet, the other is a fact about a
/// link.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChallengeMiss {
    /// The recipient has no live Active session. It is not answering
    /// the cluster plane, so it is not answering HTTP either, and a
    /// certificate authority that resolves to it gets a connection
    /// failure whether or not the token was published there.
    Offline,
    /// A node with a live session refused the publication, or the
    /// exchange failed or timed out. This one IS answering HTTP, and
    /// what it will answer is 404.
    Refused(String),
}

impl std::fmt::Display for ChallengeMiss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => f.write_str("no live session for an active node"),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

/// Which nodes took a token and which did not.
///
/// Both vectors are sorted by node id, so two runs of the same fan-out
/// produce identical reports regardless of which follower answered
/// first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChallengeReport {
    /// Node ids now serving the token.
    pub delivered: Vec<String>,
    /// `(node_id, miss)` for every recipient that is not serving it.
    pub failed: Vec<(String, ChallengeMiss)>,
}

impl ChallengeReport {
    /// Whether every recipient took the token.
    pub fn is_complete(&self) -> bool {
        self.failed.is_empty()
    }

    /// The misses that must stop the caller from telling a certificate
    /// authority to validate (decision D16).
    ///
    /// [`ChallengeMiss::Offline`] is deliberately NOT among them. A
    /// node that is not answering the cluster plane is not answering
    /// the authority's fetch either, so refusing to attempt validation
    /// because of it prevents nothing and costs a renewal: with one
    /// follower down, an all-or-nothing verdict stops renewing every
    /// certificate on a fleet-wide route until that node comes back.
    /// A node that IS up and refused the token is the opposite case,
    /// and is what this returns.
    pub fn blocking(&self) -> Vec<&(String, ChallengeMiss)> {
        self.failed
            .iter()
            .filter(|(_, miss)| matches!(miss, ChallengeMiss::Refused(_)))
            .collect()
    }

    /// Recipients skipped because they had no live session.
    pub fn offline(&self) -> Vec<&str> {
        self.failed
            .iter()
            .filter(|(_, miss)| matches!(miss, ChallengeMiss::Offline))
            .map(|(node_id, _)| node_id.as_str())
            .collect()
    }
}

/// Why a publication is not well formed, or `None` when it is.
///
/// One rule for both ends, exactly like
/// [`crate::certs::cert_bundle_defect`]: the follower's decode
/// boundary refuses a malformed publication, and
/// [`ChallengeFanout::publish`] refuses to SEND one. The send-side
/// check is the one that matters, because a malformed publication is a
/// protocol violation on the receiving side, which drops the session:
/// a control-plane bug that produced one bad token would disconnect
/// every follower it reached, in the middle of an order.
pub fn challenge_defect(
    identifier: &str,
    token: &str,
    key_authorization: &str,
) -> Option<&'static str> {
    if !cert_domain_is_valid(identifier) {
        return Some("malformed challenge identifier");
    }
    if !challenge_token_is_valid(token) {
        return Some("malformed challenge token");
    }
    if !challenge_key_authorization_is_valid(key_authorization) {
        return Some("malformed key authorization");
    }
    None
}

/// The control plane's HTTP-01 challenge fan-out (AC #6).
///
/// Stateless on purpose, and deliberately NOT serialized the way
/// [`crate::certs::CertDistributor`] and
/// [`crate::replication::Replicator`] are: two ACME orders for
/// different hostnames have no reason to queue behind each other, and
/// a lock here would add order latency to buy an exclusion nothing
/// needs. Two publications never collide, because a token is unique
/// per authorization and is its own key.
#[derive(Debug, Clone)]
pub struct ChallengeFanout {
    /// Bound on one publication or retraction with one node. Default
    /// [`crate::replication::DEFAULT_PER_NODE_DEADLINE`].
    pub per_node_deadline: Duration,
}

impl Default for ChallengeFanout {
    fn default() -> Self {
        Self::new()
    }
}

impl ChallengeFanout {
    /// A fan-out with the documented default deadline.
    pub fn new() -> Self {
        Self {
            per_node_deadline: DEFAULT_PER_NODE_DEADLINE,
        }
    }

    /// Publish `token` to the named nodes and report per node.
    ///
    /// `recipients` is resolved by the caller, control-plane side and
    /// down to a `node_id`, from `identifier` (the per-SAN hostname,
    /// not the order's primary domain) through the routes bound to it
    /// and their `node_selector`. This method never widens that list,
    /// and it never addresses a session whose node is not
    /// [`crate::roster::NodeState::Active`].
    ///
    /// Takes no all-or-nothing decision: see the module doc. Never
    /// panics and never fails as a whole; a malformed publication is
    /// reported against every recipient and nothing is sent.
    pub async fn publish(
        &self,
        sessions: &SessionRegistry,
        recipients: &[String],
        identifier: &str,
        token: &str,
        key_authorization: &str,
    ) -> ChallengeReport {
        let mut report = ChallengeReport::default();
        if let Some(defect) = challenge_defect(identifier, token, key_authorization) {
            tracing::error!(
                identifier,
                recipients = recipients.len(),
                defect,
                "refusing to distribute a malformed HTTP-01 challenge; nothing was sent"
            );
            // A local bug, not a fleet fact: it must block, so it is
            // recorded as a refusal against every recipient.
            for node_id in recipients {
                report
                    .failed
                    .push((node_id.clone(), ChallengeMiss::Refused(defect.to_string())));
            }
            finish(&mut report);
            return report;
        }

        let mut sends: JoinSet<(String, Result<(), String>)> = JoinSet::new();
        for (node_id, endpoint) in sessions.addressable(recipients) {
            let request = ClusterRequest::challenge_publish(ChallengePublish {
                identifier: identifier.to_string(),
                token: token.to_string(),
                key_authorization: key_authorization.to_string(),
            });
            let deadline = self.per_node_deadline;
            sends.spawn(async move {
                let outcome = publish_one(&endpoint, request, deadline).await;
                (node_id, outcome)
            });
        }
        let mut answered: HashSet<String> = HashSet::new();
        while let Some(joined) = sends.join_next().await {
            let Ok((node_id, outcome)) = joined else {
                // A panicking send task is a bug in this crate. The
                // node has no verdict, so it counts as not having
                // taken the token: for a challenge, silence is never
                // consent.
                continue;
            };
            answered.insert(node_id.clone());
            match outcome {
                Ok(()) => report.delivered.push(node_id),
                Err(reason) => {
                    tracing::warn!(
                        node_id = %node_id,
                        identifier,
                        %reason,
                        "a LIVE follower did not take the HTTP-01 token; it will answer the \
                         certificate authority with a 404, so the caller must not tell the \
                         authority to validate"
                    );
                    report.failed.push((node_id, ChallengeMiss::Refused(reason)));
                }
            }
        }
        // A recipient that never became a target has no live session.
        // It is recorded, but as `Offline`, and the caller does not
        // treat that as a veto: see `ChallengeReport::blocking`.
        for node_id in recipients {
            if !answered.contains(node_id.as_str()) {
                report
                    .failed
                    .push((node_id.clone(), ChallengeMiss::Offline));
            }
        }

        finish(&mut report);
        report
    }

    /// Stop serving `token` on the named nodes. Best effort: no
    /// report, no retry, and a node that never answers drops the entry
    /// on its own deadline.
    ///
    /// Called unconditionally on both the success and the failure path
    /// of an order, mirroring the ACME driver's own cleanup.
    pub async fn retract(&self, sessions: &SessionRegistry, recipients: &[String], token: &str) {
        if !challenge_token_is_valid(token) {
            tracing::error!("refusing to retract a malformed HTTP-01 token; nothing was sent");
            return;
        }
        let mut sends: JoinSet<()> = JoinSet::new();
        for (node_id, endpoint) in sessions.addressable(recipients) {
            let request = ClusterRequest::challenge_retract(token);
            let deadline = self.per_node_deadline;
            sends.spawn(async move {
                if let Err(e) = endpoint.request(request, deadline).await {
                    tracing::warn!(
                        node_id = %node_id,
                        error = %e,
                        "HTTP-01 token retraction was not acknowledged; the follower drops the \
                         entry on its own deadline"
                    );
                }
            });
        }
        while sends.join_next().await.is_some() {}
    }
}

// The intersection itself lives on `SessionRegistry::addressable`,
// shared with certificate distribution. Break-glass is deliberately
// NOT a filter on either fan-out, unlike a replication round: a
// challenge token is not configuration, it overwrites no operator
// edit, and skipping a node would fail an order the operator never
// chose to fail.

/// Sort both lists and log the fan-out.
fn finish(report: &mut ChallengeReport) {
    report.delivered.sort();
    report.failed.sort();
    tracing::info!(
        delivered = report.delivered.len(),
        failed = report.failed.len(),
        complete = report.is_complete(),
        "HTTP-01 challenge fan-out finished"
    );
}

/// One publication exchange with one node.
async fn publish_one(
    endpoint: &RpcEndpoint<ClusterFrame>,
    request: ClusterRequest,
    deadline: Duration,
) -> Result<(), String> {
    let response = endpoint
        .request(request, deadline)
        .await
        .map_err(|e| format!("challenge publish transport failure: {e}"))?;
    let status = response.cluster_status();
    if status != ClusterStatus::Ok {
        return Err(format!("challenge publish refused with status {status:?}"));
    }
    match response.body {
        Some(cluster_response::Body::ChallengePublishAck(_)) => Ok(()),
        _ => Err("challenge publish answered without an acknowledgement".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use lorica_command::{IncomingRequests, RpcEndpoint};

    use super::*;
    use crate::limits::cluster_rpc_limits;
    use crate::messages::{
        cluster_request, ChallengePublishAck, ChallengeRetractAck, ClusterResponse,
    };
    use crate::replication::AppliedConfig;
    use crate::roster::{NodeIdentity, NodeState, SessionGuard, SessionRegistry};

    const PEER: &str = "192.0.2.10:9444";
    const IDENTIFIER: &str = "edge.example.com";
    const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    const KEY_AUTH: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXd";

    fn identity(node_id: &str, state: NodeState) -> NodeIdentity {
        NodeIdentity {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            state,
            via_previous_certificate: false,
        }
    }

    /// What a scripted follower does with a publication.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// Serve the token.
        Accept,
        /// Refuse it (no room, no route, store failure).
        Refuse,
        /// Never answer anything.
        Silent,
    }

    struct Follower {
        /// Kept alive: dropping it deregisters the session.
        _guard: SessionGuard,
        /// Kept alive: dropping it tears down the reader and writer
        /// tasks that carry the follower's replies.
        _endpoint: RpcEndpoint<ClusterFrame>,
        publishes: Arc<AtomicUsize>,
        retractions: Arc<AtomicUsize>,
    }

    fn spawn_follower(
        registry: &Arc<SessionRegistry>,
        node_id: &str,
        state: NodeState,
        behaviour: Behaviour,
        applied: AppliedConfig,
    ) -> Follower {
        let (cp_side, follower_side) = tokio::io::duplex(64 * 1024);
        let (cp_endpoint, _cp_incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(cp_side, cluster_rpc_limits());
        let (follower_endpoint, follower_incoming) =
            RpcEndpoint::<ClusterFrame>::with_limits(follower_side, cluster_rpc_limits());
        let peer: SocketAddr = PEER.parse().expect("addr");
        let guard = registry.register(
            &identity(node_id, state),
            peer,
            cp_endpoint,
            "1.7.0",
            50,
            applied,
        );
        let publishes = Arc::new(AtomicUsize::new(0));
        let retractions = Arc::new(AtomicUsize::new(0));
        if behaviour != Behaviour::Silent {
            tokio::spawn(serve_follower(
                follower_incoming,
                behaviour,
                Arc::clone(&publishes),
                Arc::clone(&retractions),
            ));
        }
        Follower {
            _guard: guard,
            _endpoint: follower_endpoint,
            publishes,
            retractions,
        }
    }

    async fn serve_follower(
        mut incoming: IncomingRequests<ClusterFrame>,
        behaviour: Behaviour,
        publishes: Arc<AtomicUsize>,
        retractions: Arc<AtomicUsize>,
    ) {
        while let Some(request) = incoming.recv().await {
            let reply = match &request.request().body {
                Some(cluster_request::Body::ChallengePublish(_)) => {
                    publishes.fetch_add(1, Ordering::SeqCst);
                    if behaviour == Behaviour::Refuse {
                        ClusterResponse::refusal(ClusterStatus::Unspecified)
                    } else {
                        ClusterResponse::ok(cluster_response::Body::ChallengePublishAck(
                            ChallengePublishAck {},
                        ))
                    }
                }
                Some(cluster_request::Body::ChallengeRetract(_)) => {
                    retractions.fetch_add(1, Ordering::SeqCst);
                    ClusterResponse::ok(cluster_response::Body::ChallengeRetractAck(
                        ChallengeRetractAck {},
                    ))
                }
                _ => ClusterResponse::refusal(ClusterStatus::UnsupportedMethod),
            };
            if request.reply_frame(reply).await.is_err() {
                return;
            }
        }
    }

    fn fanout() -> ChallengeFanout {
        ChallengeFanout {
            per_node_deadline: Duration::from_millis(300),
        }
    }

    fn names(nodes: &[&str]) -> Vec<String> {
        nodes.iter().map(|n| (*n).to_string()).collect()
    }

    async fn publish(
        fanout: &ChallengeFanout,
        registry: &Arc<SessionRegistry>,
        recipients: &[&str],
    ) -> ChallengeReport {
        fanout
            .publish(registry, &names(recipients), IDENTIFIER, TOKEN, KEY_AUTH)
            .await
    }

    #[tokio::test]
    async fn a_publication_reaches_the_named_recipients_and_nobody_else() {
        let registry = SessionRegistry::new();
        let wanted = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let bystander = spawn_follower(
            &registry,
            "node-b",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );

        let report = publish(&fanout(), &registry, &["node-a"]).await;
        assert_eq!(report.delivered, vec!["node-a".to_string()]);
        assert!(report.failed.is_empty());
        assert!(report.is_complete());
        assert_eq!(wanted.publishes.load(Ordering::SeqCst), 1);
        assert_eq!(
            bystander.publishes.load(Ordering::SeqCst),
            0,
            "a live session that was not named must never be asked to answer for a hostname"
        );
        drop((wanted, bystander));
    }

    #[tokio::test]
    async fn a_node_that_refuses_is_reported_while_the_others_are_delivered() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let bad = spawn_follower(
            &registry,
            "node-b",
            NodeState::Active,
            Behaviour::Refuse,
            AppliedConfig::default(),
        );

        // The transport takes NO all-or-nothing decision: it reports
        // both halves and the ACME solver is what refuses the order.
        let report = publish(&fanout(), &registry, &["node-a", "node-b"]).await;
        assert_eq!(report.delivered, vec!["node-a".to_string()]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "node-b");
        assert!(!report.is_complete());
        assert_eq!(
            report.blocking().len(),
            1,
            "node-b is UP and refused, so it will answer the authority with a 404: this one              blocks the order"
        );
        assert_eq!(good.publishes.load(Ordering::SeqCst), 1);
        assert_eq!(bad.publishes.load(Ordering::SeqCst), 1);
        drop((good, bad));
    }

    #[tokio::test]
    async fn a_node_that_never_answers_is_a_failure_because_silence_is_not_consent() {
        let registry = SessionRegistry::new();
        let silent = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Silent,
            AppliedConfig::default(),
        );

        let report = publish(&fanout(), &registry, &["node-a"]).await;
        assert!(report.delivered.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.to_string().contains("transport"));
        assert!(!report.is_complete());
        assert_eq!(
            report.blocking().len(),
            1,
            "a node that holds a session and then goes silent is up: it blocks"
        );
        drop(silent);
    }

    #[tokio::test]
    async fn a_recipient_with_no_live_session_is_reported_but_does_not_block() {
        let registry = SessionRegistry::new();
        let connected = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );

        // node-b was resolved as plausibly serving the hostname and is
        // simply not connected. The caller has to know, so it is
        // reported; but it is NOT a veto (D16), because a node that
        // answers nothing on the cluster plane answers nothing on
        // port 80 either.
        let report = publish(&fanout(), &registry, &["node-a", "node-b"]).await;
        assert_eq!(report.delivered, vec!["node-a".to_string()]);
        assert_eq!(
            report.failed,
            vec![("node-b".to_string(), ChallengeMiss::Offline)]
        );
        assert!(!report.is_complete());
        assert!(
            report.blocking().is_empty(),
            "an offline recipient must not stop an order: refusing here would stop renewing              every certificate on a fleet-wide route while one follower is down"
        );
        assert_eq!(report.offline(), vec!["node-b"]);
        drop(connected);
    }

    #[tokio::test]
    async fn a_session_whose_node_is_not_active_is_skipped_and_reported() {
        let registry = SessionRegistry::new();
        let pending = spawn_follower(
            &registry,
            "node-a",
            NodeState::Pending,
            Behaviour::Accept,
            AppliedConfig::default(),
        );

        let report = publish(&fanout(), &registry, &["node-a"]).await;
        assert_eq!(pending.publishes.load(Ordering::SeqCst), 0);
        assert!(report.delivered.is_empty());
        assert_eq!(report.failed, vec![("node-a".to_string(), ChallengeMiss::Offline)]);
        assert!(!report.is_complete());
        drop(pending);
    }

    #[tokio::test]
    async fn a_break_glass_node_still_receives_the_token() {
        let registry = SessionRegistry::new();
        // A challenge is not configuration: skipping this node would
        // fail an order the operator never chose to fail.
        let broken_glass = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig {
                generation: 2,
                hash: "ab".to_string(),
                break_glass: true,
            },
        );

        let report = publish(&fanout(), &registry, &["node-a"]).await;
        assert_eq!(report.delivered, vec!["node-a".to_string()]);
        assert!(report.is_complete());
        assert_eq!(broken_glass.publishes.load(Ordering::SeqCst), 1);
        drop(broken_glass);
    }

    #[tokio::test]
    async fn a_malformed_publication_is_refused_locally_rather_than_dropping_every_session() {
        let registry = SessionRegistry::new();
        let follower = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let fanout = fanout();

        for (identifier, token, key_auth, expected) in [
            ("", TOKEN, KEY_AUTH, "malformed challenge identifier"),
            (IDENTIFIER, "../../etc/passwd", KEY_AUTH, "malformed challenge token"),
            (IDENTIFIER, TOKEN, "", "malformed key authorization"),
        ] {
            let report = fanout
                .publish(&registry, &names(&["node-a"]), identifier, token, key_auth)
                .await;
            assert!(report.delivered.is_empty());
            assert_eq!(
                report.failed,
                vec![(
                    "node-a".to_string(),
                    ChallengeMiss::Refused(expected.to_string())
                )]
            );
            assert_eq!(
                report.blocking().len(),
                1,
                "a malformed publication is a local bug, and it must block the order"
            );
        }
        assert_eq!(
            follower.publishes.load(Ordering::SeqCst),
            0,
            "a malformed publication is a protocol violation on the far side and would drop the \
             session in the middle of an order"
        );
        drop(follower);
    }

    #[tokio::test]
    async fn a_retraction_reaches_the_recipients_and_reports_nothing() {
        let registry = SessionRegistry::new();
        let wanted = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let bystander = spawn_follower(
            &registry,
            "node-b",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let fanout = fanout();

        fanout
            .retract(&registry, &names(&["node-a"]), TOKEN)
            .await;
        assert_eq!(wanted.retractions.load(Ordering::SeqCst), 1);
        assert_eq!(bystander.retractions.load(Ordering::SeqCst), 0);
        drop((wanted, bystander));
    }

    #[tokio::test]
    async fn a_retraction_survives_a_node_that_never_answers() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let silent = spawn_follower(
            &registry,
            "node-b",
            NodeState::Active,
            Behaviour::Silent,
            AppliedConfig::default(),
        );
        let fanout = fanout();

        // Best effort by contract: the wedged node does not stop the
        // healthy one, and nothing is reported to anybody.
        fanout
            .retract(&registry, &names(&["node-a", "node-b"]), TOKEN)
            .await;
        assert_eq!(good.retractions.load(Ordering::SeqCst), 1);
        drop((good, silent));
    }

    #[tokio::test]
    async fn a_malformed_token_is_never_retracted_on_the_wire() {
        let registry = SessionRegistry::new();
        let follower = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );

        fanout()
            .retract(&registry, &names(&["node-a"]), "../../etc/passwd")
            .await;
        assert_eq!(follower.retractions.load(Ordering::SeqCst), 0);
        drop(follower);
    }

    #[test]
    fn the_well_formedness_rule_covers_every_field_a_node_would_serve() {
        assert_eq!(challenge_defect(IDENTIFIER, TOKEN, KEY_AUTH), None);
        assert_eq!(
            challenge_defect("edge.example.com\nforged", TOKEN, KEY_AUTH),
            Some("malformed challenge identifier")
        );
        assert_eq!(
            challenge_defect(IDENTIFIER, "tok/en", KEY_AUTH),
            Some("malformed challenge token")
        );
        assert_eq!(
            challenge_defect(IDENTIFIER, TOKEN, "auth\r\nInjected: 1"),
            Some("malformed key authorization")
        );
    }

    #[test]
    fn a_report_is_complete_only_when_nothing_failed() {
        let mut report = ChallengeReport {
            delivered: vec!["node-a".to_string()],
            failed: Vec::new(),
        };
        assert!(report.is_complete());
        report
            .failed
            .push(("node-b".to_string(), ChallengeMiss::Refused("no".to_string())));
        assert!(!report.is_complete());
    }

    #[test]
    fn only_a_live_refusal_blocks_an_order() {
        // The D16 boundary, stated once as a unit fact so it cannot be
        // changed by accident: an incomplete report is not the same
        // thing as a report that must stop an order.
        let report = ChallengeReport {
            delivered: vec!["node-a".to_string()],
            failed: vec![
                ("node-b".to_string(), ChallengeMiss::Offline),
                (
                    "node-c".to_string(),
                    ChallengeMiss::Refused("refused with status Unspecified".to_string()),
                ),
            ],
        };
        assert!(!report.is_complete());
        assert_eq!(report.offline(), vec!["node-b"]);
        assert_eq!(report.blocking().len(), 1);
        assert_eq!(report.blocking()[0].0, "node-c");

        let only_offline = ChallengeReport {
            delivered: vec!["node-a".to_string()],
            failed: vec![("node-b".to_string(), ChallengeMiss::Offline)],
        };
        assert!(
            only_offline.blocking().is_empty(),
            "a fleet with one node down still renews its certificates"
        );
    }
}
