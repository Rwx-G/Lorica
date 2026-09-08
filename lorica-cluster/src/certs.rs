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

//! Certificate distribution (Story 9.5): the plain types both sides
//! exchange, the single well-formedness rule the wire boundary
//! enforces, and the control-plane [`CertDistributor`] that runs one
//! best-effort push round over the live sessions.
//!
//! # Why this is not the replication path (AC #7)
//!
//! Configuration replication is two-phase and fleet-wide: a semantic
//! rejection from any node aborts the round for everyone. Certificates
//! must not inherit that. If keys rode the commit path, one slow or
//! drifted follower would block renewals for the whole fleet until
//! expiry, which is the Story 9.4 veto problem with a worse blast
//! radius. So a push here is per node, best effort, and never aborts
//! anything.
//!
//! # Push is the optimisation, pull is the guarantee (D2)
//!
//! [`CertDistributor::push`] exists for latency: at issuance and at
//! renewal, the nodes that are connected get their material
//! immediately. Every failure it records is recoverable, because the
//! follower asks for what it lacks on the pull path
//! ([`crate::enroll::SessionHandler::on_cert_pull`]), which covers a
//! node that was offline, a push that never arrived, and a push that
//! was refused. Nothing in this module retries, and nothing here is
//! fatal to a caller.
//!
//! # The confidentiality boundary is the mutual-TLS channel (D5)
//!
//! There is no per-node public key to wrap a key to: enrollment sends
//! a bare SPKI the control plane never persists. So `key_pem` travels
//! in the clear INSIDE the authenticated channel, and the follower
//! re-encrypts on write through its own store. `key_digest` is the
//! `sha256:<hex>` the canonical blob carries in place of the key, so
//! the follower can check that what arrived is what the configuration
//! announced.
//!
//! # Recipients are resolved by the caller, never widened here (D3)
//!
//! [`CertDistributor::push`] addresses exactly the node ids it is
//! given, intersected with the Active sessions
//! ([`crate::roster::SessionRegistry::addressable`]). It never falls
//! back to "every session" when the list is empty, and it never
//! resolves a name.
//!
//! Names ARE an authorization input, since a route `node_selector`
//! lists them: that is precisely why the resolution happens on the
//! control plane, against the registry, and why the name is bound to
//! the enrollment token rather than chosen by the joining node
//! (`roster.rs`).

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use lorica_command::RpcEndpoint;
use tokio::task::JoinSet;

use crate::messages::{
    cert_digest_is_valid, cert_domain_is_valid, cert_id_is_valid, cluster_response, CertMaterial,
    CertPush, ClusterFrame, ClusterRequest, ClusterStatus,
};
use crate::replication::{safe_reason, unix_now, DEFAULT_PER_NODE_DEADLINE};
use crate::roster::SessionRegistry;

/// Longest a bundle batch may be, in either direction.
///
/// A push carries what one issuance or renewal produced, and a pull
/// answer carries what one node is missing; neither is a fleet-sized
/// list. The cap bounds the frame well under the 4 MiB transport
/// limit and bounds what a peer can make either side allocate.
pub const MAX_CERT_BUNDLES: usize = 64;

/// Longest a pull request list may be.
///
/// Larger than [`MAX_CERT_BUNDLES`] on purpose: a follower may
/// legitimately ask about more certificates than one answer can carry
/// (it enumerates what it lacks), and the control plane answers with
/// the subset it is entitled to.
pub const MAX_CERT_PULL_IDS: usize = 256;

/// One certificate's material as it travels to a follower.
#[derive(Clone, PartialEq, Eq)]
pub struct CertBundle {
    /// The certificate's stable id (its `certificates.id`).
    pub cert_id: String,
    /// The primary hostname the certificate binds to. Display and
    /// diagnostics only, never an authorization input.
    pub domain: String,
    /// PEM leaf plus chain.
    pub cert_pem: String,
    /// PEM private key. Never logged.
    pub key_pem: String,
    /// `sha256:<lowercase hex>` of `key_pem`, the same shape the
    /// canonical blob carries, so a follower can verify what arrived
    /// matches what the configuration announced before writing it.
    pub key_digest: String,
}

/// Redacted on purpose: this type holds a private key, and a bundle
/// reaches a `tracing` field or a test assertion far more easily than
/// anyone intends. The digest identifies the key without disclosing
/// it.
impl fmt::Debug for CertBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertBundle")
            .field("cert_id", &self.cert_id)
            .field("domain", &self.domain)
            .field("cert_pem_len", &self.cert_pem.len())
            .field("key_pem", &"<redacted>")
            .field("key_digest", &self.key_digest)
            .finish()
    }
}

impl CertBundle {
    /// The wire form of this bundle.
    pub fn to_material(&self) -> CertMaterial {
        CertMaterial {
            cert_id: self.cert_id.clone(),
            domain: self.domain.clone(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
            key_digest: self.key_digest.clone(),
        }
    }

    /// The in-crate form of a decoded [`CertMaterial`]. The caller
    /// MUST run [`cert_bundle_defect`] on the result before using it:
    /// this conversion moves peer-supplied strings, it does not
    /// validate them.
    pub fn from_material(material: CertMaterial) -> Self {
        Self {
            cert_id: material.cert_id,
            domain: material.domain,
            cert_pem: material.cert_pem,
            key_pem: material.key_pem,
            key_digest: material.key_digest,
        }
    }
}

/// Why a bundle is not well formed, or `None` when it is.
///
/// One rule, used by BOTH ends and in both directions: the follower's
/// decode boundary refuses a malformed push, the control plane's
/// decode boundary refuses a malformed pull answer, and
/// [`CertDistributor::push`] refuses to SEND one. That last check
/// matters more than it looks: a malformed push is a protocol
/// violation on the receiving side, which drops the session, so a
/// control-plane bug that produced one bad digest would disconnect
/// every follower it reached.
///
/// An empty `cert_pem` or `key_pem` is malformed rather than merely
/// useless: a bundle with no key would install an empty private-key
/// file through the follower's export path, which is exactly the
/// failure Story 9.5 D8 records.
pub fn cert_bundle_defect(bundle: &CertBundle) -> Option<&'static str> {
    if !cert_id_is_valid(&bundle.cert_id) {
        return Some("malformed certificate id");
    }
    if !cert_domain_is_valid(&bundle.domain) {
        return Some("malformed certificate domain");
    }
    if bundle.cert_pem.is_empty() {
        return Some("empty certificate chain");
    }
    if bundle.key_pem.is_empty() {
        return Some("empty private key");
    }
    if !cert_digest_is_valid(&bundle.key_digest) {
        return Some("malformed key digest");
    }
    None
}

/// A peer-supplied certificate id, made safe to log and to publish.
///
/// Public because both ends need it: the control plane bounds the ids
/// a follower names in a refusal, and the follower bounds the ids a
/// control plane pushes. Either string reaches a journal line.
pub fn safe_cert_id(cert_id: &str) -> String {
    if cert_id_is_valid(cert_id) {
        return cert_id.to_string();
    }
    "certificate id withheld (malformed)".to_string()
}

/// What a follower did with a pushed or pulled batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertInstallReport {
    /// Certificate ids now installed with a usable key.
    pub installed: Vec<String>,
    /// `(cert_id, reason)`: refused or failed. Reasons are bounded.
    pub refused: Vec<(String, String)>,
}

/// Outcome of one push round over the live sessions.
///
/// Every vector is sorted by node id, so two runs of the same round
/// produce identical reports regardless of which follower answered
/// first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CertPushReport {
    /// Unix seconds when the round started.
    pub started_unix: u64,
    /// Unix seconds when the round finished.
    pub finished_unix: u64,
    /// Node ids addressed. A recipient with no live Active session is
    /// simply absent: it is not a failure, it converges on the pull
    /// path.
    pub targets: Vec<String>,
    /// `(node_id, installed count)`. A node that answered with zero
    /// installed still appears here, which is how "answered, installed
    /// nothing" stays distinguishable from "never answered".
    pub installed: Vec<(String, usize)>,
    /// `(node_id, reason)`: transport failure or refusal. A node that
    /// installed part of a batch and refused the rest appears in BOTH
    /// [`CertPushReport::installed`] and here.
    pub failed: Vec<(String, String)>,
}

/// Per-node outcome of one push exchange.
enum PushOutcome {
    /// The node answered; `installed` is how many it took, `refused`
    /// what it would not take (both already bounded and sanitised).
    Answered {
        installed: usize,
        refused: Vec<(String, String)>,
    },
    /// Transport timeout, transport error, refusal status or missing
    /// body.
    Failed(String),
}

/// The control plane's certificate push coordinator (AC #7).
///
/// One round at a time: [`CertDistributor::push`] holds an internal
/// lock for its whole duration, so two issuances cannot interleave
/// their batches on the same fleet. Deliberately much simpler than
/// [`crate::replication::Replicator`]: no two-phase protocol, no
/// eviction streaks, no quarantine. A node that fails a push is
/// recorded and the round continues, because by D2 the pull path is
/// what closes the gap and per-node key-state tracking on the control
/// plane is explicitly not wanted (D13).
pub struct CertDistributor {
    /// The last finished round.
    last: Mutex<Option<CertPushReport>>,
    /// Serializes rounds.
    round: tokio::sync::Mutex<()>,
    /// Bound on one push exchange with one node. Default
    /// [`crate::replication::DEFAULT_PER_NODE_DEADLINE`].
    pub per_node_deadline: Duration,
}

impl Default for CertDistributor {
    fn default() -> Self {
        Self::new()
    }
}

impl CertDistributor {
    /// A coordinator with the documented defaults.
    pub fn new() -> Self {
        Self {
            last: Mutex::new(None),
            round: tokio::sync::Mutex::new(()),
            per_node_deadline: DEFAULT_PER_NODE_DEADLINE,
        }
    }

    /// The last finished round, or `None` before the first one.
    pub fn last_report(&self) -> Option<CertPushReport> {
        self.last.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Push `bundles` to the named nodes only.
    ///
    /// `recipients` is resolved by the caller on the control plane
    /// (D3: certificate hostname, then the routes bound to it, then
    /// their `node_selector`, then names resolved against
    /// `cluster_nodes` to a `node_id`). This function never widens
    /// that list, and it skips any session whose node is not
    /// [`crate::roster::NodeState::Active`], which
    /// [`SessionRegistry::active_sessions`] enforces by construction.
    ///
    /// A node in a break-glass window is NOT skipped, unlike a
    /// replication round: by D9 a private key overwrites no operator
    /// edit, and suspending delivery for up to twenty-four hours could
    /// expire a certificate in the middle of the incident the window
    /// was opened for.
    ///
    /// Never fails: every per-node problem lands in
    /// [`CertPushReport::failed`] and the round continues.
    pub async fn push(
        &self,
        sessions: &SessionRegistry,
        recipients: &[String],
        bundles: Vec<CertBundle>,
    ) -> CertPushReport {
        let _round = self.round.lock().await;
        let report = self.run_round(sessions, recipients, bundles).await;
        *self.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(report.clone());
        report
    }

    async fn run_round(
        &self,
        sessions: &SessionRegistry,
        recipients: &[String],
        bundles: Vec<CertBundle>,
    ) -> CertPushReport {
        let mut report = CertPushReport {
            started_unix: unix_now(),
            ..CertPushReport::default()
        };

        if let Some(reason) = batch_defect(&bundles) {
            // Nothing is sent. A malformed batch on the wire is a
            // protocol violation that would drop the session of every
            // follower it reached, so a local bug must not become a
            // fleet-wide disconnect.
            tracing::error!(
                bundles = bundles.len(),
                recipients = recipients.len(),
                %reason,
                "refusing to distribute a malformed certificate batch; nothing was sent"
            );
            for node_id in recipients {
                report.failed.push((node_id.clone(), reason.clone()));
            }
            finish(&mut report);
            return report;
        }

        let targets = sessions.addressable(recipients);
        for (node_id, _) in &targets {
            report.targets.push(node_id.clone());
        }

        let material: Vec<CertMaterial> = bundles.iter().map(CertBundle::to_material).collect();
        let mut outcomes: JoinSet<(String, PushOutcome)> = JoinSet::new();
        for (node_id, endpoint) in targets {
            let request = ClusterRequest::cert_push(CertPush {
                bundles: material.clone(),
            });
            let deadline = self.per_node_deadline;
            outcomes.spawn(async move {
                let outcome = push_one(&endpoint, request, deadline).await;
                (node_id, outcome)
            });
        }
        while let Some(joined) = outcomes.join_next().await {
            let Ok((node_id, outcome)) = joined else {
                // A panicking push task is a bug in this crate, not a
                // peer fact; the node simply gets no verdict and
                // converges on its next pull.
                continue;
            };
            match outcome {
                PushOutcome::Answered { installed, refused } => {
                    report.installed.push((node_id.clone(), installed));
                    if let Some(summary) = summarise_refusals(&refused) {
                        tracing::warn!(
                            node_id = %node_id,
                            %summary,
                            "a follower refused part of a certificate push; it converges on its \
                             next certificate pull"
                        );
                        report.failed.push((node_id, summary));
                    }
                }
                PushOutcome::Failed(reason) => {
                    tracing::warn!(
                        node_id = %node_id,
                        %reason,
                        "certificate push to a follower failed; the push is best effort and the \
                         node converges on its next certificate pull"
                    );
                    report.failed.push((node_id, reason));
                }
            }
        }

        finish(&mut report);
        report
    }
}

/// Why a batch may not be sent, or `None` when it may.
fn batch_defect(bundles: &[CertBundle]) -> Option<String> {
    if bundles.len() > MAX_CERT_BUNDLES {
        return Some(format!(
            "batch of {} bundles exceeds the cap of {MAX_CERT_BUNDLES}",
            bundles.len()
        ));
    }
    bundles.iter().find_map(|bundle| {
        cert_bundle_defect(bundle)
            .map(|defect| format!("{defect} on certificate {}", safe_cert_id(&bundle.cert_id)))
    })
}

/// One line summarising what a node refused, or `None` when it refused
/// nothing. Bounded: only the first refusal is named.
fn summarise_refusals(refused: &[(String, String)]) -> Option<String> {
    let (cert_id, reason) = refused.first()?;
    Some(format!(
        "{} of the batch refused; first {cert_id}: {reason}",
        refused.len()
    ))
}

/// Sort every list, stamp the finish time, and log the round.
fn finish(report: &mut CertPushReport) {
    report.targets.sort();
    report.installed.sort();
    report.failed.sort();
    report.finished_unix = unix_now();
    tracing::info!(
        targets = report.targets.len(),
        answered = report.installed.len(),
        failed = report.failed.len(),
        "cluster certificate push round finished"
    );
}

/// One push exchange with one node.
async fn push_one(
    endpoint: &RpcEndpoint<ClusterFrame>,
    request: ClusterRequest,
    deadline: Duration,
) -> PushOutcome {
    let response = match endpoint.request(request, deadline).await {
        Ok(response) => response,
        Err(e) => return PushOutcome::Failed(format!("cert push transport failure: {e}")),
    };
    let status = response.cluster_status();
    if status != ClusterStatus::Ok {
        return PushOutcome::Failed(format!("cert push refused with status {status:?}"));
    }
    match response.body {
        Some(cluster_response::Body::CertPushAck(ack)) => {
            // The ANSWER is bounded exactly like the request was: a
            // peer that claims thousands of entries is amplifying
            // memory, not reporting a result.
            if ack.installed.len() > MAX_CERT_BUNDLES || ack.refused.len() > MAX_CERT_BUNDLES {
                return PushOutcome::Failed(
                    "cert push acknowledged with an over-long list".to_string(),
                );
            }
            let refused = ack
                .refused
                .into_iter()
                .map(|refusal| (safe_cert_id(&refusal.cert_id), safe_reason(&refusal.reason)))
                .collect();
            PushOutcome::Answered {
                installed: ack.installed.len(),
                refused,
            }
        }
        _ => PushOutcome::Failed("cert push answered without an acknowledgement".to_string()),
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
        cluster_request, CertPushAck, CertRefusal, ClusterResponse, MAX_CONFIG_HASH_BYTES,
    };
    use crate::replication::AppliedConfig;
    use crate::roster::{NodeIdentity, NodeState, SessionGuard, SessionRegistry};

    const PEER: &str = "192.0.2.10:9444";

    fn digest(seed: char) -> String {
        format!("sha256:{}", seed.to_string().repeat(MAX_CONFIG_HASH_BYTES))
    }

    fn bundle(cert_id: &str) -> CertBundle {
        CertBundle {
            cert_id: cert_id.to_string(),
            domain: "edge.example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----".to_string(),
            key_digest: digest('a'),
        }
    }

    fn identity(node_id: &str, state: NodeState) -> NodeIdentity {
        NodeIdentity {
            node_id: node_id.to_string(),
            name: node_id.to_string(),
            state,
            via_previous_certificate: false,
        }
    }

    /// What a scripted follower does with a push.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// Install everything.
        Accept,
        /// Install nothing and name a reason per certificate.
        RefuseAll,
        /// Never answer anything.
        Silent,
        /// Answer with a list longer than the cap allows.
        OverLongAck,
    }

    /// A scripted follower over an in-process duplex pair, plus the
    /// tallies the assertions read.
    struct Follower {
        /// Kept alive: dropping it deregisters the session.
        _guard: SessionGuard,
        /// Kept alive: dropping it tears down the reader and writer
        /// tasks that carry the follower's replies.
        _endpoint: RpcEndpoint<ClusterFrame>,
        pushes: Arc<AtomicUsize>,
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
        let pushes = Arc::new(AtomicUsize::new(0));
        if behaviour != Behaviour::Silent {
            tokio::spawn(serve_follower(
                follower_incoming,
                behaviour,
                Arc::clone(&pushes),
            ));
        }
        Follower {
            _guard: guard,
            _endpoint: follower_endpoint,
            pushes,
        }
    }

    async fn serve_follower(
        mut incoming: IncomingRequests<ClusterFrame>,
        behaviour: Behaviour,
        pushes: Arc<AtomicUsize>,
    ) {
        while let Some(request) = incoming.recv().await {
            let reply = match &request.request().body {
                Some(cluster_request::Body::CertPush(push)) => {
                    pushes.fetch_add(1, Ordering::SeqCst);
                    let ack = match behaviour {
                        Behaviour::RefuseAll => CertPushAck {
                            installed: Vec::new(),
                            refused: push
                                .bundles
                                .iter()
                                .map(|b| CertRefusal {
                                    cert_id: b.cert_id.clone(),
                                    reason: "no route binds this hostname here".to_string(),
                                })
                                .collect(),
                        },
                        Behaviour::OverLongAck => CertPushAck {
                            installed: vec!["c".to_string(); MAX_CERT_BUNDLES + 1],
                            refused: Vec::new(),
                        },
                        _ => CertPushAck {
                            installed: push.bundles.iter().map(|b| b.cert_id.clone()).collect(),
                            refused: Vec::new(),
                        },
                    };
                    ClusterResponse::ok(cluster_response::Body::CertPushAck(ack))
                }
                _ => ClusterResponse::refusal(ClusterStatus::UnsupportedMethod),
            };
            if request.reply_frame(reply).await.is_err() {
                return;
            }
        }
    }

    fn fast(distributor: &mut CertDistributor) {
        distributor.per_node_deadline = Duration::from_millis(300);
    }

    fn names(nodes: &[&str]) -> Vec<String> {
        nodes.iter().map(|n| (*n).to_string()).collect()
    }

    #[tokio::test]
    async fn a_push_reaches_the_named_recipients_and_nobody_else() {
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
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![bundle("cert-1")])
            .await;
        assert_eq!(report.targets, vec!["node-a".to_string()]);
        assert_eq!(report.installed, vec![("node-a".to_string(), 1)]);
        assert!(report.failed.is_empty());
        assert_eq!(wanted.pushes.load(Ordering::SeqCst), 1);
        assert_eq!(
            bystander.pushes.load(Ordering::SeqCst),
            0,
            "a live session that was not named must never see key material"
        );
        assert_eq!(distributor.last_report(), Some(report));
        drop((wanted, bystander));
    }

    #[tokio::test]
    async fn a_node_that_fails_transport_is_counted_and_the_round_continues() {
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
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let report = distributor
            .push(&registry, &names(&["node-a", "node-b"]), vec![bundle("cert-1")])
            .await;
        assert_eq!(report.targets, vec!["node-a".to_string(), "node-b".to_string()]);
        assert_eq!(
            report.installed,
            vec![("node-a".to_string(), 1)],
            "the healthy node still receives its material"
        );
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "node-b");
        assert!(report.failed[0].1.contains("transport"));
        assert_eq!(good.pushes.load(Ordering::SeqCst), 1);
        drop((good, silent));
    }

    #[tokio::test]
    async fn a_session_whose_node_is_not_active_is_skipped() {
        let registry = SessionRegistry::new();
        let pending = spawn_follower(
            &registry,
            "node-a",
            NodeState::Pending,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        // Named as a recipient AND connected, and still not addressed:
        // a node awaiting operator activation receives no key material
        // (Story 9.3 AC #5).
        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![bundle("cert-1")])
            .await;
        assert!(report.targets.is_empty());
        assert!(report.installed.is_empty() && report.failed.is_empty());
        assert_eq!(pending.pushes.load(Ordering::SeqCst), 0);
        drop(pending);
    }

    #[tokio::test]
    async fn a_break_glass_node_still_receives_key_material() {
        let registry = SessionRegistry::new();
        // Unlike a replication round, which skips it: a private key
        // overwrites no operator edit, and a suspended delivery could
        // expire a certificate mid-incident (D9).
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
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![bundle("cert-1")])
            .await;
        assert_eq!(report.targets, vec!["node-a".to_string()]);
        assert_eq!(report.installed, vec![("node-a".to_string(), 1)]);
        assert_eq!(broken_glass.pushes.load(Ordering::SeqCst), 1);
        drop(broken_glass);
    }

    #[tokio::test]
    async fn a_batch_over_the_cap_is_rejected_before_anything_is_sent() {
        let registry = SessionRegistry::new();
        let follower = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let oversized: Vec<CertBundle> = (0..=MAX_CERT_BUNDLES)
            .map(|i| bundle(&format!("cert-{i}")))
            .collect();
        let report = distributor
            .push(&registry, &names(&["node-a"]), oversized)
            .await;
        assert!(report.targets.is_empty());
        assert!(report.installed.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("exceeds the cap"));
        assert_eq!(
            follower.pushes.load(Ordering::SeqCst),
            0,
            "an over-cap batch must not reach the wire"
        );
        drop(follower);
    }

    #[tokio::test]
    async fn a_malformed_bundle_is_refused_locally_rather_than_dropping_every_session() {
        let registry = SessionRegistry::new();
        let follower = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let mut broken = bundle("cert-1");
        broken.key_digest = "not-a-digest".to_string();
        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![broken])
            .await;
        assert!(report.targets.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("malformed key digest"));
        assert_eq!(
            follower.pushes.load(Ordering::SeqCst),
            0,
            "a malformed push is a protocol violation on the far side and would drop the session"
        );
        drop(follower);
    }

    #[tokio::test]
    async fn a_refusing_follower_is_recorded_without_failing_the_round_for_anyone_else() {
        let registry = SessionRegistry::new();
        let good = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::Accept,
            AppliedConfig::default(),
        );
        let refuser = spawn_follower(
            &registry,
            "node-b",
            NodeState::Active,
            Behaviour::RefuseAll,
            AppliedConfig::default(),
        );
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let report = distributor
            .push(&registry, &names(&["node-a", "node-b"]), vec![bundle("cert-1")])
            .await;
        assert_eq!(
            report.installed,
            vec![("node-a".to_string(), 1), ("node-b".to_string(), 0)]
        );
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "node-b");
        assert!(report.failed[0].1.contains("cert-1"));
        assert!(report.failed[0].1.contains("no route binds this hostname here"));
        assert_eq!(good.pushes.load(Ordering::SeqCst), 1);
        drop((good, refuser));
    }

    #[tokio::test]
    async fn an_over_long_acknowledgement_is_a_failure_not_a_result() {
        let registry = SessionRegistry::new();
        let liar = spawn_follower(
            &registry,
            "node-a",
            NodeState::Active,
            Behaviour::OverLongAck,
            AppliedConfig::default(),
        );
        let mut distributor = CertDistributor::new();
        fast(&mut distributor);

        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![bundle("cert-1")])
            .await;
        assert!(report.installed.is_empty());
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("over-long"));
        drop(liar);
    }

    #[tokio::test]
    async fn a_round_with_no_live_session_is_an_empty_report() {
        let registry = SessionRegistry::new();
        let distributor = CertDistributor::new();
        assert_eq!(distributor.last_report(), None);
        let report = distributor
            .push(&registry, &names(&["node-a"]), vec![bundle("cert-1")])
            .await;
        assert!(report.targets.is_empty() && report.failed.is_empty());
        assert!(report.finished_unix >= report.started_unix);
        assert_eq!(distributor.last_report(), Some(report));
    }

    #[test]
    fn the_well_formedness_rule_covers_every_field_that_reaches_the_store() {
        assert_eq!(cert_bundle_defect(&bundle("cert-1")), None);
        let mut empty_id = bundle("cert-1");
        empty_id.cert_id = String::new();
        assert_eq!(cert_bundle_defect(&empty_id), Some("malformed certificate id"));
        let mut injected = bundle("cert-1");
        injected.domain = "edge.example.com\nforged".to_string();
        assert_eq!(
            cert_bundle_defect(&injected),
            Some("malformed certificate domain")
        );
        let mut no_chain = bundle("cert-1");
        no_chain.cert_pem = String::new();
        assert_eq!(cert_bundle_defect(&no_chain), Some("empty certificate chain"));
        // The Story 9.5 D8 failure in one assertion: a bundle with no
        // key would write an empty private-key file through the
        // follower's export path.
        let mut no_key = bundle("cert-1");
        no_key.key_pem = String::new();
        assert_eq!(cert_bundle_defect(&no_key), Some("empty private key"));
        let mut bad_digest = bundle("cert-1");
        bad_digest.key_digest = digest('a').to_uppercase();
        assert_eq!(cert_bundle_defect(&bad_digest), Some("malformed key digest"));
    }

    #[test]
    fn a_bundle_never_prints_its_private_key() {
        let printed = format!("{:?}", bundle("cert-1"));
        assert!(printed.contains("cert-1"));
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn a_peer_supplied_certificate_id_never_reaches_a_report_verbatim_when_malformed() {
        assert_eq!(safe_cert_id("cert-1"), "cert-1");
        assert_eq!(
            safe_cert_id("forged\nlog line"),
            "certificate id withheld (malformed)"
        );
        assert_eq!(safe_cert_id(""), "certificate id withheld (malformed)");
    }

    #[test]
    fn a_bundle_round_trips_through_its_wire_form() {
        let original = bundle("cert-1");
        assert_eq!(
            CertBundle::from_material(original.to_material()),
            original
        );
    }
}
