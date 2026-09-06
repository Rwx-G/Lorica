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

//! Control-plane side of the cluster plane (Story 9.2): validates the
//! binds, loads the cluster CA, mints this node's server leaf from a
//! persisted keypair, and spawns the two listeners.
//!
//! Opt-in: nothing here runs unless `--cluster-listen` is set. The
//! enrollment listener binds `cluster port + 1` on the same host by
//! default (or `--cluster-enrollment-listen`) and only exists while at
//! least one join token is live; Story 9.2 ships the lifecycle with a
//! liveness source that never rises (token minting is Story 9.3), so
//! the enrollment socket stays closed in this release even when the
//! plane is enabled.
//!
//! Hot upgrade: the operational socket is handed to the next
//! supervisor through Story 9.1's cluster FD slot, so established
//! follower sessions survive a binary upgrade like proxy connections
//! do. The enrollment socket is deliberately not handed off - it is
//! bound only inside an enrollment window and rebinds on the next
//! liveness edge, which is the honest lifecycle for a socket that
//! usually does not exist.

use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use lorica_cluster::{
    AdmissionGate, ClusterCa, EnrollmentHandle, EnrollmentListener, EnrollmentStats,
    HandshakeConfig, OperationalConfig, OperationalHandle, OperationalListener,
    OperationalStats, PreAuthBudgets, SwappableAcceptor,
};
use lorica_config::store::ConfigStore;
use tokio::sync::{watch, Mutex};
use tracing::{info, warn};

use crate::cli::{validate_cluster_listen, ReservedPorts};
use crate::startup::hot_upgrade::ClusterListenerRole;

/// Convergence admission defaults (AC #10): concurrent sessions
/// admitted through the handshake at once, how many more may queue,
/// and what a queued-out peer is told to wait before retrying.
const ADMISSION_MAX_CONCURRENT: usize = 32;
const ADMISSION_QUEUE_DEPTH: usize = 128;
const ADMISSION_RETRY_AFTER_S: u32 = 5;

/// Cap on established operational sessions (one per follower plus
/// headroom); past it a peer is answered RETRY_LATER after its opener.
const MAX_OPERATIONAL_SESSIONS: usize = 1024;

/// Inputs for [`spawn_cluster_plane`], lifted from the CLI.
pub(crate) struct ClusterPlaneOptions {
    /// `--cluster-listen`; the plane is disabled when `None`.
    pub cluster_listen: Option<String>,
    /// `--cluster-enrollment-listen` (defaults to operational port + 1).
    pub enrollment_listen: Option<String>,
    /// `--cluster-advertise` (defaults to the operational host).
    pub advertise: Option<String>,
    /// `--cluster-listen-any`.
    pub listen_any: bool,
    /// Ports the cluster plane must never share.
    pub reserved: ReservedPorts,
    /// The operational listening socket inherited from an outgoing
    /// supervisor on `--hot-upgrade`, adopted instead of binding.
    pub inherited_operational_fd: Option<RawFd>,
}

/// Live handles for a running control-plane cluster plane. Dropping
/// the handles does not stop the listeners; `shutdown` does.
pub(crate) struct ClusterPlane {
    /// The mandatory-mTLS operational listener.
    pub operational: OperationalHandle,
    /// The token-gated enrollment listener.
    pub enrollment: EnrollmentHandle,
    /// Live join-token count driving the enrollment listener. Held
    /// (not read) in 9.2: dropping the sender ends the listener's
    /// lifecycle task, and Story 9.3 is the publisher.
    pub _token_liveness: watch::Sender<u32>,
    /// Fleet-size hint handed to followers for their backoff cap.
    /// Held in 9.2; Story 9.3 updates it from the roster.
    pub _fleet_size: Arc<AtomicU32>,
    /// Operational-listener counters, bridged into Prometheus at
    /// scrape time.
    pub operational_stats: Arc<OperationalStats>,
    /// Enrollment-listener counters, bridged into Prometheus at
    /// scrape time.
    pub enrollment_stats: Arc<EnrollmentStats>,
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

    /// Stop both listeners and every established session.
    pub fn shutdown(self) {
        self.operational.shutdown();
        self.enrollment.shutdown();
    }
}

/// Validate the CLI binds, load the CA, and start the listeners.
/// `Ok(None)` when `--cluster-listen` is absent (plane disabled).
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
        return Ok(None);
    };
    let binds = validate_cluster_listen(
        value,
        opts.enrollment_listen.as_deref(),
        opts.advertise.as_deref(),
        opts.reserved,
        opts.listen_any,
    )?;

    let (ca, stored_leaf, schema_version, takeover_epoch) = {
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
        (ca, leaf, schema, epoch)
    };
    let ca = ClusterCa::from_pem(&ca.0, &ca.1)
        .map_err(|e| format!("cluster plane: stored cluster CA is unusable: {e}"))?;

    // The leaf KEYPAIR is persisted and the certificate re-issued per
    // boot (90 days, comfortably beyond any process lifetime): Story
    // 9.3 pins the leaf SPKI in join tokens, so a keypair minted per
    // boot would invalidate every outstanding token on restart. The
    // SAN is the advertised name, which is what followers dial.
    let host = binds.advertise_host.as_str();
    let (server_cert, server_key) = match stored_leaf {
        Some((_, key_pem)) => {
            let cert = ca.issue_server_leaf_with_key(host, &key_pem).map_err(|e| {
                format!("cluster plane: failed to re-issue the control-plane leaf: {e}")
            })?;
            (cert, key_pem)
        }
        None => {
            let (cert, key) = ca.issue_server_leaf(host).map_err(|e| {
                format!("cluster plane: failed to issue the control-plane leaf: {e}")
            })?;
            store
                .lock()
                .await
                .set_control_plane_leaf(&cert, &key)
                .map_err(|e| format!("cluster plane: failed to persist the leaf keypair: {e}"))?;
            info!("cluster plane: control-plane leaf keypair generated and persisted");
            (cert, key)
        }
    };

    let operational_config =
        lorica_cluster::operational_server_config(ca.cert_pem(), &server_cert, &server_key)
            .map_err(|e| format!("cluster plane: operational TLS config: {e}"))?;
    let enrollment_config = lorica_cluster::enrollment_server_config(&server_cert, &server_key)
        .map_err(|e| format!("cluster plane: enrollment TLS config: {e}"))?;

    // Adopt the inherited socket on a hot upgrade (no rebind gap, no
    // EADDRINUSE against the outgoing supervisor), else bind fresh.
    let std_listener: std::net::TcpListener = match opts.inherited_operational_fd {
        Some(fd) => {
            // SAFETY: `fd` was received via SCM_RIGHTS in
            // `pull_inherited_listeners` and is owned exclusively here;
            // it refers to the same kernel listening socket the outgoing
            // supervisor accepts cluster sessions on.
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
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

    let fleet_size = Arc::new(AtomicU32::new(0));
    let operational_stats = Arc::new(OperationalStats::default());
    let operational = OperationalListener::spawn(OperationalConfig {
        listener,
        acceptor: Arc::new(SwappableAcceptor::new(Arc::new(operational_config))),
        handshake: HandshakeConfig::new(u32::try_from(schema_version).unwrap_or(u32::MAX)),
        fleet_size: Arc::clone(&fleet_size),
        admission: Arc::new(AdmissionGate::new(
            ADMISSION_MAX_CONCURRENT,
            ADMISSION_QUEUE_DEPTH,
            ADMISSION_RETRY_AFTER_S,
        )),
        stats: Arc::clone(&operational_stats),
        budgets: PreAuthBudgets::default(),
        max_sessions: MAX_OPERATIONAL_SESSIONS,
        takeover_epoch,
    });

    let (token_liveness, liveness_rx) = watch::channel(0u32);
    let enrollment_stats = Arc::new(EnrollmentStats::default());
    let enrollment = EnrollmentListener::spawn(
        binds.enrollment,
        Arc::new(SwappableAcceptor::new(Arc::new(enrollment_config))),
        liveness_rx,
        PreAuthBudgets::default(),
        Arc::clone(&enrollment_stats),
    );

    // WARN, not INFO (AC #11): exposing a fleet listener is the kind
    // of fact an operator must be able to spot in the journal.
    warn!(
        operational = %binds.operational,
        enrollment = %binds.enrollment,
        advertise = %binds.advertise_host,
        adopted = opts.inherited_operational_fd.is_some(),
        takeover_epoch,
        "cluster plane enabled: operational listener bound (mTLS mandatory); \
         enrollment listener opens only while a join token is live"
    );

    Ok(Some(ClusterPlane {
        operational,
        enrollment,
        _token_liveness: token_liveness,
        _fleet_size: fleet_size,
        operational_stats,
        enrollment_stats,
        handoff_listener,
        operational_bind: binds.operational,
    }))
}
