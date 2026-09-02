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

//! Control-plane side of the cluster plane (Story 9.2): validates
//! `--cluster-listen`, loads the cluster CA, mints this node's
//! server leaf, and spawns the two listeners.
//!
//! Opt-in: nothing here runs unless `--cluster-listen` is set. The
//! enrollment listener binds `cluster port + 1` on the same host and
//! only exists while at least one join token is live; Story 9.2 ships
//! the lifecycle with a liveness source that never rises (token
//! minting is Story 9.3), so the enrollment socket stays closed in
//! this release even when the plane is enabled.

use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use lorica_cluster::{
    AdmissionGate, ClusterCa, EnrollmentHandle, EnrollmentListener, EnrollmentStats,
    HandshakeConfig, OperationalHandle, OperationalListener, OperationalStats, PreAuthBudgets,
    SwappableAcceptor, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION,
};
use lorica_config::store::ConfigStore;
use tokio::sync::{watch, Mutex};
use tracing::warn;

use crate::cli::validate_cluster_listen;

/// Convergence admission defaults (AC #10): concurrent sessions
/// admitted through the handshake at once, how many more may queue,
/// and what a queued-out peer is told to wait before retrying.
const ADMISSION_MAX_CONCURRENT: usize = 32;
const ADMISSION_QUEUE_DEPTH: usize = 128;
const ADMISSION_RETRY_AFTER_S: u32 = 5;

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
}

impl ClusterPlane {
    /// Stop both listeners and every established session.
    pub fn shutdown(self) {
        self.operational.shutdown();
        self.enrollment.shutdown();
    }
}

/// Validate the CLI bind, load the CA, and start the listeners.
/// `Ok(None)` when `--cluster-listen` is absent (plane disabled).
///
/// Refuses to start (typed error, caller exits) when the bind is
/// invalid or no cluster CA exists: a control plane without a CA
/// cannot authenticate anyone, and silently running without the
/// plane the operator asked for is the wrong failure mode.
pub(crate) async fn spawn_cluster_plane(
    cluster_listen: Option<&str>,
    cluster_listen_any: bool,
    management_port: u16,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<Option<ClusterPlane>, String> {
    let Some(value) = cluster_listen else {
        return Ok(None);
    };
    let bind = validate_cluster_listen(value, management_port, cluster_listen_any)?;

    let (ca, schema_version) = {
        let store = store.lock().await;
        let ca = store
            .get_cluster_ca()
            .map_err(|e| format!("cluster plane: failed to read the cluster CA: {e}"))?
            .ok_or_else(|| {
                "cluster plane: no cluster CA in the database; run `lorica cluster init` \
                 on this node first"
                    .to_string()
            })?;
        let schema = store
            .schema_version()
            .map_err(|e| format!("cluster plane: failed to read the schema version: {e}"))?;
        (ca, schema)
    };
    let ca = ClusterCa::from_pem(&ca.0, &ca.1)
        .map_err(|e| format!("cluster plane: stored cluster CA is unusable: {e}"))?;

    // The server leaf is minted per boot from the persisted CA: 90
    // days of validity comfortably exceeds any process lifetime and
    // nothing has to persist or rotate it. The SAN is the bind host,
    // which is what followers dial.
    let host = bind.ip().to_string();
    let (server_cert, server_key) = ca
        .issue_server_leaf(&host)
        .map_err(|e| format!("cluster plane: failed to issue the control-plane leaf: {e}"))?;

    let operational_config =
        lorica_cluster::operational_server_config(ca.cert_pem(), &server_cert, &server_key)
            .map_err(|e| format!("cluster plane: operational TLS config: {e}"))?;
    let enrollment_config = lorica_cluster::enrollment_server_config(&server_cert, &server_key)
        .map_err(|e| format!("cluster plane: enrollment TLS config: {e}"))?;

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("cluster plane: failed to bind {bind}: {e}"))?;

    let handshake = HandshakeConfig {
        protocol_min: PROTOCOL_MIN_COMPATIBLE,
        protocol_max: PROTOCOL_VERSION,
        schema_version: u32::try_from(schema_version).unwrap_or(u32::MAX),
    };
    let fleet_size = Arc::new(AtomicU32::new(0));
    let admission = Arc::new(AdmissionGate::new(
        ADMISSION_MAX_CONCURRENT,
        ADMISSION_QUEUE_DEPTH,
        ADMISSION_RETRY_AFTER_S,
    ));
    let operational_stats = Arc::new(OperationalStats::default());
    let operational = OperationalListener::spawn(
        listener,
        Arc::new(SwappableAcceptor::new(Arc::new(operational_config))),
        handshake,
        Arc::clone(&fleet_size),
        admission,
        Arc::clone(&operational_stats),
    );

    let enrollment_bind = std::net::SocketAddr::new(bind.ip(), bind.port().wrapping_add(1));
    let (token_liveness, liveness_rx) = watch::channel(0u32);
    let enrollment_stats = Arc::new(EnrollmentStats::default());
    let enrollment = EnrollmentListener::spawn(
        enrollment_bind,
        Arc::new(SwappableAcceptor::new(Arc::new(enrollment_config))),
        liveness_rx,
        PreAuthBudgets::default(),
        Arc::clone(&enrollment_stats),
    );

    // WARN, not INFO (AC #11): exposing a fleet listener is the kind
    // of fact an operator must be able to spot in the journal.
    warn!(
        operational = %bind,
        enrollment = %enrollment_bind,
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
    }))
}
