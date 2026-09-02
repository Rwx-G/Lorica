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

//! The two cluster listeners (Story 9.2 AC #2/#3/#10).
//!
//! - The **operational** listener accepts only peers that pass the
//!   mandatory-mTLS acceptor ([`crate::tls::operational_server_config`]
//!   via [`SwappableAcceptor`], so Story 9.3's revocation can rebuild
//!   the config with CRLs without dropping the socket), runs the
//!   session handshake behind the [`AdmissionGate`], then serves the
//!   session with every inbound request routed through the
//!   [`bridge`] whitelist.
//! - The **enrollment** listener is the only unauthenticated surface
//!   in the product. It exists ONLY while at least one join token is
//!   live: the socket binds when the [`TokenLiveness`] watch goes
//!   above zero and is dropped the moment it returns to zero. Every
//!   connection is boxed in by the [`PreAuthBudgets`] BEFORE any
//!   token logic runs, and (in Story 9.2, where redemption does not
//!   exist yet) is answered with the OPAQUE status.
//!
//! Counters are plain atomics ([`EnrollmentStats`] /
//! [`OperationalStats`]); the binary bridges them into the Prometheus
//! registry (AC #12).
//!
//! [`bridge`]: crate::bridge

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use lorica_command::RpcEndpoint;

use crate::admission::{AdmissionDecision, AdmissionGate};
use crate::bridge::{translate_cluster_request, BridgeOutcome, InPlaneAction};
use crate::handshake::{serve_hello, HandshakeConfig};
use crate::messages::{
    cluster_frame, cluster_response, ClusterFrame, ClusterResponse, ClusterStatus, HeartbeatAck,
};
use crate::tls::SwappableAcceptor;

/// Live-join-token signal driving the enrollment listener's lifecycle
/// (Story 9.2 AC #2). The value is the count of currently live
/// (unburned, unexpired) join tokens; the sender is owned by the
/// caller. Story 9.3 wires it to the token table, this story to the
/// tests and (until 9.3 lands) a constant zero in production, which
/// keeps the listener closed.
pub type TokenLiveness = watch::Receiver<u32>;

/// Pre-authentication budgets on the enrollment listener (AC #3),
/// enforced BEFORE any token verification.
#[derive(Debug, Clone)]
pub struct PreAuthBudgets {
    /// Max time for the TLS handshake to complete.
    pub handshake_timeout: Duration,
    /// Max TLS handshakes in flight at once; excess connections are
    /// dropped immediately.
    pub max_concurrent_handshakes: usize,
    /// Max enrollment exchanges in flight at once (post-TLS), distinct
    /// from the handshake bound so slow token verifications (Story
    /// 9.3) cannot be used to starve the TLS accept path.
    pub max_inflight_enrollments: usize,
    /// Max bytes a connection may send in its enrollment frame.
    pub per_conn_max_bytes: u64,
    /// Max total lifetime of one enrollment connection.
    pub per_conn_max_duration: Duration,
}

impl Default for PreAuthBudgets {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(5),
            max_concurrent_handshakes: 16,
            max_inflight_enrollments: 8,
            per_conn_max_bytes: 16 * 1024,
            per_conn_max_duration: Duration::from_secs(15),
        }
    }
}

/// Enrollment-listener counters, one atomic per budget plus lifecycle
/// events. All monotonic except none; the binary exposes them as
/// Prometheus counters (AC #3: "exceeding any drops the connection
/// and increments a counter").
#[derive(Debug, Default)]
pub struct EnrollmentStats {
    /// Connections accepted (before any budget ran).
    pub connections_total: AtomicU64,
    /// Dropped: TLS handshake exceeded `handshake_timeout` or failed.
    pub rejected_handshake_timeout: AtomicU64,
    /// Dropped: `max_concurrent_handshakes` already in flight.
    pub rejected_concurrent_handshakes: AtomicU64,
    /// Dropped: `max_inflight_enrollments` already in flight.
    pub rejected_inflight_enrollments: AtomicU64,
    /// Dropped: the peer announced or sent more than
    /// `per_conn_max_bytes`.
    pub rejected_byte_budget: AtomicU64,
    /// Dropped: the connection outlived `per_conn_max_duration`.
    pub rejected_time_budget: AtomicU64,
    /// Times the listener socket opened (liveness went above zero).
    pub lifecycle_opens: AtomicU64,
    /// Times the listener socket closed (liveness returned to zero).
    pub lifecycle_closes: AtomicU64,
}

/// Handle to a running enrollment listener.
pub struct EnrollmentHandle {
    /// `Some(addr)` while the socket is bound and accepting, `None`
    /// while the listener is closed (no live token). The binary logs
    /// transitions; tests assert the lifecycle on it.
    pub bound: watch::Receiver<Option<SocketAddr>>,
    task: JoinHandle<()>,
}

impl EnrollmentHandle {
    /// Stop the listener task. Any bound socket closes with it.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// The token-gated, budget-boxed enrollment listener (AC #2/#3).
pub struct EnrollmentListener;

impl EnrollmentListener {
    /// Spawn the lifecycle task: bind `bind` while `liveness > 0`,
    /// drop the socket when it returns to zero, reopen on the next
    /// rise. Returns when the liveness sender is dropped.
    pub fn spawn(
        bind: SocketAddr,
        acceptor: Arc<SwappableAcceptor>,
        mut liveness: TokenLiveness,
        budgets: PreAuthBudgets,
        stats: Arc<EnrollmentStats>,
    ) -> EnrollmentHandle {
        let (bound_tx, bound_rx) = watch::channel(None);
        let task = tokio::spawn(async move {
            loop {
                // Closed phase: wait for at least one live token.
                while *liveness.borrow() == 0 {
                    if liveness.changed().await.is_err() {
                        return; // sender gone: shut down for good
                    }
                }

                let listener = match TcpListener::bind(bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(%bind, error = %e, "enrollment listener bind failed");
                        // Try again on the next liveness edge instead
                        // of hot-looping.
                        if liveness.changed().await.is_err() {
                            return;
                        }
                        continue;
                    }
                };
                let local = listener.local_addr().ok();
                stats.lifecycle_opens.fetch_add(1, Ordering::Relaxed);
                let _ = bound_tx.send(local);
                tracing::warn!(
                    addr = ?local,
                    "enrollment listener OPEN (unauthenticated surface; closes with the last live token)"
                );

                let handshakes = Arc::new(Semaphore::new(budgets.max_concurrent_handshakes));
                let enrollments = Arc::new(Semaphore::new(budgets.max_inflight_enrollments));

                // Open phase: accept until liveness returns to zero.
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok((tcp, peer)) = accepted else { continue };
                            stats.connections_total.fetch_add(1, Ordering::Relaxed);
                            let Ok(hs_permit) =
                                Arc::clone(&handshakes).try_acquire_owned()
                            else {
                                stats
                                    .rejected_concurrent_handshakes
                                    .fetch_add(1, Ordering::Relaxed);
                                drop(tcp);
                                continue;
                            };
                            let acceptor = Arc::clone(&acceptor);
                            let budgets = budgets.clone();
                            let stats = Arc::clone(&stats);
                            let enrollments = Arc::clone(&enrollments);
                            tokio::spawn(async move {
                                serve_enrollment_conn(
                                    tcp, peer, acceptor, budgets, stats, enrollments,
                                )
                                .await;
                                drop(hs_permit);
                            });
                        }
                        changed = liveness.changed() => {
                            if changed.is_err() {
                                let _ = bound_tx.send(None);
                                return;
                            }
                            if *liveness.borrow() == 0 {
                                break;
                            }
                        }
                    }
                }

                // AC #2 auto-close: last token burned or expired.
                drop(listener);
                stats.lifecycle_closes.fetch_add(1, Ordering::Relaxed);
                let _ = bound_tx.send(None);
                tracing::warn!("enrollment listener CLOSED (no live join token)");
            }
        });
        EnrollmentHandle {
            bound: bound_rx,
            task,
        }
    }
}

/// One enrollment connection, boxed in by every budget. Wire format
/// mirrors `RpcEndpoint` (`[8 bytes LE length][prost ClusterFrame]`)
/// but is read manually: an unauthenticated peer does not get reader
/// and writer tasks spawned on its behalf, and byte accounting stays
/// exact.
async fn serve_enrollment_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: Arc<SwappableAcceptor>,
    budgets: PreAuthBudgets,
    stats: Arc<EnrollmentStats>,
    enrollments: Arc<Semaphore>,
) {
    let overall = tokio::time::timeout(budgets.per_conn_max_duration, async {
        let tls_acceptor = TlsAcceptor::from(acceptor.current());
        let mut tls = match tokio::time::timeout(budgets.handshake_timeout, tls_acceptor.accept(tcp))
            .await
        {
            Ok(Ok(tls)) => tls,
            Ok(Err(e)) => {
                tracing::debug!(%peer, error = %e, "enrollment TLS handshake failed");
                stats
                    .rejected_handshake_timeout
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            Err(_) => {
                stats
                    .rejected_handshake_timeout
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        // Post-TLS: the enrollment-exchange budget (distinct from the
        // handshake budget so slow verifications cannot starve accepts).
        let Ok(_enroll_permit) = Arc::clone(&enrollments).try_acquire_owned() else {
            stats
                .rejected_inflight_enrollments
                .fetch_add(1, Ordering::Relaxed);
            return;
        };

        // Read exactly one length-prefixed frame within the byte budget.
        let mut len_buf = [0u8; 8];
        if tls.read_exact(&mut len_buf).await.is_err() {
            return;
        }
        let len = u64::from_le_bytes(len_buf);
        if len > budgets.per_conn_max_bytes {
            stats.rejected_byte_budget.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut body = vec![0u8; len as usize];
        if tls.read_exact(&mut body).await.is_err() {
            return;
        }

        // Story 9.2: token redemption does not exist yet, and a
        // pre-authentication peer learns nothing from refusal shapes
        // (AC #4): whatever was sent, answer the OPAQUE status with
        // the request's sequence when one is recoverable.
        let sequence = match ClusterFrame::decode(body.as_slice()) {
            Ok(frame) => match frame.kind {
                Some(cluster_frame::Kind::Request(req)) => req.sequence,
                _ => 0,
            },
            Err(_) => 0,
        };
        tracing::debug!(%peer, "enrollment attempt refused (no redemption path in this release)");
        let refusal = ClusterFrame {
            kind: Some(cluster_frame::Kind::Response(ClusterResponse::refusal(
                sequence,
                ClusterStatus::opaque(),
            ))),
        };
        let encoded = refusal.encode_to_vec();
        let mut wire = Vec::with_capacity(8 + encoded.len());
        wire.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        wire.extend_from_slice(&encoded);
        let _ = tls.write_all(&wire).await;
        let _ = tls.shutdown().await;
    })
    .await;
    if overall.is_err() {
        stats.rejected_time_budget.fetch_add(1, Ordering::Relaxed);
    }
}

/// Operational-listener counters (bridged to Prometheus by the
/// binary, AC #12).
#[derive(Debug, Default)]
pub struct OperationalStats {
    /// TLS handshakes that failed (no/invalid client certificate).
    pub tls_failures: AtomicU64,
    /// Sessions admitted through the handshake.
    pub sessions_admitted: AtomicU64,
    /// Sessions answered RETRY_LATER by the admission gate (AC #10).
    pub sessions_retry_later: AtomicU64,
    /// Handshakes refused (version / schema / protocol violation).
    pub handshake_refusals: AtomicU64,
    /// Established-session requests refused by the bridge whitelist;
    /// each one also dropped its connection (AC #6).
    pub protocol_violations: AtomicU64,
    /// Heartbeats served in-plane.
    pub heartbeats_served: AtomicU64,
}

/// Handle to a running operational listener.
pub struct OperationalHandle {
    task: JoinHandle<()>,
}

impl OperationalHandle {
    /// Stop accepting. Established sessions end when their tasks see
    /// the connection close.
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// The mandatory-mTLS operational listener (AC #2).
pub struct OperationalListener;

impl OperationalListener {
    /// Spawn the accept loop on an already-bound listener (the binary
    /// owns bind-address validation and logging, AC #11).
    ///
    /// Per connection: mTLS accept (each accept reads the CURRENT
    /// config from `acceptor`, Story 9.3's revocation seam), the
    /// admission gate (AC #10), the session handshake (AC #4/#5),
    /// then the steady-state loop with every inbound request routed
    /// through the bridge whitelist (AC #6). `fleet_size` is loaded
    /// per handshake and heartbeat so the hint tracks roster growth.
    pub fn spawn(
        listener: TcpListener,
        acceptor: Arc<SwappableAcceptor>,
        handshake: HandshakeConfig,
        fleet_size: Arc<AtomicU32>,
        admission: Arc<AdmissionGate>,
        stats: Arc<OperationalStats>,
    ) -> OperationalHandle {
        let task = tokio::spawn(async move {
            // Sessions live in a JoinSet so that aborting the accept
            // task (OperationalHandle::shutdown) also tears down every
            // established session, not just the accept loop.
            let mut sessions = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((tcp, peer)) = accepted else { continue };
                        let acceptor = Arc::clone(&acceptor);
                        let handshake = handshake.clone();
                        let fleet_size = Arc::clone(&fleet_size);
                        let admission = Arc::clone(&admission);
                        let stats = Arc::clone(&stats);
                        sessions.spawn(async move {
                            serve_operational_conn(
                                tcp, peer, acceptor, handshake, fleet_size, admission, stats,
                            )
                            .await;
                        });
                    }
                    // Reap finished sessions so the set stays small.
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                }
            }
        });
        OperationalHandle { task }
    }
}

/// Handshake phase budget on the operational path: an authenticated
/// peer that never sends its Hello must not pin a session slot
/// forever.
const OPERATIONAL_OPENER_TIMEOUT: Duration = Duration::from_secs(10);

async fn serve_operational_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: Arc<SwappableAcceptor>,
    handshake: HandshakeConfig,
    fleet_size: Arc<AtomicU32>,
    admission: Arc<AdmissionGate>,
    stats: Arc<OperationalStats>,
) {
    let tls_acceptor = TlsAcceptor::from(acceptor.current());
    let tls = match tls_acceptor.accept(tcp).await {
        Ok(tls) => tls,
        Err(e) => {
            stats.tls_failures.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, error = %e, "operational mTLS handshake failed");
            return;
        }
    };

    let (endpoint, mut incoming) = RpcEndpoint::<ClusterFrame>::from_stream(tls);

    // Admission BEFORE the opener is read (AC #10): the gate bounds
    // concurrent convergence, and a queued peer waits here.
    let permit = match admission.admit().await {
        AdmissionDecision::Admitted(permit) => Some(permit),
        AdmissionDecision::RetryLater { retry_after_s } => {
            // The peer still deserves a wire answer: read its opener
            // (bounded) and reply RETRY_LATER on its sequence.
            stats.sessions_retry_later.fetch_add(1, Ordering::Relaxed);
            if let Ok(Some(opener)) =
                tokio::time::timeout(OPERATIONAL_OPENER_TIMEOUT, incoming.recv()).await
            {
                let sequence = opener.sequence();
                let _ = opener
                    .reply_frame(ClusterResponse::retry_later(sequence, retry_after_s))
                    .await;
                // Give the reply a moment to flush before the writer
                // aborts with the endpoint drop.
                let _ = tokio::time::timeout(Duration::from_secs(2), incoming.recv()).await;
            }
            return;
        }
    };

    let Ok(Some(opener)) =
        tokio::time::timeout(OPERATIONAL_OPENER_TIMEOUT, incoming.recv()).await
    else {
        return;
    };
    let hint = fleet_size.load(Ordering::Relaxed);
    match serve_hello(opener, &handshake, hint).await {
        Ok(Ok(_ack)) => {
            stats.sessions_admitted.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(status)) => {
            stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
            tracing::info!(%peer, ?status, "cluster session refused at handshake");
            // Keep the endpoint alive briefly so the refusal flushes.
            let _ = tokio::time::timeout(Duration::from_secs(2), incoming.recv()).await;
            return;
        }
        Err(e) => {
            tracing::debug!(%peer, error = %e, "cluster handshake transport failure");
            return;
        }
    }
    // Convergence is over once the handshake completed (Story 9.4
    // will extend the hold across the initial config pull).
    drop(permit);

    serve_session(&endpoint, &mut incoming, &fleet_size, &stats).await;
    tracing::debug!(%peer, "cluster session ended");
}

/// Steady-state loop for an established operational session: EVERY
/// inbound request routes through the bridge whitelist; a violation
/// answers `PROTOCOL_VIOLATION` and drops the connection (AC #6).
async fn serve_session(
    _endpoint: &RpcEndpoint<ClusterFrame>,
    incoming: &mut lorica_command::IncomingRequests<ClusterFrame>,
    fleet_size: &AtomicU32,
    stats: &OperationalStats,
) {
    while let Some(request) = incoming.recv().await {
        let sequence = request.sequence();
        match translate_cluster_request(request.request()) {
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat { timestamp_ms }) => {
                stats.heartbeats_served.fetch_add(1, Ordering::Relaxed);
                let ack = HeartbeatAck {
                    timestamp_ms,
                    fleet_size_hint: fleet_size.load(Ordering::Relaxed),
                };
                if request
                    .reply_frame(ClusterResponse::ok(
                        sequence,
                        cluster_response::Body::HeartbeatAck(ack),
                    ))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            BridgeOutcome::ProtocolViolation => {
                stats.protocol_violations.fetch_add(1, Ordering::Relaxed);
                let _ = request
                    .reply_frame(ClusterResponse::refusal(
                        sequence,
                        ClusterStatus::ProtocolViolation,
                    ))
                    .await;
                // Drop the connection: returning drops the incoming
                // half; the caller drops the endpoint.
                return;
            }
        }
    }
}
