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
//!   the config with CRLs without dropping the socket). Before the TLS
//!   handshake it is boxed in by the same pre-authentication budgets
//!   as the enrollment listener (a concurrent-handshake permit taken
//!   BEFORE the per-connection task exists, a handshake timeout): an
//!   unauthenticated TCP peer must never be able to pin a task, a
//!   socket or a rustls session. After TLS the flow is: opener read
//!   (bounded) -> session cap -> [`AdmissionGate`] (bounded queued
//!   wait) -> handshake -> steady state with every inbound request
//!   routed through the [`bridge`] whitelist.
//! - The **enrollment** listener is the only unauthenticated surface
//!   in the product. It exists ONLY while at least one join token is
//!   live: the socket binds when the [`TokenLiveness`] watch goes
//!   above zero and is dropped, along with every in-flight
//!   pre-authentication connection, the moment it returns to zero.
//!   Every connection is boxed in by the [`PreAuthBudgets`] BEFORE any
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
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::CommonState;
use tokio_rustls::TlsAcceptor;

use lorica_command::{IncomingRequest, IncomingRequests, RpcEndpoint};

use crate::admission::{AdmissionDecision, AdmissionGate};
use crate::bridge::{translate_cluster_request, BridgeOutcome, InPlaneAction};
use crate::handshake::{serve_hello, HandshakeConfig};
use crate::limits::cluster_rpc_limits;
use crate::messages::{
    cluster_frame, cluster_response, ClusterFrame, ClusterResponse, ClusterStatus, HeartbeatAck,
};
use crate::tls::{negotiated_cluster_alpn, SwappableAcceptor};

/// Live-join-token signal driving the enrollment listener's lifecycle
/// (Story 9.2 AC #2). The value is the count of currently live
/// (unburned, unexpired) join tokens; the sender is owned by the
/// caller. Story 9.3 wires it to the token table, this story to the
/// tests and (until 9.3 lands) a constant zero in production, which
/// keeps the listener closed.
pub type TokenLiveness = watch::Receiver<u32>;

/// Pre-authentication budgets (AC #3), enforced BEFORE any token or
/// message logic. The enrollment listener applies all five; the
/// operational listener applies `handshake_timeout` and
/// `max_concurrent_handshakes` to its TLS phase (the other three are
/// enrollment-frame concerns).
#[derive(Debug, Clone)]
pub struct PreAuthBudgets {
    /// Max time for the TLS handshake to complete.
    pub handshake_timeout: Duration,
    /// Max TLS handshakes in flight at once; excess connections are
    /// dropped immediately, before a task exists for them.
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
/// events, all monotonic; the binary exposes them as Prometheus
/// counters (AC #3: "exceeding any drops the connection and
/// increments a counter").
#[derive(Debug, Default)]
pub struct EnrollmentStats {
    /// Connections accepted (before any budget ran).
    pub connections_total: AtomicU64,
    /// Dropped: the TLS handshake was rejected (bad ClientHello, no
    /// overlap, garbage).
    pub rejected_handshake_failed: AtomicU64,
    /// Dropped: the TLS handshake exceeded `handshake_timeout`.
    pub rejected_handshake_timeout: AtomicU64,
    /// Dropped: the peer completed TLS without the cluster ALPN.
    pub rejected_alpn: AtomicU64,
    /// Dropped: `max_concurrent_handshakes` already in flight.
    pub rejected_concurrent_handshakes: AtomicU64,
    /// Dropped: `max_inflight_enrollments` already in flight.
    pub rejected_inflight_enrollments: AtomicU64,
    /// Dropped: the peer announced or sent more than
    /// `per_conn_max_bytes`.
    pub rejected_byte_budget: AtomicU64,
    /// Dropped: the connection outlived `per_conn_max_duration`.
    pub rejected_time_budget: AtomicU64,
    /// Dropped: the enrollment window closed (last token gone) between
    /// the accept and the post-TLS liveness re-check.
    pub rejected_window_closed: AtomicU64,
    /// Bind attempts that failed while a token was live (retried on a
    /// bounded backoff).
    pub bind_failures: AtomicU64,
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
    /// Stop the listener task. Any bound socket closes with it, and
    /// so does every in-flight pre-authentication connection (they
    /// live in a `JoinSet` owned by the task).
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// First delay after a failed bind while a token is live; doubles up
/// to [`BIND_RETRY_MAX`].
const BIND_RETRY_MIN: Duration = Duration::from_secs(1);
/// Cap on the bind-retry backoff.
const BIND_RETRY_MAX: Duration = Duration::from_secs(30);

/// The token-gated, budget-boxed enrollment listener (AC #2/#3).
pub struct EnrollmentListener;

impl EnrollmentListener {
    /// Spawn the lifecycle task: bind `bind` while `liveness > 0`,
    /// drop the socket (and abort every in-flight connection) when it
    /// returns to zero, reopen on the next rise. A failed bind while a
    /// token is live is retried on a bounded backoff, not parked until
    /// the next liveness edge. Returns when the liveness sender is
    /// dropped.
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

                // Bind, retrying on a bounded backoff while the token
                // stays live (a single failure must not leave a live
                // token with no listener until the count CHANGES).
                let mut retry = BIND_RETRY_MIN;
                let listener = loop {
                    if *liveness.borrow() == 0 {
                        break None;
                    }
                    match TcpListener::bind(bind).await {
                        Ok(l) => break Some(l),
                        Err(e) => {
                            stats.bind_failures.fetch_add(1, Ordering::Relaxed);
                            tracing::error!(
                                %bind, error = %e, retry_in = ?retry,
                                "enrollment listener bind failed while a join token is live"
                            );
                            tokio::select! {
                                _ = tokio::time::sleep(retry) => {}
                                changed = liveness.changed() => {
                                    if changed.is_err() {
                                        return;
                                    }
                                }
                            }
                            retry = (retry * 2).min(BIND_RETRY_MAX);
                        }
                    }
                };
                let Some(listener) = listener else {
                    continue; // token gone while retrying: back to closed
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
                // In-flight connections belong to the open phase:
                // dropping the set (auto-close, or the whole task on
                // shutdown) aborts them.
                let mut conns: JoinSet<()> = JoinSet::new();

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
                            let liveness = liveness.clone();
                            conns.spawn(async move {
                                serve_enrollment_conn(
                                    tcp, peer, acceptor, budgets, stats, enrollments, liveness,
                                )
                                .await;
                                drop(hs_permit);
                            });
                        }
                        Some(_) = conns.join_next(), if !conns.is_empty() => {}
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

                // AC #2 auto-close: last token burned or expired. The
                // socket AND every pre-authentication connection go.
                drop(listener);
                conns.abort_all();
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
    liveness: TokenLiveness,
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
                    .rejected_handshake_failed
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
        if !negotiated_cluster_alpn(tls.get_ref().1) {
            stats.rejected_alpn.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "enrollment peer did not negotiate the cluster ALPN");
            return;
        }

        // The window may have closed while this handshake ran: an
        // enrollment must never proceed past the last token's death.
        if *liveness.borrow() == 0 {
            stats.rejected_window_closed.fetch_add(1, Ordering::Relaxed);
            return;
        }

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
        let mut refusal = ClusterResponse::refusal(ClusterStatus::opaque());
        refusal.sequence = sequence;
        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Response(refusal)),
        };
        let encoded = frame.encode_to_vec();
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
/// binary, AC #12). All monotonic.
#[derive(Debug, Default)]
pub struct OperationalStats {
    /// Connections dropped before a task existed for them:
    /// `max_concurrent_handshakes` already in flight.
    pub rejected_concurrent_handshakes: AtomicU64,
    /// TLS handshakes that exceeded `handshake_timeout`.
    pub handshake_timeouts: AtomicU64,
    /// TLS handshakes that failed (no/invalid client certificate).
    pub tls_failures: AtomicU64,
    /// Authenticated peers dropped for not negotiating the cluster
    /// ALPN.
    pub alpn_refusals: AtomicU64,
    /// Sessions admitted through the handshake.
    pub sessions_admitted: AtomicU64,
    /// Sessions answered RETRY_LATER by the admission gate (AC #10).
    pub sessions_retry_later: AtomicU64,
    /// Sessions answered RETRY_LATER because `max_sessions` are
    /// already established.
    pub sessions_rejected_full: AtomicU64,
    /// Handshakes refused (version / schema / protocol violation).
    pub handshake_refusals: AtomicU64,
    /// Established-session requests refused by the bridge whitelist;
    /// each one also dropped its connection (AC #6).
    pub protocol_violations: AtomicU64,
    /// Requests for a method this build does not implement, answered
    /// UNSUPPORTED_METHOD with the connection kept (AC #4).
    pub unsupported_methods: AtomicU64,
    /// Heartbeats served in-plane.
    pub heartbeats_served: AtomicU64,
    /// Established sessions that ended (any cause).
    pub sessions_ended: AtomicU64,
}

/// Everything known about an established operational session; the
/// per-session log context now, the handler input for Stories 9.3
/// (identity, fencing) and 9.4 (dispatch).
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Lowercase-hex SHA-256 of the peer's leaf certificate DER - the
    /// identity Story 9.3 records at enrollment and matches here.
    /// `None` only if the TLS layer exposed no chain (it always does
    /// on the operational path, where client auth is mandatory).
    pub peer_cert_fingerprint: Option<String>,
    /// The protocol version both sides agreed on (AC #4).
    pub negotiated_version: u32,
    /// The supervisor takeover epoch this session was accepted under
    /// (Story 9.1 AC #7; Story 9.3's registry fences older epochs).
    pub takeover_epoch: u64,
}

impl SessionContext {
    /// First 16 hex characters of the fingerprint for log lines, or
    /// `-` when absent.
    pub fn fingerprint_prefix(&self) -> &str {
        self.peer_cert_fingerprint
            .as_deref()
            .map(|fp| &fp[..fp.len().min(16)])
            .unwrap_or("-")
    }
}

/// Inputs for [`OperationalListener::spawn`].
pub struct OperationalConfig {
    /// The already-bound socket (the binary owns bind validation and
    /// logging, AC #11).
    pub listener: TcpListener,
    /// Mandatory-mTLS acceptor; read per accept (Story 9.3's
    /// revocation seam).
    pub acceptor: Arc<SwappableAcceptor>,
    /// Protocol range and schema version for the session handshake.
    pub handshake: HandshakeConfig,
    /// Fleet-size hint handed to peers (loaded per handshake and
    /// heartbeat so it tracks roster growth).
    pub fleet_size: Arc<AtomicU32>,
    /// Convergence admission control (AC #10).
    pub admission: Arc<AdmissionGate>,
    /// Counters (bridged to Prometheus by the binary).
    pub stats: Arc<OperationalStats>,
    /// Pre-TLS budgets applied to the handshake phase
    /// (`handshake_timeout`, `max_concurrent_handshakes`).
    pub budgets: PreAuthBudgets,
    /// Cap on established sessions; past it a peer is answered
    /// RETRY_LATER after its opener.
    pub max_sessions: usize,
    /// The supervisor takeover epoch stamped into every
    /// [`SessionContext`].
    pub takeover_epoch: u64,
}

/// Handle to a running operational listener.
pub struct OperationalHandle {
    task: JoinHandle<()>,
}

impl OperationalHandle {
    /// Stop accepting and tear down every established session (they
    /// live in a `JoinSet` owned by the accept task).
    pub fn shutdown(self) {
        self.task.abort();
    }
}

/// State shared by every operational connection task.
struct OperationalShared {
    acceptor: Arc<SwappableAcceptor>,
    handshake: HandshakeConfig,
    fleet_size: Arc<AtomicU32>,
    admission: Arc<AdmissionGate>,
    stats: Arc<OperationalStats>,
    budgets: PreAuthBudgets,
    session_slots: Arc<Semaphore>,
    takeover_epoch: u64,
}

/// The mandatory-mTLS operational listener (AC #2).
pub struct OperationalListener;

impl OperationalListener {
    /// Spawn the accept loop.
    ///
    /// Per connection: a concurrent-handshake permit BEFORE the task
    /// is spawned (excess connections are dropped and counted), mTLS
    /// accept under `handshake_timeout` (each accept reads the CURRENT
    /// config from the acceptor, Story 9.3's revocation seam), the
    /// ALPN check, the opener read (bounded), the session cap, the
    /// admission gate with a bounded queued wait (AC #10), the session
    /// handshake (AC #4/#5), then the steady-state loop with every
    /// inbound request routed through the bridge whitelist (AC #6).
    pub fn spawn(config: OperationalConfig) -> OperationalHandle {
        let OperationalConfig {
            listener,
            acceptor,
            handshake,
            fleet_size,
            admission,
            stats,
            budgets,
            max_sessions,
            takeover_epoch,
        } = config;
        let shared = Arc::new(OperationalShared {
            acceptor,
            handshake,
            fleet_size,
            admission,
            stats,
            session_slots: Arc::new(Semaphore::new(max_sessions)),
            takeover_epoch,
            budgets,
        });
        let handshakes = Arc::new(Semaphore::new(shared.budgets.max_concurrent_handshakes));
        let task = tokio::spawn(async move {
            // Sessions live in a JoinSet so that aborting the accept
            // task (OperationalHandle::shutdown) also tears down every
            // established session, not just the accept loop.
            let mut sessions: JoinSet<()> = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((tcp, peer)) = accepted else { continue };
                        // Pre-TLS bound: no task, no socket held, no
                        // rustls state for a peer past the cap.
                        let Ok(hs_permit) = Arc::clone(&handshakes).try_acquire_owned() else {
                            shared
                                .stats
                                .rejected_concurrent_handshakes
                                .fetch_add(1, Ordering::Relaxed);
                            drop(tcp);
                            continue;
                        };
                        let shared = Arc::clone(&shared);
                        sessions.spawn(async move {
                            serve_operational_conn(tcp, peer, shared, hs_permit).await;
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

/// Grace period for a refusal to flush before the endpoint (and its
/// writer task) drops.
const REFUSAL_FLUSH_GRACE: Duration = Duration::from_secs(2);

/// Lowercase-hex SHA-256 of the peer's leaf certificate, if the TLS
/// layer exposed one.
fn peer_fingerprint(conn: &CommonState) -> Option<String> {
    let leaf = conn.peer_certificates()?.first()?;
    let digest = ring::digest::digest(&ring::digest::SHA256, leaf.as_ref());
    Some(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

async fn serve_operational_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    shared: Arc<OperationalShared>,
    hs_permit: OwnedSemaphorePermit,
) {
    let stats = &shared.stats;
    let tls_acceptor = TlsAcceptor::from(shared.acceptor.current());
    let tls = match tokio::time::timeout(
        shared.budgets.handshake_timeout,
        tls_acceptor.accept(tcp),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            stats.tls_failures.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, error = %e, "operational mTLS handshake refused");
            return;
        }
        Err(_) => {
            stats.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "operational TLS handshake timed out");
            return;
        }
    };
    // The TLS phase is over: release the pre-auth permit so the
    // handshake cap only ever counts handshakes.
    drop(hs_permit);

    let conn: &CommonState = tls.get_ref().1;
    if !negotiated_cluster_alpn(conn) {
        stats.alpn_refusals.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%peer, "authenticated peer did not negotiate the cluster ALPN; dropped");
        return;
    }
    // Captured BEFORE the stream is split into the endpoint - the
    // one value that becomes unreachable afterwards.
    let fingerprint = peer_fingerprint(conn);

    // Session cap: taken before the opener so a stalling
    // authenticated peer holds a bounded slot, never an unbounded task.
    let session_permit = Arc::clone(&shared.session_slots).try_acquire_owned();

    let (endpoint, mut incoming) =
        RpcEndpoint::<ClusterFrame>::with_limits(tls, cluster_rpc_limits());

    let Ok(Some(opener)) =
        tokio::time::timeout(OPERATIONAL_OPENER_TIMEOUT, incoming.recv()).await
    else {
        tracing::debug!(%peer, "authenticated peer sent no opener within the budget");
        return;
    };

    let Ok(_session_permit) = session_permit else {
        stats.sessions_rejected_full.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%peer, "session cap reached; answering RETRY_LATER");
        reply_retry_later(opener, &mut incoming, shared.admission.retry_after_s_hint()).await;
        return;
    };

    // Admission (AC #10): bounded queued wait, RETRY_LATER on expiry.
    let permit = match shared.admission.admit().await {
        AdmissionDecision::Admitted(permit) => permit,
        AdmissionDecision::RetryLater { retry_after_s } => {
            stats.sessions_retry_later.fetch_add(1, Ordering::Relaxed);
            reply_retry_later(opener, &mut incoming, retry_after_s).await;
            return;
        }
    };

    let hint = shared.fleet_size.load(Ordering::Relaxed);
    let ack = match serve_hello(opener, &shared.handshake, hint).await {
        Ok(Ok(ack)) => ack,
        Ok(Err(status)) => {
            stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, ?status, "cluster session refused at handshake");
            // Keep the endpoint alive briefly so the refusal flushes.
            let _ = tokio::time::timeout(REFUSAL_FLUSH_GRACE, incoming.recv()).await;
            return;
        }
        Err(e) => {
            tracing::debug!(%peer, error = %e, "cluster handshake transport failure");
            return;
        }
    };
    stats.sessions_admitted.fetch_add(1, Ordering::Relaxed);
    // Convergence is over once the handshake completed (Story 9.4
    // will extend the hold across the initial config pull).
    drop(permit);

    let ctx = SessionContext {
        peer_addr: peer,
        peer_cert_fingerprint: fingerprint,
        negotiated_version: ack.negotiated_version,
        takeover_epoch: shared.takeover_epoch,
    };
    tracing::info!(
        peer = %ctx.peer_addr,
        fingerprint = ctx.fingerprint_prefix(),
        protocol = ctx.negotiated_version,
        epoch = ctx.takeover_epoch,
        "cluster session established"
    );

    serve_session(&endpoint, &mut incoming, &shared, &ctx).await;
    stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        peer = %ctx.peer_addr,
        fingerprint = ctx.fingerprint_prefix(),
        "cluster session ended"
    );
}

/// Answer RETRY_LATER on the opener's sequence and give the reply a
/// moment to flush before the endpoint drops.
async fn reply_retry_later(
    opener: IncomingRequest<ClusterFrame>,
    incoming: &mut IncomingRequests<ClusterFrame>,
    retry_after_s: u32,
) {
    let _ = opener
        .reply_frame(ClusterResponse::retry_later(retry_after_s))
        .await;
    let _ = tokio::time::timeout(REFUSAL_FLUSH_GRACE, incoming.recv()).await;
}

/// Steady-state loop for an established operational session: EVERY
/// inbound request routes through the bridge whitelist; a violation
/// answers `PROTOCOL_VIOLATION` and drops the connection (AC #6), an
/// unknown method answers `UNSUPPORTED_METHOD` and keeps it (AC #4).
async fn serve_session(
    _endpoint: &RpcEndpoint<ClusterFrame>,
    incoming: &mut IncomingRequests<ClusterFrame>,
    shared: &OperationalShared,
    ctx: &SessionContext,
) {
    let stats = &shared.stats;
    while let Some(request) = incoming.recv().await {
        match translate_cluster_request(request.request()) {
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat { timestamp_ms }) => {
                stats.heartbeats_served.fetch_add(1, Ordering::Relaxed);
                let ack = HeartbeatAck {
                    timestamp_ms,
                    fleet_size_hint: shared.fleet_size.load(Ordering::Relaxed),
                };
                if request
                    .reply_frame(ClusterResponse::ok(cluster_response::Body::HeartbeatAck(
                        ack,
                    )))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            BridgeOutcome::Unsupported { body_kind } => {
                stats.unsupported_methods.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    peer = %ctx.peer_addr,
                    fingerprint = ctx.fingerprint_prefix(),
                    body_kind,
                    "cluster request for a method this build does not implement; refused, session kept"
                );
                if request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            BridgeOutcome::ProtocolViolation => {
                stats.protocol_violations.fetch_add(1, Ordering::Relaxed);
                // The highest-signal security event on this plane: an
                // enrolled node speaking out of plane or out of phase.
                // Story 9.3 routes it into the audit log once the peer
                // identity is in the roster.
                tracing::warn!(
                    peer = %ctx.peer_addr,
                    fingerprint = ctx.fingerprint_prefix(),
                    "cluster protocol violation from an authenticated peer; dropping the session"
                );
                let _ = request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::ProtocolViolation))
                    .await;
                // Drop the connection: returning drops the incoming
                // half; the caller drops the endpoint.
                return;
            }
        }
    }
}
