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

//! The mandatory-mTLS operational listener (Story 9.2 AC #2/#10,
//! Story 9.3 AC #7/#8).
//!
//! Per connection, in order: handshake permit and per-source slot
//! (taken in the accept loop, before a task exists), mTLS accept under
//! `handshake_timeout` (each accept reads the CURRENT config from the
//! acceptor - the revocation seam), the ALPN check, identity
//! resolution from the peer certificate fingerprint against the
//! roster (unknown or revoked: dropped and audited, nothing read), the
//! opener read under `opener_timeout` while the handshake permit is
//! STILL held (an authenticated peer that never speaks holds a
//! bounded, per-source-capped pre-session slot and no session slot),
//! the session cap, then the handshake permit is released into the
//! session pool, the admission gate with a bounded queued wait
//! (AC #10), the session handshake (AC #4/#5), registration in the
//! session registry (superseding the node's older session; the
//! registry's kill switch ends the session synchronously on
//! revocation), and the steady-state loop with every inbound request
//! routed through the bridge whitelist (AC #6).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::rustls::CommonState;
use tokio_rustls::TlsAcceptor;

use lorica_command::{IncomingRequest, IncomingRequests, RpcEndpoint};

use crate::admission::{AdmissionDecision, AdmissionGate};
use crate::bridge::{translate_cluster_request, BridgeOutcome, InPlaneAction};
use crate::enroll::{RenewRequest, SessionHandler};
use crate::handshake::{serve_hello, HandshakeConfig};
use crate::limits::cluster_rpc_limits;
use crate::messages::{
    cluster_response, ClusterFrame, ClusterResponse, ClusterStatus, HeartbeatAck, LeaveAck,
    RenewAck,
};
use crate::preauth::{accept_error_pause, PreAuthBudgets, SourceGate, SourceSlot};
use crate::roster::{NodeIdentity, NodeState, Roster, SessionGuard, SessionRegistry};
use crate::session::SessionContext;
use crate::tls::{negotiated_cluster_alpn, peer_fingerprint, SwappableAcceptor};

/// Default cap on established sessions (one per follower plus
/// headroom); past it a peer is answered RETRY_LATER after its opener.
pub const DEFAULT_MAX_SESSIONS: usize = 1024;

/// Default bound on the wait for an authenticated peer's opener. Short
/// on purpose: the peer already completed TLS and holds a pre-session
/// slot, and a well-behaved dialer sends its Hello immediately.
pub const DEFAULT_OPENER_TIMEOUT: Duration = Duration::from_secs(3);

/// Default convergence admission (AC #10): sessions converging at
/// once.
pub const DEFAULT_ADMISSION_MAX_CONCURRENT: usize = 32;
/// Default convergence admission: how many more may queue.
pub const DEFAULT_ADMISSION_QUEUE_DEPTH: usize = 128;
/// Default convergence admission: what a queued-out peer is told to
/// wait before retrying, in seconds.
pub const DEFAULT_ADMISSION_RETRY_AFTER_S: u32 = 5;

/// Grace period for a refusal to flush before the endpoint (and its
/// writer task) drops.
const REFUSAL_FLUSH_GRACE: Duration = Duration::from_secs(1);

/// Renewals one session may request before it is treated as a
/// protocol violation: a well-behaved follower renews once per
/// session, twice at most across a retry; more is a peer abusing the
/// signing path (each grant costs the control plane a signature and
/// a CRL entry).
const MAX_RENEWALS_PER_SESSION: u32 = 3;

/// Operational-listener counters (bridged to Prometheus by the
/// binary, AC #12). All monotonic.
#[derive(Debug, Default)]
pub struct OperationalStats {
    /// `accept()` calls that failed (descriptor exhaustion and the
    /// like); each one pauses the loop instead of spinning it.
    pub accept_errors: AtomicU64,
    /// Connections dropped before a task existed for them:
    /// `max_concurrent_handshakes` already in flight.
    pub rejected_concurrent_handshakes: AtomicU64,
    /// Connections dropped before a task existed for them: the source
    /// already holds `max_per_source` pre-session connections.
    pub rejected_per_source: AtomicU64,
    /// TLS handshakes that exceeded `handshake_timeout`.
    pub handshake_timeouts: AtomicU64,
    /// TLS handshakes that failed (no/invalid/revoked client
    /// certificate).
    pub tls_failures: AtomicU64,
    /// Authenticated peers dropped for not negotiating the cluster
    /// ALPN.
    pub alpn_refusals: AtomicU64,
    /// Authenticated peers whose certificate resolved to no enrolled
    /// node, or to a revoked one (Story 9.3 AC #8): dropped and
    /// audited before any byte was read.
    pub identity_refusals: AtomicU64,
    /// Authenticated peers that sent no opener within
    /// `opener_timeout`.
    pub opener_timeouts: AtomicU64,
    /// Authenticated peers whose connection failed during the session
    /// handshake (closed before or while the Hello was in flight).
    pub handshake_transport_failures: AtomicU64,
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
    /// Certificate renewals issued over a session (Story 9.3 AC #12).
    pub renewals_served: AtomicU64,
    /// Nodes that left the fleet over their session (Story 9.3
    /// AC #13).
    pub leaves_served: AtomicU64,
    /// Sessions ended by the registry's kill switch (revocation or
    /// supersession by a newer session of the same node).
    pub sessions_killed: AtomicU64,
    /// Established sessions that ended (any cause).
    pub sessions_ended: AtomicU64,
}

/// The fleet layer the listener consults once a peer is
/// authenticated: identity resolution, the session registry and the
/// binary's lifecycle hooks. Absent in transport-only tests.
#[derive(Clone)]
pub struct FleetHooks {
    /// Fingerprint -> identity.
    pub roster: Arc<Roster>,
    /// Live sessions with kill switches.
    pub sessions: Arc<SessionRegistry>,
    /// Renewal, leave and audit hooks.
    pub handler: Arc<dyn SessionHandler>,
}

/// Inputs for [`OperationalListener::spawn`]. Construct with
/// [`OperationalConfig::new`] and override what differs from the
/// documented defaults; every field stays public.
pub struct OperationalConfig {
    /// The already-bound socket (the binary owns bind validation and
    /// logging, AC #11).
    pub listener: TcpListener,
    /// Mandatory-mTLS acceptor; read per accept (the revocation seam).
    pub acceptor: Arc<SwappableAcceptor>,
    /// Protocol range and schema version for the session handshake.
    pub handshake: HandshakeConfig,
    /// Fleet-size hint handed to peers (loaded per handshake and
    /// heartbeat so it tracks roster growth). Default 0.
    pub fleet_size: Arc<AtomicU32>,
    /// Convergence admission control (AC #10). Default: the
    /// `DEFAULT_ADMISSION_*` constants.
    pub admission: Arc<AdmissionGate>,
    /// Counters (bridged to Prometheus by the binary).
    pub stats: Arc<OperationalStats>,
    /// Pre-session budgets (`handshake_timeout`,
    /// `max_concurrent_handshakes`, `max_per_source`). Default:
    /// [`PreAuthBudgets::default`].
    pub budgets: PreAuthBudgets,
    /// Cap on established sessions; past it a peer is answered
    /// RETRY_LATER after its opener. Default [`DEFAULT_MAX_SESSIONS`].
    pub max_sessions: usize,
    /// Bound on the wait for an authenticated peer's opener. Default
    /// [`DEFAULT_OPENER_TIMEOUT`].
    pub opener_timeout: Duration,
    /// The supervisor takeover epoch stamped into every
    /// [`SessionContext`]. Default 0.
    pub takeover_epoch: u64,
    /// The fleet layer (roster, registry, hooks). Default `None`:
    /// every authenticated peer is served without identity, the
    /// transport-only mode the 9.2 tests exercise.
    pub fleet: Option<FleetHooks>,
}

impl OperationalConfig {
    /// A config with the documented defaults for everything but the
    /// three inputs that have none.
    pub fn new(
        listener: TcpListener,
        acceptor: Arc<SwappableAcceptor>,
        handshake: HandshakeConfig,
    ) -> Self {
        Self {
            listener,
            acceptor,
            handshake,
            fleet_size: Arc::new(AtomicU32::new(0)),
            admission: Arc::new(AdmissionGate::new(
                DEFAULT_ADMISSION_MAX_CONCURRENT,
                DEFAULT_ADMISSION_QUEUE_DEPTH,
                DEFAULT_ADMISSION_RETRY_AFTER_S,
            )),
            stats: Arc::new(OperationalStats::default()),
            budgets: PreAuthBudgets::default(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            opener_timeout: DEFAULT_OPENER_TIMEOUT,
            takeover_epoch: 0,
            fleet: None,
        }
    }
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
    opener_timeout: Duration,
    takeover_epoch: u64,
    fleet: Option<FleetHooks>,
}

/// The mandatory-mTLS operational listener (AC #2).
pub struct OperationalListener;

impl OperationalListener {
    /// Spawn the accept loop (see the module doc for the per-connection
    /// sequence).
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
            opener_timeout,
            takeover_epoch,
            fleet,
        } = config;
        let handshakes = Arc::new(Semaphore::new(budgets.max_concurrent_handshakes));
        let sources = SourceGate::new(budgets.max_per_source);
        let shared = Arc::new(OperationalShared {
            acceptor,
            handshake,
            fleet_size,
            admission,
            stats,
            budgets,
            session_slots: Arc::new(Semaphore::new(max_sessions)),
            opener_timeout,
            takeover_epoch,
            fleet,
        });
        let task = tokio::spawn(async move {
            // Sessions live in a JoinSet so that aborting the accept
            // task (OperationalHandle::shutdown) also tears down every
            // established session, not just the accept loop.
            let mut sessions: JoinSet<()> = JoinSet::new();
            let mut accept_errors: u64 = 0;
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, peer) = match accepted {
                            Ok(accepted) => accepted,
                            Err(e) => {
                                accept_errors += 1;
                                shared.stats.accept_errors.fetch_add(1, Ordering::Relaxed);
                                accept_error_pause("operational", &e, accept_errors).await;
                                continue;
                            }
                        };
                        // Pre-TLS bounds: no task, no socket held, no
                        // rustls state for a peer past the global cap
                        // or its source's cap.
                        let Ok(hs_permit) = Arc::clone(&handshakes).try_acquire_owned() else {
                            shared
                                .stats
                                .rejected_concurrent_handshakes
                                .fetch_add(1, Ordering::Relaxed);
                            drop(tcp);
                            continue;
                        };
                        let Some(source_slot) = sources.try_enter(peer.ip()) else {
                            shared.stats.rejected_per_source.fetch_add(1, Ordering::Relaxed);
                            drop(tcp);
                            continue;
                        };
                        let shared = Arc::clone(&shared);
                        sessions.spawn(async move {
                            serve_operational_conn(tcp, peer, shared, hs_permit, source_slot).await;
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

/// Resolve the authenticated peer against the roster (Story 9.3
/// AC #8). `Ok(None)` when no fleet layer is installed.
async fn resolve_identity(
    shared: &OperationalShared,
    fingerprint: Option<&str>,
    peer: SocketAddr,
) -> Result<Option<NodeIdentity>, ()> {
    let Some(fleet) = &shared.fleet else {
        return Ok(None);
    };
    let Some(fingerprint) = fingerprint else {
        // Mandatory client auth always yields a chain; treat its
        // absence as unknown rather than trusting the peer.
        shared.stats.identity_refusals.fetch_add(1, Ordering::Relaxed);
        fleet
            .handler
            .on_identity_refused("-", peer, "no peer certificate exposed")
            .await;
        return Err(());
    };
    let prefix = &fingerprint[..fingerprint.len().min(16)];
    match fleet.roster.lookup(fingerprint) {
        Some(identity) if identity.state != NodeState::Revoked => Ok(Some(identity)),
        Some(_) => {
            shared.stats.identity_refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, fingerprint = prefix, "revoked node reached identity resolution; dropped");
            fleet
                .handler
                .on_identity_refused(fingerprint, peer, "certificate revoked")
                .await;
            Err(())
        }
        None => {
            shared.stats.identity_refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, fingerprint = prefix, "valid cluster certificate with no enrolled node; dropped");
            fleet
                .handler
                .on_identity_refused(fingerprint, peer, "no enrolled node for this certificate")
                .await;
            Err(())
        }
    }
}

/// One operational connection from accept to session end.
/// `_source_slot` is held for the connection's whole life, so one
/// source holds at most `max_per_source` connections in ANY phase,
/// established sessions included.
async fn serve_operational_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    shared: Arc<OperationalShared>,
    hs_permit: OwnedSemaphorePermit,
    _source_slot: SourceSlot,
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

    let conn: &CommonState = tls.get_ref().1;
    if !negotiated_cluster_alpn(conn) {
        stats.alpn_refusals.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%peer, "authenticated peer did not negotiate the cluster ALPN; dropped");
        return;
    }
    // Captured BEFORE the stream is split into the endpoint - the
    // one value that becomes unreachable afterwards.
    let fingerprint = peer_fingerprint(conn);
    // Identity from the certificate, never from a payload (AC #8),
    // resolved before a single application byte is read.
    let Ok(node) = resolve_identity(&shared, fingerprint.as_deref(), peer).await else {
        return;
    };

    // The endpoint is bounded by the handshake permit (still held)
    // and the per-source slot until the peer earns a session slot.
    // `_endpoint` stays alive for the whole session: dropping it
    // closes the writer that replies ride on.
    let (_endpoint, mut incoming) =
        RpcEndpoint::<ClusterFrame>::with_limits(tls, cluster_rpc_limits());

    let opener = match tokio::time::timeout(shared.opener_timeout, incoming.recv()).await {
        Ok(Some(opener)) => opener,
        Ok(None) => {
            stats
                .handshake_transport_failures
                .fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "authenticated peer closed before sending an opener");
            return;
        }
        Err(_) => {
            stats.opener_timeouts.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%peer, "authenticated peer sent no opener within the budget");
            return;
        }
    };

    // Session cap: the peer spoke, so it may now compete for a
    // session slot; the pre-session permit goes back to the pool once
    // it holds one (the permit rule in `preauth`).
    let Ok(_session_permit) = Arc::clone(&shared.session_slots).try_acquire_owned() else {
        stats.sessions_rejected_full.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(%peer, "session cap reached; answering RETRY_LATER");
        reply_retry_later(opener, &mut incoming, shared.admission.retry_after_s_hint()).await;
        return;
    };
    drop(hs_permit);

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
    let (ack, hello) = match serve_hello(opener, &shared.handshake, hint).await {
        Ok(Ok(admitted)) => admitted,
        Ok(Err(status)) => {
            stats.handshake_refusals.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(%peer, ?status, "cluster session refused at handshake");
            // Keep the endpoint alive briefly so the refusal flushes.
            let _ = tokio::time::timeout(REFUSAL_FLUSH_GRACE, incoming.recv()).await;
            return;
        }
        Err(e) => {
            stats
                .handshake_transport_failures
                .fetch_add(1, Ordering::Relaxed);
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
        node: node.clone(),
    };
    tracing::info!(
        peer = %ctx.peer_addr,
        fingerprint = ctx.fingerprint_prefix(),
        node_id = ctx.node_id().unwrap_or("-"),
        protocol = ctx.negotiated_version,
        epoch = ctx.takeover_epoch,
        "cluster session established"
    );

    // Register in the fleet layer: supersede the node's older
    // session, tell the binary (it retires a superseded certificate
    // on the first session over the new one), hold the kill switch.
    let guard: Option<SessionGuard> = match (&shared.fleet, &node) {
        (Some(fleet), Some(identity)) => {
            let guard = fleet.sessions.register(
                &identity.node_id,
                peer,
                &hello.build_version,
                hello.schema_version,
            );
            fleet
                .handler
                .on_session_established(
                    &identity.node_id,
                    identity.via_previous_certificate,
                    peer,
                    &hello.build_version,
                    hello.schema_version,
                )
                .await;
            Some(guard)
        }
        _ => None,
    };

    serve_session(&mut incoming, &shared, &ctx, guard).await;
    stats.sessions_ended.fetch_add(1, Ordering::Relaxed);
    tracing::info!(
        peer = %ctx.peer_addr,
        fingerprint = ctx.fingerprint_prefix(),
        node_id = ctx.node_id().unwrap_or("-"),
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

/// Why the steady-state loop returned.
enum SessionEnd {
    /// The peer went away or the loop chose to drop it.
    Closed,
    /// The registry's kill switch fired.
    Killed,
}

/// Steady-state loop for an established operational session: EVERY
/// inbound request routes through the bridge whitelist; a violation
/// answers `PROTOCOL_VIOLATION` and drops the connection (AC #6), an
/// unknown method answers `UNSUPPORTED_METHOD` and keeps it (AC #4).
/// The registry's kill switch (revocation, supersession) ends the
/// loop synchronously.
async fn serve_session(
    incoming: &mut IncomingRequests<ClusterFrame>,
    shared: &OperationalShared,
    ctx: &SessionContext,
    mut guard: Option<SessionGuard>,
) {
    let stats = &shared.stats;
    let mut renewals: u32 = 0;
    loop {
        let request = match &mut guard {
            Some(guard) => {
                tokio::select! {
                    next = incoming.recv() => match next {
                        Some(request) => request,
                        None => break,
                    },
                    _ = guard.killed() => {
                        stats.sessions_killed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            peer = %ctx.peer_addr,
                            node_id = ctx.node_id().unwrap_or("-"),
                            "cluster session ended by the registry (revoked or superseded)"
                        );
                        return;
                    }
                }
            }
            None => match incoming.recv().await {
                Some(request) => request,
                None => break,
            },
        };
        if let Some(guard) = &guard {
            guard.entry().touch();
        }
        match serve_request(request, shared, ctx, &mut renewals).await {
            Some(SessionEnd::Closed) => return,
            Some(SessionEnd::Killed) => return,
            None => {}
        }
    }
}

/// Serve one inbound request; `Some` ends the session.
async fn serve_request(
    request: IncomingRequest<ClusterFrame>,
    shared: &OperationalShared,
    ctx: &SessionContext,
    renewals: &mut u32,
) -> Option<SessionEnd> {
    let stats = &shared.stats;
    match translate_cluster_request(request.request()) {
        BridgeOutcome::InPlane(InPlaneAction::Heartbeat { timestamp_ms }) => {
            stats.heartbeats_served.fetch_add(1, Ordering::Relaxed);
            let ack = HeartbeatAck {
                timestamp_ms,
                fleet_size_hint: shared.fleet_size.load(Ordering::Relaxed),
            };
            request
                .reply_frame(ClusterResponse::ok(cluster_response::Body::HeartbeatAck(
                    ack,
                )))
                .await
                .err()
                .map(|_| SessionEnd::Closed)
        }
        BridgeOutcome::InPlane(InPlaneAction::Renew { public_key_der }) => {
            let (Some(fleet), Some(node_id)) = (&shared.fleet, ctx.node_id()) else {
                // No fleet layer: the method exists but nobody can
                // serve it here.
                return request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
                    .await
                    .err()
                    .map(|_| SessionEnd::Closed);
            };
            *renewals += 1;
            if *renewals > MAX_RENEWALS_PER_SESSION {
                stats.protocol_violations.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(peer = %ctx.peer_addr, node_id, "renewal flood; dropping the session");
                fleet
                    .handler
                    .on_protocol_violation(node_id, ctx.peer_addr)
                    .await;
                let _ = request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::ProtocolViolation))
                    .await;
                tokio::time::sleep(REFUSAL_FLUSH_GRACE).await;
                return Some(SessionEnd::Closed);
            }
            let renewed = fleet
                .handler
                .on_renew(RenewRequest {
                    node_id: node_id.to_string(),
                    peer: ctx.peer_addr,
                    public_key_der,
                })
                .await;
            let reply = match renewed {
                Ok(grant) => {
                    stats.renewals_served.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(peer = %ctx.peer_addr, node_id, "node certificate renewed");
                    ClusterResponse::ok(cluster_response::Body::RenewAck(RenewAck {
                        cert_pem: grant.cert_pem,
                        cert_not_after: grant.cert_not_after,
                    }))
                }
                Err(reason) => {
                    tracing::warn!(peer = %ctx.peer_addr, node_id, %reason, "node certificate renewal refused");
                    ClusterResponse::refusal(ClusterStatus::Unspecified)
                }
            };
            request
                .reply_frame(reply)
                .await
                .err()
                .map(|_| SessionEnd::Closed)
        }
        BridgeOutcome::InPlane(InPlaneAction::Leave) => {
            let (Some(fleet), Some(node_id)) = (&shared.fleet, ctx.node_id()) else {
                return request
                    .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
                    .await
                    .err()
                    .map(|_| SessionEnd::Closed);
            };
            match fleet.handler.on_leave(node_id, ctx.peer_addr).await {
                Ok(()) => {
                    stats.leaves_served.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(peer = %ctx.peer_addr, node_id, "node left the fleet");
                    let _ = request
                        .reply_frame(ClusterResponse::ok(cluster_response::Body::LeaveAck(
                            LeaveAck {},
                        )))
                        .await;
                    // The node is revoked now; its session ends with
                    // the acknowledgement.
                    tokio::time::sleep(REFUSAL_FLUSH_GRACE).await;
                    Some(SessionEnd::Killed)
                }
                Err(reason) => {
                    tracing::warn!(peer = %ctx.peer_addr, node_id, %reason, "leave refused");
                    request
                        .reply_frame(ClusterResponse::refusal(ClusterStatus::Unspecified))
                        .await
                        .err()
                        .map(|_| SessionEnd::Closed)
                }
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
            request
                .reply_frame(ClusterResponse::refusal(ClusterStatus::UnsupportedMethod))
                .await
                .err()
                .map(|_| SessionEnd::Closed)
        }
        BridgeOutcome::ProtocolViolation => {
            stats.protocol_violations.fetch_add(1, Ordering::Relaxed);
            // The highest-signal security event on this plane: an
            // enrolled node speaking out of plane or out of phase.
            tracing::warn!(
                peer = %ctx.peer_addr,
                fingerprint = ctx.fingerprint_prefix(),
                node_id = ctx.node_id().unwrap_or("-"),
                "cluster protocol violation from an authenticated peer; dropping the session"
            );
            if let (Some(fleet), Some(node_id)) = (&shared.fleet, ctx.node_id()) {
                fleet
                    .handler
                    .on_protocol_violation(node_id, ctx.peer_addr)
                    .await;
            }
            let _ = request
                .reply_frame(ClusterResponse::refusal(ClusterStatus::ProtocolViolation))
                .await;
            // Let the refusal flush (the caller drops the endpoint,
            // and with it the writer, the moment this returns),
            // then drop the connection.
            tokio::time::sleep(REFUSAL_FLUSH_GRACE).await;
            Some(SessionEnd::Closed)
        }
    }
}
