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

//! The token-gated enrollment listener (Story 9.2 AC #2/#3): the only
//! unauthenticated surface in the product.
//!
//! The socket exists only while a join token is live. Every accepted
//! connection takes a handshake permit and a per-source slot before a
//! task exists for it, completes TLS under the handshake budget, must
//! negotiate the cluster ALPN, is re-checked against token liveness,
//! and then enters the (smaller) enrollment-exchange pool, at which
//! point the handshake permit is released (see the permit rule in
//! [`crate::preauth`]). In Story 9.2, where redemption does not exist
//! yet, the exchange itself answers the OPAQUE status; Story 9.3
//! replaces that answer with token redemption behind a handler trait.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::listener::TokenLiveness;
use crate::messages::{cluster_frame, ClusterFrame, ClusterResponse, ClusterStatus};
use crate::preauth::{accept_error_pause, PreAuthBudgets, SourceGate, SourceSlot};
use crate::tls::{negotiated_cluster_alpn, SwappableAcceptor};

/// Enrollment-listener counters, one atomic per budget plus lifecycle
/// events, all monotonic; the binary exposes them as Prometheus
/// counters (AC #3: "exceeding any drops the connection and
/// increments a counter").
#[derive(Debug, Default)]
pub struct EnrollmentStats {
    /// Connections accepted (before any budget ran).
    pub connections_total: AtomicU64,
    /// `accept()` calls that failed (descriptor exhaustion and the
    /// like); each one pauses the loop instead of spinning it.
    pub accept_errors: AtomicU64,
    /// Dropped: the TLS handshake was rejected (bad ClientHello, no
    /// overlap, garbage).
    pub rejected_handshake_failed: AtomicU64,
    /// Dropped: the TLS handshake exceeded `handshake_timeout`.
    pub rejected_handshake_timeout: AtomicU64,
    /// Dropped: the peer completed TLS without the cluster ALPN.
    pub rejected_alpn: AtomicU64,
    /// Dropped: `max_concurrent_handshakes` already in flight.
    pub rejected_concurrent_handshakes: AtomicU64,
    /// Dropped: the peer's source already holds `max_per_source`
    /// pre-authentication connections.
    pub rejected_per_source: AtomicU64,
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

/// State shared by every connection of one open phase.
struct EnrollmentShared {
    acceptor: Arc<SwappableAcceptor>,
    budgets: PreAuthBudgets,
    stats: Arc<EnrollmentStats>,
    enrollments: Arc<Semaphore>,
}

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
                let sources = SourceGate::new(budgets.max_per_source);
                let shared = Arc::new(EnrollmentShared {
                    acceptor: Arc::clone(&acceptor),
                    budgets: budgets.clone(),
                    stats: Arc::clone(&stats),
                    enrollments: Arc::new(Semaphore::new(budgets.max_inflight_enrollments)),
                });
                // In-flight connections belong to the open phase:
                // dropping the set (auto-close, or the whole task on
                // shutdown) aborts them.
                let mut conns: JoinSet<()> = JoinSet::new();
                let mut accept_errors: u64 = 0;

                // Open phase: accept until liveness returns to zero.
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (tcp, peer) = match accepted {
                                Ok(accepted) => accepted,
                                Err(e) => {
                                    accept_errors += 1;
                                    stats.accept_errors.fetch_add(1, Ordering::Relaxed);
                                    accept_error_pause("enrollment", &e, accept_errors).await;
                                    continue;
                                }
                            };
                            stats.connections_total.fetch_add(1, Ordering::Relaxed);
                            // Pre-TLS bounds: no task, no socket held,
                            // no rustls state past the global cap or
                            // the per-source cap.
                            let Ok(hs_permit) =
                                Arc::clone(&handshakes).try_acquire_owned()
                            else {
                                stats
                                    .rejected_concurrent_handshakes
                                    .fetch_add(1, Ordering::Relaxed);
                                drop(tcp);
                                continue;
                            };
                            let Some(source_slot) = sources.try_enter(peer.ip()) else {
                                stats.rejected_per_source.fetch_add(1, Ordering::Relaxed);
                                drop(tcp);
                                continue;
                            };
                            let shared = Arc::clone(&shared);
                            let liveness = liveness.clone();
                            conns.spawn(async move {
                                serve_enrollment_conn(
                                    tcp, peer, shared, liveness, hs_permit, source_slot,
                                )
                                .await;
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
/// exact. `_source_slot` is held for the connection's whole life so
/// the per-source cap covers every phase.
async fn serve_enrollment_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    shared: Arc<EnrollmentShared>,
    liveness: TokenLiveness,
    hs_permit: OwnedSemaphorePermit,
    _source_slot: SourceSlot,
) {
    let stats = &shared.stats;
    let budgets = &shared.budgets;
    let overall = tokio::time::timeout(budgets.per_conn_max_duration, async {
        let tls_acceptor = TlsAcceptor::from(shared.acceptor.current());
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
        // (Point-in-time read; Story 9.3 re-checks liveness inside the
        // redemption transaction, where the burn is.)
        if *liveness.borrow() == 0 {
            stats.rejected_window_closed.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Post-TLS: the enrollment-exchange budget (distinct from the
        // handshake budget so slow verifications cannot starve
        // accepts). Once inside it, the handshake permit goes back to
        // the pool - the permit rule in `preauth`.
        let Ok(_enroll_permit) = Arc::clone(&shared.enrollments).try_acquire_owned() else {
            stats
                .rejected_inflight_enrollments
                .fetch_add(1, Ordering::Relaxed);
            return;
        };
        drop(hs_permit);

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
