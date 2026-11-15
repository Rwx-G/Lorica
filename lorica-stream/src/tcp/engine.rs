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

//! The TCP engine and its connection pipeline (Story 12.3 D-b):
//!
//! 1. **Admit**: canonicalise the peer, take a slot of the stream's cap
//!    or end `refused(connection_cap)`. Story 12.6's filters go here.
//! 2. **Pre-forwarding**: reads that must finish before a backend is
//!    chosen, bounded in bytes and time, keeping what they read past
//!    their need as the preamble. Here, a trusted peer's PROXY header;
//!    Story 12.4 adds the ClientHello, Story 12.15 detection.
//! 3. **Connect** ([`super::connect`]), then the PROXY header to the
//!    backend in plaintext, before anything else on the socket (the
//!    upstream TLS of Story 12.4 wraps the socket after it).
//! 4. **Forward** ([`super::forward`]).
//! 5. **End**: the end reason, the record to the observer, the cap slot
//!    and gauges released by drop.
//!
//! The tracker's close and the total timeout are watched beside every
//! await of phases 2 to 4, so a drain ends a connection in any phase.
//! Closing means `shutdown(Both)` on both sockets, then drop: the peers
//! see a FIN.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{StreamEndReason, StreamRefusal};
use lorica_core::protocols::proxy_protocol::HEADER_READ_TIMEOUT;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::debug;

use super::cap::ConnectionCaps;
use super::connect::{Connected, Request, Rotation, Shared};
use super::forward::{close, Forwarder};
use super::proxy_header::{canonical, is_trusted, read_trusted, send_header, HeaderRead};
use crate::counters::StreamCounters;
use crate::handler::{
    AcceptedConnection, ConnectionObserver, ConnectionRecord, HandlerFuture, StreamHandler,
};
use crate::local::BoundPorts;
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{BackendSelector, BreakerGate};
use crate::table::StreamTable;
use crate::tracker::TrackedConnection;

/// What the TCP engine is built from. The selector, the breaker gate
/// and the resolver cache are the process's, shared with the UDP engine
/// (Story 12.5 Interface edit E3); `counters` is the `Arc` the runtime's
/// [`crate::Engines::counters`] holds.
pub struct TcpEngineParts {
    /// Backend selection.
    pub selector: Arc<dyn BackendSelector>,
    /// The circuit breaker.
    pub breaker: Arc<dyn BreakerGate>,
    /// Host names and the node's interface addresses.
    pub resolver: Arc<ResolverCache>,
    /// The process's stream counters.
    pub counters: Arc<StreamCounters>,
    /// Where each connection's record goes.
    pub observer: Arc<dyn ConnectionObserver>,
    /// The node's reserved ports, for the connect-time local check;
    /// `None` until the process knows them (rule B then covers the
    /// stream listen ports only).
    pub reserved_ports: Option<ReservedPorts>,
}

/// The TCP stream engine, a [`StreamHandler`].
#[derive(Clone)]
pub struct TcpEngine {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TcpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpEngine").finish_non_exhaustive()
    }
}

struct Inner {
    shared: Shared,
    observer: Arc<dyn ConnectionObserver>,
    caps: ConnectionCaps,
}

impl TcpEngine {
    /// An engine over `parts`.
    pub fn new(parts: TcpEngineParts) -> Self {
        TcpEngine {
            inner: Arc::new(Inner {
                shared: Shared {
                    selector: parts.selector,
                    breaker: parts.breaker,
                    resolver: parts.resolver,
                    counters: parts.counters,
                    reserved: parts.reserved_ports,
                    exclusions: LocalExclusions::default(),
                    rotation: Rotation::default(),
                },
                observer: parts.observer,
                caps: ConnectionCaps::default(),
            }),
        }
    }
}

impl StreamHandler for TcpEngine {
    fn handle(&self, conn: AcceptedConnection) -> HandlerFuture {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.serve(conn).await })
    }

    fn table_changed(&self, table: &StreamTable) {
        let shared = &self.inner.shared;
        shared.resolver.track(table);
        shared.selector.table_changed(table);
        shared.counters.retain(table);
        shared.exclusions.retain(table);
        shared.rotation.retain(table);
        self.inner.caps.retain(table);
    }
}

/// Wait until `deadline`, or forever without one.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// Run `work` unless the tracker closes the connection or the total
/// timeout fires first; either gives the end reason. Dropping `work`
/// drops whatever it had in flight (a half-open backend socket among
/// them), which reports nothing to the breaker.
async fn guarded<T>(
    tracked: &mut TrackedConnection,
    total: Option<Instant>,
    work: impl std::future::Future<Output = T>,
) -> Result<T, StreamEndReason> {
    tokio::select! {
        biased;
        reason = tracked.closed() => Err(reason),
        _ = sleep_until_opt(total) => Err(StreamEndReason::TotalTimeout),
        out = work => Ok(out),
    }
}

/// One connection while the engine serves it.
struct Live {
    client: TcpStream,
    tracked: TrackedConnection,
    table: Arc<StreamTable>,
    bound_ports: BoundPorts,
    accepted_at: Instant,
    total: Option<Instant>,
    record: ConnectionRecord,
}

impl Inner {
    async fn serve(&self, conn: AcceptedConnection) {
        let accepted_at = Instant::now();
        let snapshot = Arc::clone(conn.tracked.snapshot());
        let stats = self.shared.counters.stream(&snapshot.id);
        let _active = stats.accept();
        let peer = canonical(conn.peer);
        let local = conn.stream.local_addr().map(canonical).unwrap_or(peer);
        let mut live = Live {
            client: conn.stream,
            tracked: conn.tracked,
            table: conn.table,
            bound_ports: conn.bound_ports,
            accepted_at,
            total: snapshot
                .total_timeout_s
                .map(|s| accepted_at + Duration::from_secs(u64::from(s))),
            record: ConnectionRecord {
                stream_id: snapshot.id.clone(),
                stream_name: snapshot.name.clone(),
                bind_gen: conn.bind_gen,
                client: peer,
                peer,
                proxied_from: None,
                local,
                backend_id: None,
                backend_address: None,
                attempts: 0,
                bytes_upload: 0,
                bytes_download: 0,
                accepted_at: Utc::now(),
                connected_at: None,
                ended_at: Utc::now(),
                end_reason: StreamEndReason::ClientClose,
            },
        };

        let natural = match self
            .caps
            .try_acquire(&snapshot.id, snapshot.max_connections)
        {
            None => {
                stats.refused(StreamRefusal::ConnectionCap);
                StreamEndReason::Refused(StreamRefusal::ConnectionCap)
            }
            Some(_slot) => self.pipeline(&mut live).await,
        };
        close(&live.client);
        let Live {
            tracked,
            mut record,
            ..
        } = live;
        let reason = tracked.finish(natural);
        stats.ended(reason.kind());
        record.end_reason = reason;
        record.ended_at = Utc::now();
        self.observer.observe(record);
    }

    /// Phases 2 to 4; returns the natural end reason.
    async fn pipeline(&self, live: &mut Live) -> StreamEndReason {
        let snapshot = Arc::clone(live.tracked.snapshot());
        let stats = self.shared.counters.stream(&snapshot.id);

        // Phase 2: a trusted peer's PROXY header.
        let trusted = snapshot.proxy_protocol_accept
            && is_trusted(
                live.record.peer.ip(),
                &snapshot.proxy_protocol_trusted_cidrs,
            );
        let mut destination = live.record.local;
        let mut preamble = Vec::new();
        if trusted {
            let read = guarded(
                &mut live.tracked,
                live.total,
                read_trusted(&mut live.client, live.accepted_at + HEADER_READ_TIMEOUT),
            )
            .await;
            match read {
                Err(reason) => return reason,
                Ok(HeaderRead::Refused(outcome)) => {
                    stats.proxy_header(outcome);
                    debug!(stream_id = %snapshot.id, peer = %live.record.peer,
                           outcome = outcome.as_str(), "PROXY header refused");
                    return StreamEndReason::ProxyHeaderInvalid;
                }
                Ok(HeaderRead::Accepted {
                    outcome,
                    carried,
                    preamble: rest,
                }) => {
                    stats.proxy_header(outcome);
                    if let Some((source, carried_destination)) = carried {
                        live.record.proxied_from = Some(live.record.peer);
                        live.record.client = source;
                        destination = carried_destination;
                    }
                    preamble = rest;
                }
            }
        }
        let classify = snapshot.proxy_protocol_accept && !trusted;

        // Phase 3: connect.
        let request = Request {
            stream: &snapshot,
            table: &live.table,
            listen_port: live.record.local.port(),
            client: live.record.client.ip(),
            accepted_at: live.accepted_at.into_std(),
            bound: &live.bound_ports,
            stats: &stats,
        };
        let mut attempts = 0;
        let connected = guarded(
            &mut live.tracked,
            live.total,
            self.shared.connect(&request, &mut attempts),
        )
        .await;
        live.record.attempts = attempts;
        let Connected {
            backend,
            address,
            socket: mut upstream,
            latency,
        } = match connected {
            Err(reason) | Ok(Err(reason)) => return reason,
            Ok(Ok(connected)) => connected,
        };
        live.tracked.set_backend(&backend.id);
        live.record.backend_id = Some(backend.id.clone());
        live.record.backend_address = Some(address);
        live.record.connected_at = Some(Utc::now());
        self.shared
            .selector
            .connected(&snapshot.id, &backend, address, latency);
        let _link_active = self
            .shared
            .counters
            .link(&snapshot.id, &backend.id)
            .connected(latency);

        // The PROXY header goes first, in plaintext. Committed: a failure
        // here is the backend's close, never a retry.
        let header = send_header(
            snapshot.proxy_protocol_send,
            live.record.client,
            destination,
        );
        let sent = match header {
            Some(header) => {
                match guarded(&mut live.tracked, live.total, upstream.write_all(&header)).await {
                    Err(reason) => Err(reason),
                    Ok(Err(_)) => Err(StreamEndReason::BackendClose),
                    Ok(Ok(())) => Ok(()),
                }
            }
            None => Ok(()),
        };

        // Phase 4: forward.
        let reason = match sent {
            Err(reason) => reason,
            Ok(()) => {
                let mut forwarder = Forwarder::new(
                    &snapshot,
                    live.accepted_at,
                    &preamble,
                    classify,
                    Arc::clone(&stats),
                );
                let reason = forwarder
                    .run(&mut live.client, &mut upstream, &mut live.tracked)
                    .await;
                live.record.bytes_upload = forwarder.upload().forwarded();
                live.record.bytes_download = forwarder.download().forwarded();
                reason
            }
        };
        close(&upstream);
        self.shared.selector.closed(&snapshot.id, &backend, address);
        reason
    }
}
