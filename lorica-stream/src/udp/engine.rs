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

//! The UDP engine: the receive loop's synchronous path and the session
//! task.
//!
//! A client datagram, on the receive loop (D-c):
//!
//! 1. **Size**: over `udp.max_datagram_bytes` it is dropped
//!    (`request_oversize`).
//! 2. **Session**: one is open for its key: it is charged to its source
//!    and forwarded (or held while the session opens), and the session
//!    retires at its last request.
//! 3. **Drain**: on a draining binding a datagram that would open a
//!    session is dropped (`binding_draining`, D-m).
//! 4. **Admission**, the sequence of Story 12.6 D-a: the stream's region
//!    (`caps_unavailable` without one), the node's and the stream's
//!    source controls, then on the region the stream's and the source's
//!    open rates with the source's datagram and byte rates in one
//!    charge, then the stream and per-source session caps. A refusal is
//!    counted once, as the refusal, and goes to the refusal log; a
//!    datagram over its source's datagram or byte rate is a drop.
//! 5. **Spawn** the session task with the datagram held.
//!
//! The session task: selection (a link at its `max_active` left out,
//! Story 12.6 D-h) and breaker admission through the seams (D-i), the
//! local check, the upstream socket from `source_addresses` (D-a, D-f),
//! the held datagrams sent; then responses within the bounds of D-b,
//! idle and total timers, ICMP errors, the tracker's close; and at the
//! end the breaker report, the record, and the session's counts given
//! back.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{
    backend_address_host, backend_address_port, Backend, DatagramDropReason, HealthStatus,
    LifecycleState, Stream, StreamEndReason, StreamProtocol, StreamProxyProtocol, StreamRefusal,
    UdpSettings,
};
use lorica_core::protocols::proxy_protocol::encode_v2_dgram;
use lorica_shmem::{now_ns, BackendSlot, NewSessionVerdict, SourceKey, StreamPermit, WorkerCaps};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use super::session::{
    fits, icmp_kind, rate_limits, send_to_client, Bounds, Ending, Offer, Session, SessionKey,
};
use super::UPSTREAM_RECEIVE_BUFFER;
use crate::admission::{
    backend_at_cap, claim_backend, open_limits, udp_cap_refusal, AdmissionControl,
};
use crate::counters::{ActiveGuard, ConnectFailureKind, LinkStats, StreamCounters, StreamStats};
use crate::handler::{
    ConnectOutcome, ConnectionObserver, ConnectionRecord, Datagram, DatagramHandler, RefusalRecord,
};
use crate::listener::with_receive_buffer;
use crate::local::{BoundPorts, LocalRefusal, NodeLocality};
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{
    Admission, BackendSelector, BreakerGate, Candidate, SelectionRequest, SourceGate,
};
use crate::table::{LinkedBackend, StreamTable};
use crate::tracker::TrackedConnection;

/// What the UDP engine is built from: the process's selector, breaker
/// gate, resolver cache and counters, the same ones the TCP engine holds
/// (Story 12.5 Interface edit E3).
pub struct UdpEngineParts {
    /// Backend selection; least connections counts sessions.
    pub selector: Arc<dyn BackendSelector>,
    /// The circuit breaker.
    pub breaker: Arc<dyn BreakerGate>,
    /// Host names and the node's interface addresses.
    pub resolver: Arc<ResolverCache>,
    /// The process's stream counters.
    pub counters: Arc<StreamCounters>,
    /// Where each session's record and each admitted refusal goes.
    pub observer: Arc<dyn ConnectionObserver>,
    /// The node's reserved ports, for the local check; `None` until the
    /// process knows them.
    pub reserved_ports: Option<ReservedPorts>,
    /// The node's source controls (Story 12.6 D-d), shared with the TCP
    /// engine.
    pub source_gate: Arc<dyn SourceGate>,
}

/// The UDP stream engine, a [`DatagramHandler`].
#[derive(Clone)]
pub struct UdpEngine {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for UdpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpEngine")
            .field("sessions", &self.inner.sessions().len())
            .finish_non_exhaustive()
    }
}

struct Inner {
    selector: Arc<dyn BackendSelector>,
    breaker: Arc<dyn BreakerGate>,
    resolver: Arc<ResolverCache>,
    counters: Arc<StreamCounters>,
    observer: Arc<dyn ConnectionObserver>,
    reserved: Option<ReservedPorts>,
    exclusions: LocalExclusions,
    admission: AdmissionControl,
    /// The per-stream turn among `source_addresses` (D-f).
    source_turns: Mutex<HashMap<String, usize>>,
    /// The turn among a backend's resolved addresses.
    address_turn: AtomicUsize,
    /// The sessions taking requests, by key. A retired session leaves it
    /// and lives on in its task for the responses it is owed.
    sessions: Mutex<HashMap<SessionKey, Arc<Session>>>,
}

impl UdpEngine {
    /// An engine over `parts`.
    pub fn new(parts: UdpEngineParts) -> Self {
        UdpEngine {
            inner: Arc::new(Inner {
                selector: parts.selector,
                breaker: parts.breaker,
                resolver: parts.resolver,
                counters: parts.counters,
                admission: AdmissionControl::new(parts.source_gate, Arc::clone(&parts.observer)),
                observer: parts.observer,
                reserved: parts.reserved_ports,
                exclusions: LocalExclusions::default(),
                source_turns: Mutex::new(HashMap::new()),
                address_turn: AtomicUsize::new(0),
                sessions: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl DatagramHandler for UdpEngine {
    fn handle(&self, datagram: Datagram<'_>) {
        Inner::handle(&self.inner, datagram);
    }

    fn table_changed(&self, table: &StreamTable) {
        let inner = &self.inner;
        inner.resolver.track(table);
        inner.selector.table_changed(table);
        inner.counters.retain(table);
        inner.exclusions.retain(table);
        inner.admission.table_changed(table);
        inner
            .source_turns
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
    }
}

/// An address without its IPv4-mapped form.
fn canonical(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

/// Wait until `deadline`, or forever without one.
async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending().await,
    }
}

/// The port a session to `backend` uses: its own, or the listen port for
/// a portless backend of a range stream.
fn backend_port(backend: &Backend, listen_port: u16) -> u16 {
    backend_address_port(&backend.address)
        .ok()
        .flatten()
        .unwrap_or(listen_port)
}

/// What the session task needs beyond the shared session.
struct SessionTask {
    session: Arc<Session>,
    tracked: TrackedConnection,
    /// Holds the session's place in the region's counts until the end.
    permit: StreamPermit,
    active: ActiveGuard,
    stats: Arc<StreamStats>,
    /// The slot socket replies leave from. Dropped before `tracked`, so
    /// a draining binding's sockets close once its last session ends.
    slot: Arc<UdpSocket>,
    /// The client as the slot socket reports it, to answer to.
    client: SocketAddr,
    /// The address the client targeted, on a wildcard socket.
    reply_from: Option<IpAddr>,
    table: Arc<StreamTable>,
    bound_ports: BoundPorts,
    max_sessions: u64,
    accepted_at: Instant,
    accepted_wall: DateTime<Utc>,
}

/// A session's backend, once its upstream socket is connected.
struct Opened {
    backend: Arc<Backend>,
    address: SocketAddr,
    socket: Arc<UdpSocket>,
    was_probe: bool,
    /// The session's place on its link's `max_active`, if the link has
    /// one; held to the end of the session.
    _backend_slot: Option<BackendSlot>,
}

/// Why an upstream socket was not opened.
enum OpenError {
    /// No socket: nothing about the backend.
    Socket(io::Error),
    /// No source address of the stream could be bound.
    SourceBind(io::Error),
    /// The connect itself failed (no route): the backend's failure.
    Connect(io::Error),
}

/// One eligible backend of a session's selection.
struct Eligible<'a> {
    link: &'a LinkedBackend,
    addresses: Arc<[IpAddr]>,
    port: u16,
}

impl Inner {
    fn sessions(&self) -> MutexGuard<'_, HashMap<SessionKey, Arc<Session>>> {
        // Each critical section is one map operation.
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Remove `session` from the key map, if it is still the one there.
    fn forget(&self, session: &Arc<Session>) {
        let mut sessions = self.sessions();
        if sessions
            .get(&session.key)
            .is_some_and(|s| Arc::ptr_eq(s, session))
        {
            sessions.remove(&session.key);
        }
    }

    fn handle(self: &Arc<Self>, d: Datagram<'_>) {
        let snapshot = d.snapshot;
        let Some(udp) = snapshot.udp.as_ref() else {
            // Validation keeps every UDP stream's settings; a TCP stream
            // never binds a UDP socket.
            debug!(stream_id = %snapshot.id, "UDP datagram on a stream without udp settings: dropped");
            return;
        };
        let stats = self.counters.stream(&snapshot.id);
        if d.payload.len() > udp.max_datagram_bytes as usize {
            stats.dropped(DatagramDropReason::RequestOversize);
            return;
        }
        let key = SessionKey {
            bind_gen: d.bind_gen,
            local: canonical(d.local),
            client: canonical(d.source),
        };
        let existing = self.sessions().get(&key).cloned();
        if let Some(session) = existing {
            match session.offer(d.payload) {
                Offer::Taken { retired } => {
                    if retired {
                        self.forget(&session);
                    }
                    return;
                }
                Offer::Gone => self.forget(&session),
            }
        }
        if d.draining {
            stats.dropped(DatagramDropReason::BindingDraining);
            return;
        }
        self.open_session(&d, udp, key, stats);
    }

    /// Admit and start a session for `d`, or count why not.
    fn open_session(
        self: &Arc<Self>,
        d: &Datagram<'_>,
        udp: &UdpSettings,
        key: SessionKey,
        stats: Arc<StreamStats>,
    ) {
        let snapshot = d.snapshot;
        let refuse = |refusal: StreamRefusal| {
            stats.refused(refusal);
            self.admission.report(RefusalRecord {
                stream_id: snapshot.id.clone(),
                stream_name: snapshot.name.clone(),
                protocol: StreamProtocol::Udp,
                listen_port: key.local.port(),
                client: key.client,
                proxied_from: None,
                refusal,
                at: Utc::now(),
            });
        };
        let Some(caps) = d.caps.get(&snapshot.id) else {
            // The supervisor sends `caps` before a stream's first `attach`
            // (D-d), so this is a stream whose region has not arrived.
            refuse(StreamRefusal::CapsUnavailable);
            return;
        };
        let header = match snapshot.proxy_protocol_send {
            StreamProxyProtocol::V2 => {
                Some(encode_v2_dgram(key.client, key.local).into_boxed_slice())
            }
            // `v1` is refused on a UDP stream at validation: its text
            // format has no UDP transport.
            StreamProxyProtocol::Off | StreamProxyProtocol::V1 => None,
        };
        if !fits(header.as_deref(), d.payload.len()) {
            stats.dropped(DatagramDropReason::RequestOversize);
            return;
        }
        let client = key.client.ip();
        if let Err(refusal) = self.admission.judge(snapshot, &stats, client) {
            refuse(refusal);
            return;
        }
        let source = SourceKey::of(client);
        let limits = rate_limits(udp);
        let current = caps.current();
        let region = current.region();
        let charged = region.charge_new_session(
            source,
            d.payload.len() as u64,
            limits,
            open_limits(snapshot),
            now_ns(),
        );
        match charged {
            NewSessionVerdict::Allowed => {}
            NewSessionVerdict::OpenRate => return refuse(StreamRefusal::OpenRate),
            NewSessionVerdict::SourceOpenRate => return refuse(StreamRefusal::SourceOpenRate),
            NewSessionVerdict::DatagramRate => {
                stats.dropped(DatagramDropReason::SourceDatagramRate);
                return;
            }
            NewSessionVerdict::ByteRate => {
                stats.dropped(DatagramDropReason::SourceByteRate);
                return;
            }
            NewSessionVerdict::TableFull => return refuse(StreamRefusal::SessionTableFull),
        }
        let max_sessions = u64::from(udp.max_sessions);
        let admitted = current
            .admit_stream(caps.stream_cap_left(max_sessions), false, 0)
            .and_then(|permit| {
                permit.admit_source(
                    source,
                    u64::from(udp.effective_source_session_cap()),
                    u64::MAX,
                )
            });
        let permit = match admitted {
            Ok(permit) => permit,
            Err(refusal) => {
                let refusal = udp_cap_refusal(refusal);
                refuse(refusal);
                if refusal == StreamRefusal::SessionCap && stats.session_cap_refused() {
                    info!(stream_id = %snapshot.id, stream = %snapshot.name, max_sessions,
                          "UDP stream reached its session ceiling on this node");
                }
                return;
            }
        };
        stats.sessions_held(
            caps.retired_sessions().saturating_add(region.total()),
            max_sessions,
        );

        let session = Arc::new(Session::new(
            key,
            Bounds::of(udp),
            header,
            Arc::clone(region),
            source,
            limits,
            Arc::clone(&stats),
            d.payload,
        ));
        if !session.retired() {
            self.sessions().insert(key, Arc::clone(&session));
        }
        let reply_from = match d.socket.local_addr() {
            Ok(bound) if bound.ip().is_unspecified() => Some(d.local.ip()),
            _ => None,
        };
        let task = SessionTask {
            session,
            tracked: d.tracker.register(d.bind_gen, Arc::clone(snapshot)),
            permit,
            active: stats.accept(),
            stats,
            slot: Arc::clone(d.socket),
            client: d.source,
            reply_from,
            table: Arc::clone(d.table),
            bound_ports: d.bound_ports.clone(),
            max_sessions,
            accepted_at: Instant::now(),
            accepted_wall: Utc::now(),
        };
        tokio::spawn(Arc::clone(self).run(task));
    }

    async fn run(self: Arc<Self>, task: SessionTask) {
        let SessionTask {
            session,
            mut tracked,
            permit,
            active,
            stats,
            slot,
            client,
            reply_from,
            table,
            bound_ports,
            max_sessions,
            accepted_at,
            accepted_wall,
        } = task;
        let snapshot = Arc::clone(tracked.snapshot());
        let total = snapshot
            .total_timeout_s
            .map(|s| accepted_at + Duration::from_secs(u64::from(s)));
        let mut record = ConnectionRecord {
            stream_id: snapshot.id.clone(),
            stream_name: snapshot.name.clone(),
            protocol: StreamProtocol::Udp,
            bind_gen: session.key.bind_gen,
            client: session.key.client,
            peer: session.key.client,
            proxied_from: None,
            local: session.key.local,
            backend_id: None,
            backend_address: None,
            attempts: 0,
            bytes_upload: 0,
            bytes_download: 0,
            datagrams_upload: None,
            datagrams_download: None,
            accepted_at: accepted_wall,
            connected_at: None,
            ended_at: accepted_wall,
            end_reason: StreamEndReason::IdleTimeout,
            tls: None,
            detected_protocol: None,
        };

        let backend_caps = permit.region().worker(permit.slot());
        let opening = tokio::select! {
            biased;
            reason = tracked.closed() => Err(reason),
            _ = sleep_until_opt(total) => Err(StreamEndReason::TotalTimeout),
            opened = self.open(&snapshot, &table, &bound_ports, &stats, session.key, accepted_at, backend_caps.as_ref()) => opened,
        };
        let natural = match opening {
            Err(reason) => {
                // Only the selection can end it so; a drain or the total
                // timeout says nothing about the backends.
                if matches!(
                    reason,
                    StreamEndReason::ConnectFailed | StreamEndReason::NoHealthyBackend
                ) {
                    self.observer.connect_outcome(
                        &snapshot.id,
                        StreamProtocol::Udp,
                        ConnectOutcome::NotConnected,
                    );
                }
                reason
            }
            Ok(opened) => {
                tracked.set_backend(&opened.backend.id);
                record.backend_id = Some(opened.backend.id.clone());
                record.backend_address = Some(opened.address);
                record.attempts = 1;
                record.connected_at = Some(Utc::now());
                self.selector.connected(
                    &snapshot.id,
                    &opened.backend,
                    opened.address,
                    Duration::ZERO,
                );
                let link = self.counters.link(&snapshot.id, &opened.backend.id);
                let _link_active = link.session_opened();
                session.counting_link(Arc::clone(&link));
                session.opened(&opened.socket);
                let serving = Serving {
                    session: &session,
                    opened: &opened,
                    link: &link,
                    stream_id: &snapshot.id,
                    slot: &slot,
                    client,
                    reply_from,
                    idle: Duration::from_secs(u64::from(snapshot.idle_timeout_s)),
                    total,
                };
                let reason = self.serve(&serving, &mut tracked).await;
                self.selector
                    .closed(&snapshot.id, &opened.backend, opened.address);
                reason
            }
        };

        session.end();
        self.forget(&session);
        drop(slot);
        let forwarded = session.forwarded();
        let region = Arc::clone(session.region());
        drop(permit);
        stats.sessions_held(region.total(), max_sessions);
        // The record is handed over before the entry leaves the tracker
        // (Story 12.9 D-k): a drain waiting for an empty tracker then
        // never stops with a row still in flight.
        tracked.finish(natural, |reason| {
            stats.ended(reason.kind());
            drop(active);
            record.bytes_upload = forwarded.bytes_upload;
            record.bytes_download = forwarded.bytes_download;
            record.datagrams_upload = Some(forwarded.datagrams_upload);
            record.datagrams_download = Some(forwarded.datagrams_download);
            record.ended_at = Utc::now();
            record.end_reason = reason;
            // A refused session is a row through the refusal log, not a
            // record (Story 12.6 D-j).
            self.admission.ended(record);
        });
    }

    /// Select a backend, admit it through the breaker, check it is not a
    /// refused local destination and open the upstream socket. Each
    /// backend is considered once per session; a link at its `max_active`
    /// (counted in `backend_caps`), a `Deny`, a local refusal or no
    /// source address of its family passes over it without opening
    /// anything. Never retried once a socket is connected (D-i). No
    /// candidate left, with a cap among the reasons: `refused(backend_cap)`.
    #[allow(clippy::too_many_arguments)] // one session's whole context, read once
    async fn open(
        &self,
        stream: &Stream,
        table: &StreamTable,
        bound: &BoundPorts,
        stats: &StreamStats,
        key: SessionKey,
        accepted_at: Instant,
        backend_caps: Option<&WorkerCaps>,
    ) -> Result<Opened, StreamEndReason> {
        let mut excluded: HashSet<String> = HashSet::new();
        let mut capped = false;
        loop {
            let eligible = self.eligible(
                stream,
                table,
                key.local.port(),
                &excluded,
                backend_caps,
                &mut capped,
            );
            if eligible.is_empty() {
                if capped {
                    stats.refused(StreamRefusal::BackendCap);
                    return Err(StreamEndReason::Refused(StreamRefusal::BackendCap));
                }
                return Err(StreamEndReason::NoHealthyBackend);
            }
            let index = {
                let candidates: Vec<Candidate<'_>> = eligible
                    .iter()
                    .map(|e| Candidate {
                        backend: &e.link.backend,
                        ring_address: SocketAddr::new(e.addresses[0], e.port),
                    })
                    .collect();
                self.selector
                    .select(&SelectionRequest {
                        stream,
                        candidates: &candidates,
                        client: key.client.ip(),
                        accepted_at: accepted_at.into_std(),
                    })
                    .min(candidates.len() - 1)
            };
            let chosen = &eligible[index];
            let backend = Arc::clone(&chosen.link.backend);
            excluded.insert(backend.id.clone());
            let Ok(backend_slot) = claim_backend(backend_caps, chosen.link) else {
                capped = true;
                debug!(stream_id = %stream.id, backend_id = %backend.id,
                       "backend reached its max_active meanwhile: candidate skipped");
                continue;
            };

            let Some(destinations) = self.destinations(stream, bound, stats, chosen) else {
                continue;
            };
            let Some((address, sources)) = self.pick_sources(stream, &destinations) else {
                stats.source_family_mismatch();
                debug!(stream_id = %stream.id, backend_id = %backend.id,
                       "no source address of the backend's family: candidate skipped");
                continue;
            };
            drop(eligible);

            let admission = self.breaker.admit(&stream.id, &backend).await;
            if admission == Admission::Deny {
                stats.breaker_denied();
                continue;
            }
            let was_probe = admission == Admission::AllowProbe;
            return match open_upstream(address, &sources) {
                Ok(socket) => Ok(Opened {
                    backend,
                    address,
                    socket: Arc::new(socket),
                    was_probe,
                    _backend_slot: backend_slot,
                }),
                Err(OpenError::Socket(e)) => {
                    warn!(stream_id = %stream.id, backend_id = %backend.id, %address, error = %e,
                          "UDP session socket not opened");
                    Err(StreamEndReason::ConnectFailed)
                }
                Err(OpenError::SourceBind(e)) => {
                    stats.source_bind_failed();
                    warn!(stream_id = %stream.id, backend_id = %backend.id, %address,
                          sources = ?sources, error = %e,
                          "no source address of the UDP stream could be bound");
                    Err(StreamEndReason::ConnectFailed)
                }
                Err(OpenError::Connect(e)) => {
                    let kind = icmp_kind(&e).unwrap_or(ConnectFailureKind::Unreachable);
                    self.counters
                        .link(&stream.id, &backend.id)
                        .connect_failed(kind);
                    self.breaker
                        .record(&stream.id, &backend, false, was_probe)
                        .await;
                    debug!(stream_id = %stream.id, backend_id = %backend.id, %address,
                           error = %e, "UDP session socket not connected");
                    Err(StreamEndReason::ConnectFailed)
                }
            };
        }
    }

    /// The candidates of a session: linked, not passed over yet, not
    /// down, in the normal lifecycle, below its link's `max_active` (one
    /// at it sets `capped`), with an address known now (a name not
    /// resolved yet waits for the resolver's schedule, never for this
    /// session), the backups only when no primary is left (12.3 D-f).
    fn eligible<'a>(
        &self,
        stream: &Stream,
        table: &'a StreamTable,
        listen_port: u16,
        excluded: &HashSet<String>,
        backend_caps: Option<&WorkerCaps>,
        capped: &mut bool,
    ) -> Vec<Eligible<'a>> {
        let mut eligible: Vec<Eligible<'a>> = table
            .linked_backends(&stream.id)
            .iter()
            .filter(|link| {
                let backend = &link.backend;
                !excluded.contains(&backend.id)
                    && backend.health_status != HealthStatus::Down
                    && backend.lifecycle_state == LifecycleState::Normal
            })
            .filter(|link| {
                let at_cap = backend_at_cap(backend_caps, link);
                *capped |= at_cap;
                !at_cap
            })
            .filter_map(|link| {
                let addresses = self
                    .resolver
                    .cached(backend_address_host(&link.backend.address))
                    .filter(|a| !a.is_empty())?;
                Some(Eligible {
                    link,
                    addresses,
                    port: backend_port(&link.backend, listen_port),
                })
            })
            .collect();
        let has_primary = eligible.iter().any(|e| !e.link.backup);
        eligible.retain(|e| e.link.backup != has_primary);
        eligible
    }

    /// The destinations of `chosen` the local check lets through, in
    /// rotating order; `None` when it refuses them all (12.3 D-m),
    /// reported once per transition.
    fn destinations(
        &self,
        stream: &Stream,
        bound: &BoundPorts,
        stats: &StreamStats,
        chosen: &Eligible<'_>,
    ) -> Option<Vec<SocketAddr>> {
        let interfaces = self.resolver.interfaces();
        let node = NodeLocality {
            interfaces: &interfaces,
            reserved: self.reserved.as_ref(),
            bound,
        };
        let backend = &chosen.link.backend;
        let count = chosen.addresses.len();
        let offset = self.address_turn.fetch_add(1, Ordering::Relaxed);
        let mut refusal: Option<LocalRefusal> = None;
        let allowed: Vec<SocketAddr> = (0..count)
            .map(|i| SocketAddr::new(chosen.addresses[(offset + i) % count], chosen.port))
            .filter(
                |destination| match node.check(*destination, stream.allow_local_backend) {
                    Ok(()) => true,
                    Err(r) => {
                        refusal = Some(r);
                        false
                    }
                },
            )
            .collect();
        if allowed.is_empty() {
            stats.local_destination_refused();
            if self.exclusions.set(&stream.id, &backend.id, true) {
                self.counters.backend(&backend.id).dns_local_excluded();
                warn!(stream_id = %stream.id, stream = %stream.name,
                      backend_id = %backend.id, backend = %backend.name,
                      addresses = ?chosen.addresses,
                      rule = refusal.map_or("", |r| r.as_str()),
                      "stream backend resolves to a refused local address: excluded from the stream");
            }
            return None;
        }
        self.exclusions.set(&stream.id, &backend.id, false);
        Some(allowed)
    }

    /// The first destination with a source address of its family, and
    /// the stream's source addresses of that family from the next in turn
    /// (D-f): the bind tries them in that order. Empty sources when the
    /// stream sets none.
    fn pick_sources(
        &self,
        stream: &Stream,
        destinations: &[SocketAddr],
    ) -> Option<(SocketAddr, Vec<IpAddr>)> {
        if stream.source_addresses.is_empty() {
            return destinations.first().map(|d| (*d, Vec::new()));
        }
        destinations.iter().find_map(|destination| {
            let family: Vec<IpAddr> = stream
                .source_addresses
                .iter()
                .copied()
                .filter(|s| s.is_ipv4() == destination.is_ipv4())
                .collect();
            if family.is_empty() {
                return None;
            }
            let turn = {
                let mut turns = self
                    .source_turns
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                let n = turns.entry(stream.id.clone()).or_default();
                let current = *n;
                *n = n.wrapping_add(1);
                current
            };
            let start = turn % family.len();
            let ordered = family[start..]
                .iter()
                .chain(&family[..start])
                .copied()
                .collect();
            Some((*destination, ordered))
        })
    }

    /// Forward responses until the session ends; returns how it ended.
    async fn serve(&self, s: &Serving<'_>, tracked: &mut TrackedConnection) -> StreamEndReason {
        let mut reported = false;
        loop {
            let idle_at = s.session.last_activity() + s.idle;
            tokio::select! {
                biased;
                reason = tracked.closed() => return reason,
                _ = sleep_until_opt(s.total) => return StreamEndReason::TotalTimeout,
                _ = s.session.wake.notified() => match s.session.take_pending_end() {
                    Some(Ending::Natural(reason)) => return reason,
                    Some(Ending::Icmp(kind)) => return self.icmp_end(s, kind, reported).await,
                    None => {}
                },
                _ = tokio::time::sleep_until(idle_at) => {
                    if s.session.last_activity() + s.idle <= Instant::now() {
                        if s.session.bounds().expects_responses() && !s.session.received_any() {
                            s.link.connect_failed(ConnectFailureKind::NoResponse);
                            self.report(s, ConnectOutcome::NoResponse).await;
                        }
                        return StreamEndReason::IdleTimeout;
                    }
                },
                // An ICMP error raises only `EPOLLERR` on a UDP socket,
                // which read readiness alone never sees.
                ready = s.opened.socket.ready(Interest::READABLE | Interest::ERROR) => {
                    let ready = match ready {
                        Ok(ready) => ready,
                        Err(e) => {
                            debug!(stream_id = %s.stream_id, error = %e,
                                   "UDP session socket readiness failed");
                            return StreamEndReason::BackendClose;
                        }
                    };
                    let error = if ready.is_error() {
                        pending_error(&s.opened.socket)
                    } else {
                        None
                    };
                    let received = match error {
                        Some(e) => Err(e),
                        None if !ready.is_readable() => continue,
                        None => with_receive_buffer(|buf| {
                            let n = s.opened.socket.try_recv(buf)?;
                            Ok::<_, io::Error>(s.session.on_response(&buf[..n], |payload| {
                                send_to_client(s.slot, payload, s.client, s.reply_from)
                            }))
                        }),
                    };
                    match received {
                        Ok(response) => {
                            if response.first && !reported {
                                reported = true;
                                self.report(s, ConnectOutcome::Answered).await;
                            }
                            if let Some(end) = response.end {
                                return end;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) => match icmp_kind(&e) {
                            Some(kind) => return self.icmp_end(s, kind, reported).await,
                            None => {
                                debug!(stream_id = %s.stream_id, error = %e,
                                       "UDP session receive failed");
                                return StreamEndReason::BackendClose;
                            }
                        },
                    }
                }
            }
        }
    }

    /// An ICMP error from the backend: a failure if nothing came back
    /// before it (`connect_failed`), the backend's close otherwise.
    async fn icmp_end(
        &self,
        s: &Serving<'_>,
        kind: ConnectFailureKind,
        reported: bool,
    ) -> StreamEndReason {
        if s.session.received_any() {
            return StreamEndReason::BackendClose;
        }
        s.link.connect_failed(kind);
        if !reported {
            self.report(s, ConnectOutcome::IcmpError).await;
        }
        StreamEndReason::ConnectFailed
    }

    /// The session's one breaker outcome (D-i), which is also its connect
    /// outcome (Story 12.9 D-g).
    async fn report(&self, s: &Serving<'_>, outcome: ConnectOutcome) {
        let success = outcome == ConnectOutcome::Answered;
        self.breaker
            .record(s.stream_id, &s.opened.backend, success, s.opened.was_probe)
            .await;
        self.observer
            .connect_outcome(s.stream_id, StreamProtocol::Udp, outcome);
    }
}

/// The error pending on `socket` (an ICMP error the kernel queued on the
/// connected socket), read and cleared. `None` when there is none, which
/// also clears tokio's error readiness so the loop does not spin.
fn pending_error(socket: &UdpSocket) -> Option<io::Error> {
    socket
        .try_io(Interest::ERROR, || match socket.take_error() {
            Ok(Some(e)) | Err(e) => Ok(e),
            Ok(None) => Err(io::ErrorKind::WouldBlock.into()),
        })
        .ok()
}

/// A session being served: what [`Inner::serve`] reads.
struct Serving<'a> {
    session: &'a Session,
    opened: &'a Opened,
    link: &'a LinkStats,
    stream_id: &'a str,
    slot: &'a UdpSocket,
    client: SocketAddr,
    reply_from: Option<IpAddr>,
    idle: Duration,
    total: Option<Instant>,
}

/// Open the upstream socket of a session: non-blocking, close-on-exec,
/// its receive buffer capped, bound to the first of `sources` that binds
/// (port 0, D-f) or left to the kernel, and connected to `destination`.
/// A UDP `connect` sends nothing and never waits.
fn open_upstream(destination: SocketAddr, sources: &[IpAddr]) -> Result<UdpSocket, OpenError> {
    let socket = Socket::new(
        Domain::for_address(destination),
        Type::DGRAM.nonblocking(),
        Some(Protocol::UDP),
    )
    .map_err(OpenError::Socket)?;
    if let Err(e) = socket.set_recv_buffer_size(UPSTREAM_RECEIVE_BUFFER) {
        debug!(error = %e, "receive buffer not capped on a UDP session socket");
    }
    let mut bind_failure = None;
    for source in sources {
        match socket.bind(&SocketAddr::new(*source, 0).into()) {
            Ok(()) => {
                bind_failure = None;
                break;
            }
            Err(e) => bind_failure = Some(e),
        }
    }
    if let Some(e) = bind_failure {
        return Err(OpenError::SourceBind(e));
    }
    socket
        .connect(&destination.into())
        .map_err(OpenError::Connect)?;
    UdpSocket::from_std(socket.into()).map_err(OpenError::Socket)
}
