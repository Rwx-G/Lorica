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

//! The things a stream engine needs from the binary (Story 12.3 D-a), as
//! narrow traits: backend selection, the circuit breaker, DNS resolution
//! and, since Story 12.6 D-d, the node's source controls. `lorica`
//! implements them over the code HTTP already runs
//! (`lorica/src/stream_engine.rs`); the engines' tests use fakes.
//!
//! Protocol-neutral by design (Story 12.5 Interface edit E2): the UDP
//! engine selects, admits and resolves through the same traits, and the
//! binary builds one instance of each per process for both engines
//! (edit E3).

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::{Duration, Instant};

use lorica_config::models::{Backend, Stream, StreamRefusal};

use crate::table::StreamTable;

/// A boxed future borrowing its arguments, the shape every async seam
/// method returns.
pub type SeamFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One backend an engine may choose for a connection or session.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// The backend row.
    pub backend: &'a Backend,
    /// The address the backend is placed on a consistent-hash ring by:
    /// the lowest of its resolved addresses, with its port (the listen
    /// port N for a portless backend of a range stream), so a hostname
    /// backend takes part in the ring.
    pub ring_address: SocketAddr,
}

/// What a selection is asked.
#[derive(Debug, Clone, Copy)]
pub struct SelectionRequest<'a> {
    /// The stream, as the connection's snapshot holds it: its id keys
    /// the per-stream round-robin state, its `load_balancing` is the
    /// algorithm.
    pub stream: &'a Stream,
    /// The candidates, never empty: primaries, or the backups when no
    /// primary is a candidate (D-f).
    pub candidates: &'a [Candidate<'a>],
    /// The client, after PROXY accept when a header was accepted,
    /// canonical: the consistent-hash key, as text.
    pub client: IpAddr,
    /// When the connection was accepted: the seed of `random`.
    pub accepted_at: Instant,
}

/// Picks backends and learns how they do (D-e). One per process, shared
/// by the TCP and UDP engines, holding the per-stream round-robin state,
/// its own least-connections counts and its own latency tracker.
pub trait BackendSelector: Send + Sync + 'static {
    /// The index into `request.candidates` of the chosen backend. Must
    /// be in range.
    fn select(&self, request: &SelectionRequest<'_>) -> usize;

    /// A connection (or UDP session) to `backend` at `address` was
    /// established after `connect_latency`, the `peak_ewma` sample.
    fn connected(
        &self,
        stream_id: &str,
        backend: &Backend,
        address: SocketAddr,
        connect_latency: Duration,
    );

    /// A connection [`BackendSelector::connected`] reported has ended.
    fn closed(&self, stream_id: &str, backend: &Backend, address: SocketAddr);

    /// Told after every table load: drop the state of streams the
    /// table no longer holds.
    fn table_changed(&self, _table: &StreamTable) {}
}

/// The circuit breaker's answer for one backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The breaker is closed: connect.
    Allow,
    /// The breaker is half-open and this attempt is its probe: connect,
    /// and report the outcome with `was_probe = true`.
    AllowProbe,
    /// The breaker is open: the backend leaves this connection's
    /// candidates and selection runs again, no attempt made.
    Deny,
}

/// Passive failure detection (D-g). The implementation keys the breaker
/// by (`"stream:" + stream_id`, the backend address as configured), in
/// the registry HTTP uses, and fails open: an admission it cannot obtain
/// is `Allow`. A range stream's backend is configured without a port,
/// so one circuit covers every port of the range: a port whose service
/// is down opens it for the healthy ports too, and the circuit flaps
/// while that port stays down. Keying per port is refused on purpose,
/// since the registry never prunes (`docs/streams.md`, passive failure
/// detection).
pub trait BreakerGate: Send + Sync + 'static {
    /// Whether a connection of `stream_id` may try `backend`.
    fn admit<'a>(&'a self, stream_id: &'a str, backend: &'a Backend) -> SeamFuture<'a, Admission>;

    /// The outcome of an admitted attempt: `success` for an established
    /// connection, not for anything after it. Local refusals, unresolved
    /// names and source bind failures are never reported.
    fn record<'a>(
        &'a self,
        stream_id: &'a str,
        backend: &'a Backend,
        success: bool,
        was_probe: bool,
    ) -> SeamFuture<'a, ()>;
}

/// A successful lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The addresses the name resolved to, in any order. May be empty,
    /// which the cache treats as a failure.
    pub addresses: Vec<IpAddr>,
    /// The record TTL, the base of the re-resolution schedule.
    pub ttl: Duration,
}

/// Why a lookup failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ResolveError(pub String);

/// Resolves backend host names (D-n). The implementation reads the
/// system configuration with the hosts file honoured and returns record
/// TTLs; it must never block the thread.
pub trait Resolve: Send + Sync + 'static {
    /// Resolve `host`, a name, never an IP literal.
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>>;
}

/// The node's source controls a stream applies beside its own (Story
/// 12.6 D-d): the global connection filter, the global IP blocklist with
/// the global WAF whitelist's exemption, and the GeoIP database. The
/// implementation reads the instances the HTTP listeners read in the
/// same process, so a reload of any of them reaches the next stream
/// accept with no stream message.
///
/// Synchronous, because the UDP receive path is (Story 12.5 D-c): each
/// call is a lookup in memory, never a wait. `client` is canonical (no
/// IPv4-mapped form), and is the address Story 12.6 D-b judges: the
/// socket peer, or the client a trusted PROXY header carried.
pub trait SourceGate: Send + Sync + 'static {
    /// Steps 2 and 3 of the admission sequence (D-a): `Some` with
    /// [`StreamRefusal::ConnectionFilter`] when the global connection
    /// filter refuses `client`, else with [`StreamRefusal::IpBlocklist`]
    /// when the global blocklist holds it and the global WAF whitelist
    /// does not; `None` when both let it through.
    fn global(&self, client: IpAddr) -> Option<StreamRefusal>;

    /// The ISO 3166-1 alpha-2 code of `client`'s country, uppercase;
    /// `None` when it is unknown (no database on this node, or no entry
    /// for the address). Called only for a stream with a `geoip` list.
    fn country(&self, client: IpAddr) -> Option<[u8; 2]>;
}
