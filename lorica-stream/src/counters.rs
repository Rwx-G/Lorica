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

//! What the stream engines count (Story 12.3 D-r), one [`StreamCounters`]
//! per process, read as a [`CountersSnapshot`].
//!
//! Counters are created per stream, per (stream, backend) and per
//! backend on first use and pruned when the table no longer holds them.
//! A live connection keeps the `Arc` of its own counters, so a prune
//! never loses its decrement. Story 12.9 names the metrics, aggregates
//! the workers and writes the logs; nothing here is a metric name.
//!
//! Keyed families (end kinds, refusals, header outcomes, connect failure
//! kinds) are maps filled on first use, so a snapshot carries only what
//! happened; the word lists come from the enums ([`StreamEndKind`],
//! [`StreamRefusal`], [`ProxyHeaderOutcome::ALL`],
//! [`ConnectFailureKind::ALL`]).

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use lorica_config::models::{StreamEndKind, StreamRefusal};

use crate::table::StreamTable;

/// Upper bounds of the connect latency histogram, in seconds: the
/// bounds of the HTTP request latency histogram, a cumulative `le`
/// shape with an implicit `+Inf`.
pub const CONNECT_LATENCY_BUCKETS_S: &[f64] =
    &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// The outcome of a PROXY header on a stream (D-k).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyHeaderOutcome {
    /// A v1 header carrying TCP addresses, accepted from a trusted peer.
    AcceptedV1,
    /// A v2 header carrying TCP addresses, accepted from a trusted peer.
    AcceptedV2,
    /// A header without usable addresses (`LOCAL`, `UNKNOWN`,
    /// `AF_UNSPEC`, `AF_UNIX`), accepted: the socket addresses stay.
    AcceptedLocal,
    /// A trusted peer's header broke the grammar, or the peer closed
    /// before completing it.
    RefusedMalformed,
    /// A trusted peer's header was longer than the bound.
    RefusedOversized,
    /// A trusted peer's header used something a TCP stream does not
    /// accept (`DGRAM` among others).
    RefusedUnsupported,
    /// A trusted peer sent no complete header in time.
    RefusedTimeout,
    /// A peer outside the trusted list opened with a PROXY signature.
    RefusedUntrustedPeer,
}

impl ProxyHeaderOutcome {
    /// Every outcome, in declaration order.
    pub const ALL: [ProxyHeaderOutcome; 8] = [
        Self::AcceptedV1,
        Self::AcceptedV2,
        Self::AcceptedLocal,
        Self::RefusedMalformed,
        Self::RefusedOversized,
        Self::RefusedUnsupported,
        Self::RefusedTimeout,
        Self::RefusedUntrustedPeer,
    ];

    /// The snake_case word of the outcome.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AcceptedV1 => "accepted_v1",
            Self::AcceptedV2 => "accepted_v2",
            Self::AcceptedLocal => "accepted_local",
            Self::RefusedMalformed => "refused_malformed",
            Self::RefusedOversized => "refused_oversized",
            Self::RefusedUnsupported => "refused_unsupported",
            Self::RefusedTimeout => "refused_timeout",
            Self::RefusedUntrustedPeer => "refused_untrusted_peer",
        }
    }
}

/// Why a connect attempt failed, as the breaker counts it (D-g).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectFailureKind {
    /// The backend answered with a reset to the SYN.
    Refused,
    /// No answer within the connect timeout.
    Timeout,
    /// No route, host or network unreachable, and any other error.
    Unreachable,
    /// The connection was reset while being established.
    Reset,
}

impl ConnectFailureKind {
    /// Every kind, in declaration order.
    pub const ALL: [ConnectFailureKind; 4] =
        [Self::Refused, Self::Timeout, Self::Unreachable, Self::Reset];

    /// The snake_case word of the kind.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Unreachable => "unreachable",
            Self::Reset => "reset",
        }
    }
}

/// A map of counts keyed by an enum, filled on first use.
#[derive(Debug)]
struct Keyed<K>(Mutex<HashMap<K, u64>>);

impl<K> Default for Keyed<K> {
    fn default() -> Self {
        Keyed(Mutex::new(HashMap::new()))
    }
}

impl<K: Copy + Eq + Hash> Keyed<K> {
    fn add(&self, key: K) {
        *self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_default() += 1;
    }

    fn snapshot(&self) -> HashMap<K, u64> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

fn get(a: &AtomicU64) -> u64 {
    a.load(Ordering::Relaxed)
}

fn bump(a: &AtomicU64) {
    a.fetch_add(1, Ordering::Relaxed);
}

/// The counters of one stream.
#[derive(Debug, Default)]
pub struct StreamStats {
    active: Arc<AtomicU64>,
    accepted: AtomicU64,
    ended: Keyed<StreamEndKind>,
    refused: Keyed<StreamRefusal>,
    bytes_upload: AtomicU64,
    bytes_download: AtomicU64,
    connect_attempts: AtomicU64,
    retries: AtomicU64,
    breaker_denied: AtomicU64,
    proxy_header: Keyed<ProxyHeaderOutcome>,
    local_destination_refused: AtomicU64,
    source_family_mismatch: AtomicU64,
    source_bind_failed: AtomicU64,
}

impl StreamStats {
    /// Count an accepted connection, which is active until the guard
    /// drops.
    pub fn accept(&self) -> ActiveGuard {
        bump(&self.accepted);
        ActiveGuard::new(&self.active)
    }

    /// Count a connection ended with `kind`.
    pub fn ended(&self, kind: StreamEndKind) {
        self.ended.add(kind);
    }

    /// Count a refusal.
    pub fn refused(&self, refusal: StreamRefusal) {
        self.refused.add(refusal);
    }

    /// Add client-to-backend bytes.
    pub fn add_upload(&self, bytes: u64) {
        self.bytes_upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add backend-to-client bytes.
    pub fn add_download(&self, bytes: u64) {
        self.bytes_download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count a connect attempt; every attempt after a connection's first
    /// is a retry.
    pub fn connect_attempt(&self, first: bool) {
        bump(&self.connect_attempts);
        if !first {
            bump(&self.retries);
        }
    }

    /// Count a breaker `Deny`.
    pub fn breaker_denied(&self) {
        bump(&self.breaker_denied);
    }

    /// Count a PROXY header outcome.
    pub fn proxy_header(&self, outcome: ProxyHeaderOutcome) {
        self.proxy_header.add(outcome);
    }

    /// Count a destination refused as local.
    pub fn local_destination_refused(&self) {
        bump(&self.local_destination_refused);
    }

    /// Count a candidate skipped for want of a source address of its
    /// family.
    pub fn source_family_mismatch(&self) {
        bump(&self.source_family_mismatch);
    }

    /// Count a failed source bind.
    pub fn source_bind_failed(&self) {
        bump(&self.source_bind_failed);
    }

    fn snapshot(&self) -> StreamCountersSnapshot {
        StreamCountersSnapshot {
            active: get(&self.active),
            accepted: get(&self.accepted),
            ended: self.ended.snapshot(),
            refused: self.refused.snapshot(),
            bytes_upload: get(&self.bytes_upload),
            bytes_download: get(&self.bytes_download),
            connect_attempts: get(&self.connect_attempts),
            retries: get(&self.retries),
            breaker_denied: get(&self.breaker_denied),
            proxy_header: self.proxy_header.snapshot(),
            local_destination_refused: get(&self.local_destination_refused),
            source_family_mismatch: get(&self.source_family_mismatch),
            source_bind_failed: get(&self.source_bind_failed),
        }
    }
}

/// A fixed-bucket latency histogram over [`CONNECT_LATENCY_BUCKETS_S`].
#[derive(Debug)]
struct Histogram {
    /// One count per bound, then the overflow, not cumulative.
    buckets: Vec<AtomicU64>,
    sum_micros: AtomicU64,
    count: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram {
            buckets: (0..=CONNECT_LATENCY_BUCKETS_S.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            sum_micros: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    fn observe(&self, value: Duration) {
        let seconds = value.as_secs_f64();
        let index = CONNECT_LATENCY_BUCKETS_S
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(CONNECT_LATENCY_BUCKETS_S.len());
        bump(&self.buckets[index]);
        self.sum_micros.fetch_add(
            u64::try_from(value.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        bump(&self.count);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let mut cumulative = 0;
        let le = self
            .buckets
            .iter()
            .take(CONNECT_LATENCY_BUCKETS_S.len())
            .map(|b| {
                cumulative += get(b);
                cumulative
            })
            .collect();
        HistogramSnapshot {
            le,
            count: get(&self.count),
            sum: Duration::from_micros(get(&self.sum_micros)),
        }
    }
}

/// The counters of one backend of one stream.
#[derive(Debug, Default)]
pub struct LinkStats {
    active: Arc<AtomicU64>,
    connects: AtomicU64,
    connect_failures: Keyed<ConnectFailureKind>,
    connect_latency: Histogram,
}

impl LinkStats {
    /// Count an established connection after `latency`, active until
    /// the guard drops.
    pub fn connected(&self, latency: Duration) -> ActiveGuard {
        bump(&self.connects);
        self.connect_latency.observe(latency);
        ActiveGuard::new(&self.active)
    }

    /// Count a failed connect attempt.
    pub fn connect_failed(&self, kind: ConnectFailureKind) {
        self.connect_failures.add(kind);
    }

    fn snapshot(&self) -> LinkCountersSnapshot {
        LinkCountersSnapshot {
            active: get(&self.active),
            connects: get(&self.connects),
            connect_failures: self.connect_failures.snapshot(),
            connect_latency: self.connect_latency.snapshot(),
        }
    }
}

/// The counters of one backend, whatever the stream.
#[derive(Debug, Default)]
pub struct BackendStats {
    dns_failures: AtomicU64,
    dns_local_excluded: AtomicU64,
}

impl BackendStats {
    /// Count a failed or empty resolution of the backend's name.
    pub fn dns_failure(&self) {
        bump(&self.dns_failures);
    }

    /// Count a transition into "every address is refused as local" for a
    /// stream.
    pub fn dns_local_excluded(&self) {
        bump(&self.dns_local_excluded);
    }

    fn snapshot(&self) -> BackendCountersSnapshot {
        BackendCountersSnapshot {
            dns_failures: get(&self.dns_failures),
            dns_local_excluded: get(&self.dns_local_excluded),
        }
    }
}

/// Holds one unit of an `active` gauge, released on drop.
#[derive(Debug)]
pub struct ActiveGuard(Arc<AtomicU64>);

impl ActiveGuard {
    fn new(gauge: &Arc<AtomicU64>) -> Self {
        bump(gauge);
        ActiveGuard(Arc::clone(gauge))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

type Family<K, V> = Mutex<HashMap<K, Arc<V>>>;

fn entry<K: Eq + Hash, V: Default>(family: &Family<K, V>, key: K) -> Arc<V> {
    Arc::clone(
        family
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_default(),
    )
}

fn read<K: Clone + Ord, V, S>(family: &Family<K, V>, snap: impl Fn(&V) -> S) -> BTreeMap<K, S> {
    family
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(k, v)| (k.clone(), snap(v)))
        .collect()
}

/// The counters of one process's stream engines. One instance, shared
/// by both engines through [`crate::Engines::counters`].
#[derive(Debug, Default)]
pub struct StreamCounters {
    streams: Family<String, StreamStats>,
    links: Family<(String, String), LinkStats>,
    backends: Family<String, BackendStats>,
}

impl StreamCounters {
    /// Empty counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters of `stream_id`, created on first use.
    pub fn stream(&self, stream_id: &str) -> Arc<StreamStats> {
        entry(&self.streams, stream_id.to_string())
    }

    /// The counters of `backend_id` on `stream_id`, created on first use.
    pub fn link(&self, stream_id: &str, backend_id: &str) -> Arc<LinkStats> {
        entry(&self.links, (stream_id.to_string(), backend_id.to_string()))
    }

    /// The counters of `backend_id`, created on first use.
    pub fn backend(&self, backend_id: &str) -> Arc<BackendStats> {
        entry(&self.backends, backend_id.to_string())
    }

    /// Drop the counters of streams, links and backends `table` no
    /// longer holds.
    pub fn retain(&self, table: &StreamTable) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(stream, backend), _| table.holds(stream, Some(backend)));
        self.backends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.backend(id).is_some());
    }

    /// Every counter as it stands.
    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            streams: read(&self.streams, StreamStats::snapshot),
            links: read(&self.links, LinkStats::snapshot),
            backends: read(&self.backends, BackendStats::snapshot),
        }
    }
}

/// Every counter of a process at one instant.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CountersSnapshot {
    /// Per stream id.
    pub streams: BTreeMap<String, StreamCountersSnapshot>,
    /// Per (stream id, backend id).
    pub links: BTreeMap<(String, String), LinkCountersSnapshot>,
    /// Per backend id.
    pub backends: BTreeMap<String, BackendCountersSnapshot>,
}

/// One stream's counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamCountersSnapshot {
    /// Open connections now (a gauge).
    pub active: u64,
    /// Connections accepted.
    pub accepted: u64,
    /// Connections ended, per end kind.
    pub ended: HashMap<StreamEndKind, u64>,
    /// Connections refused, per refusal.
    pub refused: HashMap<StreamRefusal, u64>,
    /// Client-to-backend bytes forwarded, added per completed write.
    pub bytes_upload: u64,
    /// Backend-to-client bytes forwarded, added per completed write.
    pub bytes_download: u64,
    /// Connect attempts made.
    pub connect_attempts: u64,
    /// Attempts after a connection's first.
    pub retries: u64,
    /// Breaker denials.
    pub breaker_denied: u64,
    /// PROXY header outcomes.
    pub proxy_header: HashMap<ProxyHeaderOutcome, u64>,
    /// Destinations refused as local.
    pub local_destination_refused: u64,
    /// Candidates skipped for want of a source address of their family.
    pub source_family_mismatch: u64,
    /// Failed source binds.
    pub source_bind_failed: u64,
}

/// The cumulative counts of a latency histogram.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HistogramSnapshot {
    /// Observations at or below each bound of
    /// [`CONNECT_LATENCY_BUCKETS_S`], cumulative.
    pub le: Vec<u64>,
    /// Every observation, `+Inf` included.
    pub count: u64,
    /// Their sum.
    pub sum: Duration,
}

/// One (stream, backend)'s counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkCountersSnapshot {
    /// Open connections now (a gauge).
    pub active: u64,
    /// Connections established.
    pub connects: u64,
    /// Failed attempts, per kind.
    pub connect_failures: HashMap<ConnectFailureKind, u64>,
    /// Connect latency, SYN to established.
    pub connect_latency: HistogramSnapshot,
}

/// One backend's counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackendCountersSnapshot {
    /// Failed or empty resolutions of its name.
    pub dns_failures: u64,
    /// Transitions into "every address refused as local" for a stream.
    pub dns_local_excluded: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gauge_follows_its_guards() {
        let counters = StreamCounters::new();
        let first = counters.stream("s").accept();
        let second = counters.stream("s").accept();
        assert_eq!(counters.snapshot().streams["s"].active, 2);
        assert_eq!(counters.snapshot().streams["s"].accepted, 2);
        drop(first);
        drop(second);
        assert_eq!(counters.snapshot().streams["s"].active, 0);
    }

    #[test]
    fn the_histogram_is_cumulative_with_an_overflow() {
        let link = LinkStats::default();
        for ms in [0, 3, 3, 700, 9_000] {
            drop(link.connected(Duration::from_millis(ms)));
        }
        let snap = link.snapshot();
        assert_eq!(snap.connects, 5);
        assert_eq!(snap.active, 0);
        assert_eq!(snap.connect_latency.count, 5);
        assert_eq!(
            snap.connect_latency.le.len(),
            CONNECT_LATENCY_BUCKETS_S.len()
        );
        assert_eq!(snap.connect_latency.le[0], 1);
        assert_eq!(snap.connect_latency.le[1], 3);
        assert_eq!(snap.connect_latency.le.last().copied(), Some(4));
        assert_eq!(snap.connect_latency.sum, Duration::from_millis(9_706));
    }

    #[test]
    fn outcome_and_kind_words_are_distinct() {
        let words: std::collections::HashSet<&str> =
            ProxyHeaderOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(words.len(), ProxyHeaderOutcome::ALL.len());
        let words: std::collections::HashSet<&str> =
            ConnectFailureKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(words.len(), ConnectFailureKind::ALL.len());
    }
}
