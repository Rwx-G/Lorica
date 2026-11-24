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
//! kinds, datagram drops) count each key in a slot of its own, lock-free,
//! and a snapshot carries only the keys that happened; the word lists
//! come from the enums
//! ([`StreamEndKind`], [`StreamRefusal`], [`ProxyHeaderOutcome::ALL`],
//! [`ConnectFailureKind::ALL`], [`DatagramDropReason`],
//! [`ClientHelloOutcome::ALL`], [`HandshakeOutcome::ALL`],
//! [`UpstreamTlsFailure::ALL`]).
//!
//! A TLS stream (Story 12.4 D-n) adds the ClientHello and handshake
//! outcomes per stream, a `matched` count per (stream, rule), and the
//! upstream TLS failures per (stream, backend).
//!
//! A UDP stream (Story 12.5 D-n) uses the same words with their session
//! meaning (`accepted` counts sessions, `active` live sessions, the bytes
//! what was forwarded) and adds the datagram counts, the drops and the
//! "ceiling reached" edge.
//!
//! Stream protection (Story 12.6 D-i) counts every refusal under its
//! reason, keeps a `pending` gauge of the connections in their
//! pre-forwarding reads, and counts `geoip_unknown`: clients a stream's
//! GeoIP list could not place, which pass.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use lorica_config::models::{DatagramDropReason, StreamEndKind, StreamRefusal};

use crate::table::StreamTable;

/// Upper bounds of the connect latency histogram, in seconds: the
/// bounds of the HTTP request latency histogram, a cumulative `le`
/// shape with an implicit `+Inf`.
pub const CONNECT_LATENCY_BUCKETS_S: &[f64] =
    &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0];

/// A fieldless enum counted by [`Keyed`], at the slot of its
/// discriminant.
trait Counted: Copy + Eq + Hash {
    fn slot(self) -> usize;
}

/// The `lorica-config` enums counted here; their word lists are theirs.
macro_rules! counted_by_discriminant {
    ($($counted:ty),+) => {
        $(impl Counted for $counted {
            fn slot(self) -> usize {
                self as usize
            }
        })+
    };
}

counted_by_discriminant!(StreamEndKind, StreamRefusal, DatagramDropReason);

/// Declares an enum counted here from one list of `Variant => "word"`
/// lines. Its `ALL` and its `as_str` come from that list, so a variant
/// cannot be missing from either (Phase 1 audit C13), and two variants
/// sharing a word do not compile.
macro_rules! counted_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $word:literal,
            )+
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: [$name; [$($word),+].len()] = [$(Self::$variant),+];

            /// The snake_case word of the value.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $word,)+
                }
            }
        }

        impl Counted for $name {
            fn slot(self) -> usize {
                self as usize
            }
        }

        const _: () = assert!(
            words_are_distinct(&[$($word),+]),
            concat!("two ", stringify!($name), " values share a word")
        );
    };
}

const fn words_are_distinct(words: &[&str]) -> bool {
    let mut i = 0;
    while i < words.len() {
        let mut j = i + 1;
        while j < words.len() {
            if same_bytes(words[i].as_bytes(), words[j].as_bytes()) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

const fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

counted_enum! {
    /// The outcome of a PROXY header on a stream (D-k).
    pub enum ProxyHeaderOutcome {
        /// A v1 header carrying TCP addresses, accepted from a trusted peer.
        AcceptedV1 => "accepted_v1",
        /// A v2 header carrying TCP addresses, accepted from a trusted peer.
        AcceptedV2 => "accepted_v2",
        /// A header without usable addresses (`LOCAL`, `UNKNOWN`,
        /// `AF_UNSPEC`, `AF_UNIX`), accepted: the socket addresses stay.
        AcceptedLocal => "accepted_local",
        /// A trusted peer sent no header: its first bytes open with no
        /// PROXY signature, or it closed before sending any byte. The
        /// HTTP listeners' `missing` (Story 12.8 D-j).
        RefusedMissing => "refused_missing",
        /// A trusted peer's header broke the grammar, or the peer closed
        /// inside it.
        RefusedMalformed => "refused_malformed",
        /// A trusted peer's header was longer than the bound.
        RefusedOversized => "refused_oversized",
        /// A trusted peer's header used something a TCP stream does not
        /// accept (`DGRAM` among others).
        RefusedUnsupported => "refused_unsupported",
        /// A trusted peer sent no complete header in time.
        RefusedTimeout => "refused_timeout",
        /// A peer outside the trusted list opened with a PROXY signature.
        RefusedUntrustedPeer => "refused_untrusted_peer",
    }
}

counted_enum! {
    /// Why a connect attempt failed, as the breaker counts it (D-g). On a
    /// UDP session (Story 12.5 D-i) `refused` and `unreachable` come from
    /// an ICMP error on the session socket, and `no_response` is a session
    /// that expected answers and reached its idle timeout without any.
    pub enum ConnectFailureKind {
        /// The backend answered with a reset to the SYN, or with an ICMP
        /// port unreachable to a datagram.
        Refused => "refused",
        /// No answer within the connect timeout.
        Timeout => "timeout",
        /// No route, host or network unreachable, and any other error.
        Unreachable => "unreachable",
        /// The connection was reset while being established.
        Reset => "reset",
        /// A UDP session owed responses reached its idle timeout without
        /// receiving one.
        NoResponse => "no_response",
    }
}

counted_enum! {
    /// How a TLS stream's ClientHello read ended (Story 12.4 D-n).
    pub enum ClientHelloOutcome {
        /// A complete ClientHello was read.
        Parsed => "parsed",
        /// None was complete by the deadline: the connection ended
        /// `clienthello_timeout`.
        Timeout => "timeout",
        /// The bytes are no ClientHello the stream accepts.
        Invalid => "invalid",
        /// The hello was larger, or spread over more records, than the
        /// reader accepts.
        Oversized => "oversized",
    }
}

counted_enum! {
    /// How a terminating stream's handshake ended (Story 12.4 D-n). Every
    /// outcome but `ok` refuses the connection with the
    /// [`StreamRefusal`] of the same word.
    pub enum HandshakeOutcome {
        /// The handshake completed.
        Ok => "ok",
        /// No certificate of the node serves the name or the local address.
        NoCertificate => "no_certificate",
        /// The client's certificate, its absence or its organization was
        /// refused.
        ClientCertificate => "client_certificate",
        /// Any other failure, the deadline included.
        TlsHandshake => "tls_handshake",
    }
}

impl HandshakeOutcome {
    /// The refusal a failed handshake ends the connection with; `None`
    /// for [`HandshakeOutcome::Ok`].
    pub fn refusal(&self) -> Option<StreamRefusal> {
        match self {
            Self::Ok => None,
            Self::NoCertificate => Some(StreamRefusal::NoCertificate),
            Self::ClientCertificate => Some(StreamRefusal::ClientCertificate),
            Self::TlsHandshake => Some(StreamRefusal::TlsHandshake),
        }
    }
}

counted_enum! {
    /// Why an attempt's upstream TLS failed (Story 12.4 D-i, D-n). Only
    /// `handshake` and `timeout` count against the backend in the breaker.
    pub enum UpstreamTlsFailure {
        /// The backend reset the connection or sent an alert during the
        /// handshake: it does not serve TLS correctly.
        Handshake => "handshake",
        /// The backend's certificate did not verify against the stream's
        /// trust: the configuration and the backend disagree.
        Verify => "verify",
        /// The handshake did not complete within the connect timeout.
        Timeout => "timeout",
        /// The stream's upstream TLS cannot be configured on this node:
        /// the public roots did not load, its CA bundle does not load, or
        /// its client identity's key is not held here. No connection is
        /// opened.
        NoTrust => "no_trust",
    }
}

impl UpstreamTlsFailure {
    /// Whether the breaker counts it as a failure of the backend.
    pub fn is_backend_failure(&self) -> bool {
        matches!(self, Self::Handshake | Self::Timeout)
    }
}

/// The share of `udp.max_sessions` below which the "ceiling reached"
/// edge re-arms, in percent (Story 12.5 D-n).
pub const CEILING_REARM_PERCENT: u64 = 90;

/// The slots of a [`Keyed`] family.
const KEYED_SLOTS: usize = 32;

/// Counts keyed by an enum, filled on first use. A key is counted at the
/// slot of its discriminant, which takes no lock and allocates nothing
/// (Phase 1 audit C24): a flood of refusals or dropped datagrams pays one
/// atomic add each. A key past the slots is counted under the overflow
/// lock, so an enum that outgrows them loses nothing.
#[derive(Debug)]
struct Keyed<K> {
    slots: [Slot<K>; KEYED_SLOTS],
    overflow: Mutex<HashMap<K, u64>>,
}

#[derive(Debug)]
struct Slot<K> {
    /// Set by the slot's first count, so the snapshot can name it.
    key: OnceLock<K>,
    count: AtomicU64,
}

impl<K> Default for Keyed<K> {
    fn default() -> Self {
        Keyed {
            slots: std::array::from_fn(|_| Slot {
                key: OnceLock::new(),
                count: AtomicU64::new(0),
            }),
            overflow: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Counted> Keyed<K> {
    fn add(&self, key: K) {
        match self.slots.get(key.slot()) {
            Some(slot) => {
                slot.key.get_or_init(|| key);
                bump(&slot.count);
            }
            None => {
                *self
                    .overflow
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(key)
                    .or_default() += 1;
            }
        }
    }

    fn snapshot(&self) -> HashMap<K, u64> {
        let mut counts = self
            .overflow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        counts.extend(self.slots.iter().filter_map(|slot| {
            let count = get(&slot.count);
            // A count seen before its key waits for the next snapshot.
            let key = slot.key.get().filter(|_| count > 0)?;
            Some((*key, count))
        }));
        counts
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
    datagrams_upload: AtomicU64,
    datagrams_download: AtomicU64,
    dropped: Keyed<DatagramDropReason>,
    ceiling_reached: AtomicU64,
    /// Set by the `session_cap` refusal that raised the edge, cleared
    /// once the stream is below [`CEILING_REARM_PERCENT`] again.
    ceiling_raised: AtomicBool,
    clienthello: Keyed<ClientHelloOutcome>,
    no_sni_matched: AtomicU64,
    ech_offered: AtomicU64,
    handshakes: Keyed<HandshakeOutcome>,
    sni_mismatch: AtomicU64,
    pending: Arc<AtomicU64>,
    geoip_unknown: AtomicU64,
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

    /// Count one client datagram of `bytes` bytes forwarded to a backend
    /// (the PROXY header excluded).
    pub fn datagram_upload(&self, bytes: u64) {
        bump(&self.datagrams_upload);
        self.add_upload(bytes);
    }

    /// Count one backend datagram of `bytes` bytes forwarded to a client.
    pub fn datagram_download(&self, bytes: u64) {
        bump(&self.datagrams_download);
        self.add_download(bytes);
    }

    /// Count a datagram dropped for `reason`.
    pub fn dropped(&self, reason: DatagramDropReason) {
        self.dropped.add(reason);
    }

    /// A `session_cap` refusal: raises the "ceiling reached" edge unless
    /// it is already raised. Returns whether this refusal raised it.
    pub fn session_cap_refused(&self) -> bool {
        let raised = !self.ceiling_raised.swap(true, Ordering::AcqRel);
        if raised {
            bump(&self.ceiling_reached);
        }
        raised
    }

    /// The stream holds `sessions` of its `max_sessions` on the node: the
    /// edge re-arms once that is below [`CEILING_REARM_PERCENT`].
    pub fn sessions_held(&self, sessions: u64, max_sessions: u64) {
        if sessions.saturating_mul(100) < max_sessions.saturating_mul(CEILING_REARM_PERCENT) {
            self.ceiling_raised.store(false, Ordering::Release);
        }
    }

    /// Count how a ClientHello read ended.
    pub fn clienthello(&self, outcome: ClientHelloOutcome) {
        self.clienthello.add(outcome);
    }

    /// Count a client without SNI that a `no_sni` rule admitted.
    pub fn no_sni_matched(&self) {
        bump(&self.no_sni_matched);
    }

    /// Count a ClientHello carrying an `encrypted_client_hello`
    /// extension.
    pub fn ech_offered(&self) {
        bump(&self.ech_offered);
    }

    /// Count how a terminating handshake ended.
    pub fn handshake(&self, outcome: HandshakeOutcome) {
        self.handshakes.add(outcome);
    }

    /// Count a handshake whose server name, as rustls read it, differs
    /// from the one the rule was chosen by.
    pub fn sni_mismatch(&self) {
        bump(&self.sni_mismatch);
    }

    /// Count a connection in its pre-forwarding reads (Story 12.6 D-f),
    /// pending until the guard drops.
    pub fn pending(&self) -> ActiveGuard {
        ActiveGuard::new(&self.pending)
    }

    /// Count a client whose country the stream's GeoIP list could not
    /// know, and let through (Story 12.6 D-d).
    pub fn geoip_unknown(&self) {
        bump(&self.geoip_unknown);
    }

    pub(crate) fn snapshot(&self) -> StreamCountersSnapshot {
        StreamCountersSnapshot {
            clienthello: self.clienthello.snapshot(),
            no_sni_matched: get(&self.no_sni_matched),
            ech_offered: get(&self.ech_offered),
            handshakes: self.handshakes.snapshot(),
            sni_mismatch: get(&self.sni_mismatch),
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
            datagrams_upload: get(&self.datagrams_upload),
            datagrams_download: get(&self.datagrams_download),
            dropped: self.dropped.snapshot(),
            ceiling_reached: get(&self.ceiling_reached),
            pending: get(&self.pending),
            geoip_unknown: get(&self.geoip_unknown),
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
    upstream_tls_failures: Keyed<UpstreamTlsFailure>,
    /// Whether the last upstream handshake on the link failed
    /// verification, so the failure is logged once per transition.
    verify_failing: AtomicBool,
    bytes_upload: AtomicU64,
    bytes_download: AtomicU64,
}

impl LinkStats {
    /// Add client-to-backend bytes forwarded to this backend, alongside
    /// the stream's own count (Story 12.9 D-e).
    pub fn add_upload(&self, bytes: u64) {
        self.bytes_upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add backend-to-client bytes forwarded from this backend.
    pub fn add_download(&self, bytes: u64) {
        self.bytes_download.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count an upstream TLS failure of `kind`. For `verify`, returns
    /// whether the link was not already failing verification, which is
    /// when the failure deserves a log line.
    pub fn upstream_tls_failed(&self, kind: UpstreamTlsFailure) -> bool {
        self.upstream_tls_failures.add(kind);
        kind == UpstreamTlsFailure::Verify && !self.verify_failing.swap(true, Ordering::AcqRel)
    }

    /// An upstream handshake completed: a later verification failure is
    /// a new transition.
    pub fn upstream_tls_verified(&self) {
        self.verify_failing.store(false, Ordering::Release);
    }

    /// Count an established connection after `latency`, active until
    /// the guard drops.
    pub fn connected(&self, latency: Duration) -> ActiveGuard {
        bump(&self.connects);
        self.connect_latency.observe(latency);
        ActiveGuard::new(&self.active)
    }

    /// Count a UDP session opened on the backend, active until the guard
    /// drops. No latency: a connected UDP socket has no handshake to time.
    pub fn session_opened(&self) -> ActiveGuard {
        bump(&self.connects);
        ActiveGuard::new(&self.active)
    }

    /// Count a failed connect attempt.
    pub fn connect_failed(&self, kind: ConnectFailureKind) {
        self.connect_failures.add(kind);
    }

    fn snapshot(&self) -> LinkCountersSnapshot {
        LinkCountersSnapshot {
            upstream_tls_failures: self.upstream_tls_failures.snapshot(),
            active: get(&self.active),
            connects: get(&self.connects),
            connect_failures: self.connect_failures.snapshot(),
            connect_latency: self.connect_latency.snapshot(),
            bytes_upload: get(&self.bytes_upload),
            bytes_download: get(&self.bytes_download),
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

type Family<V> = Mutex<HashMap<String, Arc<V>>>;

/// A family keyed by a pair of ids, nested so that a lookup borrows both.
type PairFamily<V> = Mutex<HashMap<String, HashMap<String, Arc<V>>>>;

/// The counters of `id`, created on first use, which is the only time
/// the key is allocated: the UDP engine reads a stream's counters per
/// datagram.
fn entry_by_id<V: Default>(family: &Family<V>, id: &str) -> Arc<V> {
    let mut map = family.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = map.get(id) {
        return Arc::clone(found);
    }
    Arc::clone(map.entry(id.to_string()).or_default())
}

/// The counters of (`first`, `second`), created on first use, which is
/// the only time the keys are allocated: the engines read a link's
/// counters per connection and per session (Phase 1 audit C25).
fn entry_by_pair<V: Default>(family: &PairFamily<V>, first: &str, second: &str) -> Arc<V> {
    let mut map = family.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = map.get(first).and_then(|inner| inner.get(second)) {
        return Arc::clone(found);
    }
    Arc::clone(
        map.entry(first.to_string())
            .or_default()
            .entry(second.to_string())
            .or_default(),
    )
}

fn read<V, S>(family: &Family<V>, snap: impl Fn(&V) -> S) -> BTreeMap<String, S> {
    family
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(k, v)| (k.clone(), snap(v)))
        .collect()
}

fn read_pairs<V, S>(
    family: &PairFamily<V>,
    snap: impl Fn(&V) -> S,
) -> BTreeMap<(String, String), S> {
    let snap = &snap;
    family
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .flat_map(|(first, inner)| {
            inner
                .iter()
                .map(move |(second, v)| ((first.clone(), second.clone()), snap(v)))
        })
        .collect()
}

fn retain_pairs<V>(family: &PairFamily<V>, keep: impl Fn(&str, &str) -> bool) {
    family
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .retain(|first, inner| {
            inner.retain(|second, _| keep(first, second));
            !inner.is_empty()
        });
}

/// The counters of one process's stream engines. One instance, shared
/// by both engines through [`crate::Engines::counters`].
#[derive(Debug, Default)]
pub struct StreamCounters {
    streams: Family<StreamStats>,
    /// By stream id, then backend id.
    links: PairFamily<LinkStats>,
    backends: Family<BackendStats>,
    /// By stream id, then rule name.
    rules: PairFamily<RuleStats>,
}

/// The counters of one rule of a TLS stream (Story 12.4 D-n).
#[derive(Debug, Default)]
pub struct RuleStats {
    matched: AtomicU64,
}

impl RuleStats {
    /// Count a ClientHello the rule matched.
    pub fn matched(&self) {
        bump(&self.matched);
    }

    fn snapshot(&self) -> RuleCountersSnapshot {
        RuleCountersSnapshot {
            matched: get(&self.matched),
        }
    }
}

impl StreamCounters {
    /// Empty counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters of `stream_id`, created on first use.
    pub fn stream(&self, stream_id: &str) -> Arc<StreamStats> {
        entry_by_id(&self.streams, stream_id)
    }

    /// The counters of `backend_id` on `stream_id`, created on first use.
    pub fn link(&self, stream_id: &str, backend_id: &str) -> Arc<LinkStats> {
        entry_by_pair(&self.links, stream_id, backend_id)
    }

    /// The counters of `backend_id`, created on first use.
    pub fn backend(&self, backend_id: &str) -> Arc<BackendStats> {
        entry_by_id(&self.backends, backend_id)
    }

    /// The counters of rule `rule` of `stream_id`, created on first use.
    pub fn rule(&self, stream_id: &str, rule: &str) -> Arc<RuleStats> {
        entry_by_pair(&self.rules, stream_id, rule)
    }

    /// Drop the counters of streams, links and backends `table` no
    /// longer holds.
    pub fn retain(&self, table: &StreamTable) {
        self.streams
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
        retain_pairs(&self.links, |stream, backend| {
            table.holds(stream, Some(backend))
        });
        self.backends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.backend(id).is_some());
        retain_pairs(&self.rules, |stream, rule| {
            table
                .stream(stream)
                .is_some_and(|s| s.match_rule(rule).is_some())
        });
    }

    /// Every counter as it stands.
    pub fn snapshot(&self) -> CountersSnapshot {
        CountersSnapshot {
            streams: read(&self.streams, StreamStats::snapshot),
            links: read_pairs(&self.links, LinkStats::snapshot),
            backends: read(&self.backends, BackendStats::snapshot),
            rules: read_pairs(&self.rules, RuleStats::snapshot),
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
    /// Per (stream id, rule name) of a TLS stream.
    pub rules: BTreeMap<(String, String), RuleCountersSnapshot>,
}

/// One rule's counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleCountersSnapshot {
    /// ClientHellos the rule matched.
    pub matched: u64,
}

/// One stream's counters. On a UDP stream a connection is a session.
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
    /// UDP: client datagrams forwarded to a backend.
    pub datagrams_upload: u64,
    /// UDP: backend datagrams forwarded to a client.
    pub datagrams_download: u64,
    /// UDP: datagrams dropped, per reason. A datagram whose session was
    /// refused counts as the refusal only.
    pub dropped: HashMap<DatagramDropReason, u64>,
    /// UDP: times the stream reached its `udp.max_sessions` on the node
    /// after holding less than [`CEILING_REARM_PERCENT`] of it, as this
    /// process saw it.
    pub ceiling_reached: u64,
    /// TLS: how ClientHello reads ended, per outcome.
    pub clienthello: HashMap<ClientHelloOutcome, u64>,
    /// TLS: clients without SNI a `no_sni` rule admitted.
    pub no_sni_matched: u64,
    /// TLS: ClientHellos carrying an `encrypted_client_hello` extension.
    pub ech_offered: u64,
    /// TLS: how terminating handshakes ended, per outcome.
    pub handshakes: HashMap<HandshakeOutcome, u64>,
    /// TLS: handshakes whose server name, as rustls read it, differed
    /// from the one the rule was chosen by.
    pub sni_mismatch: u64,
    /// TCP: this process's connections in their pre-forwarding reads now
    /// (a gauge); the node's total is the region's.
    pub pending: u64,
    /// Clients the stream's GeoIP list could not place, let through.
    pub geoip_unknown: u64,
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
    /// Failed upstream TLS handshakes, per kind (Story 12.4).
    pub upstream_tls_failures: HashMap<UpstreamTlsFailure, u64>,
    /// Client-to-backend bytes forwarded to this backend, added per
    /// completed write as the stream's are (Story 12.9).
    pub bytes_upload: u64,
    /// Backend-to-client bytes forwarded from this backend.
    pub bytes_download: u64,
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
    fn a_table_change_prunes_the_links_and_rules_it_no_longer_holds() {
        use chrono::Utc;
        use lorica_config::models::{
            Stream, StreamBackend, StreamMatchRule, StreamMatcher, StreamProtocol,
        };

        let mut stream = Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            1,
            1,
            Utc::now(),
        );
        stream.match_rules = vec![StreamMatchRule {
            name: "kept".into(),
            matcher: StreamMatcher::NoSni { alpn: Vec::new() },
        }];
        let table = StreamTable::new(vec![stream], &[StreamBackend::primary("s", "b1")]);
        let counters = StreamCounters::new();
        for (stream, other) in [("s", "b1"), ("s", "b2"), ("gone", "b1")] {
            counters.link(stream, other);
        }
        for (stream, rule) in [("s", "kept"), ("s", "removed"), ("gone", "kept")] {
            counters.rule(stream, rule);
        }
        counters.retain(&table);
        let snapshot = counters.snapshot();
        let pair = |a: &str, b: &str| (a.to_string(), b.to_string());
        assert_eq!(
            snapshot.links.keys().cloned().collect::<Vec<_>>(),
            vec![pair("s", "b1")]
        );
        assert_eq!(
            snapshot.rules.keys().cloned().collect::<Vec<_>>(),
            vec![pair("s", "kept")]
        );
        assert!(
            !counters
                .links
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key("gone"),
            "a stream left without links leaves no empty map behind"
        );
    }

    #[test]
    fn the_pending_gauge_follows_its_guards_and_geoip_unknown_counts() {
        let stats = StreamStats::default();
        let pending = stats.pending();
        stats.geoip_unknown();
        stats.geoip_unknown();
        let snap = stats.snapshot();
        assert_eq!((snap.pending, snap.geoip_unknown), (1, 2));
        drop(pending);
        assert_eq!(stats.snapshot().pending, 0);
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
    fn the_ceiling_edge_raises_once_and_rearms_below_ninety_percent() {
        let stats = StreamStats::default();
        assert!(stats.session_cap_refused());
        assert!(!stats.session_cap_refused(), "already raised");
        stats.sessions_held(95, 100);
        assert!(!stats.session_cap_refused(), "still above the threshold");
        stats.sessions_held(89, 100);
        assert!(stats.session_cap_refused(), "re-armed below 90 %");
        assert_eq!(stats.snapshot().ceiling_reached, 2);
    }

    #[test]
    fn datagram_counts_carry_their_bytes() {
        let stats = StreamStats::default();
        stats.datagram_upload(40);
        stats.datagram_download(400);
        stats.datagram_download(100);
        stats.dropped(DatagramDropReason::ResponseCountBound);
        let snap = stats.snapshot();
        assert_eq!((snap.datagrams_upload, snap.bytes_upload), (1, 40));
        assert_eq!((snap.datagrams_download, snap.bytes_download), (2, 500));
        assert_eq!(snap.dropped[&DatagramDropReason::ResponseCountBound], 1);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Spread {
        First,
        PastTheSlots = KEYED_SLOTS as isize,
    }

    impl Counted for Spread {
        fn slot(self) -> usize {
            self as usize
        }
    }

    #[test]
    fn a_key_past_the_slots_is_still_counted() {
        let keyed = Keyed::default();
        keyed.add(Spread::First);
        keyed.add(Spread::PastTheSlots);
        keyed.add(Spread::PastTheSlots);
        assert_eq!(
            keyed.snapshot(),
            HashMap::from([(Spread::First, 1), (Spread::PastTheSlots, 2)])
        );
    }

    #[test]
    fn the_word_check_tells_a_shared_word() {
        assert!(words_are_distinct(&["timeout", "time", "timeouts"]));
        assert!(!words_are_distinct(&["refused", "timeout", "refused"]));
        assert!(words_are_distinct(&[]));
    }

    /// A failed handshake's word is its refusal's, so the counter and the
    /// end reason read the same.
    #[test]
    fn handshake_failures_are_spelled_as_their_refusals() {
        for outcome in HandshakeOutcome::ALL {
            match outcome.refusal() {
                None => assert_eq!(outcome, HandshakeOutcome::Ok),
                Some(refusal) => {
                    let word: &'static str = refusal.into();
                    assert_eq!(word, outcome.as_str());
                }
            }
        }
    }

    #[test]
    fn a_verification_failure_is_reported_once_per_transition() {
        let link = LinkStats::default();
        assert!(link.upstream_tls_failed(UpstreamTlsFailure::Verify));
        assert!(!link.upstream_tls_failed(UpstreamTlsFailure::Verify));
        assert!(!link.upstream_tls_failed(UpstreamTlsFailure::Handshake));
        link.upstream_tls_verified();
        assert!(link.upstream_tls_failed(UpstreamTlsFailure::Verify));
        let snap = link.snapshot();
        assert_eq!(snap.upstream_tls_failures[&UpstreamTlsFailure::Verify], 3);
        assert_eq!(
            snap.upstream_tls_failures[&UpstreamTlsFailure::Handshake],
            1
        );
        assert!(UpstreamTlsFailure::ALL
            .iter()
            .all(|k| k.is_backend_failure()
                == matches!(
                    k,
                    UpstreamTlsFailure::Handshake | UpstreamTlsFailure::Timeout
                )));
    }
}
