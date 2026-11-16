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

//! The admission sequence both engines run before any byte is forwarded
//! or any session created (Story 12.6 D-a), cheapest and table-free
//! first, so a refused source never claims a rate cell or a shard cell:
//!
//! 1. the stream's caps region is present (`caps_unavailable`);
//! 2. the global connection filter (`connection_filter`), then
//! 3. the global IP blocklist unless the WAF whitelist holds the client
//!    (`ip_blocklist`), both through the [`SourceGate`];
//! 4. the stream's deny CIDRs, then its allow CIDRs (`source_denied`);
//! 5. the stream's GeoIP list (`geoip`; an unknown country passes and
//!    counts `geoip_unknown`);
//! 6. the stream's open rate, then the source's (`open_rate`,
//!    `source_open_rate`);
//! 7. the stream cap, then, on TCP with phase 2 work, the pending cap
//!    (`connection_cap` or `session_cap`, `pending_cap`); then the
//!    source cap and the source's pending share (`source_connection_cap`
//!    or `source_session_cap`, `source_pending_cap`). A full probe
//!    window refuses `connection_table_full` or `session_table_full`.
//!
//! A trusted PROXY peer (D-b) is a load balancer, not a source: at its
//! accept only steps 1, 6 and 7 run for the stream; steps 2 to 5 and the
//! source parts of 6 and 7 run on the client its header carries, before
//! any byte is forwarded.
//!
//! Per-stream policies are built in `table_changed`, never per
//! connection. Every refusal is counted by its caller and reported to
//! the [`RefusalLog`], which writes at most one row per stream and
//! refusal per window.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use chrono::Utc;
use lorica_config::connection_filter::{parse_cidr, ConnectionFilterPolicy};
use lorica_config::models::{GeoIpConfig, Stream, StreamRefusal};
use lorica_shmem::{
    now_ns, AdmitRefusal, BackendKey, BackendSlot, OpenLimits, OpenVerdict, SourceKey,
    StreamPermit, WorkerCaps,
};
use tracing::debug;

use crate::caps::CapsRegistry;
use crate::counters::{ActiveGuard, StreamStats};
use crate::handler::{ConnectionObserver, RefusalRecord, SuppressedRecord};
use crate::refusal_log::{RefusalLogDecision, RefusalLogLimiter};
use crate::seams::SourceGate;
use crate::table::{LinkedBackend, StreamTable};

/// A stream's own source controls, parsed once per table.
#[derive(Debug, Default)]
struct SourcePolicy {
    cidrs: ConnectionFilterPolicy,
    /// The stream names an allowlist none of whose entries parsed. The
    /// policy above would then admit everyone; an allowlist fails closed
    /// instead. Validation refuses such a list before it is stored.
    unreadable_allowlist: bool,
    geoip: Option<GeoIpConfig>,
}

impl SourcePolicy {
    fn of(stream: &Stream) -> SourcePolicy {
        let parse = |entries: &[String]| {
            entries
                .iter()
                .filter_map(|entry| parse_cidr(entry).ok())
                .collect::<Vec<_>>()
        };
        let cidrs = ConnectionFilterPolicy::from_nets(
            parse(&stream.source_allow_cidrs),
            parse(&stream.source_deny_cidrs),
        );
        SourcePolicy {
            unreadable_allowlist: stream.has_source_allowlist() && cidrs.allow.is_empty(),
            cidrs,
            geoip: stream.geoip.clone(),
        }
    }

    fn admits(&self, client: IpAddr) -> bool {
        !self.unreadable_allowlist && self.cidrs.accepts(client)
    }
}

/// The stream's open rates as the region charges them.
pub(crate) fn open_limits(stream: &Stream) -> OpenLimits {
    OpenLimits {
        stream_per_s: stream.open_rate.map(u64::from),
        source_per_s: stream.source_open_rate.map(u64::from),
    }
}

/// An open-rate verdict on TCP as its refusal.
fn tcp_open_refusal(verdict: OpenVerdict) -> Result<(), StreamRefusal> {
    match verdict {
        OpenVerdict::Allowed => Ok(()),
        OpenVerdict::OpenRate => Err(StreamRefusal::OpenRate),
        OpenVerdict::SourceOpenRate => Err(StreamRefusal::SourceOpenRate),
        OpenVerdict::TableFull => Err(StreamRefusal::ConnectionTableFull),
    }
}

/// A region refusal of a TCP connection.
fn tcp_cap_refusal(refusal: AdmitRefusal) -> StreamRefusal {
    match refusal {
        AdmitRefusal::StreamCap => StreamRefusal::ConnectionCap,
        AdmitRefusal::PendingCap => StreamRefusal::PendingCap,
        AdmitRefusal::SourceCap => StreamRefusal::SourceConnectionCap,
        AdmitRefusal::SourcePendingCap => StreamRefusal::SourcePendingCap,
        AdmitRefusal::TableFull => StreamRefusal::ConnectionTableFull,
    }
}

/// A region refusal of a UDP session. A session is never pending, so
/// the two pending refusals keep their own words.
pub(crate) fn udp_cap_refusal(refusal: AdmitRefusal) -> StreamRefusal {
    match refusal {
        AdmitRefusal::StreamCap => StreamRefusal::SessionCap,
        AdmitRefusal::PendingCap => StreamRefusal::PendingCap,
        AdmitRefusal::SourceCap => StreamRefusal::SourceSessionCap,
        AdmitRefusal::SourcePendingCap => StreamRefusal::SourcePendingCap,
        AdmitRefusal::TableFull => StreamRefusal::SessionTableFull,
    }
}

/// What a TCP connection holds once admitted: its permit in the region,
/// and its place in the `pending` gauge while phase 2 lasts. Dropping it
/// gives everything back.
#[derive(Debug)]
pub(crate) struct Admitted {
    /// `None` only in the instant [`AdmissionControl::admit_carried`]
    /// moves it through the source part.
    permit: Option<StreamPermit>,
    pending: Option<ActiveGuard>,
}

impl Admitted {
    /// Phase 2 is over: give the pending slot back, on the node and in
    /// this process's gauge. Idempotent.
    pub(crate) fn end_pending(&mut self) {
        if let Some(permit) = &mut self.permit {
            permit.end_pending();
        }
        self.pending = None;
    }

    /// This worker's handle on the region the connection is counted in,
    /// through which its backend claims are counted.
    pub(crate) fn worker_caps(&self) -> Option<WorkerCaps> {
        let permit = self.permit.as_ref()?;
        permit.region().worker(permit.slot())
    }
}

/// Whether `link` is at its `max_active` on the node (D-h): it then
/// leaves the candidates of this connection or session before
/// selection. A link without a cap never is.
pub(crate) fn backend_at_cap(caps: Option<&WorkerCaps>, link: &LinkedBackend) -> bool {
    match (caps, link.max_active) {
        (Some(caps), Some(cap)) => {
            caps.region()
                .backend_active(BackendKey::of(&link.backend.id))
                >= u64::from(cap)
        }
        _ => false,
    }
}

/// Claim one place on `link`'s `max_active` for the life of a connection
/// or session: `Ok(None)` for a link without a cap (nothing counted),
/// `Err(())` when the claim lost a race for the last place.
pub(crate) fn claim_backend(
    caps: Option<&WorkerCaps>,
    link: &LinkedBackend,
) -> Result<Option<BackendSlot>, ()> {
    match (caps, link.max_active) {
        (Some(caps), Some(cap)) => caps
            .claim_backend(BackendKey::of(&link.backend.id), u64::from(cap))
            .map(Some)
            .ok_or(()),
        _ => Ok(None),
    }
}

/// The admission sequence of one process's engines: the node's source
/// gate, the per-stream policies, and the refusal log.
pub(crate) struct AdmissionControl {
    gate: Arc<dyn SourceGate>,
    policies: Mutex<HashMap<String, Arc<SourcePolicy>>>,
    log: Arc<RefusalLog>,
}

impl AdmissionControl {
    pub(crate) fn new(
        gate: Arc<dyn SourceGate>,
        observer: Arc<dyn ConnectionObserver>,
    ) -> AdmissionControl {
        AdmissionControl {
            gate,
            policies: Mutex::new(HashMap::new()),
            log: Arc::new(RefusalLog::new(observer)),
        }
    }

    /// Build the policies of `table`'s streams, and forget the refusal
    /// windows of the streams it no longer holds.
    pub(crate) fn table_changed(&self, table: &StreamTable) {
        let policies = table
            .streams()
            .map(|stream| (stream.id.clone(), Arc::new(SourcePolicy::of(stream))))
            .collect();
        *self.policies.lock().unwrap_or_else(PoisonError::into_inner) = policies;
        self.log.retain(table);
    }

    fn policy(&self, stream: &Stream) -> Arc<SourcePolicy> {
        let known = self
            .policies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&stream.id)
            .cloned();
        // A stream the last table load did not show the engine yet.
        known.unwrap_or_else(|| Arc::new(SourcePolicy::of(stream)))
    }

    /// Steps 2 to 5 for `client`, canonical.
    pub(crate) fn judge(
        &self,
        stream: &Stream,
        stats: &StreamStats,
        client: IpAddr,
    ) -> Result<(), StreamRefusal> {
        if let Some(refusal) = self.gate.global(client) {
            return Err(refusal);
        }
        let policy = self.policy(stream);
        if !policy.admits(client) {
            return Err(StreamRefusal::SourceDenied);
        }
        if let Some(geoip) = &policy.geoip {
            let country = self.gate.country(client);
            match country.as_ref().map(|code| std::str::from_utf8(code)) {
                Some(Ok(code)) if geoip.blocks(code) => return Err(StreamRefusal::Geoip),
                Some(Ok(_)) => {}
                None | Some(Err(_)) => stats.geoip_unknown(),
            }
        }
        Ok(())
    }

    /// Steps 1 to 7 at a TCP accept, before the socket is read. On a
    /// `trusted` PROXY peer the steps that judge a source are left to
    /// [`AdmissionControl::admit_carried`]. `pending` takes a pending
    /// slot: the connection has phase 2 work (a trusted header, a
    /// ClientHello).
    pub(crate) fn admit_connection(
        &self,
        caps: &CapsRegistry,
        stream: &Stream,
        stats: &StreamStats,
        peer: IpAddr,
        trusted: bool,
        pending: bool,
    ) -> Result<Admitted, StreamRefusal> {
        let caps = caps.get(&stream.id).ok_or(StreamRefusal::CapsUnavailable)?;
        let source = if trusted {
            None
        } else {
            self.judge(stream, stats, peer)?;
            Some(SourceKey::of(peer))
        };
        let current = caps.current();
        tcp_open_refusal(
            current
                .region()
                .charge_open(source, open_limits(stream), now_ns()),
        )?;
        let permit = current
            .admit_stream(
                caps.stream_cap_left(u64::from(stream.max_connections)),
                pending,
                caps.pending_cap_left(u64::from(stream.effective_pending_connections())),
            )
            .map_err(tcp_cap_refusal)?;
        let permit = match source {
            None => permit,
            Some(source) => permit
                .admit_source(source, source_cap(stream), source_pending_cap(stream))
                .map_err(tcp_cap_refusal)?,
        };
        Ok(Admitted {
            permit: Some(permit),
            pending: pending.then(|| stats.pending()),
        })
    }

    /// The source steps of a trusted PROXY peer's connection, on the
    /// client its header carried (or on the peer itself for a header
    /// that carries none): steps 2 to 5, the source's open rate, the
    /// source cap and its pending share. A refusal ends the connection,
    /// which gives back whatever `admitted` still counts.
    pub(crate) fn admit_carried(
        &self,
        admitted: &mut Admitted,
        stream: &Stream,
        stats: &StreamStats,
        client: IpAddr,
    ) -> Result<(), StreamRefusal> {
        self.judge(stream, stats, client)?;
        let Some(permit) = admitted.permit.take() else {
            return Ok(());
        };
        let source = SourceKey::of(client);
        let limits = OpenLimits {
            stream_per_s: None,
            ..open_limits(stream)
        };
        if let Err(refusal) =
            tcp_open_refusal(permit.region().charge_open(Some(source), limits, now_ns()))
        {
            admitted.permit = Some(permit);
            return Err(refusal);
        }
        let permit = permit
            .admit_source(source, source_cap(stream), source_pending_cap(stream))
            .map_err(tcp_cap_refusal)?;
        admitted.permit = Some(permit);
        Ok(())
    }

    /// Hand `record` to the refusal log.
    pub(crate) fn report(&self, record: RefusalRecord) {
        self.log.report(record);
    }
}

/// A TCP stream's per-source cap: `source_max_connections`, or no bound
/// of its own (the stream cap bounds it).
fn source_cap(stream: &Stream) -> u64 {
    stream.source_max_connections.map_or(u64::MAX, u64::from)
}

/// A source's share of the pending cap (D-f).
fn source_pending_cap(stream: &Stream) -> u64 {
    u64::from(stream.source_pending_share())
}

/// The refusal log's key on the stream engines: the stream's index (see
/// [`StreamIndices`]) and the refusal. Story 12.9 widens the second part
/// to pre-forwarding ends.
type RefusalKey = (u32, StreamRefusal);

/// A small, stable number per stream id, so the limiter's key stays
/// `Copy`: kept for as long as the table holds the stream, never reused
/// while a window of it may still be open.
#[derive(Debug, Default)]
struct StreamIndices {
    by_id: HashMap<String, u32>,
    next: u32,
}

impl StreamIndices {
    fn of(&mut self, stream_id: &str) -> u32 {
        if let Some(index) = self.by_id.get(stream_id) {
            return *index;
        }
        let index = self.next;
        self.next = self.next.wrapping_add(1);
        self.by_id.insert(stream_id.to_string(), index);
        index
    }
}

/// The stream refusal rows (D-j, as Story 12.9 D-c amends it): each
/// refusal the limiter admits goes to the observer as a
/// [`RefusalRecord`] and to the debug log; the first refusal a window
/// holds back spawns one task that hands the window's count over as a
/// [`SuppressedRecord`] when it closes.
pub(crate) struct RefusalLog {
    observer: Arc<dyn ConnectionObserver>,
    limiter: RefusalLogLimiter<RefusalKey>,
    indices: Mutex<StreamIndices>,
}

impl RefusalLog {
    fn new(observer: Arc<dyn ConnectionObserver>) -> RefusalLog {
        RefusalLog {
            observer,
            limiter: RefusalLogLimiter::default(),
            indices: Mutex::new(StreamIndices::default()),
        }
    }

    fn indices(&self) -> std::sync::MutexGuard<'_, StreamIndices> {
        self.indices.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forget the streams `table` no longer holds, and their windows.
    fn retain(&self, table: &StreamTable) {
        let live: HashSet<u32> = {
            let mut indices = self.indices();
            indices
                .by_id
                .retain(|stream_id, _| table.stream(stream_id).is_some());
            indices.by_id.values().copied().collect()
        };
        self.limiter.retain(|(index, _)| live.contains(index));
    }

    fn report(self: &Arc<Self>, record: RefusalRecord) {
        let key = (self.indices().of(&record.stream_id), record.refusal);
        match self.limiter.admit(key, Instant::now()) {
            RefusalLogDecision::Write { suppressed } => {
                if suppressed > 0 {
                    self.suppressed(&record, suppressed);
                }
                debug!(
                    stream_id = %record.stream_id,
                    stream = %record.stream_name,
                    protocol = record.protocol.as_str(),
                    listen_port = record.listen_port,
                    reason = <&'static str>::from(record.refusal),
                    client = %record.client,
                    proxied_from = ?record.proxied_from,
                    "stream connection refused"
                );
                self.observer.refused(record);
            }
            RefusalLogDecision::Suppress {
                first: true,
                window_ends,
            } => self.report_at(key, record, window_ends),
            RefusalLogDecision::Suppress { first: false, .. } => {}
        }
    }

    /// Hand over the count the window ending at `window_ends` held back,
    /// when it closes. Without a runtime to wait on, the next refusal of
    /// the key after the window reports it instead.
    fn report_at(self: &Arc<Self>, key: RefusalKey, record: RefusalRecord, window_ends: Instant) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let log = Arc::clone(self);
        runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(window_ends)).await;
            let suppressed = log.limiter.close(key, window_ends);
            if suppressed > 0 {
                log.suppressed(&record, suppressed);
            }
        });
    }

    fn suppressed(&self, record: &RefusalRecord, suppressed: u64) {
        debug!(
            stream_id = %record.stream_id,
            stream = %record.stream_name,
            protocol = record.protocol.as_str(),
            reason = <&'static str>::from(record.refusal),
            suppressed,
            window_s = crate::refusal_log::REFUSAL_LOG_WINDOW.as_secs(),
            "stream refusals suppressed"
        );
        self.observer.refusals_suppressed(SuppressedRecord {
            stream_id: record.stream_id.clone(),
            stream_name: record.stream_name.clone(),
            protocol: record.protocol,
            refusal: record.refusal,
            suppressed,
            reported_at: Utc::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU64, Ordering};

    use lorica_config::models::{GeoIpMode, StreamProtocol};

    use crate::caps::NodeCapsRegions;

    const PEER: [u8; 4] = [192, 0, 2, 10];

    fn ip(octets: [u8; 4]) -> IpAddr {
        IpAddr::from(octets)
    }

    fn tcp() -> Stream {
        Stream::new(
            "s".into(),
            "pg".into(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().unwrap(),
            5432,
            5432,
            Utc::now(),
        )
    }

    /// A gate refusing the addresses it holds, with a country table.
    #[derive(Default)]
    struct Gate {
        filtered: Vec<IpAddr>,
        blocked: Vec<IpAddr>,
        countries: HashMap<IpAddr, [u8; 2]>,
        country_calls: AtomicU64,
    }

    impl SourceGate for Gate {
        fn global(&self, client: IpAddr) -> Option<StreamRefusal> {
            if self.filtered.contains(&client) {
                Some(StreamRefusal::ConnectionFilter)
            } else if self.blocked.contains(&client) {
                Some(StreamRefusal::IpBlocklist)
            } else {
                None
            }
        }

        fn country(&self, client: IpAddr) -> Option<[u8; 2]> {
            self.country_calls.fetch_add(1, Ordering::Relaxed);
            self.countries.get(&client).copied()
        }
    }

    #[derive(Default)]
    struct Recorder {
        refused: Mutex<Vec<RefusalRecord>>,
        suppressed: Mutex<Vec<SuppressedRecord>>,
    }

    impl ConnectionObserver for Recorder {
        fn refused(&self, record: RefusalRecord) {
            self.refused.lock().unwrap().push(record);
        }

        fn refusals_suppressed(&self, record: SuppressedRecord) {
            self.suppressed.lock().unwrap().push(record);
        }
    }

    fn control(gate: Gate) -> (AdmissionControl, Arc<Recorder>) {
        let recorder = Arc::new(Recorder::default());
        let control = AdmissionControl::new(
            Arc::new(gate),
            Arc::clone(&recorder) as Arc<dyn ConnectionObserver>,
        );
        (control, recorder)
    }

    fn registry(stream: &Stream) -> (NodeCapsRegions, CapsRegistry) {
        let mut node = NodeCapsRegions::new(1);
        node.ensure(&stream.id, u64::from(stream.max_connections), 0)
            .unwrap();
        let registry = CapsRegistry::new();
        let Some(lorica_worker::stream_ctl::StreamCtlMsg::Caps { region, slot, .. }) =
            node.caps_message(&stream.id, 1, 0).unwrap()
        else {
            panic!("a caps message");
        };
        let region = Arc::new(lorica_shmem::StreamCapsRegion::open(region).unwrap());
        registry.adopt(&stream.id, region.worker(slot).unwrap());
        (node, registry)
    }

    #[test]
    fn the_global_gate_is_asked_first_and_its_refusal_kept() {
        let mut stream = tcp();
        stream.source_deny_cidrs = vec!["192.0.2.0/24".into()];
        let gate = Gate {
            filtered: vec![ip(PEER)],
            blocked: vec![ip([192, 0, 2, 11])],
            ..Gate::default()
        };
        let (control, _) = control(gate);
        let stats = StreamStats::default();
        assert_eq!(
            control.judge(&stream, &stats, ip(PEER)),
            Err(StreamRefusal::ConnectionFilter)
        );
        assert_eq!(
            control.judge(&stream, &stats, ip([192, 0, 2, 11])),
            Err(StreamRefusal::IpBlocklist)
        );
        assert_eq!(
            control.judge(&stream, &stats, ip([192, 0, 2, 12])),
            Err(StreamRefusal::SourceDenied)
        );
    }

    #[test]
    fn deny_wins_over_allow_and_an_allowlist_refuses_a_miss() {
        let mut stream = tcp();
        stream.source_allow_cidrs = vec!["192.0.2.0/24".into()];
        stream.source_deny_cidrs = vec!["192.0.2.66".into()];
        let (control, _) = control(Gate::default());
        let table = StreamTable::new(vec![stream.clone()], &[]);
        control.table_changed(&table);
        let stats = StreamStats::default();
        assert_eq!(control.judge(&stream, &stats, ip(PEER)), Ok(()));
        assert_eq!(
            control.judge(&stream, &stats, ip([192, 0, 2, 66])),
            Err(StreamRefusal::SourceDenied)
        );
        assert_eq!(
            control.judge(&stream, &stats, ip([198, 51, 100, 1])),
            Err(StreamRefusal::SourceDenied)
        );
    }

    #[test]
    fn an_allowlist_with_no_readable_entry_fails_closed() {
        let mut stream = tcp();
        stream.source_allow_cidrs = vec!["not an address".into()];
        let (control, _) = control(Gate::default());
        assert_eq!(
            control.judge(&stream, &StreamStats::default(), ip(PEER)),
            Err(StreamRefusal::SourceDenied)
        );
    }

    #[test]
    fn geoip_refuses_by_country_and_lets_an_unknown_one_pass_counted() {
        let mut stream = tcp();
        stream.geoip = Some(GeoIpConfig {
            mode: GeoIpMode::Denylist,
            countries: vec!["US".into()],
        });
        let gate = Gate {
            countries: HashMap::from([(ip(PEER), *b"US"), (ip([192, 0, 2, 11]), *b"FR")]),
            ..Gate::default()
        };
        let (control, _) = control(gate);
        let stats = StreamStats::default();
        assert_eq!(
            control.judge(&stream, &stats, ip(PEER)),
            Err(StreamRefusal::Geoip)
        );
        assert_eq!(control.judge(&stream, &stats, ip([192, 0, 2, 11])), Ok(()));
        assert_eq!(control.judge(&stream, &stats, ip([192, 0, 2, 12])), Ok(()));
        assert_eq!(stats.snapshot().geoip_unknown, 1);
    }

    #[test]
    fn a_stream_without_geoip_never_asks_for_a_country() {
        let gate = Arc::new(Gate::default());
        let control = AdmissionControl::new(
            Arc::clone(&gate) as Arc<dyn SourceGate>,
            Arc::new(Recorder::default()),
        );
        assert_eq!(
            control.judge(&tcp(), &StreamStats::default(), ip(PEER)),
            Ok(())
        );
        assert_eq!(gate.country_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn no_region_refuses_caps_unavailable_before_anything_else() {
        let mut stream = tcp();
        stream.source_deny_cidrs = vec!["192.0.2.0/24".into()];
        let (control, _) = control(Gate::default());
        let refused = control
            .admit_connection(
                &CapsRegistry::new(),
                &stream,
                &StreamStats::default(),
                ip(PEER),
                false,
                false,
            )
            .unwrap_err();
        assert_eq!(refused, StreamRefusal::CapsUnavailable);
    }

    #[test]
    fn a_refused_source_claims_no_rate_cell_and_no_shard_cell() {
        let mut stream = tcp();
        stream.source_deny_cidrs = vec!["192.0.2.0/24".into()];
        stream.source_open_rate = Some(10);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let refused = control
            .admit_connection(
                &caps,
                &stream,
                &StreamStats::default(),
                ip(PEER),
                false,
                false,
            )
            .unwrap_err();
        assert_eq!(refused, StreamRefusal::SourceDenied);
        let region = Arc::clone(caps.get("s").unwrap().current().region());
        assert_eq!(region.evict_rates(now_ns()).occupied, 0);
        assert_eq!(region.total(), 0);
    }

    #[test]
    fn the_source_open_rate_refuses_one_source_and_serves_another() {
        let mut stream = tcp();
        stream.source_open_rate = Some(2);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        let admit = |peer: [u8; 4]| {
            control.admit_connection(&caps, &stream, &stats, ip(peer), false, false)
        };
        // One second of burst at two per second.
        let held: Vec<Admitted> = (0..2).map(|_| admit(PEER).unwrap()).collect();
        assert_eq!(admit(PEER).unwrap_err(), StreamRefusal::SourceOpenRate);
        assert!(admit([192, 0, 2, 11]).is_ok(), "another source is served");
        drop(held);
    }

    #[test]
    fn a_trusted_peer_is_judged_on_the_client_its_header_carries() {
        let mut stream = tcp();
        stream.source_deny_cidrs = vec!["198.51.100.0/24".into()];
        stream.source_max_connections = Some(1);
        stream.source_open_rate = Some(1);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        // The load balancer itself sits in the denied range: as a trusted
        // peer it is not judged, rated or capped as a source.
        let balancer = ip([198, 51, 100, 1]);
        let mut first = control
            .admit_connection(&caps, &stream, &stats, balancer, true, true)
            .unwrap();
        let mut second = control
            .admit_connection(&caps, &stream, &stats, balancer, true, true)
            .unwrap();
        assert_eq!(stats.snapshot().pending, 2);
        assert_eq!(
            control.admit_carried(&mut first, &stream, &stats, ip(PEER)),
            Ok(())
        );
        assert_eq!(
            control.admit_carried(&mut second, &stream, &stats, ip(PEER)),
            Err(StreamRefusal::SourceOpenRate),
            "the carried client is rated"
        );
        let mut third = control
            .admit_connection(&caps, &stream, &stats, balancer, true, true)
            .unwrap();
        assert_eq!(
            control.admit_carried(&mut third, &stream, &stats, balancer),
            Err(StreamRefusal::SourceDenied),
            "a header carrying no client judges the peer"
        );
        let region = Arc::clone(caps.get("s").unwrap().current().region());
        assert_eq!(region.source_sessions(SourceKey::of(ip(PEER))), 1);
        first.end_pending();
        assert_eq!(region.pending(), 2, "second and third still pending");
        drop((second, third));
        assert_eq!(region.pending(), 0);
        assert_eq!(stats.snapshot().pending, 0);
        drop(first);
        assert_eq!(region.total(), 0);
    }

    #[test]
    fn a_source_at_its_pending_share_is_refused_while_another_is_admitted() {
        let mut stream = tcp();
        stream.max_pending_connections = 16;
        let share = stream.source_pending_share();
        assert_eq!(share, 2);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        let admit =
            |peer: [u8; 4]| control.admit_connection(&caps, &stream, &stats, ip(peer), false, true);
        let held: Vec<Admitted> = (0..share).map(|_| admit(PEER).unwrap()).collect();
        assert_eq!(admit(PEER).unwrap_err(), StreamRefusal::SourcePendingCap);
        let other = admit([192, 0, 2, 11]).unwrap();
        assert_eq!(stats.snapshot().pending, u64::from(share) + 1);
        drop((held, other));
    }

    #[test]
    fn the_pending_cap_and_the_stream_cap_refuse_with_their_words() {
        let mut stream = tcp();
        stream.max_connections = 3;
        stream.max_pending_connections = 2;
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        let admit = |n: u8, pending: bool| {
            control.admit_connection(&caps, &stream, &stats, ip([192, 0, 2, n]), false, pending)
        };
        let a = admit(1, true).unwrap();
        let b = admit(2, true).unwrap();
        assert_eq!(admit(3, true).unwrap_err(), StreamRefusal::PendingCap);
        let c = admit(4, false).unwrap();
        assert_eq!(admit(5, false).unwrap_err(), StreamRefusal::ConnectionCap);
        drop((a, b, c));
    }

    #[test]
    fn a_source_at_source_max_connections_is_refused() {
        let mut stream = tcp();
        stream.source_max_connections = Some(1);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        let held = control
            .admit_connection(&caps, &stream, &stats, ip(PEER), false, false)
            .unwrap();
        assert_eq!(
            control
                .admit_connection(&caps, &stream, &stats, ip(PEER), false, false)
                .unwrap_err(),
            StreamRefusal::SourceConnectionCap
        );
        drop(held);
    }

    #[test]
    fn the_stream_open_rate_refuses_open_rate() {
        let mut stream = tcp();
        stream.open_rate = Some(1);
        let (_node, caps) = registry(&stream);
        let (control, _) = control(Gate::default());
        let stats = StreamStats::default();
        let held = control
            .admit_connection(&caps, &stream, &stats, ip(PEER), true, true)
            .unwrap();
        assert_eq!(
            control
                .admit_connection(&caps, &stream, &stats, ip([192, 0, 2, 11]), false, false)
                .unwrap_err(),
            StreamRefusal::OpenRate
        );
        drop(held);
    }

    fn refusal(stream: &Stream, refusal: StreamRefusal) -> RefusalRecord {
        RefusalRecord {
            stream_id: stream.id.clone(),
            stream_name: stream.name.clone(),
            protocol: stream.protocol,
            listen_port: stream.port_first,
            client: SocketAddr::new(ip(PEER), 40_000),
            proxied_from: None,
            refusal,
            at: Utc::now(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_thousand_refusals_in_a_window_make_one_row_and_one_suppressed_row() {
        let stream = tcp();
        let (control, recorder) = control(Gate::default());
        control.table_changed(&StreamTable::new(vec![stream.clone()], &[]));
        for _ in 0..1_000 {
            control.report(refusal(&stream, StreamRefusal::SourceOpenRate));
        }
        // Another reason has its own window.
        control.report(refusal(&stream, StreamRefusal::Geoip));
        assert_eq!(recorder.refused.lock().unwrap().len(), 2);
        assert!(recorder.suppressed.lock().unwrap().is_empty());

        // Past the window: it opened on the wall clock, a little after the
        // paused clock's start.
        tokio::time::sleep(
            crate::refusal_log::REFUSAL_LOG_WINDOW + std::time::Duration::from_secs(1),
        )
        .await;
        let suppressed = recorder.suppressed.lock().unwrap().clone();
        assert_eq!(suppressed.len(), 1);
        assert_eq!(suppressed[0].suppressed, 999);
        assert_eq!(suppressed[0].refusal, StreamRefusal::SourceOpenRate);
        assert_eq!(suppressed[0].stream_id, "s");
        let refused = recorder.refused.lock().unwrap();
        assert_eq!(refused[0].refusal, StreamRefusal::SourceOpenRate);
        assert_eq!(refused[0].client, SocketAddr::new(ip(PEER), 40_000));
    }

    #[test]
    fn a_stream_leaving_the_table_takes_its_windows_with_it() {
        let stream = tcp();
        let (control, recorder) = control(Gate::default());
        control.table_changed(&StreamTable::new(vec![stream.clone()], &[]));
        control.report(refusal(&stream, StreamRefusal::Geoip));
        control.report(refusal(&stream, StreamRefusal::Geoip));
        assert_eq!(control.log.limiter.len(), 1);
        control.table_changed(&StreamTable::default());
        assert!(control.log.limiter.is_empty());
        control.report(refusal(&stream, StreamRefusal::Geoip));
        assert_eq!(
            recorder.refused.lock().unwrap().len(),
            2,
            "a stream coming back starts a new window"
        );
    }
}
