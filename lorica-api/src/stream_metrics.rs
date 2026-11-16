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

//! The stream plane's Prometheus families (Story 12.9 D-e), rendered at
//! scrape time by one [`StreamMetricsCollector`].
//!
//! The engines count in each process ([`StreamCounters`]); workers serve
//! no `/metrics`, so each worker's [`CountersSnapshot`] reaches the
//! supervisor in its metrics report and is applied here with
//! [`StreamMetricsCollector::apply_worker`]. A single process hands its
//! own counters over once ([`StreamMetricsCollector::set_local_counters`])
//! and the collector reads them at every scrape.
//!
//! **Labels** are `stream_id` and `backend_id`, never a name (a rename
//! would split a series) and never anything a client chooses (address,
//! port, SNI, ALPN). Names join through `lorica_stream_info`. Reason,
//! outcome and kind labels take the words of the closed enums the
//! counters are keyed by; a rule is labelled by its position in the
//! stream, never by what it matches.
//!
//! **Counters stay monotone across worker restarts.** A counter or
//! histogram renders `retired + sum(live sources)`. When a source's value
//! for a series goes down or the series leaves its snapshot (a restart, a
//! prune then a re-creation), or the worker dies, its last value is folded
//! into `retired` first. **Gauges** are a sum over the live sources, so a
//! dead worker's connections leave at once, except where the supervisor
//! knows the node's exact value ([`NodeStreamGauges`]).
//!
//! **Series of a deleted stream, link or backend are removed** on the
//! table change that removes it ([`StreamMetricsCollector::retain`]),
//! with the same holding rules as [`StreamCounters::retain`], so a churn
//! of streams does not grow `/metrics`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use lorica_metrics::prometheus::core::{Collector, Desc};
use lorica_metrics::prometheus::proto;
use lorica_stream::counters::{
    BackendCountersSnapshot, HistogramSnapshot, LinkCountersSnapshot, RuleCountersSnapshot,
    StreamCountersSnapshot, CONNECT_LATENCY_BUCKETS_S,
};
use lorica_stream::{
    BindStateKind, CountersSnapshot, StreamBindStates, StreamCounters, StreamTable,
};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use strum::VariantArray;

/// The type of a family as Prometheus renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyType {
    /// A monotone total.
    Counter,
    /// A value that goes up and down.
    Gauge,
    /// Cumulative buckets over [`CONNECT_LATENCY_BUCKETS_S`].
    Histogram,
}

/// One family the collector renders. Its name is `lorica_` followed by
/// [`StreamFamily::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, VariantArray)]
pub enum StreamFamily {
    /// `1` per stream of the table, joining ids to names.
    Info,
    /// Whether the supervisor holds the stream's sockets.
    ListenerUp,
    /// Open connections, or live UDP sessions.
    Active,
    /// Connections in their pre-forwarding reads.
    Pending,
    /// Connections or sessions accepted.
    Accepted,
    /// Ends, per end kind.
    Ended,
    /// Refusals, per refusal.
    Refused,
    /// Dropped datagrams, per reason.
    DatagramsDropped,
    /// Bytes forwarded, per direction.
    Bytes,
    /// Datagrams forwarded, per direction.
    Datagrams,
    /// Connect attempts.
    ConnectAttempts,
    /// Attempts after a connection's first.
    Retries,
    /// Breaker denials.
    BreakerDenied,
    /// Backend candidates skipped, per [`CandidateSkip`].
    CandidatesSkipped,
    /// PROXY header outcomes.
    ProxyHeader,
    /// Times a UDP stream reached its session ceiling, as each process
    /// saw it.
    CeilingReached,
    /// Clients the stream's GeoIP list could not place.
    GeoipUnknown,
    /// ClientHello read outcomes.
    ClientHello,
    /// Terminating handshake outcomes.
    TlsHandshakes,
    /// Clients without SNI a `no_sni` rule admitted.
    NoSniMatched,
    /// ClientHellos offering ECH.
    EchOffered,
    /// Handshakes whose server name differed from the routed one.
    SniMismatch,
    /// ClientHellos a rule matched, per rule position.
    RuleMatched,
    /// Open connections per backend of a stream.
    BackendActive,
    /// Connections established per backend of a stream.
    BackendConnects,
    /// Failed connect attempts per backend of a stream, per kind.
    BackendConnectFailures,
    /// Connect latency per backend of a stream.
    BackendConnectSeconds,
    /// Failed upstream TLS handshakes per backend of a stream, per kind.
    BackendUpstreamTlsFailures,
    /// Failed or empty resolutions of a backend's name.
    BackendDnsFailures,
    /// Transitions into "every address refused as local".
    BackendDnsLocalExcluded,
}

impl StreamFamily {
    /// The name under the `lorica` namespace.
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "stream_info",
            Self::ListenerUp => "stream_listener_up",
            Self::Active => "stream_active",
            Self::Pending => "stream_pending",
            Self::Accepted => "stream_accepted_total",
            Self::Ended => "stream_ended_total",
            Self::Refused => "stream_refused_total",
            Self::DatagramsDropped => "stream_datagrams_dropped_total",
            Self::Bytes => "stream_bytes_total",
            Self::Datagrams => "stream_datagrams_total",
            Self::ConnectAttempts => "stream_connect_attempts_total",
            Self::Retries => "stream_retries_total",
            Self::BreakerDenied => "stream_breaker_denied_total",
            Self::CandidatesSkipped => "stream_candidates_skipped_total",
            Self::ProxyHeader => "stream_proxy_header_total",
            Self::CeilingReached => "stream_ceiling_reached_total",
            Self::GeoipUnknown => "stream_geoip_unknown_total",
            Self::ClientHello => "stream_clienthello_total",
            Self::TlsHandshakes => "stream_tls_handshakes_total",
            Self::NoSniMatched => "stream_no_sni_matched_total",
            Self::EchOffered => "stream_ech_offered_total",
            Self::SniMismatch => "stream_sni_mismatch_total",
            Self::RuleMatched => "stream_rule_matched_total",
            Self::BackendActive => "stream_backend_active",
            Self::BackendConnects => "stream_backend_connects_total",
            Self::BackendConnectFailures => "stream_backend_connect_failures_total",
            Self::BackendConnectSeconds => "stream_backend_connect_seconds",
            Self::BackendUpstreamTlsFailures => "stream_backend_upstream_tls_failures_total",
            Self::BackendDnsFailures => "stream_backend_dns_failures_total",
            Self::BackendDnsLocalExcluded => "stream_backend_dns_local_excluded_total",
        }
    }

    /// The name a scrape shows.
    pub fn qualified_name(self) -> String {
        format!("{}_{}", lorica_metrics::NAMESPACE, self.name())
    }

    /// How Prometheus types the family.
    pub fn family_type(self) -> FamilyType {
        match self {
            Self::Info | Self::ListenerUp | Self::Active | Self::Pending | Self::BackendActive => {
                FamilyType::Gauge
            }
            Self::BackendConnectSeconds => FamilyType::Histogram,
            _ => FamilyType::Counter,
        }
    }

    /// The label names, in the order a series carries them. The scope of
    /// a series (stream, link, backend, rule) is read from them.
    pub fn labels(self) -> &'static [&'static str] {
        match self {
            Self::Info => &["stream_id", "stream_name", "protocol"],
            Self::Ended | Self::Refused | Self::DatagramsDropped | Self::CandidatesSkipped => {
                &["stream_id", "reason"]
            }
            Self::Bytes | Self::Datagrams => &["stream_id", "direction"],
            Self::ProxyHeader | Self::ClientHello | Self::TlsHandshakes => {
                &["stream_id", "outcome"]
            }
            Self::RuleMatched => &["stream_id", "rule"],
            Self::BackendActive | Self::BackendConnects | Self::BackendConnectSeconds => {
                &["stream_id", "backend_id"]
            }
            Self::BackendConnectFailures | Self::BackendUpstreamTlsFailures => {
                &["stream_id", "backend_id", "kind"]
            }
            Self::BackendDnsFailures | Self::BackendDnsLocalExcluded => &["backend_id"],
            Self::ListenerUp
            | Self::Active
            | Self::Pending
            | Self::Accepted
            | Self::ConnectAttempts
            | Self::Retries
            | Self::BreakerDenied
            | Self::CeilingReached
            | Self::GeoipUnknown
            | Self::NoSniMatched
            | Self::EchOffered
            | Self::SniMismatch => &["stream_id"],
        }
    }

    fn help(self) -> &'static str {
        match self {
            Self::Info => "One per stream of the table, joining stream_id to its name and protocol",
            Self::ListenerUp => {
                "Whether the node holds the stream's listening sockets (1 bound, 0 not)"
            }
            Self::Active => "Open stream connections, or live UDP sessions, on the node",
            Self::Pending => "Stream connections in their pre-forwarding reads on the node",
            Self::Accepted => "Stream connections or UDP sessions accepted",
            Self::Ended => "Stream connections or UDP sessions ended, per end reason",
            Self::Refused => "Stream connections or UDP sessions refused, per refusal reason",
            Self::DatagramsDropped => "UDP datagrams dropped, per reason",
            Self::Bytes => "Bytes forwarded by a stream, per direction",
            Self::Datagrams => "UDP datagrams forwarded by a stream, per direction",
            Self::ConnectAttempts => "Backend connect attempts made by a stream",
            Self::Retries => "Backend connect attempts after a connection's first",
            Self::BreakerDenied => "Backend candidates denied by the circuit breaker",
            Self::CandidatesSkipped => "Backend candidates skipped before a connect, per reason",
            Self::ProxyHeader => "PROXY protocol header outcomes on a stream",
            Self::CeilingReached => {
                "Times a UDP stream reached its session ceiling, per process edge"
            }
            Self::GeoipUnknown => "Clients a stream's GeoIP list could not place, let through",
            Self::ClientHello => "ClientHello read outcomes on a TLS stream",
            Self::TlsHandshakes => "Handshake outcomes on a terminating stream",
            Self::NoSniMatched => "Clients without SNI a no_sni rule admitted",
            Self::EchOffered => "ClientHellos carrying an encrypted_client_hello extension",
            Self::SniMismatch => "Handshakes whose server name differed from the one routed by",
            Self::RuleMatched => "ClientHellos a stream rule matched, per rule position",
            Self::BackendActive => "Open connections per backend of a stream",
            Self::BackendConnects => "Connections established per backend of a stream",
            Self::BackendConnectFailures => {
                "Failed connect attempts per backend of a stream, per kind"
            }
            Self::BackendConnectSeconds => "Backend connect latency of a stream, in seconds",
            Self::BackendUpstreamTlsFailures => {
                "Failed upstream TLS handshakes per backend of a stream, per kind"
            }
            Self::BackendDnsFailures => "Failed or empty resolutions of a stream backend's name",
            Self::BackendDnsLocalExcluded => {
                "Transitions of a stream backend into every address refused as local"
            }
        }
    }
}

/// The direction label of the byte and datagram families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, VariantArray)]
#[strum(serialize_all = "snake_case")]
pub enum Direction {
    /// Client to backend.
    Upload,
    /// Backend to client.
    Download,
}

impl Direction {
    /// The label word.
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// Why a backend candidate was skipped before a connect: the `reason`
/// label of `lorica_stream_candidates_skipped_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::IntoStaticStr, VariantArray)]
#[strum(serialize_all = "snake_case")]
pub enum CandidateSkip {
    /// The destination resolved to a local address.
    LocalDestination,
    /// No source address of the candidate's family.
    SourceFamilyMismatch,
    /// Binding the source address failed.
    SourceBindFailed,
}

impl CandidateSkip {
    /// The label word.
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// What the supervisor knows exactly of a stream on the node, from the
/// stream-caps regions, in place of the sum of the workers' gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NodeStreamGauges {
    /// Live sessions of a UDP stream on the node; `None` on TCP, whose
    /// active connections are the workers' sum.
    pub udp_sessions: Option<u64>,
    /// Connections in their pre-forwarding reads on the node.
    pub pending: Option<u64>,
}

impl NodeStreamGauges {
    /// A UDP stream's node values.
    pub fn udp(sessions: u64, pending: u64) -> Self {
        Self {
            udp_sessions: Some(sessions),
            pending: Some(pending),
        }
    }

    /// A TCP stream's node value: its pending connections.
    pub fn tcp(pending: u64) -> Self {
        Self {
            udp_sessions: None,
            pending: Some(pending),
        }
    }
}

/// One series: a family and its label values, positional to
/// [`StreamFamily::labels`]. A [`StreamFamily::RuleMatched`] series
/// carries the rule's name until it is rendered as its position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Series {
    family: StreamFamily,
    values: Vec<String>,
}

impl Series {
    fn new(family: StreamFamily, values: &[&str]) -> Self {
        Series {
            family,
            values: values.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    /// Whether `table` still holds what the series counts, by the rules
    /// of [`StreamCounters::retain`].
    fn held_by(&self, table: &StreamTable) -> bool {
        match (self.family.labels(), self.values.as_slice()) {
            (["stream_id", "backend_id", ..], [stream, backend, ..]) => {
                table.holds(stream, Some(backend))
            }
            (["backend_id", ..], [backend, ..]) => table.backend(backend).is_some(),
            (["stream_id", "rule"], [stream, rule]) => table
                .stream(stream)
                .is_some_and(|s| s.match_rule(rule).is_some()),
            (["stream_id", ..], [stream, ..]) => table.stream(stream).is_some(),
            _ => false,
        }
    }
}

/// One source's snapshot as series.
#[derive(Debug, Clone, Default)]
struct Flat {
    counters: BTreeMap<Series, u64>,
    gauges: BTreeMap<Series, u64>,
    histograms: BTreeMap<Series, HistogramSnapshot>,
}

impl Flat {
    fn counter(&mut self, family: StreamFamily, values: &[&str], value: u64) {
        self.counters.insert(Series::new(family, values), value);
    }

    fn gauge(&mut self, family: StreamFamily, values: &[&str], value: u64) {
        self.gauges.insert(Series::new(family, values), value);
    }

    /// Every series of `snapshot`. Each snapshot type is destructured
    /// whole, so a counter added to it does not compile until it is given
    /// a family here.
    fn of(snapshot: &CountersSnapshot) -> Self {
        let CountersSnapshot {
            streams,
            links,
            backends,
            rules,
        } = snapshot;
        let mut flat = Flat::default();
        for (stream_id, stream) in streams {
            flat.add_stream(stream_id, stream);
        }
        for ((stream_id, backend_id), link) in links {
            flat.add_link(stream_id, backend_id, link);
        }
        for (backend_id, backend) in backends {
            let BackendCountersSnapshot {
                dns_failures,
                dns_local_excluded,
            } = backend;
            flat.counter(
                StreamFamily::BackendDnsFailures,
                &[backend_id],
                *dns_failures,
            );
            flat.counter(
                StreamFamily::BackendDnsLocalExcluded,
                &[backend_id],
                *dns_local_excluded,
            );
        }
        for ((stream_id, rule), counts) in rules {
            let RuleCountersSnapshot { matched } = counts;
            flat.counter(StreamFamily::RuleMatched, &[stream_id, rule], *matched);
        }
        flat
    }

    fn add_stream(&mut self, id: &str, stream: &StreamCountersSnapshot) {
        use StreamFamily as F;
        let StreamCountersSnapshot {
            active,
            accepted,
            ended,
            refused,
            bytes_upload,
            bytes_download,
            connect_attempts,
            retries,
            breaker_denied,
            proxy_header,
            local_destination_refused,
            source_family_mismatch,
            source_bind_failed,
            datagrams_upload,
            datagrams_download,
            dropped,
            ceiling_reached,
            clienthello,
            no_sni_matched,
            ech_offered,
            handshakes,
            sni_mismatch,
            pending,
            geoip_unknown,
        } = stream;
        self.gauge(F::Active, &[id], *active);
        self.gauge(F::Pending, &[id], *pending);
        self.counter(F::Accepted, &[id], *accepted);
        for (kind, n) in ended {
            self.counter(F::Ended, &[id, kind.as_str()], *n);
        }
        for (refusal, n) in refused {
            let word: &'static str = (*refusal).into();
            self.counter(F::Refused, &[id, word], *n);
        }
        for (reason, n) in dropped {
            self.counter(F::DatagramsDropped, &[id, reason.as_str()], *n);
        }
        for &direction in Direction::VARIANTS {
            let (bytes, datagrams) = match direction {
                Direction::Upload => (bytes_upload, datagrams_upload),
                Direction::Download => (bytes_download, datagrams_download),
            };
            self.counter(F::Bytes, &[id, direction.as_str()], *bytes);
            self.counter(F::Datagrams, &[id, direction.as_str()], *datagrams);
        }
        self.counter(F::ConnectAttempts, &[id], *connect_attempts);
        self.counter(F::Retries, &[id], *retries);
        self.counter(F::BreakerDenied, &[id], *breaker_denied);
        for &skip in CandidateSkip::VARIANTS {
            let n = match skip {
                CandidateSkip::LocalDestination => local_destination_refused,
                CandidateSkip::SourceFamilyMismatch => source_family_mismatch,
                CandidateSkip::SourceBindFailed => source_bind_failed,
            };
            self.counter(F::CandidatesSkipped, &[id, skip.as_str()], *n);
        }
        for (outcome, n) in proxy_header {
            self.counter(F::ProxyHeader, &[id, outcome.as_str()], *n);
        }
        self.counter(F::CeilingReached, &[id], *ceiling_reached);
        self.counter(F::GeoipUnknown, &[id], *geoip_unknown);
        for (outcome, n) in clienthello {
            self.counter(F::ClientHello, &[id, outcome.as_str()], *n);
        }
        for (outcome, n) in handshakes {
            self.counter(F::TlsHandshakes, &[id, outcome.as_str()], *n);
        }
        self.counter(F::NoSniMatched, &[id], *no_sni_matched);
        self.counter(F::EchOffered, &[id], *ech_offered);
        self.counter(F::SniMismatch, &[id], *sni_mismatch);
    }

    fn add_link(&mut self, stream_id: &str, backend_id: &str, link: &LinkCountersSnapshot) {
        use StreamFamily as F;
        let LinkCountersSnapshot {
            active,
            connects,
            connect_failures,
            connect_latency,
            upstream_tls_failures,
        } = link;
        let ids: [&str; 2] = [stream_id, backend_id];
        self.gauge(F::BackendActive, &ids, *active);
        self.counter(F::BackendConnects, &ids, *connects);
        for (kind, n) in connect_failures {
            self.counter(
                F::BackendConnectFailures,
                &[stream_id, backend_id, kind.as_str()],
                *n,
            );
        }
        for (kind, n) in upstream_tls_failures {
            self.counter(
                F::BackendUpstreamTlsFailures,
                &[stream_id, backend_id, kind.as_str()],
                *n,
            );
        }
        self.histograms.insert(
            Series::new(F::BackendConnectSeconds, &ids),
            connect_latency.clone(),
        );
    }

    fn retain(&mut self, table: &StreamTable) {
        self.counters.retain(|s, _| s.held_by(table));
        self.gauges.retain(|s, _| s.held_by(table));
        self.histograms.retain(|s, _| s.held_by(table));
    }
}

/// Whether `new` is below `old` anywhere: the source restarted, or the
/// series was pruned and created again.
fn histogram_went_down(old: &HistogramSnapshot, new: &HistogramSnapshot) -> bool {
    new.count < old.count
        || new.sum < old.sum
        || old.le.iter().zip(&new.le).any(|(o, n)| n < o)
        || new.le.len() < old.le.len()
}

fn add_histogram(acc: &mut HistogramSnapshot, other: &HistogramSnapshot) {
    if acc.le.len() < other.le.len() {
        acc.le.resize(other.le.len(), 0);
    }
    for (a, o) in acc.le.iter_mut().zip(&other.le) {
        *a = a.saturating_add(*o);
    }
    acc.count = acc.count.saturating_add(other.count);
    acc.sum = acc.sum.saturating_add(other.sum);
}

/// Where a snapshot comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    /// The process's own counters (single process).
    Local,
    /// A worker's report, by worker id.
    Worker(u32),
}

#[derive(Debug, Default)]
struct State {
    sources: BTreeMap<Source, Flat>,
    /// What dead or restarted sources had counted, so totals never go
    /// down.
    retired_counters: BTreeMap<Series, u64>,
    retired_histograms: BTreeMap<Series, HistogramSnapshot>,
    /// The table of the last [`StreamMetricsCollector::retain`]; until
    /// one, every series is taken.
    table: Option<StreamTable>,
    node: BTreeMap<String, NodeStreamGauges>,
    local: Option<Arc<StreamCounters>>,
    bind_states: Option<StreamBindStates>,
}

impl State {
    fn held(&self, series: &Series) -> bool {
        self.table.as_ref().is_none_or(|t| series.held_by(t))
    }

    fn apply(&mut self, source: Source, snapshot: &CountersSnapshot) {
        let mut new = Flat::of(snapshot);
        if let Some(table) = &self.table {
            new.retain(table);
        }
        if let Some(old) = self.sources.remove(&source) {
            self.retire(&old, Some(&new));
        }
        self.sources.insert(source, new);
    }

    /// Fold into `retired` what `old` counted and `new` (`None`: the
    /// source is gone) no longer carries.
    fn retire(&mut self, old: &Flat, new: Option<&Flat>) {
        for (series, &value) in &old.counters {
            let now = new.and_then(|n| n.counters.get(series)).copied();
            if now.is_none_or(|n| n < value) && self.held(series) {
                let retired = self.retired_counters.entry(series.clone()).or_default();
                *retired = retired.saturating_add(value);
            }
        }
        for (series, hist) in &old.histograms {
            let now = new.and_then(|n| n.histograms.get(series));
            if now.is_none_or(|n| histogram_went_down(hist, n)) && self.held(series) {
                add_histogram(
                    self.retired_histograms.entry(series.clone()).or_default(),
                    hist,
                );
            }
        }
    }

    fn render(&self) -> BTreeMap<StreamFamily, Vec<proto::Metric>> {
        let mut out: BTreeMap<StreamFamily, Vec<proto::Metric>> = BTreeMap::new();

        let mut counters: BTreeMap<&Series, u64> =
            self.retired_counters.iter().map(|(s, v)| (s, *v)).collect();
        let mut histograms: BTreeMap<&Series, HistogramSnapshot> = self
            .retired_histograms
            .iter()
            .map(|(s, h)| (s, h.clone()))
            .collect();
        let mut gauges: BTreeMap<&Series, u64> = BTreeMap::new();
        for flat in self.sources.values() {
            for (series, value) in &flat.counters {
                let total = counters.entry(series).or_default();
                *total = total.saturating_add(*value);
            }
            for (series, hist) in &flat.histograms {
                add_histogram(histograms.entry(series).or_default(), hist);
            }
            for (series, value) in &flat.gauges {
                let total = gauges.entry(series).or_default();
                *total = total.saturating_add(*value);
            }
        }

        for (series, value) in counters {
            if let Some(labels) = self.rendered_labels(series) {
                out.entry(series.family).or_default().push(counter_metric(
                    series.family,
                    &labels,
                    value,
                ));
            }
        }
        for (series, hist) in histograms {
            if let Some(labels) = self.rendered_labels(series) {
                out.entry(series.family).or_default().push(histogram_metric(
                    series.family,
                    &labels,
                    &hist,
                ));
            }
        }

        let mut node_gauges: BTreeMap<Series, u64> = gauges
            .into_iter()
            .map(|(series, value)| (series.clone(), value))
            .collect();
        for (stream_id, node) in &self.node {
            if !self
                .table
                .as_ref()
                .is_none_or(|t| t.stream(stream_id).is_some())
            {
                continue;
            }
            if let Some(sessions) = node.udp_sessions {
                node_gauges.insert(Series::new(StreamFamily::Active, &[stream_id]), sessions);
            }
            if let Some(pending) = node.pending {
                node_gauges.insert(Series::new(StreamFamily::Pending, &[stream_id]), pending);
            }
        }
        for (series, value) in &node_gauges {
            out.entry(series.family).or_default().push(gauge_metric(
                series.family,
                &series.values,
                *value,
            ));
        }

        if let Some(table) = &self.table {
            for stream in table.streams() {
                let values = [
                    stream.id.clone(),
                    stream.name.clone(),
                    stream.protocol.as_str().to_string(),
                ];
                out.entry(StreamFamily::Info)
                    .or_default()
                    .push(gauge_metric(StreamFamily::Info, &values, 1));
            }
        }
        if let Some(states) = &self.bind_states {
            for (stream_id, state) in states.snapshot() {
                let up = u64::from(state.kind() == BindStateKind::Bound);
                out.entry(StreamFamily::ListenerUp)
                    .or_default()
                    .push(gauge_metric(StreamFamily::ListenerUp, &[stream_id], up));
            }
        }
        out
    }

    /// The label values a series renders with: a rule's name becomes its
    /// position in the stream, and a rule the table no longer knows has
    /// no series.
    fn rendered_labels(&self, series: &Series) -> Option<Vec<String>> {
        if series.family != StreamFamily::RuleMatched {
            return Some(series.values.clone());
        }
        let [stream_id, rule] = series.values.as_slice() else {
            return None;
        };
        let position = self
            .table
            .as_ref()?
            .stream(stream_id)?
            .match_rules
            .iter()
            .position(|r| r.name == *rule)?;
        Some(vec![stream_id.clone(), position.to_string()])
    }
}

fn label_pairs(family: StreamFamily, values: &[String]) -> Vec<proto::LabelPair> {
    family
        .labels()
        .iter()
        .zip(values)
        .map(|(name, value)| {
            let mut pair = proto::LabelPair::default();
            pair.set_name((*name).to_string());
            pair.set_value(value.clone());
            pair
        })
        .collect()
}

fn counter_metric(family: StreamFamily, values: &[String], value: u64) -> proto::Metric {
    let mut counter = proto::Counter::default();
    counter.set_value(value as f64);
    let mut metric = proto::Metric::from_label(label_pairs(family, values));
    metric.set_counter(counter);
    metric
}

fn gauge_metric(family: StreamFamily, values: &[String], value: u64) -> proto::Metric {
    let mut gauge = proto::Gauge::default();
    gauge.set_value(value as f64);
    let mut metric = proto::Metric::from_label(label_pairs(family, values));
    metric.set_gauge(gauge);
    metric
}

fn histogram_metric(
    family: StreamFamily,
    values: &[String],
    hist: &HistogramSnapshot,
) -> proto::Metric {
    let mut proto_hist = proto::Histogram::default();
    proto_hist.set_sample_count(hist.count);
    proto_hist.set_sample_sum(hist.sum.as_secs_f64());
    proto_hist.set_bucket(
        CONNECT_LATENCY_BUCKETS_S
            .iter()
            .zip(&hist.le)
            .map(|(bound, count)| {
                let mut bucket = proto::Bucket::default();
                bucket.set_upper_bound(*bound);
                bucket.set_cumulative_count(*count);
                bucket
            })
            .collect(),
    );
    let mut metric = proto::Metric::from_label(label_pairs(family, values));
    metric.set_histogram(proto_hist);
    metric
}

fn metric_type(family: StreamFamily) -> proto::MetricType {
    match family.family_type() {
        FamilyType::Counter => proto::MetricType::COUNTER,
        FamilyType::Gauge => proto::MetricType::GAUGE,
        FamilyType::Histogram => proto::MetricType::HISTOGRAM,
    }
}

struct Inner {
    descs: Vec<Desc>,
    state: Mutex<State>,
}

/// Renders every [`StreamFamily`] at scrape time from the node's
/// aggregate. Cloning shares it; [`stream_metrics`] is the instance the
/// process registry scrapes.
#[derive(Clone)]
pub struct StreamMetricsCollector {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for StreamMetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamMetricsCollector")
            .finish_non_exhaustive()
    }
}

impl Default for StreamMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamMetricsCollector {
    /// An empty collector, not registered anywhere.
    pub fn new() -> Self {
        let descs: Vec<Desc> = StreamFamily::VARIANTS
            .iter()
            .map(|&family| {
                let labels: Vec<String> = family.labels().iter().map(|l| l.to_string()).collect();
                match Desc::new(
                    family.qualified_name(),
                    family.help().to_string(),
                    labels,
                    HashMap::new(),
                ) {
                    Ok(desc) => desc,
                    Err(err) => panic!(
                        "stream metrics: invalid definition of {}: {err}",
                        family.qualified_name()
                    ),
                }
            })
            .collect();
        StreamMetricsCollector {
            inner: Arc::new(Inner {
                descs,
                state: Mutex::new(State::default()),
            }),
        }
    }

    /// Record worker `worker_id`'s cumulative counters, as its metrics
    /// report carries them.
    pub fn apply_worker(&self, worker_id: u32, snapshot: &CountersSnapshot) {
        self.inner
            .state
            .lock()
            .apply(Source::Worker(worker_id), snapshot);
    }

    /// Worker `worker_id` died: what it counted is retired, its gauges
    /// leave. Its replacement, under the same id, starts from zero.
    pub fn forget_worker(&self, worker_id: u32) {
        let mut state = self.inner.state.lock();
        if let Some(old) = state.sources.remove(&Source::Worker(worker_id)) {
            state.retire(&old, None);
        }
    }

    /// Single process: read `counters` at every scrape, as the only
    /// source.
    pub fn set_local_counters(&self, counters: Arc<StreamCounters>) {
        self.inner.state.lock().local = Some(counters);
    }

    /// The supervisor's bind states, read at every scrape for
    /// `lorica_stream_listener_up`.
    pub fn set_bind_states(&self, states: StreamBindStates) {
        self.inner.state.lock().bind_states = Some(states);
    }

    /// The node's exact gauges per stream id, replacing the previous set.
    pub fn set_node_gauges(&self, gauges: impl IntoIterator<Item = (String, NodeStreamGauges)>) {
        self.inner.state.lock().node = gauges.into_iter().collect();
    }

    /// The table changed: drop every series of a stream, link, backend or
    /// rule it no longer holds, and render `lorica_stream_info` from it.
    pub fn retain(&self, table: &StreamTable) {
        let mut state = self.inner.state.lock();
        for flat in state.sources.values_mut() {
            flat.retain(table);
        }
        state.retired_counters.retain(|s, _| s.held_by(table));
        state.retired_histograms.retain(|s, _| s.held_by(table));
        state.table = Some(table.clone());
    }

    /// The node's total of the counter series of `family` with
    /// `label_values` (positional to [`StreamFamily::labels`]), as the
    /// next scrape renders it: retired plus every live worker. `None`
    /// when nothing counted it. The supervisor reads
    /// `lorica_stream_ceiling_reached_total` through it to raise one
    /// alert per node (D-h).
    pub fn counter_total(&self, family: StreamFamily, label_values: &[&str]) -> Option<u64> {
        let series = Series::new(family, label_values);
        let state = self.inner.state.lock();
        let live = state
            .sources
            .values()
            .filter_map(|flat| flat.counters.get(&series));
        let mut values = state.retired_counters.get(&series).into_iter().chain(live);
        let first: u64 = *values.next()?;
        Some(values.fold(first, |acc, v| acc.saturating_add(*v)))
    }

    fn families(&self) -> Vec<proto::MetricFamily> {
        let mut state = self.inner.state.lock();
        if let Some(local) = state.local.clone() {
            state.apply(Source::Local, &local.snapshot());
        }
        let mut rendered = state.render();
        drop(state);
        StreamFamily::VARIANTS
            .iter()
            .zip(&self.inner.descs)
            .filter_map(|(family, desc)| {
                let metrics = rendered.remove(family)?;
                let mut mf = proto::MetricFamily::default();
                mf.set_name(desc.fq_name.clone());
                mf.set_help(desc.help.clone());
                mf.set_field_type(metric_type(*family));
                mf.set_metric(metrics);
                Some(mf)
            })
            .collect()
    }
}

impl Collector for StreamMetricsCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.inner.descs.iter().collect()
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        self.families()
    }
}

static STREAM_METRICS: Lazy<StreamMetricsCollector> = Lazy::new(|| {
    let collector = StreamMetricsCollector::new();
    // A second registration can only be this same collector, which is
    // then already scraped.
    let _ = lorica_metrics::registry().register(Box::new(collector.clone()));
    collector
});

/// The process's collector, registered on the process registry on first
/// use.
pub fn stream_metrics() -> &'static StreamMetricsCollector {
    &STREAM_METRICS
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use chrono::Utc;
    use lorica_config::models::{
        Backend, DatagramDropReason, Stream, StreamBackend, StreamEndKind, StreamMatchRule,
        StreamProtocol, StreamRefusal,
    };
    use lorica_metrics::prometheus::Registry;
    use lorica_stream::counters::{
        ClientHelloOutcome, ConnectFailureKind, HandshakeOutcome, ProxyHeaderOutcome,
        UpstreamTlsFailure,
    };
    use serde_json::json;

    use super::*;

    const STREAM: &str = "s-1";
    const BACKEND: &str = "b-1";
    const RULE: &str = "r-1";

    fn stream(id: &str, protocol: StreamProtocol) -> Stream {
        Stream::new(
            id.to_string(),
            format!("name of {id}"),
            protocol,
            "192.0.2.10".parse().expect("an address"),
            9000,
            9000,
            Utc::now(),
        )
    }

    /// `stream` with `no_sni` rules named `names`, in that order. The
    /// rule has no constructor; its serialised form is its contract.
    fn with_rules(mut stream: Stream, names: &[&str]) -> Stream {
        stream.match_rules = names
            .iter()
            .map(|name| {
                serde_json::from_value::<StreamMatchRule>(
                    json!({"name": name, "matcher": {"kind": "no_sni"}}),
                )
                .expect("a rule")
            })
            .collect();
        stream
    }

    /// A backend row from its required fields only. `Backend` has no
    /// constructor; its serialised form fills every defaulted field.
    fn backend_row(id: &str) -> Backend {
        serde_json::from_value(json!({
            "id": id,
            "address": "192.0.2.20:9000",
            "weight": 1,
            "health_status": "unknown",
            "health_check_enabled": false,
            "health_check_interval_s": 10,
            "lifecycle_state": "normal",
            "active_connections": 0,
            "tls_upstream": false,
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
        }))
        .expect("a backend row")
    }

    fn table(streams: Vec<Stream>, links: &[(&str, &str)]) -> StreamTable {
        let links: Vec<StreamBackend> = links
            .iter()
            .map(|(stream, backend)| StreamBackend::primary(stream, backend))
            .collect();
        let backends: Vec<Backend> = links.iter().map(|l| backend_row(&l.backend_id)).collect();
        StreamTable::with_backends(streams, &links, backends)
    }

    /// Counters with every word of every keyed enum counted once on
    /// [`STREAM`], its link to [`BACKEND`], the backend and [`RULE`].
    fn every_word() -> StreamCounters {
        let counters = StreamCounters::new();
        let stats = counters.stream(STREAM);
        drop(stats.accept());
        for &kind in StreamEndKind::VARIANTS {
            stats.ended(kind);
        }
        for &refusal in StreamRefusal::VARIANTS {
            stats.refused(refusal);
        }
        for &reason in DatagramDropReason::VARIANTS {
            stats.dropped(reason);
        }
        for outcome in ProxyHeaderOutcome::ALL {
            stats.proxy_header(outcome);
        }
        for outcome in ClientHelloOutcome::ALL {
            stats.clienthello(outcome);
        }
        for outcome in HandshakeOutcome::ALL {
            stats.handshake(outcome);
        }
        stats.datagram_upload(40);
        stats.datagram_download(400);
        let link = counters.link(STREAM, BACKEND);
        for kind in ConnectFailureKind::ALL {
            link.connect_failed(kind);
        }
        for kind in UpstreamTlsFailure::ALL {
            link.upstream_tls_failed(kind);
        }
        drop(link.connected(Duration::from_millis(3)));
        counters.backend(BACKEND).dns_failure();
        counters.rule(STREAM, RULE).matched();
        counters
    }

    fn labels_of(metric: &proto::Metric) -> BTreeMap<String, String> {
        metric
            .get_label()
            .iter()
            .map(|pair| (pair.name().to_string(), pair.value().to_string()))
            .collect()
    }

    /// The value of the `family` series carrying every pair of `labels`:
    /// a counter's or gauge's value, a histogram's count.
    fn sample(
        collector: &StreamMetricsCollector,
        family: StreamFamily,
        labels: &[(&str, &str)],
    ) -> Option<f64> {
        collector
            .collect()
            .into_iter()
            .find(|mf| mf.name() == family.qualified_name())?
            .get_metric()
            .iter()
            .find(|m| {
                let have = labels_of(m);
                labels
                    .iter()
                    .all(|(k, v)| have.get(*k).map(String::as_str) == Some(*v))
            })
            .map(|m| match family.family_type() {
                FamilyType::Counter => m.get_counter().value(),
                FamilyType::Gauge => m.get_gauge().value(),
                FamilyType::Histogram => m.get_histogram().get_sample_count() as f64,
            })
    }

    fn accepted(n: u64) -> CountersSnapshot {
        let counters = StreamCounters::new();
        for _ in 0..n {
            drop(counters.stream(STREAM).accept());
        }
        counters.snapshot()
    }

    #[test]
    fn every_word_of_every_keyed_enum_is_a_label_value() {
        let collector = StreamMetricsCollector::new();
        collector.apply_worker(1, &every_word().snapshot());
        let at = |family: StreamFamily, label: &str, word: &str| {
            let mut labels = vec![("stream_id", STREAM), (label, word)];
            if family.labels().contains(&"backend_id") {
                labels.push(("backend_id", BACKEND));
            }
            assert!(
                sample(&collector, family, &labels).is_some(),
                "{} has no {label}={word}",
                family.qualified_name()
            );
        };
        for kind in StreamEndKind::VARIANTS {
            at(StreamFamily::Ended, "reason", kind.as_str());
        }
        for &refusal in StreamRefusal::VARIANTS {
            at(StreamFamily::Refused, "reason", refusal.into());
        }
        for reason in DatagramDropReason::VARIANTS {
            at(StreamFamily::DatagramsDropped, "reason", reason.as_str());
        }
        for skip in CandidateSkip::VARIANTS {
            at(StreamFamily::CandidatesSkipped, "reason", skip.as_str());
        }
        for direction in Direction::VARIANTS {
            at(StreamFamily::Bytes, "direction", direction.as_str());
            at(StreamFamily::Datagrams, "direction", direction.as_str());
        }
        for outcome in ProxyHeaderOutcome::ALL {
            at(StreamFamily::ProxyHeader, "outcome", outcome.as_str());
        }
        for outcome in ClientHelloOutcome::ALL {
            at(StreamFamily::ClientHello, "outcome", outcome.as_str());
        }
        for outcome in HandshakeOutcome::ALL {
            at(StreamFamily::TlsHandshakes, "outcome", outcome.as_str());
        }
        for kind in ConnectFailureKind::ALL {
            at(StreamFamily::BackendConnectFailures, "kind", kind.as_str());
        }
        for kind in UpstreamTlsFailure::ALL {
            at(
                StreamFamily::BackendUpstreamTlsFailures,
                "kind",
                kind.as_str(),
            );
        }
        assert_eq!(
            sample(
                &collector,
                StreamFamily::Bytes,
                &[
                    ("stream_id", STREAM),
                    ("direction", Direction::Download.as_str())
                ]
            ),
            Some(400.0)
        );
    }

    /// Every family renders through a registry, with exactly its label
    /// names, and none of them is anything a client chooses.
    #[test]
    fn every_family_renders_with_its_labels_and_no_client_chosen_one() {
        let collector = StreamMetricsCollector::new();
        collector.retain(&table(
            vec![with_rules(
                stream(STREAM, StreamProtocol::Tcp),
                &["other", RULE],
            )],
            &[(STREAM, BACKEND)],
        ));
        let states = StreamBindStates::new();
        states.set_bound(STREAM, 2, 2);
        collector.set_bind_states(states);
        collector.apply_worker(1, &every_word().snapshot());
        let registry = Registry::new();
        registry
            .register(Box::new(collector.clone()))
            .expect("the collector registers");

        let gathered = registry.gather();
        for family in StreamFamily::VARIANTS {
            let mf = gathered
                .iter()
                .find(|mf| mf.name() == family.qualified_name())
                .unwrap_or_else(|| panic!("{} is not rendered", family.qualified_name()));
            for metric in mf.get_metric() {
                let names: Vec<String> = labels_of(metric).into_keys().collect();
                let expected: BTreeSet<&str> = family.labels().iter().copied().collect();
                assert_eq!(
                    names.iter().map(String::as_str).collect::<BTreeSet<_>>(),
                    expected,
                    "{}",
                    mf.name()
                );
                for name in &names {
                    for forbidden in ["client", "sni", "alpn", "port", "address"] {
                        assert!(!name.contains(forbidden), "{} carries {name}", mf.name());
                    }
                }
            }
        }
        assert_eq!(
            sample(
                &collector,
                StreamFamily::RuleMatched,
                &[("stream_id", STREAM), ("rule", "1")]
            ),
            Some(1.0),
            "a rule is labelled by its position, not its name"
        );
        assert_eq!(
            sample(
                &collector,
                StreamFamily::Info,
                &[
                    ("stream_id", STREAM),
                    ("stream_name", "name of s-1"),
                    ("protocol", "tcp")
                ]
            ),
            Some(1.0)
        );
        assert_eq!(
            sample(
                &collector,
                StreamFamily::ListenerUp,
                &[("stream_id", STREAM)]
            ),
            Some(1.0)
        );
    }

    #[test]
    fn a_worker_restart_or_death_never_makes_a_counter_go_down() {
        let collector = StreamMetricsCollector::new();
        let total = || sample(&collector, StreamFamily::Accepted, &[("stream_id", STREAM)]);
        collector.apply_worker(1, &accepted(5));
        collector.apply_worker(2, &accepted(3));
        assert_eq!(total(), Some(8.0), "the workers sum");

        collector.apply_worker(1, &accepted(2));
        assert_eq!(total(), Some(10.0), "a restart seen as a drop is retired");

        collector.forget_worker(1);
        assert_eq!(total(), Some(10.0), "a dead worker's count stays");
        collector.apply_worker(1, &accepted(1));
        assert_eq!(total(), Some(11.0), "its replacement starts from zero");

        collector.apply_worker(2, &CountersSnapshot::default());
        assert_eq!(
            total(),
            Some(11.0),
            "a series that leaves a snapshot is retired"
        );
        assert_eq!(
            collector.counter_total(StreamFamily::Accepted, &[STREAM]),
            Some(11),
            "the read the alerts use is the scrape's"
        );
        assert_eq!(
            collector.counter_total(StreamFamily::Accepted, &["s-9"]),
            None
        );
    }

    #[test]
    fn histogram_buckets_sum_across_workers_and_survive_a_restart() {
        let observe = |millis: &[u64]| {
            let counters = StreamCounters::new();
            for ms in millis {
                drop(
                    counters
                        .link(STREAM, BACKEND)
                        .connected(Duration::from_millis(*ms)),
                );
            }
            counters.snapshot()
        };
        let collector = StreamMetricsCollector::new();
        collector.apply_worker(1, &observe(&[3]));
        collector.apply_worker(2, &observe(&[3, 700]));
        collector.apply_worker(1, &observe(&[]));

        let family = collector
            .collect()
            .into_iter()
            .find(|mf| mf.name() == StreamFamily::BackendConnectSeconds.qualified_name())
            .expect("the histogram renders");
        let hist = family.get_metric()[0].get_histogram();
        assert_eq!(hist.get_sample_count(), 3);
        assert!((hist.get_sample_sum() - 0.706).abs() < 1e-9);
        let buckets: Vec<(f64, u64)> = hist
            .get_bucket()
            .iter()
            .map(|b| (b.upper_bound(), b.cumulative_count()))
            .collect();
        assert_eq!(buckets.len(), CONNECT_LATENCY_BUCKETS_S.len());
        for (bound, count) in buckets {
            let expected = [0.003, 0.003, 0.7]
                .iter()
                .filter(|seconds| **seconds <= bound)
                .count() as u64;
            assert_eq!(count, expected, "le={bound}");
        }
    }

    #[test]
    fn gauges_sum_live_workers_leave_with_a_dead_one_and_yield_to_the_node() {
        let counters_1 = StreamCounters::new();
        let _held_1 = [
            counters_1.stream(STREAM).accept(),
            counters_1.stream(STREAM).accept(),
        ];
        let counters_2 = StreamCounters::new();
        let _held_2 = counters_2.stream(STREAM).accept();
        let collector = StreamMetricsCollector::new();
        let active = || sample(&collector, StreamFamily::Active, &[("stream_id", STREAM)]);
        collector.apply_worker(1, &counters_1.snapshot());
        collector.apply_worker(2, &counters_2.snapshot());
        assert_eq!(active(), Some(3.0));
        collector.forget_worker(2);
        assert_eq!(
            active(),
            Some(2.0),
            "a dead worker's connections died with it"
        );

        collector.set_node_gauges([(STREAM.to_string(), NodeStreamGauges::udp(7, 1))]);
        assert_eq!(active(), Some(7.0), "the region's exact count wins");
        assert_eq!(
            sample(&collector, StreamFamily::Pending, &[("stream_id", STREAM)]),
            Some(1.0)
        );
        collector.set_node_gauges([(STREAM.to_string(), NodeStreamGauges::tcp(0))]);
        assert_eq!(
            active(),
            Some(2.0),
            "a TCP stream's active is the workers' sum"
        );
    }

    #[test]
    fn a_removed_stream_link_or_rule_loses_every_series() {
        const GONE: &str = "s-2";
        const UNLINKED: &str = "b-2";
        let counters = every_word();
        counters.stream(GONE).ended(StreamEndKind::IdleTimeout);
        drop(counters.link(STREAM, UNLINKED).session_opened());
        let collector = StreamMetricsCollector::new();
        collector.apply_worker(1, &counters.snapshot());
        collector.forget_worker(1);
        collector.apply_worker(2, &counters.snapshot());

        collector.retain(&table(
            vec![stream(STREAM, StreamProtocol::Tcp)],
            &[(STREAM, BACKEND)],
        ));
        // The worker has not seen the change yet: its late report must not
        // bring the series back.
        collector.apply_worker(2, &counters.snapshot());

        let rendered = collector.collect();
        let series: Vec<BTreeMap<String, String>> = rendered
            .iter()
            .flat_map(|mf| mf.get_metric().iter().map(labels_of))
            .collect();
        assert!(!series.is_empty());
        for labels in &series {
            assert_ne!(labels.get("stream_id").map(String::as_str), Some(GONE));
            assert_ne!(labels.get("backend_id").map(String::as_str), Some(UNLINKED));
        }
        assert!(
            sample(
                &collector,
                StreamFamily::RuleMatched,
                &[("stream_id", STREAM)]
            )
            .is_none(),
            "the rule left the stream"
        );
        assert_eq!(
            sample(
                &collector,
                StreamFamily::Ended,
                &[
                    ("stream_id", STREAM),
                    ("reason", StreamEndKind::IdleTimeout.as_str())
                ]
            ),
            Some(2.0),
            "what the stream kept is still the retired plus the live count"
        );
    }

    #[test]
    fn a_single_process_is_read_at_every_scrape() {
        let counters = Arc::new(StreamCounters::new());
        let collector = StreamMetricsCollector::new();
        collector.set_local_counters(Arc::clone(&counters));
        let total = || sample(&collector, StreamFamily::Accepted, &[("stream_id", STREAM)]);
        assert_eq!(total(), None);
        drop(counters.stream(STREAM).accept());
        assert_eq!(total(), Some(1.0));
        drop(counters.stream(STREAM).accept());
        assert_eq!(total(), Some(2.0));
    }

    #[test]
    fn the_listener_gauge_follows_the_bind_state() {
        let states = StreamBindStates::new();
        let collector = StreamMetricsCollector::new();
        collector.set_bind_states(states.clone());
        let up = || {
            sample(
                &collector,
                StreamFamily::ListenerUp,
                &[("stream_id", STREAM)],
            )
        };
        states.set_pending(STREAM);
        assert_eq!(up(), Some(0.0));
        states.set_bound(STREAM, 1, 1);
        assert_eq!(up(), Some(1.0));
        states.remove(STREAM);
        assert_eq!(up(), None);
    }

    #[test]
    fn the_process_collector_is_scraped_by_the_process_registry() {
        let names: BTreeSet<String> = StreamFamily::VARIANTS
            .iter()
            .map(|family| family.qualified_name())
            .collect();
        assert_eq!(
            names.len(),
            StreamFamily::VARIANTS.len(),
            "names are unique"
        );
        assert!(stream_metrics()
            .desc()
            .iter()
            .all(|desc| names.contains(&desc.fq_name)));
        assert!(
            lorica_metrics::registry()
                .register(Box::new(stream_metrics().clone()))
                .is_err(),
            "already registered"
        );
    }
}
