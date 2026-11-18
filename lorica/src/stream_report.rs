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

//! A worker's stream counters across the process boundary (Story 12.9
//! D-e): [`CountersSnapshot`] to the metrics report's
//! [`StreamCountersReport`] and back, plus the worker's handle on its
//! own counters.
//!
//! The wire type keys every family by its enum's word, so
//! `lorica-command` needs no dependency on the engines. The words come
//! from each enum's own list (`ALL` or `VARIANTS`); a word the decoder
//! does not know is skipped, which only a report from another binary
//! could carry, and worker and supervisor are always the same binary.

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use lorica_api::stream_metrics::StreamMetricsCollector;
use lorica_command::{
    StreamBackendCountersEntry, StreamCountersEntry, StreamCountersReport, StreamLinkCountersEntry,
    StreamRuleCountersEntry,
};
use lorica_config::models::{DatagramDropReason, StreamEndKind, StreamRefusal};
use lorica_stream::counters::{
    BackendCountersSnapshot, ClientHelloOutcome, ConnectFailureKind, HandshakeOutcome,
    HistogramSnapshot, LinkCountersSnapshot, ProxyHeaderOutcome, RuleCountersSnapshot,
    StreamCountersSnapshot, UpstreamTlsFailure,
};
use lorica_stream::{CountersSnapshot, StreamCounters};
use strum::VariantArray;

/// The worker's stream counters, installed once by its startup.
static WORKER_COUNTERS: OnceLock<Arc<StreamCounters>> = OnceLock::new();

/// Install the counters this worker's metrics reports carry: the
/// `Arc` its stream engines count into. A second call keeps the first,
/// a worker having one stream runtime.
pub fn install_worker_counters(counters: Arc<StreamCounters>) {
    let _ = WORKER_COUNTERS.set(counters);
}

/// The installed counters as they stand, for a metrics report; `None`
/// in a process that installed none (the supervisor, single-process
/// mode, a test).
pub fn worker_report() -> Option<StreamCountersReport> {
    WORKER_COUNTERS
        .get()
        .map(|counters| report_of(&counters.snapshot()))
}

/// Apply the stream counters of worker `worker_id`'s report to
/// `collector`, the supervisor's. A report without them changes
/// nothing.
pub fn apply_worker_report(
    collector: &StreamMetricsCollector,
    worker_id: u32,
    report: &lorica_command::MetricsReport,
) {
    if let Some(counters) = &report.stream_counters {
        collector.apply_worker(worker_id, &snapshot_of(counters));
    }
}

fn words<K: Copy>(
    map: &HashMap<K, u64>,
    word: impl Fn(K) -> &'static str,
) -> BTreeMap<String, u64> {
    map.iter()
        .map(|(k, v)| (word(*k).to_string(), *v))
        .collect()
}

fn keys<K: Copy + Eq + Hash>(
    map: &BTreeMap<String, u64>,
    all: &[K],
    word: impl Fn(K) -> &'static str,
) -> HashMap<K, u64> {
    map.iter()
        .filter_map(|(w, v)| all.iter().find(|k| word(**k) == w).map(|k| (*k, *v)))
        .collect()
}

fn end_word(kind: StreamEndKind) -> &'static str {
    kind.as_str()
}

fn refusal_word(refusal: StreamRefusal) -> &'static str {
    refusal.into()
}

fn drop_word(reason: DatagramDropReason) -> &'static str {
    reason.as_str()
}

/// The wire form of `snapshot`.
pub fn report_of(snapshot: &CountersSnapshot) -> StreamCountersReport {
    StreamCountersReport {
        streams: snapshot
            .streams
            .iter()
            .map(|(id, s)| stream_entry(id, s))
            .collect(),
        links: snapshot
            .links
            .iter()
            .map(|((stream_id, backend_id), l)| link_entry(stream_id, backend_id, l))
            .collect(),
        backends: snapshot
            .backends
            .iter()
            .map(|(id, b)| StreamBackendCountersEntry {
                backend_id: id.clone(),
                dns_failures: b.dns_failures,
                dns_local_excluded: b.dns_local_excluded,
            })
            .collect(),
        rules: snapshot
            .rules
            .iter()
            .map(|((stream_id, rule), r)| StreamRuleCountersEntry {
                stream_id: stream_id.clone(),
                rule: rule.clone(),
                matched: r.matched,
            })
            .collect(),
    }
}

fn stream_entry(id: &str, s: &StreamCountersSnapshot) -> StreamCountersEntry {
    // Destructured whole, so a field the snapshot gains does not compile
    // until the report carries it.
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
    } = s;
    StreamCountersEntry {
        stream_id: id.to_string(),
        active: *active,
        accepted: *accepted,
        ended: words(ended, end_word),
        refused: words(refused, refusal_word),
        bytes_upload: *bytes_upload,
        bytes_download: *bytes_download,
        connect_attempts: *connect_attempts,
        retries: *retries,
        breaker_denied: *breaker_denied,
        proxy_header: words(proxy_header, |o| o.as_str()),
        local_destination_refused: *local_destination_refused,
        source_family_mismatch: *source_family_mismatch,
        source_bind_failed: *source_bind_failed,
        datagrams_upload: *datagrams_upload,
        datagrams_download: *datagrams_download,
        dropped: words(dropped, drop_word),
        ceiling_reached: *ceiling_reached,
        clienthello: words(clienthello, |o| o.as_str()),
        no_sni_matched: *no_sni_matched,
        ech_offered: *ech_offered,
        handshakes: words(handshakes, |o| o.as_str()),
        sni_mismatch: *sni_mismatch,
        pending: *pending,
        geoip_unknown: *geoip_unknown,
    }
}

fn link_entry(
    stream_id: &str,
    backend_id: &str,
    l: &LinkCountersSnapshot,
) -> StreamLinkCountersEntry {
    let LinkCountersSnapshot {
        active,
        connects,
        connect_failures,
        connect_latency,
        upstream_tls_failures,
        bytes_upload,
        bytes_download,
    } = l;
    StreamLinkCountersEntry {
        stream_id: stream_id.to_string(),
        backend_id: backend_id.to_string(),
        active: *active,
        connects: *connects,
        connect_failures: words(connect_failures, |k| k.as_str()),
        latency_le: connect_latency.le.clone(),
        latency_count: connect_latency.count,
        latency_sum_ns: u64::try_from(connect_latency.sum.as_nanos()).unwrap_or(u64::MAX),
        upstream_tls_failures: words(upstream_tls_failures, |k| k.as_str()),
        bytes_upload: *bytes_upload,
        bytes_download: *bytes_download,
    }
}

/// The snapshot `report` carries.
pub fn snapshot_of(report: &StreamCountersReport) -> CountersSnapshot {
    CountersSnapshot {
        streams: report
            .streams
            .iter()
            .map(|s| (s.stream_id.clone(), stream_snapshot(s)))
            .collect(),
        links: report
            .links
            .iter()
            .map(|l| {
                (
                    (l.stream_id.clone(), l.backend_id.clone()),
                    LinkCountersSnapshot {
                        active: l.active,
                        connects: l.connects,
                        connect_failures: keys(
                            &l.connect_failures,
                            &ConnectFailureKind::ALL,
                            |k| k.as_str(),
                        ),
                        connect_latency: HistogramSnapshot {
                            le: l.latency_le.clone(),
                            count: l.latency_count,
                            sum: Duration::from_nanos(l.latency_sum_ns),
                        },
                        upstream_tls_failures: keys(
                            &l.upstream_tls_failures,
                            &UpstreamTlsFailure::ALL,
                            |k| k.as_str(),
                        ),
                        bytes_upload: l.bytes_upload,
                        bytes_download: l.bytes_download,
                    },
                )
            })
            .collect(),
        backends: report
            .backends
            .iter()
            .map(|b| {
                (
                    b.backend_id.clone(),
                    BackendCountersSnapshot {
                        dns_failures: b.dns_failures,
                        dns_local_excluded: b.dns_local_excluded,
                    },
                )
            })
            .collect(),
        rules: report
            .rules
            .iter()
            .map(|r| {
                (
                    (r.stream_id.clone(), r.rule.clone()),
                    RuleCountersSnapshot { matched: r.matched },
                )
            })
            .collect(),
    }
}

fn stream_snapshot(s: &StreamCountersEntry) -> StreamCountersSnapshot {
    StreamCountersSnapshot {
        active: s.active,
        accepted: s.accepted,
        ended: keys(&s.ended, StreamEndKind::VARIANTS, end_word),
        refused: keys(&s.refused, StreamRefusal::VARIANTS, refusal_word),
        bytes_upload: s.bytes_upload,
        bytes_download: s.bytes_download,
        connect_attempts: s.connect_attempts,
        retries: s.retries,
        breaker_denied: s.breaker_denied,
        proxy_header: keys(&s.proxy_header, &ProxyHeaderOutcome::ALL, |o| o.as_str()),
        local_destination_refused: s.local_destination_refused,
        source_family_mismatch: s.source_family_mismatch,
        source_bind_failed: s.source_bind_failed,
        datagrams_upload: s.datagrams_upload,
        datagrams_download: s.datagrams_download,
        dropped: keys(&s.dropped, DatagramDropReason::VARIANTS, drop_word),
        ceiling_reached: s.ceiling_reached,
        clienthello: keys(&s.clienthello, &ClientHelloOutcome::ALL, |o| o.as_str()),
        no_sni_matched: s.no_sni_matched,
        ech_offered: s.ech_offered,
        handshakes: keys(&s.handshakes, &HandshakeOutcome::ALL, |o| o.as_str()),
        sni_mismatch: s.sni_mismatch,
        pending: s.pending,
        geoip_unknown: s.geoip_unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_api::stream_metrics::StreamFamily;

    /// Every family filled with every word its enum has, each count
    /// distinct.
    fn every_word<K: Copy + Eq + Hash>(all: &[K], base: u64) -> HashMap<K, u64> {
        all.iter()
            .enumerate()
            .map(|(i, k)| (*k, base + i as u64))
            .collect()
    }

    fn full_snapshot() -> CountersSnapshot {
        let stream = StreamCountersSnapshot {
            active: 1,
            accepted: 2,
            ended: every_word(StreamEndKind::VARIANTS, 100),
            refused: every_word(StreamRefusal::VARIANTS, 200),
            bytes_upload: 3,
            bytes_download: 4,
            connect_attempts: 5,
            retries: 6,
            breaker_denied: 7,
            proxy_header: every_word(&ProxyHeaderOutcome::ALL, 300),
            local_destination_refused: 8,
            source_family_mismatch: 9,
            source_bind_failed: 10,
            datagrams_upload: 11,
            datagrams_download: 12,
            dropped: every_word(DatagramDropReason::VARIANTS, 400),
            ceiling_reached: 13,
            clienthello: every_word(&ClientHelloOutcome::ALL, 500),
            no_sni_matched: 14,
            ech_offered: 15,
            handshakes: every_word(&HandshakeOutcome::ALL, 600),
            sni_mismatch: 16,
            pending: 17,
            geoip_unknown: 18,
        };
        let link = LinkCountersSnapshot {
            active: 19,
            connects: 20,
            connect_failures: every_word(&ConnectFailureKind::ALL, 700),
            connect_latency: HistogramSnapshot {
                le: (0..lorica_stream::counters::CONNECT_LATENCY_BUCKETS_S.len() as u64)
                    .map(|i| 800 + i)
                    .collect(),
                count: 21,
                sum: Duration::from_micros(22_333),
            },
            upstream_tls_failures: every_word(&UpstreamTlsFailure::ALL, 900),
            bytes_upload: 23,
            bytes_download: 24,
        };
        CountersSnapshot {
            streams: [("s1".to_string(), stream)].into(),
            links: [(("s1".to_string(), "b1".to_string()), link)].into(),
            backends: [(
                "b1".to_string(),
                BackendCountersSnapshot {
                    dns_failures: 25,
                    dns_local_excluded: 26,
                },
            )]
            .into(),
            rules: [(
                ("s1".to_string(), "r1".to_string()),
                RuleCountersSnapshot { matched: 27 },
            )]
            .into(),
        }
    }

    /// The wire encoding of the report itself is `lorica-command`'s test;
    /// this one proves no word or value is lost on the way in and out.
    #[test]
    fn a_snapshot_with_every_word_survives_the_report() {
        let snapshot = full_snapshot();
        assert_eq!(snapshot_of(&report_of(&snapshot)), snapshot);
    }

    #[test]
    fn two_workers_reports_sum_in_the_supervisor_collector() {
        let collector = StreamMetricsCollector::new();
        for worker in [1, 2] {
            let mut report = lorica_command::MetricsReport::new(worker, 0, 0);
            report.stream_counters = Some(Box::new(report_of(&full_snapshot())));
            apply_worker_report(&collector, worker, &report);
        }
        apply_worker_report(&collector, 3, &lorica_command::MetricsReport::new(3, 0, 0));
        assert_eq!(
            collector.counter_total(StreamFamily::CeilingReached, &["s1"]),
            Some(26)
        );
        assert_eq!(
            collector.counter_total(StreamFamily::Accepted, &["s1"]),
            Some(4)
        );
    }

    #[test]
    fn an_unknown_word_is_skipped_and_the_rest_kept() {
        let mut report = report_of(&full_snapshot());
        report.streams[0]
            .ended
            .insert("a_word_no_enum_has".to_string(), 1);
        let decoded = snapshot_of(&report);
        assert_eq!(decoded, full_snapshot());
    }
}
