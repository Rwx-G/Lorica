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

//! The stream SLA collector (Story 12.9 D-g): the sibling of
//! [`super::SlaCollector`] for TCP and UDP streams.
//!
//! A stream SLA judges connections, not bytes, and judges each one when
//! its connect phase resolves rather than when it ends: a TCP connection
//! can last hours, and judging it at its end would put its availability
//! in the wrong minute. The one exception is a UDP session that owes no
//! response, whose only verdict is known at its end. The engine reports
//! that moment, the binary turns it into a [`StreamSlaOutcome`] and
//! hands it to
//! [`StreamSlaCollector::record`], which only touches an in-memory map.
//! Completed minutes are merged into `stream_sla_buckets` by the flush
//! task with the store's additive merge, so the slices every process
//! writes for one minute sum.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use lorica_config::models::{StreamSlaBucket, StreamSlaConfig};
use lorica_config::ConfigStore;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::NotifyDispatcher;
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};

use super::helpers::{compute_percentiles, current_bucket_start};

/// The `source` of every bucket this collector writes: observed traffic.
const PASSIVE_SOURCE: &str = "passive";

/// The judged outcome of one stream connection or UDP session, as the
/// engine reports it. Each connection or session is reported once, so
/// each variant is one judged connection.
///
/// The TCP variants are reported once a connection reaches backend
/// selection: a refusal or any other end before it never reaches the
/// collector, since it says nothing about the backends.
///
/// A UDP stream is reported one of two ways, by what it owes its
/// clients. A stream that owes responses (`responses_per_request >= 1`,
/// responses bounded: the engine's `expects_responses`) reports the
/// breaker outcome of Story 12.5 (D-i), where the engine reports it to
/// the breaker: [`Self::UdpAnswered`], [`Self::UdpIcmpError`] or
/// [`Self::UdpNoResponse`]. A stream that owes none (syslog, NetFlow)
/// reports [`Self::UdpUnansweredEnded`] when the session ends, and
/// nothing else: silence is its normal answer, so the decision waits
/// for the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSlaOutcome {
    /// The connection connected to a backend `connect_latency_ms` after
    /// it was accepted, retries included: what the client waited.
    TcpConnected {
        /// Accepted-to-connected of the attempt that connected (ms).
        connect_latency_ms: u64,
    },
    /// The connection ended `connect_failed` or `no_healthy_backend`.
    TcpNotConnected,
    /// A session of a stream that owes responses received its first
    /// backend datagram.
    UdpAnswered,
    /// A session of a stream that owes responses met an ICMP error from
    /// the backend before any datagram.
    UdpIcmpError,
    /// A session of a stream that owes responses went idle without a
    /// backend datagram.
    UdpNoResponse,
    /// A session of a stream that owes no response ended.
    UdpUnansweredEnded {
        /// Whether the session ended on an ICMP error from the backend
        /// (`connect_failed`): the one failure such a session can show.
        icmp_error: bool,
    },
}

/// The verdict on one judged outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Judgement {
    success: bool,
    /// The connect latency sample, for a connection that connected.
    connect_latency_ms: Option<u64>,
}

impl StreamSlaOutcome {
    /// The verdict under `config`.
    fn judge(self, config: &StreamSlaConfig) -> Judgement {
        let verdict = |success: bool| Judgement {
            success,
            connect_latency_ms: None,
        };
        match self {
            StreamSlaOutcome::TcpConnected { connect_latency_ms } => Judgement {
                success: config.connect_within_bound(connect_latency_ms),
                connect_latency_ms: Some(connect_latency_ms),
            },
            StreamSlaOutcome::TcpNotConnected
            | StreamSlaOutcome::UdpIcmpError
            | StreamSlaOutcome::UdpNoResponse => verdict(false),
            StreamSlaOutcome::UdpAnswered => verdict(true),
            StreamSlaOutcome::UdpUnansweredEnded { icmp_error } => verdict(!icmp_error),
        }
    }
}

/// One stream's judged outcomes over one minute, in this process.
#[derive(Debug, Default)]
struct StreamMinute {
    judged: i64,
    success: i64,
    failure: i64,
    /// Connect latencies of the connections that connected (ms).
    connect_latencies_ms: Vec<u64>,
}

impl StreamMinute {
    fn add(&mut self, judgement: Judgement) {
        self.judged += 1;
        if judgement.success {
            self.success += 1;
        } else {
            self.failure += 1;
        }
        if let Some(latency) = judgement.connect_latency_ms {
            self.connect_latencies_ms.push(latency);
        }
    }

    /// This minute as a bucket slice snapshotting `config`. The latency
    /// columns stay `None` when nothing connected.
    fn into_bucket(
        mut self,
        config: &StreamSlaConfig,
        bucket_start: DateTime<Utc>,
    ) -> StreamSlaBucket {
        let mut bucket = StreamSlaBucket::empty(config, bucket_start, PASSIVE_SOURCE);
        bucket.judged_count = self.judged;
        bucket.success_count = self.success;
        bucket.failure_count = self.failure;
        bucket.connected_count = to_i64(self.connect_latencies_ms.len() as u64);
        if let (Some(&min), Some(&max)) = (
            self.connect_latencies_ms.iter().min(),
            self.connect_latencies_ms.iter().max(),
        ) {
            let sum = self
                .connect_latencies_ms
                .iter()
                .fold(0u64, |sum, &ms| sum.saturating_add(ms));
            let (p50, p95, p99) = compute_percentiles(&mut self.connect_latencies_ms);
            bucket.connect_latency_sum_ms = Some(to_i64(sum));
            bucket.connect_latency_min_ms = Some(to_i64(min));
            bucket.connect_latency_max_ms = Some(to_i64(max));
            bucket.connect_latency_p50_ms = Some(p50);
            bucket.connect_latency_p95_ms = Some(p95);
            bucket.connect_latency_p99_ms = Some(p99);
        }
        bucket
    }
}

fn to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// SLA collector for stream traffic, one per process.
///
/// Unlike the route collector, a minute stays in memory until a flush
/// takes it, even when the next minute has started: a minute is keyed
/// by its start, never overwritten.
pub struct StreamSlaCollector {
    /// Judged outcomes not flushed yet, per (stream id, minute start).
    minutes: Mutex<HashMap<(String, DateTime<Utc>), StreamMinute>>,
    /// The SLA target of each stream that has a stored one; a stream
    /// without one is judged on [`StreamSlaConfig::default_for_stream`].
    sla_configs: Mutex<HashMap<String, StreamSlaConfig>>,
    /// Per-stream breach state for edge-triggered notifications: `true`
    /// while the stream is in breach.
    breach_state: Mutex<HashMap<String, bool>>,
}

impl StreamSlaCollector {
    /// An empty collector with no cached SLA target.
    pub fn new() -> Self {
        Self {
            minutes: Mutex::new(HashMap::new()),
            sla_configs: Mutex::new(HashMap::new()),
            breach_state: Mutex::new(HashMap::new()),
        }
    }

    /// Record the judged outcome of one connection or session of
    /// `stream_id`, in the current minute.
    ///
    /// Called on the stream runtime: it touches an in-memory map under a
    /// brief lock, never the store.
    pub fn record(&self, stream_id: &str, outcome: StreamSlaOutcome) {
        self.record_at(stream_id, outcome, current_bucket_start());
    }

    fn record_at(&self, stream_id: &str, outcome: StreamSlaOutcome, minute: DateTime<Utc>) {
        let judgement = self.judge(stream_id, outcome);
        if let Ok(mut minutes) = self.minutes.lock() {
            minutes
                .entry((stream_id.to_string(), minute))
                .or_default()
                .add(judgement);
        }
    }

    /// Drop the unflushed outcomes of a stream (after its stored SLA
    /// data was cleared).
    pub fn clear_stream(&self, stream_id: &str) {
        if let Ok(mut minutes) = self.minutes.lock() {
            minutes.retain(|(id, _), _| id != stream_id);
        }
    }

    /// Update the cached SLA target of a stream.
    pub fn set_sla_config(&self, config: StreamSlaConfig) {
        if let Ok(mut configs) = self.sla_configs.lock() {
            configs.insert(config.stream_id.clone(), config);
        }
    }

    /// Replace the cached SLA targets with the ones the store holds.
    pub fn load_configs(&self, store: &ConfigStore) {
        match store.list_stream_sla_configs() {
            Ok(configs) => {
                if let Ok(mut cache) = self.sla_configs.lock() {
                    *cache = configs
                        .into_iter()
                        .map(|c| (c.stream_id.clone(), c))
                        .collect();
                }
            }
            Err(e) => warn!(error = %e, "failed to load stream SLA configs"),
        }
    }

    fn judge(&self, stream_id: &str, outcome: StreamSlaOutcome) -> Judgement {
        if let Ok(configs) = self.sla_configs.lock() {
            if let Some(config) = configs.get(stream_id) {
                return outcome.judge(config);
            }
        }
        outcome.judge(&StreamSlaConfig::default_for_stream(stream_id))
    }

    fn config_for(&self, stream_id: &str) -> StreamSlaConfig {
        self.sla_configs
            .lock()
            .ok()
            .and_then(|configs| configs.get(stream_id).cloned())
            .unwrap_or_else(|| StreamSlaConfig::default_for_stream(stream_id))
    }

    /// Merge every completed (past) minute into the store. Returns the
    /// number of bucket slices written.
    pub fn flush(&self, store: &ConfigStore) -> usize {
        self.flush_before(store, current_bucket_start())
    }

    fn flush_before(&self, store: &ConfigStore, now_bucket: DateTime<Utc>) -> usize {
        let completed: Vec<((String, DateTime<Utc>), StreamMinute)> = match self.minutes.lock() {
            Ok(mut minutes) => {
                let keys: Vec<_> = minutes
                    .keys()
                    .filter(|(_, start)| *start < now_bucket)
                    .cloned()
                    .collect();
                keys.into_iter()
                    .filter_map(|key| minutes.remove_entry(&key))
                    .collect()
            }
            Err(_) => return 0,
        };

        let mut flushed = 0;
        for ((stream_id, bucket_start), minute) in completed {
            let bucket = minute.into_bucket(&self.config_for(&stream_id), bucket_start);
            match store.merge_stream_sla_bucket(&bucket) {
                Ok(()) => {
                    debug!(
                        stream_id = %stream_id,
                        judged = bucket.judged_count,
                        success = bucket.success_count,
                        "flushed stream SLA bucket"
                    );
                    flushed += 1;
                }
                Err(e) => {
                    error!(stream_id = %stream_id, error = %e, "failed to flush stream SLA bucket")
                }
            }
        }
        flushed
    }

    /// Evaluate the last hour of every stream with a stored SLA target
    /// and return the `sla_breached` / `sla_recovered` alerts of the
    /// streams whose state changed since the previous evaluation, as
    /// [`super::SlaCollector`] does for routes. A stream judged nothing
    /// in the hour keeps its state.
    pub fn check_thresholds(&self, store: &ConfigStore) -> Vec<AlertEvent> {
        let now = Utc::now();
        let one_hour_ago = now - chrono::Duration::hours(1);
        let mut alerts = Vec::new();

        let configs = match store.list_stream_sla_configs() {
            Ok(configs) => configs,
            Err(_) => return alerts,
        };
        let Ok(mut breach_state) = self.breach_state.lock() else {
            return alerts;
        };

        for config in configs {
            let Ok(summary) = store.compute_stream_sla_summary(
                &config.stream_id,
                &one_hour_ago,
                &now,
                "1h",
                PASSIVE_SOURCE,
            ) else {
                continue;
            };
            if summary.judged_count == 0 {
                continue;
            }
            let Ok(Some(stream)) = store.get_stream(&config.stream_id) else {
                continue;
            };

            let was_breached = breach_state
                .get(&config.stream_id)
                .copied()
                .unwrap_or(false);
            let is_breached = !summary.meets_target;
            let alert = match (was_breached, is_breached) {
                (false, true) => Some((AlertType::SlaBreached, "SLA breach")),
                (true, false) => Some((AlertType::SlaRecovered, "SLA recovered")),
                _ => None,
            };
            if let Some((alert_type, headline)) = alert {
                alerts.push(
                    AlertEvent::new(
                        alert_type,
                        format!(
                            "{headline} on stream {}: {:.2}% (target: {:.1}%)",
                            stream.name, summary.sla_pct, summary.target_pct
                        ),
                    )
                    .with_detail("target", "stream")
                    .with_detail("stream_id", &config.stream_id)
                    .with_detail("stream_name", &stream.name)
                    .with_detail("sla_pct", format!("{:.2}", summary.sla_pct))
                    .with_detail("target_pct", format!("{:.1}", summary.target_pct))
                    .with_detail("judged_count", summary.judged_count.to_string()),
                );
            }
            breach_state.insert(config.stream_id, is_breached);
        }
        alerts
    }

    /// Start the background task that flushes every 60 seconds and,
    /// when given a dispatcher (the supervisor, or the single process),
    /// evaluates the targets and dispatches the alerts. It evaluates
    /// even when this process flushed nothing: in worker mode the
    /// workers write the buckets and the supervisor raises the alerts.
    pub fn start_flush_task(
        self: &Arc<Self>,
        store: Arc<TokioMutex<ConfigStore>>,
        dispatcher: Option<Arc<TokioMutex<NotifyDispatcher>>>,
    ) -> tokio::task::JoinHandle<()> {
        let collector = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let (flushed, alerts) = {
                    let store = store.lock().await;
                    let flushed = collector.flush(&store);
                    let alerts = if dispatcher.is_some() {
                        collector.check_thresholds(&store)
                    } else {
                        Vec::new()
                    };
                    (flushed, alerts)
                };
                if flushed > 0 {
                    info!(count = flushed, "flushed stream SLA buckets to database");
                }
                if let (Some(dispatcher), false) = (&dispatcher, alerts.is_empty()) {
                    let dispatcher = dispatcher.lock().await;
                    for event in &alerts {
                        dispatcher.dispatch(event).await;
                    }
                }
            }
        })
    }
}

impl Default for StreamSlaCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{Stream, StreamProtocol};

    const STREAM_ID: &str = "0b5e7a1c-9d2f-4e83-a6b1-3c4d5e6f7a80";

    fn store_with_stream(id: &str, name: &str) -> ConfigStore {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        add_stream(&store, id, name);
        store
    }

    fn add_stream(store: &ConfigStore, id: &str, name: &str) {
        let stream = Stream::new(
            id.into(),
            name.into(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().expect("test setup: address"),
            5432,
            5432,
            Utc::now(),
        );
        store.create_stream(&stream).expect("test setup: stream");
    }

    fn previous_minute() -> DateTime<Utc> {
        current_bucket_start() - chrono::Duration::minutes(1)
    }

    fn connected(ms: u64) -> StreamSlaOutcome {
        StreamSlaOutcome::TcpConnected {
            connect_latency_ms: ms,
        }
    }

    /// The single bucket of `STREAM_ID` for `minute`.
    fn stored_bucket(store: &ConfigStore, minute: DateTime<Utc>) -> StreamSlaBucket {
        let mut buckets = store
            .query_stream_sla_buckets(
                STREAM_ID,
                &minute,
                &(minute + chrono::Duration::minutes(1)),
                PASSIVE_SOURCE,
            )
            .expect("query");
        assert_eq!(buckets.len(), 1, "one bucket for the minute");
        buckets.remove(0)
    }

    #[test]
    fn tcp_counts_judged_success_failure_and_the_latency_bound() {
        let store = store_with_stream(STREAM_ID, "pg");
        let collector = StreamSlaCollector::new();
        let minute = previous_minute();
        let bound = u64::try_from(StreamSlaConfig::DEFAULT_MAX_CONNECT_LATENCY_MS)
            .expect("a positive bound");

        collector.record_at(STREAM_ID, connected(10), minute);
        collector.record_at(STREAM_ID, connected(bound), minute);
        collector.record_at(STREAM_ID, connected(bound + 1), minute);
        collector.record_at(STREAM_ID, StreamSlaOutcome::TcpNotConnected, minute);

        assert_eq!(collector.flush_before(&store, current_bucket_start()), 1);
        let bucket = stored_bucket(&store, minute);
        assert_eq!(bucket.judged_count, 4);
        assert_eq!(bucket.success_count, 2, "the bound is inclusive");
        assert_eq!(bucket.failure_count, 2, "too slow, and not connected");
        assert_eq!(bucket.connected_count, 3, "the slow one connected");
        let sum = to_i64(10 + bound + bound + 1);
        assert_eq!(bucket.connect_latency_sum_ms, Some(sum));
        assert_eq!(bucket.connect_latency_min_ms, Some(10));
        assert_eq!(bucket.connect_latency_max_ms, Some(to_i64(bound + 1)));
        assert_eq!(bucket.connect_latency_p99_ms, Some(to_i64(bound + 1)));
        assert_eq!(
            bucket.cfg_max_connect_latency_ms,
            StreamSlaConfig::DEFAULT_MAX_CONNECT_LATENCY_MS
        );
    }

    #[test]
    fn a_stored_target_sets_the_bound_and_the_snapshot() {
        let store = store_with_stream(STREAM_ID, "pg");
        let mut config = StreamSlaConfig::default_for_stream(STREAM_ID);
        config.max_connect_latency_ms = 100;
        config.target_pct = 95.0;
        store.upsert_stream_sla_config(&config).expect("target");
        let collector = StreamSlaCollector::new();
        collector.load_configs(&store);
        let minute = previous_minute();

        collector.record_at(STREAM_ID, connected(150), minute);
        collector.flush_before(&store, current_bucket_start());

        let bucket = stored_bucket(&store, minute);
        assert_eq!(bucket.failure_count, 1, "150 ms is past a 100 ms bound");
        assert_eq!(bucket.cfg_max_connect_latency_ms, 100);
        assert_eq!(bucket.cfg_target_pct, 95.0);
    }

    #[test]
    fn udp_with_expected_responses_judges_every_breaker_outcome_without_latency() {
        let store = store_with_stream(STREAM_ID, "dns");
        let collector = StreamSlaCollector::new();
        let minute = previous_minute();
        for outcome in [
            StreamSlaOutcome::UdpAnswered,
            StreamSlaOutcome::UdpIcmpError,
            StreamSlaOutcome::UdpNoResponse,
        ] {
            collector.record_at(STREAM_ID, outcome, minute);
        }
        collector.flush_before(&store, current_bucket_start());

        let bucket = stored_bucket(&store, minute);
        assert_eq!(bucket.judged_count, 3);
        assert_eq!(bucket.success_count, 1);
        assert_eq!(bucket.failure_count, 2);
        assert_eq!(bucket.connected_count, 0);
        assert_eq!(bucket.connect_latency_sum_ms, None);
        assert_eq!(bucket.connect_latency_p50_ms, None);
    }

    #[test]
    fn udp_without_expected_responses_is_a_success_at_its_end_unless_icmp_failed_it() {
        let store = store_with_stream(STREAM_ID, "syslog");
        let collector = StreamSlaCollector::new();
        let minute = previous_minute();
        for icmp_error in [false, false, false, true] {
            collector.record_at(
                STREAM_ID,
                StreamSlaOutcome::UdpUnansweredEnded { icmp_error },
                minute,
            );
        }
        collector.flush_before(&store, current_bucket_start());

        let bucket = stored_bucket(&store, minute);
        assert_eq!(bucket.judged_count, 4);
        assert_eq!(bucket.success_count, 3, "silent sessions are successes");
        assert_eq!(bucket.failure_count, 1);
        assert_eq!(bucket.connected_count, 0);
        assert_eq!(bucket.connect_latency_sum_ms, None);

        let summary = store
            .compute_stream_sla_summary(
                STREAM_ID,
                &minute,
                &current_bucket_start(),
                "1m",
                PASSIVE_SOURCE,
            )
            .expect("summary");
        assert_eq!(summary.sla_pct, 75.0, "one ICMP failure in four");
    }

    #[test]
    fn the_current_minute_waits_and_a_past_one_survives_a_new_minute() {
        let store = store_with_stream(STREAM_ID, "pg");
        let collector = StreamSlaCollector::new();
        let now = current_bucket_start();
        let past = now - chrono::Duration::minutes(1);
        collector.record_at(STREAM_ID, connected(5), past);
        collector.record_at(STREAM_ID, connected(5), now);

        assert_eq!(
            collector.flush_before(&store, now),
            1,
            "only the completed minute"
        );
        assert_eq!(stored_bucket(&store, past).judged_count, 1);
        let next = now + chrono::Duration::minutes(1);
        assert_eq!(collector.flush_before(&store, next), 1, "then the other");
    }

    #[test]
    fn clearing_a_stream_drops_its_unflushed_minutes_only() {
        let other = "1c6f8b2d-0e3a-4f94-b7c2-4d5e6f708192";
        let store = store_with_stream(STREAM_ID, "pg");
        add_stream(&store, other, "redis");
        let collector = StreamSlaCollector::new();
        let minute = previous_minute();
        collector.record_at(STREAM_ID, connected(5), minute);
        collector.record_at(other, connected(5), minute);

        collector.clear_stream(STREAM_ID);
        assert_eq!(collector.flush_before(&store, current_bucket_start()), 1);
    }

    #[test]
    fn two_collectors_flushing_into_one_minute_sum() {
        let store = store_with_stream(STREAM_ID, "pg");
        let minute = previous_minute();
        let worker_a = StreamSlaCollector::new();
        let worker_b = StreamSlaCollector::new();
        worker_a.record_at(STREAM_ID, connected(20), minute);
        worker_a.record_at(STREAM_ID, StreamSlaOutcome::TcpNotConnected, minute);
        worker_b.record_at(STREAM_ID, connected(5), minute);
        worker_b.record_at(STREAM_ID, connected(40), minute);

        worker_a.flush_before(&store, current_bucket_start());
        worker_b.flush_before(&store, current_bucket_start());

        let bucket = stored_bucket(&store, minute);
        assert_eq!(bucket.judged_count, 4);
        assert_eq!(bucket.success_count, 3);
        assert_eq!(bucket.failure_count, 1);
        assert_eq!(bucket.connected_count, 3);
        assert_eq!(bucket.connect_latency_sum_ms, Some(65));
        assert_eq!(bucket.connect_latency_min_ms, Some(5));
        assert_eq!(bucket.connect_latency_max_ms, Some(40));
    }

    /// Record `judged` outcomes of which `failed` did not connect, and
    /// flush them into the previous minute.
    fn flush_outcomes(store: &ConfigStore, judged: usize, failed: usize) {
        let collector = StreamSlaCollector::new();
        let minute = previous_minute();
        for n in 0..judged {
            let outcome = if n < failed {
                StreamSlaOutcome::TcpNotConnected
            } else {
                connected(1)
            };
            collector.record_at(STREAM_ID, outcome, minute);
        }
        collector.flush_before(store, current_bucket_start());
    }

    #[test]
    fn a_breach_alerts_once_on_each_edge_with_the_stream_details() {
        let store = store_with_stream(STREAM_ID, "pg");
        store
            .upsert_stream_sla_config(&StreamSlaConfig::default_for_stream(STREAM_ID))
            .expect("target");
        let evaluator = StreamSlaCollector::new();

        flush_outcomes(&store, 10, 5);
        let alerts = evaluator.check_thresholds(&store);
        assert_eq!(alerts.len(), 1);
        let breach = &alerts[0];
        assert_eq!(breach.alert_type, AlertType::SlaBreached);
        assert_eq!(breach.details["target"], "stream");
        assert_eq!(breach.details["stream_id"], STREAM_ID);
        assert_eq!(breach.details["stream_name"], "pg");
        assert_eq!(breach.details["judged_count"], "10");
        assert!(!breach.details.contains_key("route_id"));
        assert!(
            evaluator.check_thresholds(&store).is_empty(),
            "still breached: no second alert"
        );

        // 10,005 successes out of 10,010 judged is above 99.9 %.
        flush_outcomes(&store, 10_000, 0);
        let alerts = evaluator.check_thresholds(&store);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].alert_type, AlertType::SlaRecovered);
        assert_eq!(alerts[0].details["stream_id"], STREAM_ID);
        assert!(evaluator.check_thresholds(&store).is_empty());
    }

    #[test]
    fn a_stream_without_a_stored_target_is_not_evaluated() {
        let store = store_with_stream(STREAM_ID, "pg");
        flush_outcomes(&store, 10, 10);
        assert!(StreamSlaCollector::new()
            .check_thresholds(&store)
            .is_empty());
    }
}
