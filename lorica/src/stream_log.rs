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

//! The stream engines' observer (Story 12.9 D-a, D-c, D-g):
//! [`StreamLogObserver`] turns every record the engines hand over into
//! a stream access-log row, written to the process's log store through
//! its writer queue and offered to the log-export sinks, and every
//! judged connect outcome into the stream SLA collector.
//!
//! It runs on the stream runtime's thread, so it never blocks: the row
//! goes to bounded queues with `try_send` (`enqueue_stream`,
//! `publish_stream`) and the SLA collector takes a brief lock on an
//! in-memory map.
//!
//! A UDP stream that owes no response (syslog, NetFlow) is judged when
//! its session ends, a success unless an ICMP error ended it (the D-g
//! amendment); a stream that owes responses is judged on the breaker
//! outcome the engine reports. Which streams owe none is read from the
//! table the UDP engine was last told, [`StreamLogObserver::table_changed`].

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use lorica_api::server::LogStoreSlot;
use lorica_api::stream_logs::StreamLogEntry;
use lorica_bench::{StreamSlaCollector, StreamSlaOutcome};
use lorica_config::models::{StreamEndReason, StreamProtocol};
use lorica_stream::{
    ConnectOutcome, ConnectionObserver, ConnectionRecord, RefusalRecord, StreamTable,
    SuppressedRecord,
};
use tracing::warn;

/// Rows to the log store and the sinks, judged outcomes to the stream
/// SLA collector. See the module doc.
pub struct StreamLogObserver {
    log_store: LogStoreSlot,
    sla: Arc<StreamSlaCollector>,
    /// The UDP streams that owe their clients no response.
    unanswered_udp: ArcSwap<HashSet<String>>,
}

impl std::fmt::Debug for StreamLogObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamLogObserver")
            .field("unanswered_udp", &self.unanswered_udp.load().len())
            .finish_non_exhaustive()
    }
}

impl StreamLogObserver {
    /// An observer writing through the writer of `log_store` (none yet
    /// is fine: rows are then offered to the sinks only, until the
    /// store opens) and judging into `sla`.
    pub fn new(log_store: LogStoreSlot, sla: Arc<StreamSlaCollector>) -> Self {
        StreamLogObserver {
            log_store,
            sla,
            unanswered_udp: ArcSwap::from_pointee(HashSet::new()),
        }
    }

    /// The engines were told `table`: learn which UDP streams owe no
    /// response.
    pub fn table_changed(&self, table: &StreamTable) {
        let unanswered: HashSet<String> = table
            .streams()
            .filter(|stream| {
                stream
                    .udp
                    .as_ref()
                    .is_some_and(|udp| !udp.expects_responses())
            })
            .map(|stream| stream.id.clone())
            .collect();
        self.unanswered_udp.store(Arc::new(unanswered));
    }

    fn owes_no_response(&self, stream_id: &str, protocol: StreamProtocol) -> bool {
        protocol == StreamProtocol::Udp && self.unanswered_udp.load().contains(stream_id)
    }

    fn write(&self, row: StreamLogEntry) {
        lorica_api::log_sinks::publish_stream(&row);
        if let Some(writer) = self.log_store.writer() {
            writer.enqueue_stream(row);
        }
    }
}

/// How long a stop waits for the log writer to persist what it holds.
pub const WRITER_FLUSH_AT_EXIT: Duration = Duration::from_secs(3);

/// The stop's last write (Story 12.9 D-k): wait, at most
/// [`WRITER_FLUSH_AT_EXIT`], until the log writer of `log_store` has
/// persisted every row enqueued so far, the `node_shutdown` rows of the
/// drain included. Called once the stream drain is over, before the
/// sinks drain and the process exits.
pub async fn flush_rows_at_exit(log_store: &LogStoreSlot) {
    let Some(writer) = log_store.writer() else {
        return;
    };
    match tokio::time::timeout(WRITER_FLUSH_AT_EXIT, writer.flush()).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => warn!("log writer gone at exit; rows still queued are lost"),
        Err(_) => warn!(
            timeout_s = WRITER_FLUSH_AT_EXIT.as_secs(),
            "log writer not flushed in time at exit; rows still queued are lost"
        ),
    }
}

/// [`flush_rows_at_exit`] from a thread outside any runtime (a worker's
/// drain watcher).
pub fn flush_rows_at_exit_blocking(log_store: &LogStoreSlot) {
    match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime.block_on(flush_rows_at_exit(log_store)),
        Err(e) => warn!(error = %e, "no runtime to flush the log writer at exit"),
    }
}

/// The SLA verdict of an engine's connect outcome (Lot A's mapping onto
/// Lot D's vocabulary): `NotConnected` is a failure without a latency
/// sample on either protocol.
fn sla_outcome(outcome: ConnectOutcome) -> StreamSlaOutcome {
    match outcome {
        ConnectOutcome::Connected { latency } => StreamSlaOutcome::TcpConnected {
            connect_latency_ms: u64::try_from(latency.as_millis()).unwrap_or(u64::MAX),
        },
        ConnectOutcome::NotConnected => StreamSlaOutcome::TcpNotConnected,
        ConnectOutcome::Answered => StreamSlaOutcome::UdpAnswered,
        ConnectOutcome::IcmpError => StreamSlaOutcome::UdpIcmpError,
        ConnectOutcome::NoResponse => StreamSlaOutcome::UdpNoResponse,
    }
}

/// The verdict on a session of a UDP stream that owes no response, at
/// its end. A session that never had a backend (`no_healthy_backend`)
/// is a failure without an ICMP error, which Lot D's
/// `UdpUnansweredEnded` cannot say: it is judged as the connect phase
/// that found no backend.
fn unanswered_session_outcome(end: StreamEndReason) -> StreamSlaOutcome {
    match end {
        StreamEndReason::NoHealthyBackend => StreamSlaOutcome::TcpNotConnected,
        other => StreamSlaOutcome::UdpUnansweredEnded {
            icmp_error: other == StreamEndReason::ConnectFailed,
        },
    }
}

impl ConnectionObserver for StreamLogObserver {
    fn refused(&self, record: RefusalRecord) {
        self.write(StreamLogEntry::from_refusal(&record));
    }

    fn refusals_suppressed(&self, record: SuppressedRecord) {
        self.write(StreamLogEntry::from_suppressed(&record));
    }

    fn connect_outcome(&self, stream_id: &str, protocol: StreamProtocol, outcome: ConnectOutcome) {
        if let Some(verdict) = self.connect_verdict(stream_id, protocol, outcome) {
            self.sla.record(stream_id, verdict);
        }
    }

    fn observe(&self, record: ConnectionRecord) {
        if let Some(verdict) =
            self.end_verdict(&record.stream_id, record.protocol, record.end_reason)
        {
            self.sla.record(&record.stream_id, verdict);
        }
        self.write(StreamLogEntry::from_connection(&record));
    }
}

impl StreamLogObserver {
    /// The SLA verdict of a connect outcome, `None` for a session of a
    /// stream owing no response, which is judged at its end instead.
    fn connect_verdict(
        &self,
        stream_id: &str,
        protocol: StreamProtocol,
        outcome: ConnectOutcome,
    ) -> Option<StreamSlaOutcome> {
        (!self.owes_no_response(stream_id, protocol)).then(|| sla_outcome(outcome))
    }

    /// The SLA verdict at a connection's end: only a session of a stream
    /// owing no response is judged there.
    fn end_verdict(
        &self,
        stream_id: &str,
        protocol: StreamProtocol,
        end: StreamEndReason,
    ) -> Option<StreamSlaOutcome> {
        self.owes_no_response(stream_id, protocol)
            .then(|| unanswered_session_outcome(end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use lorica_config::models::{Stream, UdpSettings};

    fn udp_stream(id: &str, responses_per_request: u32) -> Stream {
        let mut stream = Stream::new(
            id.into(),
            id.into(),
            StreamProtocol::Udp,
            "127.0.0.1".parse().expect("an address"),
            5353,
            5353,
            Utc::now(),
        );
        stream.udp = Some(UdpSettings {
            responses_per_request,
            ..UdpSettings::default()
        });
        stream
    }

    fn observer_over(streams: Vec<Stream>) -> StreamLogObserver {
        let observer =
            StreamLogObserver::new(LogStoreSlot::default(), Arc::new(StreamSlaCollector::new()));
        observer.table_changed(&StreamTable::new(streams, &[]));
        observer
    }

    #[test]
    fn every_connect_outcome_maps_onto_its_sla_verdict() {
        assert_eq!(
            sla_outcome(ConnectOutcome::Connected {
                latency: Duration::from_millis(12)
            }),
            StreamSlaOutcome::TcpConnected {
                connect_latency_ms: 12
            }
        );
        assert_eq!(
            sla_outcome(ConnectOutcome::NotConnected),
            StreamSlaOutcome::TcpNotConnected
        );
        assert_eq!(
            sla_outcome(ConnectOutcome::Answered),
            StreamSlaOutcome::UdpAnswered
        );
        assert_eq!(
            sla_outcome(ConnectOutcome::IcmpError),
            StreamSlaOutcome::UdpIcmpError
        );
        assert_eq!(
            sla_outcome(ConnectOutcome::NoResponse),
            StreamSlaOutcome::UdpNoResponse
        );
    }

    #[test]
    fn an_unanswered_session_is_judged_by_its_end() {
        assert_eq!(
            unanswered_session_outcome(StreamEndReason::IdleTimeout),
            StreamSlaOutcome::UdpUnansweredEnded { icmp_error: false }
        );
        assert_eq!(
            unanswered_session_outcome(StreamEndReason::ConnectFailed),
            StreamSlaOutcome::UdpUnansweredEnded { icmp_error: true }
        );
        assert_eq!(
            unanswered_session_outcome(StreamEndReason::NoHealthyBackend),
            StreamSlaOutcome::TcpNotConnected
        );
    }

    #[test]
    fn the_table_says_which_udp_streams_owe_no_response() {
        let observer = observer_over(vec![udp_stream("syslog", 0), udp_stream("dns", 1)]);
        assert!(observer.owes_no_response("syslog", StreamProtocol::Udp));
        assert!(!observer.owes_no_response("dns", StreamProtocol::Udp));
        assert!(!observer.owes_no_response("syslog", StreamProtocol::Tcp));
        observer.table_changed(&StreamTable::new(vec![udp_stream("dns", 1)], &[]));
        assert!(!observer.owes_no_response("syslog", StreamProtocol::Udp));
    }

    #[test]
    fn a_session_owing_no_response_is_judged_at_its_end_and_only_there() {
        let observer = observer_over(vec![udp_stream("syslog", 0), udp_stream("dns", 1)]);
        let udp = StreamProtocol::Udp;
        assert_eq!(
            observer.connect_verdict("syslog", udp, ConnectOutcome::NoResponse),
            None
        );
        assert_eq!(
            observer.end_verdict("syslog", udp, StreamEndReason::IdleTimeout),
            Some(StreamSlaOutcome::UdpUnansweredEnded { icmp_error: false })
        );
        assert_eq!(
            observer.connect_verdict("dns", udp, ConnectOutcome::NoResponse),
            Some(StreamSlaOutcome::UdpNoResponse)
        );
        assert_eq!(
            observer.end_verdict("dns", udp, StreamEndReason::IdleTimeout),
            None
        );
    }

    #[test]
    fn a_tcp_connection_is_judged_on_its_connect_outcome_only() {
        let observer = observer_over(Vec::new());
        let tcp = StreamProtocol::Tcp;
        assert_eq!(
            observer.connect_verdict("tcp1", tcp, ConnectOutcome::NotConnected),
            Some(StreamSlaOutcome::TcpNotConnected)
        );
        assert_eq!(
            observer.end_verdict("tcp1", tcp, StreamEndReason::ClientClose),
            None
        );
    }
}
