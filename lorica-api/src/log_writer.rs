//! Background log writer: decouples request-path log persistence
//! from SQLite (audit M-8, backlog #24).
//!
//! The proxy hot path used to run one synchronous `INSERT` per
//! request (access log) and one per matched WAF rule, each acquiring
//! the `LogStore` connection mutex. SQLite write throughput tops out
//! at a few thousand commits per second; with N proxy worker threads
//! contending on one mutex, sustained throughput was capped and tail
//! latency degraded.
//!
//! Now the hot path does a non-blocking `try_send` into a bounded
//! queue and moves on; a dedicated writer thread drains the queue and
//! batches rows into one transaction per drain (one WAL fsync per
//! batch instead of one per row). On overflow the entry is dropped
//! and `lorica_log_write_dropped_total{kind}` is bumped: losing an
//! access-log line under extreme load is preferable to back-pressuring
//! request serving.
//!
//! Stream rows (Story 12.9 D-b) have a queue of their own, of the same
//! capacity, drained by the same thread: one shared queue would let a
//! stream flood shed HTTP rows. Each drain takes up to [`BATCH_MAX`]
//! writes from each queue, so neither queue can starve the other.
//!
//! The consumer is a plain OS thread, not a tokio task, so the writer
//! behaves identically in supervisor, worker, and single-process
//! modes regardless of which runtime (if any) is current at spawn
//! time. It owns a current-thread runtime only to wait on both queues
//! at once; every write it makes is a blocking SQLite commit on that
//! thread. The thread exits when every [`LogWriteHandle`] is dropped
//! and both queues are drained.

use std::sync::Arc;

use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot;

use crate::log_store::{LogStore, WriterGone};
use crate::logs::LogEntry;
use crate::stream_logs::StreamLogEntry;

/// Bounded queue capacity, for each queue. At ~300 bytes per entry the
/// worst-case resident size is ~2.5 MiB per queue; at 10k rps the
/// access queue absorbs a ~0.8 s SQLite stall before dropping.
const QUEUE_CAP: usize = 8192;

/// Maximum rows folded into one transaction per queue per drain cycle.
const BATCH_MAX: usize = 256;

/// One enqueued write on the access queue.
enum LogWrite {
    /// Access-log row (`access_logs` table).
    Access(LogEntry),
    /// WAF event row (`waf_events` table).
    Waf(lorica_waf::WafEvent),
    /// Flush barrier: when the writer reaches it, every write enqueued
    /// before it has been persisted, and the ack fires. Used by the
    /// clear endpoints so a forensics wipe cannot be trailed by stale
    /// in-flight rows re-appearing right after the DELETE.
    Barrier(oneshot::Sender<()>),
}

/// One enqueued write on the stream queue.
enum StreamWrite {
    /// Stream access-log row (`stream_access_logs` table), boxed: the
    /// row is several times the size of a barrier, and a slot of the
    /// queue is the size of its largest variant.
    Row(Box<StreamLogEntry>),
    /// Flush barrier, as [`LogWrite::Barrier`].
    Barrier(oneshot::Sender<()>),
}

/// Cloneable, non-blocking producer handle for the log writer queues.
#[derive(Clone)]
pub struct LogWriteHandle {
    tx: Sender<LogWrite>,
    stream_tx: Sender<StreamWrite>,
}

impl LogWriteHandle {
    /// Enqueue an access-log entry. Never blocks: on a full queue (or
    /// a dead writer thread) the entry is dropped and
    /// `lorica_log_write_dropped_total{kind="access"}` is bumped.
    pub fn enqueue_access(&self, entry: LogEntry) {
        if self.tx.try_send(LogWrite::Access(entry)).is_err() {
            crate::metrics::inc_log_write_dropped("access");
        }
    }

    /// Enqueue a WAF event. Same non-blocking contract as
    /// [`Self::enqueue_access`], with `kind="waf"`.
    pub fn enqueue_waf(&self, event: lorica_waf::WafEvent) {
        if self.tx.try_send(LogWrite::Waf(event)).is_err() {
            crate::metrics::inc_log_write_dropped("waf");
        }
    }

    /// Enqueue a stream access-log row on the stream queue. Same
    /// non-blocking contract as [`Self::enqueue_access`], with
    /// `kind="stream"`; a full stream queue never takes a slot of the
    /// access queue. Safe to call from the stream runtime's thread.
    pub fn enqueue_stream(&self, entry: StreamLogEntry) {
        if self
            .stream_tx
            .try_send(StreamWrite::Row(Box::new(entry)))
            .is_err()
        {
            crate::metrics::inc_log_write_dropped("stream");
        }
    }

    /// Wait until every write enqueued on either queue before this call
    /// is persisted.
    ///
    /// Unlike the enqueue methods this one applies backpressure
    /// (`send().await`) instead of dropping on a full queue: it is
    /// called from rate-limited management endpoints (logs / WAF event
    /// clear), never from the request hot path, and the wipe must not
    /// silently skip the barrier. Returns [`WriterGone`] when the writer
    /// thread is gone; callers treat that as "nothing left to flush".
    pub async fn flush(&self) -> Result<(), WriterGone> {
        let (ack_tx, ack_rx) = oneshot::channel();
        let (stream_ack_tx, stream_ack_rx) = oneshot::channel();
        self.tx
            .send(LogWrite::Barrier(ack_tx))
            .await
            .map_err(|_| WriterGone)?;
        self.stream_tx
            .send(StreamWrite::Barrier(stream_ack_tx))
            .await
            .map_err(|_| WriterGone)?;
        ack_rx.await.map_err(|_| WriterGone)?;
        stream_ack_rx.await.map_err(|_| WriterGone)
    }
}

/// The writes one drain cycle took, from both queues.
#[derive(Default)]
struct Round {
    accesses: Vec<LogEntry>,
    wafs: Vec<lorica_waf::WafEvent>,
    streams: Vec<StreamLogEntry>,
    barriers: Vec<oneshot::Sender<()>>,
}

impl Round {
    fn take(&mut self, write: LogWrite) {
        match write {
            LogWrite::Access(entry) => self.accesses.push(entry),
            LogWrite::Waf(event) => self.wafs.push(event),
            LogWrite::Barrier(ack) => self.barriers.push(ack),
        }
    }

    fn take_stream(&mut self, write: StreamWrite) {
        match write {
            StreamWrite::Row(entry) => self.streams.push(*entry),
            StreamWrite::Barrier(ack) => self.barriers.push(ack),
        }
    }

    /// Add what each queue holds now, without waiting, up to
    /// [`BATCH_MAX`] writes per queue in all: `taken` and `taken_stream`
    /// are what this round already took from each.
    fn fill(
        &mut self,
        rx: &mut Receiver<LogWrite>,
        stream_rx: &mut Receiver<StreamWrite>,
        mut taken: usize,
        mut taken_stream: usize,
    ) {
        while taken < BATCH_MAX {
            let Ok(write) = rx.try_recv() else { break };
            self.take(write);
            taken += 1;
        }
        while taken_stream < BATCH_MAX {
            let Ok(write) = stream_rx.try_recv() else {
                break;
            };
            self.take_stream(write);
            taken_stream += 1;
        }
    }

    /// Persist the round, then ack its barriers: an ack means every
    /// write enqueued before the barrier is on disk.
    fn persist(self, store: &LogStore) {
        if let Err(e) = store.insert_batch(&self.accesses) {
            tracing::warn!(
                error = %e,
                rows = self.accesses.len(),
                "failed to persist access log batch"
            );
        }
        if let Err(e) = store.insert_waf_events_batch(&self.wafs) {
            tracing::warn!(error = %e, rows = self.wafs.len(), "WAF event batch persistence failed");
            crate::metrics::inc_waf_event_persist_failed();
        }
        if let Err(e) = store.insert_stream_batch(&self.streams) {
            tracing::warn!(
                error = %e,
                rows = self.streams.len(),
                "failed to persist stream log batch"
            );
        }
        // Dropped receivers (the caller gave up) are fine.
        for barrier in self.barriers {
            let _ = barrier.send(());
        }
    }
}

/// The writer thread's loop: wait for a write on either queue, take a
/// round, persist it. Ends when both queues are closed and drained.
async fn drain(
    store: Arc<LogStore>,
    mut rx: Receiver<LogWrite>,
    mut stream_rx: Receiver<StreamWrite>,
) {
    let mut access_open = true;
    let mut stream_open = true;
    while access_open || stream_open {
        // Unbiased: when both queues hold writes, either may start the
        // round, and the round takes from both anyway.
        let mut round = Round::default();
        let (taken, taken_stream) = tokio::select! {
            write = rx.recv(), if access_open => match write {
                Some(write) => {
                    round.take(write);
                    (1, 0)
                }
                None => {
                    access_open = false;
                    continue;
                }
            },
            write = stream_rx.recv(), if stream_open => match write {
                Some(write) => {
                    round.take_stream(write);
                    (0, 1)
                }
                None => {
                    stream_open = false;
                    continue;
                }
            },
        };
        round.fill(&mut rx, &mut stream_rx, taken, taken_stream);
        round.persist(&store);
    }
}

/// Spawn the dedicated writer thread and return the producer handle.
///
/// Drain strategy: block until at least one write is queued on either
/// queue, then opportunistically take up to [`BATCH_MAX`] writes from
/// each without waiting. Under load batches fill up (one fsync per
/// [`BATCH_MAX`] rows per table); when idle this degrades to one row
/// per transaction, identical to the previous per-request behaviour.
pub fn spawn_log_writer(store: Arc<LogStore>) -> LogWriteHandle {
    let (tx, rx) = tokio::sync::mpsc::channel::<LogWrite>(QUEUE_CAP);
    let (stream_tx, stream_rx) = tokio::sync::mpsc::channel::<StreamWrite>(QUEUE_CAP);
    let spawned = std::thread::Builder::new()
        .name("lorica-log-writer".into())
        .spawn(move || {
            match tokio::runtime::Builder::new_current_thread().build() {
                Ok(runtime) => runtime.block_on(drain(store, rx, stream_rx)),
                Err(e) => {
                    // Dropping the receivers closes both queues: every
                    // enqueue then counts as a drop.
                    tracing::warn!(error = %e, "failed to build the log writer runtime; log persistence disabled");
                }
            }
        });
    if let Err(e) = spawned {
        // Thread creation only fails on resource exhaustion; the
        // handle stays usable but every enqueue counts as a drop once
        // the queue fills.
        tracing::warn!(error = %e, "failed to spawn log writer thread; log persistence disabled");
    }
    LogWriteHandle { tx, stream_tx }
}

#[cfg(test)]
mod tests {
    use lorica_config::models::StreamEndReason;

    use super::*;
    use crate::stream_logs::test_support::tcp_connection;

    fn entry(path: &str) -> LogEntry {
        LogEntry {
            id: 0,
            timestamp: "2026-06-10T00:00:00Z".into(),
            method: "GET".into(),
            path: path.into(),
            host: "example.com".into(),
            status: 200,
            latency_ms: 3,
            backend: "10.0.0.10:8080".into(),
            error: None,
            client_ip: "192.0.2.10".into(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        }
    }

    fn waf_event() -> lorica_waf::WafEvent {
        lorica_waf::WafEvent {
            rule_id: 942100,
            description: "SQLi probe".into(),
            category: lorica_waf::RuleCategory::SqlInjection,
            severity: 5,
            matched_field: "query".into(),
            matched_value: "1 OR 1=1".into(),
            timestamp: "2026-06-10T00:00:00Z".into(),
            client_ip: "192.0.2.10".into(),
            route_hostname: "example.com".into(),
            action: "blocked".into(),
        }
    }

    fn stream_row() -> StreamLogEntry {
        StreamLogEntry::from_connection(&tcp_connection(StreamEndReason::ClientClose))
    }

    fn stream_drops() -> f64 {
        lorica_metrics::gather()
            .iter()
            .find(|family| family.name() == "lorica_log_write_dropped_total")
            .and_then(|family| {
                family
                    .get_metric()
                    .iter()
                    .find(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|pair| pair.name() == "kind" && pair.value() == "stream")
                    })
                    .map(|metric| metric.get_counter().value())
            })
            .unwrap_or(0.0)
    }

    #[tokio::test]
    async fn writer_persists_access_waf_and_stream_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(LogStore::open(dir.path()).expect("open log store"));
        let handle = spawn_log_writer(Arc::clone(&store));

        for i in 0..10 {
            handle.enqueue_access(entry(&format!("/r/{i}")));
        }
        handle.enqueue_waf(waf_event());
        for _ in 0..5 {
            handle.enqueue_stream(stream_row());
        }

        handle.flush().await.expect("the writer drains");
        assert_eq!(store.count().expect("count"), 10);
        assert_eq!(store.waf_event_stats().expect("stats").total, 1);
        assert_eq!(store.stream_log_count().expect("count"), 5);
    }

    #[tokio::test]
    async fn a_stream_flood_sheds_stream_rows_and_never_an_access_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(LogStore::open(dir.path()).expect("open log store"));
        let handle = spawn_log_writer(Arc::clone(&store));
        let drops_before = stream_drops();
        {
            // The writer blocks on its first commit while this is held,
            // so the queues fill as a stalled disk would fill them.
            let _stall = store.block_audit_writer_for_test();
            handle.enqueue_stream(stream_row());
            // Let the writer take that row and block on the lock: the
            // stream queue is then exactly empty.
            std::thread::sleep(std::time::Duration::from_millis(200));
            for _ in 0..QUEUE_CAP + 10 {
                handle.enqueue_stream(stream_row());
            }
            for i in 0..100 {
                handle.enqueue_access(entry(&format!("/during-flood/{i}")));
            }
        }
        handle.flush().await.expect("the writer drains");
        assert_eq!(store.count().expect("count"), 100, "every access row kept");
        assert_eq!(
            store.stream_log_count().expect("count"),
            u64::try_from(QUEUE_CAP + 1).expect("fits"),
            "the stream queue held its own capacity, plus the row in flight"
        );
        assert!(stream_drops() - drops_before >= 10.0);
    }

    #[test]
    fn one_round_takes_from_both_queues_however_full_either_is() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<LogWrite>(QUEUE_CAP);
        let (stream_tx, mut stream_rx) = tokio::sync::mpsc::channel::<StreamWrite>(QUEUE_CAP);
        for _ in 0..QUEUE_CAP {
            assert!(stream_tx
                .try_send(StreamWrite::Row(Box::new(stream_row())))
                .is_ok());
        }
        for i in 0..3 * BATCH_MAX {
            assert!(tx
                .try_send(LogWrite::Access(entry(&format!("/{i}"))))
                .is_ok());
        }
        let mut round = Round::default();
        round.fill(&mut rx, &mut stream_rx, 0, 0);
        assert_eq!(round.accesses.len(), BATCH_MAX);
        assert_eq!(round.streams.len(), BATCH_MAX);

        // A round started by a stream write still takes access rows.
        let mut round = Round::default();
        round.take_stream(stream_rx.try_recv().expect("a stream write"));
        round.fill(&mut rx, &mut stream_rx, 0, 1);
        assert_eq!(round.streams.len(), BATCH_MAX);
        assert_eq!(round.accesses.len(), BATCH_MAX);
    }
}
