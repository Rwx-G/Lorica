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
//! The consumer is a plain OS thread, not a tokio task, so the writer
//! behaves identically in supervisor, worker, and single-process
//! modes regardless of which runtime (if any) is current at spawn
//! time. The thread exits when every [`LogWriteHandle`] is dropped
//! and the queue is drained.

use std::sync::Arc;

use crate::log_store::LogStore;
use crate::logs::LogEntry;

/// Bounded queue capacity. At ~300 bytes per entry the worst-case
/// resident size is ~2.5 MiB; at 10k rps the queue absorbs a ~0.8 s
/// SQLite stall before dropping.
const QUEUE_CAP: usize = 8192;

/// Maximum rows folded into one transaction per drain cycle.
const BATCH_MAX: usize = 256;

/// One enqueued write.
enum LogWrite {
    /// Access-log row (`access_logs` table).
    Access(LogEntry),
    /// WAF event row (`waf_events` table).
    Waf(lorica_waf::WafEvent),
}

/// Cloneable, non-blocking producer handle for the log writer queue.
#[derive(Clone)]
pub struct LogWriteHandle {
    tx: tokio::sync::mpsc::Sender<LogWrite>,
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
}

/// Spawn the dedicated writer thread and return the producer handle.
///
/// Drain strategy: block until at least one write is queued, then
/// opportunistically take up to [`BATCH_MAX`] more without waiting.
/// Under load batches fill up (one fsync per [`BATCH_MAX`] rows);
/// when idle this degrades to one row per transaction, identical to
/// the previous per-request behaviour.
pub fn spawn_log_writer(store: Arc<LogStore>) -> LogWriteHandle {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<LogWrite>(QUEUE_CAP);
    let spawned = std::thread::Builder::new()
        .name("lorica-log-writer".into())
        .spawn(move || {
            let mut accesses: Vec<LogEntry> = Vec::with_capacity(BATCH_MAX);
            let mut wafs: Vec<lorica_waf::WafEvent> = Vec::new();
            while let Some(first) = rx.blocking_recv() {
                let mut taken = 1usize;
                stash(first, &mut accesses, &mut wafs);
                while taken < BATCH_MAX {
                    match rx.try_recv() {
                        Ok(w) => {
                            stash(w, &mut accesses, &mut wafs);
                            taken += 1;
                        }
                        Err(_) => break,
                    }
                }
                if let Err(e) = store.insert_batch(&accesses) {
                    tracing::warn!(
                        error = %e,
                        rows = accesses.len(),
                        "failed to persist access log batch"
                    );
                }
                if let Err(e) = store.insert_waf_events_batch(&wafs) {
                    tracing::warn!(error = %e, rows = wafs.len(), "WAF event batch persistence failed");
                    crate::metrics::inc_waf_event_persist_failed();
                }
                accesses.clear();
                wafs.clear();
            }
        });
    if let Err(e) = spawned {
        // Thread creation only fails on resource exhaustion; the
        // handle stays usable but every enqueue counts as a drop once
        // the queue fills.
        tracing::warn!(error = %e, "failed to spawn log writer thread; log persistence disabled");
    }
    LogWriteHandle { tx }
}

fn stash(write: LogWrite, accesses: &mut Vec<LogEntry>, wafs: &mut Vec<lorica_waf::WafEvent>) {
    match write {
        LogWrite::Access(entry) => accesses.push(entry),
        LogWrite::Waf(event) => wafs.push(event),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[tokio::test]
    async fn writer_persists_access_and_waf_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(LogStore::open(dir.path()).expect("open log store"));
        let handle = spawn_log_writer(Arc::clone(&store));

        for i in 0..10 {
            handle.enqueue_access(entry(&format!("/r/{i}")));
        }
        handle.enqueue_waf(waf_event());

        // The writer drains asynchronously; poll until both tables
        // are populated (bounded to keep a regression from hanging).
        for _ in 0..100 {
            let accesses = store.count().unwrap_or(0);
            let (waf_total, _) = store.waf_event_stats().unwrap_or((0, vec![]));
            if accesses == 10 && waf_total == 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("log writer did not persist queued rows within 2s");
    }
}
