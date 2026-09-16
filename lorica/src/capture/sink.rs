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

//! Where a capture record goes (Story 10.2 AC #3), and the guarantee
//! that no sink failure reaches the request (AC #4).
//!
//! Four outputs, tried in this order for every record:
//!
//! 1. The structured log: one `tracing` event at target
//!    [`CAPTURE_TRACING_TARGET`] whose `record` field is the JSON
//!    document. It lands wherever the process log lands (stdout, or the
//!    rolling file behind a non-blocking writer) in whatever format
//!    `--log-format` selected. This is the default output and it is
//!    always on.
//! 2. The recent-captures ring of `lorica_api::capture_ring`, which
//!    the dashboard reads. Process-local, bounded, cannot fail: a push
//!    is a `VecDeque` operation under a mutex nothing else holds for
//!    longer than a handful of `Arc` clones.
//! 3. The log-export lanes of `lorica_api::log_sinks`: syslog and OTLP
//!    logs, each a `try_send` into a bounded queue. The proxy reaches
//!    the hub the same way it does for access-log rows: the hub is a
//!    process-global installed by the reload path, and `publish_*` is
//!    the whole handle.
//! 4. The rule's `output.dir`: one file per capture, written by a
//!    dedicated thread fed through a bounded channel. The write itself
//!    is the only output that touches a disk, and it is the only one
//!    that leaves `logging`.
//!
//! The first three are synchronous and non-blocking by construction;
//! the fourth is queued. Nothing on the emit path blocks, awaits or
//! panics: the request was answered before `logging` ran, and the one
//! way a sink could still hurt it is by stalling the hook.
//!
//! # Why a thread and a channel, not `spawn_blocking`
//!
//! `logging` runs on the proxy's runtime, so `spawn_blocking` would
//! work there. It would also queue without bound until the blocking
//! pool is exhausted, share that pool with every other blocking call in
//! the process, and need a runtime handle that the worker and
//! single-process modes hold differently. A plain OS thread owning the
//! file I/O, fed by a `sync_channel` with `try_send`, has the shape of
//! the access-log writer and the sink consumers: it behaves the same in
//! every process mode, and its memory is bounded by two numbers written
//! down here ([`CAPTURE_DIR_QUEUE_CAP`] jobs, [`CAPTURE_DIR_QUEUE_MAX_BYTES`]
//! of documents).
//!
//! # The drop path
//!
//! Every failure ends the same way: the copy is dropped and
//! `lorica_captures_total{rule_id, outcome="dropped_sink"}` is bumped
//! once per lost copy. A full lane, a lane whose consumer died, a full
//! write queue, a directory that does not exist or refuses the write, a
//! full disk, a name that is already taken. The counter is per delivery,
//! not per record: with syslog and a directory both failing, one record
//! counts two.
//!
//! # The file
//!
//! `<timestamp>-<request_id>.json`, mode [`CAPTURE_FILE_MODE`], owned by
//! the running user (`lorica` under the shipped unit). The directory
//! must already exist: the writer never creates it, because a directory
//! that appears at the first capture is a directory nobody set the
//! permissions on. The document is written to a hidden temporary name
//! in the same directory with `create_new`, flushed to disk, then
//! published under its final name with `hard_link`, which fails when
//! the name is taken. That gives the final name the `create_new`
//! guarantee AND an atomic publish: a reader sees the temporary file
//! (which it ignores, it does not end in `.json`) or the complete
//! document, never a prefix of one. `rename` would have silently
//! replaced an existing document.
//!
//! Pruning runs after every successful write when the rule sets
//! `max_dir_bytes`, oldest first by name (the timestamp prefix makes
//! lexical order chronological), until the directory is under budget or
//! [`CAPTURE_PRUNE_MAX_REMOVALS`] files went. It counts and removes only
//! the names this writer produces; the file just written is never a
//! candidate, so a budget smaller than one record keeps the newest and
//! nothing else. The directory listing itself is linear in the number
//! of files, which the budget bounds.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use lorica_api::capture_ring::{node_capture_ring, CaptureRing};
use lorica_api::log_sinks::{self, CaptureSinkRecord, SinkKind};
use lorica_api::metrics::inc_capture_outcome;
use lorica_config::models::CaptureOutput;

use super::record::CaptureRecord;

/// The `tracing` target every capture event carries, so a log filter
/// can route or silence captures without touching the access log.
pub const CAPTURE_TRACING_TARGET: &str = "lorica::capture";

/// The `outcome` label of `lorica_captures_total` for a copy a sink
/// lost.
pub const CAPTURE_DROPPED_SINK_OUTCOME: &str = "dropped_sink";

/// Mode of every capture file: readable by the owner and its group,
/// nobody else. A capture holds request bodies.
pub const CAPTURE_FILE_MODE: u32 = 0o640;

/// Jobs the directory write queue holds before it refuses. At the
/// default 64 KiB body caps a job is under 200 KiB; the byte bound
/// below is what matters for a rule with the 4 MiB caps.
pub const CAPTURE_DIR_QUEUE_CAP: usize = 64;

/// Bytes of documents the directory write queue holds before it
/// refuses. Same figure as the node-wide in-flight buffer ceiling
/// (`CAPTURE_MAX_INFLIGHT_BYTES`): a node can owe the disk at most as
/// much as it can owe the request path.
pub const CAPTURE_DIR_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Files one prune pass removes at most. A directory far over budget
/// (an operator lowered `max_dir_bytes` by an order of magnitude) is
/// brought under it over a few captures rather than in one pass that
/// stalls the writer.
pub const CAPTURE_PRUNE_MAX_REMOVALS: usize = 64;

/// Basic ISO 8601 with nanoseconds, UTC: `20260101T000000.123456789Z`.
/// Fixed width, so file names sort chronologically, and free of `:`
/// and `-`, so the name splits on its first `-`.
const CAPTURE_FILE_TIMESTAMP_FORMAT: &str = "%Y%m%dT%H%M%S%.9fZ";

/// Byte length of a timestamp in [`CAPTURE_FILE_TIMESTAMP_FORMAT`].
const CAPTURE_FILE_TIMESTAMP_LEN: usize = 26;

/// Longest `request_id` kept in a file name. The proxy's ids are 32
/// hex characters; the cap is what keeps a foreign id under the
/// filesystem's 255-byte name limit.
const CAPTURE_FILE_REQUEST_ID_MAX_LEN: usize = 128;

/// One record and where its rule sends it.
#[derive(Debug, Clone)]
pub struct CaptureEmission {
    /// The record, built and redacted.
    pub record: CaptureRecord,
    /// The rule's `output` block: `dir` adds the file output.
    pub output: CaptureOutput,
}

/// Hand every record to its outputs. Called once per request from
/// `logging`, after the response is written; never blocks.
pub fn emit_captures(
    emissions: Vec<CaptureEmission>,
    trace_id: Option<&str>,
    span_id: Option<&str>,
) {
    for emission in emissions {
        emit_one(
            emission,
            trace_id,
            span_id,
            node_dir_writer(),
            node_capture_ring(),
        );
    }
}

fn emit_one(
    emission: CaptureEmission,
    trace_id: Option<&str>,
    span_id: Option<&str>,
    dir_writer: &CaptureDirWriter,
    ring: &CaptureRing,
) {
    let CaptureEmission { record, output } = emission;
    // Serialised straight from the struct, not through a `Value`: the
    // struct keeps its field order and a `Value` sorts its keys, and
    // the record's byte-identity promise covers the file, the log
    // line and the download.
    let text = match serde_json::to_string(&record) {
        Ok(text) => text,
        Err(error) => {
            tracing::warn!(
                target: CAPTURE_TRACING_TARGET,
                rule_id = %record.rule_id,
                request_id = %record.request_id,
                error = %error,
                "capture record failed to serialise; dropped"
            );
            inc_capture_outcome(&record.rule_id, CAPTURE_DROPPED_SINK_OUTCOME);
            return;
        }
    };

    tracing::info!(
        target: CAPTURE_TRACING_TARGET,
        rule_id = %record.rule_id,
        rule_name = %record.rule_name,
        route_id = %record.route_id,
        request_id = %record.request_id,
        record = %text,
        "traffic capture"
    );

    let file_name = capture_file_name(&record.timestamp, &record.request_id);

    // The ring and the lanes both take the record as a `Value`; it is
    // built once. A struct that serialised to text above serialises to
    // a `Value` too, so the `Err` arm is unreachable in practice and
    // is handled rather than asserted because this is the emit path.
    match serde_json::to_value(&record) {
        Ok(document) => {
            ring.remember(
                &record.rule_id,
                &record.request_id,
                &file_name,
                document.clone(),
                text.clone(),
            );
            if log_sinks::wants(SinkKind::Capture) {
                let lost = log_sinks::publish_capture(
                    CaptureSinkRecord {
                        rule_id: record.rule_id.clone(),
                        request_id: record.request_id.clone(),
                        timestamp: record.timestamp.clone(),
                        document,
                    },
                    trace_id,
                    span_id,
                );
                for _ in 0..lost {
                    inc_capture_outcome(&record.rule_id, CAPTURE_DROPPED_SINK_OUTCOME);
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                target: CAPTURE_TRACING_TARGET,
                rule_id = %record.rule_id,
                error = %error,
                "capture record failed to serialise for the ring and the export sinks; dropped"
            );
            inc_capture_outcome(&record.rule_id, CAPTURE_DROPPED_SINK_OUTCOME);
        }
    }

    if let Some(dir) = output.dir {
        let job = DirWriteJob {
            dir: PathBuf::from(dir),
            max_dir_bytes: output.max_dir_bytes,
            file_name,
            rule_id: record.rule_id.clone(),
            document: text.into_bytes(),
        };
        if let Err(refusal) = dir_writer.enqueue(job) {
            tracing::debug!(
                target: CAPTURE_TRACING_TARGET,
                rule_id = %record.rule_id,
                request_id = %record.request_id,
                refusal = ?refusal,
                "capture directory write queue refused the record; dropped"
            );
            inc_capture_outcome(&record.rule_id, CAPTURE_DROPPED_SINK_OUTCOME);
        }
    }
}

/// The file name a capture is written under: `<timestamp>-<request_id>.json`.
///
/// The timestamp is the record's, in [`CAPTURE_FILE_TIMESTAMP_FORMAT`]
/// (the time of the write when the record's does not parse). The
/// request id is reduced to `[A-Za-z0-9._-]` and capped at
/// [`CAPTURE_FILE_REQUEST_ID_MAX_LEN`] bytes: the proxy's own ids never
/// need it, and a name is a path component.
///
/// ```
/// use lorica::capture::capture_file_name;
/// assert_eq!(
///     capture_file_name("2026-01-01T00:00:00.123456789+00:00", "0123abcd"),
///     "20260101T000000.123456789Z-0123abcd.json"
/// );
/// ```
pub fn capture_file_name(timestamp: &str, request_id: &str) -> String {
    let instant = DateTime::parse_from_rfc3339(timestamp)
        .map(|ts| ts.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let stamp = instant.format(CAPTURE_FILE_TIMESTAMP_FORMAT);
    let mut id: String = request_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(CAPTURE_FILE_REQUEST_ID_MAX_LEN)
        .collect();
    if id.is_empty() {
        id.push_str("unknown");
    }
    format!("{stamp}-{id}.json")
}

/// Whether `name` is a file this writer produces, and therefore one
/// the pruner may count and remove. Anything else in the directory,
/// including another `.json` file, is not the writer's to touch.
///
/// ```
/// use lorica::capture::is_capture_file_name;
/// assert!(is_capture_file_name("20260101T000000.123456789Z-0123abcd.json"));
/// assert!(!is_capture_file_name("notes.json"));
/// assert!(!is_capture_file_name(".20260101T000000.123456789Z-0123abcd.json.tmp"));
/// ```
pub fn is_capture_file_name(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".json") else {
        return false;
    };
    let Some((timestamp, request_id)) = stem.split_once('-') else {
        return false;
    };
    timestamp.len() == CAPTURE_FILE_TIMESTAMP_LEN
        && timestamp.bytes().enumerate().all(|(i, b)| match i {
            8 => b == b'T',
            15 => b == b'.',
            25 => b == b'Z',
            _ => b.is_ascii_digit(),
        })
        && !request_id.is_empty()
}

/// Write `document` under `dir/file_name` as described in the module
/// doc: temporary name, `create_new`, mode [`CAPTURE_FILE_MODE`],
/// flushed, then published with `hard_link`. Returns the final path.
///
/// Fails, writing nothing under the final name, when the directory is
/// missing or not writable, when the disk is full, or when the final
/// name already exists (`AlreadyExists`). A temporary file never
/// outlives this call.
pub fn write_capture_file(
    dir: &Path,
    file_name: &str,
    document: &[u8],
) -> std::io::Result<PathBuf> {
    let final_path = dir.join(file_name);
    if final_path.symlink_metadata().is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} already exists", final_path.display()),
        ));
    }
    let temp_path = dir.join(format!(".{file_name}.tmp"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(CAPTURE_FILE_MODE)
        .open(&temp_path)?;
    let written = file.write_all(document).and_then(|()| {
        // `mode()` above is subject to the umask; the explicit set is
        // what makes 0640 the mode and not the ceiling.
        file.set_permissions(std::fs::Permissions::from_mode(CAPTURE_FILE_MODE))?;
        file.sync_all()
    });
    drop(file);
    let published = written.and_then(|()| std::fs::hard_link(&temp_path, &final_path));
    // Success or failure, the temporary name must not survive: it is
    // neither a document nor a prune candidate, and would pile up.
    if let Err(error) = std::fs::remove_file(&temp_path) {
        tracing::debug!(
            target: CAPTURE_TRACING_TARGET,
            path = %temp_path.display(),
            error = %error,
            "capture temporary file could not be removed"
        );
    }
    published?;
    Ok(final_path)
}

/// Remove this writer's oldest files from `dir` until the ones left
/// total at most `max_dir_bytes`, never touching `keep` (the file just
/// written) and never more than [`CAPTURE_PRUNE_MAX_REMOVALS`] in one
/// pass. Returns how many files were removed.
pub fn prune_capture_dir(dir: &Path, max_dir_bytes: u64, keep: &str) -> std::io::Result<usize> {
    let mut files: Vec<(String, u64)> = Vec::new();
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(dir)? {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_capture_file_name(name) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        total += metadata.len();
        files.push((name.to_string(), metadata.len()));
    }
    if total <= max_dir_bytes {
        return Ok(0);
    }
    files.sort_unstable();
    let mut removed = 0usize;
    for (name, len) in files {
        if total <= max_dir_bytes || removed >= CAPTURE_PRUNE_MAX_REMOVALS {
            break;
        }
        if name == keep {
            continue;
        }
        match std::fs::remove_file(dir.join(&name)) {
            Ok(()) => {
                total = total.saturating_sub(len);
                removed += 1;
            }
            // Removed by someone else between the listing and now:
            // the bytes are gone either way.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                total = total.saturating_sub(len);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(removed)
}

/// One queued directory write.
struct DirWriteJob {
    dir: PathBuf,
    max_dir_bytes: Option<u64>,
    file_name: String,
    rule_id: String,
    document: Vec<u8>,
}

/// Why the write queue refused a job. Each is a drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnqueueRefusal {
    /// [`CAPTURE_DIR_QUEUE_CAP`] jobs are already waiting.
    Full,
    /// The job would take the queued documents past the byte bound.
    OverByteBudget,
    /// The writer thread is not running.
    Gone,
}

/// Producer side of the directory writer: a bounded job queue plus a
/// byte bound over the documents it holds.
pub struct CaptureDirWriter {
    tx: SyncSender<DirWriteJob>,
    queued_bytes: Arc<AtomicUsize>,
    max_queued_bytes: usize,
}

impl CaptureDirWriter {
    fn channel(capacity: usize, max_queued_bytes: usize) -> (Self, Receiver<DirWriteJob>) {
        let (tx, rx) = sync_channel(capacity);
        let writer = CaptureDirWriter {
            tx,
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            max_queued_bytes,
        };
        (writer, rx)
    }

    /// Start the writer thread and return its producer handle. When
    /// the thread cannot be spawned the handle still exists and every
    /// job it is given is refused as [`EnqueueRefusal::Gone`], which is
    /// a counted drop and not a panic.
    pub fn spawn(capacity: usize, max_queued_bytes: usize) -> Self {
        let (writer, rx) = Self::channel(capacity, max_queued_bytes);
        let queued_bytes = Arc::clone(&writer.queued_bytes);
        let spawned = std::thread::Builder::new()
            .name("lorica-capture-writer".into())
            .spawn(move || writer_loop(rx, &queued_bytes));
        if let Err(error) = spawned {
            tracing::warn!(
                target: CAPTURE_TRACING_TARGET,
                error = %error,
                "failed to spawn the capture directory writer; directory output disabled"
            );
        }
        writer
    }

    fn enqueue(&self, job: DirWriteJob) -> Result<(), EnqueueRefusal> {
        let len = job.document.len();
        // Reserve before the check so two producers cannot both pass
        // it; the thread releases once the job is done, refused paths
        // release here.
        let prior = self.queued_bytes.fetch_add(len, Ordering::AcqRel);
        if prior.saturating_add(len) > self.max_queued_bytes {
            self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
            return Err(EnqueueRefusal::OverByteBudget);
        }
        match self.tx.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
                Err(EnqueueRefusal::Full)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
                Err(EnqueueRefusal::Gone)
            }
        }
    }
}

fn writer_loop(rx: Receiver<DirWriteJob>, queued_bytes: &AtomicUsize) {
    // One warn per broken directory, then debug: a read-only mount at
    // the rate cap is one operator problem, not ten thousand lines.
    let mut last_failed_dir: Option<PathBuf> = None;
    for job in rx {
        let len = job.document.len();
        match write_capture_file(&job.dir, &job.file_name, &job.document) {
            Ok(path) => {
                last_failed_dir = None;
                if let Some(budget) = job.max_dir_bytes {
                    match prune_capture_dir(&job.dir, budget, &job.file_name) {
                        Ok(0) => {}
                        Ok(removed) => tracing::debug!(
                            target: CAPTURE_TRACING_TARGET,
                            dir = %job.dir.display(),
                            removed,
                            "capture directory pruned to its budget"
                        ),
                        Err(error) => tracing::debug!(
                            target: CAPTURE_TRACING_TARGET,
                            dir = %job.dir.display(),
                            error = %error,
                            "capture directory could not be pruned"
                        ),
                    }
                }
                tracing::debug!(
                    target: CAPTURE_TRACING_TARGET,
                    rule_id = %job.rule_id,
                    path = %path.display(),
                    "capture written"
                );
            }
            Err(error) => {
                inc_capture_outcome(&job.rule_id, CAPTURE_DROPPED_SINK_OUTCOME);
                if last_failed_dir.as_deref() == Some(job.dir.as_path()) {
                    tracing::debug!(
                        target: CAPTURE_TRACING_TARGET,
                        rule_id = %job.rule_id,
                        dir = %job.dir.display(),
                        error = %error,
                        "capture file write failed; dropped"
                    );
                } else {
                    tracing::warn!(
                        target: CAPTURE_TRACING_TARGET,
                        rule_id = %job.rule_id,
                        dir = %job.dir.display(),
                        error = %error,
                        "capture file write failed; dropping until the directory writes again"
                    );
                    last_failed_dir = Some(job.dir.clone());
                }
            }
        }
        queued_bytes.fetch_sub(len, Ordering::AcqRel);
    }
}

/// This process's directory writer, started on the first capture that
/// has a directory to go to.
fn node_dir_writer() -> &'static CaptureDirWriter {
    static WRITER: OnceLock<CaptureDirWriter> = OnceLock::new();
    WRITER
        .get_or_init(|| CaptureDirWriter::spawn(CAPTURE_DIR_QUEUE_CAP, CAPTURE_DIR_QUEUE_MAX_BYTES))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{BodyEncoding, CapturedRequest, CapturedResponse, CAPTURE_RECORD_KIND};
    use lorica_api::metrics::capture_outcome_value;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    /// The hub is process-global; every test that emits takes this,
    /// not only the ones that register a lane: a lane one test has
    /// registered and let die is torn out by the NEXT publish, and a
    /// sibling emitting in that window would inherit its `Gone` drop.
    /// An async mutex because one of them holds it across an await.
    fn hub_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test setup: the clock is after 1970")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "lorica-capture-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("test setup: temp dir creates");
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const TIMESTAMP: &str = "2026-01-01T00:00:00.123456789+00:00";
    const REQUEST_ID: &str = "0123456789abcdef0123456789abcdef";

    fn record(rule_id: &str) -> CaptureRecord {
        CaptureRecord {
            kind: CAPTURE_RECORD_KIND,
            rule_id: rule_id.to_string(),
            rule_name: format!("rule {rule_id}"),
            route_id: "route-1".to_string(),
            request_id: REQUEST_ID.to_string(),
            timestamp: TIMESTAMP.to_string(),
            client_ip: "10.0.0.7".to_string(),
            is_xff: false,
            backend: "10.0.0.2:8080".to_string(),
            latency_ms: 12,
            error: None,
            request: CapturedRequest {
                method: "POST".to_string(),
                uri: "/checkout".to_string(),
                version: "HTTP/1.1".to_string(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some("{\"a\":1}".to_string()),
                body_encoding: Some(BodyEncoding::Utf8),
                body_bytes_total: 7,
                truncated: false,
                body_skipped: None,
            },
            response: CapturedResponse {
                status: 503,
                headers: Vec::new(),
                body: Some(String::new()),
                body_encoding: Some(BodyEncoding::Base64),
                body_bytes_total: 0,
                truncated: false,
                body_skipped: None,
            },
        }
    }

    fn emission(rule_id: &str, dir: Option<&Path>) -> CaptureEmission {
        CaptureEmission {
            record: record(rule_id),
            output: CaptureOutput {
                dir: dir.map(|d| d.to_string_lossy().into_owned()),
                max_dir_bytes: None,
            },
        }
    }

    fn dropped(rule_id: &str) -> u64 {
        capture_outcome_value(rule_id, CAPTURE_DROPPED_SINK_OUTCOME)
    }

    /// A ring of this test's own, so what one test emits is never
    /// listed by another.
    fn ring() -> CaptureRing {
        CaptureRing::new(4)
    }

    /// Poll `dropped(rule_id)` until it reaches `expected` or five
    /// seconds pass; the writer thread reports on its own schedule.
    fn wait_for_drops(rule_id: &str, expected: u64) -> u64 {
        let deadline = Instant::now() + Duration::from_secs(5);
        while dropped(rule_id) < expected && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        dropped(rule_id)
    }

    fn expected_file_name() -> String {
        format!("20260101T000000.123456789Z-{REQUEST_ID}.json")
    }

    // ---- lanes ----

    #[test]
    fn a_record_reaches_a_capture_lane_and_not_a_lane_with_the_flag_off() {
        let _guard = hub_lock().blocking_lock();
        log_sinks::install(&log_sinks::LogSinksConfig::default());
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);

        let mut off = log_sinks::register_lane("otlp", true, true, true, false);
        emit_one(emission("cap-lane-off", None), None, None, &writer, &ring());
        assert!(
            off.try_recv().is_err(),
            "a lane with capture off gets nothing"
        );
        assert_eq!(
            dropped("cap-lane-off"),
            0,
            "not wanting a kind is not a drop"
        );

        let mut on = log_sinks::register_lane("otlp", false, false, false, true);
        emit_one(
            emission("cap-lane-on", None),
            Some("4bf9"),
            Some("00f0"),
            &writer,
            &ring(),
        );
        let event = on.try_recv().expect("the lane received the record");
        assert_eq!(event.kind(), SinkKind::Capture);
        assert_eq!(event.trace_id.as_deref(), Some("4bf9"));
        match &*event.payload {
            log_sinks::SinkPayload::Capture(sink_record) => {
                assert_eq!(sink_record.rule_id, "cap-lane-on");
                assert_eq!(sink_record.request_id, REQUEST_ID);
                assert_eq!(sink_record.document["request"]["method"], "POST");
            }
            other => panic!("expected a capture payload, got {other:?}"),
        }
        assert_eq!(dropped("cap-lane-on"), 0);
        log_sinks::install(&log_sinks::LogSinksConfig::default());
    }

    #[test]
    fn a_lane_whose_consumer_is_gone_counts_a_dropped_sink() {
        let _guard = hub_lock().blocking_lock();
        log_sinks::install(&log_sinks::LogSinksConfig::default());
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let rx = log_sinks::register_lane("otlp", false, false, false, true);
        drop(rx);
        emit_one(
            emission("cap-lane-gone", None),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(dropped("cap-lane-gone"), 1);
        assert!(
            !log_sinks::wants(SinkKind::Capture),
            "the dead lane is torn out"
        );
        log_sinks::install(&log_sinks::LogSinksConfig::default());
    }

    // ---- the ring ----

    #[test]
    fn the_record_lands_in_the_ring_whole_under_the_sinks_file_name() {
        let _guard = hub_lock().blocking_lock();
        log_sinks::install(&log_sinks::LogSinksConfig::default());
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let ring = ring();
        emit_one(emission("cap-ring", None), None, None, &writer, &ring);

        let entry = ring
            .get(REQUEST_ID, Some("cap-ring"))
            .expect("the record is in the ring");
        assert_eq!(entry.file_name, expected_file_name());
        assert_eq!(
            entry.document,
            serde_json::to_string(&record("cap-ring")).expect("a record serialises"),
            "the download is the log line, byte for byte"
        );
        let listed = ring.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0]["request_id"], REQUEST_ID);
        assert_eq!(listed[0]["request"]["body_elided"], false);
        assert_eq!(
            dropped("cap-ring"),
            0,
            "the ring is not a sink that can drop"
        );
    }

    // ---- tracing ----

    /// Collects every event's target and `record` field.
    #[derive(Default)]
    struct EventTap {
        seen: Mutex<Vec<(String, Option<String>)>>,
    }

    struct RecordFieldVisitor(Option<String>);

    impl tracing::field::Visit for RecordFieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "record" {
                self.0 = Some(format!("{value:?}"));
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "record" {
                self.0 = Some(value.to_string());
            }
        }
    }

    struct EventTapLayer(Arc<EventTap>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventTapLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = RecordFieldVisitor(None);
            event.record(&mut visitor);
            self.0
                .seen
                .lock()
                .expect("event tap lock")
                .push((event.metadata().target().to_string(), visitor.0));
        }
    }

    #[test]
    fn the_tracing_event_fires_at_the_capture_target_with_the_record_as_payload() {
        use tracing_subscriber::layer::SubscriberExt;

        let _guard = hub_lock().blocking_lock();
        let tap = Arc::new(EventTap::default());
        let subscriber =
            tracing_subscriber::Registry::default().with(EventTapLayer(Arc::clone(&tap)));
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let expected = serde_json::to_string(&record("cap-trace")).expect("a record serialises");

        tracing::subscriber::with_default(subscriber, || {
            emit_one(emission("cap-trace", None), None, None, &writer, &ring());
        });

        let seen = tap.seen.lock().expect("event tap lock");
        let capture_events: Vec<_> = seen
            .iter()
            .filter(|(target, _)| target == CAPTURE_TRACING_TARGET)
            .collect();
        assert_eq!(capture_events.len(), 1, "one event per record: {seen:?}");
        assert_eq!(capture_events[0].1.as_deref(), Some(expected.as_str()));
    }

    // ---- the file ----

    #[test]
    fn the_directory_writer_names_the_file_sets_its_mode_and_writes_the_record_byte_for_byte() {
        let dir = TempDir::new("write");
        let document = serde_json::to_vec(&record("cap-file")).expect("a record serialises");
        let name = capture_file_name(TIMESTAMP, REQUEST_ID);
        assert_eq!(name, expected_file_name());

        let path = write_capture_file(dir.path(), &name, &document).expect("the write succeeds");
        assert_eq!(path, dir.path().join(&name));
        let metadata = std::fs::metadata(&path).expect("the file exists");
        assert_eq!(metadata.permissions().mode() & 0o777, CAPTURE_FILE_MODE);
        assert_eq!(std::fs::read(&path).expect("the file reads"), document);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .expect("dir lists")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec![name], "no temporary file survives the write");
    }

    #[test]
    fn an_existing_name_is_refused_and_left_untouched() {
        let dir = TempDir::new("exists");
        let name = expected_file_name();
        std::fs::write(dir.path().join(&name), b"the earlier document").expect("pre-create");

        let error = write_capture_file(dir.path(), &name, b"{\"new\":true}")
            .expect_err("create_new refuses an existing name");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(dir.path().join(&name)).expect("the file reads"),
            b"the earlier document"
        );
        let count = std::fs::read_dir(dir.path()).expect("dir lists").count();
        assert_eq!(count, 1, "no temporary file survives the refusal");
    }

    #[test]
    fn capture_file_names_are_recognised_and_sanitised() {
        assert!(is_capture_file_name(&expected_file_name()));
        assert!(is_capture_file_name(
            "20260101T000000.000000000Z-req-with-dashes.json"
        ));
        assert!(!is_capture_file_name("notes.json"));
        assert!(!is_capture_file_name("2026-01-01T00:00:00Z-abc.json"));
        assert!(!is_capture_file_name(&format!(
            ".{}.tmp",
            expected_file_name()
        )));
        assert!(!is_capture_file_name("20260101T000000.000000000Z-.json"));

        let hostile = capture_file_name(TIMESTAMP, "../../etc/passwd\n");
        assert_eq!(hostile, "20260101T000000.123456789Z-....etcpasswd.json");
        assert!(!hostile.contains('/'));
        assert!(is_capture_file_name(&hostile));
        assert!(capture_file_name("not a timestamp", "id").ends_with("-id.json"));
        assert!(capture_file_name(TIMESTAMP, "///").ends_with("-unknown.json"));
    }

    // ---- pruning ----

    fn write_named(dir: &Path, name: &str, len: usize) {
        std::fs::write(dir.join(name), vec![b'x'; len]).expect("test setup: file writes");
    }

    #[test]
    fn pruning_removes_the_oldest_first_keeps_the_newest_and_ignores_foreign_files() {
        let dir = TempDir::new("prune");
        let oldest = "20260101T000000.000000000Z-a.json";
        let middle = "20260101T000001.000000000Z-b.json";
        let newest = "20260101T000002.000000000Z-c.json";
        write_named(dir.path(), oldest, 100);
        write_named(dir.path(), middle, 100);
        write_named(dir.path(), newest, 100);
        write_named(dir.path(), "notes.txt", 1000);
        write_named(dir.path(), "operator.json", 1000);

        let removed = prune_capture_dir(dir.path(), 150, newest).expect("prune runs");
        assert_eq!(removed, 2);
        assert!(!dir.path().join(oldest).exists(), "the oldest went first");
        assert!(!dir.path().join(middle).exists());
        assert!(dir.path().join(newest).exists(), "the newest survives");
        assert!(
            dir.path().join("notes.txt").exists(),
            "not a .json: never touched"
        );
        assert!(
            dir.path().join("operator.json").exists(),
            "a .json this writer did not produce is never touched"
        );
    }

    #[test]
    fn pruning_under_budget_removes_nothing_and_a_pass_is_bounded() {
        let dir = TempDir::new("prune-bounded");
        for i in 0..(CAPTURE_PRUNE_MAX_REMOVALS + 10) {
            write_named(
                dir.path(),
                &format!("20260101T{:06}.000000000Z-r.json", i),
                10,
            );
        }
        assert_eq!(
            prune_capture_dir(dir.path(), u64::MAX, "").expect("prune runs"),
            0
        );
        let removed = prune_capture_dir(dir.path(), 0, "").expect("prune runs");
        assert_eq!(removed, CAPTURE_PRUNE_MAX_REMOVALS);
        let left = std::fs::read_dir(dir.path()).expect("dir lists").count();
        assert_eq!(left, 10);
    }

    #[test]
    fn the_writer_thread_writes_then_prunes_to_the_rules_budget() {
        let _guard = hub_lock().blocking_lock();
        let dir = TempDir::new("thread");
        let older = "20260101T000000.000000000Z-old.json";
        write_named(dir.path(), older, 100_000);
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let mut emission = emission("cap-thread", Some(dir.path()));
        emission.output.max_dir_bytes = Some(50_000);
        emit_one(emission, None, None, &writer, &ring());

        let path = dir.path().join(expected_file_name());
        let deadline = Instant::now() + Duration::from_secs(5);
        while (!path.exists() || dir.path().join(older).exists()) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(path.exists(), "the record was written");
        assert!(
            !dir.path().join(older).exists(),
            "the older file was pruned"
        );
        assert_eq!(dropped("cap-thread"), 0);
    }

    // ---- the drop path ----

    #[test]
    fn a_missing_directory_drops_counts_writes_nothing_and_does_not_panic() {
        let _guard = hub_lock().blocking_lock();
        let parent = TempDir::new("missing");
        let missing = parent.path().join("does-not-exist");
        let error = write_capture_file(&missing, &expected_file_name(), b"{}")
            .expect_err("a missing directory is not created");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!missing.exists(), "the writer never creates the directory");

        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        emit_one(
            emission("cap-missing", Some(&missing)),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(wait_for_drops("cap-missing", 1), 1);
        assert!(!missing.exists());
    }

    #[test]
    fn a_read_only_directory_drops_and_counts() {
        let _guard = hub_lock().blocking_lock();
        let dir = TempDir::new("readonly");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))
            .expect("test setup: chmod");
        // Root ignores directory modes, so the probe decides whether
        // this container can make a read-only directory at all.
        if std::fs::write(dir.path().join("probe"), b"x").is_ok() {
            eprintln!(
                "skipped: this process writes into a 0500 directory (running as root), \
                 so a read-only directory cannot be made here"
            );
            return;
        }

        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        emit_one(
            emission("cap-readonly", Some(dir.path())),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(wait_for_drops("cap-readonly", 1), 1);
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("dir lists").count(),
            0,
            "nothing was written"
        );
    }

    #[test]
    fn a_full_write_queue_drops_and_counts_rather_than_waiting() {
        let _guard = hub_lock().blocking_lock();
        let dir = TempDir::new("backpressure");
        // Capacity one and a receiver nobody drains: the first job
        // sits in the queue, the second has nowhere to go.
        let (writer, _rx) = CaptureDirWriter::channel(1, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let started = Instant::now();
        emit_one(
            emission("cap-full", Some(dir.path())),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(dropped("cap-full"), 0);
        emit_one(
            emission("cap-full", Some(dir.path())),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(dropped("cap-full"), 1);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the refusal is immediate, not a wait"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("dir lists").count(),
            0,
            "nothing reached the disk from the emit path"
        );
    }

    #[test]
    fn a_job_over_the_byte_budget_is_refused_and_counted() {
        let _guard = hub_lock().blocking_lock();
        let dir = TempDir::new("bytes");
        let (writer, _rx) = CaptureDirWriter::channel(8, 16);
        emit_one(
            emission("cap-bytes", Some(dir.path())),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(dropped("cap-bytes"), 1);
        assert_eq!(
            writer.queued_bytes.load(Ordering::Acquire),
            0,
            "a refusal releases its bytes"
        );
    }

    #[test]
    fn a_writer_that_never_started_refuses_every_job() {
        let _guard = hub_lock().blocking_lock();
        let (writer, rx) = CaptureDirWriter::channel(8, CAPTURE_DIR_QUEUE_MAX_BYTES);
        drop(rx);
        let dir = TempDir::new("gone");
        emit_one(
            emission("cap-gone", Some(dir.path())),
            None,
            None,
            &writer,
            &ring(),
        );
        assert_eq!(dropped("cap-gone"), 1);
    }

    // ---- the SQLite access-log database ----

    #[tokio::test]
    async fn a_capture_never_reaches_the_access_log_database() {
        let _guard = hub_lock().lock().await;
        log_sinks::install(&log_sinks::LogSinksConfig::default());
        let data_dir = TempDir::new("sqlite");
        let store = Arc::new(
            lorica_api::log_store::LogStore::open(data_dir.path()).expect("the store opens"),
        );
        let handle = lorica_api::log_writer::spawn_log_writer(Arc::clone(&store));
        let writer = CaptureDirWriter::spawn(4, CAPTURE_DIR_QUEUE_MAX_BYTES);
        let mut lane = log_sinks::register_lane("otlp", true, true, true, true);

        emit_one(emission("cap-sqlite", None), None, None, &writer, &ring());

        assert_eq!(
            lane.try_recv()
                .expect("the lane received the record")
                .kind(),
            SinkKind::Capture
        );
        // The barrier proves every write enqueued before it has been
        // persisted; the count says none was.
        handle.flush().await.expect("the writer is alive");
        assert_eq!(store.count().expect("the store counts"), 0);
        assert_eq!(dropped("cap-sqlite"), 0);
        log_sinks::install(&log_sinks::LogSinksConfig::default());
    }
}
