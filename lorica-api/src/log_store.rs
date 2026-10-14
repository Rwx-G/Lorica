//! SQLite-backed persistent store for access logs, WAF events, and
//! notification history. Used as the source of truth when present, with
//! [`crate::logs::LogBuffer`] as a transient fallback in tests.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;

use rusqlite::{params, Connection};

use crate::logs::{LogEntry, LogsQuery};

/// Capacity of the audit write queue that fronts
/// [`LogStore::insert_audit`].
///
/// At roughly 400 bytes per queued row the worst-case resident size is
/// under 2 MiB. Sized so a burst from a pipeline hammering the
/// automation plane is absorbed rather than dropped: SQLite commits
/// the chain at a few thousand rows per second, so 4096 buys about a
/// second of stall before the queue starts shedding.
pub const AUDIT_QUEUE_CAPACITY: usize = 4096;

/// The slots of the audit queue a sheddable row may never take: a
/// quarter of it, kept for the rows of mutations.
///
/// Every automation request lands a row, the refused and anonymous ones
/// included, so a flood that needs no credential could fill the whole
/// queue with rows about itself and shed the row of a write committing
/// beside it. A sheddable row ([`crate::audit::record_request`]) is
/// refused once only this reserve is left, and a mutation's row
/// ([`crate::audit::record`]) still has the reserve to itself: a
/// quarter of the queue is about a quarter of a second of chain
/// commits, far more mutations than the write budgets admit in one.
pub const AUDIT_QUEUE_RESERVED_FOR_MUTATIONS: usize = AUDIT_QUEUE_CAPACITY / 4;

/// The most audit rows the control plane keeps for any one follower
/// (backlog #72), enforced by [`LogStore::enforce_fanned_in_audit_cap`].
///
/// Retention ages a fanned-in row by when it ARRIVED, which bounds how
/// long a row stays but not how many a node can send inside the window:
/// a follower pushing full batches at its session's push cap for the
/// whole retention window would leave rate times window rows in
/// `access-log.db`, a file the fan-in storage watermark does not
/// measure. Audit rows are never shed on the way in, so this is where
/// "never shed" stops meaning "never bounded".
///
/// Sized so an honest node never meets it. Half a million rows over the
/// default 90-day audit retention is one row every fifteen seconds,
/// sustained for three months: operator mutations plus an automation
/// client polling a follower at a sane rate stay well below that, while
/// a node pushing full batches at the push cap passes it within
/// minutes. At the few hundred bytes a row the audit queue's sizing
/// assumes, it holds one node's share of the file to the low hundreds
/// of MiB, where the uncapped product was unbounded in practice.
///
/// Per node rather than for the whole table, for the reason the fan-in
/// store gives for its own per-node quota: a shared ceiling would let
/// one noisy node evict every quiet node's history.
///
/// The same figure bounds the node's fan-in backup: the first rows the
/// cap cuts from a chain are moved there rather than deleted, up to this
/// many over the node's lifetime, so one node holds at most twice this
/// in `access-log.db` (see [`LogStore::enforce_fanned_in_audit_cap`]).
pub const FANNED_IN_AUDIT_ROWS_PER_NODE: u64 = 500_000;

/// The action of the row the fan-in cap writes into this node's OWN
/// chain each time it cuts a follower's, followed by `:` and the
/// figures of the cut (see [`LogStore::enforce_fanned_in_audit_cap`]).
pub const FANNED_IN_AUDIT_CAP_ACTION: &str = "cluster.audit.cap_cut";

/// Rows one audit-chain lock hold reads or cuts: one verify chunk, one
/// step of a cap or retention cut.
///
/// `access-log.db` has one connection, and the access-log writer, the
/// audit writer and the fan-in ingest all wait on it. A walk that held
/// it for a whole 200,000-row chain put the access-log writer 25 s
/// behind (backlog #75, `lorica-api/tests/audit_fan_in_contention.rs`);
/// a hold of this many rows is a few milliseconds, which the writers'
/// queues absorb. Its own constant rather than the fan-in store's
/// retention chunk: each store's lock budget is decided where its lock
/// lives.
const AUDIT_CHUNK: i64 = 2_000;

/// How old an audit row is, for day-based retention: when this store
/// received it for a fanned-in row, its own timestamp for a local one
/// (the same clock). `received_at` is empty on rows older than the
/// column, which fall back to `timestamp`; both are RFC 3339 UTC, so the
/// string comparison is chronological.
///
/// One constant for the index and every query on it: SQLite uses an
/// expression index only for a query that spells the expression the
/// way the index does.
const AUDIT_AGE: &str = "COALESCE(NULLIF(received_at, ''), timestamp)";

/// Where the fan-in cap moves the oldest rows it cuts from a follower's
/// chain instead of deleting them (see
/// [`LogStore::enforce_fanned_in_audit_cap`]).
const FANNED_IN_BACKUP_TABLE: &str = "audit_log_fanned_in_backup";

/// The columns a row keeps when the cap moves it into
/// [`FANNED_IN_BACKUP_TABLE`]: all of them, its aggregated `id`
/// included, so a break the backup verify reports names the row an
/// operator saw before it moved.
const FANNED_IN_BACKUP_COLUMNS: &str = "id, node_id, origin_id, timestamp, operator_username, \
    operator_role, action, target_type, target_id, before_payload_hash, after_payload_hash, \
    ip, user_agent, prev_chain_hash, chain_hash, received_at";

/// One follower chain the fan-in cap cut, as
/// [`LogStore::enforce_fanned_in_audit_cap`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FannedInAuditCapCut {
    /// The follower whose chain was cut.
    pub node_id: String,
    /// Rows that left the chain, moved and deleted together.
    pub removed: u64,
    /// Of those, rows moved into the node's fan-in backup.
    pub backed_up: u64,
    /// The `origin_id` of the first row cut.
    pub first_origin_id: i64,
    /// The `origin_id` of the last row cut.
    pub last_origin_id: i64,
}

impl FannedInAuditCapCut {
    /// Rows the cut deleted outright, the backup being full or closed.
    pub fn deleted(&self) -> u64 {
        self.removed - self.backed_up
    }
}

/// Which table a chain walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainSegment {
    /// `audit_log`: a chain anchored on its seal, or on genesis.
    Live,
    /// [`FANNED_IN_BACKUP_TABLE`]: the run of rows the cap moved out of
    /// a follower's chain, anchored on its own first row.
    Backup,
}

impl ChainSegment {
    fn table(self) -> &'static str {
        match self {
            Self::Live => "audit_log",
            Self::Backup => FANNED_IN_BACKUP_TABLE,
        }
    }
}

/// Why a chain's prefix is cut, which decides what the cut does beside
/// removing the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CutCause {
    /// Day-based retention: the rows go and nothing else is written.
    Retention,
    /// The fan-in cap ([`LogStore::enforce_fanned_in_audit_cap`]): the
    /// oldest rows cut fill the node's fan-in backup, up to
    /// `backup_capacity` rows over its lifetime, and every chunk cut
    /// writes its [`FANNED_IN_AUDIT_CAP_ACTION`] record into this
    /// node's own chain.
    FanInCap { backup_capacity: u64 },
}

/// What one or more prefix cuts of a chain took.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PrefixCut {
    /// Rows that left the chain.
    removed: u64,
    /// Of those, rows moved into the fan-in backup.
    backed_up: u64,
    /// Chain position of the first row cut.
    first: Option<i64>,
    /// Chain position of the last row cut.
    last: Option<i64>,
}

impl PrefixCut {
    fn absorb(&mut self, next: PrefixCut) {
        self.removed += next.removed;
        self.backed_up += next.backed_up;
        self.first = self.first.or(next.first);
        self.last = next.last.or(self.last);
    }
}

/// One item on the audit write queue.
enum AuditWrite {
    /// A row to chain and persist.
    Row(Box<crate::audit::NewAuditEntry>),
    /// Flush barrier: when the consumer reaches it, every row enqueued
    /// before it is on disk, and the ack fires. The seam tests and the
    /// CLI use it; nothing on the request path does.
    Barrier(tokio::sync::oneshot::Sender<()>),
}

/// Aggregated WAF-event statistics returned by
/// [`LogStore::waf_event_stats`]: `(total, total_24h, by_category)`
/// where `by_category` is `(category, count)` pairs sorted high-to-low.
pub type WafEventStats = (u64, u64, Vec<(String, u64)>);

/// What one retention pass removed, and how much of it the fan-in drain
/// had not sent yet (backlog #76).
///
/// A follower keeps its own log and a cursor marking how far the drain
/// has pushed rows to the control plane. Retention deletes the oldest
/// rows whether or not the drain has reached them, so a partition longer
/// than local retention silently shortens the fleet view. `undrained` is
/// the part of `deleted` the control plane will now never see.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionOutcome {
    /// Rows the pass deleted.
    pub deleted: u64,
    /// Of those, rows the drain cursor had not passed.
    pub undrained: u64,
}

/// One access-log row on its way out to the cluster telemetry drain
/// (Story 9.6).
///
/// Deliberately NOT `LogEntry`: that type is the dashboard's shape and
/// carries what a dashboard needs. This one mirrors the wire message
/// exactly, so the drain is a field-for-field move with no judgement
/// in the middle, and a column added to one side fails to compile on
/// the other.
///
/// No node identity: the control plane stamps that from the session
/// (Story 9.6 decision D2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRowForFanIn {
    /// RFC 3339, as recorded locally.
    pub timestamp: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request host.
    pub host: String,
    /// Response status.
    pub status: u32,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Backend that served it.
    pub backend: String,
    /// Error text, empty when there was none.
    pub error: String,
    /// Client address as resolved locally.
    pub client_ip: String,
    /// Whether `client_ip` came from a forwarded header.
    pub is_xff: bool,
    /// The proxy that supplied the forwarded header.
    pub xff_proxy_ip: String,
    /// Origin marker.
    pub source: String,
    /// Correlation id.
    pub request_id: String,
}

/// One WAF event on its way out to the cluster telemetry drain
/// (Story 9.6). See [`AccessRowForFanIn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WafRowForFanIn {
    /// Rule that matched.
    pub rule_id: u32,
    /// Human-readable rule description.
    pub description: String,
    /// Rule category.
    pub category: String,
    /// Rule severity.
    pub severity: u32,
    /// Which part of the request matched.
    pub matched_field: String,
    /// The matching value, already truncated when it was recorded.
    pub matched_value: String,
    /// RFC 3339, as recorded locally.
    pub timestamp: String,
    /// Client address.
    pub client_ip: String,
    /// Route hostname the event fired on.
    pub route_hostname: String,
    /// What the WAF did.
    pub action: String,
}

/// Whether `table` has a column named `column`. `false` when the table
/// itself is absent.
fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2",
        params![table, column],
        |row| row.get::<_, i64>(0),
    )
    .map(|count| count > 0)
}

/// Add `column` to `table` unless it is already there, and fail on
/// anything else.
///
/// Replaces an `ALTER TABLE` whose result was discarded, which hid every
/// failure behind the one it meant to tolerate (the column already
/// existing). An ALTER that fails while the column is now present lost
/// a race with another process opening the same file (the supervisor
/// and every worker open it), and that is the only failure taken as
/// success. A local twin of the helper in `lorica-config`'s store
/// rather than a call into it: that one is private to the config
/// schema. `table`, `column` and `definition` are constants of
/// [`LogStore::open`], never input, which is what makes the
/// interpolation safe.
fn add_column_if_absent(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), String> {
    let failed = |e: rusqlite::Error| format!("failed to add column {table}.{column}: {e}");
    if column_exists(conn, table, column).map_err(failed)? {
        return Ok(());
    }
    match conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    ) {
        Ok(_) => Ok(()),
        Err(e) if column_exists(conn, table, column).map_err(failed)? => {
            tracing::debug!(error = %e, table, column, "column added concurrently by another process");
            Ok(())
        }
        Err(e) => Err(failed(e)),
    }
}

/// Persistent log database wrapper. Cheaply cloneable through `Arc<LogStore>`.
pub struct LogStore {
    /// Shared with the audit consumer thread, which therefore cannot
    /// hold an `Arc<LogStore>`: that would be a cycle keeping the
    /// store alive forever and the thread with it.
    conn: Arc<Mutex<Connection>>,
    /// Producer end of the audit write queue. Dropping the last
    /// `LogStore` closes it, which is how the consumer thread learns
    /// to drain and exit.
    audit_tx: tokio::sync::mpsc::Sender<AuditWrite>,
    /// The last [`LogStore::waf_event_stats`] and when it was computed,
    /// read by [`LogStore::waf_event_stats_within`]. One entry whatever
    /// the traffic: the per-category list holds one row per rule
    /// category the table has ever recorded.
    waf_stats_cache: Mutex<Option<(std::time::Instant, WafEventStats)>>,
    /// Moved by every write that empties `waf_events`, so a computation
    /// that raced one is not cached over the emptied table.
    waf_stats_generation: std::sync::atomic::AtomicU64,
}

impl LogStore {
    /// Open or create the access log database in the given directory.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let db_path = data_dir.join("access-log.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("failed to open access log database: {e}"))?;

        // Before any DDL, not after it: the supervisor and every worker
        // open this file, possibly together, and without a busy timeout
        // a schema write that meets another process's lock fails on the
        // spot with "database is locked" instead of waiting its turn.
        conn.execute_batch(
            "PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;",
        )
        .map_err(|e| format!("failed to set access log pragmas: {e}"))?;

        // Schema rule for every table below. On a file an older release
        // created, `CREATE TABLE IF NOT EXISTS` does nothing, so the table
        // keeps the columns that release gave it whatever the CREATE says.
        // A column some released file lacks is therefore added by
        // `add_column_if_absent`, and every statement naming it, an index
        // above all, runs after that call and never in the CREATE batch.
        // The 1.7.0 audit indexes broke that rule and failed the whole
        // open on every file 1.6.0 had written (`log_store_upgrade.rs`).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                host TEXT NOT NULL,
                status INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                backend TEXT NOT NULL,
                error TEXT,
                client_ip TEXT NOT NULL DEFAULT '',
                is_xff INTEGER NOT NULL DEFAULT 0,
                xff_proxy_ip TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);
            CREATE INDEX IF NOT EXISTS idx_access_logs_status ON access_logs(status);
            CREATE INDEX IF NOT EXISTS idx_access_logs_host_timestamp ON access_logs(host, timestamp);",
        )
        .map_err(|e| format!("failed to initialize access log schema: {e}"))?;

        // `request_id` arrived in 1.1.0; the other four predate 1.0.0 and
        // are kept for files from before the first release.
        for (column, definition) in [
            ("client_ip", "TEXT NOT NULL DEFAULT ''"),
            ("is_xff", "INTEGER NOT NULL DEFAULT 0"),
            ("xff_proxy_ip", "TEXT NOT NULL DEFAULT ''"),
            ("source", "TEXT NOT NULL DEFAULT ''"),
            ("request_id", "TEXT NOT NULL DEFAULT ''"),
        ] {
            add_column_if_absent(&conn, "access_logs", column, definition)?;
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS waf_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id INTEGER NOT NULL,
                description TEXT NOT NULL,
                category TEXT NOT NULL,
                severity INTEGER NOT NULL,
                matched_field TEXT NOT NULL,
                matched_value TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL DEFAULT '',
                route_hostname TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_waf_events_category ON waf_events(category);",
        )
        .map_err(|e| format!("failed to initialize waf events schema: {e}"))?;
        // Every released file already has these three; kept for files
        // from before the first release.
        for (column, definition) in [
            ("client_ip", "TEXT NOT NULL DEFAULT ''"),
            ("route_hostname", "TEXT NOT NULL DEFAULT ''"),
            ("action", "TEXT NOT NULL DEFAULT ''"),
        ] {
            add_column_if_absent(&conn, "waf_events", column, definition)?;
        }

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notification_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '{}',
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notif_history_timestamp ON notification_history(timestamp);",
        )
        .map_err(|e| format!("failed to initialize notification history schema: {e}"))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL DEFAULT '',
                origin_id INTEGER NOT NULL DEFAULT 0,
                timestamp TEXT NOT NULL,
                operator_username TEXT NOT NULL,
                operator_role TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                before_payload_hash TEXT NOT NULL DEFAULT '',
                after_payload_hash TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                prev_chain_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
            CREATE INDEX IF NOT EXISTS idx_audit_log_operator ON audit_log(operator_username);
            CREATE TABLE IF NOT EXISTS audit_log_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )
        .map_err(|e| format!("failed to initialize audit log schema: {e}"))?;

        // Migrate: the fan-in columns (Story 9.9 AC #2), absent from
        // every file 1.6.0 wrote. Both default to the local-row value,
        // so the rows already there join this node's own chain with no
        // backfill and read exactly as they did.
        add_column_if_absent(&conn, "audit_log", "node_id", "TEXT NOT NULL DEFAULT ''")?;
        add_column_if_absent(
            &conn,
            "audit_log",
            "origin_id",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // When a fanned-in row ARRIVED, set by this store, never by the
        // origin. Retention cuts fanned-in chains on it rather than on
        // `timestamp`, which is a string the origin node chose: a
        // node stamping its rows in the far future would otherwise
        // hold them here forever (Epic 9 close, security audit). Empty
        // on local rows and on rows written before the column existed;
        // retention falls back to `timestamp` for those.
        add_column_if_absent(
            &conn,
            "audit_log",
            "received_at",
            "TEXT NOT NULL DEFAULT ''",
        )?;

        // Every index naming a fan-in column, after the migrations that
        // add them.
        //
        // `uq_audit_log_origin` is PARTIAL on purpose. Every local row is
        // `('', 0)`, so a plain unique index would refuse the second
        // local audit entry ever written. Restricted to fanned-in rows it
        // is what makes the fan-in insert idempotent, so a batch re-sent
        // after a lost acknowledgement stores nothing twice.
        //
        // `idx_audit_log_node_age` reads `received_at` through the age
        // expression. Day-based retention finds each chain's last expired
        // row through it, in the expired range alone: without it every
        // hourly pass read every row of every chain under the lock.
        //
        // The fan-in backup keeps every column of a row the cap moved,
        // under the same unique `(node_id, origin_id)` its chain had.
        conn.execute_batch(&format!(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_node ON audit_log(node_id, origin_id);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_log_origin
                ON audit_log(node_id, origin_id) WHERE node_id != '';
            CREATE INDEX IF NOT EXISTS idx_audit_log_node_age
                ON audit_log(node_id, {AUDIT_AGE}, origin_id);
            CREATE TABLE IF NOT EXISTS {FANNED_IN_BACKUP_TABLE} (
                id INTEGER PRIMARY KEY,
                node_id TEXT NOT NULL,
                origin_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                operator_username TEXT NOT NULL,
                operator_role TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                before_payload_hash TEXT NOT NULL DEFAULT '',
                after_payload_hash TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                prev_chain_hash TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                received_at TEXT NOT NULL DEFAULT ''
            );
            CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_backup_origin
                ON {FANNED_IN_BACKUP_TABLE}(node_id, origin_id);
            CREATE INDEX IF NOT EXISTS idx_audit_backup_age
                ON {FANNED_IN_BACKUP_TABLE}(node_id, {AUDIT_AGE}, origin_id);"
        ))
        .map_err(|e| format!("failed to initialize the audit fan-in schema: {e}"))?;

        let conn = Arc::new(Mutex::new(conn));
        let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(AUDIT_QUEUE_CAPACITY);
        Self::spawn_audit_writer(Arc::clone(&conn), audit_rx);
        Ok(Self {
            conn,
            audit_tx,
            waf_stats_cache: Mutex::new(None),
            waf_stats_generation: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Spawn the single consumer that owns audit chain writes.
    ///
    /// ONE consumer, never a pool: `insert_audit` chains each row to
    /// the previous row's hash, so the chain only means anything in
    /// write order. A second consumer would fork it.
    ///
    /// A plain OS thread rather than a tokio task, matching
    /// [`crate::log_writer`]: [`LogStore::open`] runs in the daemon,
    /// in a worker, and in the CLI, sometimes with no runtime current,
    /// and `insert_audit` is a blocking SQLite commit that has no
    /// business on a runtime thread. The thread exits when the last
    /// [`LogStore`] drops and the queue has drained.
    ///
    /// No batching, unlike the access-log writer: each row's
    /// `prev_chain_hash` is the previous row's `chain_hash`, computed
    /// inside the transaction, so one row is one transaction by
    /// construction. Getting the commit off the caller's thread is the
    /// whole win here; folding commits together is not available.
    fn spawn_audit_writer(
        conn: Arc<Mutex<Connection>>,
        mut rx: tokio::sync::mpsc::Receiver<AuditWrite>,
    ) {
        let spawned = std::thread::Builder::new()
            .name("lorica-audit-writer".into())
            .spawn(move || {
                while let Some(write) = rx.blocking_recv() {
                    match write {
                        AuditWrite::Row(entry) => Self::append_local_audit(&conn, &entry),
                        AuditWrite::Barrier(ack) => {
                            let _ = ack.send(());
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            // Thread creation only fails on resource exhaustion. The
            // store stays usable; every audit row then counts as a
            // drop once the queue fills, which the metric surfaces.
            tracing::error!(error = %e, "failed to spawn the audit writer thread; audit rows will be dropped");
        }
    }

    /// Commit one row to this node's own chain and emit its
    /// `lorica::audit` event: what the audit writer does with each row
    /// it receives.
    ///
    /// The writer's failure policy, unchanged by the queue: an insert
    /// failure is counted, logged and swallowed, and the event still
    /// goes out, with an empty `chain_hash`. The mutation the row
    /// records has already happened.
    fn append_local_audit(conn: &Mutex<Connection>, entry: &crate::audit::NewAuditEntry) {
        match Self::insert_audit_into(conn, entry) {
            Ok((_id, chain_hash)) => {
                crate::audit::emit_stored_event(entry, &chain_hash);
            }
            Err(e) => {
                crate::metrics::inc_audit_insert_failed();
                tracing::error!(error = %e, "audit log insert failed");
                crate::audit::emit_stored_event(entry, "");
            }
        }
    }

    /// Hand one audit row to the write queue. Never blocks.
    ///
    /// On a full queue (or a dead consumer) the row comes back to the
    /// caller, which counts and logs the drop. Blocking here is the
    /// outage this queue exists to prevent: a caller waiting on a full
    /// audit queue is a management API that stops answering because
    /// SQLite is slow.
    ///
    /// # Errors
    ///
    /// Returns the entry unwritten when the queue is full or closed.
    /// Boxed, because the row is a dozen `String`s and an error this
    /// size inflates every `Result` on the path back.
    pub fn enqueue_audit(
        &self,
        entry: Box<crate::audit::NewAuditEntry>,
    ) -> Result<(), Box<crate::audit::NewAuditEntry>> {
        match self.audit_tx.try_send(AuditWrite::Row(entry)) {
            Ok(()) => Ok(()),
            Err(rejected) => match rejected.into_inner() {
                AuditWrite::Row(entry) => Err(entry),
                // The channel hands back exactly what was offered, and
                // what was offered on this line is a Row.
                AuditWrite::Barrier(_) => Ok(()),
            },
        }
    }

    /// [`LogStore::enqueue_audit`] for a row that may be shed first: it
    /// is refused, as a full queue refuses it, once only
    /// [`AUDIT_QUEUE_RESERVED_FOR_MUTATIONS`] slots are left.
    ///
    /// The free-slot reading and the send are two steps, so sheddable
    /// rows racing each other can each read the same free slot; the
    /// reserve is a floor they cross by at most one row per concurrent
    /// caller, not a wall. Never blocks.
    ///
    /// # Errors
    ///
    /// Returns the entry unwritten when the reserve is all that is
    /// left, or when the queue is full or closed.
    pub fn enqueue_audit_sheddable(
        &self,
        entry: Box<crate::audit::NewAuditEntry>,
    ) -> Result<(), Box<crate::audit::NewAuditEntry>> {
        if self.audit_tx.capacity() <= AUDIT_QUEUE_RESERVED_FOR_MUTATIONS {
            return Err(entry);
        }
        self.enqueue_audit(entry)
    }

    /// Wait until every audit row enqueued before this call is on disk.
    ///
    /// Unlike [`LogStore::enqueue_audit`] this applies backpressure
    /// rather than dropping: it is called where durability is the
    /// point and latency is not, which is the `lorica cluster leave`
    /// CLI (the process exits right after) and the tests that read the
    /// chain back. Never on the request path.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` when the consumer thread is gone, which
    /// callers read as "nothing left to flush".
    pub async fn flush_audit(&self) -> Result<(), ()> {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        self.audit_tx
            .send(AuditWrite::Barrier(ack_tx))
            .await
            .map_err(|_| ())?;
        ack_rx.await.map_err(|_| ())
    }

    /// Stall the audit writer by taking the connection it needs.
    ///
    /// The only way to fill a queue whose consumer drains it as fast
    /// as it is fed. Test-only: nothing in production has a reason to
    /// hold this lock across awaits.
    #[cfg(test)]
    pub(crate) fn block_audit_writer_for_test(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// Insert a log entry.
    /// Append one access log entry to the database.
    pub fn insert(&self, entry: &LogEntry) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO access_logs (timestamp, method, path, host, status, latency_ms, backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                entry.timestamp,
                entry.method,
                entry.path,
                entry.host,
                entry.status,
                entry.latency_ms as i64,
                entry.backend,
                entry.error,
                entry.client_ip,
                entry.is_xff as i64,
                entry.xff_proxy_ip,
                entry.source,
                entry.request_id,
            ],
        )
        .map_err(|e| format!("failed to insert access log entry: {e}"))?;
        Ok(())
    }

    /// Append a batch of access log entries in one transaction.
    ///
    /// One commit (and thus one WAL fsync) per batch instead of one
    /// per request. Called by the background log writer
    /// (`crate::log_writer`), never from the request path (backlog
    /// #24). A failed batch is reported as a whole; individual rows
    /// are not retried.
    pub fn insert_batch(&self, entries: &[LogEntry]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to open access log transaction: {e}"))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO access_logs (timestamp, method, path, host, status, latency_ms, backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                )
                .map_err(|e| format!("failed to prepare access log insert: {e}"))?;
            for entry in entries {
                stmt.execute(params![
                    entry.timestamp,
                    entry.method,
                    entry.path,
                    entry.host,
                    entry.status,
                    entry.latency_ms as i64,
                    entry.backend,
                    entry.error,
                    entry.client_ip,
                    entry.is_xff as i64,
                    entry.xff_proxy_ip,
                    entry.source,
                    entry.request_id,
                ])
                .map_err(|e| format!("failed to insert access log entry: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("failed to commit access log batch: {e}"))?;
        Ok(())
    }

    /// Query log entries with pagination and filters; returns
    /// `(rows, total_match_count)`, the rows oldest first.
    pub fn query(&self, params: &LogsQuery) -> Result<(Vec<LogEntry>, usize), String> {
        let (entries, total) = self.query_counting(params, true)?;
        Ok((entries, total.unwrap_or_default()))
    }

    /// [`LogStore::query`]'s rows without its match count.
    ///
    /// The count is a second pass over every row the filters match, and
    /// with `search` five unanchored `LIKE`s per retained row, all under
    /// the connection mutex the access-log writer and the audit drain
    /// need. A caller that answers no total (the automation plane's
    /// `/logs`, which pages with `has_more`) has no reason to pay it.
    pub fn query_rows(&self, params: &LogsQuery) -> Result<Vec<LogEntry>, String> {
        Ok(self.query_counting(params, false)?.0)
    }

    /// The rows, and the match count when `with_total`.
    fn query_counting(
        &self,
        params: &LogsQuery,
        with_total: bool,
    ) -> Result<(Vec<LogEntry>, Option<usize>), String> {
        let conn = self.conn.lock();

        let mut conditions = Vec::new();
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref route) = params.route {
            conditions.push(format!("host LIKE ? {LIKE_ESCAPE}"));
            bind_values.push(Box::new(format!("%{}%", like_operand(route))));
        }
        if let Some(status) = params.status {
            conditions.push("status = ?".to_string());
            bind_values.push(Box::new(status as i64));
        }
        if let Some(min) = params.status_min {
            conditions.push("status >= ?".to_string());
            bind_values.push(Box::new(min as i64));
        }
        if let Some(max) = params.status_max {
            conditions.push("status <= ?".to_string());
            bind_values.push(Box::new(max as i64));
        }
        if let Some(ref time_from) = params.time_from {
            conditions.push("timestamp >= ?".to_string());
            bind_values.push(Box::new(time_from.clone()));
        }
        if let Some(ref time_to) = params.time_to {
            conditions.push("timestamp <= ?".to_string());
            bind_values.push(Box::new(time_to.clone()));
        }
        if let Some(after_id) = params.after_id {
            conditions.push("id > ?".to_string());
            bind_values.push(Box::new(after_id as i64));
        }
        if let Some(before_id) = params.before_id {
            conditions.push("id < ?".to_string());
            bind_values.push(Box::new(i64::try_from(before_id).unwrap_or(i64::MAX)));
        }
        if let Some(ref ip) = params.client_ip {
            conditions.push(format!("client_ip LIKE ? {LIKE_ESCAPE}"));
            bind_values.push(Box::new(format!("{}%", like_operand(ip))));
        }
        if let Some(ref search) = params.search {
            let pattern = format!("%{}%", like_operand(search));
            conditions.push(format!(
                "(method LIKE ? {LIKE_ESCAPE} OR path LIKE ? {LIKE_ESCAPE} \
                 OR host LIKE ? {LIKE_ESCAPE} OR backend LIKE ? {LIKE_ESCAPE} \
                 OR error LIKE ? {LIKE_ESCAPE})"
            ));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit = params
            .limit
            .unwrap_or(200)
            .min(crate::logs::LOGS_QUERY_MAX_ROWS);

        let total = if with_total {
            let count_sql = format!("SELECT COUNT(*) FROM access_logs {where_clause}");
            let refs: Vec<&dyn rusqlite::types::ToSql> =
                bind_values.iter().map(|b| b.as_ref()).collect();
            Some(
                conn.query_row(&count_sql, refs.as_slice(), |row| row.get::<_, i64>(0))
                    .map_err(|e| format!("failed to count access logs: {e}"))?
                    as usize,
            )
        } else {
            None
        };

        let query_sql = format!(
            "SELECT id, timestamp, method, path, host, status, latency_ms, backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id \
             FROM access_logs {where_clause} ORDER BY id DESC LIMIT ?",
        );
        let mut query_bind: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for v in &bind_values {
            query_bind.push(copy_to_sql(v.as_ref()));
        }
        query_bind.push(Box::new(limit as i64));
        let query_refs: Vec<&dyn rusqlite::types::ToSql> =
            query_bind.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&query_sql)
            .map_err(|e| format!("failed to prepare access log query: {e}"))?;
        let rows = stmt
            .query_map(query_refs.as_slice(), |row| {
                Ok(LogEntry {
                    id: row.get::<_, i64>(0)? as u64,
                    timestamp: row.get(1)?,
                    method: row.get(2)?,
                    path: row.get(3)?,
                    host: row.get(4)?,
                    status: row.get::<_, i64>(5)? as u16,
                    latency_ms: row.get::<_, i64>(6)? as u64,
                    backend: row.get(7)?,
                    error: row.get(8)?,
                    client_ip: row.get(9)?,
                    is_xff: row.get::<_, i64>(10)? != 0,
                    xff_proxy_ip: row.get::<_, String>(11).unwrap_or_default(),
                    source: row.get::<_, String>(12).unwrap_or_default(),
                    request_id: row.get::<_, String>(13).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query access logs: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("failed to read access log row: {e}"))?);
        }
        entries.reverse();

        Ok((entries, total))
    }

    /// Query entries for export (up to `max` rows, no pagination). Returns oldest first.
    /// Stream up to `max` matching entries for export (CSV / JSON).
    pub fn query_export(&self, params: &LogsQuery, max: usize) -> Result<Vec<LogEntry>, String> {
        let conn = self.conn.lock();

        let mut conditions = Vec::new();
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref route) = params.route {
            conditions.push(format!("host LIKE ? {LIKE_ESCAPE}"));
            bind_values.push(Box::new(format!("%{}%", like_operand(route))));
        }
        if let Some(status) = params.status {
            conditions.push("status = ?".to_string());
            bind_values.push(Box::new(status as i64));
        }
        if let Some(min) = params.status_min {
            conditions.push("status >= ?".to_string());
            bind_values.push(Box::new(min as i64));
        }
        if let Some(max_s) = params.status_max {
            conditions.push("status <= ?".to_string());
            bind_values.push(Box::new(max_s as i64));
        }
        if let Some(ref time_from) = params.time_from {
            conditions.push("timestamp >= ?".to_string());
            bind_values.push(Box::new(time_from.clone()));
        }
        if let Some(ref time_to) = params.time_to {
            conditions.push("timestamp <= ?".to_string());
            bind_values.push(Box::new(time_to.clone()));
        }
        if let Some(ref search) = params.search {
            let pattern = format!("%{}%", like_operand(search));
            conditions.push(format!(
                "(method LIKE ? {LIKE_ESCAPE} OR path LIKE ? {LIKE_ESCAPE} \
                 OR host LIKE ? {LIKE_ESCAPE} OR backend LIKE ? {LIKE_ESCAPE} \
                 OR error LIKE ? {LIKE_ESCAPE})"
            ));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern.clone()));
            bind_values.push(Box::new(pattern));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query_sql = format!(
            "SELECT id, timestamp, method, path, host, status, latency_ms, backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id \
             FROM access_logs {where_clause} ORDER BY id ASC LIMIT ?",
        );
        bind_values.push(Box::new(max as i64));
        let refs: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&query_sql)
            .map_err(|e| format!("failed to prepare export query: {e}"))?;
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(LogEntry {
                    id: row.get::<_, i64>(0)? as u64,
                    timestamp: row.get(1)?,
                    method: row.get(2)?,
                    path: row.get(3)?,
                    host: row.get(4)?,
                    status: row.get::<_, i64>(5)? as u16,
                    latency_ms: row.get::<_, i64>(6)? as u64,
                    backend: row.get(7)?,
                    error: row.get(8)?,
                    client_ip: row.get(9)?,
                    is_xff: row.get::<_, i64>(10)? != 0,
                    xff_proxy_ip: row.get::<_, String>(11).unwrap_or_default(),
                    source: row.get::<_, String>(12).unwrap_or_default(),
                    request_id: row.get::<_, String>(13).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query export logs: {e}"))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| format!("failed to read export log row: {e}"))?);
        }
        Ok(entries)
    }

    /// The `(MIN, MAX)` ids of `access_logs`, as two scalar subqueries:
    /// SQLite answers a lone `MIN` or `MAX` of the rowid with one seek
    /// at an end of the table, and both in one select with a scan of
    /// every row.
    const ACCESS_LOG_SPAN_SQL: &'static str =
        "SELECT (SELECT MIN(id) FROM access_logs), (SELECT MAX(id) FROM access_logs)";

    /// [`LogStore::ACCESS_LOG_SPAN_SQL`] for `waf_events`.
    const WAF_EVENTS_SPAN_SQL: &'static str =
        "SELECT (SELECT MIN(id) FROM waf_events), (SELECT MAX(id) FROM waf_events)";

    /// Delete entries older than the retention limit, keeping at most `max_entries` rows.
    /// Trim the access log table to the most recent `max_entries`. Returns the number deleted.
    ///
    /// Sized from `MIN(id)` / `MAX(id)` (two `O(log n)` seeks on the
    /// PRIMARY KEY rowid, see [`LogStore::ACCESS_LOG_SPAN_SQL`]) instead
    /// of `SELECT COUNT(*)` (which scans the whole table and could
    /// freeze the writer's `Mutex<Connection>` for hundreds of
    /// milliseconds at millions of rows).
    /// `(MAX - MIN + 1)` over-estimates after deletes leave gaps in
    /// the id sequence, which is fine here: trimming slightly more
    /// aggressively than strictly needed cannot violate the retention
    /// contract. The actual DELETE remains exact via the inner ORDER
    /// BY + LIMIT subquery.
    pub fn enforce_retention(
        &self,
        max_entries: u64,
        drain_cursor: Option<u64>,
    ) -> Result<RetentionOutcome, String> {
        let conn = self.conn.lock();
        let bounds: Option<(i64, i64)> = conn
            .query_row(Self::ACCESS_LOG_SPAN_SQL, [], |row| {
                let lo: Option<i64> = row.get(0)?;
                let hi: Option<i64> = row.get(1)?;
                Ok(lo.zip(hi))
            })
            .map_err(|e| format!("failed to compute access log bounds: {e}"))?;

        let approx_count = match bounds {
            None => 0u64,
            Some((lo, hi)) => (hi - lo + 1).max(0) as u64,
        };

        if approx_count <= max_entries {
            return Ok(RetentionOutcome::default());
        }

        let to_delete = (approx_count - max_entries) as i64;
        // Counted under the same lock as the delete, over exactly the
        // rows the delete targets, so the two figures cannot disagree.
        let undrained = match drain_cursor {
            Some(cursor) => conn
                .query_row(
                    "SELECT COUNT(*) FROM access_logs
                     WHERE id > ?1
                       AND id IN (SELECT id FROM access_logs ORDER BY id ASC LIMIT ?2)",
                    params![cursor as i64, to_delete],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|e| format!("failed to count undrained access rows: {e}"))?
                as u64,
            None => 0,
        };
        let deleted = conn
            .execute(
                "DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs ORDER BY id ASC LIMIT ?1)",
                params![to_delete],
            )
            .map_err(|e| format!("failed to enforce access log retention: {e}"))?;

        Ok(RetentionOutcome {
            deleted: deleted as u64,
            undrained,
        })
    }

    /// Clear all entries.
    /// Remove every access log row.
    pub fn clear(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM access_logs", [])
            .map_err(|e| format!("failed to clear access logs: {e}"))?;
        Ok(())
    }

    /// Get total entry count.
    /// Return the total number of access log rows in the database.
    pub fn count(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .map_err(|e| format!("failed to count access logs: {e}"))?;
        Ok(count as u64)
    }

    // ---- WAF Events ----

    /// Insert a WAF event.
    /// Persist a single WAF event for later querying via the events endpoint.
    pub fn insert_waf_event(&self, event: &lorica_waf::WafEvent) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT INTO waf_events (rule_id, description, category, severity, matched_field, matched_value, timestamp, client_ip, route_hostname, action)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.rule_id as i64,
                event.description,
                event.category.as_str(),
                event.severity as i64,
                event.matched_field,
                event.matched_value,
                event.timestamp,
                event.client_ip,
                event.route_hostname,
                event.action,
            ],
        )
        .map_err(|e| format!("failed to insert WAF event: {e}"))?;
        Ok(())
    }

    /// Persist a batch of WAF events in one transaction.
    ///
    /// Same shape as [`Self::insert_batch`]: one commit per batch,
    /// called only by the background log writer. Also covers the
    /// multi-rule case (one blocked request tripping 3-4 CRS rules)
    /// with a single mutex acquisition instead of one per event
    /// (supersedes audit M-8).
    pub fn insert_waf_events_batch(&self, events: &[lorica_waf::WafEvent]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to open WAF event transaction: {e}"))?;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO waf_events (rule_id, description, category, severity, matched_field, matched_value, timestamp, client_ip, route_hostname, action)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )
                .map_err(|e| format!("failed to prepare WAF event insert: {e}"))?;
            for event in events {
                stmt.execute(params![
                    event.rule_id as i64,
                    event.description,
                    event.category.as_str(),
                    event.severity as i64,
                    event.matched_field,
                    event.matched_value,
                    event.timestamp,
                    event.client_ip,
                    event.route_hostname,
                    event.action,
                ])
                .map_err(|e| format!("failed to insert WAF event: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("failed to commit WAF event batch: {e}"))?;
        Ok(())
    }

    /// Query WAF events, newest first. When `category` is provided, only
    /// events matching that category are returned (filtered at the SQL level
    /// so that `limit` applies to the filtered set, not the full table).
    /// Return up to `limit` recent WAF events, optionally filtered by category.
    pub fn list_waf_events(
        &self,
        limit: usize,
        category: Option<&str>,
    ) -> Result<Vec<lorica_waf::WafEvent>, String> {
        let conn = self.conn.lock();
        let (sql, params_vec): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = if let Some(cat) =
            category
        {
            (
                "SELECT rule_id, description, category, severity, matched_field, matched_value, timestamp, client_ip, route_hostname, action
                 FROM waf_events WHERE category = ?2 ORDER BY id DESC LIMIT ?1".to_string(),
                vec![Box::new(limit as i64), Box::new(cat.to_string())],
            )
        } else {
            (
                "SELECT rule_id, description, category, severity, matched_field, matched_value, timestamp, client_ip, route_hostname, action
                 FROM waf_events ORDER BY id DESC LIMIT ?1".to_string(),
                vec![Box::new(limit as i64)],
            )
        };
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("failed to prepare WAF events query: {e}"))?;
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();
        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                let cat_str: String = row.get(2)?;
                let category = cat_str
                    .parse::<lorica_waf::RuleCategory>()
                    .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
                Ok(lorica_waf::WafEvent {
                    rule_id: row.get::<_, i64>(0)? as u32,
                    description: row.get(1)?,
                    category,
                    severity: row.get::<_, i64>(3)? as u8,
                    matched_field: row.get(4)?,
                    matched_value: row.get(5)?,
                    timestamp: row.get(6)?,
                    client_ip: row.get::<_, String>(7).unwrap_or_default(),
                    route_hostname: row.get::<_, String>(8).unwrap_or_default(),
                    action: row.get::<_, String>(9).unwrap_or_default(),
                })
            })
            .map_err(|e| format!("failed to query WAF events: {e}"))?;
        let mut events = Vec::new();
        for r in rows {
            events.push(r.map_err(|e| format!("failed to read WAF event row: {e}"))?);
        }
        Ok(events)
    }

    /// Summarise WAF events via SQL aggregation : total count, rolling
    /// 24h count, and per-category counts (sorted high-to-low). Used by
    /// `/api/v1/waf/stats` so the stats are accurate regardless
    /// of table size. The previous implementation loaded up to
    /// 10 000 rows into memory to `.len()` them, which capped
    /// the dashboard counter at 10 000 once the retention window
    /// (100 000 rows) was in use.
    ///
    /// Returns `(total, total_24h, by_category)`. Once
    /// `waf_event_retention` caps the table, `total` plateaus near the
    /// cap and stops carrying signal ; `total_24h` counts only rows
    /// with a `timestamp` within the last 24 hours. RFC3339 TEXT
    /// compares lexicographically, so the `timestamp >= ?` bound rides
    /// the existing `idx_waf_events_timestamp` index.
    pub fn waf_event_stats(&self) -> Result<WafEventStats, String> {
        let conn = self.conn.lock();
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM waf_events", [], |row| row.get(0))
            .map_err(|e| format!("failed to count WAF events: {e}"))?;
        let cutoff_24h: String = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let total_24h: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM waf_events WHERE timestamp >= ?1",
                params![cutoff_24h],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to count 24h WAF events: {e}"))?;
        let mut stmt = conn
            .prepare(
                "SELECT category, COUNT(*) FROM waf_events
                 GROUP BY category ORDER BY 2 DESC",
            )
            .map_err(|e| format!("failed to prepare WAF stats query: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| format!("failed to query WAF stats: {e}"))?;
        let mut by_category = Vec::new();
        for r in rows {
            by_category.push(r.map_err(|e| format!("failed to read WAF stats row: {e}"))?);
        }
        Ok((total as u64, total_24h as u64, by_category))
    }

    /// [`LogStore::waf_event_stats`], answered from the last
    /// computation while it is younger than `max_age`.
    ///
    /// The aggregates are two `COUNT(*)` passes and a `GROUP BY` over
    /// the whole retained table under the connection mutex the access
    /// log writer and the audit drain share, and a caller polling them
    /// (a model asking the automation plane in a loop) paid that per
    /// call. Within `max_age` the answer is the one already computed:
    /// counters that are up to `max_age` old, and a table scanned at
    /// most once per `max_age` whoever asks. A clear drops the cached
    /// answer, so an emptied table never reads as its old counts.
    pub fn waf_event_stats_within(
        &self,
        max_age: std::time::Duration,
    ) -> Result<WafEventStats, String> {
        use std::sync::atomic::Ordering;
        if let Some((computed_at, stats)) = self.waf_stats_cache.lock().as_ref() {
            if computed_at.elapsed() < max_age {
                return Ok(stats.clone());
            }
        }
        let generation = self.waf_stats_generation.load(Ordering::Acquire);
        let computed_at = std::time::Instant::now();
        let stats = self.waf_event_stats()?;
        let mut cache = self.waf_stats_cache.lock();
        if self.waf_stats_generation.load(Ordering::Acquire) == generation {
            *cache = Some((computed_at, stats.clone()));
        }
        Ok(stats)
    }

    /// Remove every persisted WAF event row.
    pub fn clear_waf_events(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM waf_events", [])
            .map_err(|e| format!("failed to clear WAF events: {e}"))?;
        drop(conn);
        self.waf_stats_generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        *self.waf_stats_cache.lock() = None;
        Ok(())
    }

    /// Read up to `limit` access-log rows with an id strictly above
    /// `after_id`, oldest first, for the cluster telemetry drain
    /// (Story 9.6 AC #5/#7).
    ///
    /// This is what makes the shared store the fan-in queue rather
    /// than a second in-process ring buffer: the rows are already
    /// here, already written off the hot path by the log writer,
    /// already bounded by retention, and already visible to the
    /// supervisor across every worker process under WAL. A drain that
    /// reads them by cursor touches the request path not at all.
    ///
    /// Oldest first, unlike every other read on this store, because a
    /// cursor has to advance monotonically through history.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn access_rows_after(
        &self,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<(i64, AccessRowForFanIn)>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, timestamp, method, path, host, status, latency_ms, backend,
                        error, client_ip, is_xff, xff_proxy_ip, source, request_id
                 FROM access_logs WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )
            .map_err(|e| format!("failed to prepare the access-log drain: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    i64::try_from(after_id).unwrap_or(i64::MAX),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        AccessRowForFanIn {
                            timestamp: row.get(1)?,
                            method: row.get(2)?,
                            path: row.get(3)?,
                            host: row.get(4)?,
                            status: row.get::<_, i64>(5)? as u32,
                            latency_ms: row.get::<_, i64>(6)? as u64,
                            backend: row.get(7)?,
                            error: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                            client_ip: row.get(9)?,
                            is_xff: row.get::<_, i64>(10)? != 0,
                            xff_proxy_ip: row.get(11)?,
                            source: row.get(12)?,
                            request_id: row.get(13)?,
                        },
                    ))
                },
            )
            .map_err(|e| format!("failed to run the access-log drain: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a drained access row: {e}"))?);
        }
        Ok(out)
    }

    /// Read up to `limit` WAF events with an id strictly above
    /// `after_id`, oldest first (Story 9.6 AC #5/#7). See
    /// [`LogStore::access_rows_after`].
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn waf_rows_after(
        &self,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<(i64, WafRowForFanIn)>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT id, rule_id, description, category, severity, matched_field,
                        matched_value, timestamp, client_ip, route_hostname, action
                 FROM waf_events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
            )
            .map_err(|e| format!("failed to prepare the WAF drain: {e}"))?;
        let rows = stmt
            .query_map(
                rusqlite::params![
                    i64::try_from(after_id).unwrap_or(i64::MAX),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        WafRowForFanIn {
                            rule_id: row.get::<_, i64>(1)? as u32,
                            description: row.get(2)?,
                            category: row.get(3)?,
                            severity: row.get::<_, i64>(4)? as u32,
                            matched_field: row.get(5)?,
                            matched_value: row.get(6)?,
                            timestamp: row.get(7)?,
                            client_ip: row.get(8)?,
                            route_hostname: row.get(9)?,
                            action: row.get(10)?,
                        },
                    ))
                },
            )
            .map_err(|e| format!("failed to run the WAF drain: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a drained WAF row: {e}"))?);
        }
        Ok(out)
    }

    /// Local audit rows after `after_id`, oldest first, for the
    /// cluster drain (Story 9.9 AC #2).
    ///
    /// `node_id = ''` on purpose: a follower ships only its OWN audit
    /// rows. Without that clause a control plane demoted to a follower
    /// would re-ship every other node's rows it had aggregated, under
    /// its own session identity, and the receiving control plane would
    /// stamp them with the wrong node.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn audit_rows_after(
        &self,
        after_id: u64,
        limit: usize,
    ) -> Result<Vec<(i64, crate::audit::FannedInAuditRow)>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(Self::LOCAL_AUDIT_DRAIN_SQL)
            .map_err(|e| format!("failed to prepare the audit drain: {e}"))?;
        let rows = stmt
            .query_map(params![after_id as i64, limit as i64], |row| {
                let id: i64 = row.get(0)?;
                Ok((
                    id,
                    crate::audit::FannedInAuditRow {
                        // The origin id IS this row's local id. It is
                        // carried explicitly rather than inferred at
                        // the far end, where the aggregated id is a
                        // different number entirely.
                        origin_id: id,
                        timestamp: row.get(1)?,
                        operator_username: row.get(2)?,
                        operator_role: row.get(3)?,
                        action: row.get(4)?,
                        target_type: row.get(5)?,
                        target_id: row.get(6)?,
                        before_payload_hash: row.get(7)?,
                        after_payload_hash: row.get(8)?,
                        ip: row.get(9)?,
                        user_agent: row.get(10)?,
                        prev_chain_hash: row.get(11)?,
                        chain_hash: row.get(12)?,
                    },
                ))
            })
            .map_err(|e| format!("failed to run the audit drain: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read an audit row: {e}"))?);
        }
        Ok(out)
    }

    /// The highest LOCAL audit rowid currently stored. See
    /// [`LogStore::newest_access_id`].
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn newest_local_audit_id(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let id: Option<i64> = conn
            .query_row(Self::LOCAL_AUDIT_NEWEST_SQL, [], |row| row.get(0))
            .map_err(|e| format!("failed to read the newest audit id: {e}"))?;
        Ok(id.unwrap_or(0).max(0) as u64)
    }

    /// The highest access-log rowid currently stored, so a node that
    /// has never drained can start at the present instead of
    /// replaying everything retention still holds.
    ///
    /// `MIN`/`MAX` on the rowid, never a count.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn newest_access_id(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let id: Option<i64> = conn
            .query_row("SELECT MAX(id) FROM access_logs", [], |row| row.get(0))
            .map_err(|e| format!("failed to read the newest access id: {e}"))?;
        Ok(id.unwrap_or(0).max(0) as u64)
    }

    /// The highest WAF event rowid currently stored. See
    /// [`LogStore::newest_access_id`].
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn newest_waf_id(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let id: Option<i64> = conn
            .query_row("SELECT MAX(id) FROM waf_events", [], |row| row.get(0))
            .map_err(|e| format!("failed to read the newest WAF id: {e}"))?;
        Ok(id.unwrap_or(0).max(0) as u64)
    }

    /// Trim the WAF events table to roughly the most recent
    /// `max_entries`. Returns the number deleted.
    ///
    /// Sized from `MIN(id)` / `MAX(id)`, two `O(log n)` index seeks on
    /// the rowid ([`LogStore::WAF_EVENTS_SPAN_SQL`]), for exactly the
    /// reason the access-log path already
    /// documents: `SELECT COUNT(*)` scans the whole table and can
    /// freeze this store's single `Mutex<Connection>` for hundreds of
    /// milliseconds at millions of rows. This path counted until
    /// Story 9.6, which is why a retention pass could stall the
    /// ingest writer and fire its drop counter for a reason that had
    /// nothing to do with load.
    ///
    /// The estimate over-counts when ids are sparse (earlier deletes
    /// leave gaps), so a pass can under-delete on a table pruned
    /// before. That is the safe direction, and the next hourly pass
    /// catches up.
    ///
    /// Deleted in chunks with the lock RELEASED between them, so a
    /// large backlog does not hold the store against the writer for
    /// the whole pass.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read or delete failure.
    pub fn enforce_waf_retention(
        &self,
        max_entries: u64,
        drain_cursor: Option<u64>,
    ) -> Result<RetentionOutcome, String> {
        const CHUNK: i64 = 2_000;
        let mut outcome = RetentionOutcome::default();
        loop {
            let deleted = {
                let conn = self.conn.lock();
                let span: (Option<i64>, Option<i64>) = conn
                    .query_row(Self::WAF_EVENTS_SPAN_SQL, [], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .map_err(|e| format!("failed to size WAF events: {e}"))?;
                let (Some(min_id), Some(max_id)) = span else {
                    return Ok(outcome);
                };
                let estimated = (max_id - min_id + 1).max(0);
                if estimated <= max_entries as i64 {
                    return Ok(outcome);
                }
                let take = (estimated - max_entries as i64).min(CHUNK);
                // Counted under the same lock, over exactly the rows this
                // chunk is about to delete (backlog #76).
                if let Some(cursor) = drain_cursor {
                    outcome.undrained += conn
                        .query_row(
                            "SELECT COUNT(*) FROM waf_events
                             WHERE id > ?1
                               AND id IN (SELECT id FROM waf_events ORDER BY id ASC LIMIT ?2)",
                            params![cursor as i64, take],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(|e| format!("failed to count undrained WAF rows: {e}"))?
                        as u64;
                }
                conn.execute(
                    "DELETE FROM waf_events WHERE id IN (
                         SELECT id FROM waf_events ORDER BY id ASC LIMIT ?1
                     )",
                    params![take],
                )
                .map_err(|e| format!("failed to enforce WAF event retention: {e}"))?
            };
            if deleted == 0 {
                return Ok(outcome);
            }
            outcome.deleted += deleted as u64;
        }
    }

    // ---- Notification History ----

    /// Insert a notification event.
    /// Persist a notification dispatch outcome for the history endpoint.
    pub fn insert_notification_event(
        &self,
        event: &lorica_notify::AlertEvent,
    ) -> Result<(), String> {
        let conn = self.conn.lock();
        let details_json = serde_json::to_string(&event.details)
            .map_err(|e| format!("failed to serialize alert event details: {e}"))?;
        conn.execute(
            "INSERT INTO notification_history (alert_type, summary, details, timestamp)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.alert_type.as_str(),
                event.summary,
                details_json,
                event.timestamp,
            ],
        )
        .map_err(|e| format!("failed to insert notification event: {e}"))?;
        Ok(())
    }

    /// Count the total number of persisted notification history
    /// rows. Cheap `SELECT COUNT(*)` so the API can surface an
    /// accurate total without paying for the full list payload
    /// (symmetry with `waf_event_stats` - avoids the same
    /// load-and-count plateau the WAF stats endpoint hit).
    pub fn notification_history_count(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notification_history", [], |row| {
                row.get(0)
            })
            .map_err(|e| format!("failed to count notification history: {e}"))?;
        Ok(count as u64)
    }

    /// List recent notification events, newest first.
    /// Return up to `limit` recent notification history rows.
    pub fn list_notification_history(
        &self,
        limit: usize,
    ) -> Result<Vec<lorica_notify::AlertEvent>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT alert_type, summary, details, timestamp
                 FROM notification_history ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| format!("failed to prepare notification history query: {e}"))?;
        let rows = stmt
            .query_map(params![limit as i64], |row| {
                let alert_type_str: String = row.get(0)?;
                let summary: String = row.get(1)?;
                let details_json: String = row.get(2)?;
                let timestamp: String = row.get(3)?;
                Ok((alert_type_str, summary, details_json, timestamp))
            })
            .map_err(|e| format!("failed to query notification history: {e}"))?;
        let mut events = Vec::new();
        for r in rows {
            let (alert_type_str, summary, details_json, timestamp) =
                r.map_err(|e| format!("failed to read notification row: {e}"))?;
            let alert_type = alert_type_str
                .parse()
                .unwrap_or(lorica_notify::events::AlertType::ConfigChanged);
            // Stored details JSON should always be parseable (written
            // via serde_json::to_string in insert_notification_event).
            // A parse failure at read time means storage corruption;
            // surface it as an empty map + warn so the alert history
            // stays viewable rather than blowing up the whole query.
            let details: std::collections::HashMap<String, String> =
                serde_json::from_str(&details_json).unwrap_or_else(|e| {
                    tracing::warn!(
                        error = %e,
                        "notification history row has corrupt details JSON; returning empty map"
                    );
                    std::collections::HashMap::new()
                });
            events.push(lorica_notify::AlertEvent {
                alert_type,
                summary,
                details,
                timestamp,
            });
        }
        Ok(events)
    }

    /// Prune old notification events, keeping at most `max_entries`.
    /// Trim the notification history table to the most recent `max_entries`.
    pub fn enforce_notification_retention(&self, max_entries: u64) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notification_history", [], |row| {
                row.get(0)
            })
            .map_err(|e| format!("failed to count notification events: {e}"))?;
        if count <= max_entries as i64 {
            return Ok(0);
        }
        let to_delete = count - max_entries as i64;
        conn.execute(
            "DELETE FROM notification_history WHERE id IN (SELECT id FROM notification_history ORDER BY id ASC LIMIT ?1)",
            params![to_delete],
        )
        .map_err(|e| format!("failed to enforce notification retention: {e}"))?;
        Ok(to_delete as u64)
    }
}

/// Audit-log storage (Story 8.9). See [`crate::audit`] for the chain
/// model. Every method here holds the single `Mutex<Connection>` for
/// its whole critical section, which is what serializes chain writes.
impl LogStore {
    const RETENTION_SEAL_KEY: &'static str = "retention_seal";

    /// The seal key for one node's chain (Story 9.9 AC #3).
    ///
    /// The local chain keeps the exact literal it has always used, so
    /// an upgraded single-node database reads as it did and needs no
    /// migration of `audit_log_meta`. A fanned-in node gets a suffixed
    /// key: N interleaved chains need N seals, and one shared key would
    /// make every node's retention truncation reseal every other
    /// node's chain.
    fn seal_key(node_id: &str) -> String {
        if node_id.is_empty() {
            Self::RETENTION_SEAL_KEY.to_string()
        } else {
            format!("{}:{node_id}", Self::RETENTION_SEAL_KEY)
        }
    }

    /// The key holding the highest `origin_id` a prefix cut has removed
    /// from a fanned-in chain; see [`LogStore::insert_fanned_in_audit`].
    fn cut_floor_key(node_id: &str) -> String {
        format!("fanned_in_cut:{node_id}")
    }

    /// The key counting every row the cap has ever moved into a node's
    /// fan-in backup, aged-out rows included.
    fn backup_rows_key(node_id: &str) -> String {
        format!("fanned_in_backup_rows:{node_id}")
    }

    /// The key holding the `chain_hash` of the last row moved into a
    /// node's fan-in backup.
    fn backup_tail_key(node_id: &str) -> String {
        format!("fanned_in_backup_tail:{node_id}")
    }

    fn audit_meta(conn: &Connection, key: &str) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        conn.query_row(
            "SELECT value FROM audit_log_meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("failed to read audit metadata {key}: {e}"))
    }

    fn set_audit_meta(conn: &Connection, key: &str, value: &str) -> Result<(), String> {
        conn.execute(
            "INSERT OR REPLACE INTO audit_log_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map(|_| ())
        .map_err(|e| format!("failed to write audit metadata {key}: {e}"))
    }

    fn audit_seal_for(conn: &Connection, node_id: &str) -> Result<Option<String>, String> {
        Self::audit_meta(conn, &Self::seal_key(node_id))
    }

    fn audit_seal(conn: &Connection) -> Result<Option<String>, String> {
        Self::audit_seal_for(conn, "")
    }

    /// How one chain is ordered, ascending and descending.
    ///
    /// The local chain is ordered by arrival, which for its own rows is
    /// also the order it wrote them. A fanned-in chain is ordered by
    /// the origin's own id: the aggregated `id` reflects the order rows
    /// ARRIVED in, and two reconnecting followers interleave that
    /// arbitrarily.
    ///
    /// One function rather than the same conditional in each caller,
    /// because the retention seal is only correct if it is taken in the
    /// order verify will walk. Three copies of that rule were three
    /// places for it to drift.
    fn chain_order(node_id: &str) -> (&'static str, &'static str) {
        if node_id.is_empty() {
            ("id ASC", "id DESC")
        } else {
            ("origin_id ASC", "origin_id DESC")
        }
    }

    /// The predicate selecting one chain's rows, `?1` bound to its node
    /// id.
    ///
    /// The local chain also pins `origin_id = 0`, which every local row
    /// carries and no fanned-in row can (fan-in refuses the empty node
    /// id). Redundant as a filter, it is what lets `idx_audit_log_node`
    /// serve the local chain: that index is `(node_id, origin_id)` with
    /// the rowid after it, so only with both leading columns fixed does
    /// it hand local rows back in `id` order and seek on an `id` range.
    /// With `node_id` alone SQLite read every local entry and sorted
    /// them, on every verify chunk and on every local audit write.
    fn chain_filter(node_id: &str) -> &'static str {
        if node_id.is_empty() {
            "node_id = ?1 AND origin_id = 0"
        } else {
            "node_id = ?1"
        }
    }

    /// This node's chain head, read before each local append. See
    /// [`LogStore::chain_filter`] for why it names `origin_id`.
    const LOCAL_AUDIT_TAIL_SQL: &'static str = "SELECT chain_hash FROM audit_log \
        WHERE node_id = '' AND origin_id = 0 ORDER BY id DESC LIMIT 1";

    /// The highest local rowid; see [`LogStore::newest_local_audit_id`].
    const LOCAL_AUDIT_NEWEST_SQL: &'static str =
        "SELECT MAX(id) FROM audit_log WHERE node_id = '' AND origin_id = 0";

    /// One page of the local chain for the cluster drain; see
    /// [`LogStore::audit_rows_after`].
    const LOCAL_AUDIT_DRAIN_SQL: &'static str = "SELECT id, timestamp, operator_username, \
        operator_role, action, target_type, target_id, before_payload_hash, after_payload_hash, \
        ip, user_agent, prev_chain_hash, chain_hash \
        FROM audit_log WHERE node_id = '' AND origin_id = 0 AND id > ?1 ORDER BY id ASC LIMIT ?2";

    /// The `(MIN, MAX)` origin ids of one fanned-in chain. Two
    /// subqueries rather than one `SELECT MIN(..), MAX(..)`: SQLite
    /// answers a lone `MIN` or `MAX` with one index seek, and both in
    /// one select by reading every entry of the chain.
    const FANNED_IN_SPAN_SQL: &'static str =
        "SELECT (SELECT MIN(origin_id) FROM audit_log WHERE node_id = ?1),
                (SELECT MAX(origin_id) FROM audit_log WHERE node_id = ?1)";

    /// The `origin_id` of the newest row the cap must cut: the one just
    /// past the `?2` newest, exact through the index rather than
    /// estimated.
    const FANNED_IN_CAP_CUT_SQL: &'static str = "SELECT origin_id FROM audit_log \
        WHERE node_id = ?1 ORDER BY origin_id DESC LIMIT 1 OFFSET ?2";

    /// Every node id with rows in `table`, as a skip scan: one index
    /// seek per chain, where `SELECT DISTINCT node_id` read every entry
    /// of the node index, a pass over the whole aggregate under the
    /// lock at the start of each unfiltered verify and each cap pass.
    fn node_ids_sql(table: &str) -> String {
        format!(
            "WITH RECURSIVE chains(node_id) AS (
                 SELECT MIN(node_id) FROM {table}
                 UNION ALL
                 SELECT (SELECT MIN(node_id) FROM {table} WHERE node_id > chains.node_id)
                 FROM chains WHERE chains.node_id IS NOT NULL
             )
             SELECT node_id FROM chains WHERE node_id IS NOT NULL"
        )
    }

    /// The position of a chain's head in `segment`.
    fn chain_head_sql(segment: ChainSegment, node_id: &str) -> String {
        format!(
            "SELECT MAX({}) FROM {} WHERE {}",
            Self::chain_position(node_id),
            segment.table(),
            Self::chain_filter(node_id)
        )
    }

    /// One verify chunk of a chain in `segment`: rows from position
    /// `?2` to `?3`, in chain order, at most `?4` of them. The chain
    /// position rides as a sixteenth column.
    fn chain_chunk_sql(segment: ChainSegment, node_id: &str) -> String {
        let position = Self::chain_position(node_id);
        format!(
            "SELECT {}, {position} FROM {} WHERE {} AND {position} >= ?2 AND {position} <= ?3
             ORDER BY {} LIMIT ?4",
            Self::AUDIT_COLUMNS,
            segment.table(),
            Self::chain_filter(node_id),
            Self::chain_order(node_id).0
        )
    }

    /// Whether the row at position `?2` of a chain in `segment` is
    /// still there.
    fn chain_row_exists_sql(segment: ChainSegment, node_id: &str) -> String {
        format!(
            "SELECT 1 FROM {} WHERE {} AND {} = ?2",
            segment.table(),
            Self::chain_filter(node_id),
            Self::chain_position(node_id)
        )
    }

    /// The position of a chain's last row older than `?2` in `segment`,
    /// read through the age index, so a chain with nothing expired
    /// costs one seek.
    fn retention_cut_sql(segment: ChainSegment, node_id: &str) -> String {
        format!(
            "SELECT MAX({}) FROM {} WHERE {} AND {AUDIT_AGE} < ?2",
            Self::chain_position(node_id),
            segment.table(),
            Self::chain_filter(node_id)
        )
    }

    /// The position of the `?3 + 1`th row of a chain at or below
    /// position `?2`: where the next chunk of a cut ends.
    fn cut_step_sql(node_id: &str) -> String {
        let position = Self::chain_position(node_id);
        format!(
            "SELECT {position} FROM audit_log WHERE {} AND {position} <= ?2
             ORDER BY {} LIMIT 1 OFFSET ?3",
            Self::chain_filter(node_id),
            Self::chain_order(node_id).0
        )
    }

    /// Append one audit row. `prev_chain_hash` and `chain_hash` are
    /// computed HERE, inside the connection lock: two concurrent
    /// mutations cannot fork the chain. The previous hash comes from
    /// the newest stored row, else the retention seal, else genesis.
    /// Callers on the request path go through
    /// [`LogStore::enqueue_audit`] instead; this one commits inline
    /// and is what the audit writer thread runs.
    pub fn insert_audit(
        &self,
        entry: &crate::audit::NewAuditEntry,
    ) -> Result<(i64, String), String> {
        Self::insert_audit_into(&self.conn, entry)
    }

    /// The body of [`LogStore::insert_audit`], taking the connection
    /// rather than the store so the audit writer thread can call it
    /// without holding an `Arc<LogStore>` and keeping the store (and
    /// therefore itself) alive forever.
    fn insert_audit_into(
        conn: &Mutex<Connection>,
        entry: &crate::audit::NewAuditEntry,
    ) -> Result<(i64, String), String> {
        use rusqlite::TransactionBehavior;
        let mut guard = conn.lock();
        // IMMEDIATE, so the tail read and the insert hold SQLite's
        // write lock together across PROCESSES (backlog #74): the
        // in-process mutex above serialises this daemon's writers, but
        // `lorica cluster leave` opens its own store on the same file
        // and used to be able to read the same tail as a concurrent
        // API write, producing two rows with one `prev_chain_hash`,
        // a fork the chain never recovers from.
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| format!("failed to open the audit transaction: {e}"))?;
        let appended = Self::append_local_audit_in(&tx, entry)?;
        tx.commit()
            .map_err(|e| format!("failed to commit the audit row: {e}"))?;
        Ok(appended)
    }

    /// Chain `entry` onto this node's own chain inside `tx`, an open
    /// IMMEDIATE transaction the caller commits, and return its rowid
    /// and `chain_hash`. The one place a local row is chained, so a row
    /// written inside another statement's transaction (the fan-in cap's
    /// record of its cut) links exactly as the audit writer's do.
    fn append_local_audit_in(
        conn: &Connection,
        entry: &crate::audit::NewAuditEntry,
    ) -> Result<(i64, String), String> {
        use rusqlite::OptionalExtension;
        // The LOCAL tail, not the table's. Story 9.9 makes this table
        // hold N interleaved chains, and reading the global tail would
        // chain this node's next entry off whichever follower's row
        // happened to arrive last: this node's own chain would then be
        // verifiable by nothing but this exact aggregate, and would
        // break the moment a fanned-in row was pruned.
        let last: Option<String> = conn
            .query_row(Self::LOCAL_AUDIT_TAIL_SQL, [], |row| row.get(0))
            .optional()
            .map_err(|e| format!("failed to read audit chain head: {e}"))?;

        let prev_chain_hash: String = match last {
            Some(hash) => hash,
            None => {
                Self::audit_seal(conn)?.unwrap_or_else(|| crate::audit::GENESIS_HASH.to_string())
            }
        };

        let chain_hash: String = crate::audit::compute_chain_hash(
            &prev_chain_hash,
            &crate::audit::ChainInput::from(entry),
        );

        // `node_id` and `origin_id` take their column defaults: this
        // is a local row, on a standalone install and on a clustered
        // one alike.
        conn.execute(
            "INSERT INTO audit_log (timestamp, operator_username, operator_role, action,
                target_type, target_id, before_payload_hash, after_payload_hash,
                ip, user_agent, prev_chain_hash, chain_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                entry.timestamp,
                entry.operator_username,
                entry.operator_role,
                entry.action,
                entry.target_type,
                entry.target_id,
                entry.before_payload_hash,
                entry.after_payload_hash,
                entry.ip,
                entry.user_agent,
                prev_chain_hash,
                chain_hash,
            ],
        )
        .map_err(|e| format!("failed to insert audit row: {e}"))?;

        Ok((conn.last_insert_rowid(), chain_hash))
    }

    /// Store audit rows fanned in from another node (Story 9.9 AC #2).
    ///
    /// A SEPARATE path from [`LogStore::insert_audit`], and the
    /// separation is the whole point rather than a convenience. That
    /// one computes `prev_chain_hash` from the table's global tail; if
    /// fan-in rows went through it, the control plane's own next audit
    /// entry would chain off a follower's row, so its chain would be
    /// unverifiable by anything but this exact aggregate, and the
    /// follower's rows would be re-hashed into a chain the origin
    /// never published.
    ///
    /// So the chain fields are written VERBATIM. Nothing here
    /// recomputes a hash: the aggregated copy is worth something only
    /// if it is byte-identical to what the node itself published on its
    /// `lorica::audit` stream, which is the out-of-band anchor the
    /// whole feature leans on. A row whose hash does not recompute
    /// stays as it arrived and is reported by verify; silently fixing
    /// it would erase the only evidence.
    ///
    /// Idempotent on `(node_id, origin_id)`: a drain that re-sends a
    /// batch after a lost acknowledgement must not duplicate rows, and
    /// a duplicate would break the partitioned verify's ordering.
    ///
    /// Idempotent across a cut as well. A row at or below the highest
    /// `origin_id` a prefix cut has removed from this chain is skipped:
    /// the cut moved the seal past it, so stored again it would sit
    /// before the seal in origin order, and verify would meet it first
    /// and report a break nothing tampered with. Only a re-send of a
    /// row this store already held can arrive there (origin ids only
    /// grow on the node), so it is acknowledged like any duplicate.
    ///
    /// Returns how many rows the store DURABLY HOLDS for this batch,
    /// which is all of them once the transaction commits, not how many
    /// were newly written. The difference is load-bearing: the drain
    /// advances its cursor only when the acknowledgement matches what
    /// it sent, so returning the newly-written count would make every
    /// re-send answer zero and freeze that node's cursors for the life
    /// of the process. Deduplication is how idempotency is
    /// implemented; it is not an acceptance signal.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a write failure, and refuses a
    /// row with an empty `node_id`: that is the local marker, and a
    /// fanned-in row claiming to be local would splice another node's
    /// history into this node's chain.
    pub fn insert_fanned_in_audit(
        &self,
        node_id: &str,
        rows: &[crate::audit::FannedInAuditRow],
    ) -> Result<u64, String> {
        if node_id.is_empty() {
            return Err("a fanned-in audit row cannot claim to be local".to_string());
        }
        if rows.is_empty() {
            return Ok(0);
        }
        let mut conn = self.conn.lock();
        // The arrival genesis for a chain this store has not seen
        // (Story 9.9). Fan-in starts at the node's present, not at its
        // history, so the first row to arrive carries a
        // `prev_chain_hash` naming a row this store will never hold.
        // Without a seal, verify falls back to genesis and reports
        // `prev_hash_mismatch` on that first row forever: the feature
        // whose purpose is tamper evidence would cry tamper on every
        // healthy fleet, and an operator who sees "broken" as the
        // normal state stops reading it.
        //
        // The seal is node-supplied, like every other field in the
        // chain, so it concedes nothing the threat model has not
        // already conceded: this proves internal consistency of what
        // the node sent, never authenticity.
        let seal_key = Self::seal_key(node_id);
        let known: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log_meta WHERE key = ?1",
                params![seal_key],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to read the audit arrival seal: {e}"))?;
        if known == 0 {
            let existing: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE node_id = ?1",
                    params![node_id],
                    |row| row.get(0),
                )
                .map_err(|e| format!("failed to count a node's audit rows: {e}"))?;
            if existing == 0 {
                let first = rows
                    .iter()
                    .min_by_key(|r| r.origin_id)
                    .expect("the batch is not empty");
                conn.execute(
                    "INSERT OR REPLACE INTO audit_log_meta (key, value) VALUES (?1, ?2)",
                    params![seal_key, first.prev_chain_hash],
                )
                .map_err(|e| format!("failed to write the audit arrival seal: {e}"))?;
            }
        }
        let cut_floor: Option<i64> = Self::audit_meta(&conn, &Self::cut_floor_key(node_id))?
            .and_then(|floor| floor.parse().ok());
        let tx = conn
            .transaction()
            .map_err(|e| format!("failed to open the audit fan-in transaction: {e}"))?;
        let received_at = chrono::Utc::now().to_rfc3339();
        let mut stored = 0u64;
        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT OR IGNORE INTO audit_log (timestamp, operator_username,
                        operator_role, action, target_type, target_id,
                        before_payload_hash, after_payload_hash, ip, user_agent,
                        prev_chain_hash, chain_hash, node_id, origin_id, received_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                )
                .map_err(|e| format!("failed to prepare the audit fan-in insert: {e}"))?;
            for row in rows {
                if cut_floor.is_some_and(|floor| row.origin_id <= floor) {
                    continue;
                }
                stored += stmt
                    .execute(params![
                        row.timestamp,
                        row.operator_username,
                        row.operator_role,
                        row.action,
                        row.target_type,
                        row.target_id,
                        row.before_payload_hash,
                        row.after_payload_hash,
                        row.ip,
                        row.user_agent,
                        row.prev_chain_hash,
                        row.chain_hash,
                        node_id,
                        row.origin_id,
                        received_at,
                    ])
                    .map_err(|e| format!("failed to store a fanned-in audit row: {e}"))?
                    as u64;
            }
        }
        tx.commit()
            .map_err(|e| format!("failed to commit the audit fan-in: {e}"))?;
        if stored != rows.len() as u64 {
            // Not an error: the drain re-offers a batch whenever a push
            // was not fully accepted, so a duplicate is the idempotency
            // working. Worth a line because a persistent gap means the
            // cursor is not advancing.
            tracing::debug!(
                node_id,
                offered = rows.len(),
                newly_stored = stored,
                "some fanned-in audit rows were already held"
            );
        }
        Ok(rows.len() as u64)
    }

    fn row_to_audit(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::audit::AuditRecord> {
        Ok(crate::audit::AuditRecord {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            operator_username: row.get(2)?,
            operator_role: row.get(3)?,
            action: row.get(4)?,
            target_type: row.get(5)?,
            target_id: row.get(6)?,
            before_payload_hash: row.get(7)?,
            after_payload_hash: row.get(8)?,
            ip: row.get(9)?,
            user_agent: row.get(10)?,
            prev_chain_hash: row.get(11)?,
            chain_hash: row.get(12)?,
            node_id: row.get(13)?,
            origin_id: row.get(14)?,
        })
    }

    const AUDIT_COLUMNS: &'static str = "id, timestamp, operator_username, operator_role, \
        action, target_type, target_id, before_payload_hash, after_payload_hash, \
        ip, user_agent, prev_chain_hash, chain_hash, node_id, origin_id";

    /// Query audit rows, newest first, with total count under the
    /// same filters (for pagination). `action_prefix` is a literal
    /// prefix: `%`/`_`/`\` in user input are escaped.
    pub fn query_audit(
        &self,
        q: &crate::audit::AuditQuery,
    ) -> Result<(Vec<crate::audit::AuditRecord>, u64), String> {
        let mut clauses: Vec<String> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(operator) = &q.operator {
            clauses.push("operator_username = ?".into());
            binds.push(Box::new(operator.clone()));
        }
        if let Some(prefix) = &q.action_prefix {
            let escaped = prefix
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            clauses.push("action LIKE ? ESCAPE '\\'".into());
            binds.push(Box::new(format!("{escaped}%")));
        }
        if let Some(from) = &q.from {
            clauses.push("timestamp >= ?".into());
            binds.push(Box::new(from.clone()));
        }
        if let Some(to) = &q.to {
            clauses.push("timestamp <= ?".into());
            binds.push(Box::new(to.clone()));
        }
        if let Some(before_id) = q.before_id {
            clauses.push("id < ?".into());
            binds.push(Box::new(before_id));
        }
        // `Some("")` selects this node's own rows and is not the same
        // as `None`, which selects every node's.
        if let Some(node_id) = &q.node_id {
            clauses.push("node_id = ?".into());
            binds.push(Box::new(node_id.clone()));
        }

        let where_sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };

        let conn = self.conn.lock();

        let total: i64 = {
            let sql = format!("SELECT COUNT(*) FROM audit_log{where_sql}");
            let bind_refs: Vec<&dyn rusqlite::types::ToSql> =
                binds.iter().map(|b| b.as_ref()).collect();
            conn.query_row(&sql, bind_refs.as_slice(), |row| row.get(0))
                .map_err(|e| format!("failed to count audit rows: {e}"))?
        };

        let sql = format!(
            "SELECT {} FROM audit_log{where_sql} ORDER BY id DESC LIMIT ?",
            Self::AUDIT_COLUMNS
        );
        binds.push(Box::new(q.limit.max(1) as i64));
        let bind_refs: Vec<&dyn rusqlite::types::ToSql> =
            binds.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("failed to prepare audit query: {e}"))?;
        let rows = stmt
            .query_map(bind_refs.as_slice(), Self::row_to_audit)
            .map_err(|e| format!("failed to run audit query: {e}"))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| format!("failed to read audit row: {e}"))?);
        }
        Ok((records, total as u64))
    }

    /// Walk the whole chain from genesis (or the retention seal) and
    /// recompute every `chain_hash`. Stops at the earliest break.
    pub fn verify_audit_chain(&self) -> Result<crate::audit::VerifyResult, String> {
        self.verify_audit_chain_for("")
    }

    /// Verify ONE node's chain (Story 9.9 AC #3). `""` is this node's.
    ///
    /// Partitioned, because the aggregated table interleaves N chains
    /// and the unpartitioned walk would chain one node's row to
    /// another's and report a break at the first interleave. Ordered by
    /// `origin_id` for a fanned-in node, which reconstructs the order
    /// that node wrote its rows in; the aggregated `id` reflects the
    /// order they ARRIVED in, which two reconnecting followers can
    /// interleave arbitrarily.
    ///
    /// A break is reported at the aggregated `id`, so an operator can
    /// find the row, with the origin's own id beside it.
    ///
    /// What this proves is internal consistency of what the node sent,
    /// and nothing about authenticity: a compromised follower streams a
    /// self-consistent forged chain and this reports it clean. The
    /// origin's own `lorica::audit` stream shipped to a WORM sink is
    /// the anchor; see the module doc of [`crate::audit`].
    ///
    /// The walk covers the chain as far as its head when the call
    /// began, in chunks of `AUDIT_CHUNK` rows, with the connection
    /// released between chunks; see
    /// [`LogStore::verify_audit_chain_chunked`].
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn verify_audit_chain_for(
        &self,
        node_id: &str,
    ) -> Result<crate::audit::VerifyResult, String> {
        self.walk_chain(
            ChainSegment::Live,
            node_id,
            AUDIT_CHUNK,
            &mut || {},
            &mut || {},
        )
    }

    /// Verify the run of rows the fan-in cap moved out of `node_id`'s
    /// chain into its backup, or `None` when that node has none.
    ///
    /// The backup is a contiguous run of the chain as the node sent it,
    /// every row with its original hashes, so it is checked exactly as
    /// the live chain is, link by link, but anchored on its own first
    /// row's `prev_chain_hash`: the seal that preceded it was replaced
    /// by the cut that moved it. That proves the run is internally
    /// whole, which is what an operator needs of the record a cut
    /// preserved, and, like every fanned-in verify, nothing about its
    /// authenticity. A break is reported at the row's aggregated `id`,
    /// the one it carried before it moved.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn verify_fanned_in_backup(
        &self,
        node_id: &str,
    ) -> Result<Option<crate::audit::VerifyResult>, String> {
        use rusqlite::OptionalExtension;
        if node_id.is_empty() {
            return Ok(None);
        }
        let held = self
            .conn
            .lock()
            .query_row(
                &format!("SELECT 1 FROM {FANNED_IN_BACKUP_TABLE} WHERE node_id = ?1 LIMIT 1"),
                params![node_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|e| format!("failed to read the audit fan-in backup: {e}"))?
            .is_some();
        if !held {
            return Ok(None);
        }
        self.walk_chain(
            ChainSegment::Backup,
            node_id,
            AUDIT_CHUNK,
            &mut || {},
            &mut || {},
        )
        .map(Some)
    }

    /// The walk behind [`LogStore::verify_audit_chain_for`], one chunk
    /// per lock acquisition, calling `between_chunks` with the lock
    /// released so a test can land a write exactly there.
    #[cfg(test)]
    fn verify_audit_chain_chunked(
        &self,
        node_id: &str,
        chunk: i64,
        between_chunks: &mut dyn FnMut(),
    ) -> Result<crate::audit::VerifyResult, String> {
        self.walk_chain(
            ChainSegment::Live,
            node_id,
            chunk,
            &mut || {},
            between_chunks,
        )
    }

    /// Walk one chain of `segment`, `chunk` rows per lock acquisition.
    /// `before_first` runs before the first acquisition and
    /// `between_chunks` between two, both with the lock released, which
    /// is where a test lands a concurrent write.
    ///
    /// Chunked because every other user of `access-log.db` waits on the
    /// same connection, the access-log writer first among them, and it
    /// drops rows once its queue fills. A fanned-in chain may hold up to
    /// [`FANNED_IN_AUDIT_ROWS_PER_NODE`] rows, and a walk holding the
    /// lock throughout stalled that writer for the whole chain (backlog
    /// #75). Hashing happens outside the lock as well; only the read of
    /// each chunk is inside it.
    ///
    /// The head and the anchor (the seal, or for the backup the first
    /// row's own predecessor) are read in the SAME acquisition as the
    /// first chunk. Read in one of their own, a cut landing before the
    /// first chunk would move the seal past the anchor already taken,
    /// and the first surviving row, which names the new seal, would be
    /// reported as a break.
    ///
    /// Releasing the lock mid-walk lets two kinds of write land between
    /// chunks, and neither may read as a break:
    ///
    /// - Appends. The walk stops at the chain's head as it stood when
    ///   the walk began, so a row written after that is left to the
    ///   next verify rather than racing this one. An append that lands
    ///   below that head, a fanned-in row filling a gap in origin
    ///   order, is walked exactly as an unchunked verify starting at
    ///   that moment would walk it.
    /// - Prefix cuts ([`LogStore::cut_chain_prefix`], from retention or
    ///   the fan-in cap; retention alone on the backup). A cut deletes
    ///   a prefix, and on the live chain reseals in the same
    ///   transaction. If the last row walked survived it, the cut
    ///   stopped short of the cursor and everything ahead of it is
    ///   untouched, so the walk goes on. If that row is gone, the cut
    ///   reached the cursor or past it, and the first row ahead is now
    ///   the chain's first: it is checked against the CURRENT anchor,
    ///   which is the one a verify started now would use for it.
    ///
    /// Neither rule loosens what a break is. Every row walked is
    /// checked against its predecessor or the anchor, as before. A row
    /// deleted out from under the cursor by anything other than a cut
    /// leaves the seal where it was, so the next row is checked against
    /// a seal that does not name it and is reported. `total_rows`
    /// counts rows walked, including any a cut removed after they were.
    fn walk_chain(
        &self,
        segment: ChainSegment,
        node_id: &str,
        chunk: i64,
        before_first: &mut dyn FnMut(),
        between_chunks: &mut dyn FnMut(),
    ) -> Result<crate::audit::VerifyResult, String> {
        use rusqlite::OptionalExtension;
        let head_sql = Self::chain_head_sql(segment, node_id);
        let chunk_sql = Self::chain_chunk_sql(segment, node_id);
        let exists_sql = Self::chain_row_exists_sql(segment, node_id);
        // `None` means "the next row's own predecessor": the backup has
        // no seal, its first row is where it starts.
        let anchor = |conn: &Connection| -> Result<Option<String>, String> {
            match segment {
                ChainSegment::Live => Ok(Some(
                    Self::audit_seal_for(conn, node_id)?
                        .unwrap_or_else(|| crate::audit::GENESIS_HASH.to_string()),
                )),
                ChainSegment::Backup => Ok(None),
            }
        };

        let mut walk_head: Option<i64> = None;
        let mut expected: Option<String> = None;
        let mut total_rows: u64 = 0;
        let mut last_walked: Option<i64> = None;
        let mut from = i64::MIN;
        before_first();
        loop {
            let (records, head): (Vec<(crate::audit::AuditRecord, i64)>, i64) = {
                let conn = self.conn.lock();
                let head = match walk_head {
                    Some(head) => {
                        if let Some(last) = last_walked {
                            let survived = conn
                                .query_row(&exists_sql, params![node_id, last], |_| Ok(()))
                                .optional()
                                .map_err(|e| format!("failed to re-anchor the audit verify: {e}"))?
                                .is_some();
                            if !survived {
                                expected = anchor(&conn)?;
                            }
                        }
                        head
                    }
                    None => {
                        let head: Option<i64> = conn
                            .query_row(&head_sql, params![node_id], |row| row.get(0))
                            .map_err(|e| format!("failed to read the audit chain head: {e}"))?;
                        let Some(head) = head else {
                            break;
                        };
                        expected = anchor(&conn)?;
                        walk_head = Some(head);
                        head
                    }
                };
                let mut stmt = conn
                    .prepare_cached(&chunk_sql)
                    .map_err(|e| format!("failed to prepare audit verify: {e}"))?;
                let rows = stmt
                    .query_map(params![node_id, from, head, chunk], |row| {
                        Ok((Self::row_to_audit(row)?, row.get(15)?))
                    })
                    .map_err(|e| format!("failed to run audit verify: {e}"))?;
                let records = rows
                    .collect::<rusqlite::Result<_>>()
                    .map_err(|e| format!("failed to read audit row: {e}"))?;
                (records, head)
            };

            let fetched = records.len() as i64;
            for (record, at) in records {
                total_rows += 1;
                let predecessor = expected.get_or_insert_with(|| record.prev_chain_hash.clone());
                if record.prev_chain_hash != *predecessor {
                    return Ok(crate::audit::VerifyResult {
                        verified: false,
                        total_rows,
                        first_break_id: Some(record.id),
                        first_break_reason: Some("prev_hash_mismatch".into()),
                    });
                }
                if crate::audit::recompute_chain_hash(&record) != record.chain_hash {
                    return Ok(crate::audit::VerifyResult {
                        verified: false,
                        total_rows,
                        first_break_id: Some(record.id),
                        first_break_reason: Some("chain_hash_mismatch".into()),
                    });
                }
                expected = Some(record.chain_hash);
                last_walked = Some(at);
            }

            let next = last_walked.and_then(|at| at.checked_add(1));
            match next {
                Some(next) if fetched == chunk && next <= head => from = next,
                _ => break,
            }
            between_chunks();
        }

        Ok(crate::audit::VerifyResult {
            verified: true,
            total_rows,
            first_break_id: None,
            first_break_reason: None,
        })
    }

    /// Test-only: rewrite when a fanned-in row arrived, so retention
    /// tests can age rows without sleeping through a retention window.
    #[cfg(test)]
    pub(crate) fn backdate_arrival(&self, node_id: &str, origin_id: i64, received_at: &str) {
        self.conn
            .lock()
            .execute(
                "UPDATE audit_log SET received_at = ?1 WHERE node_id = ?2 AND origin_id = ?3",
                params![received_at, node_id, origin_id],
            )
            .expect("test setup: backdate a fanned-in row");
    }

    /// Every node id that has rows in the aggregate, `""` included,
    /// sorted.
    ///
    /// The input to a verify that reports per node: an operator asking
    /// "is the fleet's audit trail intact" needs one answer per chain,
    /// and there is no other list of which chains exist.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn audit_node_ids(&self) -> Result<Vec<String>, String> {
        self.node_ids_in(ChainSegment::Live)
    }

    /// Every node id with rows in the fan-in backup, sorted. A node can
    /// be here and not in [`LogStore::audit_node_ids`] once its live
    /// chain has aged out ahead of its backup.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn audit_backup_node_ids(&self) -> Result<Vec<String>, String> {
        self.node_ids_in(ChainSegment::Backup)
    }

    fn node_ids_in(&self, segment: ChainSegment) -> Result<Vec<String>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(&Self::node_ids_sql(segment.table()))
            .map_err(|e| format!("failed to prepare the audit node list: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to list audit nodes: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read an audit node id: {e}"))?);
        }
        out.sort();
        Ok(out)
    }

    /// Delete audit rows older than `cutoff_timestamp` (RFC 3339),
    /// preserving chain verifiability, from every chain and from the
    /// fan-in backup. Returns the number of rows deleted, backup rows
    /// included.
    ///
    /// Each chain is cut as a PREFIX of its own verify order, never by
    /// a timestamp predicate applied across it. The two orders are not
    /// the same thing: a fanned-in chain's order is the origin's
    /// `origin_id`, and its `timestamp` is a string that node chose.
    /// Deleting `WHERE timestamp < cutoff` would take rows out of the
    /// MIDDLE of such a chain whenever that node's clock stepped, and
    /// verify would then report a tamper alarm caused by nothing but a
    /// retention pass. So a chain is cut at the position of its LAST
    /// expired row: that row and everything before it goes, and the
    /// count can exceed the rows actually past the cutoff, because a
    /// younger row that sits before an expired one goes with it.
    ///
    /// Every chain gets its own seal (Story 9.9 AC #3): the earliest
    /// SURVIVING row's `prev_chain_hash`, or the newest deleted row's
    /// `chain_hash` when nothing survives, which verify and insert then
    /// treat as that chain's genesis.
    ///
    /// The backup ages by the same arrival time, so a cut never keeps
    /// rows longer than the retention setting would have, and it is cut
    /// as a prefix too, which is all its own-first-row anchor needs.
    ///
    /// Chunked like the cap, chain by chain, with the connection
    /// released between chunks: the first pass after the setting is
    /// lowered, or after a long-lived chain crosses the window, can
    /// expire a large slice of a chain at once, and held for all of it
    /// the lock would stall the access-log writer (backlog #75). Each
    /// chunk is a sealed cut, so the chain verifies between chunks.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read, seal or delete failure.
    /// Chunks cut before the failure stay cut, and sealed.
    pub fn enforce_audit_retention(&self, cutoff_timestamp: &str) -> Result<u64, String> {
        let mut removed = 0u64;
        for node_id in self.audit_node_ids()? {
            let cut: Option<i64> = self
                .conn
                .lock()
                .query_row(
                    &Self::retention_cut_sql(ChainSegment::Live, &node_id),
                    params![node_id, cutoff_timestamp],
                    |row| row.get(0),
                )
                .map_err(|e| format!("failed to find the audit retention cut: {e}"))?;
            let Some(cut) = cut else {
                continue;
            };
            let mut totals = PrefixCut::default();
            let outcome = self.cut_chain_in_chunks(&node_id, cut, CutCause::Retention, &mut totals);
            removed += totals.removed;
            outcome?;
        }
        for node_id in self.audit_backup_node_ids()? {
            removed += self.age_out_fanned_in_backup(&node_id, cutoff_timestamp)?;
        }
        Ok(removed)
    }

    /// The backup half of [`LogStore::enforce_audit_retention`] for one
    /// node: its rows up to the last one older than the cutoff, in
    /// chunks.
    fn age_out_fanned_in_backup(
        &self,
        node_id: &str,
        cutoff_timestamp: &str,
    ) -> Result<u64, String> {
        let cut: Option<i64> = self
            .conn
            .lock()
            .query_row(
                &Self::retention_cut_sql(ChainSegment::Backup, node_id),
                params![node_id, cutoff_timestamp],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to find the audit backup retention cut: {e}"))?;
        let Some(cut) = cut else {
            return Ok(0);
        };
        let delete_sql = format!(
            "DELETE FROM {FANNED_IN_BACKUP_TABLE} WHERE node_id = ?1 AND origin_id IN (
                 SELECT origin_id FROM {FANNED_IN_BACKUP_TABLE}
                 WHERE node_id = ?1 AND origin_id <= ?2 ORDER BY origin_id ASC LIMIT ?3
             )"
        );
        let mut removed = 0u64;
        loop {
            let deleted = self
                .conn
                .lock()
                .execute(&delete_sql, params![node_id, cut, AUDIT_CHUNK])
                .map_err(|e| format!("failed to age out the audit fan-in backup: {e}"))?;
            removed += deleted as u64;
            if (deleted as i64) < AUDIT_CHUNK {
                return Ok(removed);
            }
        }
    }

    /// Cut every FANNED-IN chain down to its newest `rows_per_node`
    /// rows (backlog #72), returning each chain it cut. The production
    /// ceiling is [`FANNED_IN_AUDIT_ROWS_PER_NODE`].
    ///
    /// The cut is the one time-based retention makes, through the same
    /// [`LogStore::cut_chain_prefix`]: the oldest rows of the chain's
    /// own order go, the survivor's predecessor becomes the chain's
    /// seal, and verify walks the remaining suffix from that seal as it
    /// would from genesis. A cap that deleted any other way would make
    /// a node's chain report tampering because the node was busy.
    ///
    /// The oldest rows are the ones worth keeping when the node is the
    /// reason for the cut. A follower controls its own chain head, so a
    /// compromised one can extend its chain to the ceiling in minutes
    /// and have this pass evict what it sent BEFORE the compromise, the
    /// rows its attacker can no longer reach on the node itself. So the
    /// first rows ever cut from a chain are MOVED, in the cut's own
    /// transaction, into that node's fan-in backup, until
    /// `rows_per_node` rows have been moved for it over its lifetime;
    /// past that, cut rows are deleted. The backup is filled once and
    /// never overwritten: it holds the oldest rows ever cut, a partial
    /// fill takes them oldest first, rows it has aged out do not make
    /// room again, and a run that does not chain onto its last row (a
    /// retention cut deleted the rows between) closes it for good,
    /// since a backup with a hole could not be verified. One node
    /// therefore holds at most twice the ceiling. The backup ages out
    /// with day-based retention like the chain it came from, and
    /// [`LogStore::verify_fanned_in_backup`] checks it.
    ///
    /// Every chunk cut also writes a [`FANNED_IN_AUDIT_CAP_ACTION`] row
    /// into this node's OWN chain, which no peer can cap: the node, the
    /// rows cut, their `origin_id` range and how many were moved and how
    /// many deleted, so the eviction and the seal it moved are on a
    /// record the follower cannot touch. The row commits in the chunk's
    /// own transaction, so no crash or failure can leave rows cut with
    /// no record of the cut; a cut spanning several chunks therefore
    /// leaves one record per chunk, their figures summing to the cut's.
    ///
    /// This node's own chain is never capped. The ceiling bounds what a
    /// PEER can make this store hold; local rows are written by this
    /// node's own API, are bounded by the operator's audit retention
    /// setting, and are the history an operator verifies this node
    /// against. Trimming them to make room would let a flood of
    /// fanned-in rows cost the local record, which is backwards.
    ///
    /// Chunked, with the connection released between chunks: the audit
    /// writer thread commits this node's own rows through the same
    /// lock, and the overshoot this reclaims can be an hour of arrivals
    /// at the push cap. Held for the whole reclaim, that lock would
    /// stall the writer until the audit queue started dropping local
    /// rows. Each chunk is itself a sealed prefix cut, so the chain
    /// verifies between chunks as well as after the last.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read, seal, move or delete
    /// failure. Chains cut before the failure stay cut, and sealed, and
    /// a chain the failure interrupted has what was cut of it recorded.
    pub fn enforce_fanned_in_audit_cap(
        &self,
        rows_per_node: u64,
    ) -> Result<Vec<FannedInAuditCapCut>, String> {
        use rusqlite::OptionalExtension;
        let keep = i64::try_from(rows_per_node).unwrap_or(i64::MAX);
        let nodes: Vec<String> = self
            .audit_node_ids()?
            .into_iter()
            .filter(|node_id| !node_id.is_empty())
            .collect();

        let mut cuts = Vec::new();
        for node_id in nodes {
            let cut: i64 = {
                let conn = self.conn.lock();
                let (min, max): (Option<i64>, Option<i64>) = conn
                    .query_row(Self::FANNED_IN_SPAN_SQL, params![node_id], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .map_err(|e| format!("failed to size a fanned-in audit chain: {e}"))?;
                let (Some(min), Some(max)) = (min, max) else {
                    continue;
                };
                // Origin ids are unique within a chain, so a chain whose
                // span fits under the ceiling holds no more rows than
                // that, and is settled by two index seeks. Only a chain
                // spanning more pays the exact walk below, which is
                // `keep` index entries long.
                if i128::from(max) - i128::from(min) < i128::from(keep) {
                    continue;
                }
                let cut: Option<i64> = conn
                    .query_row(Self::FANNED_IN_CAP_CUT_SQL, params![node_id, keep], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(|e| format!("failed to find the audit cap cut: {e}"))?;
                let Some(cut) = cut else {
                    continue;
                };
                cut
            };

            let mut totals = PrefixCut::default();
            let outcome = self.cut_chain_in_chunks(
                &node_id,
                cut,
                CutCause::FanInCap {
                    backup_capacity: rows_per_node,
                },
                &mut totals,
            );
            if let (Some(first), Some(last)) = (totals.first, totals.last) {
                cuts.push(FannedInAuditCapCut {
                    node_id,
                    removed: totals.removed,
                    backed_up: totals.backed_up,
                    first_origin_id: first,
                    last_origin_id: last,
                });
            }
            outcome?;
        }
        Ok(cuts)
    }

    /// The [`FANNED_IN_AUDIT_CAP_ACTION`] row recording one cut, for
    /// this node's own chain.
    ///
    /// The figures ride in the action, after the `:` where an action
    /// carries its detail, because a row stores its payloads hashed and
    /// the point here is that an operator can read them, on this node's
    /// chain and on its `lorica::audit` stream alike. They are integers
    /// this store computed; the node id is the session-proved one the
    /// fan-in stamped, as in every other `cluster_node` target.
    fn cap_cut_entry(cut: &FannedInAuditCapCut) -> crate::audit::NewAuditEntry {
        let actor = crate::audit::AuditContext::node("cluster");
        crate::audit::NewAuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operator_username: actor.username,
            operator_role: actor.role,
            action: format!(
                "{FANNED_IN_AUDIT_CAP_ACTION}:rows={},origin_ids={}..={},backed_up={},deleted={}",
                cut.removed,
                cut.first_origin_id,
                cut.last_origin_id,
                cut.backed_up,
                cut.deleted()
            ),
            target_type: "cluster_node".to_string(),
            target_id: cut.node_id.clone(),
            before_payload_hash: String::new(),
            after_payload_hash: String::new(),
            ip: actor.ip,
            user_agent: actor.user_agent,
        }
    }

    /// The column a chain's prefix cut is positioned on: the aggregated
    /// `id` for the local chain, the origin's `origin_id` for a
    /// fanned-in one. Always the column [`LogStore::chain_order`] sorts
    /// on, for the reason that function gives.
    fn chain_position(node_id: &str) -> &'static str {
        if node_id.is_empty() {
            "id"
        } else {
            "origin_id"
        }
    }

    /// Cut `node_id`'s chain up to and including position `cut`, in
    /// sealed prefix cuts of [`AUDIT_CHUNK`] rows with the connection
    /// released between them, adding what each took to `totals` as it
    /// goes so a caller still knows what was cut when a later chunk
    /// fails. `cause` is passed to [`LogStore::cut_chain_prefix`].
    fn cut_chain_in_chunks(
        &self,
        node_id: &str,
        cut: i64,
        cause: CutCause,
        totals: &mut PrefixCut,
    ) -> Result<(), String> {
        use rusqlite::OptionalExtension;
        let step_sql = Self::cut_step_sql(node_id);
        loop {
            let conn = self.conn.lock();
            let chunk_end: Option<i64> = conn
                .query_row(&step_sql, params![node_id, cut, AUDIT_CHUNK - 1], |row| {
                    row.get(0)
                })
                .optional()
                .map_err(|e| format!("failed to size an audit cut chunk: {e}"))?;
            // Fewer than a chunk left at or below the cut: the rest goes
            // in this one.
            let step = chunk_end.unwrap_or(cut);
            let done = Self::cut_chain_prefix(&conn, node_id, step, cause)?;
            totals.absorb(done);
            if step >= cut || done.removed == 0 {
                return Ok(());
            }
        }
    }

    /// Cut `node_id`'s chain up to and including position `cut`,
    /// sealing it, and return what went.
    ///
    /// The seal is the `prev_chain_hash` of the first row that
    /// survives, or, when nothing does, the `chain_hash` of the chain's
    /// tail, which is what the next row that arrives will name. Either
    /// way verify and insert then treat it as the chain's genesis. A
    /// fanned-in chain also records the cut position, below which
    /// [`LogStore::insert_fanned_in_audit`] stores nothing again.
    ///
    /// Cut by the fan-in cap (never retention, never the local chain),
    /// the oldest rows of the cut are moved into the node's fan-in
    /// backup rather than deleted, as
    /// [`LogStore::enforce_fanned_in_audit_cap`] describes (see
    /// [`LogStore::move_to_fanned_in_backup`]), and the cut is recorded
    /// in this node's own chain, its `lorica::audit` event emitted once
    /// the record is committed.
    ///
    /// Seal, move, delete and record commit in ONE transaction. Written
    /// apart, a failure between them would leave a seal naming a row
    /// that is still the chain's first, and verify would report a break
    /// that nothing tampered with, or rows deleted that the backup was
    /// owed, or a cut no record names.
    fn cut_chain_prefix(
        conn: &Connection,
        node_id: &str,
        cut: i64,
        cause: CutCause,
    ) -> Result<PrefixCut, String> {
        use rusqlite::{OptionalExtension, Transaction, TransactionBehavior};
        let (order, tail_order) = Self::chain_order(node_id);
        let position = Self::chain_position(node_id);
        let filter = Self::chain_filter(node_id);
        // IMMEDIATE for the reason `insert_audit_into` gives: another
        // process on the same file must not slip a write in between
        // the read the seal is taken from and the delete.
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
            .map_err(|e| format!("failed to open the audit cut transaction: {e}"))?;

        // Nothing at or below the cut: nothing to seal either. Resealing
        // here would overwrite the anchor of a chain that lost no row.
        let first: Option<(i64, String)> = tx
            .query_row(
                &format!(
                    "SELECT {position}, prev_chain_hash FROM audit_log WHERE {filter} AND {position} <= ?2 ORDER BY {order} LIMIT 1"
                ),
                params![node_id, cut],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| format!("failed to read the first audit row of a cut: {e}"))?;
        let Some((first_position, first_prev)) = first else {
            return Ok(PrefixCut::default());
        };

        let survivor_prev: Option<String> = tx
            .query_row(
                &format!(
                    "SELECT prev_chain_hash FROM audit_log WHERE {filter} AND {position} > ?2 ORDER BY {order} LIMIT 1"
                ),
                params![node_id, cut],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to read earliest surviving audit row: {e}"))?;

        let seal: Option<String> = match survivor_prev {
            Some(prev) => Some(prev),
            None => tx
                .query_row(
                    &format!(
                        "SELECT chain_hash FROM audit_log WHERE {filter} ORDER BY {tail_order} LIMIT 1"
                    ),
                    params![node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| format!("failed to read audit chain tail: {e}"))?,
        };

        let backed_up = match cause {
            CutCause::FanInCap { backup_capacity } if !node_id.is_empty() => {
                Self::move_to_fanned_in_backup(&tx, node_id, cut, backup_capacity, &first_prev)?
            }
            _ => 0,
        };

        if let Some(seal) = seal {
            Self::set_audit_meta(&tx, &Self::seal_key(node_id), &seal)?;
        }
        if !node_id.is_empty() {
            Self::set_audit_meta(&tx, &Self::cut_floor_key(node_id), &cut.to_string())?;
        }

        let deleted = tx
            .execute(
                &format!("DELETE FROM audit_log WHERE {filter} AND {position} <= ?2"),
                params![node_id, cut],
            )
            .map_err(|e| format!("failed to enforce audit retention: {e}"))?;
        let done = PrefixCut {
            removed: deleted as u64,
            backed_up,
            first: Some(first_position),
            last: Some(cut),
        };

        let record = match cause {
            CutCause::FanInCap { .. } if deleted > 0 => {
                let entry = Self::cap_cut_entry(&FannedInAuditCapCut {
                    node_id: node_id.to_string(),
                    removed: done.removed,
                    backed_up,
                    first_origin_id: first_position,
                    last_origin_id: cut,
                });
                let (_id, chain_hash) = Self::append_local_audit_in(&tx, &entry)?;
                Some((entry, chain_hash))
            }
            _ => None,
        };

        tx.commit()
            .map_err(|e| format!("failed to commit the audit cut: {e}"))?;
        if let Some((entry, chain_hash)) = record {
            crate::audit::emit_stored_event(&entry, &chain_hash);
        }
        Ok(done)
    }

    /// Inside a cut's transaction, copy the oldest rows of
    /// `node_id`'s chain at or below `cut` into its fan-in backup, as
    /// many as the backup still has room for, and return how many.
    ///
    /// Room is `capacity` less every row EVER moved for the node, a
    /// count kept beside the seal rather than read off the table, which
    /// is what makes the backup fill once: rows retention ages out of
    /// it do not free room for later ones. And a run joins the backup
    /// only when its first row chains onto the last row moved, the
    /// `chain_hash` also kept beside the seal. Rows cut while the
    /// backup was full or closed, or by day-based retention, sit
    /// between the two otherwise, and a backup holding that hole could
    /// never verify; so the first gap closes it.
    fn move_to_fanned_in_backup(
        tx: &Connection,
        node_id: &str,
        cut: i64,
        capacity: u64,
        first_prev: &str,
    ) -> Result<u64, String> {
        let rows_key = Self::backup_rows_key(node_id);
        let tail_key = Self::backup_tail_key(node_id);
        let moved_before: u64 = Self::audit_meta(tx, &rows_key)?
            .and_then(|rows| rows.parse().ok())
            .unwrap_or(0);
        let room = capacity.saturating_sub(moved_before);
        if room == 0 {
            return Ok(0);
        }
        if let Some(tail) = Self::audit_meta(tx, &tail_key)? {
            if tail != first_prev {
                return Ok(0);
            }
        }
        let moved = tx
            .execute(
                &format!(
                    "INSERT INTO {FANNED_IN_BACKUP_TABLE} ({FANNED_IN_BACKUP_COLUMNS})
                     SELECT {FANNED_IN_BACKUP_COLUMNS} FROM audit_log
                     WHERE node_id = ?1 AND origin_id <= ?2 ORDER BY origin_id ASC LIMIT ?3"
                ),
                params![node_id, cut, i64::try_from(room).unwrap_or(i64::MAX)],
            )
            .map_err(|e| format!("failed to move audit rows into the fan-in backup: {e}"))?;
        if moved == 0 {
            return Ok(0);
        }
        let tail: String = tx
            .query_row(
                &format!(
                    "SELECT chain_hash FROM {FANNED_IN_BACKUP_TABLE}
                     WHERE node_id = ?1 ORDER BY origin_id DESC LIMIT 1"
                ),
                params![node_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to read the audit fan-in backup tail: {e}"))?;
        let moved = moved as u64;
        Self::set_audit_meta(tx, &rows_key, &(moved_before + moved).to_string())?;
        Self::set_audit_meta(tx, &tail_key, &tail)?;
        Ok(moved)
    }
}

/// The escape declaration every `LIKE` predicate built from caller text
/// carries.
///
/// SQLite has no default escape character, so a pattern containing a
/// backslash means nothing without this clause; it is part of the
/// predicate, not a decoration on it.
const LIKE_ESCAPE: &str = r"ESCAPE '\'";

/// `text` as a `LIKE` operand that matches itself and nothing else.
///
/// `%` and `_` are wildcards inside a `LIKE` pattern and every filter
/// below interpolates caller text into one. Unescaped, a search for
/// `%` matches every row while reading as a narrow filter, which is a
/// result an operator or a model draws a conclusion from. The
/// backslash goes first, or it would escape the escapes added after it.
fn like_operand(text: &str) -> String {
    text.replace('\\', r"\\")
        .replace('%', r"\%")
        .replace('_', r"\_")
}

/// Helper to re-box a ToSql value for a second bind pass.
/// We only store String and i64 values, so this covers all cases.
fn copy_to_sql(val: &dyn rusqlite::types::ToSql) -> Box<dyn rusqlite::types::ToSql> {
    use rusqlite::types::{ToSqlOutput, Value};
    match val.to_sql().unwrap_or(ToSqlOutput::Owned(Value::Null)) {
        ToSqlOutput::Owned(Value::Text(s)) => Box::new(s),
        ToSqlOutput::Owned(Value::Integer(i)) => Box::new(i),
        ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Text(b)) => {
            Box::new(String::from_utf8_lossy(b).to_string())
        }
        ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Integer(i)) => Box::new(i),
        _ => Box::new(String::new()),
    }
}

#[cfg(test)]
mod waf_stats_tests {
    use super::*;

    fn tmp_store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LogStore::open(dir.path()).expect("open store");
        (store, dir)
    }

    fn mk_event(rule_id: u32, category: lorica_waf::RuleCategory) -> lorica_waf::WafEvent {
        lorica_waf::WafEvent {
            rule_id,
            description: "test".into(),
            category,
            severity: 1,
            matched_field: "uri".into(),
            matched_value: "x".into(),
            timestamp: "2026-04-21T12:00:00Z".into(),
            client_ip: "127.0.0.1".into(),
            route_hostname: "example.com".into(),
            action: "block".into(),
        }
    }

    /// The v1.5.1 fix : `waf_event_stats` must return the real
    /// table size (via `COUNT(*)`), not the length of a
    /// load-and-count page. Insert more rows than the old 10 000
    /// cap and confirm the counter does not plateau.
    #[test]
    fn waf_event_stats_is_not_capped_at_ten_thousand() {
        let (store, _dir) = tmp_store();
        let n = 10_050u32;
        for i in 0..n {
            let cat = if i % 3 == 0 {
                lorica_waf::RuleCategory::Xss
            } else if i % 3 == 1 {
                lorica_waf::RuleCategory::SqlInjection
            } else {
                lorica_waf::RuleCategory::PathTraversal
            };
            store.insert_waf_event(&mk_event(i, cat)).expect("insert");
        }
        let (total, _total_24h, by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, n as u64, "total must reflect the full table");
        let sum: u64 = by_cat.iter().map(|(_, c)| c).sum();
        assert_eq!(sum, n as u64, "per-category counts must sum to total");
        // Ordering is high-to-low.
        for pair in by_cat.windows(2) {
            assert!(pair[0].1 >= pair[1].1);
        }
    }

    #[test]
    fn waf_event_stats_groups_by_category() {
        let (store, _dir) = tmp_store();
        for _ in 0..3 {
            store
                .insert_waf_event(&mk_event(1, lorica_waf::RuleCategory::Xss))
                .expect("insert");
        }
        store
            .insert_waf_event(&mk_event(2, lorica_waf::RuleCategory::SqlInjection))
            .expect("insert");
        let (total, _total_24h, by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, 4);
        assert_eq!(by_cat.len(), 2);
        // XSS first (3 > 1).
        assert_eq!(by_cat[0].1, 3);
        assert_eq!(by_cat[1].1, 1);
    }

    #[test]
    fn cached_waf_stats_are_reused_within_their_age_and_dropped_by_a_clear() {
        let (store, _dir) = tmp_store();
        let an_hour = std::time::Duration::from_secs(3600);
        store
            .insert_waf_event(&mk_event(1, lorica_waf::RuleCategory::Xss))
            .expect("insert");
        assert_eq!(store.waf_event_stats_within(an_hour).expect("stats").0, 1);

        // A row recorded inside the window does not move the cached
        // answer: the table is not scanned again.
        store
            .insert_waf_event(&mk_event(2, lorica_waf::RuleCategory::SqlInjection))
            .expect("insert");
        let cached = store.waf_event_stats_within(an_hour).expect("stats");
        assert_eq!(cached.0, 1);
        assert_eq!(cached.2.len(), 1);

        // An answer older than the age asked for is recomputed, and is
        // what the uncached aggregate says.
        let fresh = store
            .waf_event_stats_within(std::time::Duration::ZERO)
            .expect("stats");
        assert_eq!(fresh, store.waf_event_stats().expect("stats"));
        assert_eq!(fresh.0, 2);

        // A clear never reads as the counts it emptied.
        store.clear_waf_events().expect("clear");
        assert_eq!(
            store.waf_event_stats_within(an_hour).expect("stats"),
            (0, 0, Vec::new())
        );
    }

    #[test]
    fn waf_event_stats_on_empty_table() {
        let (store, _dir) = tmp_store();
        let (total, total_24h, by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, 0);
        assert_eq!(total_24h, 0);
        assert!(by_cat.is_empty());
    }

    /// Backlog #44 : with `waf_event_retention` capping the table,
    /// the global total plateaus near the cap and stops carrying
    /// signal, so `waf_event_stats` also returns a rolling 24h count.
    /// Insert rows dated well in the past and rows dated now, then
    /// assert `total_24h` counts only the recent ones while `total`
    /// still reflects the whole table.
    #[test]
    fn waf_event_stats_counts_only_last_24h() {
        let (store, _dir) = tmp_store();
        let old_ts: String = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
        let recent_ts: String = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();

        for i in 0..4 {
            let mut ev = mk_event(i, lorica_waf::RuleCategory::Xss);
            ev.timestamp = old_ts.clone();
            store.insert_waf_event(&ev).expect("insert old");
        }
        for i in 0..3 {
            let mut ev = mk_event(i, lorica_waf::RuleCategory::SqlInjection);
            ev.timestamp = recent_ts.clone();
            store.insert_waf_event(&ev).expect("insert recent");
        }

        let (total, total_24h, _by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, 7, "total must reflect the whole table");
        assert_eq!(total_24h, 3, "total_24h must count only rows within 24h");
    }
}

#[cfg(test)]
mod notification_history_tests {
    use super::*;

    fn tmp_store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LogStore::open(dir.path()).expect("open store");
        (store, dir)
    }

    fn mk_event(i: u32) -> lorica_notify::AlertEvent {
        lorica_notify::AlertEvent {
            alert_type: lorica_notify::events::AlertType::ConfigChanged,
            summary: format!("event {i}"),
            details: std::collections::HashMap::new(),
            timestamp: "2026-04-21T12:00:00Z".into(),
        }
    }

    /// Regression pin for the v1.5.1 fix : the notification
    /// history endpoint previously returned `events.len()` as
    /// the total, which would plateau at the `list_` page size
    /// once the history table grew past it. `notification_history_count`
    /// uses `SELECT COUNT(*)` so the total tracks the real row
    /// count regardless of the page size.
    #[test]
    fn notification_history_count_is_not_capped_at_the_page_size() {
        let (store, _dir) = tmp_store();
        let n = 250u32; // > the 200 page size used by the API handler.
        for i in 0..n {
            store
                .insert_notification_event(&mk_event(i))
                .expect("insert");
        }
        let count = store.notification_history_count().expect("count");
        assert_eq!(count, n as u64);
        // Listing is still capped to the page size.
        let events = store.list_notification_history(200).expect("list");
        assert_eq!(events.len(), 200);
    }

    #[test]
    fn notification_history_count_on_empty_table() {
        let (store, _dir) = tmp_store();
        assert_eq!(store.notification_history_count().expect("count"), 0);
    }
}

#[cfg(test)]
mod fleet_audit_tests {
    use super::*;
    use crate::audit::{FannedInAuditRow, NewAuditEntry};

    fn store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let store = LogStore::open(dir.path()).expect("test setup: log store opens");
        (store, dir)
    }

    fn local_entry(action: &str) -> NewAuditEntry {
        NewAuditEntry {
            timestamp: "2026-09-09T10:00:00Z".to_string(),
            operator_username: "admin".to_string(),
            operator_role: "super_admin".to_string(),
            action: action.to_string(),
            target_type: "route".to_string(),
            target_id: "r1".to_string(),
            before_payload_hash: String::new(),
            after_payload_hash: String::new(),
            ip: "192.0.2.10".to_string(),
            user_agent: "curl".to_string(),
        }
    }

    /// Build a chain the way an origin node would, so the rows that
    /// arrive are exactly what that node published.
    fn origin_chain(actions: &[&str]) -> Vec<FannedInAuditRow> {
        let mut prev = crate::audit::GENESIS_HASH.to_string();
        let mut out = Vec::new();
        for (i, action) in actions.iter().enumerate() {
            let entry = local_entry(action);
            let chain_hash =
                crate::audit::compute_chain_hash(&prev, &crate::audit::ChainInput::from(&entry));
            out.push(FannedInAuditRow {
                origin_id: i as i64 + 1,
                timestamp: entry.timestamp,
                operator_username: entry.operator_username,
                operator_role: entry.operator_role,
                action: entry.action,
                target_type: entry.target_type,
                target_id: entry.target_id,
                before_payload_hash: entry.before_payload_hash,
                after_payload_hash: entry.after_payload_hash,
                ip: entry.ip,
                user_agent: entry.user_agent,
                prev_chain_hash: prev.clone(),
                chain_hash: chain_hash.clone(),
            });
            prev = chain_hash;
        }
        out
    }

    /// Recompute a chain's hashes after editing its rows, so a
    /// fixture stays something a real origin node could have produced.
    fn rechain(rows: Vec<FannedInAuditRow>) -> Vec<FannedInAuditRow> {
        let mut prev = crate::audit::GENESIS_HASH.to_string();
        let mut out = Vec::new();
        for mut row in rows {
            row.prev_chain_hash = prev.clone();
            let entry = NewAuditEntry {
                timestamp: row.timestamp.clone(),
                operator_username: row.operator_username.clone(),
                operator_role: row.operator_role.clone(),
                action: row.action.clone(),
                target_type: row.target_type.clone(),
                target_id: row.target_id.clone(),
                before_payload_hash: row.before_payload_hash.clone(),
                after_payload_hash: row.after_payload_hash.clone(),
                ip: row.ip.clone(),
                user_agent: row.user_agent.clone(),
            };
            row.chain_hash =
                crate::audit::compute_chain_hash(&prev, &crate::audit::ChainInput::from(&entry));
            prev = row.chain_hash.clone();
            out.push(row);
        }
        out
    }

    #[test]
    fn a_far_future_timestamp_does_not_keep_a_fanned_in_row_forever() {
        // The origin chooses `timestamp`; this store chooses when the
        // row arrived. Retention ages a fanned-in row by the latter,
        // so a node stamping its rows in 2999 cannot hold the control
        // plane's database hostage.
        let (store, _dir) = store();
        let mut rows = origin_chain(&["a.one", "a.two"]);
        for row in &mut rows {
            row.timestamp = "2999-01-01T00:00:00Z".to_string();
        }
        let rebuilt = rechain(rows);
        store
            .insert_fanned_in_audit("node-a", &rebuilt)
            .expect("fan-in");

        // A cutoff a minute from now is after the arrival time of
        // every row and before their own stamp.
        let cutoff = (chrono::Utc::now() + chrono::Duration::minutes(1)).to_rfc3339();
        let deleted = store.enforce_audit_retention(&cutoff).expect("retention");
        assert_eq!(deleted, 2, "both rows aged out by arrival time");
        assert_eq!(
            store.audit_node_ids().expect("chains"),
            Vec::<String>::new(),
            "nothing of that chain survives"
        );
    }

    #[test]
    fn retention_cuts_a_chain_as_a_prefix_of_its_own_order() {
        // A fanned-in chain is ordered by the origin's id and aged by
        // when each row ARRIVED here; its timestamps are that node's
        // own and play no part. Deleting by any per-row predicate
        // would take a row out of the MIDDLE and verify would then
        // report tampering caused by a retention pass, so the cut is
        // a prefix: the last expired row and everything before it.
        let (store, _dir) = store();
        let mut rows = origin_chain(&["a.one", "a.two", "a.three"]);
        // The origin stamps its FIRST row in the far future; that
        // must not keep it.
        rows[0].timestamp = "2999-01-01T00:00:00Z".to_string();
        let rebuilt = rechain(rows);
        store
            .insert_fanned_in_audit("node-a", &rebuilt)
            .expect("fan-in");
        // The first two rows arrived long ago, the third just now.
        store.backdate_arrival("node-a", 1, "2026-01-01T00:00:00Z");
        store.backdate_arrival("node-a", 2, "2026-01-01T00:00:01Z");

        store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");

        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(
            result.verified,
            "retention left a hole in the chain: {result:?}"
        );
        assert_eq!(
            result.total_rows, 1,
            "the cut takes the expired row and everything before it in chain order"
        );
    }

    #[test]
    fn a_fanned_in_row_never_joins_this_node_s_chain() {
        // The reason AC #2 demands a separate insert path. If fan-in
        // went through `insert_audit`, this node's next entry would
        // chain off a follower's row and its own chain would be
        // verifiable by nothing but this exact aggregate.
        let (store, _dir) = store();
        let (_, first_local) = store
            .insert_audit(&local_entry("route.create"))
            .expect("local");
        store
            .insert_fanned_in_audit("node-a", &origin_chain(&["backend.create"]))
            .expect("fan-in");
        let (_, second_local) = store
            .insert_audit(&local_entry("route.delete"))
            .expect("local");

        let (rows, _) = store
            .query_audit(&crate::audit::AuditQuery {
                limit: 10,
                node_id: Some(String::new()),
                ..Default::default()
            })
            .expect("query");
        let newest = rows.first().expect("a local row");
        assert_eq!(newest.chain_hash, second_local);
        assert_eq!(
            newest.prev_chain_hash, first_local,
            "the local chain skips the fanned-in row entirely"
        );
    }

    #[test]
    fn each_node_s_chain_verifies_on_its_own_and_the_unpartitioned_walk_would_not() {
        let (store, _dir) = store();
        store
            .insert_audit(&local_entry("route.create"))
            .expect("local");
        store
            .insert_fanned_in_audit("node-a", &origin_chain(&["a.one", "a.two"]))
            .expect("fan-in a");
        store
            .insert_audit(&local_entry("route.delete"))
            .expect("local");
        store
            .insert_fanned_in_audit("node-b", &origin_chain(&["b.one"]))
            .expect("fan-in b");

        for node_id in ["", "node-a", "node-b"] {
            let result = store.verify_audit_chain_for(node_id).expect("verify");
            assert!(
                result.verified,
                "chain {node_id} did not verify: {result:?}"
            );
        }
        assert_eq!(
            store.audit_node_ids().expect("node ids"),
            vec!["".to_string(), "node-a".to_string(), "node-b".to_string()]
        );
    }

    #[test]
    fn a_re_sent_batch_is_acknowledged_in_full_and_stored_once() {
        // Two properties in one test because they are two halves of the
        // same requirement. The table must not gain a duplicate, and
        // the caller must be told the rows are held: the drain advances
        // its cursor only on a full acknowledgement, so answering with
        // the newly-written count would freeze that node's cursors
        // permanently the first time a push was not fully accepted.
        let (store, _dir) = store();
        let rows = origin_chain(&["a.one", "a.two"]);
        assert_eq!(
            store
                .insert_fanned_in_audit("node-a", &rows)
                .expect("first"),
            2
        );
        assert_eq!(
            store
                .insert_fanned_in_audit("node-a", &rows)
                .expect("second"),
            2,
            "a re-sent batch is acknowledged in full, or the cursor never moves again"
        );

        let (all, _) = store
            .query_audit(&crate::audit::AuditQuery {
                limit: 100,
                node_id: Some("node-a".to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(all.len(), 2, "the second delivery stored no duplicate");
        assert!(
            store
                .verify_audit_chain_for("node-a")
                .expect("verify")
                .verified
        );
    }

    #[test]
    fn a_chain_that_arrives_mid_history_verifies_from_where_fan_in_started() {
        // Fan-in starts at a node's present, not its history: a node
        // that joins an existing fleet ships what it records from then
        // on. So the first row to arrive names a predecessor this store
        // will never hold, and without an arrival seal verify would
        // report `prev_hash_mismatch` on it forever, on every healthy
        // fleet.
        let (store, _dir) = store();
        let full = origin_chain(&["a.one", "a.two", "a.three"]);
        let tail = &full[1..];
        assert_eq!(
            store
                .insert_fanned_in_audit("node-a", tail)
                .expect("fan-in"),
            2
        );

        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(
            result.verified,
            "a chain that starts mid-history still verifies: {result:?}"
        );
        assert_eq!(result.total_rows, 2);
    }

    #[test]
    fn the_arrival_seal_is_written_once_and_not_moved_by_later_batches() {
        // A later batch must not reseal the chain: doing so would let a
        // node that skipped rows hide the gap by resealing over it.
        let (store, _dir) = store();
        let full = origin_chain(&["a.one", "a.two", "a.three", "a.four"]);
        store
            .insert_fanned_in_audit("node-a", &full[0..2])
            .expect("first batch");
        // A batch that skips `a.three` entirely.
        store
            .insert_fanned_in_audit("node-a", &full[3..4])
            .expect("second batch");

        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(!result.verified, "the gap is reported rather than resealed");
        assert_eq!(
            result.first_break_reason.as_deref(),
            Some("prev_hash_mismatch")
        );
    }

    #[test]
    fn a_fanned_in_row_cannot_claim_to_be_local() {
        // The empty node id is this node's own marker. A row claiming
        // it would splice another node's history into this node's
        // chain, which is the one thing the separate path exists to
        // prevent.
        let (store, _dir) = store();
        assert!(store
            .insert_fanned_in_audit("", &origin_chain(&["a.one"]))
            .is_err());
    }

    #[test]
    fn a_tampered_fanned_in_row_is_reported_rather_than_repaired() {
        // Storing verbatim is the point: the aggregated copy is worth
        // something only if it matches what the node published. A row
        // whose hash does not recompute must stay as it arrived.
        let (store, _dir) = store();
        let mut rows = origin_chain(&["a.one", "a.two"]);
        rows[1].action = "a.two.tampered".to_string();
        store
            .insert_fanned_in_audit("node-a", &rows)
            .expect("fan-in");

        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(!result.verified);
        assert_eq!(
            result.first_break_reason.as_deref(),
            Some("chain_hash_mismatch")
        );
    }

    #[test]
    fn retention_seals_every_chain_not_just_the_local_one() {
        // A truncation crosses every node's rows at once. Sealing only
        // the local key would leave each fanned-in chain unverifiable
        // from its new first surviving row.
        let (store, _dir) = store();
        let mut old = local_entry("route.create");
        old.timestamp = "2026-01-01T00:00:00Z".to_string();
        store.insert_audit(&old).expect("local old");
        store
            .insert_audit(&local_entry("route.delete"))
            .expect("local new");

        let rows = origin_chain(&["a.one", "a.two"]);
        store
            .insert_fanned_in_audit("node-a", &rows)
            .expect("fan-in");
        store.backdate_arrival("node-a", 1, "2026-01-01T00:00:00Z");

        let deleted = store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");
        assert_eq!(deleted, 2, "one local row and one fanned-in row expired");

        for node_id in ["", "node-a"] {
            assert!(
                store
                    .verify_audit_chain_for(node_id)
                    .expect("verify")
                    .verified,
                "chain {node_id} lost its seal"
            );
        }
    }

    #[test]
    fn the_drain_ships_only_this_node_s_own_rows() {
        // A control plane demoted to a follower must not re-ship every
        // other node's rows under its own session identity.
        let (store, _dir) = store();
        store
            .insert_audit(&local_entry("route.create"))
            .expect("local");
        store
            .insert_fanned_in_audit("node-a", &origin_chain(&["a.one"]))
            .expect("fan-in");

        let shipped = store.audit_rows_after(0, 100).expect("drain read");
        assert_eq!(shipped.len(), 1);
        assert_eq!(shipped[0].1.action, "route.create");
        assert_eq!(
            store.newest_local_audit_id().expect("newest"),
            shipped[0].0 as u64
        );
    }

    fn rows_held(store: &LogStore, node_id: &str) -> u64 {
        store
            .query_audit(&crate::audit::AuditQuery {
                limit: 1,
                node_id: Some(node_id.to_string()),
                ..Default::default()
            })
            .expect("count a chain")
            .1
    }

    fn oldest_origin_id(store: &LogStore, node_id: &str) -> i64 {
        store
            .conn
            .lock()
            .query_row(
                "SELECT MIN(origin_id) FROM audit_log WHERE node_id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .expect("oldest origin id")
    }

    fn cut_summary(cuts: &[FannedInAuditCapCut]) -> Vec<(String, u64)> {
        cuts.iter()
            .map(|cut| (cut.node_id.clone(), cut.removed))
            .collect()
    }

    /// The origin ids the fan-in backup holds for `node_id`, in order.
    fn backup_origin_ids(store: &LogStore, node_id: &str) -> Vec<i64> {
        let conn = store.conn.lock();
        let mut stmt = conn
            .prepare(&format!(
                "SELECT origin_id FROM {FANNED_IN_BACKUP_TABLE} WHERE node_id = ?1 ORDER BY origin_id"
            ))
            .expect("backup query");
        let ids = stmt
            .query_map(params![node_id], |row| row.get(0))
            .expect("backup rows")
            .map(|id| id.expect("a backup row"))
            .collect();
        ids
    }

    #[test]
    fn the_audit_cap_cuts_only_the_oldest_rows_of_a_chain_over_it() {
        // Backlog #72. The node over the ceiling loses its OLDEST rows,
        // as a prefix of its own order, and nobody else loses anything:
        // not a node under the ceiling, and not this node's own chain,
        // which is over the ceiling here on purpose.
        let (store, _dir) = store();
        for n in 0..5 {
            store
                .insert_audit(&local_entry(&format!("local.{n}")))
                .expect("local");
        }
        let noisy = origin_chain(&["a.1", "a.2", "a.3", "a.4", "a.5", "a.6", "a.7"]);
        store
            .insert_fanned_in_audit("node-a", &noisy[..5])
            .expect("fan-in a");
        store
            .insert_fanned_in_audit("node-b", &origin_chain(&["b.1", "b.2"]))
            .expect("fan-in b");

        let cut = store.enforce_fanned_in_audit_cap(3).expect("cap");

        assert_eq!(cut_summary(&cut), vec![("node-a".to_string(), 2)]);
        assert_eq!(rows_held(&store, "node-a"), 3);
        assert_eq!(
            oldest_origin_id(&store, "node-a"),
            3,
            "the two oldest rows went, not two arbitrary ones"
        );
        assert_eq!(rows_held(&store, "node-b"), 2, "a node under the cap");
        assert_eq!(
            rows_held(&store, ""),
            5 + 1,
            "the local chain is never capped; it gains the row recording the cut"
        );
        for node_id in ["", "node-a", "node-b"] {
            let result = store.verify_audit_chain_for(node_id).expect("verify");
            assert!(result.verified, "chain {node_id} after the cap: {result:?}");
        }

        // The node keeps pushing. Its next rows chain off a row the cap
        // kept, and the seal the cap wrote is not the arrival seal, so
        // nothing about the cut may make the continuation read as a gap.
        store
            .insert_fanned_in_audit("node-a", &noisy[5..])
            .expect("fan-in a continues");
        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(
            result.verified,
            "the chain continues past the cut: {result:?}"
        );
        assert_eq!(result.total_rows, 5);
    }

    #[test]
    fn a_chain_under_the_audit_cap_is_left_exactly_as_it_was() {
        // Not merely "no rows deleted": the seal must not move either,
        // or a chain that was never cut would be resealed every hour.
        let (store, _dir) = store();
        let full = origin_chain(&["a.1", "a.2", "a.3"]);
        // Arrives mid-history, so the chain already carries an arrival
        // seal that a careless pass would overwrite.
        store
            .insert_fanned_in_audit("node-a", &full[1..])
            .expect("fan-in");
        let seal_before = LogStore::audit_seal_for(&store.conn.lock(), "node-a").expect("seal");

        let cut = store
            .enforce_fanned_in_audit_cap(2)
            .expect("cap at exactly");
        assert!(cut.is_empty(), "a chain AT the cap is not over it");
        let cut = store.enforce_fanned_in_audit_cap(10).expect("cap above");
        assert!(cut.is_empty());

        assert_eq!(rows_held(&store, "node-a"), 2);
        assert_eq!(
            LogStore::audit_seal_for(&store.conn.lock(), "node-a").expect("seal"),
            seal_before
        );
        assert!(
            store
                .verify_audit_chain_for("node-a")
                .expect("verify")
                .verified
        );
    }

    #[test]
    fn an_audit_cap_cut_across_several_chunks_still_verifies() {
        // The reclaim releases the connection between chunks so the
        // audit writer is not starved, which makes every chunk a cut of
        // its own. Each must leave the chain sealed and whole.
        let (store, _dir) = store();
        let chunk = AUDIT_CHUNK as u64;
        let total = chunk * 2 + chunk / 2;
        let actions: Vec<String> = (0..total).map(|n| format!("a.{n}")).collect();
        let actions: Vec<&str> = actions.iter().map(String::as_str).collect();
        store
            .insert_fanned_in_audit("node-a", &origin_chain(&actions))
            .expect("fan-in");

        let keep = 100;
        let cut = store.enforce_fanned_in_audit_cap(keep).expect("cap");

        assert_eq!(
            cut_summary(&cut),
            vec![("node-a".to_string(), total - keep)]
        );
        assert_eq!(cut[0].backed_up, keep, "the backup fills to the cap");
        let result = store.verify_audit_chain_for("node-a").expect("verify");
        assert!(result.verified, "a chunked cut left a hole: {result:?}");
        assert_eq!(result.total_rows, keep);
        let backup = store
            .verify_fanned_in_backup("node-a")
            .expect("verify backup")
            .expect("a backup");
        assert_eq!(verdict(&backup), (true, keep, None, None));
        assert_eq!(
            oldest_origin_id(&store, "node-a"),
            (total - keep) as i64 + 1
        );
    }

    /// A chain of `n` rows as its origin would have published it.
    fn long_origin_chain(n: usize) -> Vec<FannedInAuditRow> {
        let actions: Vec<String> = (1..=n).map(|i| format!("a.{i}")).collect();
        let actions: Vec<&str> = actions.iter().map(String::as_str).collect();
        origin_chain(&actions)
    }

    /// Verify in one chunk: the walk as it was before it was chunked,
    /// against which every chunked verdict below is compared.
    fn verify_whole(store: &LogStore, node_id: &str) -> crate::audit::VerifyResult {
        store
            .verify_audit_chain_chunked(node_id, i64::MAX, &mut || {})
            .expect("whole verify")
    }

    fn verdict(result: &crate::audit::VerifyResult) -> (bool, u64, Option<i64>, Option<&str>) {
        (
            result.verified,
            result.total_rows,
            result.first_break_id,
            result.first_break_reason.as_deref(),
        )
    }

    #[test]
    fn a_chain_walked_in_several_chunks_verifies_in_full() {
        let (store, _dir) = store();
        for n in 0..10 {
            store
                .insert_audit(&local_entry(&format!("local.{n}")))
                .expect("local");
        }
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(10))
            .expect("fan-in");
        for node_id in ["", "node-a"] {
            let mut pauses = 0;
            let result = store
                .verify_audit_chain_chunked(node_id, 3, &mut || pauses += 1)
                .expect("verify");
            assert_eq!(
                verdict(&result),
                (true, 10, None, None),
                "chain {node_id:?}"
            );
            assert_eq!(pauses, 3, "four chunks, the lock released between each");
        }
    }

    #[test]
    fn a_break_in_a_later_chunk_is_reported_as_the_whole_walk_reports_it() {
        let (store, _dir) = store();
        for n in 0..10 {
            store
                .insert_audit(&local_entry(&format!("local.{n}")))
                .expect("local");
        }
        let mut rows = long_origin_chain(10);
        rows[7].action = "a.8.tampered".to_string();
        store
            .insert_fanned_in_audit("node-a", &rows)
            .expect("fan-in");
        // A rewritten row and a deleted one, both past the first chunk.
        {
            let conn = store.conn.lock();
            conn.execute(
                "UPDATE audit_log SET target_id = '999' WHERE node_id = '' AND id = 8",
                [],
            )
            .expect("tamper");
        }
        let (store_deleted, _dir_deleted) = super::tests_support::store_with_local_rows(10);
        store_deleted
            .conn
            .lock()
            .execute("DELETE FROM audit_log WHERE id = 7", [])
            .expect("delete");

        for (store, node_id, reason) in [
            (&store, "", "chain_hash_mismatch"),
            (&store, "node-a", "chain_hash_mismatch"),
            (&store_deleted, "", "prev_hash_mismatch"),
        ] {
            let whole = verify_whole(store, node_id);
            let chunked = store
                .verify_audit_chain_chunked(node_id, 3, &mut || {})
                .expect("chunked verify");
            assert!(!whole.verified);
            assert_eq!(whole.first_break_reason.as_deref(), Some(reason));
            assert_eq!(verdict(&chunked), verdict(&whole), "chain {node_id:?}");
        }
    }

    #[test]
    fn rows_appended_while_the_walk_is_paused_are_not_a_break() {
        let (store, _dir) = store();
        for n in 0..6 {
            store
                .insert_audit(&local_entry(&format!("local.{n}")))
                .expect("local");
        }
        let chain = long_origin_chain(12);
        store
            .insert_fanned_in_audit("node-a", &chain[..6])
            .expect("fan-in");

        let mut appended = 0;
        let mut append = || {
            store
                .insert_audit(&local_entry(&format!("local.late.{appended}")))
                .expect("local append");
            store
                .insert_fanned_in_audit("node-a", &chain[6 + appended..7 + appended])
                .expect("fan-in append");
            appended += 1;
        };
        for node_id in ["", "node-a"] {
            let at_start = super::tests_support::count_audit_rows(&store, node_id);
            let result = store
                .verify_audit_chain_chunked(node_id, 2, &mut append)
                .expect("verify");
            assert_eq!(
                verdict(&result),
                (true, at_start as u64, None, None),
                "chain {node_id:?} is walked to the head it had when the walk began"
            );
            assert!(
                super::tests_support::count_audit_rows(&store, node_id) > at_start,
                "rows landed on chain {node_id:?} during its walk"
            );
        }
        for node_id in ["", "node-a"] {
            assert!(verify_whole(&store, node_id).verified, "chain {node_id:?}");
        }
    }

    #[test]
    fn a_prefix_cut_landing_mid_walk_is_not_a_break() {
        // Ahead of the cursor: the cap takes rows the walk has not
        // reached, and the next chunk starts at the new first row.
        let (ahead, _ahead_dir) = store();
        ahead
            .insert_fanned_in_audit("node-a", &long_origin_chain(20))
            .expect("fan-in");
        let mut pauses = 0;
        let result = ahead
            .verify_audit_chain_chunked("node-a", 4, &mut || {
                pauses += 1;
                if pauses == 1 {
                    ahead.enforce_fanned_in_audit_cap(5).expect("cap");
                }
            })
            .expect("verify");
        assert_eq!(oldest_origin_id(&ahead, "node-a"), 16, "the cut landed");
        assert_eq!(verdict(&result), (true, 9, None, None));

        // Behind the cursor: the cut takes only rows already walked.
        let (behind, _behind_dir) = store();
        behind
            .insert_fanned_in_audit("node-a", &long_origin_chain(20))
            .expect("fan-in");
        let mut pauses = 0;
        let result = behind
            .verify_audit_chain_chunked("node-a", 4, &mut || {
                pauses += 1;
                if pauses == 2 {
                    behind.enforce_fanned_in_audit_cap(15).expect("cap");
                }
            })
            .expect("verify");
        assert_eq!(oldest_origin_id(&behind, "node-a"), 6, "the cut landed");
        assert_eq!(verdict(&result), (true, 20, None, None));

        // Retention on the local chain, cutting through the cursor.
        let (local, _local_dir) = super::tests_support::store_with_local_rows(10);
        let mut pauses = 0;
        let result = local
            .verify_audit_chain_chunked("", 3, &mut || {
                pauses += 1;
                if pauses == 2 {
                    local
                        .enforce_audit_retention("2026-08-08T00:00:00+00:00")
                        .expect("retention");
                }
            })
            .expect("verify");
        assert_eq!(
            super::tests_support::count_audit_rows(&local, ""),
            3,
            "the cut landed"
        );
        assert_eq!(verdict(&result), (true, 9, None, None));
    }

    #[test]
    fn a_row_deleted_under_the_cursor_without_a_cut_is_still_reported() {
        // Re-anchoring on the seal is only sound because a cut moves
        // the seal. A row deleted any other way leaves it where it was,
        // and the next row, which names the deleted one, is a break.
        let (store, _dir) = store();
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(12))
            .expect("fan-in");
        let mut pauses = 0;
        let result = store
            .verify_audit_chain_chunked("node-a", 4, &mut || {
                pauses += 1;
                if pauses == 1 {
                    store
                        .conn
                        .lock()
                        .execute(
                            "DELETE FROM audit_log WHERE node_id = 'node-a' AND origin_id = 4",
                            [],
                        )
                        .expect("tamper");
                }
            })
            .expect("verify");
        let fifth: i64 = store
            .conn
            .lock()
            .query_row(
                "SELECT id FROM audit_log WHERE node_id = 'node-a' AND origin_id = 5",
                [],
                |row| row.get(0),
            )
            .expect("fifth row");
        assert_eq!(
            verdict(&result),
            (false, 5, Some(fifth), Some("prev_hash_mismatch"))
        );
        let whole = verify_whole(&store, "node-a");
        assert_eq!(
            (whole.first_break_id, whole.first_break_reason.as_deref()),
            (Some(fifth), Some("prev_hash_mismatch")),
            "a verify started after the deletion reports the same row"
        );
    }

    /// Age every row of `node_id` up to `origin_id` in `table` as if it
    /// arrived at the start of 2026.
    fn age_rows(store: &LogStore, table: &str, node_id: &str, up_to_origin_id: i64) {
        store
            .conn
            .lock()
            .execute(
                &format!(
                    "UPDATE {table} SET received_at = '2026-01-01T00:00:00Z'
                     WHERE node_id = ?1 AND origin_id <= ?2"
                ),
                params![node_id, up_to_origin_id],
            )
            .expect("test setup: age rows");
    }

    #[test]
    fn the_first_rows_the_cap_cuts_are_moved_into_the_backup_oldest_first() {
        // The security audit's case: a follower extends its chain to the
        // cap so the pass evicts what it sent before. The oldest rows
        // ever cut are kept, up to the cap, and only then deleted.
        let (store, _dir) = store();
        let chain = long_origin_chain(12);
        store
            .insert_fanned_in_audit("node-a", &chain[..5])
            .expect("fan-in");

        // Room for three, two cut: both moved.
        let cut = store.enforce_fanned_in_audit_cap(3).expect("cap");
        assert_eq!(
            (
                cut[0].removed,
                cut[0].backed_up,
                cut[0].first_origin_id,
                cut[0].last_origin_id
            ),
            (2, 2, 1, 2)
        );
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2]);

        // Room for one, three cut: the oldest of them is moved, the
        // other two deleted.
        store
            .insert_fanned_in_audit("node-a", &chain[5..8])
            .expect("fan-in");
        let cut = store.enforce_fanned_in_audit_cap(3).expect("cap");
        assert_eq!(
            (cut[0].removed, cut[0].backed_up, cut[0].deleted()),
            (3, 1, 2)
        );
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2, 3]);

        // Full: a further cut deletes, and the backup is left as it was.
        store
            .insert_fanned_in_audit("node-a", &chain[8..])
            .expect("fan-in");
        let cut = store.enforce_fanned_in_audit_cap(3).expect("cap");
        assert_eq!((cut[0].removed, cut[0].backed_up), (4, 0));
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2, 3]);

        assert_eq!(
            verdict(&store.verify_audit_chain_for("node-a").expect("verify")),
            (true, 3, None, None)
        );
        let backup = store
            .verify_fanned_in_backup("node-a")
            .expect("verify backup")
            .expect("a backup");
        assert_eq!(verdict(&backup), (true, 3, None, None));
        assert_eq!(
            store.audit_backup_node_ids().expect("backup nodes"),
            vec!["node-a".to_string()]
        );
        assert_eq!(
            store.verify_fanned_in_backup("node-b").expect("verify"),
            None,
            "a node with no backup has no backup verdict"
        );
    }

    #[test]
    fn every_cap_cut_is_recorded_in_this_node_s_own_chain() {
        let (store, _dir) = store();
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(5))
            .expect("fan-in");
        store.enforce_fanned_in_audit_cap(3).expect("cap");
        // A pass that cuts nothing records nothing.
        store.enforce_fanned_in_audit_cap(3).expect("cap again");

        let (rows, total) = store
            .query_audit(&crate::audit::AuditQuery {
                limit: 10,
                node_id: Some(String::new()),
                action_prefix: Some(FANNED_IN_AUDIT_CAP_ACTION.to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 1);
        let row = &rows[0];
        assert_eq!(
            row.action,
            format!("{FANNED_IN_AUDIT_CAP_ACTION}:rows=2,origin_ids=1..=2,backed_up=2,deleted=0")
        );
        assert_eq!(
            (
                row.target_type.as_str(),
                row.target_id.as_str(),
                row.operator_role.as_str()
            ),
            ("cluster_node", "node-a", "node")
        );
        assert!(
            store.verify_audit_chain_for("").expect("verify").verified,
            "the record is a link of this node's own chain"
        );
    }

    /// The actions of every cap record in this node's own chain, oldest
    /// first.
    fn cap_cut_records(store: &LogStore) -> Vec<String> {
        let (rows, _) = store
            .query_audit(&crate::audit::AuditQuery {
                limit: 100,
                node_id: Some(String::new()),
                action_prefix: Some(FANNED_IN_AUDIT_CAP_ACTION.to_string()),
                ..Default::default()
            })
            .expect("query the cap records");
        rows.into_iter().rev().map(|row| row.action).collect()
    }

    #[test]
    fn a_cap_cut_failing_before_its_commit_leaves_neither_the_cut_nor_its_record() {
        // The record is the chunk's last statement before the commit, so
        // a trigger refusing it is a failure after the seal, the move and
        // the delete have run and before any of them is durable.
        let (store, _dir) = store();
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(5))
            .expect("fan-in");
        let seal_before = LogStore::audit_seal_for(&store.conn.lock(), "node-a").expect("seal");
        store
            .conn
            .lock()
            .execute_batch(&format!(
                "CREATE TEMP TRIGGER refuse_cap_record BEFORE INSERT ON audit_log
                 WHEN NEW.action LIKE '{FANNED_IN_AUDIT_CAP_ACTION}%'
                 BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
            ))
            .expect("test setup: trigger");

        let err = store
            .enforce_fanned_in_audit_cap(3)
            .expect_err("the record is refused, and the cut with it");
        assert!(err.contains("injected failure"), "{err}");
        assert_eq!(rows_held(&store, "node-a"), 5, "no row was cut");
        assert!(
            backup_origin_ids(&store, "node-a").is_empty(),
            "no row was moved"
        );
        {
            let conn = store.conn.lock();
            assert_eq!(
                LogStore::audit_seal_for(&conn, "node-a").expect("seal"),
                seal_before,
                "the seal did not move"
            );
            assert_eq!(
                LogStore::audit_meta(&conn, &LogStore::cut_floor_key("node-a")).expect("floor"),
                None
            );
        }
        assert!(cap_cut_records(&store).is_empty(), "no record either");
        for node_id in ["", "node-a"] {
            assert!(
                store
                    .verify_audit_chain_for(node_id)
                    .expect("verify")
                    .verified,
                "chain {node_id:?} after the rolled-back cut"
            );
        }

        store
            .conn
            .lock()
            .execute_batch("DROP TRIGGER refuse_cap_record")
            .expect("test teardown: trigger");
        let cut = store.enforce_fanned_in_audit_cap(3).expect("cap");
        assert_eq!(
            (cut[0].removed, cut[0].backed_up),
            (2, 2),
            "the retried cut is the whole cut, its backup room untouched"
        );
        assert_eq!(
            cap_cut_records(&store),
            vec![format!(
                "{FANNED_IN_AUDIT_CAP_ACTION}:rows=2,origin_ids=1..=2,backed_up=2,deleted=0"
            )]
        );
    }

    #[test]
    fn every_chunk_of_a_cap_cut_commits_with_its_own_record() {
        let (store, _dir) = store();
        let chunk = AUDIT_CHUNK;
        let total = chunk * 2 + chunk / 2;
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(total as usize))
            .expect("fan-in");
        let keep = 100;

        let cut = store.enforce_fanned_in_audit_cap(keep as u64).expect("cap");

        let last = total - keep;
        let record = |first: i64, end: i64, backed_up: i64| {
            let rows = end - first + 1;
            format!(
                "{FANNED_IN_AUDIT_CAP_ACTION}:rows={rows},origin_ids={first}..={end},backed_up={backed_up},deleted={}",
                rows - backed_up
            )
        };
        assert_eq!(
            cap_cut_records(&store),
            vec![
                record(1, chunk, keep),
                record(chunk + 1, chunk * 2, 0),
                record(chunk * 2 + 1, last, 0),
            ]
        );
        assert_eq!(
            (cut[0].removed, cut[0].backed_up),
            (last as u64, keep as u64),
            "the pass reports the sum of its chunks"
        );
        assert!(
            store.verify_audit_chain_for("").expect("verify").verified,
            "each record is a link of this node's own chain"
        );
    }

    #[test]
    fn retention_ages_the_backup_like_the_chain_it_came_from() {
        let (store, _dir) = store();
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(8))
            .expect("fan-in");
        store.enforce_fanned_in_audit_cap(4).expect("cap");
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2, 3, 4]);

        age_rows(&store, FANNED_IN_BACKUP_TABLE, "node-a", 2);
        let removed = store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");
        assert_eq!(removed, 2, "only the two aged backup rows");
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![3, 4]);
        let backup = store
            .verify_fanned_in_backup("node-a")
            .expect("verify backup")
            .expect("a backup");
        assert_eq!(
            verdict(&backup),
            (true, 2, None, None),
            "the backup verifies from its new first row"
        );
        assert_eq!(rows_held(&store, "node-a"), 4, "the live chain is not aged");

        age_rows(&store, FANNED_IN_BACKUP_TABLE, "node-a", 4);
        store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");
        assert_eq!(
            store.verify_fanned_in_backup("node-a").expect("verify"),
            None
        );
        assert!(store
            .audit_backup_node_ids()
            .expect("backup nodes")
            .is_empty());
    }

    #[test]
    fn a_run_that_does_not_chain_onto_the_backup_closes_it() {
        // Retention deletes rows between two cap cuts. Moving the second
        // cut's rows would leave a hole in the backup that no verify
        // could pass, so the backup keeps what it has and takes no more.
        let (store, _dir) = store();
        let chain = long_origin_chain(12);
        store
            .insert_fanned_in_audit("node-a", &chain[..6])
            .expect("fan-in");
        store.enforce_fanned_in_audit_cap(4).expect("cap");
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2]);

        age_rows(&store, "audit_log", "node-a", 4);
        store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");
        assert_eq!(oldest_origin_id(&store, "node-a"), 5);

        store
            .insert_fanned_in_audit("node-a", &chain[6..])
            .expect("fan-in");
        let cut = store.enforce_fanned_in_audit_cap(4).expect("cap");
        assert_eq!((cut[0].removed, cut[0].backed_up), (4, 0));
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2]);
        assert!(
            store
                .verify_fanned_in_backup("node-a")
                .expect("verify")
                .expect("a backup")
                .verified
        );
    }

    #[test]
    fn a_re_sent_row_at_or_below_a_cut_is_acknowledged_and_not_stored() {
        // A drain whose cursor went back re-sends rows the cap already
        // cut. Stored again, they would sit before the seal and verify
        // would meet them first.
        let (store, _dir) = store();
        let chain = long_origin_chain(8);
        store
            .insert_fanned_in_audit("node-a", &chain[..7])
            .expect("fan-in");
        store.enforce_fanned_in_audit_cap(3).expect("cap");

        assert_eq!(
            store
                .insert_fanned_in_audit("node-a", &chain[..7])
                .expect("re-send"),
            7,
            "acknowledged in full, or the drain cursor freezes"
        );
        assert_eq!(rows_held(&store, "node-a"), 3);
        assert_eq!(oldest_origin_id(&store, "node-a"), 5);

        // The same batch with one new row at its end stores that row.
        store
            .insert_fanned_in_audit("node-a", &chain)
            .expect("re-send with a new row");
        assert_eq!(rows_held(&store, "node-a"), 4);
        assert_eq!(
            verdict(&store.verify_audit_chain_for("node-a").expect("verify")),
            (true, 4, None, None)
        );
    }

    #[test]
    fn a_prefix_cut_landing_before_the_first_chunk_is_not_a_break() {
        // The walk used to read the seal in one lock hold and the first
        // chunk in the next; a cut between the two moved the seal past
        // the anchor already taken.
        let (fanned, _fanned_dir) = store();
        fanned
            .insert_fanned_in_audit("node-a", &long_origin_chain(20))
            .expect("fan-in");
        let result = fanned
            .walk_chain(
                ChainSegment::Live,
                "node-a",
                4,
                &mut || {
                    fanned.enforce_fanned_in_audit_cap(5).expect("cap");
                },
                &mut || {},
            )
            .expect("verify");
        assert_eq!(oldest_origin_id(&fanned, "node-a"), 16, "the cut landed");
        assert_eq!(verdict(&result), (true, 5, None, None));

        let (local, _local_dir) = super::tests_support::store_with_local_rows(10);
        let result = local
            .walk_chain(
                ChainSegment::Live,
                "",
                3,
                &mut || {
                    local
                        .enforce_audit_retention("2026-08-08T00:00:00+00:00")
                        .expect("retention");
                },
                &mut || {},
            )
            .expect("verify");
        assert_eq!(verdict(&result), (true, 3, None, None));
    }

    #[test]
    fn a_backup_aged_under_the_walk_is_not_a_break() {
        let (store, _dir) = store();
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(12))
            .expect("fan-in");
        store.enforce_fanned_in_audit_cap(6).expect("cap");
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![1, 2, 3, 4, 5, 6]);

        // Retention takes the backup's first three rows, the cursor's
        // row with them, between the first chunk and the second.
        let mut pauses = 0;
        let result = store
            .walk_chain(ChainSegment::Backup, "node-a", 2, &mut || {}, &mut || {
                pauses += 1;
                if pauses == 1 {
                    age_rows(&store, FANNED_IN_BACKUP_TABLE, "node-a", 3);
                    store
                        .enforce_audit_retention("2026-06-01T00:00:00Z")
                        .expect("retention");
                }
            })
            .expect("verify backup");
        assert_eq!(backup_origin_ids(&store, "node-a"), vec![4, 5, 6]);
        assert_eq!(
            verdict(&result),
            (true, 5, None, None),
            "rows 1 and 2, then 4 to 6 from the backup's new first row"
        );

        // A tampered backup row is still a break, at its original id.
        let tampered_id: i64 = {
            let conn = store.conn.lock();
            conn.execute(
                &format!(
                    "UPDATE {FANNED_IN_BACKUP_TABLE} SET action = 'forged'
                     WHERE node_id = 'node-a' AND origin_id = 5"
                ),
                [],
            )
            .expect("tamper");
            conn.query_row(
                &format!(
                    "SELECT id FROM {FANNED_IN_BACKUP_TABLE} WHERE node_id = 'node-a' AND origin_id = 5"
                ),
                [],
                |row| row.get(0),
            )
            .expect("the tampered row's id")
        };
        let backup = store
            .verify_fanned_in_backup("node-a")
            .expect("verify backup")
            .expect("a backup");
        assert_eq!(
            verdict(&backup),
            (false, 2, Some(tampered_id), Some("chain_hash_mismatch"))
        );
    }

    #[test]
    fn a_retention_cut_spanning_several_chunks_still_verifies() {
        let (store, _dir) = store();
        let total = AUDIT_CHUNK * 2 + 10;
        store
            .insert_fanned_in_audit("node-a", &long_origin_chain(total as usize))
            .expect("fan-in");
        age_rows(&store, "audit_log", "node-a", total - 5);

        let removed = store
            .enforce_audit_retention("2026-06-01T00:00:00Z")
            .expect("retention");
        assert_eq!(removed, (total - 5) as u64);
        assert_eq!(
            verdict(&store.verify_audit_chain_for("node-a").expect("verify")),
            (true, 5, None, None)
        );
        assert_eq!(
            store.verify_fanned_in_backup("node-a").expect("verify"),
            None,
            "retention never fills the backup"
        );
    }

    /// The `EXPLAIN QUERY PLAN` detail lines for `sql`, joined.
    fn plan_of(store: &LogStore, sql: &str, binds: &[&dyn rusqlite::ToSql]) -> String {
        let conn = store.conn.lock();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .expect("the statement plans");
        let details = stmt
            .query_map(binds, |row| row.get::<_, String>(3))
            .expect("the plan runs");
        details
            .map(|d| d.expect("a plan row"))
            .collect::<Vec<_>>()
            .join(" | ")
    }

    #[test]
    fn every_audit_chain_statement_rides_an_index() {
        // The local chain shares `idx_audit_log_node` with every
        // follower's, and before `origin_id = 0` was spelled out its
        // chunk read sorted every local row (`USE TEMP B-TREE`) and its
        // head and tail reads walked them all. Every statement the
        // verify, the cap, retention, the drain and the local append run
        // is pinned here to a seek, never a scan of the table or of a
        // whole index and never a sort.
        let (store, _dir) = store();
        let cutoff = "2026-06-01T00:00:00Z";
        let mut statements: Vec<(String, String, Vec<&dyn rusqlite::ToSql>)> = vec![
            (
                "local tail".into(),
                LogStore::LOCAL_AUDIT_TAIL_SQL.into(),
                vec![],
            ),
            (
                "local newest".into(),
                LogStore::LOCAL_AUDIT_NEWEST_SQL.into(),
                vec![],
            ),
            (
                "local drain".into(),
                LogStore::LOCAL_AUDIT_DRAIN_SQL.into(),
                vec![&0i64 as &dyn rusqlite::ToSql, &10i64],
            ),
            (
                "fanned-in span".into(),
                LogStore::FANNED_IN_SPAN_SQL.into(),
                vec![&"node-a" as &dyn rusqlite::ToSql],
            ),
            (
                "cap cut".into(),
                LogStore::FANNED_IN_CAP_CUT_SQL.into(),
                vec![&"node-a" as &dyn rusqlite::ToSql, &5i64],
            ),
        ];
        for segment in [ChainSegment::Live, ChainSegment::Backup] {
            statements.push((
                format!("{segment:?} node ids"),
                LogStore::node_ids_sql(segment.table()),
                vec![],
            ));
            let node_ids: &'static [&'static str] = match segment {
                ChainSegment::Live => &["", "node-a"],
                ChainSegment::Backup => &["node-a"],
            };
            for node_id in node_ids {
                let name = |what: &str| format!("{segment:?} {what} of {node_id:?}");
                statements.push((
                    name("head"),
                    LogStore::chain_head_sql(segment, node_id),
                    vec![node_id as &dyn rusqlite::ToSql],
                ));
                statements.push((
                    name("chunk"),
                    LogStore::chain_chunk_sql(segment, node_id),
                    vec![node_id as &dyn rusqlite::ToSql, &1i64, &100i64, &10i64],
                ));
                statements.push((
                    name("row exists"),
                    LogStore::chain_row_exists_sql(segment, node_id),
                    vec![node_id as &dyn rusqlite::ToSql, &3i64],
                ));
                statements.push((
                    name("retention cut"),
                    LogStore::retention_cut_sql(segment, node_id),
                    vec![node_id as &dyn rusqlite::ToSql, &cutoff],
                ));
                if segment == ChainSegment::Live {
                    statements.push((
                        name("cut step"),
                        LogStore::cut_step_sql(node_id),
                        vec![node_id as &dyn rusqlite::ToSql, &100i64, &9i64],
                    ));
                }
            }
        }
        for (name, sql, binds) in &statements {
            let plan = plan_of(&store, sql, binds);
            assert!(
                !plan.contains("SCAN audit_log") && !plan.contains("TEMP B-TREE"),
                "{name} scans or sorts: {plan}"
            );
        }

        let local_chunk = plan_of(
            &store,
            &LogStore::chain_chunk_sql(ChainSegment::Live, ""),
            &[&"" as &dyn rusqlite::ToSql, &1i64, &100i64, &10i64],
        );
        assert!(
            local_chunk
                .contains("idx_audit_log_node (node_id=? AND origin_id=? AND rowid>? AND rowid<?)"),
            "the local chunk seeks its id range inside the node index: {local_chunk}"
        );
        let local_cut = plan_of(
            &store,
            &LogStore::retention_cut_sql(ChainSegment::Live, ""),
            &[&"" as &dyn rusqlite::ToSql, &cutoff],
        );
        assert!(
            local_cut.contains("idx_audit_log_node_age"),
            "retention reads the expired range alone: {local_cut}"
        );
    }

    #[test]
    fn the_retention_spans_seek_both_ends_of_the_table() {
        // `SELECT MIN(id), MAX(id)` in one select is two aggregates, which
        // SQLite's min/max optimisation does not serve: it read every
        // entry of a covering index under the lock the writers wait on,
        // on every pass.
        let (store, _dir) = store();
        for (table, sql) in [
            ("access_logs", LogStore::ACCESS_LOG_SPAN_SQL),
            ("waf_events", LogStore::WAF_EVENTS_SPAN_SQL),
        ] {
            let plan = plan_of(&store, sql, &[]);
            assert!(
                !plan.contains(&format!("SCAN {table}")),
                "the {table} span scans: {plan}"
            );
            assert_eq!(
                plan.matches(&format!("SEARCH {table}")).count(),
                2,
                "one seek per end of {table}: {plan}"
            );
        }
    }
}

#[cfg(test)]
mod tests_support {
    use super::*;

    /// A store holding `n` local audit rows stamped on consecutive days
    /// from 2026-08-01, so a retention cutoff selects a known prefix.
    pub(super) fn store_with_local_rows(n: u32) -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let store = LogStore::open(dir.path()).expect("test setup: log store opens");
        for day in 1..=n {
            store
                .insert_audit(&crate::audit::NewAuditEntry {
                    timestamp: format!("2026-08-{day:02}T12:00:00+00:00"),
                    operator_username: "admin".to_string(),
                    operator_role: "super_admin".to_string(),
                    action: "route.update".to_string(),
                    target_type: "route".to_string(),
                    target_id: day.to_string(),
                    before_payload_hash: String::new(),
                    after_payload_hash: String::new(),
                    ip: "192.0.2.10".to_string(),
                    user_agent: "test".to_string(),
                })
                .expect("test setup: local audit row");
        }
        (store, dir)
    }

    pub(super) fn count_audit_rows(store: &LogStore, node_id: &str) -> i64 {
        store
            .conn
            .lock()
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE node_id = ?1",
                params![node_id],
                |row| row.get(0),
            )
            .expect("count audit rows")
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use crate::audit::{AuditQuery, NewAuditEntry, GENESIS_HASH};

    fn tmp_store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LogStore::open(dir.path()).expect("open store");
        (store, dir)
    }

    fn entry(n: u32, action: &str, operator: &str) -> NewAuditEntry {
        NewAuditEntry {
            timestamp: format!("2026-08-{:02}T12:00:00+00:00", n),
            operator_username: operator.to_string(),
            operator_role: "super_admin".to_string(),
            action: action.to_string(),
            target_type: action.split('.').next().unwrap_or("").to_string(),
            target_id: n.to_string(),
            before_payload_hash: String::new(),
            after_payload_hash: String::new(),
            ip: "192.0.2.10".to_string(),
            user_agent: "test".to_string(),
        }
    }

    #[test]
    fn chain_inserts_and_verifies() {
        let (store, _dir) = tmp_store();
        for n in 1..=5 {
            store
                .insert_audit(&entry(n, "route.create", "alice"))
                .expect("insert");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 5);
        assert!(result.first_break_id.is_none());

        // Genesis row anchors on the all-zero hash.
        let (rows, total) = store
            .query_audit(&AuditQuery {
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 5);
        assert_eq!(rows.last().expect("rows").prev_chain_hash, GENESIS_HASH);
        // Newest first.
        assert_eq!(rows.first().expect("rows").target_id, "5");
    }

    #[test]
    fn two_handles_on_one_file_extend_one_chain() {
        // Backlog #74: `lorica cluster leave` opens its own `LogStore` on
        // the daemon's file. Alternating writers on two handles must
        // extend a single chain; a forked chain fails verification.
        let (store_a, dir) = tmp_store();
        let store_b = LogStore::open(dir.path()).expect("second handle");
        for n in 1..=6 {
            let writer = if n % 2 == 0 { &store_b } else { &store_a };
            writer
                .insert_audit(&entry(n, "cluster.leave", "cli"))
                .expect("insert");
        }
        for store in [&store_a, &store_b] {
            let result = store.verify_audit_chain().expect("verify");
            assert!(result.verified);
            assert_eq!(result.total_rows, 6);
            assert!(result.first_break_id.is_none());
        }
    }

    #[test]
    fn tampering_breaks_at_the_modified_row() {
        let (store, _dir) = tmp_store();
        for n in 1..=4 {
            store
                .insert_audit(&entry(n, "route.update", "alice"))
                .expect("insert");
        }
        {
            let conn = store.conn.lock();
            conn.execute("UPDATE audit_log SET target_id = '999' WHERE id = 2", [])
                .expect("tamper");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(!result.verified);
        assert_eq!(result.first_break_id, Some(2));
        assert_eq!(
            result.first_break_reason.as_deref(),
            Some("chain_hash_mismatch")
        );
    }

    #[test]
    fn deleting_a_middle_row_breaks_the_successor() {
        let (store, _dir) = tmp_store();
        for n in 1..=4 {
            store
                .insert_audit(&entry(n, "backend.delete", "bob"))
                .expect("insert");
        }
        {
            let conn = store.conn.lock();
            conn.execute("DELETE FROM audit_log WHERE id = 2", [])
                .expect("delete");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(!result.verified);
        assert_eq!(result.first_break_id, Some(3));
        assert_eq!(
            result.first_break_reason.as_deref(),
            Some("prev_hash_mismatch")
        );
    }

    #[test]
    fn retention_seal_keeps_chain_verifiable() {
        let (store, _dir) = tmp_store();
        for n in 1..=10 {
            store
                .insert_audit(&entry(n, "cert.renew", "alice"))
                .expect("insert");
        }
        // Truncate the first 5 rows (timestamps 2026-08-01..05).
        let deleted = store
            .enforce_audit_retention("2026-08-06T00:00:00+00:00")
            .expect("retention");
        assert_eq!(deleted, 5);

        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified, "seal must anchor the surviving suffix");
        assert_eq!(result.total_rows, 5);

        // New inserts keep chaining onto the surviving tail.
        store
            .insert_audit(&entry(11, "cert.renew", "alice"))
            .expect("insert");
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 6);
    }

    #[test]
    fn retention_that_empties_the_table_seals_the_tail() {
        let (store, _dir) = tmp_store();
        for n in 1..=3 {
            store
                .insert_audit(&entry(n, "waf.toggle", "alice"))
                .expect("insert");
        }
        let deleted = store
            .enforce_audit_retention("2026-09-01T00:00:00+00:00")
            .expect("retention");
        assert_eq!(deleted, 3);
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 0);

        // The next insert anchors on the seal, not genesis.
        store
            .insert_audit(&entry(4, "waf.toggle", "alice"))
            .expect("insert");
        let (rows, _) = store
            .query_audit(&AuditQuery {
                limit: 1,
                ..Default::default()
            })
            .expect("query");
        assert_ne!(rows[0].prev_chain_hash, GENESIS_HASH);
        assert!(store.verify_audit_chain().expect("verify").verified);
    }

    #[test]
    fn query_filters_operator_action_prefix_and_cursor() {
        let (store, _dir) = tmp_store();
        store
            .insert_audit(&entry(1, "route.create", "alice"))
            .expect("insert");
        store
            .insert_audit(&entry(2, "route.delete", "bob"))
            .expect("insert");
        store
            .insert_audit(&entry(3, "backend.create", "alice"))
            .expect("insert");

        let (rows, total) = store
            .query_audit(&AuditQuery {
                operator: Some("alice".into()),
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);

        let (rows, total) = store
            .query_audit(&AuditQuery {
                action_prefix: Some("route.".into()),
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 2);
        assert!(rows.iter().all(|r| r.action.starts_with("route.")));

        // LIKE wildcards in user input are escaped, not interpreted.
        let (_, total) = store
            .query_audit(&AuditQuery {
                action_prefix: Some("%".into()),
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 0);

        let (rows, total) = store
            .query_audit(&AuditQuery {
                before_id: Some(3),
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(total, 2);
        assert!(rows.iter().all(|r| r.id < 3));

        let (rows, _) = store
            .query_audit(&AuditQuery {
                from: Some("2026-08-02T00:00:00+00:00".into()),
                to: Some("2026-08-02T23:59:59+00:00".into()),
                limit: 10,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].operator_username, "bob");
    }
}

#[cfg(test)]
mod retention_loss_tests {
    use super::*;

    fn tmp_store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LogStore::open(dir.path()).expect("open store");
        (store, dir)
    }

    fn access_entry(n: u64) -> crate::logs::LogEntry {
        crate::logs::LogEntry {
            id: n,
            timestamp: format!("2026-09-09T12:00:{:02}+00:00", n % 60),
            method: "GET".into(),
            path: "/".into(),
            host: "example.com".into(),
            status: 200,
            latency_ms: 3,
            backend: "10.0.0.10:8080".into(),
            error: None,
            client_ip: "192.0.2.10".into(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: format!("req-{n}"),
        }
    }

    #[test]
    fn retention_reports_the_rows_it_took_before_the_drain_sent_them() {
        // Backlog #76: a follower cut off from its control plane keeps
        // logging while local retention keeps trimming. Rows above the drain
        // cursor that retention deletes never reach the fleet view, and a
        // quiet edge used to look exactly like a truncated one.
        let (store, _dir) = tmp_store();
        for n in 0..10 {
            store.insert(&access_entry(n)).expect("insert access row");
        }

        // The drain has sent rows up to id 3; retention keeps four of the
        // ten, so it deletes six, three of which the drain never sent.
        let outcome = store
            .enforce_retention(4, Some(3))
            .expect("retention with a cursor");
        assert_eq!(outcome.deleted, 6);
        assert_eq!(outcome.undrained, 3);

        // Without a cursor the pass reports deletions only: a standalone
        // node has no fleet view to fall short of.
        for n in 10..20 {
            store.insert(&access_entry(n)).expect("insert access row");
        }
        let outcome = store.enforce_retention(4, None).expect("retention");
        assert!(outcome.deleted > 0);
        assert_eq!(outcome.undrained, 0);

        // Nothing to delete is not a loss.
        let outcome = store
            .enforce_retention(1_000, Some(0))
            .expect("retention under the cap");
        assert_eq!(outcome, RetentionOutcome::default());
    }

    #[test]
    fn the_mutation_reserve_is_the_quarter_the_documents_say() {
        assert_eq!(AUDIT_QUEUE_RESERVED_FOR_MUTATIONS * 4, AUDIT_QUEUE_CAPACITY);
    }

    #[test]
    fn the_rows_without_the_count_are_the_rows_with_it() {
        // `/automation/v1/logs` answers no total, so it reads the rows
        // alone; they must be the same rows the counted query answers,
        // filters and limit included.
        let (store, _dir) = tmp_store();
        for n in 0..30 {
            let mut entry = access_entry(n);
            if n % 3 == 0 {
                entry.path = format!("/needle/{n}");
                entry.status = 404;
            }
            store.insert(&entry).expect("insert access row");
        }
        let query =
            |search: Option<&str>, status: Option<u16>, limit: usize| crate::logs::LogsQuery {
                route: None,
                status,
                status_min: None,
                status_max: None,
                time_from: None,
                time_to: None,
                client_ip: None,
                search: search.map(str::to_string),
                limit: Some(limit),
                after_id: None,
                before_id: None,
            };
        for params in [
            query(None, None, 5),
            query(Some("needle"), None, 4),
            query(None, Some(404), 100),
            query(Some("absent"), None, 10),
        ] {
            let (counted, _total) = store.query(&params).expect("counted");
            let rows = store.query_rows(&params).expect("rows alone");
            let ids = |entries: &[crate::logs::LogEntry]| {
                entries.iter().map(|e| e.id).collect::<Vec<_>>()
            };
            assert_eq!(ids(&rows), ids(&counted), "{params:?}");
        }
    }
}
