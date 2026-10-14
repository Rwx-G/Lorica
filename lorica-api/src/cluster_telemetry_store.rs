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

//! The control plane's fan-in database (Story 9.6 AC #2).
//!
//! # Why this is a separate file and a separate connection
//!
//! [`crate::log_store::LogStore`] is one `Mutex<Connection>` shared by
//! every insert, every dashboard query, every retention pass and the
//! audit verify. Fan-in multiplies the write rate by the fleet size:
//! the control plane serves its own traffic AND stores every other
//! node's, so a three-node fleet at 2 000 rps is four write streams
//! through one mutex. Putting that on the control plane's OWN log
//! store would make the fleet's telemetry volume a latency input to
//! the control plane's own dashboard and audit paths.
//!
//! `access-log.db` beside `lorica.db` is the existing precedent for a
//! second file in the data directory; this is a third, on the same
//! terms.
//!
//! # `node_id` comes from the session, never from the payload
//!
//! Every row here carries the `node_id` the mutual-TLS session proved
//! (decision D2). Nothing on the wire carries a node identity, so a
//! compromised follower cannot file rows under another node's name.
//! That is also why the LOCAL tables on each node have no `node_id`
//! column: in a per-node database the value is a constant, and paying
//! per-row storage on the hot path to record a constant is waste.
//!
//! # Retention is a per-node quota (AC #3)
//!
//! A global row cap would make the fleet view shallower than each
//! node's own local log, and would let one noisy edge evict every
//! quiet edge's rows, which is exactly the incident-correlation case
//! this store exists for. Each node gets its own budget, enforced
//! with chunked deletes that release the lock between chunks.
//!
//! The cut is found EXACTLY, by seeking the `rows_per_node`-th newest
//! row for that node through the `(node_id, id)` index, not estimated
//! from `MIN(id)`/`MAX(id)`. The estimate is what `log_store.rs` uses
//! and it is right there, on a single-writer table; on this table
//! `id` is shared by every node, so a node's id span is inflated by
//! every interleaved row from every other node and the estimate
//! overstates by roughly the fleet size. See
//! [`ClusterTelemetryStore::enforce_node_quota`].

use std::path::Path;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension};

/// Rows kept per node, per kind, by default.
///
/// Per NODE, deliberately, not per fleet: see the module doc. The
/// number matches the single-node default so a fleet view is never
/// shallower than the local log it aggregates.
pub const DEFAULT_ROWS_PER_NODE: u64 = 100_000;

/// Rows deleted per retention chunk.
///
/// The lock is released between chunks. A single unbounded
/// `DELETE ... LIMIT` sized at an hour of overflow is what the
/// access-log path does today, and it is the reason a retention pass
/// can stall the ingest writer.
pub const RETENTION_CHUNK: u64 = 2_000;

/// Default page size for a fan-in query.
pub const DEFAULT_PAGE: u32 = 100;

/// Largest page a caller may ask for.
pub const MAX_PAGE: u32 = 1_000;

/// One fanned-in access-log row, as stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FleetAccessRow {
    /// Cursor for pagination: this store's own rowid.
    pub id: i64,
    /// The node the row came from, stamped from the session.
    pub node_id: String,
    /// RFC 3339, as the origin node recorded it.
    pub timestamp: String,
    /// HTTP method.
    pub method: String,
    /// Request path.
    pub path: String,
    /// Request host.
    pub host: String,
    /// Response status, the same width as the wire and local types
    /// so the round trip cannot silently truncate.
    pub status: u32,
    /// End-to-end latency in milliseconds.
    pub latency_ms: u64,
    /// Backend that served it.
    pub backend: String,
    /// Error text, empty when there was none.
    pub error: String,
    /// Client address as the origin node resolved it.
    pub client_ip: String,
    /// Correlation id.
    pub request_id: String,
}

/// One fanned-in WAF event, as stored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FleetWafRow {
    /// Cursor for pagination: this store's own rowid.
    pub id: i64,
    /// The node the event came from, stamped from the session.
    pub node_id: String,
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
    /// The matching value, already truncated by the origin node.
    pub matched_value: String,
    /// RFC 3339, as the origin node recorded it.
    pub timestamp: String,
    /// Client address.
    pub client_ip: String,
    /// Route hostname the event fired on.
    pub route_hostname: String,
    /// What the WAF did.
    pub action: String,
}

/// One node's view of one banned client, as last reported (AC #10).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FleetBanRow {
    /// The node reporting it, stamped from the session.
    pub node_id: String,
    /// The banned client address.
    pub client_ip: String,
    /// Seconds left when the snapshot was taken.
    pub remaining_s: u64,
    /// Why that node banned it.
    pub reason: String,
    /// When the control plane recorded this snapshot, RFC 3339.
    pub observed_at: String,
}

/// Filters for a fan-in query (AC #9).
///
/// Deliberately cursor-paginated rather than offset-paginated, and
/// deliberately without a total: the single-node logs query runs
/// `SELECT COUNT(*)` on every page, which on an aggregated table is a
/// full scan per page under the store lock.
#[derive(Debug, Clone, Default)]
pub struct FleetQuery {
    /// Restrict to one node.
    pub node_id: Option<String>,
    /// Substring match on the host (access) or route hostname (WAF).
    pub route: Option<String>,
    /// Inclusive lower bound on `timestamp`, RFC 3339.
    pub from: Option<String>,
    /// Inclusive upper bound on `timestamp`, RFC 3339.
    pub to: Option<String>,
    /// Exact WAF rule category. WAF queries only: the access table
    /// has no such column, so [`FleetQuery::build_where`] takes the
    /// column name from the caller rather than reading this field
    /// unconditionally.
    pub category: Option<String>,
    /// Return rows with an id strictly BELOW this one. Rows come back
    /// newest first, so this walks backwards through the table.
    pub before_id: Option<i64>,
    /// Rows per page, clamped to [`MAX_PAGE`].
    pub limit: u32,
}

impl FleetQuery {
    /// The page size to actually use.
    fn page(&self) -> u32 {
        match self.limit {
            0 => DEFAULT_PAGE,
            n => n.min(MAX_PAGE),
        }
    }
}

/// What one ingest call stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestOutcome {
    /// Access rows written.
    pub access: u64,
    /// WAF events written.
    pub waf: u64,
    /// Bans recorded.
    pub bans: u64,
}

/// The control plane's fan-in database.
pub struct ClusterTelemetryStore {
    conn: Mutex<Connection>,
}

impl ClusterTelemetryStore {
    /// Open or create `cluster-telemetry.db` in `data_dir`.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text when the file cannot be opened or
    /// the schema cannot be created.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let db_path = data_dir.join("cluster-telemetry.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("failed to open the cluster telemetry database: {e}"))?;

        // Same pragmas as the access-log store: WAL so a reader (the
        // dashboard) does not block the writer (ingest), a busy
        // timeout so a slow retention chunk answers rather than
        // failing, and NORMAL sync because losing the last few
        // telemetry rows on a crash costs nothing.
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; \
             PRAGMA synchronous=NORMAL; \
             PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| format!("failed to configure the cluster telemetry database: {e}"))?;

        // The composite (node_id, timestamp) index AC #9 names is the
        // one the fleet queries actually use: every one of them either
        // filters by node or orders by time within a node. The plain
        // timestamp index serves the cross-fleet view.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS fleet_access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                host TEXT NOT NULL,
                status INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                backend TEXT NOT NULL,
                error TEXT NOT NULL DEFAULT '',
                client_ip TEXT NOT NULL DEFAULT '',
                is_xff INTEGER NOT NULL DEFAULT 0,
                xff_proxy_ip TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                request_id TEXT NOT NULL DEFAULT ''
            );
            -- (node_id, id) serves BOTH the retention cut and every
            -- node-scoped read, all of which order by id DESC. The
            -- (node_id, timestamp) index alone forced either a sort
            -- or a rowid scan filtering row by row.
            CREATE INDEX IF NOT EXISTS idx_fleet_access_node_id
                ON fleet_access_logs(node_id, id);
            CREATE INDEX IF NOT EXISTS idx_fleet_access_node_ts
                ON fleet_access_logs(node_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_fleet_access_ts
                ON fleet_access_logs(timestamp);

            CREATE TABLE IF NOT EXISTS fleet_waf_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id TEXT NOT NULL,
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
            CREATE INDEX IF NOT EXISTS idx_fleet_waf_node_id
                ON fleet_waf_events(node_id, id);
            CREATE INDEX IF NOT EXISTS idx_fleet_waf_node_ts
                ON fleet_waf_events(node_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_fleet_waf_ts
                ON fleet_waf_events(timestamp);
            -- The category filter (backlog #70). Without these the
            -- planner walks id DESC testing every row, so a rare or
            -- absent category scans the node's whole quota (or the
            -- whole table) under the lock every ingest needs. One per
            -- shape: the leading node_id cannot serve the fleet-wide
            -- query. IF NOT EXISTS is also the migration: an existing
            -- file gains them on its next open.
            CREATE INDEX IF NOT EXISTS idx_fleet_waf_category
                ON fleet_waf_events(node_id, category, id);
            CREATE INDEX IF NOT EXISTS idx_fleet_waf_category_fleet
                ON fleet_waf_events(category, id);

            -- Bans are a SNAPSHOT, not a stream (decision D3): a node
            -- holds them in memory and rebuilds from nothing on
            -- restart, so the fleet view keeps the latest snapshot per
            -- (node, address) rather than a history that could never
            -- be complete.
            CREATE TABLE IF NOT EXISTS fleet_bans (
                node_id TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                remaining_s INTEGER NOT NULL,
                reason TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                PRIMARY KEY (node_id, client_ip)
            );",
        )
        .map_err(|e| format!("failed to initialise the cluster telemetry schema: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Store one node's batch, stamping every row with `node_id`.
    ///
    /// `node_id` is the caller's, taken from the authenticated
    /// session; nothing in `access`, `waf` or `bans` is trusted to
    /// name a node.
    ///
    /// The whole batch is one transaction: a partial batch would
    /// leave the follower's cursor ambiguous.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text when the transaction fails.
    pub fn ingest(
        &self,
        node_id: &str,
        access: &[lorica_cluster::TelemetryAccessRow],
        waf: &[lorica_cluster::TelemetryWafRow],
        bans: &[lorica_cluster::TelemetryBan],
    ) -> Result<IngestOutcome, String> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| format!("failed to open a telemetry transaction: {e}"))?;
        let observed_at = chrono::Utc::now().to_rfc3339();

        {
            // One prepared statement reused across the batch rather
            // than a fresh compile per row. Up to 512 rows run under
            // the store lock, which every other node's ingest and
            // every dashboard read also wait on.
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO fleet_access_logs
                        (node_id, timestamp, method, path, host, status, latency_ms,
                         backend, error, client_ip, is_xff, xff_proxy_ip, source, request_id)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                )
                .map_err(|e| format!("failed to prepare the access insert: {e}"))?;
            for row in access {
                stmt.execute(rusqlite::params![
                    node_id,
                    row.timestamp,
                    row.method,
                    row.path,
                    row.host,
                    i64::from(row.status),
                    i64::try_from(row.latency_ms).unwrap_or(i64::MAX),
                    row.backend,
                    row.error,
                    row.client_ip,
                    i64::from(row.is_xff),
                    row.xff_proxy_ip,
                    row.source,
                    row.request_id,
                ])
                .map_err(|e| format!("failed to store a fanned-in access row: {e}"))?;
            }
        }

        {
            let mut stmt = tx
                .prepare_cached(
                    "INSERT INTO fleet_waf_events
                        (node_id, rule_id, description, category, severity, matched_field,
                         matched_value, timestamp, client_ip, route_hostname, action)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .map_err(|e| format!("failed to prepare the WAF insert: {e}"))?;
            for row in waf {
                stmt.execute(rusqlite::params![
                    node_id,
                    i64::from(row.rule_id),
                    row.description,
                    row.category,
                    i64::from(row.severity),
                    row.matched_field,
                    row.matched_value,
                    row.timestamp,
                    row.client_ip,
                    row.route_hostname,
                    row.action,
                ])
                .map_err(|e| format!("failed to store a fanned-in WAF event: {e}"))?;
            }
        }

        // A snapshot replaces what that node last reported for that
        // address; a node that no longer reports an address has let
        // the ban lapse, which `prune_stale_bans` reclaims.
        for ban in bans {
            tx.execute(
                "INSERT OR REPLACE INTO fleet_bans
                    (node_id, client_ip, remaining_s, reason, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    node_id,
                    ban.client_ip,
                    i64::try_from(ban.remaining_s).unwrap_or(i64::MAX),
                    ban.reason,
                    observed_at,
                ],
            )
            .map_err(|e| format!("failed to store a fanned-in ban: {e}"))?;
        }

        tx.commit()
            .map_err(|e| format!("failed to commit a telemetry batch: {e}"))?;

        Ok(IngestOutcome {
            access: access.len() as u64,
            waf: waf.len() as u64,
            bans: bans.len() as u64,
        })
    }

    /// Replace a node's whole ban snapshot with `bans`.
    ///
    /// A snapshot is authoritative for the node that sent it: an
    /// address absent from it is no longer banned there. Without this
    /// a lifted ban would linger in the fleet view until the row was
    /// evicted by something else.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text when the transaction fails.
    pub fn replace_ban_snapshot(
        &self,
        node_id: &str,
        bans: &[lorica_cluster::TelemetryBan],
    ) -> Result<u64, String> {
        let mut conn = self.conn.lock();
        let tx = conn
            .transaction()
            .map_err(|e| format!("failed to open a ban transaction: {e}"))?;
        tx.execute(
            "DELETE FROM fleet_bans WHERE node_id = ?1",
            rusqlite::params![node_id],
        )
        .map_err(|e| format!("failed to clear a node's bans: {e}"))?;
        let observed_at = chrono::Utc::now().to_rfc3339();
        for ban in bans {
            tx.execute(
                "INSERT OR REPLACE INTO fleet_bans
                    (node_id, client_ip, remaining_s, reason, observed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    node_id,
                    ban.client_ip,
                    i64::try_from(ban.remaining_s).unwrap_or(i64::MAX),
                    ban.reason,
                    observed_at,
                ],
            )
            .map_err(|e| format!("failed to store a fanned-in ban: {e}"))?;
        }
        tx.commit()
            .map_err(|e| format!("failed to commit a ban snapshot: {e}"))?;
        Ok(bans.len() as u64)
    }

    /// Every node that has rows in either table.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn nodes_with_rows(&self) -> Result<Vec<String>, String> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                "SELECT node_id FROM fleet_access_logs
                 UNION
                 SELECT node_id FROM fleet_waf_events
                 ORDER BY node_id",
            )
            .map_err(|e| format!("failed to list telemetry nodes: {e}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| format!("failed to list telemetry nodes: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a telemetry node: {e}"))?);
        }
        Ok(out)
    }

    /// Enforce `rows_per_node` on one node's rows in one table,
    /// deleting in chunks and releasing the lock between them.
    ///
    /// Returns how many rows were removed.
    ///
    /// # Why this is not a `MIN(id)` / `MAX(id)` estimate
    ///
    /// It was, and that was wrong here. `id` is ONE autoincrement
    /// sequence shared by every node writing into this table, so a
    /// node's id span is inflated by every interleaved row from every
    /// other node: with N nodes writing at similar rates the estimate
    /// overstates a node's row count by roughly a factor of N. The
    /// quota then believes a quiet node is far over budget and prunes
    /// it below its allowance, which is exactly the "a noisy edge
    /// evicts a quiet edge's rows" failure per-node retention exists
    /// to prevent. The estimate is sound on the single-writer tables
    /// in `log_store.rs`, where the only gaps come from earlier
    /// deletes; it does not survive being copied to a shared table.
    ///
    /// So this finds the exact cut instead: the id of the
    /// `rows_per_node`-th newest row FOR THIS NODE. Everything of
    /// this node's at or below it is surplus. The walk is bounded by
    /// `rows_per_node` and rides the `(node_id, id)` index, so it
    /// costs neither a full-table scan nor a `COUNT(*)`.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read or delete failure.
    pub fn enforce_node_quota(
        &self,
        table: TelemetryTable,
        node_id: &str,
        rows_per_node: u64,
    ) -> Result<u64, String> {
        let cut: Option<i64> = {
            let conn = self.conn.lock();
            conn.query_row(
                &Self::quota_cut_sql(table),
                rusqlite::params![node_id, i64::try_from(rows_per_node).unwrap_or(i64::MAX)],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| {
                format!(
                    "failed to find the retention cut for {}: {e}",
                    table.as_str()
                )
            })?
        };
        // No row at that offset: the node holds at most its quota.
        let Some(cut) = cut else {
            return Ok(0);
        };

        let mut removed = 0u64;
        loop {
            let chunk = {
                let conn = self.conn.lock();
                conn.execute(
                    &Self::quota_chunk_sql(table),
                    rusqlite::params![
                        node_id,
                        cut,
                        i64::try_from(RETENTION_CHUNK).unwrap_or(i64::MAX)
                    ],
                )
                .map_err(|e| format!("failed to prune {}: {e}", table.as_str()))?
            };
            // The guard is dropped here, between chunks, on purpose:
            // ingest gets the lock back instead of waiting out the
            // whole pass.
            if chunk == 0 {
                return Ok(removed);
            }
            removed += chunk as u64;
        }
    }

    /// The statement that finds [`ClusterTelemetryStore::enforce_node_quota`]'s
    /// cut. Separate, like the two below, so the query-plan tests
    /// inspect the SQL the retention path issues rather than a copy.
    fn quota_cut_sql(table: TelemetryTable) -> String {
        format!(
            "SELECT id FROM {} WHERE node_id = ?1
             ORDER BY id DESC LIMIT 1 OFFSET ?2",
            table.as_str()
        )
    }

    /// One chunk of [`ClusterTelemetryStore::enforce_node_quota`]'s delete.
    fn quota_chunk_sql(table: TelemetryTable) -> String {
        let table = table.as_str();
        format!(
            "DELETE FROM {table} WHERE id IN (
                 SELECT id FROM {table} WHERE node_id = ?1 AND id <= ?2
                 ORDER BY id ASC LIMIT ?3
             )"
        )
    }

    /// One chunk of [`ClusterTelemetryStore::forget_node`]'s delete.
    fn forget_chunk_sql(table: TelemetryTable) -> String {
        let table = table.as_str();
        format!(
            "DELETE FROM {table} WHERE id IN (
                 SELECT id FROM {table} WHERE node_id = ?1 LIMIT ?2
             )"
        )
    }

    /// Drop everything one node ever fanned in: both series and its
    /// ban snapshot. For a node that is no longer in the roster, or
    /// was revoked long enough ago that its last hours are no longer
    /// an incident to review (Epic 9 close, architecture review).
    ///
    /// Without this, a retired node's rows sat at up to twice the
    /// per-node quota for the life of the database, counting toward
    /// the storage watermark whose breach sheds EVERY node: a fleet
    /// that churns hardware slowly walked its own watermark down.
    ///
    /// Chunked like [`ClusterTelemetryStore::enforce_node_quota`], and
    /// for the same reason: ingest gets the lock back between chunks.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a delete failure.
    pub fn forget_node(&self, node_id: &str) -> Result<u64, String> {
        let mut removed = 0u64;
        for table in [TelemetryTable::Access, TelemetryTable::Waf] {
            loop {
                let chunk = {
                    let conn = self.conn.lock();
                    conn.execute(
                        &Self::forget_chunk_sql(table),
                        rusqlite::params![
                            node_id,
                            i64::try_from(RETENTION_CHUNK).unwrap_or(i64::MAX)
                        ],
                    )
                    .map_err(|e| {
                        format!(
                            "failed to reclaim {} for a retired node: {e}",
                            table.as_str()
                        )
                    })?
                };
                if chunk == 0 {
                    break;
                }
                removed += chunk as u64;
            }
        }
        let conn = self.conn.lock();
        removed += conn
            .execute(
                "DELETE FROM fleet_bans WHERE node_id = ?1",
                rusqlite::params![node_id],
            )
            .map_err(|e| format!("failed to reclaim the bans of a retired node: {e}"))?
            as u64;
        Ok(removed)
    }

    /// Drop ban rows nobody has refreshed since `cutoff`.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a delete failure.
    pub fn prune_stale_bans(&self, cutoff: &str) -> Result<u64, String> {
        let conn = self.conn.lock();
        let removed = conn
            .execute(
                "DELETE FROM fleet_bans WHERE observed_at < ?1",
                rusqlite::params![cutoff],
            )
            .map_err(|e| format!("failed to prune stale fleet bans: {e}"))?;
        Ok(removed as u64)
    }

    /// Every node's live bans, as last reported (AC #10).
    ///
    /// A snapshot rather than a history: bans are in-memory state on
    /// each node, so this is what the fleet believed a moment ago and
    /// is lossy across a node restart by construction.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn query_bans(&self, node_id: Option<&str>) -> Result<Vec<FleetBanRow>, String> {
        let conn = self.conn.lock();
        // One shape with a bound filter rather than two statements:
        // an absent `node_id` matches every row instead of branching.
        let mut stmt = conn
            .prepare(
                "SELECT node_id, client_ip, remaining_s, reason, observed_at
                 FROM fleet_bans WHERE (?1 IS NULL OR node_id = ?1)
                 ORDER BY node_id, client_ip",
            )
            .map_err(|e| format!("failed to prepare the fleet ban query: {e}"))?;
        let rows = stmt
            .query_map(rusqlite::params![node_id], |row| {
                Ok(FleetBanRow {
                    node_id: row.get(0)?,
                    client_ip: row.get(1)?,
                    remaining_s: row.get::<_, i64>(2)? as u64,
                    reason: row.get(3)?,
                    observed_at: row.get(4)?,
                })
            })
            .map_err(|e| format!("failed to run the fleet ban query: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a fleet ban row: {e}"))?);
        }
        Ok(out)
    }

    /// One page of fanned-in access rows, newest first (AC #9).
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn query_access(&self, params: &FleetQuery) -> Result<Vec<FleetAccessRow>, String> {
        let (where_clause, binds) = params.build_where("host", None);
        let sql = format!(
            "SELECT id, node_id, timestamp, method, path, host, status, latency_ms,
                    backend, error, client_ip, request_id
             FROM fleet_access_logs {where_clause}
             ORDER BY id DESC LIMIT {}",
            params.page()
        );
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("failed to prepare the fleet log query: {e}"))?;
        let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(FleetAccessRow {
                    id: row.get(0)?,
                    node_id: row.get(1)?,
                    timestamp: row.get(2)?,
                    method: row.get(3)?,
                    path: row.get(4)?,
                    host: row.get(5)?,
                    status: row.get::<_, i64>(6)? as u32,
                    latency_ms: row.get::<_, i64>(7)? as u64,
                    backend: row.get(8)?,
                    error: row.get(9)?,
                    client_ip: row.get(10)?,
                    request_id: row.get(11)?,
                })
            })
            .map_err(|e| format!("failed to run the fleet log query: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a fleet log row: {e}"))?);
        }
        Ok(out)
    }

    /// One page of fanned-in WAF events, newest first (AC #9).
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn query_waf(&self, params: &FleetQuery) -> Result<Vec<FleetWafRow>, String> {
        let (sql, binds) = Self::waf_query_sql(params);
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("failed to prepare the fleet WAF query: {e}"))?;
        let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(refs.as_slice(), |row| {
                Ok(FleetWafRow {
                    id: row.get(0)?,
                    node_id: row.get(1)?,
                    rule_id: row.get::<_, i64>(2)? as u32,
                    description: row.get(3)?,
                    category: row.get(4)?,
                    severity: row.get::<_, i64>(5)? as u32,
                    matched_field: row.get(6)?,
                    matched_value: row.get(7)?,
                    timestamp: row.get(8)?,
                    client_ip: row.get(9)?,
                    route_hostname: row.get(10)?,
                    action: row.get(11)?,
                })
            })
            .map_err(|e| format!("failed to run the fleet WAF query: {e}"))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| format!("failed to read a fleet WAF row: {e}"))?);
        }
        Ok(out)
    }

    /// The statement [`ClusterTelemetryStore::query_waf`] runs, and its
    /// binds. Separate so the query-plan tests inspect the exact SQL
    /// the read path issues rather than a copy that could drift from it.
    fn waf_query_sql(params: &FleetQuery) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let (where_clause, binds) = params.build_where("route_hostname", Some("category"));
        let sql = format!(
            "SELECT id, node_id, rule_id, description, category, severity, matched_field,
                    matched_value, timestamp, client_ip, route_hostname, action
             FROM fleet_waf_events {where_clause}
             ORDER BY id DESC LIMIT {}",
            params.page()
        );
        (sql, binds)
    }

    /// How many rows one node holds in one table. Test and diagnostic
    /// use: it is the `COUNT(*)` the retention path deliberately
    /// avoids, so it must not be called on a request path.
    ///
    /// # Errors
    ///
    /// Returns the SQLite error text on a read failure.
    pub fn count_for_node(&self, table: TelemetryTable, node_id: &str) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM {} WHERE node_id = ?1", table.as_str()),
                rusqlite::params![node_id],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to count telemetry rows: {e}"))?;
        Ok(count as u64)
    }
}

/// Which fan-in table a retention pass or a count addresses.
///
/// An enum rather than a string because both callers interpolate the
/// name into SQL: this makes it impossible for a caller-supplied
/// value to reach that interpolation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryTable {
    /// `fleet_access_logs`.
    Access,
    /// `fleet_waf_events`.
    Waf,
}

impl TelemetryTable {
    /// The table name, a compile-time constant of this module.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Access => "fleet_access_logs",
            Self::Waf => "fleet_waf_events",
        }
    }
}

impl FleetQuery {
    /// Build the shared `WHERE` clause. `route_column` differs between
    /// the two tables and `category_column` exists only on the WAF one;
    /// everything else is identical, and every value is bound rather
    /// than interpolated. Both column names come from this module, not
    /// from a request, which is why interpolating them is safe.
    fn build_where(
        &self,
        route_column: &str,
        category_column: Option<&str>,
    ) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
        let mut conditions: Vec<String> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(node_id) = &self.node_id {
            conditions.push("node_id = ?".to_string());
            binds.push(Box::new(node_id.clone()));
        }
        if let Some(route) = &self.route {
            conditions.push(format!("{route_column} LIKE ?"));
            binds.push(Box::new(format!("%{route}%")));
        }
        // With a category filter the time bounds are written `+timestamp`,
        // which keeps them as filters but out of index selection. Without
        // statistics the planner otherwise prefers `(node_id, timestamp)`
        // or `(timestamp)` for a node plus a time bound, then reads every
        // row of the window and sorts it for `id DESC`: on a rare category
        // that is the whole-quota walk under the ingest lock the category
        // indexes exist to remove (backlog #70).
        let mut timestamp = "timestamp";
        if let (Some(column), Some(category)) = (category_column, &self.category) {
            conditions.push(format!("{column} = ?"));
            binds.push(Box::new(category.clone()));
            timestamp = "+timestamp";
        }
        if let Some(from) = &self.from {
            conditions.push(format!("{timestamp} >= ?"));
            binds.push(Box::new(from.clone()));
        }
        if let Some(to) = &self.to {
            conditions.push(format!("{timestamp} <= ?"));
            binds.push(Box::new(to.clone()));
        }
        if let Some(before) = self.before_id {
            conditions.push("id < ?".to_string());
            binds.push(Box::new(before));
        }
        if conditions.is_empty() {
            (String::new(), binds)
        } else {
            (format!("WHERE {}", conditions.join(" AND ")), binds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_cluster::{TelemetryAccessRow, TelemetryBan, TelemetryWafRow};

    fn store() -> (ClusterTelemetryStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let store = ClusterTelemetryStore::open(dir.path()).expect("test setup: store opens");
        (store, dir)
    }

    fn access_row(host: &str, ts: &str) -> TelemetryAccessRow {
        TelemetryAccessRow {
            timestamp: ts.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            host: host.to_string(),
            status: 200,
            latency_ms: 3,
            backend: "app".to_string(),
            error: String::new(),
            client_ip: "192.0.2.10".to_string(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: "req-1".to_string(),
        }
    }

    fn waf_row(hostname: &str, ts: &str) -> TelemetryWafRow {
        TelemetryWafRow {
            rule_id: 942100,
            description: "SQL injection".to_string(),
            category: "sqli".to_string(),
            severity: 5,
            matched_field: "ARGS:id".to_string(),
            matched_value: "1 OR 1=1".to_string(),
            timestamp: ts.to_string(),
            client_ip: "192.0.2.11".to_string(),
            route_hostname: hostname.to_string(),
            action: "block".to_string(),
        }
    }

    #[test]
    fn every_stored_row_carries_the_node_the_caller_named() {
        let (store, _dir) = store();
        store
            .ingest(
                "node-a",
                &[access_row("a.example.com", "2026-09-09T10:00:00Z")],
                &[waf_row("a.example.com", "2026-09-09T10:00:01Z")],
                &[],
            )
            .expect("ingest");
        store
            .ingest(
                "node-b",
                &[access_row("b.example.com", "2026-09-09T10:00:02Z")],
                &[],
                &[],
            )
            .expect("ingest");

        let all = store.query_access(&FleetQuery::default()).expect("query");
        assert_eq!(all.len(), 2);
        // The identity is the caller's, never the payload's: nothing
        // in `TelemetryAccessRow` names a node at all.
        assert_eq!(all[0].node_id, "node-b");
        assert_eq!(all[1].node_id, "node-a");

        let scoped = store
            .query_access(&FleetQuery {
                node_id: Some("node-a".to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].host, "a.example.com");
    }

    #[test]
    fn a_noisy_node_cannot_evict_a_quiet_one() {
        // The whole reason retention is per node (AC #3): with a
        // global cap, this test's node-b rows would be gone.
        let (store, _dir) = store();
        for i in 0..300 {
            store
                .ingest(
                    "node-noisy",
                    &[access_row(
                        "noisy.example.com",
                        &format!("2026-09-09T10:{i:02}:00Z"),
                    )],
                    &[],
                    &[],
                )
                .expect("ingest");
        }
        store
            .ingest(
                "node-quiet",
                &[access_row("quiet.example.com", "2026-09-09T11:00:00Z")],
                &[],
                &[],
            )
            .expect("ingest");

        let removed = store
            .enforce_node_quota(TelemetryTable::Access, "node-noisy", 100)
            .expect("prune");
        assert!(removed > 0, "the noisy node is over its own quota");
        assert_eq!(
            store
                .count_for_node(TelemetryTable::Access, "node-quiet")
                .expect("count"),
            1,
            "the quiet node keeps every row it sent"
        );
        assert!(
            store
                .count_for_node(TelemetryTable::Access, "node-noisy")
                .expect("count")
                <= 100,
            "the noisy node is brought back to its quota"
        );
    }

    #[test]
    fn interleaved_nodes_do_not_inflate_each_other_s_quota() {
        // The test that was missing, and the reason the shared-id
        // MIN/MAX estimate survived review: the original fixture
        // wrote all of one node's rows before any of the other's, so
        // ids never interleaved and the estimate happened to be
        // right. Interleave them and the estimate overstates each
        // node's count by roughly the number of nodes, which pruned a
        // node that was inside its quota.
        let (store, _dir) = store();
        for i in 0..120 {
            for node in ["node-a", "node-b", "node-c"] {
                store
                    .ingest(
                        node,
                        &[access_row(
                            "x.example.com",
                            &format!("2026-09-09T10:00:{i:02}Z"),
                        )],
                        &[],
                        &[],
                    )
                    .expect("ingest");
            }
        }
        // Every node holds 120 rows, inside a quota of 200. Nothing
        // may be pruned: with the old estimate each node's id span
        // was ~360, so all three looked 160 rows over budget.
        for node in ["node-a", "node-b", "node-c"] {
            assert_eq!(
                store
                    .enforce_node_quota(TelemetryTable::Access, node, 200)
                    .expect("prune"),
                0,
                "{node} is inside its quota and must keep every row"
            );
            assert_eq!(
                store
                    .count_for_node(TelemetryTable::Access, node)
                    .expect("count"),
                120
            );
        }

        // Now cut one node to 50 and check the cut is exact and does
        // not touch its neighbours.
        store
            .enforce_node_quota(TelemetryTable::Access, "node-b", 50)
            .expect("prune");
        assert_eq!(
            store
                .count_for_node(TelemetryTable::Access, "node-b")
                .expect("count"),
            50,
            "the cut is exact, not an estimate"
        );
        for node in ["node-a", "node-c"] {
            assert_eq!(
                store
                    .count_for_node(TelemetryTable::Access, node)
                    .expect("count"),
                120,
                "{node} was not touched by its neighbour's retention"
            );
        }
    }

    #[test]
    fn a_ban_snapshot_is_readable_back_per_node_and_fleet_wide() {
        let (store, _dir) = store();
        let ban = |ip: &str| TelemetryBan {
            client_ip: ip.to_string(),
            remaining_s: 60,
            reason: "waf_flood".to_string(),
        };
        store
            .replace_ban_snapshot("node-a", &[ban("192.0.2.10")])
            .expect("snapshot");
        store
            .replace_ban_snapshot("node-b", &[ban("192.0.2.11")])
            .expect("snapshot");

        let all = store.query_bans(None).expect("read");
        assert_eq!(all.len(), 2);
        let scoped = store.query_bans(Some("node-a")).expect("read");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].node_id, "node-a");
        assert_eq!(scoped[0].client_ip, "192.0.2.10");
        assert_eq!(scoped[0].reason, "waf_flood");
    }

    #[test]
    fn a_quota_pass_on_an_empty_node_is_a_no_op() {
        let (store, _dir) = store();
        assert_eq!(
            store
                .enforce_node_quota(TelemetryTable::Access, "node-never-seen", 100)
                .expect("prune"),
            0
        );
    }

    #[test]
    fn a_ban_snapshot_replaces_what_the_node_last_reported() {
        let (store, _dir) = store();
        let ban = |ip: &str| TelemetryBan {
            client_ip: ip.to_string(),
            remaining_s: 60,
            reason: "waf_flood".to_string(),
        };
        store
            .replace_ban_snapshot("node-a", &[ban("192.0.2.10"), ban("192.0.2.11")])
            .expect("snapshot");
        // The second snapshot no longer names .11: that ban lapsed,
        // and the fleet view must stop showing it.
        store
            .replace_ban_snapshot("node-a", &[ban("192.0.2.10")])
            .expect("snapshot");

        let conn = store.conn.lock();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM fleet_bans WHERE node_id = 'node-a'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(count, 1, "a lapsed ban does not linger in the fleet view");
    }

    #[test]
    fn a_page_walks_backwards_by_cursor_without_counting_anything() {
        let (store, _dir) = store();
        for i in 0..10 {
            store
                .ingest(
                    "node-a",
                    &[access_row(
                        "a.example.com",
                        &format!("2026-09-09T10:{i:02}:00Z"),
                    )],
                    &[],
                    &[],
                )
                .expect("ingest");
        }
        let first = store
            .query_access(&FleetQuery {
                limit: 4,
                ..Default::default()
            })
            .expect("query");
        assert_eq!(first.len(), 4);
        let second = store
            .query_access(&FleetQuery {
                limit: 4,
                before_id: Some(first.last().expect("row").id),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(second.len(), 4);
        assert!(
            second[0].id < first[3].id,
            "the cursor walks strictly backwards, so no row is served twice"
        );
    }

    #[test]
    fn the_time_and_route_filters_bind_their_values() {
        let (store, _dir) = store();
        store
            .ingest(
                "node-a",
                &[
                    access_row("shop.example.com", "2026-09-09T09:00:00Z"),
                    access_row("api.example.com", "2026-09-09T11:00:00Z"),
                ],
                &[],
                &[],
            )
            .expect("ingest");

        let windowed = store
            .query_access(&FleetQuery {
                from: Some("2026-09-09T10:00:00Z".to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0].host, "api.example.com");

        // A quote in the filter must reach the driver as a bound
        // value, not as SQL.
        let hostile = store
            .query_access(&FleetQuery {
                route: Some("' OR 1=1 --".to_string()),
                ..Default::default()
            })
            .expect("a hostile filter is a filter, not an error");
        assert!(hostile.is_empty());
    }

    #[test]
    fn waf_events_filter_on_their_own_route_column() {
        let (store, _dir) = store();
        store
            .ingest(
                "node-a",
                &[],
                &[
                    waf_row("shop.example.com", "2026-09-09T10:00:00Z"),
                    waf_row("api.example.com", "2026-09-09T10:00:01Z"),
                ],
                &[],
            )
            .expect("ingest");
        let scoped = store
            .query_waf(&FleetQuery {
                route: Some("shop".to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].route_hostname, "shop.example.com");
        assert_eq!(scoped[0].node_id, "node-a");
    }

    #[test]
    fn the_category_filter_reaches_the_waf_table_and_nothing_else() {
        let (store, _dir) = store();
        let mut xss = waf_row("shop.example.com", "2026-09-09T10:00:02Z");
        xss.category = "xss".to_string();
        store
            .ingest(
                "node-a",
                &[access_row("shop.example.com", "2026-09-09T10:00:00Z")],
                &[waf_row("shop.example.com", "2026-09-09T10:00:01Z"), xss],
                &[],
            )
            .expect("ingest");

        let sqli = store
            .query_waf(&FleetQuery {
                category: Some("sqli".to_string()),
                ..Default::default()
            })
            .expect("query");
        assert_eq!(sqli.len(), 1);
        assert_eq!(sqli[0].category, "sqli");

        // The access table has no `category` column, so setting the
        // filter must be ignored there rather than producing SQL that
        // names a column the table does not have.
        let access = store
            .query_access(&FleetQuery {
                category: Some("sqli".to_string()),
                ..Default::default()
            })
            .expect("the access query ignores a WAF-only filter");
        assert_eq!(access.len(), 1);
    }

    #[test]
    fn a_hostile_category_is_bound_not_interpolated() {
        let (store, _dir) = store();
        store
            .ingest(
                "node-a",
                &[],
                &[waf_row("shop.example.com", "2026-09-09T10:00:00Z")],
                &[],
            )
            .expect("ingest");
        let hostile = store
            .query_waf(&FleetQuery {
                category: Some("' OR 1=1 --".to_string()),
                ..Default::default()
            })
            .expect("a hostile filter is a filter, not an error");
        assert!(hostile.is_empty());
    }

    #[test]
    fn nodes_with_rows_reports_both_tables() {
        let (store, _dir) = store();
        store
            .ingest("node-a", &[access_row("a.example.com", "t")], &[], &[])
            .expect("ingest");
        store
            .ingest("node-b", &[], &[waf_row("b.example.com", "t")], &[])
            .expect("ingest");
        assert_eq!(
            store.nodes_with_rows().expect("list"),
            vec!["node-a".to_string(), "node-b".to_string()]
        );
    }

    /// The `EXPLAIN QUERY PLAN` detail lines for the statement
    /// [`ClusterTelemetryStore::query_waf`] runs with `params`.
    fn waf_plan(store: &ClusterTelemetryStore, params: &FleetQuery) -> String {
        let (sql, binds) = ClusterTelemetryStore::waf_query_sql(params);
        let refs: Vec<&dyn rusqlite::ToSql> = binds.iter().map(|b| b.as_ref()).collect();
        plan_of(store, &sql, refs.as_slice())
    }

    /// The `EXPLAIN QUERY PLAN` detail lines for `sql`, joined.
    fn plan_of(store: &ClusterTelemetryStore, sql: &str, binds: &[&dyn rusqlite::ToSql]) -> String {
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

    /// Every statement shape `query_waf` can issue: each filter of
    /// [`FleetQuery`] present and absent, in every combination.
    fn every_waf_shape() -> Vec<FleetQuery> {
        // Exhaustive on purpose: a filter added to `FleetQuery` fails
        // to compile here until it is given a place in the loops below.
        let FleetQuery {
            node_id: _,
            route: _,
            from: _,
            to: _,
            category: _,
            before_id: _,
            limit: _,
        } = FleetQuery::default();
        let window = [
            (None, None),
            (Some("2026-09-09T00:00:00Z"), None),
            (None, Some("2026-09-10T00:00:00Z")),
            (Some("2026-09-09T00:00:00Z"), Some("2026-09-10T00:00:00Z")),
        ];
        let mut shapes = Vec::new();
        for node_id in [None, Some("node-1")] {
            for category in [None, Some(RARE_CATEGORY)] {
                for route in [None, Some("shop")] {
                    for (from, to) in window {
                        for before_id in [None, Some(300)] {
                            shapes.push(FleetQuery {
                                node_id: node_id.map(str::to_string),
                                route: route.map(str::to_string),
                                from: from.map(str::to_string),
                                to: to.map(str::to_string),
                                category: category.map(str::to_string),
                                before_id,
                                limit: 0,
                            });
                        }
                    }
                }
            }
        }
        shapes
    }

    const DOMINANT_CATEGORY: &str = "sqli";
    const RARE_CATEGORY: &str = "ssrf";
    const ABSENT_CATEGORY: &str = "never-seen";

    /// 0.1% rare, the rest split 70/20/10 between a dominant category
    /// and two common ones: the shape of a WAF log where one rule
    /// family fires on every scanner and another almost never.
    fn waf_category_for(i: usize) -> &'static str {
        if i % 1000 == 999 {
            RARE_CATEGORY
        } else {
            match i % 10 {
                0..=6 => DOMINANT_CATEGORY,
                7 | 8 => "xss",
                _ => "lfi",
            }
        }
    }

    /// Seed `per_node` WAF rows for each of `nodes` nodes, interleaved
    /// row by row the way concurrent pushes interleave the shared id.
    fn seed_waf_fleet(store: &ClusterTelemetryStore, nodes: usize, per_node: usize) {
        let mut conn = store.conn.lock();
        let tx = conn.transaction().expect("test setup: transaction");
        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO fleet_waf_events
                        (node_id, rule_id, description, category, severity, matched_field,
                         matched_value, timestamp, client_ip, route_hostname, action)
                     VALUES (?1, 942100, 'rule', ?2, 5, 'ARGS:id', '1 OR 1=1',
                             '2026-09-09T10:00:00Z', '192.0.2.11', 'shop.example.com', 'block')",
                )
                .expect("test setup: prepare");
            for i in 0..per_node {
                for n in 0..nodes {
                    stmt.execute(rusqlite::params![format!("node-{n}"), waf_category_for(i)])
                        .expect("test setup: seed a WAF row");
                }
            }
        }
        tx.commit().expect("test setup: commit");
    }

    /// Put the file back in its pre-#70 shape, as a database written by
    /// an earlier release would be.
    fn drop_category_indexes(store: &ClusterTelemetryStore) {
        store
            .conn
            .lock()
            .execute_batch(
                "DROP INDEX idx_fleet_waf_category;
                 DROP INDEX idx_fleet_waf_category_fleet;",
            )
            .expect("test setup: drop the category indexes");
    }

    #[test]
    fn the_category_filter_rides_an_index_in_every_shape() {
        // A plan assertion rather than a timing one: on a small table a
        // scan is as fast as a seek, and what regresses silently is the
        // plan. Without these indexes a rare category walked the whole
        // node quota, or the whole table, under the ingest lock. The
        // time window matters most: it makes the timestamp indexes
        // candidates too, and those cannot deliver id DESC unsorted.
        let (store, _dir) = store();
        seed_waf_fleet(&store, 3, 200);
        for query in every_waf_shape()
            .into_iter()
            .filter(|q| q.category.is_some())
        {
            let plan = waf_plan(&store, &query);
            let expected = if query.node_id.is_some() {
                "USING INDEX idx_fleet_waf_category ("
            } else {
                "USING INDEX idx_fleet_waf_category_fleet ("
            };
            assert!(plan.contains(expected), "{query:?}: {plan}");
            assert!(
                !plan.contains("TEMP B-TREE"),
                "the index must also deliver id DESC without a sort: {query:?}: {plan}"
            );
        }
    }

    #[test]
    fn the_category_indexes_change_no_plan_that_does_not_filter_on_category() {
        // `idx_fleet_waf_category` leads with node_id like
        // `idx_fleet_waf_node_id` does, so the planner could take it for
        // a node-scoped read it cannot order. Every shape without a
        // category must plan exactly as it did before the indexes.
        let (baseline, _baseline_dir) = store();
        let (store, _dir) = store();
        drop_category_indexes(&baseline);
        seed_waf_fleet(&store, 3, 200);
        seed_waf_fleet(&baseline, 3, 200);
        for query in every_waf_shape()
            .into_iter()
            .filter(|q| q.category.is_none())
        {
            let plan = waf_plan(&store, &query);
            assert_eq!(plan, waf_plan(&baseline, &query), "{query:?}");
            assert!(
                !plan.contains("idx_fleet_waf_category"),
                "{query:?}: {plan}"
            );
        }
        let page = waf_plan(
            &store,
            &FleetQuery {
                node_id: Some("node-1".to_string()),
                ..Default::default()
            },
        );
        assert!(
            page.contains("USING INDEX idx_fleet_waf_node_id (") && !page.contains("TEMP B-TREE"),
            "a node's page walks (node_id, id) backwards: {page}"
        );
    }

    #[test]
    fn the_retention_statements_stay_on_the_node_id_index() {
        let (store, _dir) = store();
        seed_waf_fleet(&store, 3, 200);
        let node: &dyn rusqlite::ToSql = &"node-1";
        let cut = plan_of(
            &store,
            &ClusterTelemetryStore::quota_cut_sql(TelemetryTable::Waf),
            &[node, &100i64],
        );
        let chunk = plan_of(
            &store,
            &ClusterTelemetryStore::quota_chunk_sql(TelemetryTable::Waf),
            &[node, &300i64, &100i64],
        );
        let forget = plan_of(
            &store,
            &ClusterTelemetryStore::forget_chunk_sql(TelemetryTable::Waf),
            &[node, &100i64],
        );
        for (name, plan) in [("quota cut", &cut), ("quota chunk", &chunk)] {
            assert!(
                plan.contains("idx_fleet_waf_node_id (") && !plan.contains("TEMP B-TREE"),
                "the {name} walks (node_id, id) in order: {plan}"
            );
        }
        assert!(
            !forget.contains("SCAN fleet_waf_events"),
            "reclaiming a node seeks its rows: {forget}"
        );
    }

    #[test]
    fn an_existing_database_gains_the_category_indexes_on_open() {
        let (store, dir) = store();
        drop_category_indexes(&store);
        drop(store);
        let store = ClusterTelemetryStore::open(dir.path()).expect("reopen");
        let query = FleetQuery {
            category: Some(RARE_CATEGORY.to_string()),
            ..Default::default()
        };
        assert!(waf_plan(&store, &query).contains("idx_fleet_waf_category_fleet"));
        // And a second open over a file that has them is a no-op.
        drop(store);
        ClusterTelemetryStore::open(dir.path()).expect("an idempotent reopen");
    }

    /// Backlog #70 measurement: plan and wall time of the category
    /// filter on a fleet at its per-node row cap. Prints, asserts
    /// nothing; the guard is the plan test below.
    #[test]
    #[ignore = "measurement (backlog #70): seeds five nodes at the per-node row cap"]
    fn measure_waf_category_filter_at_the_row_cap() {
        const NODES: usize = 5;
        let per_node = DEFAULT_ROWS_PER_NODE as usize;
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        {
            let store = ClusterTelemetryStore::open(dir.path()).expect("test setup: open");
            drop_category_indexes(&store);
            let started = std::time::Instant::now();
            seed_waf_fleet(&store, NODES, per_node);
            eprintln!(
                "[#70] seeded {} rows in {:?}",
                NODES * per_node,
                started.elapsed()
            );
        }
        {
            // The write-side price of the category indexes.
            let (indexed, _indexed_dir) = store();
            let started = std::time::Instant::now();
            seed_waf_fleet(&indexed, NODES, per_node);
            eprintln!(
                "[#70] seeded {} rows with the category indexes in {:?}",
                NODES * per_node,
                started.elapsed()
            );
        }
        // Reopening is what an upgraded control plane does: any index
        // the schema gained since the file was written is built here.
        let started = std::time::Instant::now();
        let store = ClusterTelemetryStore::open(dir.path()).expect("reopen");
        eprintln!("[#70] reopen (schema migration) {:?}", started.elapsed());

        for (scope, node) in [("fleet-wide", None), ("one node", Some("node-2"))] {
            for category in [DOMINANT_CATEGORY, RARE_CATEGORY, ABSENT_CATEGORY] {
                let query = FleetQuery {
                    node_id: node.map(str::to_string),
                    category: Some(category.to_string()),
                    ..Default::default()
                };
                let plan = waf_plan(&store, &query);
                let mut times = Vec::new();
                let mut rows = 0;
                for _ in 0..5 {
                    let started = std::time::Instant::now();
                    rows = store.query_waf(&query).expect("query").len();
                    times.push(started.elapsed());
                }
                times.sort();
                eprintln!(
                    "[#70] {scope:<10} category={category:<10} rows={rows:<3} median={:?} max={:?} plan: {plan}",
                    times[2], times[4]
                );
            }
        }
    }
}
