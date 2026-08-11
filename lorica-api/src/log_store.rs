//! SQLite-backed persistent store for access logs, WAF events, and
//! notification history. Used as the source of truth when present, with
//! [`crate::logs::LogBuffer`] as a transient fallback in tests.

use std::path::Path;

use parking_lot::Mutex;

use rusqlite::{params, Connection};

use crate::logs::{LogEntry, LogsQuery};

/// Persistent log database wrapper. Cheaply cloneable through `Arc<LogStore>`.
pub struct LogStore {
    conn: Mutex<Connection>,
}

impl LogStore {
    /// Open or create the access log database in the given directory.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let db_path = data_dir.join("access-log.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("failed to open access log database: {e}"))?;

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

        // Migrate: add columns if missing (existing databases).
        // Each ALTER is separate because execute_batch stops at first error.
        let _ = conn.execute(
            "ALTER TABLE access_logs ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE access_logs ADD COLUMN is_xff INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE access_logs ADD COLUMN xff_proxy_ip TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE access_logs ADD COLUMN source TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE access_logs ADD COLUMN request_id TEXT NOT NULL DEFAULT ''",
            [],
        );

        // Migrate: add columns to waf_events if missing
        let _ = conn.execute(
            "ALTER TABLE waf_events ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE waf_events ADD COLUMN route_hostname TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE waf_events ADD COLUMN action TEXT NOT NULL DEFAULT ''",
            [],
        );

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

        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| format!("failed to set access log pragmas: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
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
                entry.latency_ms,
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
                    entry.latency_ms,
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

    /// Query entries with filtering. Returns newest first.
    /// Query log entries with pagination and filters; returns `(rows, total_match_count)`.
    pub fn query(&self, params: &LogsQuery) -> Result<(Vec<LogEntry>, usize), String> {
        let conn = self.conn.lock();

        let mut conditions = Vec::new();
        let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(ref route) = params.route {
            conditions.push("host LIKE ?".to_string());
            bind_values.push(Box::new(format!("%{route}%")));
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
        if let Some(ref ip) = params.client_ip {
            conditions.push("client_ip LIKE ?".to_string());
            bind_values.push(Box::new(format!("{ip}%")));
        }
        if let Some(ref search) = params.search {
            let pattern = format!("%{search}%");
            conditions.push(
                "(method LIKE ? OR path LIKE ? OR host LIKE ? OR backend LIKE ? OR error LIKE ?)"
                    .to_string(),
            );
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

        let limit = params.limit.unwrap_or(200).min(10_000);

        let count_sql = format!("SELECT COUNT(*) FROM access_logs {where_clause}");
        let refs: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|b| b.as_ref()).collect();
        let total: usize = conn
            .query_row(&count_sql, refs.as_slice(), |row| row.get(0))
            .map_err(|e| format!("failed to count access logs: {e}"))?;

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
            conditions.push("host LIKE ?".to_string());
            bind_values.push(Box::new(format!("%{route}%")));
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
            let pattern = format!("%{search}%");
            conditions.push(
                "(method LIKE ? OR path LIKE ? OR host LIKE ? OR backend LIKE ? OR error LIKE ?)"
                    .to_string(),
            );
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

    /// Delete entries older than the retention limit, keeping at most `max_entries` rows.
    /// Trim the access log table to the most recent `max_entries`. Returns the number deleted.
    ///
    /// Uses `MIN(id)` / `MAX(id)` (both `O(log n)` index seeks on the
    /// PRIMARY KEY rowid) instead of `SELECT COUNT(*)` (which scans
    /// the whole table and could freeze the writer's `Mutex<Connection>`
    /// for hundreds of milliseconds at millions of rows).
    /// `(MAX - MIN + 1)` over-estimates after deletes leave gaps in
    /// the id sequence, which is fine here: trimming slightly more
    /// aggressively than strictly needed cannot violate the retention
    /// contract. The actual DELETE remains exact via the inner ORDER
    /// BY + LIMIT subquery.
    pub fn enforce_retention(&self, max_entries: u64) -> Result<u64, String> {
        let conn = self.conn.lock();
        let bounds: Option<(i64, i64)> = conn
            .query_row("SELECT MIN(id), MAX(id) FROM access_logs", [], |row| {
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
            return Ok(0);
        }

        let to_delete = (approx_count - max_entries) as i64;
        let deleted = conn
            .execute(
                "DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs ORDER BY id ASC LIMIT ?1)",
                params![to_delete],
            )
            .map_err(|e| format!("failed to enforce access log retention: {e}"))?;

        Ok(deleted as u64)
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

    /// Summarise WAF events via SQL aggregation : total count and
    /// per-category counts (sorted high-to-low). Used by
    /// `/api/v1/waf/stats` so the stats are accurate regardless
    /// of table size. The previous implementation loaded up to
    /// 10 000 rows into memory to `.len()` them, which capped
    /// the dashboard counter at 10 000 once the retention window
    /// (100 000 rows) was in use.
    pub fn waf_event_stats(&self) -> Result<(u64, Vec<(String, u64)>), String> {
        let conn = self.conn.lock();
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM waf_events", [], |row| row.get(0))
            .map_err(|e| format!("failed to count WAF events: {e}"))?;
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
        Ok((total as u64, by_category))
    }

    /// Clear all WAF events.
    /// Remove every persisted WAF event row.
    pub fn clear_waf_events(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM waf_events", [])
            .map_err(|e| format!("failed to clear WAF events: {e}"))?;
        Ok(())
    }

    /// Purge old WAF events, keeping at most `max_entries`.
    /// Trim the WAF events table to the most recent `max_entries`. Returns the number deleted.
    pub fn enforce_waf_retention(&self, max_entries: u64) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM waf_events", [], |row| row.get(0))
            .map_err(|e| format!("failed to count WAF events: {e}"))?;
        if count <= max_entries as i64 {
            return Ok(0);
        }
        let to_delete = count - max_entries as i64;
        conn.execute(
            "DELETE FROM waf_events WHERE id IN (SELECT id FROM waf_events ORDER BY id ASC LIMIT ?1)",
            params![to_delete],
        )
        .map_err(|e| format!("failed to enforce WAF event retention: {e}"))?;
        Ok(to_delete as u64)
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
    /// (symmetry with `waf_event_stats` — avoids the same
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

    fn audit_seal(conn: &Connection) -> Result<Option<String>, String> {
        use rusqlite::OptionalExtension;
        conn.query_row(
            "SELECT value FROM audit_log_meta WHERE key = ?1",
            params![Self::RETENTION_SEAL_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| format!("failed to read audit retention seal: {e}"))
    }

    /// Append one audit row. `prev_chain_hash` and `chain_hash` are
    /// computed HERE, inside the connection lock: two concurrent
    /// mutations cannot fork the chain. The previous hash comes from
    /// the newest stored row, else the retention seal, else genesis.
    pub fn insert_audit(&self, entry: &crate::audit::NewAuditEntry) -> Result<i64, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock();

        let last: Option<String> = conn
            .query_row(
                "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to read audit chain head: {e}"))?;

        let prev_chain_hash: String = match last {
            Some(hash) => hash,
            None => Self::audit_seal(&conn)?
                .unwrap_or_else(|| crate::audit::GENESIS_HASH.to_string()),
        };

        let chain_hash: String = crate::audit::compute_chain_hash(
            &prev_chain_hash,
            &crate::audit::ChainInput::from(entry),
        );

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

        Ok(conn.last_insert_rowid())
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
        })
    }

    const AUDIT_COLUMNS: &'static str = "id, timestamp, operator_username, operator_role, \
        action, target_type, target_id, before_payload_hash, after_payload_hash, \
        ip, user_agent, prev_chain_hash, chain_hash";

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
        let conn = self.conn.lock();
        let mut expected: String = Self::audit_seal(&conn)?
            .unwrap_or_else(|| crate::audit::GENESIS_HASH.to_string());

        let sql = format!(
            "SELECT {} FROM audit_log ORDER BY id ASC",
            Self::AUDIT_COLUMNS
        );
        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("failed to prepare audit verify: {e}"))?;
        let rows = stmt
            .query_map([], Self::row_to_audit)
            .map_err(|e| format!("failed to run audit verify: {e}"))?;

        let mut total_rows: u64 = 0;
        for row in rows {
            let record = row.map_err(|e| format!("failed to read audit row: {e}"))?;
            total_rows += 1;
            if record.prev_chain_hash != expected {
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
            expected = record.chain_hash;
        }

        Ok(crate::audit::VerifyResult {
            verified: true,
            total_rows,
            first_break_id: None,
            first_break_reason: None,
        })
    }

    /// Delete audit rows older than `cutoff_timestamp` (RFC 3339),
    /// preserving chain verifiability: before deleting, the earliest
    /// SURVIVING row's `prev_chain_hash` (or, when nothing survives,
    /// the newest deleted row's `chain_hash`) is stored as the
    /// retention seal, which `verify` and `insert` then treat as the
    /// new genesis. Returns the number of rows deleted.
    pub fn enforce_audit_retention(&self, cutoff_timestamp: &str) -> Result<u64, String> {
        use rusqlite::OptionalExtension;
        let conn = self.conn.lock();

        let doomed: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_log WHERE timestamp < ?1",
                params![cutoff_timestamp],
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to count expired audit rows: {e}"))?;
        if doomed == 0 {
            return Ok(0);
        }

        let survivor_prev: Option<String> = conn
            .query_row(
                "SELECT prev_chain_hash FROM audit_log WHERE timestamp >= ?1 ORDER BY id ASC LIMIT 1",
                params![cutoff_timestamp],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| format!("failed to read earliest surviving audit row: {e}"))?;

        let seal: Option<String> = match survivor_prev {
            Some(prev) => Some(prev),
            None => conn
                .query_row(
                    "SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| format!("failed to read audit chain tail: {e}"))?,
        };

        if let Some(seal) = seal {
            conn.execute(
                "INSERT OR REPLACE INTO audit_log_meta (key, value) VALUES (?1, ?2)",
                params![Self::RETENTION_SEAL_KEY, seal],
            )
            .map_err(|e| format!("failed to write audit retention seal: {e}"))?;
        }

        let deleted = conn
            .execute(
                "DELETE FROM audit_log WHERE timestamp < ?1",
                params![cutoff_timestamp],
            )
            .map_err(|e| format!("failed to enforce audit retention: {e}"))?;

        Ok(deleted as u64)
    }
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
        let (total, by_cat) = store.waf_event_stats().expect("stats");
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
        let (total, by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, 4);
        assert_eq!(by_cat.len(), 2);
        // XSS first (3 > 1).
        assert_eq!(by_cat[0].1, 3);
        assert_eq!(by_cat[1].1, 1);
    }

    #[test]
    fn waf_event_stats_on_empty_table() {
        let (store, _dir) = tmp_store();
        let (total, by_cat) = store.waf_event_stats().expect("stats");
        assert_eq!(total, 0);
        assert!(by_cat.is_empty());
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
            store.insert_audit(&entry(n, "route.create", "alice")).expect("insert");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 5);
        assert!(result.first_break_id.is_none());

        // Genesis row anchors on the all-zero hash.
        let (rows, total) = store
            .query_audit(&AuditQuery { limit: 10, ..Default::default() })
            .expect("query");
        assert_eq!(total, 5);
        assert_eq!(rows.last().expect("rows").prev_chain_hash, GENESIS_HASH);
        // Newest first.
        assert_eq!(rows.first().expect("rows").target_id, "5");
    }

    #[test]
    fn tampering_breaks_at_the_modified_row() {
        let (store, _dir) = tmp_store();
        for n in 1..=4 {
            store.insert_audit(&entry(n, "route.update", "alice")).expect("insert");
        }
        {
            let conn = store.conn.lock();
            conn.execute("UPDATE audit_log SET target_id = '999' WHERE id = 2", [])
                .expect("tamper");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(!result.verified);
        assert_eq!(result.first_break_id, Some(2));
        assert_eq!(result.first_break_reason.as_deref(), Some("chain_hash_mismatch"));
    }

    #[test]
    fn deleting_a_middle_row_breaks_the_successor() {
        let (store, _dir) = tmp_store();
        for n in 1..=4 {
            store.insert_audit(&entry(n, "backend.delete", "bob")).expect("insert");
        }
        {
            let conn = store.conn.lock();
            conn.execute("DELETE FROM audit_log WHERE id = 2", []).expect("delete");
        }
        let result = store.verify_audit_chain().expect("verify");
        assert!(!result.verified);
        assert_eq!(result.first_break_id, Some(3));
        assert_eq!(result.first_break_reason.as_deref(), Some("prev_hash_mismatch"));
    }

    #[test]
    fn retention_seal_keeps_chain_verifiable() {
        let (store, _dir) = tmp_store();
        for n in 1..=10 {
            store.insert_audit(&entry(n, "cert.renew", "alice")).expect("insert");
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
        store.insert_audit(&entry(11, "cert.renew", "alice")).expect("insert");
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 6);
    }

    #[test]
    fn retention_that_empties_the_table_seals_the_tail() {
        let (store, _dir) = tmp_store();
        for n in 1..=3 {
            store.insert_audit(&entry(n, "waf.toggle", "alice")).expect("insert");
        }
        let deleted = store
            .enforce_audit_retention("2026-09-01T00:00:00+00:00")
            .expect("retention");
        assert_eq!(deleted, 3);
        let result = store.verify_audit_chain().expect("verify");
        assert!(result.verified);
        assert_eq!(result.total_rows, 0);

        // The next insert anchors on the seal, not genesis.
        store.insert_audit(&entry(4, "waf.toggle", "alice")).expect("insert");
        let (rows, _) = store
            .query_audit(&AuditQuery { limit: 1, ..Default::default() })
            .expect("query");
        assert_ne!(rows[0].prev_chain_hash, GENESIS_HASH);
        assert!(store.verify_audit_chain().expect("verify").verified);
    }

    #[test]
    fn query_filters_operator_action_prefix_and_cursor() {
        let (store, _dir) = tmp_store();
        store.insert_audit(&entry(1, "route.create", "alice")).expect("insert");
        store.insert_audit(&entry(2, "route.delete", "bob")).expect("insert");
        store.insert_audit(&entry(3, "backend.create", "alice")).expect("insert");

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
