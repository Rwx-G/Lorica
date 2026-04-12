use std::path::Path;

use parking_lot::Mutex;

use rusqlite::{params, Connection};

use crate::logs::{LogEntry, LogsQuery};

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
            CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);",
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
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| format!("failed to set access log pragmas: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a log entry.
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

    /// Query entries with filtering. Returns newest first.
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
    pub fn enforce_retention(&self, max_entries: u64) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .map_err(|e| format!("failed to count access logs: {e}"))?;

        if count <= max_entries as i64 {
            return Ok(0);
        }

        let to_delete = count - max_entries as i64;
        conn.execute(
            "DELETE FROM access_logs WHERE id IN (SELECT id FROM access_logs ORDER BY id ASC LIMIT ?1)",
            params![to_delete],
        )
        .map_err(|e| format!("failed to enforce access log retention: {e}"))?;

        Ok(to_delete as u64)
    }

    /// Clear all entries.
    pub fn clear(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM access_logs", [])
            .map_err(|e| format!("failed to clear access logs: {e}"))?;
        Ok(())
    }

    /// Get total entry count.
    pub fn count(&self) -> Result<u64, String> {
        let conn = self.conn.lock();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .map_err(|e| format!("failed to count access logs: {e}"))?;
        Ok(count as u64)
    }

    // ---- WAF Events ----

    /// Insert a WAF event.
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

    /// Query WAF events, newest first. When `category` is provided, only
    /// events matching that category are returned (filtered at the SQL level
    /// so that `limit` applies to the filtered set, not the full table).
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

    /// Clear all WAF events.
    pub fn clear_waf_events(&self) -> Result<(), String> {
        let conn = self.conn.lock();
        conn.execute("DELETE FROM waf_events", [])
            .map_err(|e| format!("failed to clear WAF events: {e}"))?;
        Ok(())
    }

    /// Purge old WAF events, keeping at most `max_entries`.
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
    pub fn insert_notification_event(
        &self,
        event: &lorica_notify::AlertEvent,
    ) -> Result<(), String> {
        let conn = self.conn.lock();
        let details_json = serde_json::to_string(&event.details).unwrap_or_default();
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

    /// List recent notification events, newest first.
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
            let details: std::collections::HashMap<String, String> =
                serde_json::from_str(&details_json).unwrap_or_default();
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
