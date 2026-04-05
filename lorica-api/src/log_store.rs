use std::path::Path;
use std::sync::Mutex;

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
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_access_logs_host ON access_logs(host);",
        )
        .map_err(|e| format!("failed to initialize access log schema: {e}"))?;

        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .map_err(|e| format!("failed to set access log pragmas: {e}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a log entry.
    pub fn insert(&self, entry: &LogEntry) -> Result<(), String> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO access_logs (timestamp, method, path, host, status, latency_ms, backend, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                entry.timestamp,
                entry.method,
                entry.path,
                entry.host,
                entry.status,
                entry.latency_ms,
                entry.backend,
                entry.error,
            ],
        )
        .map_err(|e| format!("failed to insert access log entry: {e}"))?;
        Ok(())
    }

    /// Query entries with filtering. Returns newest first.
    pub fn query(&self, params: &LogsQuery) -> Result<(Vec<LogEntry>, usize), String> {
        let conn = self.conn.lock().unwrap();

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
            "SELECT id, timestamp, method, path, host, status, latency_ms, backend, error \
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

    /// Delete entries older than the retention limit, keeping at most `max_entries` rows.
    pub fn enforce_retention(&self, max_entries: u64) -> Result<u64, String> {
        let conn = self.conn.lock().unwrap();
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
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM access_logs", [])
            .map_err(|e| format!("failed to clear access logs: {e}"))?;
        Ok(())
    }

    /// Get total entry count.
    pub fn count(&self) -> Result<u64, String> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM access_logs", [], |row| row.get(0))
            .map_err(|e| format!("failed to count access logs: {e}"))?;
        Ok(count as u64)
    }
}

/// Helper to re-box a ToSql value for a second bind pass.
/// We only store String and i64 values, so this covers all cases.
fn copy_to_sql(val: &dyn rusqlite::types::ToSql) -> Box<dyn rusqlite::types::ToSql> {
    use rusqlite::types::{ToSqlOutput, Value};
    match val.to_sql().unwrap() {
        ToSqlOutput::Owned(Value::Text(s)) => Box::new(s),
        ToSqlOutput::Owned(Value::Integer(i)) => Box::new(i),
        ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Text(b)) => {
            Box::new(String::from_utf8_lossy(b).to_string())
        }
        ToSqlOutput::Borrowed(rusqlite::types::ValueRef::Integer(i)) => Box::new(i),
        _ => Box::new(String::new()),
    }
}
