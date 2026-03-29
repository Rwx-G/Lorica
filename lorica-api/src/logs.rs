use axum::extract::{Extension, Query};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// A single access log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status: u16,
    pub latency_ms: u64,
    pub backend: String,
    pub error: Option<String>,
}

/// Thread-safe in-memory ring buffer for access logs.
pub struct LogBuffer {
    entries: tokio::sync::RwLock<LogBufferInner>,
}

struct LogBufferInner {
    buf: Vec<LogEntry>,
    capacity: usize,
    next_id: u64,
    /// Write position in the circular buffer.
    write_pos: usize,
    /// Total entries currently stored (up to capacity).
    len: usize,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: tokio::sync::RwLock::new(LogBufferInner {
                buf: Vec::with_capacity(capacity),
                capacity,
                next_id: 1,
                write_pos: 0,
                len: 0,
            }),
        }
    }

    /// Push a new log entry into the ring buffer.
    pub async fn push(&self, mut entry: LogEntry) {
        let mut inner = self.entries.write().await;
        entry.id = inner.next_id;
        inner.next_id += 1;

        if inner.buf.len() < inner.capacity {
            inner.buf.push(entry);
        } else {
            let pos = inner.write_pos;
            inner.buf[pos] = entry;
        }
        inner.write_pos = (inner.write_pos + 1) % inner.capacity;
        if inner.len < inner.capacity {
            inner.len += 1;
        }
    }

    /// Return all entries in chronological order (oldest first).
    pub async fn snapshot(&self) -> Vec<LogEntry> {
        let inner = self.entries.read().await;
        if inner.len < inner.capacity {
            // Buffer not yet full - entries are in order from index 0
            inner.buf.clone()
        } else {
            // Buffer is full - read from write_pos (oldest) wrapping around
            let mut result = Vec::with_capacity(inner.capacity);
            for i in 0..inner.capacity {
                let idx = (inner.write_pos + i) % inner.capacity;
                result.push(inner.buf[idx].clone());
            }
            result
        }
    }

    /// Clear all entries.
    pub async fn clear(&self) {
        let mut inner = self.entries.write().await;
        inner.buf.clear();
        inner.write_pos = 0;
        inner.len = 0;
    }
}

/// Query parameters for the logs endpoint.
#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    /// Filter by route hostname.
    pub route: Option<String>,
    /// Filter by HTTP status code.
    pub status: Option<u16>,
    /// Filter by minimum status code.
    pub status_min: Option<u16>,
    /// Filter by maximum status code.
    pub status_max: Option<u16>,
    /// Search text across method, path, host, backend, error fields.
    pub search: Option<String>,
    /// Maximum number of entries to return (default 200).
    pub limit: Option<usize>,
    /// Return entries after this ID (for pagination).
    pub after_id: Option<u64>,
}

#[derive(Serialize)]
struct LogsResponse {
    entries: Vec<LogEntry>,
    total: usize,
}

/// GET /api/v1/logs
pub async fn get_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let all_entries = state.log_buffer.snapshot().await;
    let limit = params.limit.unwrap_or(200).min(10_000);

    let filtered: Vec<LogEntry> = all_entries
        .into_iter()
        .filter(|e| {
            if let Some(after_id) = params.after_id {
                if e.id <= after_id {
                    return false;
                }
            }
            if let Some(ref route) = params.route {
                if !e.host.contains(route.as_str()) {
                    return false;
                }
            }
            if let Some(status) = params.status {
                if e.status != status {
                    return false;
                }
            }
            if let Some(min) = params.status_min {
                if e.status < min {
                    return false;
                }
            }
            if let Some(max) = params.status_max {
                if e.status > max {
                    return false;
                }
            }
            if let Some(ref search) = params.search {
                let s = search.to_lowercase();
                let matches = e.method.to_lowercase().contains(&s)
                    || e.path.to_lowercase().contains(&s)
                    || e.host.to_lowercase().contains(&s)
                    || e.backend.to_lowercase().contains(&s)
                    || e.error
                        .as_ref()
                        .is_some_and(|err| err.to_lowercase().contains(&s));
                if !matches {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len();
    // Return last N entries (most recent) respecting the limit
    let entries: Vec<LogEntry> = if filtered.len() > limit {
        filtered[filtered.len() - limit..].to_vec()
    } else {
        filtered
    };

    Ok(json_data(LogsResponse { entries, total }))
}

/// DELETE /api/v1/logs
pub async fn clear_logs(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.log_buffer.clear().await;
    Ok(json_data(serde_json::json!({ "message": "logs cleared" })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_log_buffer_push_and_snapshot() {
        let buf = LogBuffer::new(3);

        for i in 1..=3 {
            buf.push(LogEntry {
                id: 0,
                timestamp: format!("2026-01-0{i}T00:00:00Z"),
                method: "GET".into(),
                path: format!("/path{i}"),
                host: "example.com".into(),
                status: 200,
                latency_ms: 10,
                backend: "10.0.0.1:8080".into(),
                error: None,
            })
            .await;
        }

        let snap = buf.snapshot().await;
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].id, 1);
        assert_eq!(snap[2].id, 3);
    }

    #[tokio::test]
    async fn test_log_buffer_ring_overflow() {
        let buf = LogBuffer::new(3);

        for i in 1..=5 {
            buf.push(LogEntry {
                id: 0,
                timestamp: format!("2026-01-0{i}T00:00:00Z"),
                method: "GET".into(),
                path: format!("/path{i}"),
                host: "example.com".into(),
                status: 200,
                latency_ms: 10,
                backend: "10.0.0.1:8080".into(),
                error: None,
            })
            .await;
        }

        let snap = buf.snapshot().await;
        assert_eq!(snap.len(), 3);
        // Should contain entries 3, 4, 5 (oldest first)
        assert_eq!(snap[0].id, 3);
        assert_eq!(snap[1].id, 4);
        assert_eq!(snap[2].id, 5);
    }

    #[tokio::test]
    async fn test_log_buffer_clear() {
        let buf = LogBuffer::new(10);
        buf.push(LogEntry {
            id: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            method: "GET".into(),
            path: "/".into(),
            host: "example.com".into(),
            status: 200,
            latency_ms: 5,
            backend: "10.0.0.1:8080".into(),
            error: None,
        })
        .await;

        assert_eq!(buf.snapshot().await.len(), 1);
        buf.clear().await;
        assert_eq!(buf.snapshot().await.len(), 0);
    }
}
