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

//! The stream access log (Story 12.9 D-a, D-b): one [`StreamLogEntry`]
//! per TCP connection or UDP session at its end, per refusal the refusal
//! log admits, and per window of refusals it held back, kept in
//! `access-log.db`'s `stream_access_logs` table and served by
//! `/api/v1/stream-logs`.
//!
//! A table of its own rather than a kind of `access_logs` row: every
//! `access_logs` column after its id and timestamp is HTTP, and a kind
//! column would make every HTTP query, export and retention pass filter
//! on it. Its retention (`stream_access_log_retention`) and its writer
//! queue ([`crate::log_writer::LogWriteHandle::enqueue_stream`]) are its
//! own too, so a chatty UDP stream cannot evict or shed HTTP rows.

use std::net::SocketAddr;

use axum::extract::{Extension, Query};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, SecondsFormat, Utc};
use http::header;
use lorica_config::models::{
    StreamEndKind, StreamEndReason, StreamProtocol, StreamRefusal, StreamTlsMode,
};
use lorica_stream::{
    ClientCertificateOutcome, ConnectionRecord, RefusalRecord, SuppressedRecord, TlsRecord,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use strum::VariantArray as _;

use crate::db::log_db_blocking;
use crate::error::{json_data, ApiError};
use crate::log_store::{like_operand, LogStore, RetentionOutcome, LIKE_ESCAPE};
use crate::middleware::auth::Session;
use crate::server::AppState;

/// What a stream log row records (Story 12.9 D-c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamLogEntryKind {
    /// A connection or session that ended, refused ones included.
    Ended,
    /// The refusals one window of the refusal log held back, counted in
    /// [`StreamLogEntry::suppressed`].
    RefusalsSuppressed,
}

impl StreamLogEntryKind {
    /// Every kind, for the surfaces that publish the word list.
    pub const ALL: [StreamLogEntryKind; 2] = [Self::Ended, Self::RefusalsSuppressed];

    /// The snake_case word the row carries in `entry`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::RefusalsSuppressed => "refusals_suppressed",
        }
    }
}

/// One stream access-log row: the dashboard, store and sink shape
/// (Story 12.9 D-a). Built only by [`StreamLogEntry::from_connection`],
/// [`StreamLogEntry::from_refusal`] and [`StreamLogEntry::from_suppressed`],
/// so every word it carries comes from the enums of `lorica-config`.
///
/// The word fields are strings, not the enums, so a row a later release
/// wrote with a word this one does not know still reads back after a
/// rollback instead of failing the whole page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamLogEntry {
    /// Row id in `stream_access_logs`; 0 until stored.
    pub id: u64,
    /// When the connection ended, the refusal happened or the suppressed
    /// count was reported: RFC 3339 UTC with milliseconds, a fixed width
    /// so the time filters compare as text.
    pub timestamp: String,
    /// A [`StreamLogEntryKind`] word.
    pub entry: String,
    /// The stream's id.
    pub stream_id: String,
    /// The stream's name when the row was written.
    pub stream_name: String,
    /// `tcp` or `udp`.
    pub protocol: String,
    /// The local port the client reached, which tells the ports of a
    /// range stream apart; 0 on a `refusals_suppressed` row.
    pub listen_port: u16,
    /// The client's address after PROXY protocol where accepted; empty on
    /// a `refusals_suppressed` row.
    pub client_ip: String,
    /// The client's port; 0 on a `refusals_suppressed` row.
    pub client_port: u16,
    /// The socket peer (`ip:port`) when a PROXY header replaced it as the
    /// client, empty otherwise.
    pub proxied_from: String,
    /// The backend connected, empty when none was.
    pub backend_id: String,
    /// The address actually connected (`ip:port`), empty when none was.
    pub backend_address: String,
    /// Connect attempts made, the one that connected included.
    pub attempts: u32,
    /// Client-to-backend bytes forwarded.
    pub bytes_upload: u64,
    /// Backend-to-client bytes forwarded.
    pub bytes_download: u64,
    /// Client datagrams forwarded; null on TCP.
    pub datagrams_upload: Option<u64>,
    /// Backend datagrams forwarded; null on TCP.
    pub datagrams_download: Option<u64>,
    /// Accepted to end.
    pub duration_ms: u64,
    /// Accepted to connected; null when nothing connected.
    pub connect_ms: Option<u64>,
    /// A [`StreamTlsMode`] word; empty on the rows whose record carries
    /// no TLS mode (refusal and suppressed rows).
    pub tls_mode: String,
    /// The server name the ClientHello carried, empty when none.
    pub sni: String,
    /// The negotiated ALPN on a terminated stream, the first offered one
    /// in passthrough; empty when none.
    pub alpn: String,
    /// `absent` or `verified`, the outcome of a stream that verifies
    /// client certificates; null when the stream does not verify. The
    /// subject is never logged, as on HTTP (Resolved 4).
    pub client_cert: Option<String>,
    /// The protocol Phase 2 detection found; null until Story 12.15.
    pub detected_protocol: Option<String>,
    /// A [`StreamEndKind`] word.
    pub end_reason: String,
    /// A [`StreamRefusal`] word when `end_reason` is `refused`, else
    /// empty.
    pub refusal_reason: String,
    /// The count on a `refusals_suppressed` row, else 0.
    pub suppressed: u64,
}

/// RFC 3339 UTC with milliseconds and a `Z`, the one timestamp shape of
/// the table: fixed width, so a text comparison is a time comparison.
fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Milliseconds from `from` to `to`, 0 when the clock went backwards.
fn millis_between(from: DateTime<Utc>, to: DateTime<Utc>) -> u64 {
    u64::try_from((to - from).num_milliseconds()).unwrap_or(0)
}

/// The word a [`StreamRefusal`] is published as.
fn refusal_word(refusal: StreamRefusal) -> &'static str {
    refusal.into()
}

/// The word a client certificate outcome is logged as.
fn client_certificate_word(outcome: ClientCertificateOutcome) -> &'static str {
    match outcome {
        ClientCertificateOutcome::Absent => "absent",
        ClientCertificateOutcome::Verified => "verified",
    }
}

/// The ALPN a row shows for a connection's TLS (D-a).
fn alpn_of(tls: &TlsRecord) -> String {
    let protocol = match tls.mode {
        StreamTlsMode::Terminate => tls.negotiated_alpn.as_deref(),
        StreamTlsMode::Passthrough | StreamTlsMode::None => {
            tls.offered_alpn.first().map(Vec::as_slice)
        }
    };
    protocol
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default()
}

/// The datagram counts a row without a record of them carries: none on
/// TCP, nothing forwarded on UDP.
fn no_datagrams(protocol: StreamProtocol) -> Option<u64> {
    match protocol {
        StreamProtocol::Tcp => None,
        StreamProtocol::Udp => Some(0),
    }
}

impl StreamLogEntry {
    /// The row every constructor starts from: nothing forwarded, nothing
    /// connected, no TLS recorded.
    fn base(
        at: DateTime<Utc>,
        entry: StreamLogEntryKind,
        stream_id: &str,
        stream_name: &str,
        protocol: StreamProtocol,
    ) -> Self {
        Self {
            id: 0,
            timestamp: rfc3339(at),
            entry: entry.as_str().to_string(),
            stream_id: stream_id.to_string(),
            stream_name: stream_name.to_string(),
            protocol: protocol.as_str().to_string(),
            listen_port: 0,
            client_ip: String::new(),
            client_port: 0,
            proxied_from: String::new(),
            backend_id: String::new(),
            backend_address: String::new(),
            attempts: 0,
            bytes_upload: 0,
            bytes_download: 0,
            datagrams_upload: no_datagrams(protocol),
            datagrams_download: no_datagrams(protocol),
            duration_ms: 0,
            connect_ms: None,
            tls_mode: String::new(),
            sni: String::new(),
            alpn: String::new(),
            client_cert: None,
            detected_protocol: None,
            end_reason: StreamEndKind::Refused.as_str().to_string(),
            refusal_reason: String::new(),
            suppressed: 0,
        }
    }

    fn with_client(mut self, client: SocketAddr, proxied_from: Option<SocketAddr>) -> Self {
        self.client_ip = client.ip().to_string();
        self.client_port = client.port();
        self.proxied_from = proxied_from
            .map(|peer| peer.to_string())
            .unwrap_or_default();
        self
    }

    /// The row of a connection or session that ended, a pre-forwarding
    /// end the refusal log admitted included.
    pub fn from_connection(record: &ConnectionRecord) -> Self {
        let mut row = Self::base(
            record.ended_at,
            StreamLogEntryKind::Ended,
            &record.stream_id,
            &record.stream_name,
            record.protocol,
        )
        .with_client(record.client, record.proxied_from);
        row.listen_port = record.local.port();
        row.backend_id = record.backend_id.clone().unwrap_or_default();
        row.backend_address = record
            .backend_address
            .map(|address| address.to_string())
            .unwrap_or_default();
        row.attempts = record.attempts;
        row.bytes_upload = record.bytes_upload;
        row.bytes_download = record.bytes_download;
        row.datagrams_upload = record.datagrams_upload;
        row.datagrams_download = record.datagrams_download;
        row.duration_ms = millis_between(record.accepted_at, record.ended_at);
        row.connect_ms = record
            .connected_at
            .map(|connected| millis_between(record.accepted_at, connected));
        let tls = record.tls.as_ref();
        row.tls_mode = tls
            .map_or(StreamTlsMode::None, |tls| tls.mode)
            .as_str()
            .to_string();
        row.sni = tls
            .and_then(|tls| tls.server_name.clone())
            .unwrap_or_default();
        row.alpn = tls.map(alpn_of).unwrap_or_default();
        row.client_cert = tls
            .and_then(|tls| tls.client_certificate)
            .map(|outcome| client_certificate_word(outcome).to_string());
        row.detected_protocol = record.detected_protocol.clone();
        row.end_reason = record.end_reason.kind().as_str().to_string();
        if let StreamEndReason::Refused(refusal) = record.end_reason {
            row.refusal_reason = refusal_word(refusal).to_string();
        }
        row
    }

    /// The row of a refusal the refusal log admitted (D-c).
    pub fn from_refusal(record: &RefusalRecord) -> Self {
        let mut row = Self::base(
            record.at,
            StreamLogEntryKind::Ended,
            &record.stream_id,
            &record.stream_name,
            record.protocol,
        )
        .with_client(record.client, record.proxied_from);
        row.listen_port = record.listen_port;
        row.refusal_reason = refusal_word(record.refusal).to_string();
        row
    }

    /// The row counting the rows one window held back (D-c): its
    /// `end_reason` is `refused` with the refusal beside it, or the
    /// pre-forwarding end the window counted.
    pub fn from_suppressed(record: &SuppressedRecord) -> Self {
        let mut row = Self::base(
            record.reported_at,
            StreamLogEntryKind::RefusalsSuppressed,
            &record.stream_id,
            &record.stream_name,
            record.protocol,
        );
        row.end_reason = record.key.end_kind().as_str().to_string();
        row.refusal_reason = record
            .key
            .refusal()
            .map(refusal_word)
            .unwrap_or_default()
            .to_string();
        row.suppressed = record.suppressed;
        row
    }
}

/// `stream_access_logs` and its indexes, created whole by
/// [`LogStore::open`] after the tables that predate it. `access-log.db`
/// has no numbered migrations: a column added later goes through
/// `add_column_if_absent`, and every statement naming it runs after
/// that call, as the schema rule in `open` says. A release that does not
/// know the table never reads it, so a rollback keeps its log store.
pub(crate) fn create_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS stream_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            entry TEXT NOT NULL,
            stream_id TEXT NOT NULL,
            stream_name TEXT NOT NULL,
            protocol TEXT NOT NULL,
            listen_port INTEGER NOT NULL DEFAULT 0,
            client_ip TEXT NOT NULL DEFAULT '',
            client_port INTEGER NOT NULL DEFAULT 0,
            proxied_from TEXT NOT NULL DEFAULT '',
            backend_id TEXT NOT NULL DEFAULT '',
            backend_address TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0,
            bytes_upload INTEGER NOT NULL DEFAULT 0,
            bytes_download INTEGER NOT NULL DEFAULT 0,
            datagrams_upload INTEGER,
            datagrams_download INTEGER,
            duration_ms INTEGER NOT NULL DEFAULT 0,
            connect_ms INTEGER,
            tls_mode TEXT NOT NULL DEFAULT '',
            sni TEXT NOT NULL DEFAULT '',
            alpn TEXT NOT NULL DEFAULT '',
            client_cert TEXT,
            detected_protocol TEXT,
            end_reason TEXT NOT NULL,
            refusal_reason TEXT NOT NULL DEFAULT '',
            suppressed INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_stream_access_logs_timestamp
            ON stream_access_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_stream_access_logs_stream_timestamp
            ON stream_access_logs(stream_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_stream_access_logs_end_reason
            ON stream_access_logs(end_reason);",
    )
    .map_err(|e| format!("failed to initialize stream access log schema: {e}"))
}

/// The columns a row is read with, in [`read_row`]'s order.
const SELECT_COLUMNS: &str = "id, timestamp, entry, stream_id, stream_name, protocol, \
    listen_port, client_ip, client_port, proxied_from, backend_id, backend_address, attempts, \
    bytes_upload, bytes_download, datagrams_upload, datagrams_download, duration_ms, connect_ms, \
    tls_mode, sni, alpn, client_cert, detected_protocol, end_reason, refusal_reason, suppressed";

/// The insert, every column but `id`, in [`insert_params`]'s order.
const INSERT_SQL: &str = "INSERT INTO stream_access_logs (timestamp, entry, stream_id, \
    stream_name, protocol, listen_port, client_ip, client_port, proxied_from, backend_id, \
    backend_address, attempts, bytes_upload, bytes_download, datagrams_upload, \
    datagrams_download, duration_ms, connect_ms, tls_mode, sni, alpn, client_cert, \
    detected_protocol, end_reason, refusal_reason, suppressed) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, \
    ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26)";

/// SQLite holds signed 64-bit integers; a counter past `i64::MAX` is
/// stored as the maximum rather than wrapping negative.
fn sql_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn insert_row(
    stmt: &mut rusqlite::CachedStatement<'_>,
    e: &StreamLogEntry,
) -> rusqlite::Result<()> {
    stmt.execute(params![
        e.timestamp,
        e.entry,
        e.stream_id,
        e.stream_name,
        e.protocol,
        e.listen_port,
        e.client_ip,
        e.client_port,
        e.proxied_from,
        e.backend_id,
        e.backend_address,
        e.attempts,
        sql_int(e.bytes_upload),
        sql_int(e.bytes_download),
        e.datagrams_upload.map(sql_int),
        e.datagrams_download.map(sql_int),
        sql_int(e.duration_ms),
        e.connect_ms.map(sql_int),
        e.tls_mode,
        e.sni,
        e.alpn,
        e.client_cert,
        e.detected_protocol,
        e.end_reason,
        e.refusal_reason,
        sql_int(e.suppressed),
    ])
    .map(|_| ())
}

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StreamLogEntry> {
    let unsigned = |index: usize| -> rusqlite::Result<u64> {
        Ok(u64::try_from(row.get::<_, i64>(index)?).unwrap_or(0))
    };
    let optional = |index: usize| -> rusqlite::Result<Option<u64>> {
        Ok(row
            .get::<_, Option<i64>>(index)?
            .map(|value| u64::try_from(value).unwrap_or(0)))
    };
    let port = |index: usize| -> rusqlite::Result<u16> {
        Ok(u16::try_from(row.get::<_, i64>(index)?).unwrap_or(0))
    };
    Ok(StreamLogEntry {
        id: unsigned(0)?,
        timestamp: row.get(1)?,
        entry: row.get(2)?,
        stream_id: row.get(3)?,
        stream_name: row.get(4)?,
        protocol: row.get(5)?,
        listen_port: port(6)?,
        client_ip: row.get(7)?,
        client_port: port(8)?,
        proxied_from: row.get(9)?,
        backend_id: row.get(10)?,
        backend_address: row.get(11)?,
        attempts: u32::try_from(row.get::<_, i64>(12)?).unwrap_or(0),
        bytes_upload: unsigned(13)?,
        bytes_download: unsigned(14)?,
        datagrams_upload: optional(15)?,
        datagrams_download: optional(16)?,
        duration_ms: unsigned(17)?,
        connect_ms: optional(18)?,
        tls_mode: row.get(19)?,
        sni: row.get(20)?,
        alpn: row.get(21)?,
        client_cert: row.get(22)?,
        detected_protocol: row.get(23)?,
        end_reason: row.get(24)?,
        refusal_reason: row.get(25)?,
        suppressed: unsigned(26)?,
    })
}

/// A validated selection of stream log rows: every word checked against
/// its enum and every time normalised to the table's timestamp shape, so
/// the store only ever binds values it can compare.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamLogFilter {
    /// Exact stream id.
    pub stream_id: Option<String>,
    /// A [`StreamEndKind`] word.
    pub end_reason: Option<String>,
    /// A [`StreamRefusal`] word.
    pub refusal_reason: Option<String>,
    /// Client address prefix.
    pub client_ip: Option<String>,
    /// Rows at or after this time.
    pub from: Option<String>,
    /// Rows at or before this time.
    pub to: Option<String>,
    /// Rows above this id.
    pub after_id: Option<u64>,
    /// Rows below this id: the keyset cursor walking back in time.
    pub before_id: Option<u64>,
    /// Rows per page, clamped to [`crate::logs::LOGS_QUERY_MAX_ROWS`].
    pub limit: Option<usize>,
}

impl StreamLogFilter {
    /// The `WHERE` clause (empty when nothing filters) and its binds.
    fn where_clause(&self) -> (String, Vec<Box<dyn rusqlite::types::ToSql>>) {
        let mut conditions: Vec<String> = Vec::new();
        let mut binds: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for (column, value) in [
            ("stream_id", &self.stream_id),
            ("end_reason", &self.end_reason),
            ("refusal_reason", &self.refusal_reason),
        ] {
            if let Some(value) = value {
                conditions.push(format!("{column} = ?"));
                binds.push(Box::new(value.clone()));
            }
        }
        if let Some(ip) = &self.client_ip {
            conditions.push(format!("client_ip LIKE ? {LIKE_ESCAPE}"));
            binds.push(Box::new(format!("{}%", like_operand(ip))));
        }
        if let Some(from) = &self.from {
            conditions.push("timestamp >= ?".to_string());
            binds.push(Box::new(from.clone()));
        }
        if let Some(to) = &self.to {
            conditions.push("timestamp <= ?".to_string());
            binds.push(Box::new(to.clone()));
        }
        if let Some(after_id) = self.after_id {
            conditions.push("id > ?".to_string());
            binds.push(Box::new(sql_int(after_id)));
        }
        if let Some(before_id) = self.before_id {
            conditions.push("id < ?".to_string());
            binds.push(Box::new(sql_int(before_id)));
        }
        let clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        (clause, binds)
    }
}

/// The `(MIN, MAX)` ids of `stream_access_logs` as two scalar subqueries,
/// each one seek at an end of the rowid (see `LogStore`'s access-log
/// span for why not one select).
const STREAM_LOG_SPAN_SQL: &str = "SELECT (SELECT MIN(id) FROM stream_access_logs), \
    (SELECT MAX(id) FROM stream_access_logs)";

fn select_rows(
    conn: &Connection,
    sql: &str,
    binds: &[&dyn rusqlite::types::ToSql],
) -> Result<Vec<StreamLogEntry>, String> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| format!("failed to prepare stream log query: {e}"))?;
    let rows = stmt
        .query_map(binds, read_row)
        .map_err(|e| format!("failed to query stream logs: {e}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| format!("failed to read stream log row: {e}"))
}

impl LogStore {
    fn stream_conn(&self) -> parking_lot::MutexGuard<'_, Connection> {
        self.conn().lock()
    }

    /// Append stream log rows in one transaction. Called by the log
    /// writer's stream queue, never from the stream runtime's thread.
    pub fn insert_stream_batch(&self, entries: &[StreamLogEntry]) -> Result<(), String> {
        if entries.is_empty() {
            return Ok(());
        }
        let conn = self.stream_conn();
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("failed to open stream log transaction: {e}"))?;
        {
            let mut stmt = tx
                .prepare_cached(INSERT_SQL)
                .map_err(|e| format!("failed to prepare stream log insert: {e}"))?;
            for entry in entries {
                insert_row(&mut stmt, entry)
                    .map_err(|e| format!("failed to insert stream log row: {e}"))?;
            }
        }
        tx.commit()
            .map_err(|e| format!("failed to commit stream log batch: {e}"))
    }

    /// The newest `limit` rows `filter` selects, oldest first, and how
    /// many rows it selects in all.
    pub fn query_stream_logs(
        &self,
        filter: &StreamLogFilter,
    ) -> Result<(Vec<StreamLogEntry>, usize), String> {
        let conn = self.stream_conn();
        let (clause, mut binds) = filter.where_clause();
        let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(AsRef::as_ref).collect();
        let total: i64 = conn
            .query_row(
                &format!("SELECT COUNT(*) FROM stream_access_logs {clause}"),
                refs.as_slice(),
                |row| row.get(0),
            )
            .map_err(|e| format!("failed to count stream logs: {e}"))?;
        let limit = filter
            .limit
            .unwrap_or(200)
            .min(crate::logs::LOGS_QUERY_MAX_ROWS);
        binds.push(Box::new(i64::try_from(limit).unwrap_or(i64::MAX)));
        let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(AsRef::as_ref).collect();
        let mut rows = select_rows(
            &conn,
            &format!(
                "SELECT {SELECT_COLUMNS} FROM stream_access_logs {clause} ORDER BY id DESC LIMIT ?"
            ),
            &refs,
        )?;
        rows.reverse();
        Ok((rows, usize::try_from(total).unwrap_or(0)))
    }

    /// Up to `max` rows `filter` selects, oldest first, for an export.
    /// The filter's page fields are ignored.
    pub fn export_stream_logs(
        &self,
        filter: &StreamLogFilter,
        max: usize,
    ) -> Result<Vec<StreamLogEntry>, String> {
        let conn = self.stream_conn();
        let (clause, mut binds) = StreamLogFilter {
            after_id: None,
            before_id: None,
            limit: None,
            ..filter.clone()
        }
        .where_clause();
        binds.push(Box::new(i64::try_from(max).unwrap_or(i64::MAX)));
        let refs: Vec<&dyn rusqlite::types::ToSql> = binds.iter().map(AsRef::as_ref).collect();
        select_rows(
            &conn,
            &format!(
                "SELECT {SELECT_COLUMNS} FROM stream_access_logs {clause} ORDER BY id ASC LIMIT ?"
            ),
            &refs,
        )
    }

    /// Remove every stream log row.
    pub fn clear_stream_logs(&self) -> Result<(), String> {
        self.stream_conn()
            .execute("DELETE FROM stream_access_logs", [])
            .map(|_| ())
            .map_err(|e| format!("failed to clear stream logs: {e}"))
    }

    /// Rows in `stream_access_logs`.
    pub fn stream_log_count(&self) -> Result<u64, String> {
        self.stream_conn()
            .query_row("SELECT COUNT(*) FROM stream_access_logs", [], |row| {
                row.get::<_, i64>(0)
            })
            .map(|count| u64::try_from(count).unwrap_or(0))
            .map_err(|e| format!("failed to count stream logs: {e}"))
    }

    /// Trim `stream_access_logs` to its newest `max_entries` rows
    /// (`stream_access_log_retention`; the caller skips `0`, unlimited),
    /// touching no other table. The same span estimate as
    /// [`LogStore::enforce_retention`]: `MAX - MIN + 1` from two seeks,
    /// which over-counts after gaps and so trims at worst slightly more,
    /// never a whole-table `COUNT(*)` under the writers' lock.
    /// `undrained` counts the deleted rows above `drain_cursor`, the
    /// fleet drain's position once it ships stream rows.
    pub fn enforce_stream_retention(
        &self,
        max_entries: u64,
        drain_cursor: Option<u64>,
    ) -> Result<RetentionOutcome, String> {
        let conn = self.stream_conn();
        let span: Option<(i64, i64)> = conn
            .query_row(STREAM_LOG_SPAN_SQL, [], |row| {
                let low: Option<i64> = row.get(0)?;
                let high: Option<i64> = row.get(1)?;
                Ok(low.zip(high))
            })
            .map_err(|e| format!("failed to compute stream log bounds: {e}"))?;
        let approx_count = span.map_or(0, |(low, high)| u64::try_from(high - low + 1).unwrap_or(0));
        if approx_count <= max_entries {
            return Ok(RetentionOutcome::default());
        }
        let to_delete = sql_int(approx_count - max_entries);
        let undrained = match drain_cursor {
            Some(cursor) => conn
                .query_row(
                    "SELECT COUNT(*) FROM stream_access_logs
                     WHERE id > ?1
                       AND id IN (SELECT id FROM stream_access_logs ORDER BY id ASC LIMIT ?2)",
                    params![sql_int(cursor), to_delete],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(|e| format!("failed to count undrained stream rows: {e}"))?,
            None => 0,
        };
        let deleted = conn
            .execute(
                "DELETE FROM stream_access_logs
                 WHERE id IN (SELECT id FROM stream_access_logs ORDER BY id ASC LIMIT ?1)",
                params![to_delete],
            )
            .map_err(|e| format!("failed to enforce stream log retention: {e}"))?;
        Ok(RetentionOutcome {
            deleted: deleted as u64,
            undrained: u64::try_from(undrained).unwrap_or(0),
        })
    }
}

/// Query parameters of `GET /api/v1/stream-logs`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StreamLogsQuery {
    /// Exact stream id.
    pub stream_id: Option<String>,
    /// An end reason word.
    pub end_reason: Option<String>,
    /// A refusal reason word.
    pub refusal_reason: Option<String>,
    /// Client address prefix.
    pub client_ip: Option<String>,
    /// RFC 3339 lower bound, inclusive.
    pub from: Option<String>,
    /// RFC 3339 upper bound, inclusive.
    pub to: Option<String>,
    /// Rows per page (default 200).
    pub limit: Option<usize>,
    /// Rows above this id.
    pub after_id: Option<u64>,
    /// Rows below this id.
    pub before_id: Option<u64>,
}

/// Query parameters of `GET /api/v1/stream-logs/export`: the filters of
/// [`StreamLogsQuery`], no page, and the format.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StreamLogExportQuery {
    /// Exact stream id.
    pub stream_id: Option<String>,
    /// An end reason word.
    pub end_reason: Option<String>,
    /// A refusal reason word.
    pub refusal_reason: Option<String>,
    /// Client address prefix.
    pub client_ip: Option<String>,
    /// RFC 3339 lower bound, inclusive.
    pub from: Option<String>,
    /// RFC 3339 upper bound, inclusive.
    pub to: Option<String>,
    /// `csv` (default) or `json`.
    pub format: Option<String>,
}

/// `value` when it is one of `words`, else a 400 naming the parameter
/// and the words it takes.
fn checked_word(
    parameter: &str,
    value: Option<String>,
    words: &[&'static str],
) -> Result<Option<String>, ApiError> {
    match value {
        Some(word) if !words.contains(&word.as_str()) => Err(ApiError::BadRequest(format!(
            "{parameter} must be one of: {}",
            words.join(", ")
        ))),
        other => Ok(other),
    }
}

/// `value` parsed as RFC 3339 and rewritten in the table's timestamp
/// shape, else a 400 naming the parameter.
fn checked_time(parameter: &str, value: Option<String>) -> Result<Option<String>, ApiError> {
    value
        .map(|text| {
            DateTime::parse_from_rfc3339(&text)
                .map(|at| rfc3339(at.with_timezone(&Utc)))
                .map_err(|e| ApiError::BadRequest(format!("{parameter} is not RFC 3339: {e}")))
        })
        .transpose()
}

/// The filter of the six selection parameters both endpoints share.
fn selection(
    stream_id: Option<String>,
    end_reason: Option<String>,
    refusal_reason: Option<String>,
    client_ip: Option<String>,
    from: Option<String>,
    to: Option<String>,
) -> Result<StreamLogFilter, ApiError> {
    let end_reasons: Vec<&'static str> = StreamEndKind::VARIANTS
        .iter()
        .map(StreamEndKind::as_str)
        .collect();
    let refusals: Vec<&'static str> = StreamRefusal::VARIANTS
        .iter()
        .copied()
        .map(refusal_word)
        .collect();
    Ok(StreamLogFilter {
        stream_id,
        end_reason: checked_word("end_reason", end_reason, &end_reasons)?,
        refusal_reason: checked_word("refusal_reason", refusal_reason, &refusals)?,
        client_ip,
        from: checked_time("from", from)?,
        to: checked_time("to", to)?,
        ..StreamLogFilter::default()
    })
}

impl StreamLogsQuery {
    /// The validated filter, or a 400 naming the parameter at fault.
    pub fn filter(self) -> Result<StreamLogFilter, ApiError> {
        Ok(StreamLogFilter {
            after_id: self.after_id,
            before_id: self.before_id,
            limit: self.limit,
            ..selection(
                self.stream_id,
                self.end_reason,
                self.refusal_reason,
                self.client_ip,
                self.from,
                self.to,
            )?
        })
    }
}

#[derive(Serialize)]
struct StreamLogsPage {
    entries: Vec<StreamLogEntry>,
    total: usize,
}

/// GET /api/v1/stream-logs - stream log rows matching the filters, the
/// newest page oldest first, and the match count. A process with no log
/// store answers an empty page: stream rows have no in-memory fallback.
pub async fn get_stream_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<StreamLogsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let filter = params.filter()?;
    let Some(store) = state.log_store.as_ref() else {
        return Ok(json_data(StreamLogsPage {
            entries: Vec::new(),
            total: 0,
        }));
    };
    let (entries, total) = log_db_blocking(store, move |s| s.query_stream_logs(&filter)).await?;
    Ok(json_data(StreamLogsPage { entries, total }))
}

/// Most rows one export returns, the HTTP export's ceiling.
const EXPORT_MAX_ENTRIES: usize = crate::logs::EXPORT_MAX_ENTRIES;

/// A CSV column: its header and how a row renders in it.
type CsvColumn = (&'static str, fn(&StreamLogEntry) -> String);

fn optional_number(value: Option<u64>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

/// The CSV export's columns, in row order. Every field of
/// [`StreamLogEntry`] has one, which a test checks against the JSON
/// shape rather than against a copy of this list.
const CSV_COLUMNS: &[CsvColumn] = &[
    ("id", |e| e.id.to_string()),
    ("timestamp", |e| e.timestamp.clone()),
    ("entry", |e| e.entry.clone()),
    ("stream_id", |e| e.stream_id.clone()),
    ("stream_name", |e| e.stream_name.clone()),
    ("protocol", |e| e.protocol.clone()),
    ("listen_port", |e| e.listen_port.to_string()),
    ("client_ip", |e| e.client_ip.clone()),
    ("client_port", |e| e.client_port.to_string()),
    ("proxied_from", |e| e.proxied_from.clone()),
    ("backend_id", |e| e.backend_id.clone()),
    ("backend_address", |e| e.backend_address.clone()),
    ("attempts", |e| e.attempts.to_string()),
    ("bytes_upload", |e| e.bytes_upload.to_string()),
    ("bytes_download", |e| e.bytes_download.to_string()),
    ("datagrams_upload", |e| optional_number(e.datagrams_upload)),
    ("datagrams_download", |e| {
        optional_number(e.datagrams_download)
    }),
    ("duration_ms", |e| e.duration_ms.to_string()),
    ("connect_ms", |e| optional_number(e.connect_ms)),
    ("tls_mode", |e| e.tls_mode.clone()),
    ("sni", |e| e.sni.clone()),
    ("alpn", |e| e.alpn.clone()),
    ("client_cert", |e| e.client_cert.clone().unwrap_or_default()),
    ("detected_protocol", |e| {
        e.detected_protocol.clone().unwrap_or_default()
    }),
    ("end_reason", |e| e.end_reason.clone()),
    ("refusal_reason", |e| e.refusal_reason.clone()),
    ("suppressed", |e| e.suppressed.to_string()),
];

/// The rows as CSV, every cell through the HTTP export's escape, which
/// also defuses spreadsheet formulas: SNI, ALPN and the stream name are
/// client- or operator-chosen text.
fn to_csv(entries: &[StreamLogEntry]) -> String {
    let mut csv = String::with_capacity((entries.len() + 1) * 200);
    let header: Vec<&str> = CSV_COLUMNS.iter().map(|(name, _)| *name).collect();
    csv.push_str(&header.join(","));
    csv.push('\n');
    for entry in entries {
        let cells: Vec<String> = CSV_COLUMNS
            .iter()
            .map(|(_, render)| crate::logs::csv_escape(&render(entry)))
            .collect();
        csv.push_str(&cells.join(","));
        csv.push('\n');
    }
    csv
}

/// GET /api/v1/stream-logs/export - download the matching stream log rows
/// as CSV (default) or JSON, oldest first, up to the HTTP export's
/// ceiling.
pub async fn export_stream_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<StreamLogExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let format = params.format.as_deref().unwrap_or("csv").to_lowercase();
    if format != "csv" && format != "json" {
        return Err(ApiError::BadRequest(
            "format must be \"csv\" or \"json\"".into(),
        ));
    }
    let filter = selection(
        params.stream_id,
        params.end_reason,
        params.refusal_reason,
        params.client_ip,
        params.from,
        params.to,
    )?;
    let entries = match state.log_store.as_ref() {
        Some(store) => {
            log_db_blocking(store, move |s| {
                s.export_stream_logs(&filter, EXPORT_MAX_ENTRIES)
            })
            .await?
        }
        None => Vec::new(),
    };
    let today = Utc::now().format("%Y-%m-%d");
    let (content_type, body) = if format == "json" {
        let body = serde_json::to_string(&entries)
            .map_err(|e| ApiError::Internal(format!("JSON serialization failed: {e}")))?;
        ("application/json", body)
    } else {
        ("text/csv; charset=utf-8", to_csv(&entries))
    };
    Ok((
        [
            (header::CONTENT_TYPE, content_type.to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"lorica-stream-logs-{today}.{format}\""),
            ),
        ],
        body,
    ))
}

/// DELETE /api/v1/stream-logs - remove every stream log row, after the
/// log writer has persisted what it held, so no queued row reappears
/// after the wipe.
pub async fn clear_stream_logs(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if let Some(store) = state.log_store.as_ref() {
        if let Some(writer) = &state.log_writer {
            // A gone writer has nothing left to flush.
            let _ = writer.flush().await;
        }
        log_db_blocking(store, LogStore::clear_stream_logs).await?;
    }
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "stream_logs.clear",
        ("stream_logs", ""),
        None,
        None,
    )
    .await;
    Ok(json_data(
        serde_json::json!({ "message": "stream logs cleared" }),
    ))
}

#[cfg(test)]
pub(crate) mod test_support {
    //! The one place each `lorica-stream` record is spelled out, so a
    //! field the record gains changes these constructors and no test.

    use lorica_stream::StreamLogKey;

    use super::*;

    /// 2026-11-16T10:00:00Z, plus `millis`.
    pub(crate) fn at(millis: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-16T10:00:00Z")
            .expect("fixture time")
            .with_timezone(&Utc)
            + chrono::Duration::milliseconds(millis)
    }

    /// A TCP connection to `backend` that ended with `end_reason`.
    pub(crate) fn tcp_connection(end_reason: StreamEndReason) -> ConnectionRecord {
        ConnectionRecord {
            stream_id: "stream-1".into(),
            stream_name: "postgres".into(),
            protocol: StreamProtocol::Tcp,
            bind_gen: 1,
            client: "192.0.2.10:40000".parse().expect("fixture address"),
            peer: "192.0.2.10:40000".parse().expect("fixture address"),
            proxied_from: None,
            local: "192.0.2.1:5432".parse().expect("fixture address"),
            backend_id: Some("backend-1".into()),
            backend_address: Some("10.0.0.10:5432".parse().expect("fixture address")),
            attempts: 1,
            bytes_upload: 100,
            bytes_download: 2_000,
            datagrams_upload: None,
            datagrams_download: None,
            accepted_at: at(0),
            connected_at: Some(at(7)),
            ended_at: at(1_500),
            end_reason,
            tls: None,
            detected_protocol: None,
        }
    }

    /// A UDP session: datagram counts set.
    pub(crate) fn udp_session(end_reason: StreamEndReason) -> ConnectionRecord {
        let mut record = tcp_connection(end_reason);
        record.protocol = StreamProtocol::Udp;
        record.datagrams_upload = Some(3);
        record.datagrams_download = Some(2);
        record
    }

    /// A refusal of `refusal` on a stream of `protocol`.
    pub(crate) fn refusal(protocol: StreamProtocol, refusal: StreamRefusal) -> RefusalRecord {
        RefusalRecord {
            stream_id: "stream-1".into(),
            stream_name: "postgres".into(),
            protocol,
            listen_port: 5432,
            client: "198.51.100.7:51000".parse().expect("fixture address"),
            proxied_from: None,
            refusal,
            at: at(0),
        }
    }

    /// `suppressed` rows of `key` held back by one window.
    pub(crate) fn suppressed(key: StreamLogKey, suppressed: u64) -> SuppressedRecord {
        SuppressedRecord {
            stream_id: "stream-1".into(),
            stream_name: "postgres".into(),
            protocol: StreamProtocol::Tcp,
            key,
            suppressed,
            reported_at: at(60_000),
        }
    }

    /// A TLS record of `mode`, every field set.
    pub(crate) fn tls(mode: StreamTlsMode) -> TlsRecord {
        TlsRecord {
            mode,
            server_name: Some("db.example.com".into()),
            offered_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            negotiated_alpn: Some(b"http/1.1".to_vec()),
            rule: Some("db".into()),
            ech_offered: false,
            client_certificate: Some(ClientCertificateOutcome::Verified),
            upstream_tls: false,
        }
    }

    /// One reason of each kind: the kind's end, with a refusal for
    /// `refused`. The match is exhaustive, so a new kind fails to compile
    /// here rather than going untested.
    pub(crate) fn reason_of(kind: StreamEndKind) -> StreamEndReason {
        match kind {
            StreamEndKind::ClientClose => StreamEndReason::ClientClose,
            StreamEndKind::BackendClose => StreamEndReason::BackendClose,
            StreamEndKind::IdleTimeout => StreamEndReason::IdleTimeout,
            StreamEndKind::TotalTimeout => StreamEndReason::TotalTimeout,
            StreamEndKind::ConnectFailed => StreamEndReason::ConnectFailed,
            StreamEndKind::NoHealthyBackend => StreamEndReason::NoHealthyBackend,
            StreamEndKind::Refused => StreamEndReason::Refused(StreamRefusal::NoMatch),
            StreamEndKind::ClienthelloTimeout => StreamEndReason::ClienthelloTimeout,
            StreamEndKind::ProxyHeaderInvalid => StreamEndReason::ProxyHeaderInvalid,
            StreamEndKind::DetectionTimeout => StreamEndReason::DetectionTimeout,
            StreamEndKind::RequestBoundReached => StreamEndReason::RequestBoundReached,
            StreamEndKind::ResponseBoundReached => StreamEndReason::ResponseBoundReached,
            StreamEndKind::BackendDown => StreamEndReason::BackendDown,
            StreamEndKind::ConfigRemoved => StreamEndReason::ConfigRemoved,
            StreamEndKind::DrainedByUpgrade => StreamEndReason::DrainedByUpgrade,
            StreamEndKind::NodeShutdown => StreamEndReason::NodeShutdown,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lorica_stream::StreamLogKey;

    use super::test_support::*;
    use super::*;
    use crate::log_sinks::{body_json, SinkEvent, SinkPayload};

    fn store() -> (LogStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = LogStore::open(dir.path()).expect("open log store");
        (store, dir)
    }

    fn sink_body(entry: &StreamLogEntry) -> serde_json::Value {
        let event = SinkEvent {
            payload: Arc::new(SinkPayload::Stream(Box::new(entry.clone()))),
            trace_id: None,
            span_id: None,
        };
        serde_json::from_str(&body_json(&event)).expect("the body is JSON")
    }

    fn all_rows(store: &LogStore) -> Vec<StreamLogEntry> {
        store
            .query_stream_logs(&StreamLogFilter {
                limit: Some(crate::logs::LOGS_QUERY_MAX_ROWS),
                ..StreamLogFilter::default()
            })
            .expect("query")
            .0
    }

    #[test]
    fn every_end_reason_word_round_trips_the_store_and_the_sink_body() {
        let (store, _dir) = store();
        let written: Vec<StreamLogEntry> = StreamEndKind::VARIANTS
            .iter()
            .map(|&kind| StreamLogEntry::from_connection(&tcp_connection(reason_of(kind))))
            .collect();
        store.insert_stream_batch(&written).expect("insert");
        let read = all_rows(&store);
        assert_eq!(read.len(), StreamEndKind::VARIANTS.len());
        for (kind, row) in StreamEndKind::VARIANTS.iter().zip(&read) {
            assert_eq!(row.end_reason, kind.as_str());
            let body = sink_body(row);
            assert_eq!(body["end_reason"], kind.as_str());
            assert_eq!(body["kind"], crate::log_sinks::SinkKind::Stream.as_str());
            assert_eq!(body["v"], crate::log_sinks::SINK_BODY_VERSION);
            let filtered = store
                .query_stream_logs(&StreamLogFilter {
                    end_reason: Some(kind.as_str().to_string()),
                    ..StreamLogFilter::default()
                })
                .expect("query by end reason");
            assert_eq!(filtered.1, 1, "{}", kind.as_str());
        }
    }

    #[test]
    fn every_refusal_word_round_trips_the_store_and_the_sink_body() {
        let (store, _dir) = store();
        let written: Vec<StreamLogEntry> = StreamRefusal::VARIANTS
            .iter()
            .map(|&r| StreamLogEntry::from_refusal(&refusal(StreamProtocol::Tcp, r)))
            .collect();
        store.insert_stream_batch(&written).expect("insert");
        let read = all_rows(&store);
        assert_eq!(read.len(), StreamRefusal::VARIANTS.len());
        for (&r, row) in StreamRefusal::VARIANTS.iter().zip(&read) {
            assert_eq!(row.refusal_reason, refusal_word(r));
            assert_eq!(row.end_reason, StreamEndKind::Refused.as_str());
            assert_eq!(row.entry, StreamLogEntryKind::Ended.as_str());
            assert_eq!(sink_body(row)["refusal_reason"], refusal_word(r));
        }
    }

    #[test]
    fn a_stored_row_reads_back_as_it_was_written() {
        let (store, _dir) = store();
        let mut record = udp_session(StreamEndReason::IdleTimeout);
        record.tls = Some(tls(StreamTlsMode::Terminate));
        let suppressed = StreamLogEntry::from_suppressed(&suppressed(
            StreamLogKey::Refused(StreamRefusal::OpenRate),
            41,
        ));
        let written = vec![StreamLogEntry::from_connection(&record), suppressed];
        store.insert_stream_batch(&written).expect("insert");
        let read = all_rows(&store);
        for (wrote, got) in written.iter().zip(&read) {
            assert_eq!(
                StreamLogEntry {
                    id: 0,
                    ..got.clone()
                },
                *wrote
            );
            assert!(got.id > 0);
        }
    }

    #[test]
    fn a_connection_row_carries_the_record_s_values() {
        let mut record = tcp_connection(StreamEndReason::BackendClose);
        record.client = "203.0.113.5:61000".parse().expect("address");
        record.proxied_from = Some(record.peer);
        record.tls = Some(tls(StreamTlsMode::Terminate));
        let row = StreamLogEntry::from_connection(&record);
        assert_eq!(row.entry, StreamLogEntryKind::Ended.as_str());
        assert_eq!(row.protocol, StreamProtocol::Tcp.as_str());
        assert_eq!(row.listen_port, record.local.port());
        assert_eq!(row.client_ip, record.client.ip().to_string());
        assert_eq!(row.client_port, record.client.port());
        assert_eq!(row.proxied_from, record.peer.to_string());
        assert_eq!(row.backend_id, "backend-1");
        assert_eq!(row.backend_address, "10.0.0.10:5432");
        assert_eq!(row.duration_ms, 1_500);
        assert_eq!(row.connect_ms, Some(7));
        assert_eq!(row.datagrams_upload, None);
        assert_eq!(row.tls_mode, StreamTlsMode::Terminate.as_str());
        assert_eq!(row.sni, "db.example.com");
        assert_eq!(row.alpn, "http/1.1", "terminate: the negotiated protocol");
        assert_eq!(row.client_cert.as_deref(), Some("verified"));
        assert_eq!(row.detected_protocol, None);
        assert_eq!(row.refusal_reason, "");

        record.detected_protocol = Some("postgresql".into());
        let detected = StreamLogEntry::from_connection(&record);
        assert_eq!(detected.detected_protocol.as_deref(), Some("postgresql"));
        assert_eq!(row.timestamp, "2026-11-16T10:00:01.500Z");

        record.tls = Some(tls(StreamTlsMode::Passthrough));
        let passthrough = StreamLogEntry::from_connection(&record);
        assert_eq!(passthrough.alpn, "h2", "passthrough: the first offered");

        record.tls = None;
        record.connected_at = None;
        let plain = StreamLogEntry::from_connection(&record);
        assert_eq!(plain.tls_mode, StreamTlsMode::None.as_str());
        assert_eq!(plain.connect_ms, None);
        assert_eq!(plain.client_cert, None);

        let udp = StreamLogEntry::from_connection(&udp_session(StreamEndReason::IdleTimeout));
        assert_eq!(udp.protocol, StreamProtocol::Udp.as_str());
        assert_eq!(udp.datagrams_upload, Some(3));
        assert_eq!(udp.datagrams_download, Some(2));
    }

    #[test]
    fn refusal_and_suppressed_rows_carry_what_their_records_hold() {
        let udp =
            StreamLogEntry::from_refusal(&refusal(StreamProtocol::Udp, StreamRefusal::SessionCap));
        assert_eq!(udp.protocol, StreamProtocol::Udp.as_str());
        assert_eq!(udp.listen_port, 5432);
        assert_eq!(udp.client_ip, "198.51.100.7");
        assert_eq!(udp.datagrams_upload, Some(0));
        assert_eq!(udp.tls_mode, "", "a refusal record carries no TLS mode");

        let row = StreamLogEntry::from_suppressed(&suppressed(
            StreamLogKey::Refused(StreamRefusal::SourceDenied),
            999,
        ));
        assert_eq!(row.entry, StreamLogEntryKind::RefusalsSuppressed.as_str());
        assert_eq!(row.end_reason, StreamEndKind::Refused.as_str());
        assert_eq!(
            row.refusal_reason,
            refusal_word(StreamRefusal::SourceDenied)
        );
        assert_eq!(row.suppressed, 999);
        assert_eq!(row.client_ip, "");
        assert_eq!(row.timestamp, "2026-11-16T10:01:00.000Z");

        let pre_forwarding = StreamLogEntry::from_suppressed(&suppressed(
            StreamLogKey::PreForwarding(StreamEndKind::ProxyHeaderInvalid),
            12,
        ));
        assert_eq!(
            pre_forwarding.end_reason,
            StreamEndKind::ProxyHeaderInvalid.as_str()
        );
        assert_eq!(pre_forwarding.refusal_reason, "");
        assert_eq!(pre_forwarding.suppressed, 12);
    }

    #[test]
    fn retention_trims_the_stream_rows_only() {
        let (store, _dir) = store();
        let http: Vec<crate::logs::LogEntry> = (0..10)
            .map(|n| crate::logs::LogEntry {
                id: 0,
                timestamp: format!("2026-11-16T10:00:0{n}Z"),
                method: "GET".into(),
                path: format!("/{n}"),
                host: "app.example.com".into(),
                status: 200,
                latency_ms: 1,
                backend: "10.0.0.10:8080".into(),
                error: None,
                client_ip: "192.0.2.10".into(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: String::new(),
            })
            .collect();
        store.insert_batch(&http).expect("http rows");
        let streams: Vec<StreamLogEntry> = (0..10)
            .map(|_| StreamLogEntry::from_connection(&tcp_connection(StreamEndReason::ClientClose)))
            .collect();
        store.insert_stream_batch(&streams).expect("stream rows");

        let outcome = store
            .enforce_stream_retention(4, Some(3))
            .expect("retention");
        assert_eq!(outcome.deleted, 6);
        assert_eq!(
            outcome.undrained, 3,
            "rows 4 to 6 were past the drain cursor"
        );
        assert_eq!(store.stream_log_count().expect("count"), 4);
        assert_eq!(
            store.count().expect("http count"),
            10,
            "HTTP rows untouched"
        );
        let kept: Vec<u64> = all_rows(&store).iter().map(|row| row.id).collect();
        assert_eq!(kept, [7, 8, 9, 10], "the newest rows stay");

        store.enforce_retention(3, None).expect("http retention");
        assert_eq!(
            store.stream_log_count().expect("count"),
            4,
            "and the reverse"
        );
    }

    #[test]
    fn the_filters_select_and_page_like_the_http_log() {
        let (store, _dir) = store();
        let mut other = tcp_connection(StreamEndReason::IdleTimeout);
        other.stream_id = "stream-2".into();
        other.client = "203.0.113.9:1000".parse().expect("address");
        other.ended_at = at(3_600_000);
        let rows = vec![
            StreamLogEntry::from_connection(&tcp_connection(StreamEndReason::ClientClose)),
            StreamLogEntry::from_refusal(&refusal(StreamProtocol::Tcp, StreamRefusal::Geoip)),
            StreamLogEntry::from_connection(&other),
        ];
        store.insert_stream_batch(&rows).expect("insert");
        let count = |filter: StreamLogFilter| store.query_stream_logs(&filter).expect("query").1;
        let stream_2 = Some("stream-2".to_string());
        assert_eq!(
            count(StreamLogFilter {
                stream_id: stream_2,
                ..StreamLogFilter::default()
            }),
            1
        );
        assert_eq!(
            count(StreamLogFilter {
                refusal_reason: Some(refusal_word(StreamRefusal::Geoip).into()),
                ..StreamLogFilter::default()
            }),
            1
        );
        assert_eq!(
            count(StreamLogFilter {
                client_ip: Some("203.0.113.".into()),
                ..StreamLogFilter::default()
            }),
            1
        );
        let after_ten = StreamLogsQuery {
            from: Some("2026-11-16T10:30:00+00:00".into()),
            ..StreamLogsQuery::default()
        }
        .filter()
        .expect("valid");
        assert_eq!(count(after_ten), 1, "the time filter compares as time");

        let (page, total) = store
            .query_stream_logs(&StreamLogFilter {
                limit: Some(2),
                ..StreamLogFilter::default()
            })
            .expect("page");
        assert_eq!(total, 3);
        let ids: Vec<u64> = page.iter().map(|row| row.id).collect();
        assert_eq!(ids, [2, 3], "the newest page, oldest first");
        let (older, _) = store
            .query_stream_logs(&StreamLogFilter {
                before_id: Some(2),
                ..StreamLogFilter::default()
            })
            .expect("older page");
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].id, 1);
    }

    #[test]
    fn a_word_or_time_the_filters_do_not_know_is_refused() {
        for query in [
            StreamLogsQuery {
                end_reason: Some("exploded".into()),
                ..StreamLogsQuery::default()
            },
            StreamLogsQuery {
                refusal_reason: Some("because".into()),
                ..StreamLogsQuery::default()
            },
            StreamLogsQuery {
                to: Some("yesterday".into()),
                ..StreamLogsQuery::default()
            },
        ] {
            assert!(matches!(query.filter(), Err(ApiError::BadRequest(_))));
        }
    }

    #[test]
    fn the_csv_export_has_one_column_per_field_and_defuses_formulas() {
        let mut record = tcp_connection(StreamEndReason::ClientClose);
        record.tls = Some(tls(StreamTlsMode::Passthrough));
        record.tls.as_mut().expect("tls").server_name = Some("=cmd|calc".into());
        let row = StreamLogEntry::from_connection(&record);
        let csv = to_csv(std::slice::from_ref(&row));
        let mut lines = csv.lines();
        let header: Vec<&str> = lines.next().expect("header").split(',').collect();
        let fields: Vec<String> = serde_json::to_value(&row)
            .expect("json")
            .as_object()
            .expect("an object")
            .keys()
            .cloned()
            .collect();
        let mut sorted_header: Vec<&str> = header.clone();
        sorted_header.sort_unstable();
        let mut sorted_fields: Vec<&str> = fields.iter().map(String::as_str).collect();
        sorted_fields.sort_unstable();
        assert_eq!(sorted_header, sorted_fields);
        assert!(lines.next().expect("row").contains("'=cmd|calc"));
    }

    #[test]
    fn each_endpoint_takes_the_role_of_its_http_log_counterpart() {
        use crate::middleware::authorize::required_role;
        for (method, stream, http) in [
            (http::Method::GET, "/api/v1/stream-logs", "/api/v1/logs"),
            (
                http::Method::GET,
                "/api/v1/stream-logs/export",
                "/api/v1/logs/export",
            ),
            (http::Method::DELETE, "/api/v1/stream-logs", "/api/v1/logs"),
        ] {
            assert_eq!(
                required_role(&method, stream),
                required_role(&method, http),
                "{method} {stream}"
            );
        }
    }

    #[tokio::test]
    async fn the_endpoints_read_export_and_clear_the_store() {
        use axum::http::StatusCode;

        use crate::tests::{parse_data, send, setup_admin_and_login, test_state};

        let dir = tempfile::tempdir().expect("tempdir");
        let (mut state, sessions, limiter) = test_state().await;
        let log_store = Arc::new(LogStore::open(dir.path()).expect("open log store"));
        state.log_store = Some(Arc::clone(&log_store));
        log_store
            .insert_stream_batch(&[
                StreamLogEntry::from_connection(&tcp_connection(StreamEndReason::IdleTimeout)),
                StreamLogEntry::from_refusal(&refusal(
                    StreamProtocol::Tcp,
                    StreamRefusal::SourceDenied,
                )),
            ])
            .expect("insert");
        let admin = setup_admin_and_login(&state, &sessions, &limiter).await;
        let get = |uri: String| {
            let (state, sessions, limiter, admin) = (&state, &sessions, &limiter, &admin);
            async move { send(state, sessions, limiter, "GET", &uri, admin, None).await }
        };

        let idle = StreamEndKind::IdleTimeout.as_str();
        let page = parse_data(get(format!("/api/v1/stream-logs?end_reason={idle}")).await).await;
        assert_eq!(page["total"], 1);
        assert_eq!(page["entries"][0]["end_reason"], idle);

        let refused = get("/api/v1/stream-logs?end_reason=exploded".into()).await;
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);

        let csv = get("/api/v1/stream-logs/export".into()).await;
        assert_eq!(csv.status(), StatusCode::OK);
        let body = axum::body::to_bytes(csv.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(String::from_utf8_lossy(&body).lines().count(), 3);

        let cleared = send(
            &state,
            &sessions,
            &limiter,
            "DELETE",
            "/api/v1/stream-logs",
            &admin,
            None,
        )
        .await;
        assert_eq!(cleared.status(), StatusCode::OK);
        assert_eq!(log_store.stream_log_count().expect("count"), 0);
    }

    #[test]
    fn each_entry_kind_is_the_word_its_rows_carry() {
        for kind in StreamLogEntryKind::ALL {
            let row = match kind {
                StreamLogEntryKind::Ended => {
                    StreamLogEntry::from_connection(&tcp_connection(StreamEndReason::ClientClose))
                }
                StreamLogEntryKind::RefusalsSuppressed => StreamLogEntry::from_suppressed(
                    &suppressed(StreamLogKey::Refused(StreamRefusal::NoMatch), 1),
                ),
            };
            assert_eq!(row.entry, kind.as_str());
        }
    }
}
