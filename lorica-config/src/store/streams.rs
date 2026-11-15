//! Stream CRUD and stream-backend link operations on `ConfigStore`
//! (Story 12.1).
//!
//! The management writes ([`ConfigStore::create_stream`],
//! [`ConfigStore::update_stream`], [`ConfigStore::set_stream_backends`])
//! run `Stream::validate` and the attachment rule
//! (`check_backend_attachments`) inside the savepoint that writes. The
//! `_unchecked` writers skip the attachment rule for a caller that
//! checked a whole consistent snapshot first (replica apply, import):
//! applied row by row, such a snapshot can pass through a transient
//! violation, a backend moving from a UDP stream to a route.

use std::net::IpAddr;
use std::str::FromStr;

use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::*;

/// The column list every stream read binds, in the order
/// `row_to_stream` expects. A later story appends its column here and
/// in `row_to_stream`, never `SELECT *`.
const STREAM_COLUMNS: &str = "id, name, group_name, protocol, enabled, listen_address, \
     port_first, port_last, node_selector, created_at, updated_at, \
     load_balancing, connect_timeout_ms, idle_timeout_s, total_timeout_s, \
     max_connect_attempts, backend_keepalive, backend_keepalive_idle_s, \
     close_on_backend_down, proxy_protocol_send, proxy_protocol_accept, \
     proxy_protocol_trusted_cidrs, source_addresses, allow_local_backend, \
     upload_rate_bps, download_rate_bps, max_connections, \
     udp_max_sessions, udp_source_session_cap, udp_requests_per_session, \
     udp_responses_per_request, udp_response_bytes_ratio, udp_unbounded_responses, \
     udp_source_datagram_rate, udp_source_byte_rate, udp_max_datagram_bytes";

/// The `udp_*` columns of one row (Story 12.5 D-l), in `STREAM_COLUMNS`
/// order, every one NULL on a TCP row.
type UdpColumns = (
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<bool>,
    Option<u32>,
    Option<u32>,
    Option<u32>,
);

/// The `udp_*` column values of `udp`, all NULL for `None` (a TCP
/// stream). `requests_per_session` and `source_session_cap` are NULL on
/// a UDP row too when unset; the protocol tells the two apart.
fn udp_to_columns(udp: Option<&UdpSettings>) -> UdpColumns {
    match udp {
        None => (None, None, None, None, None, None, None, None, None),
        Some(u) => (
            Some(u.max_sessions),
            u.source_session_cap,
            u.requests_per_session,
            Some(u.responses_per_request),
            Some(u.response_bytes_ratio),
            Some(u.unbounded_responses),
            Some(u.source_datagram_rate),
            Some(u.source_byte_rate),
            Some(u.max_datagram_bytes),
        ),
    }
}

/// The UDP settings of a row of `protocol`: present on a UDP row, which
/// must carry every non-nullable one, absent on a TCP row, which must
/// carry none.
fn udp_from_columns(protocol: StreamProtocol, columns: UdpColumns) -> Result<Option<UdpSettings>> {
    let (
        max_sessions,
        source_session_cap,
        requests_per_session,
        responses_per_request,
        response_bytes_ratio,
        unbounded_responses,
        source_datagram_rate,
        source_byte_rate,
        max_datagram_bytes,
    ) = columns;
    let required = |value: Option<u32>, column: &str| {
        value.ok_or_else(|| ConfigError::Corrupt(format!("stored UDP stream has no {column}")))
    };
    match protocol {
        StreamProtocol::Tcp => {
            if columns != udp_to_columns(None) {
                return Err(ConfigError::Corrupt(
                    "stored TCP stream carries UDP settings".to_string(),
                ));
            }
            Ok(None)
        }
        StreamProtocol::Udp => Ok(Some(UdpSettings {
            max_sessions: required(max_sessions, "udp_max_sessions")?,
            source_session_cap,
            requests_per_session,
            responses_per_request: required(responses_per_request, "udp_responses_per_request")?,
            response_bytes_ratio: required(response_bytes_ratio, "udp_response_bytes_ratio")?,
            unbounded_responses: unbounded_responses.ok_or_else(|| {
                ConfigError::Corrupt("stored UDP stream has no udp_unbounded_responses".to_string())
            })?,
            source_datagram_rate: required(source_datagram_rate, "udp_source_datagram_rate")?,
            source_byte_rate: required(source_byte_rate, "udp_source_byte_rate")?,
            max_datagram_bytes: required(max_datagram_bytes, "udp_max_datagram_bytes")?,
        })),
    }
}

/// A stored JSON list column, refused as corrupt when it does not
/// decode.
fn json_list<T: serde::de::DeserializeOwned>(raw: &str, column: &str) -> Result<Vec<T>> {
    serde_json::from_str(raw)
        .map_err(|e| ConfigError::Corrupt(format!("invalid stream {column} JSON: {e}")))
}

/// A stored rate, which `Stream::validate` bounds well inside `i64`.
fn rate_from_column(raw: Option<i64>, column: &str) -> Result<Option<u64>> {
    raw.map(|value| {
        u64::try_from(value)
            .map_err(|_| ConfigError::Corrupt(format!("stored stream {column} is negative")))
    })
    .transpose()
}

/// A rate as a column value. The range `Stream::validate` enforces fits
/// an `i64`, so the conversion only fails on a stream that skipped it.
fn rate_to_column(rate: Option<u64>, column: &str) -> Result<Option<i64>> {
    rate.map(|value| {
        i64::try_from(value)
            .map_err(|_| ConfigError::Validation(format!("stream {column} is out of range")))
    })
    .transpose()
}

fn row_to_stream(row: &rusqlite::Row<'_>) -> Result<Stream> {
    let protocol: String = row.get(3)?;
    let listen_address: String = row.get(5)?;
    let selector: String = row.get(8)?;
    let load_balancing: String = row.get(11)?;
    let proxy_protocol_send: String = row.get(19)?;
    let protocol = StreamProtocol::from_str(&protocol)
        .map_err(|e| ConfigError::Corrupt(format!("stored stream protocol is invalid: {e}")))?;
    let udp = udp_from_columns(
        protocol,
        (
            row.get(27)?,
            row.get(28)?,
            row.get(29)?,
            row.get(30)?,
            row.get(31)?,
            row.get(32)?,
            row.get(33)?,
            row.get(34)?,
            row.get(35)?,
        ),
    )?;
    Ok(Stream {
        id: row.get(0)?,
        name: row.get(1)?,
        group_name: row.get(2)?,
        protocol,
        enabled: row.get(4)?,
        listen_address: IpAddr::from_str(&listen_address).map_err(|e| {
            ConfigError::Corrupt(format!("stored stream listen_address is invalid: {e}"))
        })?,
        port_first: row.get(6)?,
        port_last: row.get(7)?,
        node_selector: json_list(&selector, "node_selector")?,
        load_balancing: LoadBalancing::from_str(&load_balancing).map_err(|e| {
            ConfigError::Corrupt(format!("stored stream load_balancing is invalid: {e}"))
        })?,
        connect_timeout_ms: row.get(12)?,
        idle_timeout_s: row.get(13)?,
        total_timeout_s: row.get(14)?,
        max_connect_attempts: row.get(15)?,
        backend_keepalive: row.get(16)?,
        backend_keepalive_idle_s: row.get(17)?,
        close_on_backend_down: row.get(18)?,
        proxy_protocol_send: StreamProxyProtocol::from_str(&proxy_protocol_send).map_err(|e| {
            ConfigError::Corrupt(format!("stored stream proxy_protocol_send is invalid: {e}"))
        })?,
        proxy_protocol_accept: row.get(20)?,
        proxy_protocol_trusted_cidrs: json_list(
            &row.get::<_, String>(21)?,
            "proxy_protocol_trusted_cidrs",
        )?,
        source_addresses: json_list(&row.get::<_, String>(22)?, "source_addresses")?,
        allow_local_backend: row.get(23)?,
        upload_rate_bps: rate_from_column(row.get(24)?, "upload_rate_bps")?,
        download_rate_bps: rate_from_column(row.get(25)?, "download_rate_bps")?,
        max_connections: row.get(26)?,
        udp,
        created_at: parse_datetime(&row.get::<_, String>(9)?)?,
        updated_at: parse_datetime(&row.get::<_, String>(10)?)?,
    })
}

/// A `UNIQUE(name)` violation as the refusal it is, everything else as
/// the database error it is.
fn name_taken(e: rusqlite::Error, name: &str) -> ConfigError {
    match e {
        rusqlite::Error::SqliteFailure(ref failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
                && e.to_string().contains("streams.name") =>
        {
            ConfigError::Validation(format!("a stream named `{name}` already exists"))
        }
        other => ConfigError::from(other),
    }
}

fn validated(stream: &Stream) -> Result<()> {
    stream.validate().map_err(ConfigError::Validation)
}

impl ConfigStore {
    /// Insert a new stream, refused when it breaks `Stream::validate` or
    /// when its name is taken.
    pub fn create_stream(&self, stream: &Stream) -> Result<()> {
        self.within_savepoint(|| {
            self.create_stream_unchecked(stream)?;
            self.check_attachments_of_stream(&stream.id)
        })
    }

    /// [`ConfigStore::create_stream`] without the attachment rule, for a
    /// writer that checked a whole consistent snapshot first.
    /// `Stream::validate` and the name uniqueness still apply.
    pub(crate) fn create_stream_unchecked(&self, stream: &Stream) -> Result<()> {
        validated(stream)?;
        let selector = serialize_field("node_selector", &stream.node_selector)?;
        let trusted = serialize_field(
            "proxy_protocol_trusted_cidrs",
            &stream.proxy_protocol_trusted_cidrs,
        )?;
        let sources = serialize_field("source_addresses", &stream.source_addresses)?;
        let udp = udp_to_columns(stream.udp.as_ref());
        self.conn
            .execute(
                &format!(
                    "INSERT INTO streams ({STREAM_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                     ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28, \
                     ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36)"
                ),
                params![
                    stream.id,
                    stream.name,
                    stream.group_name,
                    stream.protocol.as_str(),
                    stream.enabled,
                    stream.listen_address.to_string(),
                    stream.port_first,
                    stream.port_last,
                    selector,
                    stream.created_at.to_rfc3339(),
                    stream.updated_at.to_rfc3339(),
                    stream.load_balancing.as_str(),
                    stream.connect_timeout_ms,
                    stream.idle_timeout_s,
                    stream.total_timeout_s,
                    stream.max_connect_attempts,
                    stream.backend_keepalive,
                    stream.backend_keepalive_idle_s,
                    stream.close_on_backend_down,
                    stream.proxy_protocol_send.as_str(),
                    stream.proxy_protocol_accept,
                    trusted,
                    sources,
                    stream.allow_local_backend,
                    rate_to_column(stream.upload_rate_bps, "upload_rate_bps")?,
                    rate_to_column(stream.download_rate_bps, "download_rate_bps")?,
                    stream.max_connections,
                    udp.0,
                    udp.1,
                    udp.2,
                    udp.3,
                    udp.4,
                    udp.5,
                    udp.6,
                    udp.7,
                    udp.8,
                ],
            )
            .map_err(|e| name_taken(e, &stream.name))?;
        Ok(())
    }

    /// Fetch a stream by ID, or `None` if not found.
    pub fn get_stream(&self, id: &str) -> Result<Option<Stream>> {
        self.conn
            .query_row(
                &format!("SELECT {STREAM_COLUMNS} FROM streams WHERE id = ?1"),
                params![id],
                |row| Ok(row_to_stream(row)),
            )
            .optional()?
            .transpose()
    }

    /// Every stream, ordered by name.
    pub fn list_streams(&self) -> Result<Vec<Stream>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {STREAM_COLUMNS} FROM streams ORDER BY name, id"
        ))?;
        let rows = stmt.query_map([], |row| Ok(row_to_stream(row)))?;
        let mut streams = Vec::new();
        for r in rows {
            streams.push(r??);
        }
        Ok(streams)
    }

    /// Update an existing stream. `NotFound` when the ID does not exist;
    /// refused when it breaks `Stream::validate`, when the new name is
    /// taken, or when the change breaks the attachment rule for one of
    /// its backends (a TCP stream turned UDP while a backend is shared
    /// with a route, a single port turned into a range under a backend
    /// with a port).
    pub fn update_stream(&self, stream: &Stream) -> Result<()> {
        self.within_savepoint(|| {
            self.update_stream_unchecked(stream)?;
            self.check_attachments_of_stream(&stream.id)
        })
    }

    /// [`ConfigStore::update_stream`] without the attachment rule, for a
    /// writer that checked a whole consistent snapshot first.
    pub(crate) fn update_stream_unchecked(&self, stream: &Stream) -> Result<()> {
        validated(stream)?;
        let selector = serialize_field("node_selector", &stream.node_selector)?;
        let trusted = serialize_field(
            "proxy_protocol_trusted_cidrs",
            &stream.proxy_protocol_trusted_cidrs,
        )?;
        let sources = serialize_field("source_addresses", &stream.source_addresses)?;
        let udp = udp_to_columns(stream.udp.as_ref());
        let changed = self
            .conn
            .execute(
                "UPDATE streams SET name = ?2, group_name = ?3, protocol = ?4, enabled = ?5, \
                 listen_address = ?6, port_first = ?7, port_last = ?8, node_selector = ?9, \
                 updated_at = ?10, load_balancing = ?11, connect_timeout_ms = ?12, \
                 idle_timeout_s = ?13, total_timeout_s = ?14, max_connect_attempts = ?15, \
                 backend_keepalive = ?16, backend_keepalive_idle_s = ?17, \
                 close_on_backend_down = ?18, proxy_protocol_send = ?19, \
                 proxy_protocol_accept = ?20, proxy_protocol_trusted_cidrs = ?21, \
                 source_addresses = ?22, allow_local_backend = ?23, upload_rate_bps = ?24, \
                 download_rate_bps = ?25, max_connections = ?26, udp_max_sessions = ?27, \
                 udp_source_session_cap = ?28, udp_requests_per_session = ?29, \
                 udp_responses_per_request = ?30, udp_response_bytes_ratio = ?31, \
                 udp_unbounded_responses = ?32, udp_source_datagram_rate = ?33, \
                 udp_source_byte_rate = ?34, udp_max_datagram_bytes = ?35 WHERE id = ?1",
                params![
                    stream.id,
                    stream.name,
                    stream.group_name,
                    stream.protocol.as_str(),
                    stream.enabled,
                    stream.listen_address.to_string(),
                    stream.port_first,
                    stream.port_last,
                    selector,
                    stream.updated_at.to_rfc3339(),
                    stream.load_balancing.as_str(),
                    stream.connect_timeout_ms,
                    stream.idle_timeout_s,
                    stream.total_timeout_s,
                    stream.max_connect_attempts,
                    stream.backend_keepalive,
                    stream.backend_keepalive_idle_s,
                    stream.close_on_backend_down,
                    stream.proxy_protocol_send.as_str(),
                    stream.proxy_protocol_accept,
                    trusted,
                    sources,
                    stream.allow_local_backend,
                    rate_to_column(stream.upload_rate_bps, "upload_rate_bps")?,
                    rate_to_column(stream.download_rate_bps, "download_rate_bps")?,
                    stream.max_connections,
                    udp.0,
                    udp.1,
                    udp.2,
                    udp.3,
                    udp.4,
                    udp.5,
                    udp.6,
                    udp.7,
                    udp.8,
                ],
            )
            .map_err(|e| name_taken(e, &stream.name))?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("stream {}", stream.id)));
        }
        Ok(())
    }

    /// Delete a stream by ID; its backend links go with it (the foreign
    /// key cascades). `NotFound` when the ID does not exist.
    pub fn delete_stream(&self, id: &str) -> Result<()> {
        let changed = self
            .conn
            .execute("DELETE FROM streams WHERE id = ?1", params![id])?;
        if changed == 0 {
            return Err(ConfigError::NotFound(format!("stream {id}")));
        }
        Ok(())
    }

    // ---- Stream-Backend associations ----

    /// Replace the set of backends `stream_id` forwards to with
    /// `backend_ids`, every one a primary: [`Self::set_stream_backend_links`]
    /// with no backup.
    pub fn set_stream_backends(&self, stream_id: &str, backend_ids: &[String]) -> Result<()> {
        self.set_stream_backend_links(stream_id, backend_ids, &[])
    }

    /// Replace the set of backends `stream_id` forwards to with
    /// `primary_ids` and `backup_ids` (Story 12.3, D-f), in one
    /// savepoint: either the whole new set stands, or, when one backend
    /// breaks the attachment rule (`check_backend_attachments`), the old
    /// set does and the error names the stream. A backend in both lists
    /// is refused. `NotFound` when the stream does not exist; a backend
    /// id naming no backend is refused by the foreign key.
    pub fn set_stream_backend_links(
        &self,
        stream_id: &str,
        primary_ids: &[String],
        backup_ids: &[String],
    ) -> Result<()> {
        if self.get_stream(stream_id)?.is_none() {
            return Err(ConfigError::NotFound(format!("stream {stream_id}")));
        }
        if let Some(both) = primary_ids.iter().find(|id| backup_ids.contains(id)) {
            return Err(ConfigError::Validation(format!(
                "backend {both} is listed both as a primary and as a backup of stream {stream_id}"
            )));
        }
        self.within_savepoint(|| {
            self.conn.execute(
                "DELETE FROM stream_backends WHERE stream_id = ?1",
                params![stream_id],
            )?;
            let links = primary_ids
                .iter()
                .map(|id| (id, false))
                .chain(backup_ids.iter().map(|id| (id, true)));
            for (backend_id, backup) in links {
                self.link_stream_backend_unchecked(&StreamBackend {
                    stream_id: stream_id.to_string(),
                    backend_id: backend_id.clone(),
                    backup,
                })?;
            }
            self.check_attachments_of_stream(stream_id)
        })
    }

    /// Write one stream-backend link without the attachment rule, for a
    /// writer that checked a whole consistent snapshot first.
    /// Idempotent (ignores duplicates: the first write of a pair stands).
    pub(crate) fn link_stream_backend_unchecked(&self, link: &StreamBackend) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO stream_backends (stream_id, backend_id, backup) \
             VALUES (?1, ?2, ?3)",
            params![link.stream_id, link.backend_id, link.backup],
        )?;
        Ok(())
    }

    /// Every stream-backend link, ordered by stream then backend ID.
    pub fn list_stream_backends(&self) -> Result<Vec<StreamBackend>> {
        let mut stmt = self.conn.prepare(
            "SELECT stream_id, backend_id, backup FROM stream_backends \
             ORDER BY stream_id, backend_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StreamBackend {
                stream_id: row.get(0)?,
                backend_id: row.get(1)?,
                backup: row.get(2)?,
            })
        })?;
        let mut links = Vec::new();
        for r in rows {
            links.push(r?);
        }
        Ok(links)
    }

    /// The backend IDs `stream_id` forwards to, sorted.
    pub fn list_backends_for_stream(&self, stream_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT backend_id FROM stream_backends WHERE stream_id = ?1 ORDER BY backend_id",
        )?;
        let rows = stmt.query_map(params![stream_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    /// The stream IDs that forward to `backend_id`, sorted.
    pub fn list_streams_for_backend(&self, backend_id: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT stream_id FROM stream_backends WHERE backend_id = ?1 ORDER BY stream_id",
        )?;
        let rows = stmt.query_map(params![backend_id], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for r in rows {
            ids.push(r?);
        }
        Ok(ids)
    }

    /// The attachment rule over the backends `stream_id` links.
    fn check_attachments_of_stream(&self, stream_id: &str) -> Result<()> {
        let ids = self.list_backends_for_stream(stream_id)?;
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        self.check_attachments_of(&ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        sample_stream, sample_stream_backend, sample_stream_id as sid, sample_stream_off_default,
    };

    fn store_with_backends(backends: &[(&str, &str)]) -> ConfigStore {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        for (id, address) in backends {
            store
                .create_backend(&sample_stream_backend(id, address))
                .expect("test setup: backend");
        }
        store
    }

    fn insert_route(store: &ConfigStore, id: &str, hostname: &str) {
        store
            .conn
            .execute(
                "INSERT INTO routes (id, hostname, created_at, updated_at) \
                 VALUES (?1, ?2, '2026-11-14T00:00:00Z', '2026-11-14T00:00:00Z')",
                params![id, hostname],
            )
            .expect("test setup: route");
    }

    #[test]
    fn a_stream_round_trips_with_every_field() {
        let store = store_with_backends(&[]);
        let mut s = sample_stream("s-1", "dns", StreamProtocol::Udp, 53);
        s.group_name = "edge".to_string();
        s.enabled = false;
        s.listen_address = "2001:db8::53".parse().expect("test setup: address");
        s.node_selector = vec!["edge-1".to_string()];
        store.create_stream(&s).expect("create");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), Some(s.clone()));

        s.enabled = true;
        s.port_last = 54;
        s.name = "dns-pair".to_string();
        store.update_stream(&s).expect("update");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), Some(s.clone()));
        assert_eq!(store.list_streams().expect("list"), vec![s]);

        store.delete_stream(&sid("s-1")).expect("delete");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), None);
        assert!(matches!(
            store.delete_stream(&sid("s-1")),
            Err(ConfigError::NotFound(_))
        ));
        let ghost = sample_stream("nope", "ghost", StreamProtocol::Tcp, 1);
        assert!(matches!(
            store.update_stream(&ghost),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn a_stream_name_is_unique_and_validated() {
        let store = store_with_backends(&[]);
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        let twin = sample_stream("s-2", "dns", StreamProtocol::Tcp, 5353);
        let err = store.create_stream(&twin).expect_err("the name is taken");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("`dns`")),
            "{err}"
        );
        let invalid = sample_stream("s-3", "DNS", StreamProtocol::Tcp, 5353);
        assert!(matches!(
            store.create_stream(&invalid),
            Err(ConfigError::Validation(_))
        ));
        assert_eq!(store.list_streams().expect("list").len(), 1);
    }

    #[test]
    fn set_stream_backends_replaces_the_set() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:25"), ("b-2", "192.0.2.20:25")]);
        store
            .create_stream(&sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25))
            .expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("first set");
        assert_eq!(
            store.list_backends_for_stream(&sid("s-1")).expect("links"),
            vec!["b-1"]
        );
        store
            .set_stream_backends(&sid("s-1"), &["b-2".to_string(), "b-1".to_string()])
            .expect("second set");
        assert_eq!(
            store.list_backends_for_stream(&sid("s-1")).expect("links"),
            vec!["b-1", "b-2"]
        );
        store
            .set_stream_backends(&sid("s-1"), &[])
            .expect("emptied");
        assert!(store.list_stream_backends().expect("links").is_empty());
        assert!(matches!(
            store.set_stream_backends("ghost", &[]),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn a_refused_set_keeps_the_previous_one_and_names_the_stream() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:53"), ("b-2", "192.0.2.20:53")]);
        insert_route(&store, "r-1", "app.example.com");
        store.link_route_backend("r-1", "b-2").expect("route link");
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("first set");
        let err = store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string(), "b-2".to_string()])
            .expect_err("b-2 serves a route");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("`dns`")),
            "{err}"
        );
        assert_eq!(
            store.list_backends_for_stream(&sid("s-1")).expect("links"),
            vec!["b-1"]
        );

        // The same rule from the route side: linking a UDP stream's
        // backend to a route is refused naming the stream.
        let err = store
            .link_route_backend("r-1", "b-1")
            .expect_err("b-1 serves a UDP stream");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("`dns`")),
            "{err}"
        );
        assert_eq!(
            store.list_backends_for_route("r-1").expect("links"),
            vec!["b-2"]
        );
    }

    #[test]
    fn turning_checks_on_for_a_udp_backend_is_refused_naming_the_stream() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:53")]);
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("link");
        let mut backend = store.get_backend("b-1").expect("get").expect("exists");
        backend.health_check_enabled = true;
        let err = store.update_backend(&backend).expect_err("refused");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("`dns`")),
            "{err}"
        );
        assert!(
            !store
                .get_backend("b-1")
                .expect("get")
                .expect("exists")
                .health_check_enabled,
            "the refused update left the row as it was"
        );
    }

    #[test]
    fn a_stream_update_that_breaks_an_attachment_is_refused() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:25")]);
        let mut s = sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25);
        store.create_stream(&s).expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("link");
        s.port_last = 30;
        assert!(matches!(
            store.update_stream(&s),
            Err(ConfigError::Validation(_))
        ));
        assert_eq!(
            store
                .get_stream(&sid("s-1"))
                .expect("get")
                .expect("exists")
                .port_last,
            25
        );
    }

    #[test]
    fn a_portless_backend_needs_checks_off_and_a_range_stream() {
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        let mut portless = sample_stream_backend("b-1", "backend.example.com");
        portless.health_check_enabled = true;
        assert!(matches!(
            store.create_backend(&portless),
            Err(ConfigError::Validation(_))
        ));
        assert!(store.get_backend("b-1").expect("get").is_none());
        portless.health_check_enabled = false;
        store.create_backend(&portless).expect("checks off");

        let mut range = sample_stream("s-1", "game", StreamProtocol::Udp, 27000);
        range.port_last = 27015;
        store.create_stream(&range).expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("a portless backend serves a range");

        insert_route(&store, "r-1", "app.example.com");
        assert!(matches!(
            store.link_route_backend("r-1", "b-1"),
            Err(ConfigError::Validation(_))
        ));
    }

    #[test]
    fn links_cascade_on_stream_and_on_backend_deletion() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:25"), ("b-2", "192.0.2.20:25")]);
        for (id, name, port) in [("s-1", "smtp", 25), ("s-2", "submission", 587)] {
            store
                .create_stream(&sample_stream(id, name, StreamProtocol::Tcp, port))
                .expect("create");
            store
                .set_stream_backends(&sid(id), &["b-1".to_string(), "b-2".to_string()])
                .expect("link");
        }
        store.delete_stream(&sid("s-1")).expect("delete stream");
        assert_eq!(
            store.list_streams_for_backend("b-1").expect("links"),
            vec![sid("s-2")]
        );
        store.delete_backend("b-1").expect("delete backend");
        assert_eq!(
            store.list_stream_backends().expect("links"),
            vec![StreamBackend {
                stream_id: sid("s-2"),
                backend_id: "b-2".to_string(),
                backup: false,
            }]
        );
    }

    #[test]
    fn every_engine_setting_and_the_backup_flag_round_trip() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:25"), ("b-2", "192.0.2.20:25")]);
        let s = sample_stream_off_default(sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25));
        store.create_stream(&s).expect("create");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), Some(s.clone()));
        let mut changed = s.clone();
        changed.load_balancing = LoadBalancing::PeakEwma;
        changed.total_timeout_s = None;
        changed.upload_rate_bps = Some(*Stream::RATE_BPS_RANGE.end());
        changed.source_addresses = vec![
            "192.0.2.51".parse().expect("test setup: address"),
            "2001:db8::50".parse().expect("test setup: address"),
        ];
        store.update_stream(&changed).expect("update");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), Some(changed));

        store
            .set_stream_backend_links(&sid("s-1"), &["b-1".to_string()], &["b-2".to_string()])
            .expect("a primary and a backup");
        let links = store.list_stream_backends().expect("links");
        let flags: Vec<(&str, bool)> = links
            .iter()
            .map(|l| (l.backend_id.as_str(), l.backup))
            .collect();
        assert_eq!(flags, vec![("b-1", false), ("b-2", true)]);

        let err = store
            .set_stream_backend_links(&sid("s-1"), &[], &["b-2".to_string()])
            .expect_err("backups alone");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("`smtp`")),
            "{err}"
        );
        assert!(store
            .set_stream_backend_links(&sid("s-1"), &["b-1".to_string()], &["b-1".to_string()])
            .is_err());
        assert_eq!(store.list_stream_backends().expect("links"), links);
    }

    #[test]
    fn the_udp_settings_round_trip_and_a_tcp_row_carries_none() {
        let store = store_with_backends(&[]);
        let mut dns = sample_stream("s-1", "dns", StreamProtocol::Udp, 53);
        // Private, so the per-source cap may go back to its default.
        dns.listen_address = "10.0.0.53".parse().expect("test setup: address");
        let udp = dns.udp.as_mut().expect("test setup: udp");
        udp.max_sessions = 9_000;
        udp.source_session_cap = Some(12);
        udp.requests_per_session = None;
        udp.responses_per_request = 0;
        udp.response_bytes_ratio = 4;
        udp.unbounded_responses = true;
        udp.source_datagram_rate = 50;
        udp.source_byte_rate = 65_507;
        udp.max_datagram_bytes = 65_507;
        dns.idle_timeout_s = 3_600;
        dns.total_timeout_s = Some(60);
        store.create_stream(&dns).expect("create");
        assert_eq!(
            store.get_stream(&sid("s-1")).expect("get"),
            Some(dns.clone())
        );

        let udp = dns.udp.as_mut().expect("test setup: udp");
        udp.source_session_cap = None;
        udp.requests_per_session = Some(1);
        udp.unbounded_responses = false;
        store.update_stream(&dns).expect("update");
        assert_eq!(store.get_stream(&sid("s-1")).expect("get"), Some(dns));

        let smtp = sample_stream("s-2", "smtp", StreamProtocol::Tcp, 25);
        store.create_stream(&smtp).expect("create");
        let nulls: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM streams WHERE id = ?1 AND udp_max_sessions IS NULL \
                 AND udp_source_session_cap IS NULL AND udp_requests_per_session IS NULL \
                 AND udp_responses_per_request IS NULL AND udp_response_bytes_ratio IS NULL \
                 AND udp_unbounded_responses IS NULL AND udp_source_datagram_rate IS NULL \
                 AND udp_source_byte_rate IS NULL AND udp_max_datagram_bytes IS NULL",
                params![sid("s-2")],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(nulls, 1, "a TCP row stores no UDP setting");
        assert_eq!(store.get_stream(&sid("s-2")).expect("get"), Some(smtp));
    }

    #[test]
    fn a_row_whose_udp_columns_disagree_with_its_protocol_is_corrupt() {
        let store = store_with_backends(&[]);
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        store
            .create_stream(&sample_stream("s-2", "smtp", StreamProtocol::Tcp, 25))
            .expect("create");
        store
            .conn
            .execute(
                "UPDATE streams SET udp_max_sessions = NULL WHERE id = ?1",
                params![sid("s-1")],
            )
            .expect("test setup: a UDP row without its cap");
        assert!(matches!(
            store.get_stream(&sid("s-1")),
            Err(ConfigError::Corrupt(m)) if m.contains("udp_max_sessions")
        ));
        store
            .conn
            .execute(
                "UPDATE streams SET udp_max_sessions = 4096 WHERE id = ?1",
                params![sid("s-2")],
            )
            .expect("test setup: a TCP row with a UDP value");
        assert!(matches!(
            store.get_stream(&sid("s-2")),
            Err(ConfigError::Corrupt(m)) if m.contains("TCP stream carries UDP settings")
        ));
    }

    #[test]
    fn a_udp_stream_takes_a_backup() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:53"), ("b-2", "192.0.2.20:53")]);
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        store
            .set_stream_backend_links(&sid("s-1"), &["b-1".to_string()], &["b-2".to_string()])
            .expect("a primary and a backup on UDP");
    }

    #[test]
    fn a_local_backend_is_refused_on_a_stream_without_the_flag() {
        let store = store_with_backends(&[("b-1", "127.0.0.1:5432")]);
        let mut s = sample_stream("s-1", "pg", StreamProtocol::Tcp, 5432);
        store.create_stream(&s).expect("create");
        let err = store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect_err("local");
        assert!(
            matches!(&err, ConfigError::Validation(m) if m.contains("allow_local_backend")),
            "{err}"
        );
        s.allow_local_backend = true;
        store.update_stream(&s).expect("flag on");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("with the flag");
        // Turning the flag off again under a local backend is refused.
        s.allow_local_backend = false;
        assert!(store.update_stream(&s).is_err());
    }

    #[test]
    fn clear_all_removes_streams_and_their_links() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:25")]);
        store
            .create_stream(&sample_stream("s-1", "smtp", StreamProtocol::Tcp, 25))
            .expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("link");
        store.clear_all().expect("clear");
        assert!(store.list_streams().expect("list").is_empty());
        assert!(store.list_stream_backends().expect("links").is_empty());
    }

    #[test]
    fn a_checked_write_inside_a_transaction_rolls_back_alone() {
        let store = store_with_backends(&[("b-1", "192.0.2.10:53")]);
        store
            .create_stream(&sample_stream("s-1", "dns", StreamProtocol::Udp, 53))
            .expect("create");
        store
            .set_stream_backends(&sid("s-1"), &["b-1".to_string()])
            .expect("link");
        insert_route(&store, "r-1", "app.example.com");
        let outcome: Result<()> = store.in_transaction(|s| {
            s.create_backend(&sample_stream_backend("b-2", "192.0.2.20:80"))?;
            assert!(s.link_route_backend("r-1", "b-1").is_err());
            s.link_route_backend("r-1", "b-2")
        });
        outcome.expect("the refused link did not poison the transaction");
        assert_eq!(
            store.list_backends_for_route("r-1").expect("links"),
            vec!["b-2"]
        );
    }
}
