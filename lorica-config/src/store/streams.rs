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
     port_first, port_last, node_selector, created_at, updated_at";

fn row_to_stream(row: &rusqlite::Row<'_>) -> Result<Stream> {
    let protocol: String = row.get(3)?;
    let listen_address: String = row.get(5)?;
    let selector: String = row.get(8)?;
    Ok(Stream {
        id: row.get(0)?,
        name: row.get(1)?,
        group_name: row.get(2)?,
        protocol: StreamProtocol::from_str(&protocol)
            .map_err(|e| ConfigError::Corrupt(format!("stored stream protocol is invalid: {e}")))?,
        enabled: row.get(4)?,
        listen_address: IpAddr::from_str(&listen_address).map_err(|e| {
            ConfigError::Corrupt(format!("stored stream listen_address is invalid: {e}"))
        })?,
        port_first: row.get(6)?,
        port_last: row.get(7)?,
        node_selector: serde_json::from_str(&selector)
            .map_err(|e| ConfigError::Corrupt(format!("invalid stream node_selector JSON: {e}")))?,
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
        self.conn
            .execute(
                &format!(
                    "INSERT INTO streams ({STREAM_COLUMNS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"
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
        let changed = self
            .conn
            .execute(
                "UPDATE streams SET name = ?2, group_name = ?3, protocol = ?4, enabled = ?5, \
                 listen_address = ?6, port_first = ?7, port_last = ?8, node_selector = ?9, \
                 updated_at = ?10 WHERE id = ?1",
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
    /// `backend_ids`, in one savepoint: either the whole new set stands,
    /// or, when one backend breaks the attachment rule
    /// (`check_backend_attachments`), the old set does and the error
    /// names the stream. `NotFound` when the stream does not exist; a
    /// backend id naming no backend is refused by the foreign key.
    pub fn set_stream_backends(&self, stream_id: &str, backend_ids: &[String]) -> Result<()> {
        if self.get_stream(stream_id)?.is_none() {
            return Err(ConfigError::NotFound(format!("stream {stream_id}")));
        }
        self.within_savepoint(|| {
            self.conn.execute(
                "DELETE FROM stream_backends WHERE stream_id = ?1",
                params![stream_id],
            )?;
            for backend_id in backend_ids {
                self.link_stream_backend_unchecked(stream_id, backend_id)?;
            }
            self.check_attachments_of_stream(stream_id)
        })
    }

    /// Link one backend to one stream without the attachment rule, for a
    /// writer that checked a whole consistent snapshot first.
    /// Idempotent (ignores duplicates).
    pub(crate) fn link_stream_backend_unchecked(
        &self,
        stream_id: &str,
        backend_id: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO stream_backends (stream_id, backend_id) VALUES (?1, ?2)",
            params![stream_id, backend_id],
        )?;
        Ok(())
    }

    /// Every stream-backend link, ordered by stream then backend ID.
    pub fn list_stream_backends(&self) -> Result<Vec<StreamBackend>> {
        let mut stmt = self.conn.prepare(
            "SELECT stream_id, backend_id FROM stream_backends ORDER BY stream_id, backend_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StreamBackend {
                stream_id: row.get(0)?,
                backend_id: row.get(1)?,
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
    use crate::models::{sample_stream, sample_stream_backend, sample_stream_id as sid};

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
            }]
        );
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
