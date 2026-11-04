//! Route protection records on `ConfigStore` (backlog #93).
//!
//! # These rows do NOT replicate, and the export does not carry them
//!
//! `route_protection_records` is absent from [`CanonicalConfig`], from
//! `store/replica.rs` and from the TOML export, for the reasons
//! `api_tokens` is:
//!
//! 1. A record bounds this node's automation tokens; it is not
//!    configuration any node serves. The proxy never reads it, and the
//!    tokens it bounds, and the OIDC entries, are themselves node-local.
//! 2. Nothing on a follower reads it. The automation listener runs on a
//!    standalone node or on a control plane, which is where every write
//!    a record holds is accepted.
//!
//! `route_protection_records_stay_out_of_the_canonical_blob_and_the_export`
//! asserts the absence so a later slice cannot add it back by symmetry.
//!
//! # A record's names are rows of their own
//!
//! Every write a record could bind reads only the records naming a host
//! that write could serve (`route_selection::keys_reaching`), so the
//! names sit in `route_protection_record_names`, indexed, rather than in
//! a JSON column every lookup would have to decode. Every name is
//! stored, and every lookup bound, in `route_selection::canonical_hostname`
//! form, so the table's binary collation compares them as
//! `route_selection::same_name` does.
//!
//! # A snapshot that does not parse still lists
//!
//! `route_json` is read leniently: text that is not JSON is kept as a
//! JSON string, which [`RouteProtectionRecord::route`] then reports as
//! corrupt for that record alone. Refusing the row here would fail every
//! listing, the dashboard's included, and leave the operator who must
//! clear it nothing but the sqlite CLI. A record whose names do not
//! read still fails the whole read: the plane cannot tell which writes
//! it binds, so it binds them all.
//!
//! [`CanonicalConfig`]: crate::canonical::CanonicalConfig

use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::RouteProtectionRecord;
use crate::route_selection::canonical_names;

/// The column list every record read binds, in the order
/// [`row_to_record`] expects.
const RECORD_COLUMNS: &str = "id, route_id, path_prefix, route_json, deleted_by, deleted_at";

/// Every record holding one of `count` names, bound `?1` to `?count`,
/// the most recent first.
fn records_naming_sql(count: usize) -> String {
    let placeholders: Vec<String> = (1..=count).map(|at| format!("?{at}")).collect();
    format!(
        "SELECT {RECORD_COLUMNS} FROM route_protection_records WHERE id IN \
         (SELECT record_id FROM route_protection_record_names WHERE name IN ({})) \
         ORDER BY deleted_at DESC, id ASC",
        placeholders.join(", ")
    )
}

/// Decode one `route_protection_records` row, its names left for
/// [`ConfigStore::read_route_protection_records`] to attach.
fn row_to_record(row: &rusqlite::Row<'_>) -> Result<RouteProtectionRecord> {
    let route_json: String = row.get(3)?;
    let deleted_at: String = row.get(5)?;
    Ok(RouteProtectionRecord {
        id: row.get(0)?,
        route_id: row.get(1)?,
        hostname: String::new(),
        hostname_aliases: Vec::new(),
        path_prefix: row.get(2)?,
        route: match serde_json::from_str(&route_json) {
            Ok(snapshot) => snapshot,
            Err(_) => serde_json::Value::String(route_json),
        },
        deleted_by: row.get(4)?,
        deleted_at: parse_datetime(&deleted_at)?,
    })
}

impl ConfigStore {
    /// Every record, the most recent first.
    pub fn list_route_protection_records(&self) -> Result<Vec<RouteProtectionRecord>> {
        self.read_route_protection_records(
            &format!(
                "SELECT {RECORD_COLUMNS} FROM route_protection_records \
                 ORDER BY deleted_at DESC, id ASC"
            ),
            [],
        )
    }

    /// Every record holding at least one of `names`, in any spelling the
    /// selection takes for the same name, the most recent first, found
    /// through the index on the names and decoding no other record.
    pub fn route_protection_records_naming(
        &self,
        names: &[&str],
    ) -> Result<Vec<RouteProtectionRecord>> {
        let names = canonical_names(names.iter().copied());
        if names.is_empty() {
            return Ok(Vec::new());
        }
        self.read_route_protection_records(
            &records_naming_sql(names.len()),
            rusqlite::params_from_iter(names.iter()),
        )
    }

    /// One record by id, or `None` when no such row exists.
    pub fn get_route_protection_record(&self, id: &str) -> Result<Option<RouteProtectionRecord>> {
        Ok(self
            .read_route_protection_records(
                &format!("SELECT {RECORD_COLUMNS} FROM route_protection_records WHERE id = ?1"),
                params![id],
            )?
            .pop())
    }

    /// Store a record and its names.
    ///
    /// Two statements: the settles that write a record run inside the
    /// transaction of the route write it belongs to, so the row and its
    /// names commit together.
    pub fn create_route_protection_record(&self, record: &RouteProtectionRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO route_protection_records (id, route_id, path_prefix, route_json,
             deleted_by, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.id,
                record.route_id,
                record.path_prefix,
                serialize_field("route protection record route", &record.route)?,
                record.deleted_by,
                record.deleted_at.to_rfc3339(),
            ],
        )?;
        self.insert_route_protection_record_names(record)
    }

    /// Replace the names a stored record holds with `record`'s.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NotFound`] when no record has `record.id`.
    pub fn update_route_protection_record_names(
        &self,
        record: &RouteProtectionRecord,
    ) -> Result<()> {
        let stored: Option<String> = self
            .conn
            .query_row(
                "SELECT id FROM route_protection_records WHERE id = ?1",
                params![record.id],
                |row| row.get(0),
            )
            .optional()?;
        if stored.is_none() {
            return Err(ConfigError::NotFound(format!(
                "route protection record {}",
                record.id
            )));
        }
        self.conn.execute(
            "DELETE FROM route_protection_record_names WHERE record_id = ?1",
            params![record.id],
        )?;
        self.insert_route_protection_record_names(record)
    }

    /// Delete one record by id, its names with it.
    ///
    /// # Errors
    ///
    /// [`ConfigError::NotFound`] when no record has that id.
    pub fn delete_route_protection_record(&self, id: &str) -> Result<()> {
        let affected = self.conn.execute(
            "DELETE FROM route_protection_records WHERE id = ?1",
            params![id],
        )?;
        if affected == 0 {
            return Err(ConfigError::NotFound(format!(
                "route protection record {id}"
            )));
        }
        Ok(())
    }

    /// The records `sql` selects (its columns [`RECORD_COLUMNS`]), each
    /// with its names in order.
    fn read_route_protection_records(
        &self,
        sql: &str,
        bound: impl rusqlite::Params,
    ) -> Result<Vec<RouteProtectionRecord>> {
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map(bound, |row| Ok(row_to_record(row)))?;
        let mut names = self.conn.prepare(
            "SELECT name FROM route_protection_record_names WHERE record_id = ?1 \
             ORDER BY position",
        )?;
        let mut out = Vec::new();
        for row in rows {
            let mut record = row??;
            let held = names
                .query_map(params![record.id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()?;
            let Some((hostname, aliases)) = held.split_first() else {
                return Err(ConfigError::Corrupt(format!(
                    "route protection record {} holds no name",
                    record.id
                )));
            };
            record.hostname.clone_from(hostname);
            record.hostname_aliases = aliases.to_vec();
            out.push(record);
        }
        Ok(out)
    }

    /// Store `record`'s names, its hostname first, each canonical and
    /// once.
    fn insert_route_protection_record_names(&self, record: &RouteProtectionRecord) -> Result<()> {
        let mut insert = self.conn.prepare(
            "INSERT INTO route_protection_record_names (record_id, position, name)
             VALUES (?1, ?2, ?3)",
        )?;
        for (position, name) in canonical_names(record.names()).iter().enumerate() {
            insert.execute(params![record.id, position as i64, name])?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::models::Route;

    fn deleted_route(id: &str, hostname: &str) -> Route {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "hostname": hostname,
            "hostname_aliases": [format!("www.{hostname}")],
            "path_prefix": "/",
            "load_balancing": "round_robin",
            "waf_enabled": true,
            "waf_mode": "blocking",
            "enabled": true,
            "basic_auth_username": "user01",
            "basic_auth_password_hash": "$argon2id$record-sentinel",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a route")
    }

    fn record(id: &str, hostname: &str, at: i64) -> RouteProtectionRecord {
        let mut record = RouteProtectionRecord::of_deleted(
            &deleted_route(&format!("route-{id}"), hostname),
            "ci (0123456789abcdef01234567)",
            Utc.timestamp_opt(at, 0).single().expect("a time"),
        )
        .expect("test setup: a record");
        record.id = id.to_string();
        record
    }

    #[test]
    fn a_record_round_trips_and_lists_the_latest_deletion_first() {
        let store = ConfigStore::open_in_memory().expect("store");
        let older = record("rec-1", "old.example.com", 1_700_000_000);
        let newer = record("rec-2", "new.example.com", 1_800_000_000);
        store
            .create_route_protection_record(&older)
            .expect("insert");
        store
            .create_route_protection_record(&newer)
            .expect("insert");

        let listed = store.list_route_protection_records().expect("list");
        assert_eq!(listed, vec![newer.clone(), older.clone()]);
        assert_eq!(
            store.get_route_protection_record("rec-1").expect("get"),
            Some(older)
        );
        let read = listed[0].route().expect("the snapshot reads");
        assert_eq!(read.id, "route-rec-2");
        assert_eq!(
            read.basic_auth_password_hash.as_deref(),
            Some("$argon2id$record-sentinel")
        );

        store
            .delete_route_protection_record("rec-1")
            .expect("delete");
        assert!(matches!(
            store.delete_route_protection_record("rec-1"),
            Err(ConfigError::NotFound(_))
        ));
        assert_eq!(
            store.get_route_protection_record("rec-1").expect("get"),
            None
        );
    }

    #[test]
    fn a_record_whose_snapshot_text_is_not_json_lists_and_reads_as_corrupt() {
        // The listing and the clear must keep working, or the operator's
        // remedy for an unreadable record needs the sqlite CLI.
        let store = ConfigStore::open_in_memory().expect("store");
        store
            .create_route_protection_record(&record("rec-1", "app.example.com", 1_700_000_000))
            .expect("insert");
        store
            .conn
            .execute(
                "UPDATE route_protection_records SET route_json = '{\"truncated' WHERE id = 'rec-1'",
                [],
            )
            .expect("test setup: the snapshot is damaged");
        let listed = store.list_route_protection_records().expect("still lists");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].hostname, "app.example.com");
        assert!(matches!(listed[0].route(), Err(ConfigError::Corrupt(_))));
        store
            .delete_route_protection_record("rec-1")
            .expect("still clears");
    }

    #[test]
    fn a_lookup_by_name_is_served_by_an_index() {
        let store = ConfigStore::open_in_memory().expect("store");
        let plan: Vec<String> = store
            .conn
            .prepare(&format!("EXPLAIN QUERY PLAN {}", records_naming_sql(2)))
            .expect("the lookup prepares")
            .query_map(["a.example.com", "b.example.com"], |row| {
                row.get::<_, String>(3)
            })
            .expect("plan")
            .collect::<std::result::Result<_, _>>()
            .expect("plan rows");
        assert!(
            plan.iter()
                .any(|step| step.contains("route_protection_record_names")
                    && step.contains("USING COVERING INDEX")),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|step| step.starts_with("SCAN")),
            "{plan:?}"
        );
    }

    #[test]
    fn a_lookup_by_name_reads_the_records_holding_it_and_no_other() {
        let store = ConfigStore::open_in_memory().expect("store");
        let app = record("rec-1", "app.example.com", 1_700_000_000);
        let other = record("rec-2", "other.example.com", 1_800_000_000);
        for record in [&app, &other] {
            store
                .create_route_protection_record(record)
                .expect("insert");
        }
        let ids = |names: &[&str]| -> Vec<String> {
            store
                .route_protection_records_naming(names)
                .expect("lookup")
                .into_iter()
                .map(|record| record.id)
                .collect()
        };
        // An alias is a name the record holds.
        assert_eq!(ids(&["www.app.example.com"]), vec!["rec-1"]);
        assert_eq!(
            ids(&["app.example.com", "www.other.example.com"]),
            vec!["rec-2", "rec-1"]
        );
        assert!(ids(&["unrelated.example.com"]).is_empty());
        assert!(ids(&[]).is_empty());
        assert_eq!(
            store
                .route_protection_records_naming(&["www.app.example.com"])
                .expect("lookup"),
            vec![app]
        );
    }

    #[test]
    fn a_record_narrowed_to_fewer_names_reads_back_with_them_and_its_names_go_with_it() {
        let store = ConfigStore::open_in_memory().expect("store");
        let mut held = record("rec-1", "app.example.com", 1_700_000_000);
        store.create_route_protection_record(&held).expect("insert");
        held.hostname = "www.app.example.com".to_string();
        held.hostname_aliases = Vec::new();
        store
            .update_route_protection_record_names(&held)
            .expect("narrowed");
        assert_eq!(
            store.get_route_protection_record("rec-1").expect("get"),
            Some(held.clone())
        );
        assert!(store
            .route_protection_records_naming(&["app.example.com"])
            .expect("lookup")
            .is_empty());

        store
            .delete_route_protection_record("rec-1")
            .expect("delete");
        let names: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM route_protection_record_names",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(names, 0);
        assert!(matches!(
            store.update_route_protection_record_names(&held),
            Err(ConfigError::NotFound(_))
        ));
    }

    #[test]
    fn route_protection_records_stay_out_of_the_canonical_blob_and_the_export() {
        // A record bounds this node's tokens; nothing on a follower reads
        // it and the export carries no token either. Asserted so a later
        // slice cannot add it back by symmetry with the other tables.
        let store = ConfigStore::open_in_memory().expect("store");
        store
            .create_route_protection_record(&record("rec-1", "sentinel.example.com", 1_700_000_000))
            .expect("insert");
        let blob = crate::canonical::canonical_config(&store).expect("canonical blob");
        let json = serde_json::to_string(&blob).expect("blob serialises");
        assert!(!json.contains("sentinel.example.com"), "{json}");
        assert!(!json.contains("record-sentinel"), "{json}");
        let exported = crate::export::export_to_toml(&store).expect("export");
        assert!(!exported.contains("sentinel.example.com"), "{exported}");
        assert!(!exported.contains("route_protection"), "{exported}");
    }

    #[test]
    fn an_import_leaves_the_records_in_place() {
        let store = ConfigStore::open_in_memory().expect("store");
        store
            .create_route_protection_record(&record("rec-1", "kept.example.com", 1_700_000_000))
            .expect("insert");
        store.clear_all().expect("the import's wipe");
        assert_eq!(
            store.list_route_protection_records().expect("list").len(),
            1
        );
    }
}
