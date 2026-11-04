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
//! [`CanonicalConfig`]: crate::canonical::CanonicalConfig

use rusqlite::{params, OptionalExtension};

use super::row_helpers::{json_column, parse_datetime};
use super::{serialize_field, ConfigStore};
use crate::error::{ConfigError, Result};
use crate::models::RouteProtectionRecord;

/// The column list every record read binds, in the order
/// [`row_to_record`] expects.
const RECORD_COLUMNS: &str =
    "id, route_id, hostname, hostname_aliases_json, path_prefix, route_json, deleted_by, deleted_at";

/// Decode one `route_protection_records` row.
fn row_to_record(row: &rusqlite::Row<'_>) -> Result<RouteProtectionRecord> {
    let deleted_at: String = row.get(7)?;
    Ok(RouteProtectionRecord {
        id: row.get(0)?,
        route_id: row.get(1)?,
        hostname: row.get(2)?,
        hostname_aliases: json_column(row, 3, "route protection record", "hostname_aliases")?,
        path_prefix: row.get(4)?,
        route: json_column(row, 5, "route protection record", "route")?,
        deleted_by: row.get(6)?,
        deleted_at: parse_datetime(&deleted_at)?,
    })
}

impl ConfigStore {
    /// Every record, the most recent deletion first.
    pub fn list_route_protection_records(&self) -> Result<Vec<RouteProtectionRecord>> {
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM route_protection_records \
             ORDER BY deleted_at DESC, id ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| Ok(row_to_record(row)))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row??);
        }
        Ok(out)
    }

    /// One record by id, or `None` when no such row exists.
    pub fn get_route_protection_record(&self, id: &str) -> Result<Option<RouteProtectionRecord>> {
        let sql = format!("SELECT {RECORD_COLUMNS} FROM route_protection_records WHERE id = ?1");
        self.conn
            .query_row(&sql, params![id], |row| Ok(row_to_record(row)))
            .optional()?
            .transpose()
    }

    /// Store a record.
    pub fn create_route_protection_record(&self, record: &RouteProtectionRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO route_protection_records (id, route_id, hostname, hostname_aliases_json,
             path_prefix, route_json, deleted_by, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.id,
                record.route_id,
                record.hostname,
                serialize_field(
                    "route protection record hostname_aliases",
                    &record.hostname_aliases
                )?,
                record.path_prefix,
                serialize_field("route protection record route", &record.route)?,
                record.deleted_by,
                record.deleted_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Delete one record by id.
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
