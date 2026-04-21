//! CRUD for the `cert_export_acls` table (v1.4.1).

use chrono::{DateTime, Utc};
use rusqlite::params;

use super::ConfigStore;
use crate::error::Result;
use crate::models::CertExportAcl;

impl ConfigStore {
    /// Create a new ACL row. Returns the id (caller supplies one
    /// already).
    pub fn create_cert_export_acl(&self, acl: &CertExportAcl) -> Result<()> {
        self.conn.execute(
            "INSERT INTO cert_export_acls (id, hostname_pattern, allowed_uid, allowed_gid, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                acl.id,
                acl.hostname_pattern,
                acl.allowed_uid,
                acl.allowed_gid,
                acl.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List every ACL, ordered by created_at ascending so the order
    /// is stable in the dashboard.
    pub fn list_cert_export_acls(&self) -> Result<Vec<CertExportAcl>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, hostname_pattern, allowed_uid, allowed_gid, created_at
             FROM cert_export_acls
             ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let id: String = row.get(0)?;
            let pattern: String = row.get(1)?;
            let uid: Option<i64> = row.get(2)?;
            let gid: Option<i64> = row.get(3)?;
            let created: String = row.get(4)?;
            Ok((id, pattern, uid, gid, created))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, pattern, uid, gid, created) = r?;
            out.push(CertExportAcl {
                id,
                hostname_pattern: pattern,
                allowed_uid: uid.map(|n| n as u32),
                allowed_gid: gid.map(|n| n as u32),
                created_at: DateTime::parse_from_rfc3339(&created)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
            });
        }
        Ok(out)
    }

    /// Delete one ACL by id. No-op (returns Ok) if the id does not
    /// exist so the API idempotency is trivial.
    pub fn delete_cert_export_acl(&self, id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM cert_export_acls WHERE id = ?1", params![id])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;

    #[test]
    fn crud_round_trip() {
        let store = ConfigStore::open_in_memory().expect("test setup");
        let acl = CertExportAcl {
            id: "acl-1".into(),
            hostname_pattern: "*.prod.mibu.fr".into(),
            allowed_uid: Some(1001),
            allowed_gid: Some(2001),
            created_at: Utc::now(),
        };
        store.create_cert_export_acl(&acl).expect("test setup");

        let got = store.list_cert_export_acls().expect("test setup");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, "acl-1");
        assert_eq!(got[0].hostname_pattern, "*.prod.mibu.fr");
        assert_eq!(got[0].allowed_uid, Some(1001));
        assert_eq!(got[0].allowed_gid, Some(2001));

        store.delete_cert_export_acl("acl-1").expect("test setup");
        assert!(store
            .list_cert_export_acls()
            .expect("test setup")
            .is_empty());
    }

    #[test]
    fn delete_is_idempotent() {
        let store = ConfigStore::open_in_memory().expect("test setup");
        // Delete on an empty table must not error.
        store
            .delete_cert_export_acl("does-not-exist")
            .expect("test setup");
    }
}
