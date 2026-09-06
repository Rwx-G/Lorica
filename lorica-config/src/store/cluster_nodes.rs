//! The control plane's node registry and revocation source on
//! `ConfigStore` (Story 9.3 AC #7/#9).
//!
//! `cluster_nodes` is keyed by the server-assigned `node_id`; identity
//! lookups run by certificate fingerprint (current OR the superseded
//! one a renewal left in `prev_cert_fingerprint`). `cluster_revoked_serials`
//! is what the CRL is minted from: an operator revocation adds the
//! node's serials, a completed renewal adds the superseded one.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::{parse_datetime, parse_optional_datetime};
use super::ConfigStore;
use crate::error::{ConfigError, Result};
use crate::models::{ClusterNode, NodeStatus, RevokedSerial};

const NODE_COLUMNS: &str = "node_id, name, cert_fingerprint, cert_serial, prev_cert_fingerprint, \
     prev_cert_serial, address, version, schema_version, status, enrolled_at, last_seen_at, \
     applied_config_generation, applied_config_hash, cert_not_after, revoked_at";

fn row_to_node(row: &rusqlite::Row<'_>) -> Result<ClusterNode> {
    let status: String = row.get(9)?;
    Ok(ClusterNode {
        node_id: row.get(0)?,
        name: row.get(1)?,
        cert_fingerprint: row.get(2)?,
        cert_serial: row.get(3)?,
        prev_cert_fingerprint: row.get(4)?,
        prev_cert_serial: row.get(5)?,
        address: row.get(6)?,
        version: row.get(7)?,
        schema_version: row.get(8)?,
        status: status
            .parse()
            .map_err(|e: String| ConfigError::Validation(e))?,
        enrolled_at: parse_datetime(&row.get::<_, String>(10)?)?,
        last_seen_at: parse_optional_datetime(row.get(11)?)?,
        applied_config_generation: row.get(12)?,
        applied_config_hash: row.get(13)?,
        cert_not_after: parse_datetime(&row.get::<_, String>(14)?)?,
        revoked_at: parse_optional_datetime(row.get(15)?)?,
    })
}

impl ConfigStore {
    /// Insert a freshly enrolled node (status as given, normally
    /// `Pending`).
    pub fn create_cluster_node(&self, node: &ClusterNode) -> Result<()> {
        self.conn.execute(
            "INSERT INTO cluster_nodes (node_id, name, cert_fingerprint, cert_serial, \
             prev_cert_fingerprint, prev_cert_serial, address, version, schema_version, status, \
             enrolled_at, last_seen_at, applied_config_generation, applied_config_hash, \
             cert_not_after, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                node.node_id,
                node.name,
                node.cert_fingerprint,
                node.cert_serial,
                node.prev_cert_fingerprint,
                node.prev_cert_serial,
                node.address,
                node.version,
                node.schema_version,
                node.status.as_str(),
                node.enrolled_at.to_rfc3339(),
                node.last_seen_at.map(|t| t.to_rfc3339()),
                node.applied_config_generation,
                node.applied_config_hash,
                node.cert_not_after.to_rfc3339(),
                node.revoked_at.map(|t| t.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    /// Fetch a node by id.
    pub fn get_cluster_node(&self, node_id: &str) -> Result<Option<ClusterNode>> {
        self.conn
            .query_row(
                &format!("SELECT {NODE_COLUMNS} FROM cluster_nodes WHERE node_id = ?1"),
                params![node_id],
                |row| Ok(row_to_node(row)),
            )
            .optional()?
            .transpose()
    }

    /// Fetch a node by certificate fingerprint: the current one or the
    /// superseded one a renewal left behind (AC #8 identity lookup).
    pub fn get_cluster_node_by_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<ClusterNode>> {
        self.conn
            .query_row(
                &format!(
                    "SELECT {NODE_COLUMNS} FROM cluster_nodes \
                     WHERE cert_fingerprint = ?1 OR prev_cert_fingerprint = ?1"
                ),
                params![fingerprint],
                |row| Ok(row_to_node(row)),
            )
            .optional()?
            .transpose()
    }

    /// Every node, oldest enrollment first.
    pub fn list_cluster_nodes(&self) -> Result<Vec<ClusterNode>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {NODE_COLUMNS} FROM cluster_nodes ORDER BY enrolled_at, node_id"
        ))?;
        let rows = stmt.query_map([], |row| Ok(row_to_node(row)))?;
        let mut nodes = Vec::new();
        for r in rows {
            nodes.push(r??);
        }
        Ok(nodes)
    }

    /// Nodes in `status`.
    pub fn count_cluster_nodes_with_status(&self, status: NodeStatus) -> Result<i64> {
        let n = self.conn.query_row(
            "SELECT COUNT(*) FROM cluster_nodes WHERE status = ?1",
            params![status.as_str()],
            |row| row.get(0),
        )?;
        Ok(n)
    }

    /// `Pending` -> `Active` (AC #5). Returns `false` when the node is
    /// not pending (already active, revoked, or absent).
    pub fn activate_cluster_node(&self, node_id: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE cluster_nodes SET status = 'active' WHERE node_id = ?1 AND status = 'pending'",
            params![node_id],
        )?;
        Ok(changed == 1)
    }

    /// Revoke a node (AC #7): marks it `Revoked`, records both of its
    /// serials on the revocation list, and returns the row as it was
    /// so the caller can tear its session down. `None` when the node
    /// is absent or already revoked.
    pub fn revoke_cluster_node(
        &self,
        node_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<ClusterNode>> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(None);
        };
        if node.status == NodeStatus::Revoked {
            return Ok(None);
        }
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE cluster_nodes SET status = 'revoked', revoked_at = ?2 WHERE node_id = ?1",
            params![node_id, now.to_rfc3339()],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO cluster_revoked_serials (serial, revoked_at, reason) \
             VALUES (?1, ?2, 'revoked')",
            params![node.cert_serial, now.to_rfc3339()],
        )?;
        if let Some(prev) = &node.prev_cert_serial {
            tx.execute(
                "INSERT OR IGNORE INTO cluster_revoked_serials (serial, revoked_at, reason) \
                 VALUES (?1, ?2, 'revoked')",
                params![prev, now.to_rfc3339()],
            )?;
        }
        tx.commit()?;
        Ok(Some(node))
    }

    /// Persist live facts the session layer observed (address, build
    /// version, schema version, last seen). Absent nodes are ignored.
    pub fn touch_cluster_node(
        &self,
        node_id: &str,
        address: &str,
        version: &str,
        schema_version: i64,
        last_seen_at: DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE cluster_nodes SET address = ?2, version = ?3, schema_version = ?4, \
             last_seen_at = ?5 WHERE node_id = ?1",
            params![
                node_id,
                address,
                version,
                schema_version,
                last_seen_at.to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// A renewal issued a new certificate (AC #12): the current one
    /// becomes `prev_*` (still accepted until the node's first session
    /// on the new one), the new one becomes current. A still-pending
    /// previous certificate (two renewals without a session in
    /// between) is retired to the revocation list first.
    pub fn record_cluster_node_renewal(
        &self,
        node_id: &str,
        new_fingerprint: &str,
        new_serial: &str,
        new_not_after: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(false);
        };
        let tx = self.conn.unchecked_transaction()?;
        if let Some(stale) = &node.prev_cert_serial {
            tx.execute(
                "INSERT OR IGNORE INTO cluster_revoked_serials (serial, revoked_at, reason) \
                 VALUES (?1, ?2, 'superseded')",
                params![stale, now.to_rfc3339()],
            )?;
        }
        tx.execute(
            "UPDATE cluster_nodes SET prev_cert_fingerprint = cert_fingerprint, \
             prev_cert_serial = cert_serial, cert_fingerprint = ?2, cert_serial = ?3, \
             cert_not_after = ?4 WHERE node_id = ?1",
            params![node_id, new_fingerprint, new_serial, new_not_after.to_rfc3339()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The node's first session on its renewed certificate: retire the
    /// superseded one (revocation list, reason `superseded`) and clear
    /// the `prev_*` columns. Returns the retired serial, `None` when
    /// there was nothing to retire.
    pub fn retire_previous_cluster_certificate(
        &self,
        node_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<String>> {
        let Some(node) = self.get_cluster_node(node_id)? else {
            return Ok(None);
        };
        let Some(prev_serial) = node.prev_cert_serial else {
            return Ok(None);
        };
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO cluster_revoked_serials (serial, revoked_at, reason) \
             VALUES (?1, ?2, 'superseded')",
            params![prev_serial, now.to_rfc3339()],
        )?;
        tx.execute(
            "UPDATE cluster_nodes SET prev_cert_fingerprint = NULL, prev_cert_serial = NULL \
             WHERE node_id = ?1",
            params![node_id],
        )?;
        tx.commit()?;
        Ok(Some(prev_serial))
    }

    /// Every revoked serial, oldest first: the CRL input.
    pub fn list_cluster_revoked_serials(&self) -> Result<Vec<RevokedSerial>> {
        let mut stmt = self.conn.prepare(
            "SELECT serial, revoked_at, reason FROM cluster_revoked_serials ORDER BY revoked_at, serial",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (serial, revoked_at, reason) = r?;
            out.push(RevokedSerial {
                serial,
                revoked_at: parse_datetime(&revoked_at)?,
                reason,
            });
        }
        Ok(out)
    }
}
