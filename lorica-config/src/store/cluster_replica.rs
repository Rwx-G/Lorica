//! Follower-side replication state on `ConfigStore` (Story 9.4).
//!
//! Three keys in the `cluster_replica` table created by migration 52:
//! the generation and canonical hash of the last replica this node
//! applied (AC #7 / AC #12 convergence and drift input), and the
//! break-glass deadline (AC #11).
//!
//! They live here rather than in `cluster_state` because migration 48
//! typed that table's `value` column as INTEGER, and both the hash and
//! the deadline are text.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::Result;

/// Read one `cluster_replica` value. Absent (a row a future migration
/// adds but an older database has not seeded) reads as the empty
/// string, which every caller treats as "never set".
fn read_key(store: &ConfigStore, key: &str) -> Result<String> {
    let value: Option<String> = store
        .conn
        .query_row(
            "SELECT value FROM cluster_replica WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value.unwrap_or_default())
}

/// Write one `cluster_replica` value, creating the row when absent.
fn write_key(store: &ConfigStore, key: &str, value: &str) -> Result<()> {
    store.conn.execute(
        "INSERT INTO cluster_replica (key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

impl ConfigStore {
    /// The generation and canonical hash of the last replica applied on
    /// this node (Story 9.4 AC #7). `(0, String::new())` when the node
    /// has never applied one, which is what a fresh follower reports in
    /// its first heartbeat so the control plane sends a full blob.
    pub fn cluster_applied_config(&self) -> Result<(u64, String)> {
        let generation: i64 = read_key(self, "applied_config_generation")?
            .parse()
            .unwrap_or(0);
        let hash: String = read_key(self, "applied_config_hash")?;
        Ok((generation.max(0) as u64, hash))
    }

    /// Record the generation and canonical hash just applied (Story 9.4
    /// D12: written in the same commit sequence as the replica itself,
    /// so a crash between the two can only under-report and trigger a
    /// re-apply, never claim a generation this node does not hold).
    pub fn set_cluster_applied_config(&self, generation: u64, hash: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO cluster_replica (key, value) VALUES ('applied_config_generation', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![generation.to_string()],
        )?;
        tx.execute(
            "INSERT INTO cluster_replica (key, value) VALUES ('applied_config_hash', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The instant the break-glass window closes (Story 9.4 AC #11),
    /// or `None` when break-glass has never been armed on this node.
    /// A deadline in the past is a closed window: the caller compares
    /// it against the current time, it is not pruned here.
    pub fn cluster_break_glass_until(&self) -> Result<Option<DateTime<Utc>>> {
        let raw = read_key(self, "break_glass_until")?;
        if raw.is_empty() {
            return Ok(None);
        }
        Ok(Some(parse_datetime(&raw)?))
    }

    /// Arm (or, with `None`, disarm) the break-glass window.
    pub fn set_cluster_break_glass_until(&self, until: Option<DateTime<Utc>>) -> Result<()> {
        let value = until.map(|t| t.to_rfc3339()).unwrap_or_default();
        write_key(self, "break_glass_until", &value)
    }
}
