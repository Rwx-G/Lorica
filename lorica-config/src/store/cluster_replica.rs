//! Replication state on `ConfigStore` that is text rather than a
//! number (Story 9.4).
//!
//! Four keys in the `cluster_replica` table created by migration 52.
//! Three are follower-side: the generation and canonical hash of the
//! last replica this node applied (AC #7 / AC #12 convergence and
//! drift input), and the break-glass deadline (AC #11). The fourth is
//! control-plane side: the fleet identity hash of the last generation
//! this node published (Story 10.0 restart path).
//!
//! They live here rather than in `cluster_state` because migration 48
//! typed that table's `value` column as INTEGER, and a hash, a
//! deadline and a digest are all text. The table is key-value and
//! `read_key` answers an absent row with the empty string, so a new
//! key needs no migration: a database created before this one simply
//! reads it as "never published".

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::row_helpers::parse_datetime;
use super::ConfigStore;
use crate::error::{ConfigError, Result};

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
        let raw = read_key(self, "applied_config_generation")?;
        // A row we wrote ourselves that will not parse means the store
        // is corrupt. Reporting 0 would silently make this node claim
        // it has applied nothing and re-apply from scratch, which hides
        // the corruption behind a full reconciliation.
        let generation: u64 = raw.parse().map_err(|_| {
            ConfigError::Corrupt(
                "stored cluster_replica.applied_config_generation is not a number".to_string(),
            )
        })?;
        let hash: String = read_key(self, "applied_config_hash")?;
        Ok((generation, hash))
    }

    /// Record the generation and canonical hash just applied, in a
    /// transaction of its own. [`ConfigStore::apply_replica`] writes
    /// the same marker inside the apply transaction instead; this
    /// entry point is for the paths that record a generation without
    /// applying tables (the join bootstrap, tests).
    pub fn set_cluster_applied_config(&self, generation: u64, hash: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        self.record_applied_config(generation, hash)?;
        tx.commit()?;
        Ok(())
    }

    /// The two marker writes, on the connection's CURRENT transaction
    /// (Story 9.4 D12: in the same commit as the replica itself, so a
    /// crash can only under-report and trigger a re-apply, never claim
    /// a generation this node does not hold). Callers own the
    /// transaction.
    pub(crate) fn record_applied_config(&self, generation: u64, hash: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO cluster_replica (key, value) VALUES ('applied_config_generation', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![generation.to_string()],
        )?;
        self.conn.execute(
            "INSERT INTO cluster_replica (key, value) VALUES ('applied_config_hash', ?1) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![hash],
        )?;
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

    /// The fleet identity hash of the last generation this CONTROL
    /// PLANE published: the canonical blob folded together with the
    /// roster rows the per-recipient cuts resolve against (Story 10.0,
    /// `lorica_config::canonical::fleet_identity_hash`).
    ///
    /// Empty on a node that has never published one, which is what a
    /// database created before this key existed reads as.
    ///
    /// # Why it is persisted at all
    ///
    /// The generation is a counter over changes to the fleet's
    /// identity, and the boot seed rebuilds a generation's payloads
    /// from the store. Those two agree only if nothing changed the
    /// identity without advancing the counter. A crash between a
    /// roster write and the round it owes is exactly that window, and
    /// the recomputed hash differing from this one is how the next
    /// boot notices instead of seeding a generation no node holds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a read failure.
    pub fn cluster_published_fleet_hash(&self) -> Result<String> {
        read_key(self, "published_fleet_hash")
    }

    /// Record the fleet identity hash just published.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Database`] on a write failure.
    pub fn set_cluster_published_fleet_hash(&self, hash: &str) -> Result<()> {
        write_key(self, "published_fleet_hash", hash)
    }
}
