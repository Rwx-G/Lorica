//! Cross-worker pending-challenge stash for bot protection.
//!
//! v1.4.0 Epic 3 closed the per-worker stash deferred item by
//! backing the pending-challenge state with SQLite (table
//! `bot_pending_challenges`, schema V36). Every stash / take / prune
//! operation goes through the shared DB so a client that solves on
//! worker A can submit on worker B — the DELETE RETURNING on take
//! gives atomic "first solver wins" semantics across the whole
//! pool, no RPC needed.
//!
//! Wire format (not typed here because the types live in
//! `lorica::bot` which depends on this crate): the `kind` column is
//! a free-form string ("pow" / "captcha"); the `payload` column is
//! an opaque JSON blob the caller ser/deses. PNG bytes for captcha
//! challenges go in a separate BLOB column so they do not inflate
//! the JSON payload. Mode is stored as the numeric value of
//! `lorica_challenge::Mode::as_u8()`.

use rusqlite::params;

use super::ConfigStore;
use crate::error::Result;

/// One row in the pending-challenge stash. Fields are plain-old-data
/// — semantics live in `lorica::bot`, we just move bytes.
#[derive(Debug, Clone)]
pub struct BotStashEntry {
    pub nonce: String,
    pub kind: String,
    pub payload: String,
    pub mode: u8,
    pub route_id: String,
    pub ip_prefix_disc: u8,
    pub ip_prefix_bytes: Vec<u8>,
    pub return_url: String,
    pub cookie_ttl_s: u32,
    pub expires_at: i64,
    pub png_bytes: Option<Vec<u8>>,
}

/// Maximum captcha PNG size (512 KiB). The `captcha` crate's
/// default output is ~15 KiB; anything beyond 512 KiB is either a
/// bug or a crafted payload trying to inflate the DB on disk.
const MAX_PNG_BYTES: usize = 512 * 1024;

/// Maximum pending challenges in the stash. Bounds disk + memory
/// usage under sustained bot traffic. When the cap is reached, the
/// oldest rows are evicted before the new insert.
const MAX_STASH_ROWS: usize = 10_000;

impl ConfigStore {
    /// Insert a pending challenge. Enforces a PNG size cap and a
    /// global row limit with oldest-first eviction to prevent
    /// disk/memory exhaustion from sustained bot traffic.
    pub fn bot_stash_insert(&self, entry: &BotStashEntry) -> Result<()> {
        if let Some(ref png) = entry.png_bytes {
            if png.len() > MAX_PNG_BYTES {
                return Err(crate::error::ConfigError::Validation(format!(
                    "captcha PNG too large ({} bytes, max {})",
                    png.len(),
                    MAX_PNG_BYTES,
                )));
            }
        }
        // Evict oldest rows when the stash is at capacity.
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM bot_pending_challenges", [], |row| {
                    row.get(0)
                })?;
        if count as usize >= MAX_STASH_ROWS {
            let to_evict = (count as usize - MAX_STASH_ROWS + 1) as i64;
            self.conn.execute(
                "DELETE FROM bot_pending_challenges WHERE rowid IN (
                     SELECT rowid FROM bot_pending_challenges
                     ORDER BY expires_at ASC LIMIT ?1
                 )",
                params![to_evict],
            )?;
        }
        self.conn.execute(
            "INSERT OR REPLACE INTO bot_pending_challenges
             (nonce, kind, payload, mode, route_id, ip_prefix_disc,
              ip_prefix_bytes, return_url, cookie_ttl_s,
              expires_at, png_bytes)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                entry.nonce,
                entry.kind,
                entry.payload,
                entry.mode as i64,
                entry.route_id,
                entry.ip_prefix_disc as i64,
                entry.ip_prefix_bytes,
                entry.return_url,
                entry.cookie_ttl_s as i64,
                entry.expires_at,
                entry.png_bytes,
            ],
        )?;
        Ok(())
    }

    /// Atomically remove + return a pending challenge. The
    /// DELETE...RETURNING wraps the SELECT + DELETE in one SQLite
    /// statement so two workers both racing to verify a solution
    /// will NOT both succeed — only one wins, the other gets
    /// `None` and rejects with 403 "challenge expired or unknown".
    /// This is the cross-worker replay defence.
    pub fn bot_stash_take(&self, nonce: &str, now: i64) -> Result<Option<BotStashEntry>> {
        let mut stmt = self.conn.prepare(
            "DELETE FROM bot_pending_challenges
             WHERE nonce = ?1 AND expires_at > ?2
             RETURNING nonce, kind, payload, mode, route_id,
                       ip_prefix_disc, ip_prefix_bytes, return_url,
                       cookie_ttl_s, expires_at, png_bytes",
        )?;
        let mut rows = stmt.query(params![nonce, now])?;
        if let Some(row) = rows.next()? {
            Ok(Some(BotStashEntry {
                nonce: row.get(0)?,
                kind: row.get(1)?,
                payload: row.get(2)?,
                mode: row.get::<_, i64>(3)? as u8,
                route_id: row.get(4)?,
                ip_prefix_disc: row.get::<_, i64>(5)? as u8,
                ip_prefix_bytes: row.get(6)?,
                return_url: row.get(7)?,
                cookie_ttl_s: row.get::<_, i64>(8)? as u32,
                expires_at: row.get(9)?,
                png_bytes: row.get(10)?,
            }))
        } else {
            Ok(None)
        }
    }

    /// Read-only lookup of the PNG bytes for a captcha nonce. Does
    /// NOT consume the stashed entry so the user can reload the
    /// image without losing the challenge. Returns `None` when the
    /// nonce is unknown OR the row is not a captcha entry.
    pub fn bot_stash_captcha_image(&self, nonce: &str) -> Result<Option<Vec<u8>>> {
        let mut stmt = self.conn.prepare(
            "SELECT png_bytes FROM bot_pending_challenges
             WHERE nonce = ?1 AND kind = 'captcha'",
        )?;
        let mut rows = stmt.query(params![nonce])?;
        if let Some(row) = rows.next()? {
            let bytes: Option<Vec<u8>> = row.get(0)?;
            Ok(bytes)
        } else {
            Ok(None)
        }
    }

    /// Evict every row with `expires_at <= now`. Called
    /// opportunistically from the challenge-render path so a bot
    /// probing for unknown nonces does not pay the GC cost.
    pub fn bot_stash_prune_expired(&self, now: i64) -> Result<usize> {
        let n = self.conn.execute(
            "DELETE FROM bot_pending_challenges WHERE expires_at <= ?1",
            params![now],
        )?;
        Ok(n)
    }

    /// Current row count. Used for the stash-length metric + tests.
    pub fn bot_stash_len(&self) -> Result<usize> {
        let n: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM bot_pending_challenges", [], |row| {
                    row.get(0)
                })?;
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ConfigStore;

    fn entry(nonce: &str, kind: &str, expires_at: i64) -> BotStashEntry {
        BotStashEntry {
            nonce: nonce.into(),
            kind: kind.into(),
            payload: r#"{"difficulty":14}"#.into(),
            mode: 2,
            route_id: "r1".into(),
            ip_prefix_disc: 1,
            ip_prefix_bytes: vec![192, 0, 2],
            return_url: "/".into(),
            cookie_ttl_s: 3600,
            expires_at,
            png_bytes: if kind == "captcha" {
                Some(vec![1, 2, 3, 4])
            } else {
                None
            },
        }
    }

    #[test]
    fn insert_then_take_roundtrip() {
        let store = ConfigStore::open_in_memory().unwrap();
        let e = entry("abc", "pow", 2_000_000_000);
        store.bot_stash_insert(&e).unwrap();
        let taken = store
            .bot_stash_take("abc", 1_900_000_000)
            .unwrap()
            .expect("round-trip");
        assert_eq!(taken.nonce, "abc");
        assert_eq!(taken.kind, "pow");
        assert_eq!(taken.mode, 2);
        // second take returns None — first solver wins.
        assert!(store
            .bot_stash_take("abc", 1_900_000_000)
            .unwrap()
            .is_none());
    }

    #[test]
    fn take_atomic_consumes_single_row() {
        let store = ConfigStore::open_in_memory().unwrap();
        let e = entry("once", "pow", 2_000_000_000);
        store.bot_stash_insert(&e).unwrap();
        assert!(store
            .bot_stash_take("once", 1_900_000_000)
            .unwrap()
            .is_some());
        assert!(store
            .bot_stash_take("once", 1_900_000_000)
            .unwrap()
            .is_none());
        assert_eq!(store.bot_stash_len().unwrap(), 0);
    }

    #[test]
    fn captcha_image_is_read_only() {
        let store = ConfigStore::open_in_memory().unwrap();
        let e = entry("cap1", "captcha", 2_000_000_000);
        store.bot_stash_insert(&e).unwrap();
        assert_eq!(
            store.bot_stash_captcha_image("cap1").unwrap(),
            Some(vec![1, 2, 3, 4])
        );
        // Image fetch must NOT remove the row — user can reload.
        assert_eq!(store.bot_stash_len().unwrap(), 1);
        // Still present + takeable.
        assert!(store
            .bot_stash_take("cap1", 1_900_000_000)
            .unwrap()
            .is_some());
    }

    #[test]
    fn captcha_image_none_for_pow_entries() {
        let store = ConfigStore::open_in_memory().unwrap();
        let e = entry("pow1", "pow", 2_000_000_000);
        store.bot_stash_insert(&e).unwrap();
        assert!(store.bot_stash_captcha_image("pow1").unwrap().is_none());
    }

    #[test]
    fn prune_removes_expired_rows() {
        let store = ConfigStore::open_in_memory().unwrap();
        store
            .bot_stash_insert(&entry("keep", "pow", 2_000_000_000))
            .unwrap();
        store
            .bot_stash_insert(&entry("drop1", "pow", 1_000_000_000))
            .unwrap();
        store
            .bot_stash_insert(&entry("drop2", "captcha", 1_500_000_000))
            .unwrap();
        let pruned = store.bot_stash_prune_expired(1_800_000_000).unwrap();
        assert_eq!(pruned, 2);
        assert_eq!(store.bot_stash_len().unwrap(), 1);
        assert!(store
            .bot_stash_take("keep", 1_900_000_000)
            .unwrap()
            .is_some());
    }

    #[test]
    fn replace_on_nonce_collision() {
        let store = ConfigStore::open_in_memory().unwrap();
        store
            .bot_stash_insert(&entry("dup", "pow", 2_000_000_000))
            .unwrap();
        // Same nonce, different mode → replaces.
        let mut e2 = entry("dup", "captcha", 2_000_000_100);
        e2.mode = 3;
        store.bot_stash_insert(&e2).unwrap();
        let taken = store.bot_stash_take("dup", 1_900_000_000).unwrap().unwrap();
        assert_eq!(taken.kind, "captcha");
        assert_eq!(taken.mode, 3);
        assert_eq!(store.bot_stash_len().unwrap(), 0);
    }
}
