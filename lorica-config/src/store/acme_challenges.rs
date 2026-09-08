//! Pending ACME HTTP-01 challenges on `ConfigStore` (Story 9.5 AC #6,
//! decision D11).
//!
//! The table is owned by migration 47 and gained its `expires_at`
//! column in migration 54. Before that column existed the only way a
//! token stopped being served was the driver's cleanup call, so an
//! order that died in between left the node answering
//! `/.well-known/acme-challenge/{token}` with a valid key
//! authorization forever. Expiry is enforced on READ, not only by the
//! purge: a row that is still present but past its deadline must not
//! be served, whether or not the purge has run yet.
//!
//! Timestamps are stored as RFC 3339 produced by
//! `DateTime<Utc>::to_rfc3339`, which pins the offset to `+00:00`, so
//! SQLite's lexicographic TEXT comparison is a chronological one. This
//! is the same convention `cluster_revoked_serials.expires_at` uses.

use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

use super::ConfigStore;
use crate::error::Result;

impl ConfigStore {
    /// Record a challenge with an explicit expiry (Story 9.5 AC #6).
    ///
    /// Re-recording a token that is already present refreshes both its
    /// key authorization and its deadline: an ACME order that retries
    /// an authorization must not inherit the previous attempt's
    /// expiry.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ConfigError::Database`] when the write
    /// fails.
    pub fn set_acme_challenge(
        &self,
        token: &str,
        key_auth: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO acme_challenges (token, key_auth, expires_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(token) DO UPDATE SET key_auth = excluded.key_auth, \
             expires_at = excluded.expires_at",
            params![token, key_auth, expires_at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// The key authorization for `token`, or `None` when absent OR
    /// expired.
    ///
    /// The expiry is part of the query rather than a post-filter so
    /// that no caller can accidentally serve a stale token by reading
    /// the row and forgetting to check: the purge is a housekeeping
    /// task, this predicate is the guarantee.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ConfigError::Database`] when the read
    /// fails.
    pub fn get_acme_challenge(&self, token: &str, now: DateTime<Utc>) -> Result<Option<String>> {
        let key_auth: Option<String> = self
            .conn
            .query_row(
                "SELECT key_auth FROM acme_challenges WHERE token = ?1 AND expires_at > ?2",
                params![token, now.to_rfc3339()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(key_auth)
    }

    /// Forget a challenge, whether or not it had expired. Deleting an
    /// absent token is not an error: the ACME driver runs its cleanup
    /// on both the success and the failure path, so a second call is a
    /// normal outcome.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ConfigError::Database`] when the delete
    /// fails.
    pub fn delete_acme_challenge(&self, token: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM acme_challenges WHERE token = ?1",
            params![token],
        )?;
        Ok(())
    }

    /// Drop every entry past its expiry. Returns how many went.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ConfigError::Database`] when the delete
    /// fails.
    pub fn purge_expired_acme_challenges(&self, now: DateTime<Utc>) -> Result<usize> {
        let purged = self.conn.execute(
            "DELETE FROM acme_challenges WHERE expires_at <= ?1",
            params![now.to_rfc3339()],
        )?;
        Ok(purged)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, Utc};

    use crate::store::ConfigStore;

    fn at(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339)
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
    }

    #[test]
    fn a_challenge_is_served_before_its_expiry_and_never_after() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let now = at("2026-09-08T12:00:00Z");
        store
            .set_acme_challenge("tok", "tok.thumbprint", now + Duration::minutes(5))
            .expect("test setup: challenge writes");

        assert_eq!(
            store
                .get_acme_challenge("tok", now)
                .expect("read succeeds")
                .as_deref(),
            Some("tok.thumbprint")
        );

        // The row is still there; only the deadline moved. Serving it
        // would be exactly the leak AC #6 closes.
        let later = now + Duration::minutes(6);
        assert_eq!(
            store.get_acme_challenge("tok", later).expect("read succeeds"),
            None,
            "an expired challenge must not be served even before the purge runs"
        );
        let still_present: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM acme_challenges", [], |row| row.get(0))
            .expect("test setup: count query");
        assert_eq!(still_present, 1, "the read predicate, not a delete, hid it");
    }

    #[test]
    fn an_absent_token_reads_as_none() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        assert_eq!(
            store
                .get_acme_challenge("never-written", at("2026-09-08T12:00:00Z"))
                .expect("read succeeds"),
            None
        );
    }

    #[test]
    fn re_recording_a_token_refreshes_the_key_auth_and_the_deadline() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let now = at("2026-09-08T12:00:00Z");
        store
            .set_acme_challenge("tok", "first", now + Duration::minutes(1))
            .expect("test setup: first write");
        store
            .set_acme_challenge("tok", "second", now + Duration::minutes(30))
            .expect("test setup: second write");

        let refreshed = now + Duration::minutes(10);
        assert_eq!(
            store
                .get_acme_challenge("tok", refreshed)
                .expect("read succeeds")
                .as_deref(),
            Some("second"),
            "the retry's key authorization and expiry both win"
        );
    }

    #[test]
    fn the_purge_counts_only_what_it_dropped() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let now = at("2026-09-08T12:00:00Z");
        store
            .set_acme_challenge("stale-1", "a", now - Duration::minutes(1))
            .expect("test setup: write");
        store
            .set_acme_challenge("stale-2", "b", now - Duration::hours(9))
            .expect("test setup: write");
        store
            .set_acme_challenge("live", "c", now + Duration::minutes(5))
            .expect("test setup: write");

        assert_eq!(
            store
                .purge_expired_acme_challenges(now)
                .expect("purge succeeds"),
            2
        );
        assert_eq!(
            store
                .purge_expired_acme_challenges(now)
                .expect("purge succeeds"),
            0,
            "a second pass has nothing left to drop"
        );
        assert_eq!(
            store
                .get_acme_challenge("live", now)
                .expect("read succeeds")
                .as_deref(),
            Some("c"),
            "the purge is bounded by the expiry, not by the table"
        );
    }

    #[test]
    fn deleting_a_challenge_is_idempotent() {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store opens");
        let now = at("2026-09-08T12:00:00Z");
        store
            .set_acme_challenge("tok", "auth", now + Duration::minutes(5))
            .expect("test setup: write");
        store.delete_acme_challenge("tok").expect("delete succeeds");
        store
            .delete_acme_challenge("tok")
            .expect("a second delete is a normal cleanup outcome");
        assert_eq!(
            store.get_acme_challenge("tok", now).expect("read succeeds"),
            None
        );
    }
}
