// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SQLite-backed store for pending ACME HTTP-01 challenges.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

/// SQLite-backed store for pending ACME HTTP-01 challenges.
/// Maps token -> key_authorization for /.well-known/acme-challenge/{token}.
/// Uses SQLite so challenges are accessible across forked worker processes
/// (workers share the same database file).
///
/// # Consistency model
///
/// **Source of truth:** SQLite (`acme_challenges` table). The in-memory
/// `RwLock<HashMap>` is a supervisor-local read cache. Workers bypass the
/// cache and hit SQLite directly on `/.well-known/acme-challenge/{token}`
/// because they do not share the supervisor's memory.
///
/// **Writes:** `set()` writes the cache first, then spawns a blocking
/// SQLite INSERT so the call returns quickly. The CA polls the
/// challenge endpoint seconds-to-minutes later, so the ~tens-of-ms
/// write window is harmless in practice.
///
/// **Deletes:** challenges are short-lived (ACME validates within
/// seconds). Entries that outlive their useful life are purged on the
/// provisioning path after the CA confirms success.
///
/// **Worker visibility:** workers serve the HTTP-01 endpoint from the
/// proxy data plane (port 80); their `request_filter` calls `get()`
/// which falls back to SQLite when the in-process cache is empty
/// (always, in the worker case). SQLite WAL mode makes the cross-process
/// read safe under concurrent writes.
#[derive(Debug, Clone)]
pub struct AcmeChallengeStore {
    /// In-memory cache for fast lookups in the supervisor process.
    challenges: Arc<RwLock<HashMap<String, String>>>,
    /// Long-lived SQLite connection shared across all calls in this
    /// process. `None` only if the initial open failed (e.g. a test
    /// pointed at an unwritable path) - in that case we degrade to
    /// memory-only and log on first access.
    conn: Option<Arc<parking_lot::Mutex<rusqlite::Connection>>>,
    /// Path to the SQLite database (kept for diagnostics).
    db_path: std::path::PathBuf,
}

impl Default for AcmeChallengeStore {
    fn default() -> Self {
        Self::with_db_path(std::path::PathBuf::from("/var/lib/lorica/lorica.db"))
    }
}

impl AcmeChallengeStore {
    /// Build a store using the default database path (`/var/lib/lorica/lorica.db`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a store backed by a SQLite file at `path`.
    pub fn with_db_path(path: std::path::PathBuf) -> Self {
        // Open one long-lived connection. WAL + busy_timeout + sync=NORMAL
        // matches the rest of the codebase: cross-process readers (workers
        // serving the HTTP-01 endpoint) coexist safely with concurrent
        // multi-domain ACME renewals on the supervisor side without
        // hitting SQLITE_BUSY at the timeout boundary.
        let conn = match rusqlite::Connection::open(&path) {
            Ok(c) => {
                let _ = c.execute_batch(
                    "PRAGMA journal_mode=WAL; \
                     PRAGMA busy_timeout=5000; \
                     PRAGMA synchronous=NORMAL;",
                );
                // Schema ownership note (Story 9.1 AC #10): the
                // `acme_challenges` table is created by lorica-config
                // migration v47, which every process runs on
                // `ConfigStore::open` before this store attaches to
                // the same file. No DDL is issued here so future
                // schema changes (Story 9.5 adds a network writer)
                // have exactly one owner.
                Some(Arc::new(parking_lot::Mutex::new(c)))
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    db = %path.display(),
                    "failed to open SQLite for ACME challenge store; degrading to memory-only"
                );
                None
            }
        };
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            conn,
            db_path: path,
        }
    }

    /// Persist a challenge `token -> key_authorization` to SQLite and
    /// the in-memory cache.
    ///
    /// Fallible since Story 9.1 AC #9: in worker mode the workers
    /// serve the challenge from SQLite, so a failed INSERT means the
    /// data plane would 404 the CA's validation request - that must
    /// abort the order before readiness, not race it. A store running
    /// memory-only (SQLite unavailable at construction, single-process
    /// degraded mode) still returns `Ok`: the in-memory copy is what
    /// that topology serves from.
    pub async fn set(&self, token: String, key_authorization: String) -> Result<(), String> {
        self.challenges
            .write()
            .await
            .insert(token.clone(), key_authorization.clone());
        let Some(ref conn) = self.conn else {
            return Ok(());
        };
        let conn = Arc::clone(conn);
        let token_log = token.clone();
        let db_log = self.db_path.clone();
        let persist = tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT OR REPLACE INTO acme_challenges (token, key_auth) VALUES (?1, ?2)",
                    rusqlite::params![token, key_authorization],
                )
                .map_err(|e| e.to_string())
        })
        .await;
        let outcome = match persist {
            Ok(Ok(_)) => {
                tracing::info!(token = %token_log, db = %db_log.display(),
                    "ACME challenge persisted to SQLite");
                Ok(())
            }
            Ok(Err(e)) => {
                tracing::warn!(token = %token_log, error = %e,
                    "failed to persist ACME challenge to SQLite");
                Err(format!("challenge persist failed: {e}"))
            }
            Err(e) => {
                tracing::warn!(token = %token_log, error = %e,
                    "ACME challenge persist task failed");
                Err(format!("challenge persist task failed: {e}"))
            }
        };
        if outcome.is_err() {
            // The order aborts on this Err; do not leave the
            // supervisor's cache serving a key authorization for it.
            self.challenges.write().await.remove(&token_log);
        }
        outcome
    }

    /// Look up the key authorization for `token`, falling back to SQLite if not in the local cache.
    pub async fn get(&self, token: &str) -> Option<String> {
        // Try in-memory first (supervisor process)
        if let Some(val) = self.challenges.read().await.get(token).cloned() {
            tracing::info!(token = token, "ACME challenge found in memory");
            return Some(val);
        }
        // Fall back to SQLite (worker processes)
        let conn = self.conn.as_ref()?.clone();
        let token_owned = token.to_string();
        let db_log = self.db_path.clone();
        let result = tokio::task::spawn_blocking(move || {
            let guard = conn.lock();
            guard
                .query_row(
                    "SELECT key_auth FROM acme_challenges WHERE token = ?1",
                    rusqlite::params![token_owned],
                    |row| row.get::<_, String>(0),
                )
                .ok()
        })
        .await
        .ok()
        .flatten();
        if result.is_some() {
            tracing::info!(token = token, "ACME challenge found in SQLite");
        } else {
            tracing::info!(token = token, db = %db_log.display(),
                "ACME challenge not found in memory or SQLite");
        }
        result
    }

    /// Remove a challenge token from both the cache and SQLite once it is no longer needed.
    pub async fn remove(&self, token: &str) {
        self.challenges.write().await.remove(token);
        if let Some(ref conn) = self.conn {
            let conn = Arc::clone(conn);
            let token = token.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                let guard = conn.lock();
                // Cleanup stays infallible for the driver, but a
                // failed DELETE means workers keep serving this token
                // from SQLite across restarts (no expiry exists yet) -
                // that deserves a journal line, never key_auth.
                if let Err(e) = guard.execute(
                    "DELETE FROM acme_challenges WHERE token = ?1",
                    rusqlite::params![token],
                ) {
                    tracing::warn!(token = %token, error = %e,
                        "failed to delete ACME challenge from SQLite; stale token stays served");
                }
            })
            .await;
        }
    }
}

/// The store is the HTTP-01 challenge-solving strategy for the ACME driver:
/// publishing a token persists it (`set`), retracting it deletes it
/// (`remove`), so the proxy data plane serves the right key authorization at
/// `/.well-known/acme-challenge/{token}` while the order is live.
#[async_trait::async_trait]
impl lorica_acme::Http01ChallengeSolver for AcmeChallengeStore {
    async fn present(
        &self,
        _identifier: &str,
        token: String,
        key_authorization: String,
    ) -> Result<(), lorica_acme::AcmeError> {
        // The local store serves every token regardless of hostname;
        // `identifier` is for Story 9.5's fleet distribution.
        self.set(token, key_authorization)
            .await
            .map_err(lorica_acme::AcmeError::Solver)
    }

    async fn cleanup(&self, token: &str) {
        self.remove(token).await;
    }
}
