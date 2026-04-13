//! Cookie-based session middleware: parsing, persistence, GC, and the
//! `require_auth` axum guard.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Duration, Utc};
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::ApiError;

const SESSION_COOKIE_NAME: &str = "lorica_session";
const SESSION_TIMEOUT_MINUTES: i64 = 30;

/// Authenticated session injected into request extensions by [`require_auth`].
#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Session store backed by SQLite with an in-memory cache for fast lookups.
///
/// # Consistency model
///
/// **Source of truth:** SQLite (`sessions` table). The in-memory
/// `HashMap` is a cache rebuilt on startup from `load_all_sessions`.
///
/// **Writes:** `set()` mutates the cache synchronously (under the
/// mutex) and spawns a blocking task to persist to SQLite. The HTTP
/// response is returned as soon as the cache is updated; SQLite catches
/// up asynchronously. A crash between the two writes can forget a
/// session that the client has already received a cookie for - the
/// next request will be unauthenticated and the user re-logs in. An
/// accepted trade-off for login latency vs durability on a crash.
///
/// **Deletes:** `remove()` is async; the cache and SQLite are updated
/// in the same task. A failed SQLite delete leaves the row dangling
/// until the next startup rebuild filters it out by `expires_at`.
///
/// **Worker mode:** The supervisor owns the only `SessionStore`. Workers
/// never read/write sessions; authentication happens in the supervisor
/// and upstream requests carry no session state. See Epic 2 notes.
#[derive(Clone)]
pub struct SessionStore {
    pub(crate) sessions: Arc<Mutex<HashMap<String, Session>>>,
    db: Arc<Mutex<ConfigStore>>,
    /// Tracker for the fire-and-forget SQLite writes (`delete_session`,
    /// `update_session_expiry`, `cleanup_expired_sessions`). Defaults
    /// to a standalone tracker so tests and callers that don't care
    /// about drain still work; the supervisor wires its shared tracker
    /// via `with_task_tracker` so shutdown can wait on pending writes.
    task_tracker: tokio_util::task::TaskTracker,
}

impl SessionStore {
    /// Create a new session store backed by the given ConfigStore.
    /// Loads existing non-expired sessions from the database into memory.
    pub async fn new(db: Arc<Mutex<ConfigStore>>) -> Self {
        let mut cache = HashMap::new();

        // Load persisted sessions from SQLite
        {
            let store = db.lock().await;
            match store.load_all_sessions() {
                Ok(rows) => {
                    for (id, user_id, username, created_at, expires_at) in rows {
                        cache.insert(
                            id,
                            Session {
                                user_id,
                                username,
                                created_at,
                                expires_at,
                            },
                        );
                    }
                    if !cache.is_empty() {
                        tracing::info!(count = cache.len(), "restored sessions from database");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to load sessions from database, starting fresh");
                }
            }
        }

        Self {
            sessions: Arc::new(Mutex::new(cache)),
            db,
            task_tracker: tokio_util::task::TaskTracker::new(),
        }
    }

    /// Swap in the supervisor's shared task tracker so background
    /// session-store writes are drained on shutdown instead of being
    /// dropped mid-write.
    pub fn with_task_tracker(mut self, tracker: tokio_util::task::TaskTracker) -> Self {
        self.task_tracker = tracker;
        self
    }

    /// Create a new session and return the session ID.
    pub async fn create(&self, user_id: String, username: String) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let session = Session {
            user_id: user_id.clone(),
            username: username.clone(),
            created_at: now,
            expires_at: now + Duration::minutes(SESSION_TIMEOUT_MINUTES),
        };

        // Persist to SQLite
        {
            let store = self.db.lock().await;
            if let Err(e) = store.save_session(
                &session_id,
                &user_id,
                &username,
                &session.created_at,
                &session.expires_at,
            ) {
                tracing::warn!(error = %e, "failed to persist session to database");
            }
        }

        // Insert into memory cache
        self.sessions
            .lock()
            .await
            .insert(session_id.clone(), session);
        session_id
    }

    /// Get a session by ID, returning None if expired or not found.
    pub async fn get(&self, session_id: &str) -> Option<Session> {
        // Check memory cache first
        {
            let mut sessions = self.sessions.lock().await;
            if let Some(session) = sessions.get(session_id) {
                if session.expires_at > Utc::now() {
                    return Some(session.clone());
                }
                // Expired - remove from cache and DB
                sessions.remove(session_id);
                let db = self.db.clone();
                let sid = session_id.to_string();
                self.task_tracker.spawn(async move {
                    let store = db.lock().await;
                    let _ = store.delete_session(&sid);
                });
                return None;
            }
        }

        // Fallback: check database
        let session = {
            let store = self.db.lock().await;
            match store.get_session(session_id) {
                Ok(Some((user_id, username, created_at, expires_at))) => {
                    if expires_at > Utc::now() {
                        Some(Session {
                            user_id,
                            username,
                            created_at,
                            expires_at,
                        })
                    } else {
                        let _ = store.delete_session(session_id);
                        None
                    }
                }
                _ => None,
            }
        };

        // Populate cache if found in DB
        if let Some(ref s) = session {
            self.sessions
                .lock()
                .await
                .insert(session_id.to_string(), s.clone());
        }

        session
    }

    /// Remove a session.
    pub async fn remove(&self, session_id: &str) {
        self.sessions.lock().await.remove(session_id);
        let store = self.db.lock().await;
        let _ = store.delete_session(session_id);
    }

    /// Renew a session's expiry (sliding window).
    pub async fn renew(&self, session_id: &str) {
        let new_expiry = Utc::now() + Duration::minutes(SESSION_TIMEOUT_MINUTES);
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            session.expires_at = new_expiry;

            let db = self.db.clone();
            let sid = session_id.to_string();
            self.task_tracker.spawn(async move {
                let store = db.lock().await;
                let _ = store.update_session_expiry(&sid, &new_expiry);
            });
        }
    }

    /// Get the expiration time of a session.
    pub async fn expires_at(&self, session_id: &str) -> Option<DateTime<Utc>> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|s| s.expires_at)
    }

    /// Remove all sessions for a user except the given session ID.
    pub async fn remove_all_for_user_except(&self, user_id: &str, keep_session_id: &str) {
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|sid, session| session.user_id != user_id || sid == keep_session_id);

        let db = self.db.clone();
        let uid = user_id.to_string();
        let keep = keep_session_id.to_string();
        self.task_tracker.spawn(async move {
            let store = db.lock().await;
            let _ = store.delete_sessions_for_user_except(&uid, &keep);
        });
    }

    /// Remove all expired sessions from memory and database.
    pub async fn purge_expired(&self) -> usize {
        let now = Utc::now();
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.expires_at > now);
        let purged = before - sessions.len();

        if purged > 0 {
            let db = self.db.clone();
            self.task_tracker.spawn(async move {
                let store = db.lock().await;
                let _ = store.cleanup_expired_sessions();
            });
        }

        purged
    }

    /// Spawn a background task that purges expired sessions at a fixed interval.
    pub fn spawn_gc(self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        let tracker = self.task_tracker.clone();
        tracker.spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let purged = self.purge_expired().await;
                if purged > 0 {
                    tracing::debug!(purged, "session GC: removed expired sessions");
                }
            }
        })
    }
}

/// Extract the session cookie value from a request.
fn extract_session_cookie(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get(http::header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let cookie = cookie.trim();
        if let Some(value) = cookie.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value.to_string());
        }
    }
    None
}

/// Build a Set-Cookie header value for the session.
pub fn session_cookie(session_id: &str) -> String {
    format!("{SESSION_COOKIE_NAME}={session_id}; HttpOnly; Secure; SameSite=Strict; Path=/api")
}

/// Build a Set-Cookie header to clear the session.
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0")
}

/// Axum middleware that requires a valid session.
pub async fn require_auth(req: Request, next: Next) -> Result<Response, ApiError> {
    let session_store = req
        .extensions()
        .get::<SessionStore>()
        .cloned()
        .ok_or_else(|| ApiError::Internal("session store not configured".into()))?;

    let session_id = extract_session_cookie(&req)
        .ok_or_else(|| ApiError::Unauthorized("missing session cookie".into()))?;

    let session = session_store
        .get(&session_id)
        .await
        .ok_or_else(|| ApiError::Unauthorized("invalid or expired session".into()))?;

    // Sliding window: renew session expiry on every authenticated request
    session_store.renew(&session_id).await;

    let mut req = req;
    req.extensions_mut().insert(session);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_store() -> SessionStore {
        let db = ConfigStore::open_in_memory().expect("test setup");
        SessionStore::new(Arc::new(Mutex::new(db))).await
    }

    #[tokio::test]
    async fn test_session_store_create_and_get() {
        let store = test_store().await;
        let sid = store.create("user-1".into(), "admin".into()).await;
        let session = store.get(&sid).await.expect("test setup");
        assert_eq!(session.user_id, "user-1");
        assert_eq!(session.username, "admin");
    }

    #[tokio::test]
    async fn test_session_store_get_nonexistent() {
        let store = test_store().await;
        assert!(store.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_remove() {
        let store = test_store().await;
        let sid = store.create("user-1".into(), "admin".into()).await;
        store.remove(&sid).await;
        // Allow spawned DB task to complete
        tokio::task::yield_now().await;
        assert!(store.get(&sid).await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_expires_at() {
        let store = test_store().await;
        let sid = store.create("user-1".into(), "admin".into()).await;
        let expires = store.expires_at(&sid).await;
        assert!(expires.is_some());
        assert!(expires.expect("test setup") > Utc::now());
    }

    #[tokio::test]
    async fn test_session_store_expires_at_nonexistent() {
        let store = test_store().await;
        assert!(store.expires_at("nope").await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_expired_session_returns_none() {
        let store = test_store().await;
        let sid = Uuid::new_v4().to_string();
        let expired = Session {
            user_id: "user-1".into(),
            username: "admin".into(),
            created_at: Utc::now() - Duration::minutes(60),
            expires_at: Utc::now() - Duration::minutes(1),
        };
        store.sessions.lock().await.insert(sid.clone(), expired);
        assert!(store.get(&sid).await.is_none());
        // Verify the expired session was removed from the map
        assert!(store.sessions.lock().await.get(&sid).is_none());
    }

    #[tokio::test]
    async fn test_purge_expired_removes_stale_sessions() {
        let store = test_store().await;

        // Insert a valid session
        let valid_sid = store.create("user-1".into(), "admin".into()).await;

        // Insert an expired session
        let expired_sid = Uuid::new_v4().to_string();
        let expired = Session {
            user_id: "user-2".into(),
            username: "old".into(),
            created_at: Utc::now() - Duration::minutes(60),
            expires_at: Utc::now() - Duration::minutes(1),
        };
        store
            .sessions
            .lock()
            .await
            .insert(expired_sid.clone(), expired);

        let purged = store.purge_expired().await;
        assert_eq!(purged, 1);

        // Valid session still exists
        assert!(store.get(&valid_sid).await.is_some());
        // Expired session gone
        assert!(store.sessions.lock().await.get(&expired_sid).is_none());
    }

    #[tokio::test]
    async fn test_purge_expired_returns_zero_when_none_expired() {
        let store = test_store().await;
        store.create("user-1".into(), "admin".into()).await;
        assert_eq!(store.purge_expired().await, 0);
    }

    #[tokio::test]
    async fn test_session_persisted_to_db() {
        let db = Arc::new(Mutex::new(
            ConfigStore::open_in_memory().expect("test setup"),
        ));
        let store = SessionStore::new(db.clone()).await;
        let sid = store.create("user-1".into(), "admin".into()).await;

        // Verify session exists in database
        let db_lock = db.lock().await;
        let row = db_lock.get_session(&sid).expect("test setup");
        assert!(row.is_some());
        let (user_id, _username, _created, _expires) = row.expect("test setup");
        assert_eq!(user_id, "user-1");
    }

    #[tokio::test]
    async fn test_session_restored_on_startup() {
        let db = Arc::new(Mutex::new(
            ConfigStore::open_in_memory().expect("test setup"),
        ));

        // Create a session with the first store instance
        let store1 = SessionStore::new(db.clone()).await;
        let sid = store1.create("user-1".into(), "admin".into()).await;
        drop(store1);

        // Create a new store instance (simulates restart)
        let store2 = SessionStore::new(db.clone()).await;
        let session = store2.get(&sid).await;
        assert!(session.is_some());
        assert_eq!(session.expect("test setup").user_id, "user-1");
    }

    #[test]
    fn test_session_cookie_format() {
        let cookie = session_cookie("abc-123");
        assert!(cookie.contains("lorica_session=abc-123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Path=/api"));
    }

    #[test]
    fn test_clear_session_cookie_format() {
        let cookie = clear_session_cookie();
        assert!(cookie.contains("lorica_session="));
        assert!(cookie.contains("Max-Age=0"));
        assert!(cookie.contains("HttpOnly"));
    }

    #[test]
    fn test_extract_session_cookie_from_request() {
        let req = Request::builder()
            .header(
                http::header::COOKIE,
                "lorica_session=test-sid-123; other=val",
            )
            .body(axum::body::Body::empty())
            .expect("test setup");
        let result = extract_session_cookie(&req);
        assert_eq!(result.expect("test setup"), "test-sid-123");
    }

    #[test]
    fn test_extract_session_cookie_missing() {
        let req = Request::builder()
            .body(axum::body::Body::empty())
            .expect("test setup");
        assert!(extract_session_cookie(&req).is_none());
    }

    #[test]
    fn test_extract_session_cookie_wrong_name() {
        let req = Request::builder()
            .header(http::header::COOKIE, "other_cookie=val")
            .body(axum::body::Body::empty())
            .expect("test setup");
        assert!(extract_session_cookie(&req).is_none());
    }

    // ------------------------------------------------------------------
    // Task tracker wiring test
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_store_tracker_drains_pending_writes() {
        // Regression test for QUA-5. Fire-and-forget SQLite writes
        // issued from the session store must be drained by the
        // supervisor's shared `TaskTracker` on shutdown, not dropped
        // mid-step. `get()` on an expired cache entry spawns a
        // `delete_session` write; after `tracker.close(); wait()`
        // the write must have executed.
        let tracker = tokio_util::task::TaskTracker::new();
        let store = test_store().await.with_task_tracker(tracker.clone());

        // Seed an already-expired session directly in memory (bypass
        // `create()` which sets a future expiry) so the next `get()`
        // triggers the spawn path we want to exercise.
        let sid = "expired-session".to_string();
        {
            let mut cache = store.sessions.lock().await;
            cache.insert(
                sid.clone(),
                Session {
                    user_id: "u1".into(),
                    username: "u1".into(),
                    created_at: Utc::now() - Duration::hours(2),
                    expires_at: Utc::now() - Duration::hours(1),
                },
            );
        }
        assert!(
            store.get(&sid).await.is_none(),
            "expired lookup returns None"
        );

        // Now drain: shutdown semantics. `close()` prevents further
        // spawns, `wait()` resolves once every tracked future is done.
        tracker.close();
        let drained = tokio::time::timeout(std::time::Duration::from_secs(2), tracker.wait()).await;
        assert!(
            drained.is_ok(),
            "tracker.wait() must resolve; a leaked tokio::spawn would hang it"
        );
    }
}
