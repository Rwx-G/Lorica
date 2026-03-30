use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::error::ApiError;

const SESSION_COOKIE_NAME: &str = "lorica_session";
const SESSION_TIMEOUT_MINUTES: i64 = 30;

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: String,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// In-memory session store.
#[derive(Debug, Clone)]
pub struct SessionStore {
    pub(crate) sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new session and return the session ID.
    pub async fn create(&self, user_id: String, username: String) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let session = Session {
            user_id,
            username,
            created_at: now,
            expires_at: now + Duration::minutes(SESSION_TIMEOUT_MINUTES),
        };
        self.sessions
            .lock()
            .await
            .insert(session_id.clone(), session);
        session_id
    }

    /// Get a session by ID, returning None if expired or not found.
    pub async fn get(&self, session_id: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(session_id) {
            if session.expires_at > Utc::now() {
                return Some(session.clone());
            }
            sessions.remove(session_id);
        }
        None
    }

    /// Remove a session.
    pub async fn remove(&self, session_id: &str) {
        self.sessions.lock().await.remove(session_id);
    }

    /// Get the expiration time of a session.
    pub async fn expires_at(&self, session_id: &str) -> Option<DateTime<Utc>> {
        self.sessions
            .lock()
            .await
            .get(session_id)
            .map(|s| s.expires_at)
    }

    /// Remove all expired sessions from memory.
    pub async fn purge_expired(&self) -> usize {
        let now = Utc::now();
        let mut sessions = self.sessions.lock().await;
        let before = sessions.len();
        sessions.retain(|_, s| s.expires_at > now);
        before - sessions.len()
    }

    /// Spawn a background task that purges expired sessions at a fixed interval.
    pub fn spawn_gc(self, interval: std::time::Duration) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
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

    let mut req = req;
    req.extensions_mut().insert(session);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_store_create_and_get() {
        let store = SessionStore::new();
        let sid = store.create("user-1".into(), "admin".into()).await;
        let session = store.get(&sid).await.unwrap();
        assert_eq!(session.user_id, "user-1");
        assert_eq!(session.username, "admin");
    }

    #[tokio::test]
    async fn test_session_store_get_nonexistent() {
        let store = SessionStore::new();
        assert!(store.get("nonexistent").await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_remove() {
        let store = SessionStore::new();
        let sid = store.create("user-1".into(), "admin".into()).await;
        store.remove(&sid).await;
        assert!(store.get(&sid).await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_expires_at() {
        let store = SessionStore::new();
        let sid = store.create("user-1".into(), "admin".into()).await;
        let expires = store.expires_at(&sid).await;
        assert!(expires.is_some());
        assert!(expires.unwrap() > Utc::now());
    }

    #[tokio::test]
    async fn test_session_store_expires_at_nonexistent() {
        let store = SessionStore::new();
        assert!(store.expires_at("nope").await.is_none());
    }

    #[tokio::test]
    async fn test_session_store_expired_session_returns_none() {
        let store = SessionStore::new();
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
        let store = SessionStore::new();

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
        let store = SessionStore::new();
        store.create("user-1".into(), "admin".into()).await;
        assert_eq!(store.purge_expired().await, 0);
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
            .header(http::header::COOKIE, "lorica_session=test-sid-123; other=val")
            .body(axum::body::Body::empty())
            .unwrap();
        let result = extract_session_cookie(&req);
        assert_eq!(result.unwrap(), "test-sid-123");
    }

    #[test]
    fn test_extract_session_cookie_missing() {
        let req = Request::builder()
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(extract_session_cookie(&req).is_none());
    }

    #[test]
    fn test_extract_session_cookie_wrong_name() {
        let req = Request::builder()
            .header(http::header::COOKIE, "other_cookie=val")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(extract_session_cookie(&req).is_none());
    }

    #[test]
    fn test_session_store_default() {
        let store = SessionStore::default();
        assert!(store.sessions.try_lock().is_ok());
    }
}
