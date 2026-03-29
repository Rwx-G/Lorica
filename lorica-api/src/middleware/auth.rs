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
    sessions: Arc<Mutex<HashMap<String, Session>>>,
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
    format!("{SESSION_COOKIE_NAME}={session_id}; HttpOnly; SameSite=Strict; Path=/api")
}

/// Build a Set-Cookie header to clear the session.
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/api; Max-Age=0")
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
