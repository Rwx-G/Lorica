//! Optional authentication gate on the `/metrics` endpoint (Story 8.8
//! AC #4 / AC #5).
//!
//! When the global setting `metrics_require_auth` is `false` (the
//! v1.6.0 default) this middleware is a straight pass-through, so
//! existing unauthenticated Prometheus scrapes keep working. When it is
//! `true`, a scrape must present ONE of:
//!
//! - a valid dashboard session cookie (an operator viewing `/metrics`
//!   in the browser), or
//! - the static bearer token in `prometheus_scrape_token` (or its
//!   environment override `LORICA_PROMETHEUS_SCRAPE_TOKEN`), supplied
//!   as `Authorization: Bearer <token>`.
//!
//! The bearer comparison is constant-time (AC #5). A failed auth
//! returns `401` with `WWW-Authenticate: Bearer realm="lorica-metrics"`.

use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use super::auth::SessionStore;
use crate::error::ApiError;
use crate::server::AppState;

/// Environment variable that overrides the persisted
/// `prometheus_scrape_token` at request time (Story 8.8 AC #4). Lets
/// an operator inject the token out of band without writing it to the
/// database.
const SCRAPE_TOKEN_ENV: &str = "LORICA_PROMETHEUS_SCRAPE_TOKEN";

/// Realm advertised in the `WWW-Authenticate` challenge on a 401.
const METRICS_REALM: &str = "lorica-metrics";

/// How long a cached auth-settings snapshot is reused before re-reading
/// the store. Bounds the settings DB read to at most once per this window
/// regardless of scrape rate (performance: a Prometheus scrape must not
/// pay a blocking SQLite read every time, especially in the default
/// `metrics_require_auth = false` configuration). A change to the toggle
/// or token takes effect within one TTL.
const AUTH_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// The two settings the middleware needs, cached to keep `/metrics`
/// scrapes off the store's connection lock.
#[derive(Clone)]
struct AuthSettings {
    require_auth: bool,
    scrape_token: Option<String>,
}

/// Process-wide TTL cache of [`AuthSettings`]. The management API runs in
/// a single process, so one cache suffices.
static AUTH_CACHE: std::sync::LazyLock<std::sync::RwLock<Option<(AuthSettings, std::time::Instant)>>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(None));

/// Return the auth settings, from the TTL cache when fresh, otherwise
/// re-read them from the store and refresh the cache. `Err(())` on a
/// store-read failure so the caller can fail closed.
async fn cached_auth_settings(state: &AppState) -> Result<AuthSettings, ()> {
    if let Ok(guard) = AUTH_CACHE.read() {
        if let Some((cached, at)) = guard.as_ref() {
            if at.elapsed() < AUTH_CACHE_TTL {
                return Ok(cached.clone());
            }
        }
    }
    let settings = crate::db::db_blocking(&state.store, |store| store.get_global_settings())
        .await
        .map_err(|_| ())?;
    let fresh = AuthSettings {
        require_auth: settings.metrics_require_auth,
        scrape_token: settings.prometheus_scrape_token,
    };
    if let Ok(mut guard) = AUTH_CACHE.write() {
        *guard = Some((fresh.clone(), std::time::Instant::now()));
    }
    Ok(fresh)
}

/// Axum middleware guarding `/metrics`. See the module docs for the
/// trust model. Fails closed: if `AppState` is somehow absent from the
/// request extensions (never in normal wiring) the request is rejected.
pub async fn metrics_auth(req: Request, next: Next) -> Result<Response, ApiError> {
    let Some(state) = req.extensions().get::<AppState>().cloned() else {
        return Ok(unauthorized());
    };

    let settings = match cached_auth_settings(&state).await {
        Ok(s) => s,
        // A store read failure must not silently open the endpoint
        // once the operator has asked for auth. Fail closed.
        Err(()) => return Ok(unauthorized()),
    };

    if !settings.require_auth {
        return Ok(next.run(req).await);
    }

    // Extract everything the auth check needs from the request BEFORE
    // any await: `Request<Body>` is `!Sync`, so holding a `&req` across
    // an `.await` would make this middleware future `!Send` and fail
    // axum's `Service` bound. The bearer check is fully synchronous;
    // the session check needs only the owned cookie value + a cloned
    // `SessionStore`.
    if bearer_authorized(&req, settings.scrape_token.as_deref()) {
        return Ok(next.run(req).await);
    }
    let session_store = req.extensions().get::<SessionStore>().cloned();
    let session_id = session_cookie_value(&req);

    if let (Some(store), Some(sid)) = (session_store, session_id) {
        if store.get(&sid).await.is_some() {
            return Ok(next.run(req).await);
        }
    }

    Ok(unauthorized())
}

/// Resolve the effective scrape token: the `LORICA_PROMETHEUS_SCRAPE_TOKEN`
/// environment variable wins over the persisted setting, and an empty
/// value (after trim) counts as "unset". Returns `None` when no token
/// is configured, in which case bearer auth can never succeed.
fn effective_scrape_token(setting: Option<&str>) -> Option<String> {
    if let Ok(env_val) = std::env::var(SCRAPE_TOKEN_ENV) {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    setting
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Constant-time comparison of the request's `Authorization: Bearer`
/// token against the expected token. Returns `false` when no token is
/// configured, when the header is absent or malformed, or when the
/// value does not match. The `subtle` comparison keeps the match
/// timing independent of how many leading bytes are correct (AC #5).
fn bearer_authorized(req: &Request, setting_token: Option<&str>) -> bool {
    let Some(expected) = effective_scrape_token(setting_token) else {
        return false;
    };
    let Some(provided) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    provided
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .into()
}

/// Extract the `lorica_session` cookie value from the request, if present.
fn session_cookie_value(req: &Request) -> Option<String> {
    let cookie_header = req.headers().get(header::COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        if let Some(value) = cookie.trim().strip_prefix("lorica_session=") {
            return Some(value.to_string());
        }
    }
    None
}

/// Build the `401 Unauthorized` response with the metrics `WWW-Authenticate`
/// challenge (AC #5).
fn unauthorized() -> Response {
    let mut response = (StatusCode::UNAUTHORIZED, "metrics authentication required").into_response();
    let challenge = format!("Bearer realm=\"{METRICS_REALM}\"");
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `effective_scrape_token` reads a process-global env var, so the
    // tests that mutate it must not run concurrently with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn req_with_auth(value: &str) -> Request {
        Request::builder()
            .header(header::AUTHORIZATION, value)
            .body(axum::body::Body::empty())
            .expect("test request")
    }

    #[test]
    fn effective_token_prefers_env_over_setting() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        // No env var set: setting is used.
        std::env::remove_var(SCRAPE_TOKEN_ENV);
        assert_eq!(
            effective_scrape_token(Some("from-setting")),
            Some("from-setting".to_string())
        );
        // Env override wins.
        std::env::set_var(SCRAPE_TOKEN_ENV, "from-env");
        assert_eq!(
            effective_scrape_token(Some("from-setting")),
            Some("from-env".to_string())
        );
        // Blank env is treated as unset.
        std::env::set_var(SCRAPE_TOKEN_ENV, "   ");
        assert_eq!(
            effective_scrape_token(Some("from-setting")),
            Some("from-setting".to_string())
        );
        std::env::remove_var(SCRAPE_TOKEN_ENV);
        // No setting and no env: nothing configured.
        assert_eq!(effective_scrape_token(None), None);
        assert_eq!(effective_scrape_token(Some("  ")), None);
    }

    #[test]
    fn bearer_matches_exact_token_only() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        std::env::remove_var(SCRAPE_TOKEN_ENV);
        assert!(bearer_authorized(
            &req_with_auth("Bearer s3cret"),
            Some("s3cret")
        ));
        assert!(!bearer_authorized(
            &req_with_auth("Bearer wrong"),
            Some("s3cret")
        ));
        // Wrong scheme.
        assert!(!bearer_authorized(
            &req_with_auth("Basic s3cret"),
            Some("s3cret")
        ));
        // A prefix of the real token must not pass (length differs).
        assert!(!bearer_authorized(
            &req_with_auth("Bearer s3cre"),
            Some("s3cret")
        ));
        // No token configured: bearer can never authorize.
        assert!(!bearer_authorized(&req_with_auth("Bearer s3cret"), None));
    }

    #[test]
    fn bearer_missing_header_is_rejected() {
        let req = Request::builder()
            .body(axum::body::Body::empty())
            .expect("test request");
        assert!(!bearer_authorized(&req, Some("s3cret")));
    }

    #[test]
    fn session_cookie_is_extracted() {
        let req = Request::builder()
            .header(header::COOKIE, "foo=bar; lorica_session=abc-123; x=y")
            .body(axum::body::Body::empty())
            .expect("test request");
        assert_eq!(session_cookie_value(&req), Some("abc-123".to_string()));
    }
}
