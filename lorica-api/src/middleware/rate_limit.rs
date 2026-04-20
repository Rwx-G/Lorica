//! In-memory fixed-window rate limiter with N named buckets.
//!
//! **Legacy login path.** The original limiter was single-bucket
//! (5 attempts / 60 s) keyed by client IP, used exclusively for
//! `POST /api/v1/auth/login`. The `.check(key)` method preserves
//! that contract so the login handler does not need to change.
//!
//! **Named buckets (v1.5.0 audit A.3).** The state-mutating
//! endpoints on the management plane (`PUT /settings`,
//! `POST /certificates`, `POST /config/import`, `POST /acme/
//! provision*`, `PUT /auth/password`, route CRUD, ACL CRUD)
//! now each get a dedicated bucket so a compromised session
//! cookie cannot be used to flood ACME quotas, overwrite the
//! whole config, or password-spray. Buckets are keyed by
//! `(bucket_name, key)` where `key` is typically the client IP
//! but can include a compound discriminator (e.g. `ip+user_id`
//! for password change).
//!
//! Each `check_bucket` call passes its own `limit` + `window`,
//! so one limiter instance can carry heterogeneous policies:
//! 3/60 s for ACME, 30/60 s for route CRUD, 10/60 s for
//! settings, etc.
//!
//! On denial `check_bucket` returns the number of seconds until
//! the window rolls over, which the middleware layer surfaces as
//! a `Retry-After` header alongside the 429 response (RFC 6585).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Extension, Request};
use axum::middleware::Next;
use axum::response::Response;
use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;

use crate::error::ApiError;

/// Legacy login bucket configuration (5 attempts / 60 s). Kept so
/// the existing login path can call `.check(key)` without caring
/// about named buckets.
const LOGIN_BUCKET: &str = "login";
const LOGIN_MAX: u32 = 5;
const LOGIN_WINDOW_SECONDS: i64 = 60;

#[derive(Debug, Clone)]
struct RateBucket {
    attempts: u32,
    window_start: DateTime<Utc>,
}

/// In-memory rate limiter with per-named-bucket fixed windows.
/// Cheap lock (single `tokio::Mutex<HashMap>`) ; the API management
/// plane is localhost-only so contention is not a concern at our
/// scale.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, RateBucket>>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    /// Construct an empty limiter.
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Legacy login check: returns true if the client is allowed,
    /// false if the window is exhausted. Retained for backward
    /// compatibility with the login handler.
    pub async fn check(&self, key: &str) -> bool {
        self.check_bucket(LOGIN_BUCKET, key, LOGIN_MAX, LOGIN_WINDOW_SECONDS as u64)
            .await
            .is_ok()
    }

    /// Fixed-window check on a named bucket. Returns `Ok(())` when
    /// the request is allowed, `Err(retry_after_seconds)` when the
    /// window is exhausted. `retry_after_seconds` is a conservative
    /// upper bound (time until the current window rolls over).
    ///
    /// `bucket` should be a short static string identifying the
    /// endpoint class (`login`, `settings`, `acme_provision`, ...)
    /// so a flood on one endpoint does not exhaust another.
    /// `key` is typically the client IP, but callers can carry a
    /// compound discriminator (e.g. `{ip}:{user_id}`) when a tighter
    /// isolation is required.
    pub async fn check_bucket(
        &self,
        bucket: &str,
        key: &str,
        limit: u32,
        window_seconds: u64,
    ) -> Result<(), u64> {
        let mut buckets = self.buckets.lock().await;
        let now = Utc::now();
        let composite = format!("{bucket}:{key}");

        let entry = buckets.entry(composite).or_insert(RateBucket {
            attempts: 0,
            window_start: now,
        });

        let window = Duration::seconds(window_seconds as i64);
        let elapsed = now - entry.window_start;
        if elapsed > window {
            entry.attempts = 0;
            entry.window_start = now;
        }

        entry.attempts += 1;
        if entry.attempts <= limit {
            Ok(())
        } else {
            // Conservative Retry-After: seconds remaining in the
            // current window, rounded up. Minimum 1 s so clients
            // that retry immediately still back off a frame.
            let remaining = window - (now - entry.window_start);
            let secs = remaining.num_seconds().max(1) as u64;
            Err(secs)
        }
    }
}

/// Configuration for a rate-limit middleware instance. Each
/// state-mutating endpoint that wants its own bucket calls
/// `rate_limit_layer(config)` at the router-build site and
/// attaches the returned layer to the route. Cheap: the config
/// is `Copy` (all three fields are primitive types).
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Short static label identifying the bucket class (e.g.
    /// `"acme_provision"`). Per-key flood on one bucket does not
    /// consume another bucket's budget.
    pub bucket: &'static str,
    /// Max requests per window per key (typically client IP).
    pub limit: u32,
    /// Window size in seconds.
    pub window_seconds: u64,
}

/// Middleware handler that enforces a per-endpoint rate limit.
/// Designed to be wired via `axum::middleware::from_fn_with_state`
/// with a [`RateLimitConfig`] as state, behind
/// [`RateLimiter`] installed as an `Extension`.
///
/// Keys buckets by the client IP (extracted from
/// `ConnectInfo<SocketAddr>`). Falls back to `"127.0.0.1"` when
/// the connection info is absent (unit-test / Tower `oneshot`
/// path) so tests that don't attach `ConnectInfo` still see
/// deterministic bucketing.
pub async fn rate_limit_middleware(
    Extension(limiter): Extension<RateLimiter>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    axum::extract::State(config): axum::extract::State<RateLimitConfig>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let client_ip = connect_info
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    match limiter
        .check_bucket(
            config.bucket,
            &client_ip,
            config.limit,
            config.window_seconds,
        )
        .await
    {
        Ok(()) => Ok(next.run(request).await),
        Err(retry_after) => Err(ApiError::RateLimited(retry_after)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn login_allows_up_to_max_attempts() {
        let limiter = RateLimiter::new();
        for _ in 0..LOGIN_MAX {
            assert!(limiter.check("key1").await);
        }
    }

    #[tokio::test]
    async fn login_blocks_after_max_attempts() {
        let limiter = RateLimiter::new();
        for _ in 0..LOGIN_MAX {
            limiter.check("key1").await;
        }
        assert!(!limiter.check("key1").await);
    }

    #[tokio::test]
    async fn login_independent_keys() {
        let limiter = RateLimiter::new();
        for _ in 0..LOGIN_MAX {
            limiter.check("key1").await;
        }
        assert!(limiter.check("key2").await);
    }

    #[tokio::test]
    async fn login_window_resets_after_expiry() {
        let limiter = RateLimiter::new();
        for _ in 0..=LOGIN_MAX {
            limiter.check("key1").await;
        }
        assert!(!limiter.check("key1").await);

        {
            let mut buckets = limiter.buckets.lock().await;
            let bucket = buckets
                .get_mut("login:key1")
                .expect("test setup: bucket inserted just above");
            bucket.window_start = Utc::now() - Duration::seconds(LOGIN_WINDOW_SECONDS + 1);
        }

        assert!(limiter.check("key1").await);
    }

    #[tokio::test]
    async fn named_bucket_allows_up_to_limit() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check_bucket("acme", "1.2.3.4", 3, 60).await.is_ok());
        }
    }

    #[tokio::test]
    async fn named_bucket_denies_with_retry_after() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            let _ = limiter.check_bucket("acme", "1.2.3.4", 3, 60).await;
        }
        let result = limiter.check_bucket("acme", "1.2.3.4", 3, 60).await;
        assert!(result.is_err());
        let retry = result.expect_err("test just asserted Err");
        assert!(
            (1..=60).contains(&retry),
            "retry_after {retry} out of [1, 60]"
        );
    }

    #[tokio::test]
    async fn named_buckets_are_isolated_from_login() {
        // Exhausting the login bucket must NOT affect the settings bucket.
        let limiter = RateLimiter::new();
        for _ in 0..LOGIN_MAX {
            limiter.check("192.0.2.1").await;
        }
        assert!(!limiter.check("192.0.2.1").await);
        assert!(limiter
            .check_bucket("settings", "192.0.2.1", 10, 60)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn named_buckets_are_isolated_from_each_other() {
        let limiter = RateLimiter::new();
        for _ in 0..3 {
            let _ = limiter.check_bucket("acme", "192.0.2.1", 3, 60).await;
        }
        assert!(limiter
            .check_bucket("acme", "192.0.2.1", 3, 60)
            .await
            .is_err());
        // Different bucket, same IP — fresh budget.
        assert!(limiter
            .check_bucket("config_import", "192.0.2.1", 3, 60)
            .await
            .is_ok());
    }

    #[test]
    fn default_impl() {
        let limiter = RateLimiter::default();
        assert!(limiter.buckets.try_lock().is_ok());
    }
}
