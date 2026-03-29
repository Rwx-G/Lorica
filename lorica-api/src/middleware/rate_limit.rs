use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::Mutex;

const MAX_ATTEMPTS: u32 = 5;
const WINDOW_SECONDS: i64 = 60;

#[derive(Debug, Clone)]
struct RateBucket {
    attempts: u32,
    window_start: DateTime<Utc>,
}

/// Simple in-memory rate limiter keyed by IP address (or a fixed key for localhost).
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
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a request from the given key is allowed. Returns true if allowed.
    pub async fn check(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Utc::now();

        let bucket = buckets.entry(key.to_string()).or_insert(RateBucket {
            attempts: 0,
            window_start: now,
        });

        if now - bucket.window_start > Duration::seconds(WINDOW_SECONDS) {
            bucket.attempts = 0;
            bucket.window_start = now;
        }

        bucket.attempts += 1;
        bucket.attempts <= MAX_ATTEMPTS
    }
}
