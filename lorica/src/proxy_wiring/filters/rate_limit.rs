// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Rate-limit `check_<name>` helpers. Two distinct paths coexist :
//!
//! - The newer `RateLimit` struct : token-bucket per-IP / per-route
//!   with explicit refill rate + burst, evaluated by
//!   `check_token_bucket_rate_limit`.
//! - The legacy `rate_limit_rps` field : exponential-decay rate via
//!   `self.rate_limiter`, with adaptive flood-defense halving and
//!   auto-ban escalation, evaluated by `check_legacy_rate_limit`.
//!
//! Both run after the IP-based gates so abusive clients are throttled
//! before any WAF / mTLS / forward-auth work happens.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tracing::warn;

use super::super::context::RequestCtx;
use super::super::error_pages::Decision;
use super::super::routing::RouteEntry;
use super::super::LoricaProxy;

impl LoricaProxy {
    /// Per-route token-bucket rate limit (the new `RateLimit` struct
    /// path - distinct from the legacy `rate_limit_rps` engine). Runs
    /// after ban / blocklist + redirects so abusive clients get
    /// rejected before WAF / mTLS / forward-auth. Whitelisted IPs
    /// bypass.
    pub(crate) fn check_token_bucket_rate_limit(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        is_whitelisted: bool,
    ) -> Option<Decision> {
        let rl = entry.route.rate_limit.as_ref()?;
        if is_whitelisted {
            return None;
        }
        let scope_key = match rl.scope {
            lorica_config::models::RateLimitScope::PerIp => {
                ctx.client_ip.as_deref().unwrap_or("unknown").to_string()
            }
            lorica_config::models::RateLimitScope::PerRoute => "__route__".to_string(),
        };
        let key = format!("{}|{}", entry.route.id, scope_key);
        let admitted =
            self.rate_limit_buckets
                .try_consume(&key, rl, 1, lorica_shmem::now_ns());
        if admitted {
            return None;
        }
        ctx.block_reason = Some("rate limited".to_string());
        // Retry-After in seconds. For any configured refill rate >= 1
        // tok/s, 1 second is the right advice (one token refills in
        // <= 1 s). A zero refill means a one-shot bucket that never
        // refills - advise a generous 60 s backoff instead of a tight
        // loop.
        let retry_after: u64 = if rl.refill_per_sec >= 1 { 1 } else { 60 };
        Some(
            Decision::reject(429, "Rate limit exceeded")
                .with_html(entry.route.error_page_html.clone())
                .with_header("Retry-After", retry_after.to_string()),
        )
    }

    /// Legacy per-route rate limit (the `rate_limit_rps` field, distinct
    /// from the newer `RateLimit` struct token-bucket path handled by
    /// `check_token_bucket_rate_limit`). Tracks per-(route, client-IP)
    /// rate via `self.rate_limiter`, applies the global flood-defense
    /// halving when global RPS exceeds `flood_threshold_rps`, and on
    /// throttle :
    ///
    /// - Bumps `self.rate_violations` for the IP and inserts into
    ///   `self.ban_list` when the count crosses `auto_ban_threshold`
    ///   (auto-ban escalation).
    /// - Dispatches an `IpBanned` notification via the alert sender.
    /// - Returns `Decision::reject(429, ...)` with `Retry-After: 1`
    ///   and `X-RateLimit-Reset` headers.
    ///
    /// Whitelisted IPs and routes without `rate_limit_rps` set fall
    /// through. Always sets `ctx.rate_limit_info` for the response
    /// header injection downstream, even when not throttled.
    pub(crate) fn check_legacy_rate_limit(
        &self,
        ctx: &mut RequestCtx,
        entry: &Arc<RouteEntry>,
        client_ip: Option<&str>,
        is_whitelisted: bool,
    ) -> Option<Decision> {
        if is_whitelisted {
            return None;
        }
        let rps = entry.route.rate_limit_rps?;
        let ip = client_ip?;
        let key = format!("{}:{}", entry.route.id, ip);
        self.rate_limiter.observe(&key, 1);
        let current_rate = self.rate_limiter.rate(&key);
        let mut effective_limit = match entry.route.rate_limit_burst {
            Some(burst) => (rps + burst) as f64,
            None => rps as f64,
        };

        // Adaptive flood defense : when global RPS exceeds the
        // configured threshold, halve per-IP rate limits.
        let threshold = self.config.load().flood_threshold_rps;
        if threshold > 0 {
            let global_rps = self.global_rate.rate(&"global");
            if global_rps > threshold as f64 {
                effective_limit *= 0.5;
            }
        }
        // Store rate info for response headers (even if not throttled).
        ctx.rate_limit_info = Some((rps, current_rate));

        if current_rate <= effective_limit {
            return None;
        }
        warn!(
            route_id = %entry.route.id,
            client_ip = %ip,
            current_rate = %current_rate,
            limit_rps = %rps,
            "request rate-limited (429)"
        );

        // Track rate-limit violations for auto-ban.
        if let Some(ban_threshold) = entry.route.auto_ban_threshold {
            let violation_key = format!("violation:{}", ip);
            self.rate_violations.observe(&violation_key, 1);
            let violations = self.rate_violations.rate(&violation_key);
            if violations > ban_threshold as f64 {
                let ban_duration = entry.route.auto_ban_duration_s;
                self.ban_list.insert(
                    ip.to_string(),
                    (Instant::now(), ban_duration as u64),
                );
                warn!(
                    ip = %ip,
                    violations = %violations,
                    ban_duration_s = %ban_duration,
                    "IP auto-banned for rate limit abuse"
                );
                if let Some(ref sender) = self.alert_sender {
                    sender.send(
                        lorica_notify::AlertEvent::new(
                            lorica_notify::events::AlertType::IpBanned,
                            format!("IP {} auto-banned for rate limit abuse", ip),
                        )
                        .with_detail("ip", ip.to_string())
                        .with_detail("violations", violations.to_string())
                        .with_detail("ban_duration_s", ban_duration.to_string()),
                    );
                }
            }
        }

        let reset_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 1;
        ctx.block_reason = Some("rate limited".to_string());
        Some(
            Decision::reject(429, "Rate limit exceeded")
                .with_html(entry.route.error_page_html.clone())
                .with_header("Retry-After", "1".to_string())
                .with_header("X-RateLimit-Reset", reset_ts.to_string()),
        )
    }
}
