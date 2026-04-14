// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Forward-auth sub-request engine + per-process verdict cache
//! (audit M-8 step 3).
//!
//! Moved verbatim from `proxy_wiring.rs`; no logic change. The module
//! owns:
//!   - the shared reqwest client (`FORWARD_AUTH_CLIENT`) with its
//!     connect-timeout + pool settings
//!   - the per-process Allow-only verdict cache
//!     (`FORWARD_AUTH_VERDICT_CACHE` + `FORWARD_AUTH_VERDICT_ORDER`)
//!     with its bounded-FIFO eviction policy
//!   - `run_forward_auth` / `run_forward_auth_keyed` (the hot path)
//!   - `build_forward_auth_headers`
//!   - `ForwardAuthOutcome` (pub(crate) outcome enum)

use std::time::Duration;

use once_cell::sync::Lazy;

use super::VerdictCacheEngine;

static FORWARD_AUTH_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(32)
        // Default connect timeout; per-request total timeout is set on each call.
        .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("build forward-auth reqwest client")
});

/// Per-route verdict cache for forward-auth. ONLY caches `Allow`
/// outcomes keyed on the downstream session cookie. `Deny` and
/// `FailClosed` are never cached - re-evaluating them is cheap and
/// lets session revocation take effect immediately.
///
/// The cache is in-process (per worker). A ban-list-style cross-
/// worker cache would be a significant complexity increase for
/// bounded upside: auth services already cache session lookups
/// internally, so we're only saving the sub-request round-trip for
/// requests that the *same* worker sees in succession.
///
/// Opt-in via `ForwardAuthConfig.verdict_cache_ttl_ms > 0`, capped at
/// 60s by the API validator. Default is 0 (off) - strict zero-trust.
///
/// Eviction: bounded FIFO via a sibling VecDeque that records
/// insertion order. On cap overflow we pop_front the oldest key and
/// remove it from the map. This keeps insert cost O(1) even under a
/// cookie-flood attack where an attacker spins up new session IDs
/// faster than legitimate users - without the FIFO, `iter().take()`-
/// style eviction would scan the DashMap per insert (O(n)).
static FORWARD_AUTH_VERDICT_CACHE: Lazy<dashmap::DashMap<String, CachedVerdict>> =
    Lazy::new(|| dashmap::DashMap::with_capacity(4096));

/// Insertion-order queue for O(1) FIFO eviction. The queue tracks
/// the keys currently in `FORWARD_AUTH_VERDICT_CACHE`; when a key is
/// overwritten we still record a fresh entry (the older one becomes
/// a no-op pop later). Periodic cleanup isn't necessary because the
/// queue is bounded at the same cap as the map.
static FORWARD_AUTH_VERDICT_ORDER: Lazy<parking_lot::Mutex<std::collections::VecDeque<String>>> =
    Lazy::new(|| parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(16_384)));

#[derive(Clone)]
struct CachedVerdict {
    /// The injected headers that should be added to the upstream
    /// request. Matches `ForwardAuthOutcome::Allow.response_headers`.
    response_headers: Vec<(String, String)>,
    /// Monotonic-time expiry; entry is treated as miss when
    /// `Instant::now() >= expires_at`.
    expires_at: std::time::Instant,
}

/// Hard cap on cache size. 16_384 distinct sessions is well above any
/// single-node workload we expect in practice; if you need higher,
/// scale horizontally rather than grow one cache.
const VERDICT_CACHE_MAX_ENTRIES: usize = 16_384;

/// Test-only helper that resets the verdict cache and its FIFO queue
/// together so tests aren't affected by leftover state from a prior
/// test that used the cache.
#[cfg(test)]
pub(crate) fn verdict_cache_reset_for_test() {
    FORWARD_AUTH_VERDICT_CACHE.clear();
    FORWARD_AUTH_VERDICT_ORDER.lock().clear();
}

/// Insert a freshly computed verdict into the cache, enforcing the
/// bounded-FIFO eviction policy. Returns nothing; the caller does
/// not need to know whether an older entry was displaced.
fn verdict_cache_insert(key: String, value: CachedVerdict) {
    let mut order = FORWARD_AUTH_VERDICT_ORDER.lock();
    // If we're at or over the cap, pop the oldest key until we're
    // strictly under. In normal operation this runs at most once per
    // insert. Under a cookie-flood it runs exactly once.
    while order.len() >= VERDICT_CACHE_MAX_ENTRIES {
        if let Some(old) = order.pop_front() {
            FORWARD_AUTH_VERDICT_CACHE.remove(&old);
        } else {
            break;
        }
    }
    order.push_back(key.clone());
    drop(order);
    FORWARD_AUTH_VERDICT_CACHE.insert(key, value);
}

/// Build the verdict-cache lookup key.
///
/// The key is the literal concatenation `"{route_id}\0{cookie}"`
/// (with a NUL separator so no legitimate route id or cookie value
/// can fake the boundary). We deliberately avoid a truncated hash
/// here: a 64-bit hash has a 2^32 birthday collision cost which is
/// feasible on a busy multi-tenant deployment, and a collision
/// would mean user B receives the injected `response_headers` from
/// user A's cached Allow verdict. DashMap's internal sharding uses
/// its own hash for bucket selection, but lookup still performs
/// full `String` equality - so two different raw keys can never
/// match the same entry.
///
/// Cost: keys are roughly `len(route_id) + 1 + len(cookie)` bytes;
/// for a 16384-entry cap that caps at a few MiB of cookie text in
/// the cache - trivial on any host that can run a reverse proxy.
/// The same memory would be present in `response_headers` stored in
/// the value anyway, since those typically include user identity
/// fields like `Remote-User`.
pub(crate) fn verdict_cache_key(
    route_id: &str,
    req: &lorica_http::RequestHeader,
) -> Option<String> {
    // We key on Cookie because Authelia / Authentik / Keycloak all
    // use session cookies for identification. If the request has no
    // Cookie header we refuse to cache - without a session identity
    // we could collide unrelated users and leak one user's Allow
    // verdict to another.
    let cookie = req.headers.get("cookie").and_then(|v| v.to_str().ok())?;
    if cookie.is_empty() {
        return None;
    }
    let mut key = String::with_capacity(route_id.len() + 1 + cookie.len());
    key.push_str(route_id);
    key.push('\0');
    key.push_str(cookie);
    Some(key)
}

#[derive(Debug)]
pub(crate) enum ForwardAuthOutcome {
    /// Request is authorised. `response_headers` lists headers harvested
    /// from the auth response that the caller should inject into the
    /// upstream request (owner-configured whitelist).
    Allow {
        response_headers: Vec<(String, String)>,
    },
    /// The auth service rejected the request. Status + headers + body
    /// are forwarded verbatim to the downstream client.
    Deny {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// The auth service is unreachable, timed out, or returned an
    /// unexpected status. Fail closed with a 503 so the client never
    /// accidentally proxies past a broken auth service.
    FailClosed {
        /// Short human-readable reason for logs / block_reason.
        reason: String,
    },
}

/// Build the fixed header set that Lorica forwards to the auth service.
/// Matches the Traefik / Authelia convention (`X-Forwarded-*`) plus any
/// identifying headers the client originally sent (Cookie, Authorization,
/// User-Agent) so stateful auth can see the session.
///
/// Extracted as a pure function so the header-wiring contract is
/// unit-testable without a live auth backend.
pub(crate) fn build_forward_auth_headers(
    req: &lorica_http::RequestHeader,
    client_ip: Option<&str>,
    scheme: &str,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(8);

    // X-Forwarded-Method: original HTTP method so auth can distinguish a
    // GET from a POST to the same path (Authelia's access control lists
    // can match on method).
    out.push(("X-Forwarded-Method".into(), req.method.as_str().to_string()));

    // X-Forwarded-Proto: http vs https so auth can enforce TLS-only
    // policies and generate correct login URLs.
    out.push(("X-Forwarded-Proto".into(), scheme.to_string()));

    // X-Forwarded-Host: the Host the client was trying to reach. Auth
    // redirects the user back here after login.
    if let Some(host) = req.headers.get("host").and_then(|v| v.to_str().ok()) {
        out.push(("X-Forwarded-Host".into(), host.to_string()));
    }

    // X-Forwarded-Uri: the full original path+query so auth can enforce
    // per-resource policies.
    let uri = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    out.push(("X-Forwarded-Uri".into(), uri.to_string()));

    // X-Forwarded-For: true client IP (already resolved upstream - may
    // include XFF chain if trusted proxies are configured).
    if let Some(ip) = client_ip {
        out.push(("X-Forwarded-For".into(), ip.to_string()));
    }

    // Cookie: session cookies are how Authelia/Authentik identify users.
    // Without this, every request looks unauthenticated.
    if let Some(cookie) = req.headers.get("cookie").and_then(|v| v.to_str().ok()) {
        out.push(("Cookie".into(), cookie.to_string()));
    }

    // Authorization: Bearer tokens (OAuth, API keys). Required for
    // header-based auth flows.
    if let Some(auth) = req
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
    {
        out.push(("Authorization".into(), auth.to_string()));
    }

    // User-Agent: some auth services log or rate-limit by UA.
    if let Some(ua) = req.headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        out.push(("User-Agent".into(), ua.to_string()));
    }

    out
}

/// Execute the forward-auth sub-request and classify the verdict. The
/// network I/O is contained here so the surrounding `request_filter`
/// stays a straight pipeline - the caller only has to match on
/// `ForwardAuthOutcome`.
///
/// Thin wrapper over `run_forward_auth_keyed` with cache disabled.
/// Production callers invoke the keyed variant directly; this one exists
/// for tests that predate the verdict cache.
#[cfg(test)]
pub(crate) async fn run_forward_auth(
    cfg: &lorica_config::models::ForwardAuthConfig,
    req: &lorica_http::RequestHeader,
    client_ip: Option<&str>,
    scheme: &str,
) -> ForwardAuthOutcome {
    run_forward_auth_keyed(cfg, req, client_ip, scheme, "", &VerdictCacheEngine::Local).await
}

/// Internal variant that takes a `route_id` so the verdict cache can
/// partition entries per route, plus a [`VerdictCacheEngine`] so workers
/// can delegate the cache to the supervisor via the pipelined RPC. The
/// public helper keeps the old signature for cases where caching is
/// definitely off (unit tests, ad-hoc validation) and simply passes an
/// empty route id which `verdict_cache_key` treats as "no cache".
pub(crate) async fn run_forward_auth_keyed(
    cfg: &lorica_config::models::ForwardAuthConfig,
    req: &lorica_http::RequestHeader,
    client_ip: Option<&str>,
    scheme: &str,
    route_id: &str,
    cache_engine: &VerdictCacheEngine,
) -> ForwardAuthOutcome {
    // Verdict cache lookup. Only applies when:
    //   - cache is enabled for this route (ttl > 0),
    //   - we have a route_id to partition on, and
    //   - the request carries a Cookie (session identity).
    // Any of those missing = skip cache path entirely.
    let cache_enabled = cfg.verdict_cache_ttl_ms > 0 && !route_id.is_empty();
    let cache_key = if cache_enabled {
        verdict_cache_key(route_id, req)
    } else {
        None
    };
    let cookie_value = if cache_enabled {
        req.headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    };

    if cache_enabled {
        match cache_engine {
            VerdictCacheEngine::Local => {
                if let Some(ref key) = cache_key {
                    // Clone out under the ref, then drop it before any
                    // potential mutation so we can't self-deadlock or
                    // hold the shard lock across the miss path below.
                    let snapshot = FORWARD_AUTH_VERDICT_CACHE
                        .get(key)
                        .map(|e| (e.expires_at, e.response_headers.clone()));
                    if let Some((expires_at, response_headers)) = snapshot {
                        if std::time::Instant::now() < expires_at {
                            lorica_api::metrics::inc_forward_auth_cache(route_id, "hit");
                            return ForwardAuthOutcome::Allow { response_headers };
                        }
                        // Expired: evict atomically only if the entry at
                        // `key` is still the one we just observed. A
                        // concurrent fresh `insert` between snapshot and
                        // remove is preserved - audit M-3 TOCTOU fix.
                        FORWARD_AUTH_VERDICT_CACHE
                            .remove_if(key, |_, e| e.expires_at == expires_at);
                    }
                    lorica_api::metrics::inc_forward_auth_cache(route_id, "miss");
                }
            }
            VerdictCacheEngine::Rpc { endpoint, timeout } => {
                if let Some(ref cookie) = cookie_value {
                    let payload = lorica_command::command::Payload::VerdictLookup(
                        lorica_command::VerdictLookup {
                            route_id: route_id.to_string(),
                            cookie: cookie.clone(),
                        },
                    );
                    match endpoint
                        .request_rpc(
                            lorica_command::CommandType::VerdictLookup,
                            payload,
                            *timeout,
                        )
                        .await
                    {
                        Ok(resp) => {
                            if let Some(lorica_command::response::Payload::VerdictResult(v)) =
                                resp.payload
                            {
                                if v.found
                                    && lorica_command::Verdict::from_i32(v.verdict)
                                        == lorica_command::Verdict::Allow
                                {
                                    lorica_api::metrics::inc_forward_auth_cache(route_id, "hit");
                                    return ForwardAuthOutcome::Allow {
                                        response_headers: v
                                            .response_headers
                                            .into_iter()
                                            .map(|h| (h.name, h.value))
                                            .collect(),
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            // RPC failure degrades gracefully: we
                            // fall through to the upstream auth call
                            // rather than denying, matching the
                            // "transport fail open" semantics the
                            // local cache uses when evicting a stale
                            // entry.
                            tracing::debug!(
                                error = %e,
                                route_id,
                                "verdict cache RPC lookup failed; falling back to upstream auth call"
                            );
                        }
                    }
                    lorica_api::metrics::inc_forward_auth_cache(route_id, "miss");
                }
            }
        }
    }

    let headers_out = build_forward_auth_headers(req, client_ip, scheme);

    let mut builder = FORWARD_AUTH_CLIENT
        .get(&cfg.address)
        .timeout(Duration::from_millis(cfg.timeout_ms as u64));
    for (name, value) in &headers_out {
        builder = builder.header(name, value);
    }

    let resp = match builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return ForwardAuthOutcome::FailClosed {
                reason: format!("forward-auth unreachable: {e}"),
            };
        }
    };

    let status = resp.status().as_u16();

    // 2xx -> allow. Harvest configured response_headers verbatim so
    // Authelia's Remote-User et al. propagate to the upstream.
    if resp.status().is_success() {
        // Honor `Cache-Control: no-store` / `no-cache` from the auth
        // service: if Authelia explicitly asks us not to cache this
        // verdict, we don't, even when the route opted in.
        let cacheable = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|s| {
                let lower = s.to_ascii_lowercase();
                !lower.contains("no-store") && !lower.contains("no-cache")
            })
            .unwrap_or(true);
        let mut inject = Vec::new();
        let resp_headers = resp.headers().clone();
        for name in &cfg.response_headers {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(v) = resp_headers.get(trimmed) {
                if let Ok(s) = v.to_str() {
                    inject.push((trimmed.to_string(), s.to_string()));
                }
            }
        }
        if cache_enabled && cacheable {
            match cache_engine {
                VerdictCacheEngine::Local => {
                    if let Some(key) = cache_key {
                        let expires_at = std::time::Instant::now()
                            + Duration::from_millis(cfg.verdict_cache_ttl_ms as u64);
                        verdict_cache_insert(
                            key,
                            CachedVerdict {
                                response_headers: inject.clone(),
                                expires_at,
                            },
                        );
                    }
                }
                VerdictCacheEngine::Rpc { endpoint, timeout } => {
                    if let Some(cookie) = cookie_value.clone() {
                        let headers = inject
                            .iter()
                            .map(|(n, v)| lorica_command::ForwardAuthHeader {
                                name: n.clone(),
                                value: v.clone(),
                            })
                            .collect();
                        let payload = lorica_command::command::Payload::VerdictPush(
                            lorica_command::VerdictPush {
                                route_id: route_id.to_string(),
                                cookie,
                                verdict: lorica_command::Verdict::Allow as i32,
                                ttl_ms: cfg.verdict_cache_ttl_ms as u64,
                                response_headers: headers,
                            },
                        );
                        // Fire-and-forget: a failed push just means the
                        // supervisor misses one entry; we still return
                        // Allow to the caller. No await on metrics
                        // either - keep the hot path lean.
                        let endpoint = endpoint.clone();
                        let timeout = *timeout;
                        tokio::spawn(async move {
                            if let Err(e) = endpoint
                                .request_rpc(
                                    lorica_command::CommandType::VerdictPush,
                                    payload,
                                    timeout,
                                )
                                .await
                            {
                                tracing::debug!(
                                    error = %e,
                                    "verdict cache RPC push failed; supervisor cache may miss this entry"
                                );
                            }
                        });
                    }
                }
            }
        }
        return ForwardAuthOutcome::Allow {
            response_headers: inject,
        };
    }

    // 401 / 403 / 3xx (login redirect) -> forward verdict verbatim.
    // Authelia returns 302 + Location for unauthenticated browser
    // traffic, and we must propagate that response body+headers so the
    // client is sent to the login page.
    if matches!(status, 300..=399) || matches!(status, 401 | 403) {
        let mut fwd_headers: Vec<(String, String)> = Vec::new();
        for (name, value) in resp.headers().iter() {
            // Skip hop-by-hop headers and Content-Length (re-computed
            // from body below).
            let n = name.as_str();
            if matches!(
                n.to_ascii_lowercase().as_str(),
                "content-length"
                    | "transfer-encoding"
                    | "connection"
                    | "keep-alive"
                    | "proxy-connection"
                    | "te"
                    | "trailer"
                    | "upgrade"
            ) {
                continue;
            }
            if let Ok(v) = value.to_str() {
                fwd_headers.push((n.to_string(), v.to_string()));
            }
        }
        let body = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
        return ForwardAuthOutcome::Deny {
            status,
            headers: fwd_headers,
            body,
        };
    }

    // Anything else (5xx, 400, 418, ...) is an anomaly. Treat as deny-
    // closed so a misbehaving auth service can't silently let traffic
    // through.
    ForwardAuthOutcome::FailClosed {
        reason: format!("forward-auth unexpected status {status}"),
    }
}
