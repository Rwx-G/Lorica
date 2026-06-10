// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `request_filter` stage methods and their helpers (backlog #7
//! step 3).
//!
//! The 22 sequential stage methods extracted in audit H-8, plus the
//! shared terminal-response helper (`write_error_response`) and the
//! WAF event persistence helpers they depend on.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use lorica_config::models::WafMode;
use lorica_error::Result;
use lorica_http::ResponseHeader;
use lorica_proxy::Session;
use tracing::{debug, warn};

use super::{
    bot_handlers, build_mirror_forward_headers, canary_bucket, downstream_ssl_digest,
    evaluate_mtls, extract_host, mirror_sample_hit, render_error_body, request_has_body,
    run_forward_auth_keyed, spawn_mirrors, ForwardAuthOutcome, LoricaProxy, MirrorBodyState,
    MirrorPending, ProxyConfig, RequestCtx, RouteEntry, VerdictCacheEngine, WAF_BODY_SCAN_MAX,
};

/// Compact a client IP into a `u64` key for the shmem hashtables.
///
/// `lorica_shmem` pre-hashes this with its secret siphash key before
/// slotting, so the only requirement here is a deterministic, low-cost
/// serialisation of the IP into 64 bits. IPv4 becomes its 32-bit value;
/// IPv6 folds the two 64-bit halves via XOR; an unparseable string
/// falls back to a deterministic FNV-1a rollup so malformed inputs
/// still route consistently (they should not reach this path in
/// practice).
pub fn ip_to_shmem_key(ip: &str) -> u64 {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => u32::from(v4) as u64,
        Ok(IpAddr::V6(v6)) => {
            let o = v6.octets();
            let high = u64::from_be_bytes([o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]]);
            let low = u64::from_be_bytes([o[8], o[9], o[10], o[11], o[12], o[13], o[14], o[15]]);
            high ^ low
        }
        Err(_) => {
            let mut h: u64 = 0xcbf29ce484222325;
            for b in ip.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            h
        }
    }
}

/// Check whether an IP address matches a pattern (exact match or CIDR range).
pub(crate) fn ip_matches(ip: &str, pattern: &str) -> bool {
    if pattern.contains('/') {
        // CIDR - parse and use proper network containment check
        let net: std::net::IpAddr = match ip.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let cidr: ipnet::IpNet = match pattern.parse() {
            Ok(n) => n,
            Err(_) => return false,
        };
        cidr.contains(&net)
    } else {
        ip == pattern
    }
}

/// Build the `Location` header value for a `redirect_to` rule.
///
/// When `literal` is true (a path rule explicitly set `redirect_to`),
/// the target is emitted verbatim: the operator picked the exact
/// destination for this matched path, so appending the request path
/// would only produce a broken URL (the Plex `/tesla` case).
///
/// When `literal` is false (route-level `redirect_to`), the request
/// path and query are appended to the target with its trailing `/`
/// trimmed. This is the documented migration-friendly behavior:
/// pointing `old.example.com` at `https://new.example.com/` preserves
/// every subpath.
pub(crate) fn build_redirect_location(
    target: &str,
    req_path: &str,
    req_query: Option<&str>,
    literal: bool,
) -> String {
    if literal {
        return target.to_string();
    }
    let query_suffix = req_query.map(|q| format!("?{q}")).unwrap_or_default();
    let base = target.trim_end_matches('/');
    format!("{base}{req_path}{query_suffix}")
}

impl LoricaProxy {
    /// Persist a `WafEvent` to the SQLite-backed `LogStore`.
    ///
    /// No-op when no log writer is configured. The event is handed to
    /// the background log writer queue (backlog #24): the hot path
    /// never touches SQLite. Persistence failures surface from the
    /// writer thread as a `warn!` per batch plus
    /// `lorica_waf_event_persist_failed_total` (keeping the v1.5.1
    /// audit L-6 guarantee that the trail never breaks silently);
    /// queue overflow bumps `lorica_log_write_dropped_total{kind="waf"}`.
    /// The proxy keeps serving regardless ; the in-memory ring buffer +
    /// Prometheus category counters still surface the events, only
    /// the persistent forensics trail is shed.
    pub(super) fn persist_waf_event(&self, ev: &lorica_waf::WafEvent) {
        if let Some(ref writer) = self.log_writer {
            writer.enqueue_waf(ev.clone());
        }
    }

    /// Record that a request body crossed `WAF_BODY_SCAN_MAX` while
    /// the route's WAF was in Detection mode (v1.5.1 audit H-2).
    ///
    /// Idempotent per request via `ctx.waf_body_truncated` so that a
    /// streaming chunked body that produces N chunks past the cap
    /// emits exactly one `WafEvent` (rather than spamming the
    /// dashboard with one event per chunk). Mirrors ModSecurity's
    /// `ProcessPartial` action and AWS WAF's `Continue`
    /// oversize-handling : the request proceeds with whatever the
    /// scanner already buffered (the first `WAF_BODY_SCAN_MAX`
    /// bytes), but the operator gets a first-class signal in the
    /// WAF event log so they can decide to flip the route to
    /// Blocking or raise the cap.
    pub(super) fn record_waf_body_truncated(
        &self,
        ctx: &mut RequestCtx,
        route_id: &str,
        route_hostname: &str,
        observed_size: u64,
    ) {
        if ctx.waf_body_truncated {
            return;
        }
        ctx.waf_body_truncated = true;

        warn!(
            received = observed_size,
            cap = WAF_BODY_SCAN_MAX,
            route_id = route_id,
            "request body exceeds WAF scan window (partial scan, detection mode)"
        );

        lorica_api::metrics::record_waf_event("protocol_violation", "detected");
        self.waf_counts
            .entry(("protocol_violation".to_string(), "detected".to_string()))
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        let ev = lorica_waf::WafEvent {
            rule_id: 0,
            description: format!(
                "request body ({observed_size} bytes) exceeded WAF scan window ({WAF_BODY_SCAN_MAX} bytes); partial scan only"
            ),
            category: lorica_waf::RuleCategory::ProtocolViolation,
            severity: 5,
            matched_field: "body_size".to_string(),
            matched_value: observed_size.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip: ctx.client_ip.as_deref().unwrap_or("-").to_string(),
            route_hostname: route_hostname.to_string(),
            action: "detected".to_string(),
        };
        self.persist_waf_event(&ev);
    }

    /// Write a terminal HTML error response and end the request (audit H-10
    /// dedup).
    ///
    /// Renders the branded error page via [`render_error_body`] (per-route
    /// `error_page_html` override when provided, default Lorica page
    /// otherwise), sets `Content-Type` / `Content-Length`, writes the
    /// response header and body, and returns `Ok(true)` so `request_filter`
    /// call sites can `return` the call directly to stop the proxy pipeline.
    /// Write failures propagate as `Err`, exactly like the inline blocks
    /// this helper replaced.
    ///
    /// The host header shown on the error page is always derived from the
    /// downstream request via `extract_host`, which is what every former
    /// inline block did.
    ///
    /// `extra_headers` are inserted BEFORE `Content-Type`, preserving the
    /// exact wire order of the rate-limit 429 sites (`Retry-After`,
    /// `X-RateLimit-Reset`) that the e2e suites pin. Pass `&[]` when no
    /// extra headers are needed.
    pub(super) async fn write_error_response(
        &self,
        session: &mut Session,
        status: u16,
        request_id: &str,
        error_page_html: Option<&str>,
        reason: &str,
        extra_headers: &[(&'static str, String)],
    ) -> Result<bool> {
        let host_header: String = extract_host(session.req_header()).to_string();
        let body: String =
            render_error_body(status, request_id, &host_header, error_page_html, reason);
        let mut header = lorica_http::ResponseHeader::build(status, None)?;
        for (name, value) in extra_headers {
            header.insert_header(*name, value.as_str())?;
        }
        header.insert_header("Content-Type", "text/html; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(body)), true)
            .await?;
        Ok(true)
    }
}

/// `request_filter` stage helpers (audit H-8).
///
/// Each method wraps exactly one sequential check block of the filter
/// pipeline, preserving the original code, ordering, and side effects.
/// Convention: `Ok(Some(handled))` means the request was fully handled
/// (a terminal response was written) and `request_filter` must return
/// `Ok(handled)` immediately; `Ok(None)` means fall through to the
/// next stage.
impl LoricaProxy {
    /// Stage: bot-protection cross-cutting endpoints (v1.4.0 Epic 3
    /// story 3.5). Triggers on the two Lorica-handled paths below the
    /// `/lorica/bot/` namespace: POST `/lorica/bot/solve` (verify a
    /// submitted PoW / captcha, issue verdict cookie) and GET
    /// `/lorica/bot/captcha/{nonce}` (serve the captcha PNG). Both are
    /// route-independent: the stashed entry carries the route_id the
    /// cookie gets bound to, and the captcha nonce is self-scoped.
    /// Client IP extraction + cookie-bound scope validation happen
    /// inside the handlers. Terminal: handler-defined status, or 503
    /// when the client address is unavailable on the solve path.
    pub(super) async fn check_bot_endpoints(&self, session: &mut Session) -> Result<Option<bool>> {
        let path: String = session.req_header().uri.path().to_owned();
        if crate::bot::is_bot_solve_path(&path) {
            // Client IP must go through the SAME XFF unwrap that
            // the challenge-render path used; otherwise the
            // stashed entry's IP prefix (XFF-unwrapped) won't
            // match the current TCP client's prefix and the
            // handler rejects with 403 "client network changed".
            // Duplicates the xff_used logic from the client-IP
            // resolution stage, because that stage is skipped
            // entirely when we take this early return.
            let config = self.config.load();
            let tcp_ip = session
                .client_addr()
                .and_then(|addr| addr.as_inet())
                .map(|a| a.ip());
            let xff_header = session
                .req_header()
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok());
            let direct_is_trusted =
                tcp_ip.is_some_and(|ip| config.trusted_proxies.iter().any(|net| net.contains(&ip)));
            let client_ip = if direct_is_trusted {
                xff_header
                    .and_then(|xff| xff.split(',').next().unwrap_or(xff).trim().parse().ok())
                    .or(tcp_ip)
            } else {
                tcp_ip
            };
            let now_secs = chrono::Utc::now().timestamp();
            let secret = lorica_challenge::secret::handle();
            let secret_ref = secret.as_deref();
            if let Some(ip) = client_ip {
                return bot_handlers::handle_solve(
                    session,
                    &self.bot_engine,
                    secret_ref,
                    ip,
                    now_secs,
                )
                .await
                .map(Some);
            }
            // No client address is exotic but real (tests,
            // non-TCP transports). Fail closed so we never
            // issue a cookie to a request we cannot attribute.
            let msg = "client address unavailable";
            let mut header = ResponseHeader::build(503, None)?;
            header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
            header.insert_header("Content-Length", msg.len().to_string())?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(bytes::Bytes::from_static(msg.as_bytes())), true)
                .await?;
            return Ok(Some(true));
        }
        if let Some(nonce) = crate::bot::parse_bot_captcha_path(&path) {
            return bot_handlers::handle_captcha_image(session, &self.bot_engine, nonce)
                .await
                .map(Some);
        }
        Ok(None)
    }

    /// Stage: global connection limit. Triggers when
    /// `max_global_connections > 0` and the live connection count has
    /// reached it. Terminal: 503.
    pub(super) async fn check_global_connection_limit(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        config: &ProxyConfig,
    ) -> Result<Option<bool>> {
        if config.max_global_connections > 0 {
            let current = self.active_connections.load(Ordering::Relaxed);
            if current >= config.max_global_connections as u64 {
                ctx.block_reason = Some("global connection limit".to_string());
                // No route matched yet at this stage, so no per-route
                // override is consultable: always render the default page.
                return self
                    .write_error_response(
                        session,
                        503,
                        &ctx.request_id,
                        None,
                        "Global connection limit exceeded",
                        &[],
                    )
                    .await
                    .map(Some);
            }
        }
        Ok(None)
    }

    /// Stage: client IP resolution (never terminal). Derives the
    /// effective client IP - the direct TCP peer, or the leftmost
    /// X-Forwarded-For entry when the direct peer is a trusted proxy -
    /// stamps `ctx.client_ip`, `ctx.client_ip_addr`, `ctx.is_xff`,
    /// `ctx.xff_proxy_ip` and `ctx.source`, and returns the IP string
    /// every later check keys on.
    pub(super) fn resolve_client_ip(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
        config: &ProxyConfig,
    ) -> Option<String> {
        let client_ip = session
            .as_downstream()
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|addr| addr.ip().to_string());

        // Only trust X-Forwarded-For when the direct TCP client is a trusted proxy.
        // When trusted_proxies is empty, XFF is never used (secure default).
        let req = session.req_header();
        let has_xff = req.headers.get("x-forwarded-for").is_some();
        let direct_ip = client_ip.clone();

        let direct_is_trusted = direct_ip.as_ref().is_some_and(|ip| {
            if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                config.trusted_proxies.iter().any(|net| net.contains(&addr))
            } else {
                false
            }
        });

        let xff_used = direct_is_trusted && has_xff;
        let check_ip = if xff_used {
            // Trusted proxy: extract real client IP from XFF (leftmost entry)
            req.headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .map(|xff| xff.split(',').next().unwrap_or(xff).trim().to_string())
                .or(client_ip)
        } else {
            // Not trusted or no XFF: use direct TCP client IP
            client_ip
        };

        // Store client IP and source in context for access logging.
        // Parse the string form once; every later per-request
        // consumer (whitelist, blocklist, GeoIP, bot protection)
        // reuses `ctx.client_ip_addr` instead of re-parsing
        // (audit #41f).
        ctx.client_ip = check_ip.clone();
        ctx.client_ip_addr = check_ip
            .as_deref()
            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
        ctx.is_xff = xff_used && check_ip.is_some();
        ctx.xff_proxy_ip = if ctx.is_xff { direct_ip } else { None };
        ctx.source = req
            .headers
            .get("x-lorica-source")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        check_ip
    }

    /// Stage: WAF ban list + global IP blocklist (pre-route). Triggers
    /// when the client IP carries an unexpired auto-ban or matches the
    /// IP blocklist; the caller skips this stage entirely for
    /// whitelisted IPs. Terminal: 403 (both variants).
    pub(super) async fn check_ban_and_blocklist(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        ip: &str,
    ) -> Result<Option<bool>> {
        let banned = if let Some(entry) = self.ban_list.get(ip) {
            let (banned_at, duration_s) = entry.value();
            if banned_at.elapsed() >= Duration::from_secs(*duration_s) {
                drop(entry);
                // Ban expired - lazy cleanup
                self.ban_list.remove(ip);
                false
            } else {
                true
            }
        } else {
            false
        };
        if banned {
            ctx.block_reason = Some("IP banned".to_string());
            // Pre-route stage: no route override consultable.
            return self
                .write_error_response(session, 403, &ctx.request_id, None, "IP banned", &[])
                .await
                .map(Some);
        }

        let blocklisted = ctx
            .client_ip_addr
            .as_ref()
            .is_some_and(|addr| self.waf_engine.ip_blocklist().is_blocked(addr));
        if blocklisted {
            warn!(
                ip = %ip,
                "request blocked by IP blocklist"
            );
            ctx.waf_blocked = true;
            // Record as WAF event + Prometheus metric + persist
            let req = session.req_header();
            let path = req.uri.path();
            let host_val = extract_host(req);
            self.waf_engine.record_blocklist_event(ip, host_val, path);
            lorica_api::metrics::record_waf_event("ip_blocklist", "blocked");
            self.waf_counts
                .entry(("ip_blocklist".to_string(), "blocked".to_string()))
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::Relaxed);
            let ev = lorica_waf::WafEvent {
                rule_id: 0,
                description: format!("IP {ip} blocked by IP blocklist"),
                category: lorica_waf::RuleCategory::IpBlocklist,
                severity: 5,
                matched_field: "client_ip".to_string(),
                matched_value: ip.to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                client_ip: ip.to_string(),
                route_hostname: {
                    let h = extract_host(req);
                    if h.is_empty() {
                        "-"
                    } else {
                        h
                    }
                }
                .to_string(),
                action: "blocked".to_string(),
            };
            self.persist_waf_event(&ev);
            // Pre-route stage: no route override consultable.
            return self
                .write_error_response(session, 403, &ctx.request_id, None, "IP blocked", &[])
                .await
                .map(Some);
        }
        Ok(None)
    }

    /// Stage: WebSocket gate. Triggers when the route has
    /// `websocket_enabled = false` and the request carries an
    /// `Upgrade: websocket` header. Terminal: 403.
    pub(super) async fn check_websocket_gate(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        if !entry.route.websocket_enabled {
            if let Some(upgrade) = session.req_header().headers.get("upgrade") {
                if upgrade
                    .to_str()
                    .unwrap_or("")
                    .eq_ignore_ascii_case("websocket")
                {
                    ctx.block_reason = Some("WebSocket disabled".to_string());
                    return self
                        .write_error_response(
                            session,
                            403,
                            &ctx.request_id,
                            entry.route.error_page_html.as_deref(),
                            "WebSocket upgrades disabled on this route",
                            &[],
                        )
                        .await
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Stage: route-level redirects. Covers the force-HTTPS redirect
    /// (skipped for ACME challenge paths, which must stay on HTTP) and
    /// the hostname redirect (`redirect_hostname`). Terminal: 301.
    pub(super) async fn check_route_redirects(
        &self,
        session: &mut Session,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        let req = session.req_header();
        let host_raw = extract_host(req);
        let host = host_raw.split(':').next().unwrap_or(host_raw);
        let path = req.uri.path();

        // Force HTTPS redirect (skip for ACME challenges - must stay HTTP)
        if entry.route.force_https && !path.starts_with("/.well-known/acme-challenge/") {
            let is_tls = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            let scheme = if is_tls {
                "https"
            } else {
                req.headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("http")
            };
            if scheme != "https" {
                let redir_host = extract_host(req);
                let redir_path = req.uri.path();
                let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let location = format!("https://{redir_host}{redir_path}{redir_query}");
                let mut header = lorica_http::ResponseHeader::build(301, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(Some(true));
            }
        }

        // Hostname redirect
        if let Some(ref target) = entry.route.redirect_hostname {
            if host != target.as_str() {
                let redir_path = req.uri.path();
                let redir_query = req.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
                let scheme = req
                    .headers
                    .get("x-forwarded-proto")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("https");
                let location = format!("{scheme}://{target}{redir_path}{redir_query}");
                let mut header = lorica_http::ResponseHeader::build(301, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
                return Ok(Some(true));
            }
        }
        Ok(None)
    }

    /// Stage: structured per-route token-bucket rate limit. Runs after
    /// ban/blocklist and redirects so that an abusive client is
    /// rejected before we touch WAF / mtls / forward_auth. See design
    /// § 6 and `lorica_limits::token_bucket::AuthoritativeBucket`.
    /// Whitelisted IPs bypass the limiter (same policy as WAF ban
    /// checks - an operator who added an IP to the whitelist has made
    /// a deliberate trust decision). Terminal: 429 with `Retry-After`.
    pub(super) async fn check_structured_rate_limit(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
        is_whitelisted: bool,
    ) -> Result<Option<bool>> {
        if let Some(ref rl) = entry.route.rate_limit {
            if !is_whitelisted {
                let scope_key = match rl.scope {
                    lorica_config::models::RateLimitScope::PerIp => {
                        ctx.client_ip.as_deref().unwrap_or("unknown").to_string()
                    }
                    lorica_config::models::RateLimitScope::PerRoute => "__route__".to_string(),
                };
                let key = format!("{}|{}", entry.route.id, scope_key);
                let admitted = self
                    .rate_limit_buckets
                    .try_consume(&key, rl, 1, lorica_shmem::now_ns());
                if !admitted {
                    ctx.block_reason = Some("rate limited".to_string());
                    // Retry-After in seconds. For any configured refill
                    // rate >= 1 tok/s, 1 second is the right advice
                    // (one token refills in <= 1 s). A zero refill means
                    // a one-shot bucket that never refills - advise a
                    // generous 60 s backoff instead of a tight loop.
                    let retry_after: u64 = if rl.refill_per_sec >= 1 { 1 } else { 60 };
                    return self
                        .write_error_response(
                            session,
                            429,
                            &ctx.request_id,
                            entry.route.error_page_html.as_deref(),
                            "Rate limit exceeded",
                            &[("Retry-After", retry_after.to_string())],
                        )
                        .await
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Stage: mTLS client verification. Runs before forward_auth so a
    /// request that failed to present a valid client cert is rejected
    /// cheaply (no auth sub-request spawned). The listener has already
    /// validated the cert chain against the union CA bundle; this just
    /// checks presence and the per-route org allowlist. Terminal: 495
    /// (cert error) / 496 (cert required), the semi-standard Nginx
    /// codes that don't collide with our other rejection paths.
    pub(super) async fn check_mtls(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        if let Some(ref enforcer) = entry.mtls_enforcer {
            let verdict = evaluate_mtls(enforcer, downstream_ssl_digest(session).as_deref());
            if let Some(status) = verdict {
                ctx.block_reason = Some(format!("mtls rejected ({status})"));
                let message = match status {
                    496 => "SSL certificate required",
                    495 => "SSL certificate error",
                    _ => "Forbidden",
                };
                return self
                    .write_error_response(
                        session,
                        status,
                        &ctx.request_id,
                        entry.route.error_page_html.as_deref(),
                        message,
                        &[],
                    )
                    .await
                    .map(Some);
            }
        }
        Ok(None)
    }

    /// Stage: forward authentication. Gates the request on an external
    /// auth service (Authelia / Authentik / Keycloak / oauth2-proxy).
    /// Runs after route match but before header/canary/path rules so a
    /// denied request never leaks into the backend-selection phase.
    /// On Allow, stashes the harvested response headers in
    /// `ctx.forward_auth_inject`. Terminal: auth-service status (deny /
    /// redirect), or 503 when the auth service is unreachable
    /// (fail-closed).
    pub(super) async fn check_forward_auth(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        if let Some(ref fa_cfg) = entry.route.forward_auth {
            // Detect TLS from the downstream socket, not HTTP version:
            // h2c (HTTP/2 over plaintext) would otherwise be reported
            // as https to the auth service, which is misleading and
            // may trigger redirect loops.
            let is_tls = session
                .digest()
                .and_then(|d| d.ssl_digest.as_ref())
                .is_some();
            let scheme = if is_tls { "https" } else { "http" };
            let req = session.req_header();
            let outcome = run_forward_auth_keyed(
                fa_cfg,
                req,
                ctx.client_ip.as_deref(),
                scheme,
                &entry.route.id,
                &self.verdict_cache,
            )
            .await;
            match outcome {
                ForwardAuthOutcome::Allow { response_headers } => {
                    ctx.forward_auth_inject = response_headers;
                }
                ForwardAuthOutcome::Deny {
                    status,
                    headers,
                    body,
                } => {
                    ctx.block_reason = Some(format!("forward auth denied ({status})"));
                    let mut resp_header = ResponseHeader::build(status, None)?;
                    for (name, value) in &headers {
                        let _ = resp_header.insert_header(name.clone(), value);
                    }
                    let _ = resp_header.insert_header("Content-Length", body.len().to_string());
                    session
                        .write_response_header(Box::new(resp_header), false)
                        .await?;
                    session
                        .write_response_body(Some(bytes::Bytes::from(body)), true)
                        .await?;
                    return Ok(Some(true));
                }
                ForwardAuthOutcome::FailClosed { reason } => {
                    tracing::warn!(
                        route_id = %entry.route.id,
                        reason = %reason,
                        "forward auth fail-closed"
                    );
                    ctx.block_reason = Some(format!("forward auth error: {reason}"));
                    return self
                        .write_error_response(
                            session,
                            503,
                            &ctx.request_id,
                            entry.route.error_page_html.as_deref(),
                            "Authentication service unavailable",
                            &[],
                        )
                        .await
                        .map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Stage: backend selection (never terminal). Applies, in order:
    /// header rule matching (first match wins, sets the backend
    /// override before path rules so a later path rule with its own
    /// `backend_ids` can still take precedence - "more specific
    /// wins"), the canary traffic split (only when no earlier phase
    /// already set `matched_backends`), and path rule matching (first
    /// match wins, overrides the route snapshot).
    pub(super) fn apply_backend_selection(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) {
        let req = session.req_header();
        let path = req.uri.path();

        // Header rule matching (first match wins; sets backend override
        // before path rules so a later path rule with its own backend_ids
        // can still take precedence - "more specific wins"). Also
        // emits a Prometheus counter so operators can see rule-match
        // activity in metrics, not just logs. `rule_index = "default"`
        // means no rule matched.
        if !entry.route.header_rules.is_empty() {
            let mut matched_idx: Option<usize> = None;
            for (i, rule) in entry.route.header_rules.iter().enumerate() {
                let value = req
                    .headers
                    .get(rule.header_name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let regex: Option<&regex::Regex> = entry
                    .header_rule_regexes
                    .get(i)
                    .and_then(|opt| opt.as_deref());
                if rule.matches(value, |v| regex.is_some_and(|re| re.is_match(v))) {
                    matched_idx = Some(i);
                    if let Some(b) = entry.header_rule_backends.get(i).and_then(|b| b.as_ref()) {
                        ctx.matched_backends = Some(b.clone());
                    }
                    break;
                }
            }
            match matched_idx {
                Some(i) => {
                    // Stack-allocated itoa buffer avoids the per-request
                    // String allocation that the old `i.to_string()`
                    // performed on every header-rule match. ~1-2% CPU
                    // saved at high QPS on routes with many rules.
                    let mut buf = itoa::Buffer::new();
                    lorica_api::metrics::inc_header_rule_match(&entry.route.id, buf.format(i));
                }
                None => lorica_api::metrics::inc_header_rule_match(&entry.route.id, "default"),
            }
        }

        // Canary traffic split: runs AFTER header rules (operator opt-in
        // always wins) and BEFORE path rules (URL-specific overrides
        // still win). The split is applied only when no earlier phase
        // already set `matched_backends`, so a user with X-Version: beta
        // is never accidentally rebalanced into the canary bucket for
        // the default version. Requests without a client IP (Unix-socket
        // listeners in tests, rare IPv6 edge cases) keep route defaults
        // rather than being bucketed deterministically on an empty
        // string.
        if ctx.matched_backends.is_none() && !entry.route.traffic_splits.is_empty() {
            if let Some(ref ip) = ctx.client_ip {
                let bucket = canary_bucket(&entry.route.id, ip);
                // Inline walk so we know which split matched (for the
                // split_name metric label). Mirrors
                // `pick_traffic_split_backends` logic; the helper stays
                // as-is for its unit-test callers.
                let mut cumulative: u32 = 0;
                let mut matched_split_name: Option<&str> = None;
                for (i, split) in entry.route.traffic_splits.iter().enumerate() {
                    let w = split.weight_percent.min(100) as u32;
                    if w == 0 {
                        continue;
                    }
                    cumulative = cumulative.saturating_add(w).min(100);
                    if (bucket as u32) < cumulative {
                        if let Some(backends) =
                            entry.traffic_split_backends.get(i).and_then(|b| b.as_ref())
                        {
                            ctx.matched_backends = Some(backends.clone());
                            matched_split_name = Some(if split.name.is_empty() {
                                "unnamed"
                            } else {
                                split.name.as_str()
                            });
                        }
                        break;
                    }
                }
                match matched_split_name {
                    Some(name) => {
                        lorica_api::metrics::inc_canary_split_selected(&entry.route.id, name)
                    }
                    None => {
                        lorica_api::metrics::inc_canary_split_selected(&entry.route.id, "default")
                    }
                }
            }
        }

        // Path rule matching (first match wins, overrides route config)
        for (i, rule) in entry.route.path_rules.iter().enumerate() {
            if rule.matches(path) {
                let effective = entry.route.with_path_rule_overrides(rule);
                ctx.route_snapshot = Some(Arc::new(effective));
                if rule.backend_ids.is_some() {
                    if let Some(ref backends) = entry.path_rule_backends[i] {
                        ctx.matched_backends = Some(backends.clone());
                    }
                }
                // A path rule that explicitly sets redirect_to means
                // the operator picked the exact destination for this
                // path. Flag it so the redirect branches below emit
                // the target verbatim instead of appending the
                // request's path/query (which is the documented
                // route-level behavior, but nonsensical here: the
                // path has already been matched).
                if rule.redirect_to.is_some() {
                    ctx.path_rule_literal_redirect = true;
                }
                break;
            }
        }
    }

    /// Stage: request mirroring setup (never terminal). Fire-and-forget
    /// shadow copies: body-less requests (GET/HEAD/DELETE, or any
    /// request without Content-Length / Transfer-Encoding) spawn
    /// immediately; body-bearing requests stash the metadata in
    /// `ctx.mirror_pending` and fire in `request_body_filter` once the
    /// body is buffered - so shadow backends see the same request body
    /// as the primary, up to the configured max_body_bytes cap.
    pub(super) fn setup_request_mirror(
        &self,
        session: &Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) {
        let req = session.req_header();
        if let Some(ref mirror_cfg) = entry.route.mirror {
            if !entry.mirror_backends.is_empty()
                && mirror_sample_hit(&ctx.request_id, mirror_cfg.sample_percent)
            {
                let headers = build_mirror_forward_headers(req, &ctx.request_id);
                let path = req
                    .uri
                    .path_and_query()
                    .map(|pq| pq.as_str().to_string())
                    .unwrap_or_else(|| "/".to_string());
                let method = req.method.clone();
                let max_body = mirror_cfg.max_body_bytes as usize;
                let body_expected = max_body > 0 && request_has_body(req);

                if body_expected {
                    // Defer mirror firing until request_body_filter has
                    // buffered the full body.
                    ctx.mirror_pending = Some(MirrorPending {
                        cfg: mirror_cfg.clone(),
                        backends: entry.mirror_backends.clone(),
                        method,
                        path_and_query: path,
                        headers,
                        request_id: ctx.request_id.clone(),
                        max_body_bytes: max_body,
                        route_id: entry.route.id.clone(),
                    });
                    ctx.mirror_body_state = Some(MirrorBodyState::Active(Vec::new()));
                } else {
                    // No body to buffer (or operator opted into
                    // headers-only via max_body_bytes = 0): fire now.
                    spawn_mirrors(
                        mirror_cfg,
                        &entry.mirror_backends,
                        method,
                        path,
                        headers,
                        None,
                        ctx.request_id.clone(),
                        entry.route.id.clone(),
                    );
                }
            }
        }
    }

    /// Stage: maintenance mode. Triggers when the route snapshot has
    /// `maintenance_mode = true`. Terminal: 503 with `Retry-After: 300`
    /// and the route's custom error HTML when configured. Kept inline
    /// (not via `write_error_response`) because of the Retry-After
    /// variant.
    pub(super) async fn check_maintenance_mode(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
    ) -> Result<Option<bool>> {
        if let Some(ref route) = ctx.route_snapshot {
            if route.maintenance_mode {
                let host_header = extract_host(session.req_header()).to_string();
                let body_html = render_error_body(
                    503,
                    &ctx.request_id,
                    &host_header,
                    route.error_page_html.as_deref(),
                    "Service under maintenance",
                );
                let mut header = ResponseHeader::build(503, None)?;
                header.insert_header("Content-Type", "text/html; charset=utf-8")?;
                header.insert_header("Content-Length", body_html.len().to_string())?;
                header.insert_header("Retry-After", "300")?;
                session
                    .write_response_header(Box::new(header), false)
                    .await?;
                session
                    .write_response_body(Some(bytes::Bytes::from(body_html)), true)
                    .await?;
                return Ok(Some(true));
            }
        }
        Ok(None)
    }

    /// Stage: HTTP Basic Auth (per-route) with credential verification
    /// cache. The cache avoids running Argon2 (~100ms) on every request
    /// by caching the hash of verified credentials for 60 seconds.
    /// Triggers when the route snapshot carries both a username and a
    /// password hash and the request fails verification. Terminal: 401
    /// with `WWW-Authenticate`.
    pub(super) async fn check_basic_auth(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
    ) -> Result<Option<bool>> {
        if let Some(ref route) = ctx.route_snapshot {
            if let (Some(ref expected_user), Some(ref expected_hash)) =
                (&route.basic_auth_username, &route.basic_auth_password_hash)
            {
                let authorized = session
                    .req_header()
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.strip_prefix("Basic "))
                    .and_then(|b64| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(b64).ok()
                    })
                    .and_then(|decoded| String::from_utf8(decoded).ok())
                    .map(|cred| {
                        let mut parts = cred.splitn(2, ':');
                        let user = parts.next().unwrap_or("");
                        let pass = parts.next().unwrap_or("");
                        if user != expected_user {
                            return false;
                        }

                        // Check credential cache before running Argon2.
                        // Key is the NUL-joined literal "{cred}\0{hash}"
                        // so two distinct credentials cannot collide on
                        // a truncated 64-bit digest (which, at a small
                        // cache size, is not worth the bypass risk).
                        let mut cache_key =
                            String::with_capacity(cred.len() + 1 + expected_hash.len());
                        cache_key.push_str(&cred);
                        cache_key.push('\0');
                        cache_key.push_str(expected_hash.as_str());

                        const AUTH_CACHE_TTL: Duration = Duration::from_secs(60);
                        if let Some(verified_at) = self.basic_auth_cache.get(&cache_key) {
                            if verified_at.elapsed() < AUTH_CACHE_TTL {
                                return true; // cache hit - skip Argon2
                            }
                        }

                        // Cache miss or expired - run full Argon2 verification.
                        // Parse the hash first; if it's corrupt, deny immediately
                        // without paying the cost of block_in_place.
                        if argon2::PasswordHash::new(expected_hash).is_err() {
                            return false;
                        }
                        // Offload CPU-intensive Argon2 to the blocking thread
                        // pool to avoid stalling the async proxy runtime.
                        let pass_bytes = pass.as_bytes().to_vec();
                        let hash_str = expected_hash.to_string();
                        let ok = tokio::task::block_in_place(|| {
                            use argon2::PasswordVerifier;
                            match argon2::PasswordHash::new(&hash_str) {
                                Ok(h) => argon2::Argon2::default()
                                    .verify_password(&pass_bytes, &h)
                                    .is_ok(),
                                Err(_) => false,
                            }
                        });
                        if ok {
                            self.basic_auth_cache.insert(cache_key, Instant::now());
                            // Evict expired entries to prevent unbounded growth
                            self.basic_auth_cache
                                .retain(|_, t| t.elapsed() < AUTH_CACHE_TTL);
                        }
                        ok
                    })
                    .unwrap_or(false);

                if !authorized {
                    let mut header = ResponseHeader::build(401, None)?;
                    header.insert_header("WWW-Authenticate", "Basic realm=\"Lorica\"")?;
                    header.insert_header("Content-Length", "0")?;
                    session
                        .write_response_header(Box::new(header), true)
                        .await?;
                    return Ok(Some(true));
                }
            }
        }
        Ok(None)
    }

    /// Stage: direct status response (`return_status`) and external
    /// redirect (`redirect_to`), read from the route snapshot (path
    /// rules may have overridden them). `return_status` combined with
    /// `redirect_to` emits a redirect with that specific status;
    /// `return_status` alone renders the branded error page;
    /// `redirect_to` alone emits a 301. Terminal: configured status /
    /// 301.
    pub(super) async fn check_return_status_and_redirect(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
    ) -> Result<Option<bool>> {
        let req = session.req_header();

        // Direct status response (return_status)
        if let Some(status) = ctx.route_snapshot.as_ref().and_then(|r| r.return_status) {
            ctx.block_reason = Some(format!("return_status {status}"));
            if let Some(ref target) = ctx
                .route_snapshot
                .as_ref()
                .and_then(|r| r.redirect_to.clone())
            {
                // return_status + redirect_to = redirect with specific status code
                let location = build_redirect_location(
                    target,
                    req.uri.path(),
                    req.uri.query(),
                    ctx.path_rule_literal_redirect,
                );
                let mut header = lorica_http::ResponseHeader::build(status, None)?;
                header.insert_header("Location", &location)?;
                session
                    .write_response_header(Box::new(header), true)
                    .await?;
            } else {
                // return_status alone = direct response. Route the body
                // through render_error_body() so operators get Lorica's
                // branded error page (or their own error_page_html when
                // configured), consistent with every other terminal
                // branch (403 IP / WAF / GeoIP, 429 rate limit,
                // 502 / 504 upstream). Previously this path wrote empty
                // headers only, which produced a blank page for
                // return_status routes.
                let error_page_html = ctx
                    .route_snapshot
                    .as_ref()
                    .and_then(|r| r.error_page_html.as_deref())
                    .map(|s| s.to_string());
                self.write_error_response(
                    session,
                    status,
                    &ctx.request_id,
                    error_page_html.as_deref(),
                    &format!("return_status {status}"),
                    &[],
                )
                .await?;
            }
            return Ok(Some(true));
        }

        // Redirect to external URL (read from snapshot, path rules may have overridden it)
        if let Some(ref target) = ctx
            .route_snapshot
            .as_ref()
            .and_then(|r| r.redirect_to.clone())
        {
            let location = build_redirect_location(
                target,
                req.uri.path(),
                req.uri.query(),
                ctx.path_rule_literal_redirect,
            );
            let mut header = lorica_http::ResponseHeader::build(301, None)?;
            header.insert_header("Location", &location)?;
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(Some(true));
        }
        Ok(None)
    }

    /// Stage: per-route IP allowlist / denylist. Triggers when the
    /// route has a non-empty allowlist that does not match the client
    /// IP, or a denylist entry that does. Terminal: 403 (both
    /// variants).
    pub(super) async fn check_ip_allow_deny(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
        ip: &str,
    ) -> Result<Option<bool>> {
        if !entry.route.ip_allowlist.is_empty()
            && !entry.route.ip_allowlist.iter().any(|a| ip_matches(ip, a))
        {
            ctx.block_reason = Some("IP not in allowlist".to_string());
            return self
                .write_error_response(
                    session,
                    403,
                    &ctx.request_id,
                    entry.route.error_page_html.as_deref(),
                    "IP not in allowlist",
                    &[],
                )
                .await
                .map(Some);
        }
        if entry.route.ip_denylist.iter().any(|d| ip_matches(ip, d)) {
            ctx.block_reason = Some("IP in denylist".to_string());
            return self
                .write_error_response(
                    session,
                    403,
                    &ctx.request_id,
                    entry.route.error_page_html.as_deref(),
                    "IP in denylist",
                    &[],
                )
                .await
                .map(Some);
        }
        Ok(None)
    }

    /// Stage: per-route GeoIP country filter (v1.4.0 Epic 2 story 2.4).
    /// Evaluated after IP allow/denylist so a specific IP always wins
    /// over a country rule, and before WAF so cheap geographic
    /// rejection happens before expensive regex matching. Unknown
    /// country (reserved / private ranges, DB miss) falls through
    /// without blocking so a legitimate client behind a corporate NAT
    /// is never accidentally denied - the operator can layer an
    /// explicit `ip_allowlist` on top when they want fail-close
    /// semantics. Terminal: 403.
    ///
    /// Returns `(handled, cached_country)`: the country is resolved
    /// once here and reused by the bot-protection stage's
    /// `bypass.countries` / `only_country` checks, avoiding a redundant
    /// mmdb decode_path call on the hot path.
    pub(super) async fn check_geoip_filter(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<(Option<bool>, Option<String>)> {
        let mut cached_country: Option<String> = None;
        if let Some(ip_addr) = ctx.client_ip_addr {
            if let Some(country) = self.geoip_resolver.lookup_country(ip_addr) {
                cached_country = Some(country.as_str().to_string());
                // Always stamp the country on the root tracing
                // span - the attribute is useful even on requests
                // that are not blocked (traffic analytics per
                // country, anomaly detection). The bridge
                // mirrors this onto the exported OTel span when
                // the `otel` feature is on; without the feature
                // it just shows up as a span field in JSON logs.
                ctx.root_tracing_span
                    .record("client.geo.country_iso_code", country.as_str());

                if let Some(ref geoip_cfg) = entry.route.geoip {
                    use lorica_config::models::GeoIpMode;
                    if geoip_cfg.blocks(country.as_str()) {
                        let mode_str = match geoip_cfg.mode {
                            GeoIpMode::Allowlist => "allowlist",
                            GeoIpMode::Denylist => "denylist",
                        };
                        // Prometheus counter: bounded cardinality
                        // (routes * ~240 countries * 2 modes).
                        // Use `entry.route.id` directly - the
                        // per-request `ctx.route_id` is only
                        // assigned further down the filter (after
                        // response_headers + auth checks) and
                        // would show up as "_unknown" here.
                        lorica_api::metrics::inc_geoip_block(
                            entry.route.id.as_str(),
                            country.as_str(),
                            mode_str,
                        );

                        let reason = format!("GeoIP blocked ({country} via {mode_str})");
                        ctx.block_reason = Some(reason.clone());
                        let handled = self
                            .write_error_response(
                                session,
                                403,
                                &ctx.request_id,
                                entry.route.error_page_html.as_deref(),
                                &reason,
                                &[],
                            )
                            .await?;
                        return Ok((Some(handled), cached_country));
                    }
                }
            }
            // `country` is None = DB miss / unknown range;
            // fall through without blocking. Operators that
            // want fail-close behaviour can layer
            // ip_allowlist on top. No OTel attribute when
            // country is unknown - omitting is semantically
            // clearer than setting an empty string.
        }
        Ok((None, cached_country))
    }

    /// Stage: per-route bot-protection evaluation (v1.4.0 Epic 3
    /// story 3.5). Runs after GeoIP (so the `bypass.countries` and
    /// `only_country` checks can use the resolved country) and only on
    /// the request path; `POST /lorica/bot/solve` and the captcha image
    /// GET are intercepted earlier by `check_bot_endpoints`. Terminal:
    /// challenge response (HTML / JSON) when the evaluator decides
    /// `Challenge`; a `Pass` records metrics and span attributes and
    /// falls through.
    pub(super) async fn check_bot_protection(
        &self,
        session: &mut Session,
        ctx: &RequestCtx,
        entry: &RouteEntry,
        cached_country: &Option<String>,
    ) -> Result<Option<bool>> {
        if let Some(ref bot_cfg) = entry.route.bot_protection {
            if let Some(ip_addr) = ctx.client_ip_addr {
                // Reuse the country resolved in the GeoIP stage
                // (cached_country) to avoid a redundant
                // mmdb decode_path call on every request.
                let country = cached_country.clone();
                // ASN lookup via the hot-swappable resolver.
                // Returns None when no DB is loaded - the
                // evaluator treats that as "asn bypass
                // disabled for this request" and falls through
                // to the remaining categories. Zero-cost when
                // the operator has no ASN DB configured.
                let asn = self.asn_resolver.lookup_asn(ip_addr);
                // Forward-confirmed rDNS from the per-process
                // cache. Cache miss on the hot path is
                // intentional: the rDNS lookup is O(~network
                // RTT) and must not block request_filter. We
                // spawn a populate task so the NEXT request
                // from the same IP gets a hit, then proceed
                // with rdns_name = None for this request (the
                // evaluator treats that as "rdns bypass does
                // not fire").
                let rdns_name: Option<String> = if bot_cfg.bypass.rdns.is_empty() {
                    // Zero-cost when the operator has no rDNS
                    // bypass configured - do not even probe the
                    // cache.
                    None
                } else if let Some(resolver) = crate::bot_rdns::handle() {
                    let now_i = chrono::Utc::now().timestamp();
                    match resolver.cache_check(ip_addr, now_i) {
                        Some(cached) => cached,
                        None => {
                            // Fire-and-forget populate via the
                            // resolver's bounded `try_spawn_resolve`
                            // (v1.5.1 audit L-10). Dedups
                            // concurrent misses for the same
                            // fresh IP and caps total in-flight
                            // resolve tasks at
                            // `MAX_INFLIGHT_RESOLVES` (256).
                            // Each spawned task is bounded by
                            // hickory's own timeout + attempts
                            // (<= 6 s) and dropped on runtime
                            // shutdown.
                            resolver.try_spawn_resolve(ip_addr);
                            None
                        }
                    }
                } else {
                    None
                };
                let ua = session
                    .req_header()
                    .headers
                    .get(http::header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let cookie_header = session
                    .req_header()
                    .headers
                    .get(http::header::COOKIE)
                    .and_then(|v| v.to_str().ok());
                let verdict_cookie = cookie_header.and_then(crate::bot::extract_verdict_cookie);
                let now_secs = chrono::Utc::now().timestamp();
                let secret = lorica_challenge::secret::handle();
                let secret_ref = secret.as_deref();
                // Cross-worker verdict cache (story 3.6 closure):
                // in worker mode, consult the supervisor-owned
                // cache BEFORE running HMAC verify so a cookie
                // issued on a sibling worker is honoured without
                // a fresh verify on this worker. Local-mode
                // evaluator handles the in-process cache
                // internally; Rpc-mode hits this path.
                let ip_prefix = lorica_challenge::IpPrefix::from_ip(ip_addr);
                let cached_cookie_hit =
                    if matches!(self.verdict_cache, VerdictCacheEngine::Rpc { .. }) {
                        if let Some(cookie) = verdict_cookie {
                            crate::bot::rpc_cache_check(
                                &self.verdict_cache,
                                &entry.route.id,
                                &ip_prefix,
                                cookie,
                                now_secs,
                            )
                            .await
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                let inputs = crate::bot::EvalInputs {
                    client_ip: ip_addr,
                    country,
                    asn,
                    rdns_name,
                    user_agent: ua,
                    verdict_cookie,
                    now: now_secs,
                    hmac_secret: secret_ref,
                    route_id: &entry.route.id,
                    config: bot_cfg,
                    cached_cookie_hit,
                    ua_regex_set: entry.bot_ua_regex_set.as_deref(),
                };
                match crate::bot::evaluate(&inputs) {
                    crate::bot::Decision::Pass { reason } => {
                        debug!(
                            route_id = %entry.route.id,
                            reason = reason.as_str(),
                            "bot-protection: pass"
                        );
                        // In Rpc mode AND on a fresh HMAC-verify
                        // hit (not a cache short-circuit), push
                        // the verdict to the supervisor cache so
                        // the next request on any worker skips
                        // the verify. Fire-and-forget - a failed
                        // push just means the next request
                        // re-verifies, which is the same as a
                        // cache miss. Skips pushes when the hit
                        // already came from the cache (to avoid
                        // refreshing TTL on every request, which
                        // would extend the cookie's effective
                        // life past its `expires_at`).
                        if reason == crate::bot::PassReason::ValidCookie
                            && cached_cookie_hit.is_none()
                            && matches!(self.verdict_cache, VerdictCacheEngine::Rpc { .. })
                        {
                            if let (Some(cookie), Some(secret)) = (verdict_cookie, secret_ref) {
                                if let Ok(payload) =
                                    lorica_challenge::cookie::verify(cookie, secret, now_secs)
                                {
                                    let engine = self.verdict_cache.clone();
                                    let route_id = entry.route.id.clone();
                                    let ip_prefix_c = ip_prefix.clone();
                                    let cookie_c = cookie.to_string();
                                    let exp = payload.expires_at;
                                    tokio::spawn(async move {
                                        crate::bot::rpc_cache_push(
                                            &engine,
                                            &route_id,
                                            &ip_prefix_c,
                                            &cookie_c,
                                            exp,
                                            now_secs,
                                        )
                                        .await;
                                    });
                                }
                            }
                        }
                        // Metric + OTel span attribute. A valid
                        // cookie yields outcome=passed; any of
                        // the bypass reasons yields
                        // outcome=bypassed. The detailed bypass
                        // category lives on the OTel span
                        // attribute so Prometheus cardinality
                        // stays bounded.
                        let outcome = match reason {
                            crate::bot::PassReason::ValidCookie => "passed",
                            crate::bot::PassReason::Disabled => "passed",
                            crate::bot::PassReason::OnlyCountryGateMiss => "bypassed",
                            crate::bot::PassReason::BypassIpCidr
                            | crate::bot::PassReason::BypassAsn
                            | crate::bot::PassReason::BypassRdns
                            | crate::bot::PassReason::BypassCountry
                            | crate::bot::PassReason::BypassUserAgent => "bypassed",
                        };
                        let mode_str = match bot_cfg.mode {
                            lorica_config::models::BotProtectionMode::Cookie => "cookie",
                            lorica_config::models::BotProtectionMode::Javascript => "javascript",
                            lorica_config::models::BotProtectionMode::Captcha => "captcha",
                        };
                        lorica_api::metrics::inc_bot_challenge(
                            entry.route.id.as_str(),
                            mode_str,
                            outcome,
                        );
                        ctx.root_tracing_span
                            .record("bot_protection.challenge.outcome", outcome);
                        ctx.root_tracing_span
                            .record("bot_protection.challenge.mode", mode_str);
                        ctx.root_tracing_span
                            .record("bot_protection.challenge.reason", reason.as_str());
                    }
                    crate::bot::Decision::Challenge => {
                        // Render the original request URI so a
                        // successful solve bounces the user back
                        // to where they came from (path + query).
                        let req = session.req_header();
                        let path_and_q = req
                            .uri
                            .path_and_query()
                            .map(|pq| pq.as_str().to_string())
                            .unwrap_or_else(|| "/".to_string());
                        let accept_html = bot_handlers::accept_prefers_html(
                            req.headers
                                .get(http::header::ACCEPT)
                                .and_then(|v| v.to_str().ok()),
                        );
                        return bot_handlers::serve_challenge(
                            session,
                            &self.bot_engine,
                            bot_cfg,
                            &entry.route.id,
                            ip_addr,
                            &path_and_q,
                            accept_html,
                            now_secs,
                        )
                        .await
                        .map(Some);
                    }
                }
            }
        }
        Ok(None)
    }

    /// Stage: slowloris detection. Triggers when the route configures
    /// `slowloris_threshold_ms > 0` and the time from connection start
    /// to `request_filter` exceeds it (the client is likely sending
    /// headers very slowly). Terminal: 408.
    pub(super) async fn check_slowloris(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
        check_ip: Option<&str>,
    ) -> Result<Option<bool>> {
        let slowloris_ms = entry.route.slowloris_threshold_ms;
        if slowloris_ms > 0 {
            let elapsed_ms = ctx.start_time.elapsed().as_millis() as i32;
            if elapsed_ms > slowloris_ms {
                let client_ip_str = check_ip.unwrap_or("-");
                warn!(
                    ip = %client_ip_str,
                    elapsed_ms = elapsed_ms,
                    threshold_ms = slowloris_ms,
                    route_id = %entry.route.id,
                    "slowloris detected - slow request headers"
                );
                ctx.block_reason = Some("slowloris detected".to_string());
                return self
                    .write_error_response(
                        session,
                        408,
                        &ctx.request_id,
                        entry.route.error_page_html.as_deref(),
                        "Request headers took too long",
                        &[],
                    )
                    .await
                    .map(Some);
            }
        }
        Ok(None)
    }

    /// Stage: per-route max connections enforcement. Tracks active
    /// connections per route using atomic counters; on pass, stashes
    /// the incremented counter in `ctx.route_conn_counter` so
    /// `logging()` decrements it when the request ends. Terminal: 503
    /// when the route exceeds its configured connection limit.
    pub(super) async fn check_route_connection_limit(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        if let Some(max_conn) = entry.route.max_connections {
            let counter = self
                .route_connections
                .entry(entry.route.id.clone())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .value()
                .clone();
            let current = counter.fetch_add(1, Ordering::Relaxed);
            if current >= max_conn as u64 {
                counter.fetch_sub(1, Ordering::Relaxed);
                warn!(
                    route_id = %entry.route.id,
                    current_connections = current + 1,
                    max_connections = max_conn,
                    "max connections exceeded for route (503)"
                );
                ctx.block_reason = Some("route connection limit".to_string());
                let error_page_html = ctx
                    .route_snapshot
                    .as_ref()
                    .and_then(|r| r.error_page_html.as_deref())
                    .map(|s| s.to_string());
                return self
                    .write_error_response(
                        session,
                        503,
                        &ctx.request_id,
                        error_page_html.as_deref(),
                        "Route connection limit exceeded",
                        &[],
                    )
                    .await
                    .map(Some);
            }
            ctx.route_conn_counter = Some(counter);
        }
        Ok(None)
    }

    /// Stage: request body limits on the advertised Content-Length.
    /// Covers the per-route `max_request_body_bytes` cap and the WAF
    /// body-scan cap (v1.5.1 audit H-2): when WAF is enabled and the
    /// advertised Content-Length exceeds the scan window, Blocking mode
    /// rejects and Detection mode records a `BodyTruncated` event and
    /// proceeds (mirrors ModSecurity `SecRequestBodyLimitAction` and
    /// AWS WAF oversize handling). The chunked / no-Content-Length case
    /// is caught downstream in `request_body_filter` by the same caps.
    /// Terminal: 413.
    pub(super) async fn check_body_limits(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
    ) -> Result<Option<bool>> {
        let req = session.req_header();

        // Request body size limit
        if let Some(max_bytes) = entry.route.max_request_body_bytes {
            if let Some(cl) = req.headers.get("content-length") {
                if let Ok(len) = cl.to_str().unwrap_or("0").parse::<u64>() {
                    if len > max_bytes {
                        let header = lorica_http::ResponseHeader::build(413, None)?;
                        session
                            .write_response_header(Box::new(header), true)
                            .await?;
                        return Ok(Some(true));
                    }
                }
            }
        }

        // WAF body-scan cap on the advertised Content-Length.
        // Fail-fast here avoids buffering bytes we would reject
        // anyway in `request_body_filter`.
        if entry.route.waf_enabled {
            if let Some(cl) = req.headers.get("content-length") {
                if let Ok(len) = cl.to_str().unwrap_or("0").parse::<u64>() {
                    if len > WAF_BODY_SCAN_MAX as u64 {
                        match entry.route.waf_mode {
                            WafMode::Blocking => {
                                warn!(
                                    content_length = len,
                                    cap = WAF_BODY_SCAN_MAX,
                                    route_id = %entry.route.id,
                                    "request body exceeds WAF scan window (413, blocking, advertised CL)"
                                );
                                let header = lorica_http::ResponseHeader::build(413, None)?;
                                session
                                    .write_response_header(Box::new(header), true)
                                    .await?;
                                return Ok(Some(true));
                            }
                            WafMode::Detection => {
                                self.record_waf_body_truncated(
                                    ctx,
                                    &entry.route.id,
                                    &entry.route.hostname,
                                    len,
                                );
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    /// Stage: legacy per-route rate limiting (`rate_limit_rps` +
    /// optional burst), with adaptive flood defense (per-IP limits
    /// halved when global RPS exceeds `flood_threshold_rps`) and
    /// auto-ban on repeated violations (`auto_ban_threshold`). Skipped
    /// for whitelisted IPs. Stores `ctx.rate_limit_info` for response
    /// headers even when not throttled. Terminal: 429 with
    /// `Retry-After` and `X-RateLimit-Reset`.
    pub(super) async fn check_legacy_rate_limit(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
        check_ip: Option<&str>,
        is_whitelisted: bool,
        config: &ProxyConfig,
    ) -> Result<Option<bool>> {
        if !is_whitelisted {
            if let Some(rps) = entry.route.rate_limit_rps {
                if let Some(ip) = check_ip {
                    let key = format!("{}:{}", entry.route.id, ip);
                    self.rate_limiter.observe(&key, 1);
                    let current_rate = self.rate_limiter.rate(&key);
                    let mut effective_limit = match entry.route.rate_limit_burst {
                        Some(burst) => (rps + burst) as f64,
                        None => rps as f64,
                    };

                    // Adaptive flood defense: when global RPS exceeds the
                    // configured threshold, halve per-IP rate limits.
                    let threshold = config.flood_threshold_rps;
                    if threshold > 0 {
                        let global_rps = self.global_rate.rate(&"global");
                        if global_rps > threshold as f64 {
                            effective_limit *= 0.5;
                        }
                    }
                    // Store rate info for response headers (even if not throttled)
                    ctx.rate_limit_info = Some((rps, current_rate));

                    if current_rate > effective_limit {
                        warn!(
                            route_id = %entry.route.id,
                            client_ip = %ip,
                            current_rate = %current_rate,
                            limit_rps = %rps,
                            "request rate-limited (429)"
                        );

                        // Track rate limit violations for auto-ban
                        if let Some(ban_threshold) = entry.route.auto_ban_threshold {
                            let violation_key = format!("violation:{}", ip);
                            self.rate_violations.observe(&violation_key, 1);
                            let violations = self.rate_violations.rate(&violation_key);
                            if violations > ban_threshold as f64 {
                                let ban_duration = entry.route.auto_ban_duration_s;
                                self.ban_list
                                    .insert(ip.to_string(), (Instant::now(), ban_duration as u64));
                                warn!(
                                    ip = %ip,
                                    violations = %violations,
                                    ban_duration_s = %ban_duration,
                                    "IP auto-banned for rate limit abuse"
                                );
                                // Dispatch ip_banned notification
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
                        return self
                            .write_error_response(
                                session,
                                429,
                                &ctx.request_id,
                                entry.route.error_page_html.as_deref(),
                                "Rate limit exceeded",
                                &[
                                    ("Retry-After", "1".to_string()),
                                    ("X-RateLimit-Reset", reset_ts.to_string()),
                                ],
                            )
                            .await
                            .map(Some);
                    }
                }
            }
        }
        Ok(None)
    }

    /// Stage: WAF evaluation over path, query, and headers (terminal
    /// stage of `request_filter`). Returns `Ok(false)` immediately when
    /// the IP is whitelisted or WAF is disabled on the route (zero
    /// overhead). A `Blocked` verdict records events, metrics, and the
    /// WAF auto-ban counter (shmem in multi-worker mode, local DashMap
    /// otherwise) and answers 403; `Detected` records events and lets
    /// the request through; `Pass` is a no-op. Terminal: 403, or
    /// `Ok(false)` to continue to `upstream_peer`.
    pub(super) async fn evaluate_waf_request(
        &self,
        session: &mut Session,
        ctx: &mut RequestCtx,
        entry: &RouteEntry,
        check_ip: Option<&str>,
        is_whitelisted: bool,
    ) -> Result<bool> {
        // Skip WAF evaluation entirely if not enabled or IP is whitelisted (zero overhead)
        if is_whitelisted || !entry.route.waf_enabled {
            return Ok(false);
        }

        let req = session.req_header();
        let host_raw = extract_host(req);
        let host = host_raw.split(':').next().unwrap_or(host_raw);
        let path = req.uri.path();
        let query = req.uri.query();

        // Collect headers for inspection. Every header carrying a valid
        // UTF-8 value is scanned; non-UTF-8 (binary) values are skipped
        // by `to_str().ok()`. A fixed name allowlist was a WAF bypass:
        // any header a backend trusts but that was not on the list
        // (`Forwarded`, `True-Client-IP`, app-specific headers, ...)
        // carried injection payloads straight upstream with no event.
        // The Aho-Corasick prefilter short-circuits clean values cheaply,
        // so scanning every header is affordable on the hot path.
        let headers: Vec<(&str, &str)> = req
            .headers
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v)))
            .collect();

        let waf_mode = match entry.route.waf_mode {
            WafMode::Detection => lorica_waf::WafMode::Detection,
            WafMode::Blocking => lorica_waf::WafMode::Blocking,
        };

        let mut verdict = self.waf_engine.evaluate(
            waf_mode,
            path,
            query,
            &headers,
            host,
            check_ip.unwrap_or("-"),
        );

        match verdict {
            lorica_waf::WafVerdict::Blocked(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.to_string();
                    ev.action = "blocked".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "blocked");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "blocked".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    self.persist_waf_event(ev);
                }
                // Dispatch waf_alert notification
                if let (Some(ref sender), Some(ev)) = (&self.alert_sender, events.first()) {
                    sender.send(
                        lorica_notify::AlertEvent::new(
                            lorica_notify::events::AlertType::WafAlert,
                            format!("WAF blocked {} on {}{}", ev.category.as_str(), host, path),
                        )
                        .with_detail("rule_id", ev.rule_id.to_string())
                        .with_detail("category", ev.category.as_str().to_string())
                        .with_detail("host", host.to_string())
                        .with_detail("path", path.to_string())
                        .with_detail("client_ip", check_ip.unwrap_or("-").to_string()),
                    );
                }
                ctx.waf_blocked = true;
                ctx.matched_host = Some(host.to_string());
                ctx.matched_path = Some(path.to_string());

                // WAF auto-ban counter. Two modes:
                //
                // - Multi-worker (`self.shmem.is_some()`): increment the
                //   cross-worker `waf_auto_ban` atomic counter. The
                //   supervisor reads the counter on each UDS WAF event,
                //   decides when the threshold is crossed, broadcasts
                //   `BanIp` to all workers, and resets the slot. Workers
                //   never issue bans directly - the supervisor is the
                //   sole authority so the ban is consistent across the
                //   pool.
                //
                // - Single-process (`self.shmem.is_none()`): fall back to
                //   the per-process `waf_violations` DashMap + local
                //   `ban_list` insertion, as before.
                if let Some(ip) = check_ip {
                    let config = self.config.load();
                    let threshold = config.waf_ban_threshold;
                    if threshold > 0 {
                        if let Some(region) = self.shmem {
                            // Multi-worker: just bump the shmem counter.
                            let tagged = region.tagged(ip_to_shmem_key(ip));
                            let _ =
                                region
                                    .waf_auto_ban
                                    .increment(tagged, 1, lorica_shmem::now_ns());
                        } else {
                            let violations = self
                                .waf_violations
                                .entry(ip.to_string())
                                .or_insert_with(|| AtomicU64::new(0))
                                .fetch_add(1, Ordering::Relaxed)
                                + 1;
                            if violations >= threshold as u64 {
                                let ban_duration = config.waf_ban_duration_s;
                                self.ban_list
                                    .insert(ip.to_string(), (Instant::now(), ban_duration as u64));
                                self.waf_violations.remove(ip);
                                warn!(
                                    ip = %ip,
                                    violations = %violations,
                                    ban_duration_s = %ban_duration,
                                    "IP auto-banned for repeated WAF violations (local counter)"
                                );
                                if let Some(ref sender) = self.alert_sender {
                                    sender.send(
                                        lorica_notify::AlertEvent::new(
                                            lorica_notify::events::AlertType::IpBanned,
                                            format!(
                                                "IP {} auto-banned for repeated WAF violations",
                                                ip
                                            ),
                                        )
                                        .with_detail("ip", ip.to_string())
                                        .with_detail("violations", violations.to_string())
                                        .with_detail("ban_duration_s", ban_duration.to_string()),
                                    );
                                }
                            }
                        }
                    }
                }

                self.write_error_response(
                    session,
                    403,
                    &ctx.request_id,
                    entry.route.error_page_html.as_deref(),
                    "Request blocked by WAF",
                    &[],
                )
                .await
            }
            lorica_waf::WafVerdict::Detected(ref mut events) => {
                for ev in events.iter_mut() {
                    ev.route_hostname = host.to_string();
                    ev.action = "detected".to_string();
                    lorica_api::metrics::record_waf_event(ev.category.as_str(), "detected");
                    self.waf_counts
                        .entry((ev.category.as_str().to_string(), "detected".to_string()))
                        .or_insert_with(|| AtomicU64::new(0))
                        .fetch_add(1, Ordering::Relaxed);
                    self.persist_waf_event(ev);
                }
                ctx.waf_detected = true;
                Ok(false)
            }
            lorica_waf::WafVerdict::Pass => Ok(false),
        }
    }
}
