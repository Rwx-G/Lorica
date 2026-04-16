// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Bot-protection request-filter integration (v1.4.0 Epic 3, story
//! 3.5). Cross-worker stash uses SQLite (table `bot_pending_challenges`).
//!
//! Two things live here:
//!
//! 1. [`BotEngine`] — the pending-challenge stash. Keyed by a
//!    server-side nonce (separate from the PoW nonce to keep the
//!    two namespaces orthogonal). An entry is consumed on the
//!    first verify attempt regardless of outcome so a failed
//!    solution cannot be replayed against the same challenge.
//!    Captcha challenges additionally hold the PNG bytes the image
//!    handler serves at `/lorica/bot/captcha/{nonce}`.
//!
//!    The backend is pluggable via [`StashBackend`]. Production
//!    deployments use [`StashBackend::Sqlite`] so pending entries
//!    are visible to every worker in the pool — a client solving
//!    on worker A can submit on worker B, and the atomic
//!    DELETE...RETURNING on `take()` gives "first solver wins"
//!    cross-worker replay defence. Unit tests and the single-
//!    process path can use [`StashBackend::InMemory`] which keeps
//!    the O(1) hashmap behaviour without a DB dep.
//!
//! 2. [`evaluate`] — the pure-logic decision function called from
//!    `proxy_wiring::request_filter`. Returns one of:
//!    - [`Decision::Pass`] (valid cookie, bypass match, or
//!      `only_country` gate missed) — forward to the backend
//!    - [`Decision::Challenge`] — render a challenge page; caller
//!      is responsible for stashing the pending entry and writing
//!      the HTML
//!
//! The submit endpoint (`POST /lorica/bot/solve`) and the captcha
//! image endpoint (`GET /lorica/bot/captcha/{nonce}`) are routed by
//! [`is_bot_solve_path`] / [`is_bot_captcha_path`] + handled in
//! `proxy_wiring::request_filter` directly (they consume the
//! session and return 302 / 200 / 403). Keeping the handlers
//! inside `proxy_wiring` avoids a circular dep on the session type.

use std::collections::HashMap;
use std::sync::Arc;

use dashmap::DashMap;
use lorica_challenge::{IpPrefix, Mode};
use lorica_config::ConfigStore;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use rand::RngCore;

/// Path prefix for all Lorica-handled bot-protection endpoints.
/// Chosen to be improbable-to-collide with real routes; the `lorica`
/// product name plus `bot` scopes it unambiguously. Every handler
/// here matches on this prefix first so a normal route whose
/// backend happens to expose `/bot/*` is never swallowed.
pub const BOT_PATH_PREFIX: &str = "/lorica/bot/";

/// Path the challenge page's `<form action="...">` POSTs to.
pub const BOT_SOLVE_PATH: &str = "/lorica/bot/solve";

/// Path prefix for the captcha image handler. Followed by the
/// server-side nonce: `/lorica/bot/captcha/{nonce}`.
pub const BOT_CAPTCHA_PATH_PREFIX: &str = "/lorica/bot/captcha/";

/// Name of the verdict cookie the proxy sets on successful verify.
pub const VERDICT_COOKIE_NAME: &str = "lorica_bot_verdict";

/// Return true iff `path` is the solve endpoint. Match is case-
/// sensitive and exact (no query parameters) because the submit
/// form always posts to the same literal URL.
pub fn is_bot_solve_path(path: &str) -> bool {
    // Strip query string if any (`/lorica/bot/solve?route=…`).
    let p = path.split('?').next().unwrap_or(path);
    p == BOT_SOLVE_PATH
}

/// Return true iff `path` is a captcha image request and extract
/// the nonce portion. Returns `Some(nonce)` on match, `None`
/// otherwise. Rejects empty nonces and nonces containing `/` so a
/// traversal cannot escape the stash lookup.
pub fn parse_bot_captcha_path(path: &str) -> Option<&str> {
    let p = path.split('?').next().unwrap_or(path);
    let nonce = p.strip_prefix(BOT_CAPTCHA_PATH_PREFIX)?;
    if nonce.is_empty() || nonce.contains('/') {
        return None;
    }
    Some(nonce)
}

/// Kind of pending challenge waiting for a client solution.
#[derive(Debug, Clone)]
pub enum Pending {
    /// JavaScript PoW: client must find a counter such that
    /// `SHA-256(nonce_hex || counter_decimal)` has `difficulty`
    /// leading zero bits.
    Pow {
        nonce_hex: String,
        difficulty: u8,
    },
    /// Image captcha: client must submit the text shown in the
    /// PNG. The PNG bytes are kept here so
    /// [`BotEngine::captcha_image`] can serve them at
    /// `/lorica/bot/captcha/{nonce}`.
    Captcha {
        expected_text: String,
        png_bytes: Vec<u8>,
    },
}

/// One pending challenge entry in [`BotEngine`]. Keyed by a
/// server-side nonce; consumed on the first verify call.
#[derive(Debug, Clone)]
pub struct PendingEntry {
    pub kind: Pending,
    pub mode: Mode,
    pub route_id: String,
    pub ip_prefix: IpPrefix,
    pub return_url: String,
    pub cookie_ttl_s: u32,
    pub expires_at: i64,
}

/// Stash backend selector. Single-process mode can use an in-memory
/// map (zero dep, zero I/O); multi-worker mode needs the SQLite
/// backend so a challenge stashed by worker A is visible to the
/// POST handler on worker B.
pub enum StashBackend {
    /// Per-process `HashMap<nonce, entry>`. Fastest, no cross-
    /// worker sharing. Used by tests + the single-process runtime.
    InMemory(Mutex<HashMap<String, PendingEntry>>),
    /// SQLite-backed stash (table `bot_pending_challenges`).
    /// Every operation goes through the
    /// shared store so all workers see the same state. Atomic
    /// `DELETE ... RETURNING` on `take` gives "first solver wins"
    /// cross-worker replay defence.
    Sqlite(Arc<tokio::sync::Mutex<ConfigStore>>),
}

/// Pending-challenge stash.
///
/// `insert` / `take` / `captcha_image` / `prune_expired` / `len` all
/// dispatch on the backend. The public API is synchronous even when
/// the underlying store is async (SQLite calls under
/// `tokio::sync::Mutex`) by using `blocking_lock()` — acceptable
/// here because the lock hold time is bounded at a single SQL
/// statement (microseconds under WAL) and every hot-path caller
/// already runs inside a tokio runtime.
pub struct BotEngine {
    backend: StashBackend,
}

impl BotEngine {
    /// In-memory backend — single-process mode / tests. The engine
    /// drops every entry on process exit.
    pub fn new() -> Self {
        Self {
            backend: StashBackend::InMemory(Mutex::new(HashMap::new())),
        }
    }

    /// SQLite-backed backend — multi-worker mode. The store is
    /// the same `ConfigStore` every worker holds, so pending rows
    /// propagate via the shared DB file's WAL.
    pub fn with_sqlite(store: Arc<tokio::sync::Mutex<ConfigStore>>) -> Self {
        Self {
            backend: StashBackend::Sqlite(store),
        }
    }

    /// Generate a fresh 16-byte hex nonce. Uses `OsRng` so nonces
    /// are unpredictable — a predictable nonce would let an attacker
    /// pre-register a matching row and bypass the verify step.
    pub fn fresh_nonce(&self) -> String {
        use std::fmt::Write;
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let mut out = String::with_capacity(32);
        for b in raw.iter() {
            let _ = write!(out, "{b:02x}");
        }
        out
    }

    /// Stash a pending challenge. Overwrites any prior entry with
    /// the same nonce (128-bit random, collisions unobservable in
    /// practice). Async because the SQLite backend needs an
    /// `.await` on the shared store mutex; the in-memory backend
    /// completes synchronously (no real await) so the async
    /// overhead is a single vtable dispatch on the future.
    pub async fn insert(&self, nonce: String, entry: PendingEntry) {
        match &self.backend {
            StashBackend::InMemory(mx) => {
                mx.lock().insert(nonce, entry);
            }
            StashBackend::Sqlite(store) => {
                let stash = to_stash(&nonce, &entry);
                let g = store.lock().await;
                if let Err(e) = g.bot_stash_insert(&stash) {
                    tracing::warn!(error = %e, nonce = %nonce, "bot_stash_insert failed");
                }
            }
        }
    }

    /// Atomically remove + return the entry if it has not expired.
    /// Replay defence: a stashed challenge verifies at most once.
    /// The `now` parameter is checked atomically in the SQL DELETE
    /// (SQLite backend) so a clock-skew race cannot redeem an
    /// expired challenge.
    pub async fn take(&self, nonce: &str) -> Option<PendingEntry> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        match &self.backend {
            StashBackend::InMemory(mx) => {
                let entry = mx.lock().remove(nonce)?;
                if entry.expires_at > now {
                    Some(entry)
                } else {
                    None
                }
            }
            StashBackend::Sqlite(store) => {
                let g = store.lock().await;
                match g.bot_stash_take(nonce, now) {
                    Ok(Some(stash)) => from_stash(&stash),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(error = %e, nonce = %nonce, "bot_stash_take failed");
                        None
                    }
                }
            }
        }
    }

    /// Captcha PNG bytes lookup. Does NOT consume the stashed
    /// entry.
    pub async fn captcha_image(&self, nonce: &str) -> Option<Vec<u8>> {
        match &self.backend {
            StashBackend::InMemory(mx) => {
                let g = mx.lock();
                let entry = g.get(nonce)?;
                match &entry.kind {
                    Pending::Captcha { png_bytes, .. } => Some(png_bytes.clone()),
                    _ => None,
                }
            }
            StashBackend::Sqlite(store) => {
                let g = store.lock().await;
                g.bot_stash_captcha_image(nonce).ok().flatten()
            }
        }
    }

    /// Drop expired entries. Called opportunistically from the
    /// render path so a bot probing for unknown nonces does not
    /// pay the GC cost.
    pub async fn prune_expired(&self, now: i64) {
        match &self.backend {
            StashBackend::InMemory(mx) => {
                mx.lock().retain(|_, e| e.expires_at > now);
            }
            StashBackend::Sqlite(store) => {
                let g = store.lock().await;
                if let Err(e) = g.bot_stash_prune_expired(now) {
                    tracing::warn!(error = %e, "bot_stash_prune_expired failed");
                }
            }
        }
    }

    /// Current row count. Used by tests + the stash-size metric.
    pub async fn len(&self) -> usize {
        match &self.backend {
            StashBackend::InMemory(mx) => mx.lock().len(),
            StashBackend::Sqlite(store) => {
                let g = store.lock().await;
                g.bot_stash_len().unwrap_or(0)
            }
        }
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

impl Default for BotEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Serialise an in-memory `PendingEntry` into the SQLite wire
/// shape. The payload JSON captures the mode-specific fields; the
/// PNG bytes get their own column so we do not round-trip binary
/// through JSON.
fn to_stash(nonce: &str, entry: &PendingEntry) -> lorica_config::BotStashEntry {
    let (kind, payload, png) = match &entry.kind {
        Pending::Pow {
            nonce_hex,
            difficulty,
        } => {
            let payload = serde_json::json!({
                "nonce_hex": nonce_hex,
                "difficulty": difficulty,
            })
            .to_string();
            ("pow".to_string(), payload, None)
        }
        Pending::Captcha {
            expected_text,
            png_bytes,
        } => {
            let payload = serde_json::json!({
                "expected_text": expected_text,
            })
            .to_string();
            ("captcha".to_string(), payload, Some(png_bytes.clone()))
        }
    };
    let ip_prefix_disc = entry.ip_prefix.discriminator();
    let ip_prefix_bytes = entry.ip_prefix.as_bytes().to_vec();
    lorica_config::BotStashEntry {
        nonce: nonce.to_string(),
        kind,
        payload,
        mode: entry.mode as u8,
        route_id: entry.route_id.clone(),
        ip_prefix_disc,
        ip_prefix_bytes,
        return_url: entry.return_url.clone(),
        cookie_ttl_s: entry.cookie_ttl_s,
        expires_at: entry.expires_at,
        png_bytes: png,
    }
}

/// Inverse of [`to_stash`]. `None` on malformed wire data — caller
/// treats that as "no stashed entry" which collapses to 403 at
/// verify time.
fn from_stash(stash: &lorica_config::BotStashEntry) -> Option<PendingEntry> {
    let kind = match stash.kind.as_str() {
        "pow" => {
            let v: serde_json::Value = serde_json::from_str(&stash.payload).ok()?;
            Pending::Pow {
                nonce_hex: v.get("nonce_hex")?.as_str()?.to_string(),
                difficulty: v.get("difficulty")?.as_u64()? as u8,
            }
        }
        "captcha" => {
            let v: serde_json::Value = serde_json::from_str(&stash.payload).ok()?;
            Pending::Captcha {
                expected_text: v.get("expected_text")?.as_str()?.to_string(),
                png_bytes: stash.png_bytes.clone().unwrap_or_default(),
            }
        }
        _ => return None,
    };
    let mode = Mode::from_u8(stash.mode)?;
    let ip_prefix = match stash.ip_prefix_disc {
        1 => {
            let mut out = [0u8; 4];
            let len = stash.ip_prefix_bytes.len().min(3);
            out[..len].copy_from_slice(&stash.ip_prefix_bytes[..len]);
            IpPrefix::V4(out)
        }
        2 => {
            let mut out = [0u8; 16];
            let len = stash.ip_prefix_bytes.len().min(8);
            out[..len].copy_from_slice(&stash.ip_prefix_bytes[..len]);
            IpPrefix::V6(out)
        }
        _ => return None,
    };
    Some(PendingEntry {
        kind,
        mode,
        route_id: stash.route_id.clone(),
        ip_prefix,
        return_url: stash.return_url.clone(),
        cookie_ttl_s: stash.cookie_ttl_s,
        expires_at: stash.expires_at,
    })
}

/// Decision returned by [`evaluate`]. `Pass` = forward to backend;
/// `Challenge` = render the challenge page.
#[derive(Debug, Clone)]
pub enum Decision {
    Pass {
        reason: PassReason,
    },
    Challenge,
}

/// Why a request passed the bot-protection stage. Logged at debug
/// and surfaced as the `reason` field on the
/// `lorica_bot_challenge_total{outcome="bypassed"}` or
/// `outcome="passed"` counter (story 3.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PassReason {
    /// Route has no `bot_protection` config; evaluation skipped.
    Disabled,
    /// Client presented a valid verdict cookie.
    ValidCookie,
    /// `only_country` gate: resolved country is NOT in the listed
    /// "challenge only these" set, so traffic passes through
    /// without even evaluating the bypass rules.
    OnlyCountryGateMiss,
    /// Bypass category matched: IP CIDR list.
    BypassIpCidr,
    /// Bypass category matched: ASN list.
    BypassAsn,
    /// Bypass category matched: forward-confirmed rDNS suffix list.
    BypassRdns,
    /// Bypass category matched: country list.
    BypassCountry,
    /// Bypass category matched: User-Agent regex list.
    BypassUserAgent,
}

impl PassReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PassReason::Disabled => "disabled",
            PassReason::ValidCookie => "cookie",
            PassReason::OnlyCountryGateMiss => "only_country_miss",
            PassReason::BypassIpCidr => "bypass_ip",
            PassReason::BypassAsn => "bypass_asn",
            PassReason::BypassRdns => "bypass_rdns",
            PassReason::BypassCountry => "bypass_country",
            PassReason::BypassUserAgent => "bypass_ua",
        }
    }
}

/// Inputs to the evaluator, bundled so the function signature stays
/// readable. All fields are borrowed — the evaluator never owns
/// state beyond what the caller provides.
pub struct EvalInputs<'a> {
    /// Parsed client IP (already through the trusted_proxies XFF
    /// unwrap upstream, if applicable).
    pub client_ip: std::net::IpAddr,
    /// Resolved ISO country from the GeoIP resolver. `None` when
    /// the DB is not loaded or the IP is outside any indexed
    /// prefix.
    pub country: Option<String>,
    /// Resolved Autonomous System Number from the ASN resolver.
    /// `None` when the ASN DB is not loaded or the IP is not
    /// indexed. Callers that do not need ASN bypass can pass
    /// `None` unconditionally - the evaluator just skips the
    /// ASN arm.
    pub asn: Option<u32>,
    /// Forward-confirmed rDNS name for the client IP. `Some(name)`
    /// = the hot-path cache returned a confirmed PTR; `None` = no
    /// cached result (cache miss, lookup in flight, or the IP
    /// simply has no PTR). Caller (request_filter) schedules an
    /// async populate for the NEXT request on a miss.
    pub rdns_name: Option<String>,
    /// Remote-verdict cache hit from the supervisor RPC cache
    /// (worker mode only). `Some(expires_at_secs)` = the RPC
    /// cache reported this cookie as Allow with the given expiry;
    /// evaluate() short-circuits to Pass::ValidCookie without
    /// running HMAC verify. `None` = RPC cache miss OR
    /// single-process mode (which uses the sync local cache
    /// inside `evaluate`).
    pub cached_cookie_hit: Option<i64>,
    /// Request `User-Agent` header value, if any. Empty string if
    /// the client did not send one.
    pub user_agent: &'a str,
    /// Incoming verdict cookie value (raw base64url string), if the
    /// client presented one. `None` = no cookie header or cookie
    /// with a different name.
    pub verdict_cookie: Option<&'a str>,
    /// Current UNIX timestamp in seconds. Injected for testability.
    pub now: i64,
    /// Pre-shared HMAC secret for cookie verify. Evaluator refuses
    /// to validate cookies when the secret slot is empty (early
    /// boot, mis-seeded config) — returns `Decision::Challenge` to
    /// play safe.
    pub hmac_secret: Option<&'a [u8; 32]>,
    /// The route's `id` (for cookie binding).
    pub route_id: &'a str,
    /// The route's `bot_protection` config.
    pub config: &'a lorica_config::models::BotProtectionConfig,
    /// Pre-compiled User-Agent regex set from RouteEntry. When `Some`,
    /// the evaluator uses `is_match` on the set instead of compiling
    /// patterns per-request. `None` falls back to per-pattern compile
    /// (backwards-compatible, but slower).
    pub ua_regex_set: Option<&'a regex::RegexSet>,
}

/// Evaluate bot-protection policy for a single request. Pure
/// decision function with no I/O — the caller owns request /
/// response machinery and the pending-challenge stash.
///
/// Order of checks (mirrors `docs/architecture/bot-protection.md`
/// § 6.3):
///
/// 1. Valid verdict cookie → pass.
/// 2. Bypass IP CIDRs → pass.
/// 3. Bypass countries → pass.
/// 4. Bypass User-Agent regexes → pass.
/// 5. `only_country` gate (if set) and country not in list → pass.
/// 6. Otherwise → challenge.
pub fn evaluate(inputs: &EvalInputs<'_>) -> Decision {
    // 1. Valid verdict cookie.
    if let Some(cookie) = inputs.verdict_cookie {
        let expected_prefix = IpPrefix::from_ip(inputs.client_ip);

        // 1a. Short-circuit via the RPC cache hit (worker mode) OR
        //     the per-process local cache (single-process mode).
        //     `cached_cookie_hit` is populated upstream by the
        //     request_filter when the RPC cache returned an Allow;
        //     `cache_check` is the sync local-cache path that
        //     single-process mode relies on.
        if let Some(expires_at) = inputs.cached_cookie_hit {
            if expires_at > inputs.now {
                return Decision::Pass {
                    reason: PassReason::ValidCookie,
                };
            }
        }
        if cache_check(inputs.route_id, &expected_prefix, cookie, inputs.now).is_some() {
            return Decision::Pass {
                reason: PassReason::ValidCookie,
            };
        }

        // 1b. Cache miss: fall through to the canonical HMAC verify
        //     path.
        if let Some(secret) = inputs.hmac_secret {
            if let Ok(payload) = lorica_challenge::cookie::verify(cookie, secret, inputs.now) {
                // Scope check: the cookie must bind to this route's id
                // AND the client's IP prefix must match the one the
                // cookie was minted for. Fails open to Challenge on
                // any mismatch so a stolen cookie cannot be replayed
                // across routes or across NAT gateways (cf. § 4.2 in
                // the design doc).
                let expected_route_bytes = route_id_bytes(inputs.route_id);
                if payload.route_id == expected_route_bytes
                    && payload.ip_prefix == expected_prefix
                {
                    // Seed the cache so the next request on the same
                    // triple short-circuits. Store the cookie's own
                    // `expires_at` so an entry never outlives the
                    // cookie itself.
                    cache_insert(
                        inputs.route_id,
                        &expected_prefix,
                        cookie,
                        payload.expires_at,
                    );
                    return Decision::Pass {
                        reason: PassReason::ValidCookie,
                    };
                }
            }
        }
    }

    // 2. IP CIDR bypass. Parse each entry lazily; malformed CIDRs
    //    are rejected at write time by `validate_bot_protection`,
    //    but we defensively skip bad ones here rather than panic.
    for raw in &inputs.config.bypass.ip_cidrs {
        if ip_matches_cidr(inputs.client_ip, raw) {
            return Decision::Pass {
                reason: PassReason::BypassIpCidr,
            };
        }
    }

    // 3. ASN bypass. Evaluated before country so an operator
    //    allow-listing all of Googlebot's ASN does not have to
    //    also allow-list the USA + IE + every other country the
    //    crawler operates out of.
    if let Some(client_asn) = inputs.asn {
        if inputs.config.bypass.asns.contains(&client_asn) {
            return Decision::Pass {
                reason: PassReason::BypassAsn,
            };
        }
    }

    // 4. Country bypass.
    if let Some(country) = inputs.country.as_deref() {
        if inputs
            .config
            .bypass
            .countries
            .iter()
            .any(|c| c.eq_ignore_ascii_case(country))
        {
            return Decision::Pass {
                reason: PassReason::BypassCountry,
            };
        }
    }

    // 3b. Forward-confirmed rDNS bypass. The forward-confirm
    //     happens upstream of the evaluator (in `bot_rdns`);
    //     we just match the confirmed name against the operator's
    //     suffix list here.
    if let Some(ref name) = inputs.rdns_name {
        if crate::bot_rdns::suffix_matches(name, &inputs.config.bypass.rdns) {
            return Decision::Pass {
                reason: PassReason::BypassRdns,
            };
        }
    }

    // 4. User-Agent regex bypass. When a pre-compiled RegexSet is
    //    available (built once at config-reload in RouteEntry), use
    //    it for O(1) match against all patterns. Falls back to
    //    per-pattern compile when the set is absent (test helpers).
    if !inputs.user_agent.is_empty() {
        if let Some(set) = inputs.ua_regex_set {
            if set.is_match(inputs.user_agent) {
                return Decision::Pass {
                    reason: PassReason::BypassUserAgent,
                };
            }
        } else {
            for pat in &inputs.config.bypass.user_agents {
                if regex::Regex::new(pat)
                    .map(|r| r.is_match(inputs.user_agent))
                    .unwrap_or(false)
                {
                    return Decision::Pass {
                        reason: PassReason::BypassUserAgent,
                    };
                }
            }
        }
    }

    // 5. `only_country` gate. When `Some(list)`, the challenge
    //    applies ONLY when the resolved country is in the list.
    //    Missing / None country with an active gate: conservative
    //    choice is to pass (the operator opted into "only these
    //    countries" which implies "the rest are trusted").
    if let Some(only) = inputs.config.only_country.as_ref() {
        let matches = inputs.country.as_deref().is_some_and(|c| {
            only.iter().any(|oc| oc.eq_ignore_ascii_case(c))
        });
        if !matches {
            return Decision::Pass {
                reason: PassReason::OnlyCountryGateMiss,
            };
        }
    }

    Decision::Challenge
}

/// Convert a route UUID string into the fixed 16-byte
/// representation that the cookie payload expects. Uses the low 16
/// bytes of a SHA-256 hash of the route id bytes so hyphenated UUID
/// strings and raw byte-form route ids both collapse to the same
/// shape, and a non-UUID route id (lorica accepts anything) also
/// fits in the slot.
pub fn route_id_bytes(route_id: &str) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(route_id.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Per-process cache of verified verdict cookies (story 3.6). A hit
/// short-circuits the cookie HMAC re-verification on repeat
/// requests from the same (route_id, client IP prefix, cookie
/// HMAC-tag) triple. Verification itself is already ~1 µs, but
/// bypassing it shaves the cost at steady state to a single hash-
/// map read + a timestamp compare (~50 ns). FIFO-bounded at 16 384
/// entries — same shape as `forward_auth::FORWARD_AUTH_VERDICT_CACHE`,
/// so the memory ceiling is deterministic and tiny.
///
/// This is the `Local` path of the cache. The worker-mode `Rpc`
/// path is layered on top in `proxy_wiring::request_filter`: the
/// request_filter calls [`rpc_cache_check`] BEFORE the sync
/// `evaluate()`, stashes any hit in `EvalInputs.cached_cookie_hit`,
/// and `evaluate()` short-circuits to Pass::ValidCookie on a hit
/// without touching the sync cache. On a miss that then HMAC-
/// verifies, the request_filter fire-and-forgets a push via
/// [`rpc_cache_push`]. This matches the design-doc § 3.6
/// requirement that bot verdict state propagates across workers
/// using the existing `VerdictCacheEngine::Rpc` plumbing — no new
/// RPC endpoint needed, the supervisor just stores opaque
/// (route_id, cookie) tuples and we flavour the route_id with a
/// `bot\0` prefix so our entries cannot collide with forward_auth's.
///
/// Cached value is the cookie's `expires_at` (seconds since UNIX
/// epoch). Lookup checks `expires_at > now` before accepting the
/// hit so an entry that ages past its cookie TTL is a cache miss
/// even before the FIFO eviction reclaims the slot.
const VERDICT_CACHE_CAP: usize = 16_384;

static VERDICT_CACHE: Lazy<DashMap<String, i64>> = Lazy::new(DashMap::new);

/// FIFO order list for the verdict cache. Same pattern as
/// `forward_auth::FORWARD_AUTH_VERDICT_ORDER`: key written on
/// every insert, oldest popped when the cache hits the cap.
static VERDICT_ORDER: Lazy<Mutex<std::collections::VecDeque<String>>> =
    Lazy::new(|| Mutex::new(std::collections::VecDeque::with_capacity(VERDICT_CACHE_CAP)));

/// Compose the verdict-cache key for a (route_id, ip_prefix, cookie
/// HMAC-tag) triple. NUL-separated so no sub-field can forge a
/// collision via crafted content. HMAC tag is the last 16 bytes of
/// the cookie's base64url wire format (since it appears at the
/// same fixed offset at the end of the pre-encoding payload, and
/// base64url-encoding it a second time has the same bytes as the
/// original cookie's tail). We just take the last 21 or 22 chars
/// of the cookie string — 21 for v4 IP (16 B tag = 22 base64url
/// chars, minus 1 pad-free adjustment = 21 or 22 depending on
/// alignment). Simpler: hash the cookie string itself into 16
/// bytes and use that as the tag stand-in.
fn verdict_cache_key(route_id: &str, ip_prefix: &IpPrefix, cookie: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(cookie.as_bytes());
    let tag = hasher.finalize();
    // 8 hex chars of the hash is ample to avoid collisions at our
    // 16 k cache capacity (probability << 2^-60).
    use std::fmt::Write;
    let prefix_bytes = ip_prefix.as_bytes();
    // Pre-allocate: route_id + \0 + prefix_hex + \0 + tag_hex(16 chars)
    let mut key = String::with_capacity(route_id.len() + 2 + prefix_bytes.len() * 2 + 16);
    key.push_str(route_id);
    key.push('\0');
    for b in prefix_bytes {
        let _ = write!(key, "{b:02x}");
    }
    key.push('\0');
    for b in tag.iter().take(8) {
        let _ = write!(key, "{b:02x}");
    }
    key
}

/// Return the cached `expires_at` for a verdict key if it is
/// present AND still valid per `now`. Returns `None` on cache miss
/// or on a stale entry (which is NOT evicted here — the next
/// verify's `cache_insert` does not touch the stale slot; the FIFO
/// reclaim will catch it eventually).
#[doc(hidden)]
pub fn cache_check(
    route_id: &str,
    ip_prefix: &IpPrefix,
    cookie: &str,
    now: i64,
) -> Option<i64> {
    let key = verdict_cache_key(route_id, ip_prefix, cookie);
    let expires = *VERDICT_CACHE.get(&key)?;
    if expires > now {
        Some(expires)
    } else {
        None
    }
}

/// Insert a verified cookie into the cache. Called from the hot
/// path immediately after `lorica_challenge::cookie::verify`
/// succeeds. The FIFO eviction mirrors forward_auth's implementation
/// so future cleanup (when both caches move to a shared helper)
/// stays trivial.
pub(crate) fn cache_insert(
    route_id: &str,
    ip_prefix: &IpPrefix,
    cookie: &str,
    expires_at: i64,
) {
    let key = verdict_cache_key(route_id, ip_prefix, cookie);
    let mut order = VERDICT_ORDER.lock();
    while order.len() >= VERDICT_CACHE_CAP {
        if let Some(old) = order.pop_front() {
            VERDICT_CACHE.remove(&old);
        } else {
            break;
        }
    }
    order.push_back(key.clone());
    drop(order);
    VERDICT_CACHE.insert(key, expires_at);
}

/// Clear the process-wide verdict cache. Used by unit tests to
/// isolate cache state between test cases, and reserved for a
/// future "revoke all cookies" operator action on the dashboard.
#[doc(hidden)]
pub(crate) fn cache_reset_for_test() {
    VERDICT_CACHE.clear();
    VERDICT_ORDER.lock().clear();
}

/// Flavour a route_id for the cross-worker bot verdict cache. The
/// `bot\0` prefix partitions our entries from forward_auth's on the
/// shared supervisor cache. The IP prefix is folded in so different
/// NATs never collide.
fn rpc_verdict_route_id(route_id: &str, ip_prefix: &IpPrefix) -> String {
    use std::fmt::Write;
    let prefix_bytes = ip_prefix.as_bytes();
    let mut key = String::with_capacity(4 + route_id.len() + 1 + prefix_bytes.len() * 2);
    key.push_str("bot\0");
    key.push_str(route_id);
    key.push('\0');
    for b in prefix_bytes {
        let _ = write!(key, "{b:02x}");
    }
    key
}

/// RPC cache lookup (worker mode). Delegates to the supervisor's
/// verdict cache via the existing `VerdictLookup` wire protocol.
/// The supervisor is oblivious to bot-vs-forward_auth — the
/// `bot\0` route_id prefix is enough to partition namespaces. Returns
/// the cached cookie's `expires_at` in seconds on Allow-hit, `None`
/// on miss or any RPC failure (fail-open: a flaky supervisor
/// connection must never DoS the data plane).
pub async fn rpc_cache_check(
    engine: &crate::proxy_wiring::VerdictCacheEngine,
    route_id: &str,
    ip_prefix: &IpPrefix,
    cookie: &str,
    now_secs: i64,
) -> Option<i64> {
    use crate::proxy_wiring::VerdictCacheEngine;
    let key_route = rpc_verdict_route_id(route_id, ip_prefix);
    match engine {
        // Local path is handled inside `evaluate()` via the sync
        // `cache_check` helper — the request_filter should call
        // this function only when it knows the engine is `Rpc`.
        // For completeness we also honour `Local` here by
        // delegating to the sync path.
        VerdictCacheEngine::Local => cache_check(route_id, ip_prefix, cookie, now_secs),
        VerdictCacheEngine::Rpc { endpoint, timeout } => {
            let payload = lorica_command::command::Payload::VerdictLookup(
                lorica_command::VerdictLookup {
                    route_id: key_route,
                    cookie: cookie.to_string(),
                },
            );
            let resp = endpoint
                .request_rpc(lorica_command::CommandType::VerdictLookup, payload, *timeout)
                .await
                .ok()?;
            let lorica_command::response::Payload::VerdictResult(v) = resp.payload? else {
                return None;
            };
            if !v.found
                || lorica_command::Verdict::from_i32(v.verdict)
                    != lorica_command::Verdict::Allow
            {
                return None;
            }
            // The supervisor returns remaining TTL in ms; convert
            // to absolute `expires_at` in seconds so the caller
            // compares against `now_secs` uniformly.
            Some(now_secs + (v.ttl_ms as i64) / 1000)
        }
    }
}

/// RPC cache push (worker mode). Fire-and-forget: a failed push
/// just means the next request re-runs HMAC verify, which is the
/// same as a miss.
pub async fn rpc_cache_push(
    engine: &crate::proxy_wiring::VerdictCacheEngine,
    route_id: &str,
    ip_prefix: &IpPrefix,
    cookie: &str,
    expires_at: i64,
    now_secs: i64,
) {
    use crate::proxy_wiring::VerdictCacheEngine;
    let key_route = rpc_verdict_route_id(route_id, ip_prefix);
    match engine {
        VerdictCacheEngine::Local => {
            cache_insert(route_id, ip_prefix, cookie, expires_at);
        }
        VerdictCacheEngine::Rpc { endpoint, timeout } => {
            let ttl_ms = ((expires_at - now_secs).max(0) * 1000) as u64;
            let payload = lorica_command::command::Payload::VerdictPush(
                lorica_command::VerdictPush {
                    route_id: key_route,
                    cookie: cookie.to_string(),
                    verdict: lorica_command::Verdict::Allow as i32,
                    // Bot verdicts carry no response headers — the
                    // cookie IS the verdict. Empty vec keeps the
                    // wire payload minimal.
                    response_headers: Vec::<lorica_command::ForwardAuthHeader>::new(),
                    ttl_ms,
                },
            );
            let _ = endpoint
                .request_rpc(lorica_command::CommandType::VerdictPush, payload, *timeout)
                .await;
        }
    }
}

/// Check whether `ip` matches a CIDR string. Accepts both bare IPs
/// (treated as /32 or /128) and `addr/len` forms. Returns false on
/// any parse error — validator-enforced input should never fail to
/// parse here, so a false from a non-empty config is a "wasn't
/// actually a match" signal, not a data-shape problem.
fn ip_matches_cidr(ip: std::net::IpAddr, cidr: &str) -> bool {
    let trimmed = cidr.trim();
    if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
        return net.contains(&ip);
    }
    if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
        return addr == ip;
    }
    false
}

/// Extract the verdict cookie value from a `Cookie:` header. Scans
/// for `lorica_bot_verdict=<value>` with tolerant whitespace
/// handling — different browsers space the cookie separators
/// differently (`; ` vs `;`). Returns the FIRST match (RFC 6265
/// leaves "same-name duplicates" implementation-defined; first-
/// wins matches how most servers treat it).
pub fn extract_verdict_cookie(cookie_header: &str) -> Option<&str> {
    for pair in cookie_header.split(';') {
        let pair = pair.trim_start();
        if let Some(rest) = pair.strip_prefix(VERDICT_COOKIE_NAME) {
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{
        BotBypassRules, BotProtectionConfig, BotProtectionMode,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn cfg() -> BotProtectionConfig {
        BotProtectionConfig {
            mode: BotProtectionMode::Javascript,
            cookie_ttl_s: 86_400,
            pow_difficulty: 14,
            captcha_alphabet: "abcdefghijklmnop".to_string(),
            bypass: BotBypassRules::default(),
            only_country: None,
        }
    }

    fn inputs<'a>(c: &'a BotProtectionConfig, ua: &'a str) -> EvalInputs<'a> {
        EvalInputs {
            client_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42)),
            country: Some("FR".to_string()),
            asn: None,
            rdns_name: None,
            user_agent: ua,
            verdict_cookie: None,
            now: 1_700_000_000,
            hmac_secret: None,
            route_id: "route-abc",
            config: c,
            cached_cookie_hit: None,
            ua_regex_set: None,
        }
    }

    #[test]
    fn paths_are_recognised() {
        assert!(is_bot_solve_path("/lorica/bot/solve"));
        assert!(is_bot_solve_path("/lorica/bot/solve?x=1"));
        assert!(!is_bot_solve_path("/lorica/bot/solve/extra"));
        assert!(!is_bot_solve_path("/other"));

        assert_eq!(
            parse_bot_captcha_path("/lorica/bot/captcha/abc123"),
            Some("abc123")
        );
        assert_eq!(
            parse_bot_captcha_path("/lorica/bot/captcha/abc123?t=1"),
            Some("abc123")
        );
        assert_eq!(parse_bot_captcha_path("/lorica/bot/captcha/"), None);
        assert_eq!(
            parse_bot_captcha_path("/lorica/bot/captcha/a/b"),
            None,
            "path traversal must not escape the lookup"
        );
        assert_eq!(parse_bot_captcha_path("/other"), None);
    }

    #[test]
    fn extract_cookie_handles_whitespace_variants() {
        assert_eq!(
            extract_verdict_cookie("lorica_bot_verdict=abc"),
            Some("abc")
        );
        assert_eq!(
            extract_verdict_cookie("session=xyz; lorica_bot_verdict=abc"),
            Some("abc")
        );
        assert_eq!(
            extract_verdict_cookie("session=xyz;lorica_bot_verdict=abc"),
            Some("abc")
        );
        assert_eq!(extract_verdict_cookie("session=xyz"), None);
        // No stray "lorica_bot_verdictX=..." match.
        assert_eq!(
            extract_verdict_cookie("lorica_bot_verdictX=abc"),
            None
        );
    }

    #[test]
    fn evaluate_challenges_on_bare_config() {
        let c = cfg();
        let i = inputs(&c, "Mozilla/5.0");
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn bypass_ip_cidr_matches() {
        let mut c = cfg();
        c.bypass.ip_cidrs = vec!["203.0.113.0/24".to_string()];
        let i = inputs(&c, "Mozilla/5.0");
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::BypassIpCidr),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bypass_asn_matches() {
        let mut c = cfg();
        c.bypass.asns = vec![15169, 8075];
        let mut i = inputs(&c, "");
        i.asn = Some(15169);
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::BypassAsn),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bypass_asn_no_db_loaded_falls_through() {
        // When the ASN resolver has no DB loaded, `inputs.asn` is
        // None and the config's asn list must not match — the
        // evaluator skips straight to the remaining categories.
        let mut c = cfg();
        c.bypass.asns = vec![15169];
        let i = inputs(&c, "Mozilla/5.0"); // asn = None per default
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn bypass_rdns_matches_forward_confirmed_name() {
        let mut c = cfg();
        c.bypass.rdns = vec!["googlebot.com".to_string()];
        let mut i = inputs(&c, "");
        i.rdns_name = Some("crawl-123.googlebot.com".to_string());
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::BypassRdns),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bypass_rdns_ignores_unconfirmed_lookup() {
        // When the request filter could not cache a forward-
        // confirmed name (miss, or lookup in flight), rdns_name
        // stays None — the evaluator must NOT grant the bypass.
        let mut c = cfg();
        c.bypass.rdns = vec!["googlebot.com".to_string()];
        let i = inputs(&c, ""); // rdns_name = None per default
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn bypass_rdns_rejects_sibling_host() {
        // Forward-confirmed name `fakegooglebot.com` does NOT
        // match `googlebot.com`. This is the exact attack the
        // suffix-matching anchor guards against.
        let mut c = cfg();
        c.bypass.rdns = vec!["googlebot.com".to_string()];
        let mut i = inputs(&c, "");
        i.rdns_name = Some("fakegooglebot.com".to_string());
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn bypass_country_matches_case_insensitive() {
        let mut c = cfg();
        c.bypass.countries = vec!["fr".to_string()];
        let i = inputs(&c, "Mozilla/5.0");
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::BypassCountry),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bypass_user_agent_regex_matches() {
        let mut c = cfg();
        c.bypass.user_agents = vec![r"(?i)mozilla/5\.0".to_string()];
        let i = inputs(&c, "Mozilla/5.0 (compatible; Bot/1.0)");
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::BypassUserAgent),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_country_gate_passes_non_listed_country() {
        let mut c = cfg();
        c.only_country = Some(vec!["US".to_string()]);
        // Client is in FR, list says only US → pass.
        let i = inputs(&c, "");
        match evaluate(&i) {
            Decision::Pass { reason } => {
                assert_eq!(reason, PassReason::OnlyCountryGateMiss);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_country_gate_challenges_listed_country() {
        let mut c = cfg();
        c.only_country = Some(vec!["FR".to_string()]);
        let i = inputs(&c, "");
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn only_country_passes_when_country_unknown() {
        let mut c = cfg();
        c.only_country = Some(vec!["US".to_string()]);
        let mut i = inputs(&c, "");
        i.country = None;
        match evaluate(&i) {
            Decision::Pass { reason } => {
                assert_eq!(reason, PassReason::OnlyCountryGateMiss);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn valid_cookie_passes() {
        use lorica_challenge::cookie::{sign, Payload};

        let secret = [0x55u8; 32];
        let route_id = "route-abc";
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let ip_prefix = IpPrefix::from_ip(ip);
        let payload = Payload {
            route_id: route_id_bytes(route_id),
            ip_prefix,
            expires_at: 1_700_000_000 + 86_400,
            mode: Mode::Javascript,
        };
        let cookie = sign(&payload, &secret).unwrap();

        let c = cfg();
        let mut i = inputs(&c, "");
        i.hmac_secret = Some(&secret);
        i.verdict_cookie = Some(&cookie);

        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::ValidCookie),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cookie_for_wrong_route_does_not_pass() {
        use lorica_challenge::cookie::{sign, Payload};

        let secret = [0x55u8; 32];
        let payload = Payload {
            route_id: route_id_bytes("DIFFERENT-ROUTE"),
            ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42))),
            expires_at: 1_700_000_000 + 86_400,
            mode: Mode::Javascript,
        };
        let cookie = sign(&payload, &secret).unwrap();

        let c = cfg();
        let mut i = inputs(&c, "");
        i.hmac_secret = Some(&secret);
        i.verdict_cookie = Some(&cookie);

        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn cookie_for_wrong_ip_prefix_does_not_pass() {
        use lorica_challenge::cookie::{sign, Payload};

        let secret = [0x55u8; 32];
        let payload = Payload {
            route_id: route_id_bytes("route-abc"),
            // /24 = 198.51.100.0/24 which is a *different* /24 from
            // the client's 203.0.113.42.
            ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            expires_at: 1_700_000_000 + 86_400,
            mode: Mode::Javascript,
        };
        let cookie = sign(&payload, &secret).unwrap();

        let c = cfg();
        let mut i = inputs(&c, "");
        i.hmac_secret = Some(&secret);
        i.verdict_cookie = Some(&cookie);

        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[tokio::test]
    async fn engine_stash_roundtrip() {
        let e = BotEngine::new();
        let nonce = e.fresh_nonce();
        assert_eq!(nonce.len(), 32, "hex of 16 bytes = 32 chars");

        e.insert(
            nonce.clone(),
            PendingEntry {
                kind: Pending::Pow {
                    nonce_hex: "deadbeef".to_string(),
                    difficulty: 14,
                },
                mode: Mode::Javascript,
                route_id: "r".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                return_url: "/".to_string(),
                cookie_ttl_s: 86_400,
                expires_at: 4_000_000_000,
            },
        )
        .await;
        assert_eq!(e.len().await, 1);
        let taken = e.take(&nonce).await.expect("round-trip");
        assert!(matches!(taken.kind, Pending::Pow { .. }));
        assert_eq!(e.len().await, 0, "take() must remove the entry");
        assert!(
            e.take(&nonce).await.is_none(),
            "second take is None (no replay)"
        );
    }

    #[tokio::test]
    async fn engine_captcha_image_only_for_captcha_entries() {
        let e = BotEngine::new();
        let nonce = "abc".to_string();
        e.insert(
            nonce.clone(),
            PendingEntry {
                kind: Pending::Captcha {
                    expected_text: "xyz".to_string(),
                    png_bytes: vec![1, 2, 3],
                },
                mode: Mode::Captcha,
                route_id: "r".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                return_url: "/".to_string(),
                cookie_ttl_s: 86_400,
                expires_at: 4_000_000_000,
            },
        )
        .await;
        assert_eq!(e.captcha_image("abc").await, Some(vec![1, 2, 3]));
        assert_eq!(e.captcha_image("nope").await, None);
        // Image fetch does NOT consume the entry.
        assert_eq!(e.len().await, 1);
    }

    #[tokio::test]
    async fn engine_prune_evicts_expired() {
        let e = BotEngine::new();
        e.insert(
            "keep".to_string(),
            PendingEntry {
                kind: Pending::Pow {
                    nonce_hex: "".to_string(),
                    difficulty: 14,
                },
                mode: Mode::Javascript,
                route_id: "r".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                return_url: "/".to_string(),
                cookie_ttl_s: 86_400,
                expires_at: 2_000_000_000,
            },
        )
        .await;
        e.insert(
            "drop".to_string(),
            PendingEntry {
                kind: Pending::Pow {
                    nonce_hex: "".to_string(),
                    difficulty: 14,
                },
                mode: Mode::Javascript,
                route_id: "r".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                return_url: "/".to_string(),
                cookie_ttl_s: 86_400,
                expires_at: 1_000_000_000,
            },
        )
        .await;
        e.prune_expired(1_500_000_000).await;
        assert_eq!(e.len().await, 1);
        assert!(e.take("keep").await.is_some());
        assert!(e.take("drop").await.is_none());
    }

    // SQLite-backed round-trip: an entry stashed through the SQL
    // backend must round-trip with the same fields, and `take`
    // must be atomic (second call returns None). Uses an
    // in-memory ConfigStore so the test runs without touching
    // the filesystem.
    #[tokio::test]
    async fn sqlite_backend_roundtrip() {
        use std::sync::Arc as StdArc;
        let store = StdArc::new(tokio::sync::Mutex::new(
            lorica_config::ConfigStore::open_in_memory().unwrap(),
        ));
        let e = BotEngine::with_sqlite(store);
        let nonce = "sql-nonce".to_string();
        e.insert(
            nonce.clone(),
            PendingEntry {
                kind: Pending::Pow {
                    nonce_hex: "cafebabe".to_string(),
                    difficulty: 18,
                },
                mode: Mode::Javascript,
                route_id: "r-sql".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                return_url: "/back".to_string(),
                cookie_ttl_s: 86_400,
                expires_at: 2_000_000_000,
            },
        )
        .await;
        assert_eq!(e.len().await, 1);
        let taken = e.take(&nonce).await.expect("round-trip");
        match taken.kind {
            Pending::Pow {
                nonce_hex,
                difficulty,
            } => {
                assert_eq!(nonce_hex, "cafebabe");
                assert_eq!(difficulty, 18);
            }
            other => panic!("wrong kind: {other:?}"),
        }
        assert_eq!(taken.route_id, "r-sql");
        assert_eq!(taken.return_url, "/back");
        // Second take returns None — replay defence.
        assert!(e.take(&nonce).await.is_none());
    }

    #[tokio::test]
    async fn sqlite_backend_captcha_png_roundtrip() {
        use std::sync::Arc as StdArc;
        let store = StdArc::new(tokio::sync::Mutex::new(
            lorica_config::ConfigStore::open_in_memory().unwrap(),
        ));
        let e = BotEngine::with_sqlite(store);
        e.insert(
            "png-nonce".to_string(),
            PendingEntry {
                kind: Pending::Captcha {
                    expected_text: "ABC123".to_string(),
                    png_bytes: vec![0x89, b'P', b'N', b'G'],
                },
                mode: Mode::Captcha,
                route_id: "r".to_string(),
                ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                return_url: "/".to_string(),
                cookie_ttl_s: 3600,
                expires_at: 2_000_000_000,
            },
        )
        .await;
        // Image lookup returns the PNG bytes without consuming.
        assert_eq!(
            e.captcha_image("png-nonce").await,
            Some(vec![0x89, b'P', b'N', b'G'])
        );
        // Still present after image fetch.
        assert_eq!(e.len().await, 1);
        // Take round-trips the expected_text AND re-attaches the
        // PNG bytes (they live in their own column).
        let taken = e.take("png-nonce").await.unwrap();
        match taken.kind {
            Pending::Captcha {
                expected_text,
                png_bytes,
            } => {
                assert_eq!(expected_text, "ABC123");
                assert_eq!(png_bytes, vec![0x89, b'P', b'N', b'G']);
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }

    #[test]
    fn ip_matches_cidr_works() {
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        assert!(ip_matches_cidr(v4, "203.0.113.0/24"));
        assert!(!ip_matches_cidr(v4, "203.0.114.0/24"));
        assert!(ip_matches_cidr(v4, "203.0.113.42"));
        assert!(!ip_matches_cidr(v4, "203.0.113.43"));
        assert!(!ip_matches_cidr(v4, "garbage"));
    }

    #[test]
    fn verdict_cache_hit_skips_hmac_verify() {
        cache_reset_for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let prefix = IpPrefix::from_ip(ip);
        let cookie = "fake-cookie-string";
        let route_id = "route-cache-test";
        let now = 1_700_000_000;
        // Seed the cache as if a prior verify succeeded.
        cache_insert(route_id, &prefix, cookie, now + 3600);

        // Evaluate with NO hmac_secret. Without the cache, the
        // cookie branch would skip entirely; WITH the cache hit,
        // evaluate returns Pass::ValidCookie.
        let c = cfg();
        let i = EvalInputs {
            client_ip: ip,
            country: None,
            asn: None,
            rdns_name: None,
            user_agent: "",
            verdict_cookie: Some(cookie),
            now,
            hmac_secret: None,
            route_id,
            config: &c,
            cached_cookie_hit: None,
            ua_regex_set: None,
        };
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::ValidCookie),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rpc_cached_cookie_hit_short_circuits_evaluate() {
        // Worker mode: `cached_cookie_hit` set upstream by the
        // request_filter (after a VerdictLookup hit). evaluate()
        // MUST skip the HMAC verify path entirely and return
        // Pass::ValidCookie.
        let c = cfg();
        let mut i = inputs(&c, "");
        i.verdict_cookie = Some("any-cookie-string");
        i.cached_cookie_hit = Some(i.now + 3600);
        match evaluate(&i) {
            Decision::Pass { reason } => assert_eq!(reason, PassReason::ValidCookie),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rpc_cached_cookie_hit_expired_is_ignored() {
        // Stale cached hit (expires_at < now) must NOT short-
        // circuit. Evaluator falls through to the sync local cache
        // / HMAC verify path.
        let c = cfg();
        let mut i = inputs(&c, "");
        i.verdict_cookie = Some("any-cookie-string");
        i.cached_cookie_hit = Some(i.now - 10);
        // No HMAC secret, cookie won't verify through the fallback
        // path, so the evaluator must return Challenge.
        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn rpc_verdict_route_id_flavours_bot_prefix() {
        // The `bot\0` prefix ensures our RPC cache entries cannot
        // collide with forward_auth entries on the shared
        // supervisor cache. The IP prefix is folded in so two
        // clients behind different NAT gateways never share a
        // cache entry even with the same cookie.
        use std::net::{IpAddr, Ipv4Addr};
        let p1 = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let p2 = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        let a = rpc_verdict_route_id("r", &p1);
        let b = rpc_verdict_route_id("r", &p2);
        assert_ne!(a, b);
        assert!(a.starts_with("bot\0r\0"));
    }

    #[test]
    fn verdict_cache_expired_entry_is_miss() {
        cache_reset_for_test();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let prefix = IpPrefix::from_ip(ip);
        let cookie = "stale-cookie";
        let route_id = "route-cache-test-2";
        // expires_at = 1000, now = 2000 → entry is past expiry.
        cache_insert(route_id, &prefix, cookie, 1000);

        assert!(cache_check(route_id, &prefix, cookie, 2000).is_none());
    }

    #[test]
    fn verdict_cache_key_differs_per_scope() {
        // The cache key MUST differ across (route, ip prefix, cookie)
        // triples so one route's verdict never pollutes another
        // route's lookup.
        let p1 = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let p2 = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
        let k1 = verdict_cache_key("r1", &p1, "cookie");
        let k2 = verdict_cache_key("r2", &p1, "cookie");
        let k3 = verdict_cache_key("r1", &p2, "cookie");
        let k4 = verdict_cache_key("r1", &p1, "different-cookie");
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k1, k4);
    }

    #[test]
    fn verdict_cache_fifo_evicts_oldest_when_full() {
        cache_reset_for_test();
        // Insert one more than the cap; the first entry must be
        // gone on the next check.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = IpPrefix::from_ip(ip);
        for i in 0..(VERDICT_CACHE_CAP + 10) {
            let cookie = format!("cookie-{i}");
            cache_insert("route", &prefix, &cookie, 2_000_000_000);
        }
        // The very first `cookie-0` is out by now.
        assert!(cache_check("route", &prefix, "cookie-0", 1_900_000_000).is_none());
        // A recent one still hits.
        let last = format!("cookie-{}", VERDICT_CACHE_CAP + 9);
        assert!(cache_check("route", &prefix, &last, 1_900_000_000).is_some());
    }
}
