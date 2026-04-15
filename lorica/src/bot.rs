// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Bot-protection request-filter integration (v1.4.0 Epic 3, story
//! 3.5).
//!
//! Two things live here:
//!
//! 1. [`BotEngine`] — the in-process pending-challenge stash. Keyed
//!    by a server-side nonce (separate from the PoW nonce to keep
//!    the two namespaces orthogonal). An entry is consumed on the
//!    first verify attempt regardless of outcome so a failed
//!    solution cannot be replayed against the same challenge.
//!    Captcha challenges additionally hold the PNG bytes the image
//!    handler serves at `/lorica/bot/captcha/{nonce}`.
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

use lorica_challenge::{IpPrefix, Mode};
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

/// In-process stash of pending challenges. No cross-worker sharing
/// in v1.4.0 — a client that solves a challenge on one worker and
/// hits a different worker for the POST just gets a fresh challenge
/// (the first solve becomes a wasted round trip, which is a minor
/// UX cost). Cross-worker sharing via `VerdictCacheEngine::Rpc`
/// lands in story 3.6.
///
/// Thread safety: the map is guarded by a `parking_lot::Mutex`. Every
/// operation is O(1) in expectation so contention is minimal. A
/// sharded approach (DashMap) is premature at the current cardinality
/// — a busy proxy sees ~1000 pending challenges at steady state,
/// which one mutex handles trivially.
pub struct BotEngine {
    entries: Mutex<HashMap<String, PendingEntry>>,
}

impl BotEngine {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a fresh 16-byte hex nonce for a new pending
    /// challenge. Uses `OsRng` so the nonces are
    /// unpredictable-to-the-attacker; a predictable nonce would let
    /// an attacker pre-register a matching entry and bypass the
    /// verify step.
    pub fn fresh_nonce(&self) -> String {
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let mut out = String::with_capacity(32);
        for b in raw.iter() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// Stash a pending challenge. Overwrites any prior entry with
    /// the same nonce (nonces are 128-bit random, so a collision is
    /// a ~2^-128 event — in practice "never" — but preferring
    /// overwrite over reject keeps the request path deterministic).
    pub fn insert(&self, nonce: String, entry: PendingEntry) {
        let mut guard = self.entries.lock();
        guard.insert(nonce, entry);
    }

    /// Atomically remove + return a pending entry. Called from the
    /// submit handler so the entry is gone from the stash regardless
    /// of whether the solution verifies. Replay defence: a single
    /// stashed challenge can be verified at most once.
    pub fn take(&self, nonce: &str) -> Option<PendingEntry> {
        self.entries.lock().remove(nonce)
    }

    /// Read-only access to the PNG bytes for the captcha image
    /// handler. Does NOT consume the entry (the user may reload
    /// the image while still deciding on the answer). Returns
    /// `None` for non-captcha entries too, so a PoW nonce probed
    /// at `/lorica/bot/captcha/{nonce}` gives a 404.
    pub fn captcha_image(&self, nonce: &str) -> Option<Vec<u8>> {
        let guard = self.entries.lock();
        let entry = guard.get(nonce)?;
        match &entry.kind {
            Pending::Captcha { png_bytes, .. } => Some(png_bytes.clone()),
            _ => None,
        }
    }

    /// Evict stashed entries whose `expires_at` is in the past.
    /// Called opportunistically from the challenge-render path so
    /// a bot probing for unknown nonces does not pay the GC cost.
    /// A dedicated background task could take over if the eviction
    /// budget ever becomes noticeable in prod telemetry.
    pub fn prune_expired(&self, now: i64) {
        self.entries.lock().retain(|_, e| e.expires_at > now);
    }

    /// Snapshot count, for metrics / tests. Does not clone the
    /// entries.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

impl Default for BotEngine {
    fn default() -> Self {
        Self::new()
    }
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
    if let (Some(cookie), Some(secret)) = (inputs.verdict_cookie, inputs.hmac_secret) {
        if let Ok(payload) = lorica_challenge::cookie::verify(cookie, secret, inputs.now) {
            // Scope check: the cookie must bind to this route's id
            // AND the client's IP prefix must match the one the
            // cookie was minted for. Fails open to Challenge on any
            // mismatch so a stolen cookie cannot be replayed across
            // routes or across NAT gateways (cf. § 4.2 in the
            // design doc).
            let expected_route_bytes = route_id_bytes(inputs.route_id);
            let expected_prefix = IpPrefix::from_ip(inputs.client_ip);
            if payload.route_id == expected_route_bytes && payload.ip_prefix == expected_prefix
            {
                return Decision::Pass {
                    reason: PassReason::ValidCookie,
                };
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

    // 3. Country bypass.
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

    // 4. User-Agent regex bypass. Pattern compilation was already
    //    validated at write time; compiling per-evaluation here is
    //    ~200 ns per pattern on x86 and acceptable at the scale we
    //    run (bounded at 500 patterns max, typically <10 in prod).
    //    A future optimisation can cache a compiled Regex alongside
    //    the config, but the current shape keeps state minimal.
    if !inputs.user_agent.is_empty() {
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
            user_agent: ua,
            verdict_cookie: None,
            now: 1_700_000_000,
            hmac_secret: None,
            route_id: "route-abc",
            config: c,
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
        let cookie = sign(&payload, &secret);

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
        let cookie = sign(&payload, &secret);

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
        let cookie = sign(&payload, &secret);

        let c = cfg();
        let mut i = inputs(&c, "");
        i.hmac_secret = Some(&secret);
        i.verdict_cookie = Some(&cookie);

        assert!(matches!(evaluate(&i), Decision::Challenge));
    }

    #[test]
    fn engine_stash_roundtrip() {
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
                expires_at: 1_700_000_300,
            },
        );
        assert_eq!(e.len(), 1);
        let taken = e.take(&nonce).expect("round-trip");
        assert!(matches!(taken.kind, Pending::Pow { .. }));
        assert_eq!(e.len(), 0, "take() must remove the entry");
        assert!(e.take(&nonce).is_none(), "second take is None (no replay)");
    }

    #[test]
    fn engine_captcha_image_only_for_captcha_entries() {
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
                expires_at: 1_700_000_300,
            },
        );
        assert_eq!(e.captcha_image("abc"), Some(vec![1, 2, 3]));
        assert_eq!(e.captcha_image("nope"), None);
        // Image fetch does NOT consume the entry.
        assert_eq!(e.len(), 1);
    }

    #[test]
    fn engine_prune_evicts_expired() {
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
        );
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
        );
        e.prune_expired(1_500_000_000);
        assert_eq!(e.len(), 1);
        assert!(e.take("keep").is_some());
        assert!(e.take("drop").is_none());
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
}
