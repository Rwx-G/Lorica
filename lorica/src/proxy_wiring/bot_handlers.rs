// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Session-level handlers for the bot-protection endpoints and the
//! challenge-render path. Lives in `proxy_wiring` because the code
//! here owns the `Session` type from `lorica-proxy`; the decision
//! engine itself is in `lorica::bot` and has no session dep.
//!
//! Three response paths:
//! 1. `POST /lorica/bot/solve` → [`handle_solve`]: parse form body,
//!    take the stashed pending entry, verify mode-specific, mint
//!    verdict cookie, 302 to the return URL.
//! 2. `GET /lorica/bot/captcha/{nonce}` → [`handle_captcha_image`]:
//!    look up PNG by nonce, serve as `image/png`.
//! 3. Challenge render on a route with `bot_protection` and no
//!    valid cookie → [`serve_challenge`]: stash a pending entry,
//!    render HTML, write response.
//!
//! Each handler returns `Ok(true)` to tell the caller "response
//! written, stop the filter pipeline" (the `request_filter`
//! convention in `lorica_proxy::ProxyHttp`).

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use lorica_challenge::{cookie, pow, render as chrender, IpPrefix, Mode};
use lorica_config::models::{BotProtectionConfig, BotProtectionMode};
use lorica_http::ResponseHeader;
use lorica_proxy::Session;
use tracing::{debug, info, warn};

use crate::bot::{
    route_id_bytes, BotEngine, Pending, PendingEntry, BOT_CAPTCHA_PATH_PREFIX, BOT_SOLVE_PATH,
    VERDICT_COOKIE_NAME,
};

/// Upper bound on the POST body we read on `/lorica/bot/solve`.
/// A legitimate submission carries ~80 bytes (nonce + counter or
/// nonce + short answer); 2 KiB leaves generous headroom for a
/// future extension (multi-field solution, etc.) without letting a
/// malicious POST wedge the parser with a multi-megabyte body.
const MAX_SOLVE_BODY_BYTES: usize = 2048;

/// How long a pending challenge lives in the stash. Matches the
/// default PoW challenge TTL; captcha reuses the same window so
/// a user can read-type-submit well inside it.
const PENDING_TTL_S: u64 = 300;

/// Handle `POST /lorica/bot/solve`. Returns `Ok(true)` when the
/// handler has written a full response (regardless of verdict —
/// successful verify writes 302, failed verify writes 403). The
/// caller stops the filter pipeline.
pub async fn handle_solve(
    session: &mut Session,
    engine: &BotEngine,
    secret: Option<&[u8; 32]>,
    client_ip: std::net::IpAddr,
    now: i64,
) -> lorica_core::Result<bool> {
    let method = session.req_header().method.clone();
    if method != http::Method::POST {
        return write_plain(session, 405, "POST required").await;
    }

    let body = match read_bounded_body(session, MAX_SOLVE_BODY_BYTES).await {
        Ok(b) => b,
        Err(reason) => {
            warn!(reason, "bot-solve: body read rejected");
            return write_plain(session, 413, "request body too large").await;
        }
    };

    let form = parse_form_urlencoded(&body);
    let Some(nonce) = form.get("nonce") else {
        return write_plain(session, 400, "missing nonce").await;
    };

    let Some(entry) = engine.take(nonce).await else {
        // No stashed pending challenge. Either expired / already
        // consumed (replay attempt) or never existed. The response
        // does not distinguish the two so a scanner cannot probe
        // for valid nonces.
        debug!(nonce = %nonce, "bot-solve: no stashed entry for nonce");
        return write_plain(session, 403, "challenge expired or unknown").await;
    };

    // Expiry guard. The engine's `take` already pulled the entry,
    // so even an expired one is gone from the stash now.
    if now > entry.expires_at {
        debug!("bot-solve: pending entry was past its expires_at at verify time");
        return write_plain(session, 403, "challenge expired").await;
    }

    // Scope check: the submitting client's IP prefix must match the
    // prefix the challenge was minted for. Prevents a lifted cookie
    // across NAT gateways (cf. design doc § 4.2).
    let now_prefix = IpPrefix::from_ip(client_ip);
    if now_prefix != entry.ip_prefix {
        return write_plain(
            session,
            403,
            "client network changed since challenge was issued",
        )
        .await;
    }

    // Dispatch by mode.
    let verdict = match &entry.kind {
        Pending::Pow {
            nonce_hex,
            difficulty,
        } => {
            let Some(counter_str) = form.get("counter") else {
                return write_plain(session, 400, "missing counter").await;
            };
            let Ok(counter) = counter_str.parse::<u64>() else {
                return write_plain(session, 400, "counter is not a u64").await;
            };
            pow::verify_solution(
                nonce_hex,
                counter,
                now as u64,
                *difficulty,
                entry.expires_at as u64,
            )
        }
        Pending::Captcha { expected_text, .. } => {
            let Some(answer) = form.get("answer") else {
                return write_plain(session, 400, "missing answer").await;
            };
            lorica_challenge::captcha::verify(answer, expected_text)
        }
    };

    if let Err(e) = verdict {
        debug!(error = ?e, "bot-solve: verify failed");
        lorica_api::metrics::inc_bot_challenge(&entry.route_id, entry.mode.as_str(), "failed");
        return write_plain(session, 403, "wrong answer").await;
    }
    lorica_api::metrics::inc_bot_challenge(&entry.route_id, entry.mode.as_str(), "passed");

    // Success: mint verdict cookie bound to the stashed route_id
    // and IP prefix. Use the stashed cookie_ttl_s so a per-route
    // override propagates end-to-end. Secret MUST be present — if
    // it isn't, the process is in a weird state and we fail
    // closed rather than issue an unverifiable cookie.
    let Some(secret) = secret else {
        warn!("bot-solve: HMAC secret not installed; cannot mint verdict cookie");
        return write_plain(session, 503, "bot-protection not initialised").await;
    };

    let payload = cookie::Payload {
        route_id: entry.route_id_bytes_cached(),
        ip_prefix: entry.ip_prefix.clone(),
        expires_at: now + entry.cookie_ttl_s as i64,
        mode: entry.mode,
    };
    let cookie_value = match cookie::sign(&payload, secret) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "bot-solve: cookie sign failed");
            return write_plain(session, 500, "internal error").await;
        }
    };
    let set_cookie = build_set_cookie_header(&cookie_value, entry.cookie_ttl_s);

    info!(
        route_id = %entry.route_id,
        mode = %entry.mode.as_str(),
        "bot-solve: verdict issued"
    );

    let mut header = ResponseHeader::build(302, None)?;
    header.insert_header("Location", entry.return_url.clone())?;
    header.insert_header("Set-Cookie", set_cookie)?;
    header.insert_header("Cache-Control", "no-store")?;
    header.insert_header("Content-Length", "0")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::new()), true)
        .await?;
    Ok(true)
}

/// Handle `GET /lorica/bot/captcha/{nonce}`. Serves the stashed
/// PNG as `image/png` when found, 404 otherwise. Does NOT consume
/// the stashed entry so a user can reload the image while still
/// deciding on the answer.
pub async fn handle_captcha_image(
    session: &mut Session,
    engine: &BotEngine,
    nonce: &str,
) -> lorica_core::Result<bool> {
    let Some(png) = engine.captcha_image(nonce).await else {
        return write_plain(session, 404, "captcha not found").await;
    };

    let mut header = ResponseHeader::build(200, None)?;
    header.insert_header("Content-Type", "image/png")?;
    header.insert_header("Content-Length", png.len().to_string())?;
    // Disable any proxy / browser cache — the image is one-shot
    // and must not be served from a stale cache after the nonce
    // expires or is consumed.
    header.insert_header("Cache-Control", "no-store, private")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(png)), true)
        .await?;
    Ok(true)
}

/// Render + stash the appropriate challenge page for `cfg.mode`,
/// then write the HTML response. The `return_url` is what the
/// client will end up at after a successful solve; typically the
/// original request URI including query string.
///
/// `content_type_prefers_html` is true when the client advertised
/// `text/html` in `Accept`. When false, the response becomes a
/// plain-text 403 instead of the HTML page — useful for curl /
/// wget / scripts that would otherwise see a blob of HTML.
#[allow(clippy::too_many_arguments)]
pub async fn serve_challenge(
    session: &mut Session,
    engine: &Arc<BotEngine>,
    cfg: &BotProtectionConfig,
    route_id: &str,
    client_ip: std::net::IpAddr,
    return_url: &str,
    content_type_prefers_html: bool,
    now: i64,
) -> lorica_core::Result<bool> {
    let mode = match cfg.mode {
        BotProtectionMode::Cookie => Mode::Cookie,
        BotProtectionMode::Javascript => Mode::Javascript,
        BotProtectionMode::Captcha => Mode::Captcha,
    };

    let mode_str = mode.as_str();
    if !content_type_prefers_html {
        // Non-HTML client → plain-text fallback. Still counts as
        // "shown" for metrics because the filter served a
        // challenge response — it just rendered as text.
        lorica_api::metrics::inc_bot_challenge(route_id, mode_str, "shown");
        let body = chrender::render_plaintext_fallback(mode, None);
        let mut header = ResponseHeader::build(403, None)?;
        header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
        header.insert_header("Content-Length", body.len().to_string())?;
        header.insert_header("Cache-Control", "no-store")?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(Bytes::from(body)), true)
            .await?;
        return Ok(true);
    }

    // Opportunistic GC so the stash cannot grow unbounded under a
    // probing attacker. Cheap: O(n) scan of the stash, n bounded
    // by PENDING_TTL_S * request rate.
    engine.prune_expired(now).await;

    let ip_prefix = IpPrefix::from_ip(client_ip);

    let html = match cfg.mode {
        BotProtectionMode::Cookie => {
            // Passive Cookie mode: no server-side stash + no solve
            // round trip. The challenge page IS the verdict: the
            // browser that follows the meta-refresh AND carries
            // the cookie back is what we let through. Any HTTP
            // client that handles cookies + redirects will pass
            // (which is the whole point of "catch low-effort
            // scripts").
            //
            // We still need a verdict cookie so the NEXT request
            // to the same route skips straight through. Mint it
            // here inline.
            // HMAC secret must be installed at this point — if it
            // is not, bail with 503 rather than issue a
            // non-verifiable cookie.
            let Some(secret) = lorica_challenge::secret::handle() else {
                return write_plain(session, 503, "bot-protection not initialised").await;
            };
            let payload = cookie::Payload {
                route_id: route_id_bytes(route_id),
                ip_prefix,
                expires_at: now + cfg.cookie_ttl_s as i64,
                mode: Mode::Cookie,
            };
            let cookie_value = match cookie::sign(&payload, &secret) {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "bot-cookie: cookie sign failed");
                    return write_plain(session, 500, "internal error").await;
                }
            };
            let set_cookie = build_set_cookie_header(&cookie_value, cfg.cookie_ttl_s);

            // Cookie mode's page IS the verdict issuance — the
            // browser that follows the meta-refresh AND carries
            // the cookie back is what we let through. Count it as
            // "passed" here rather than "shown" because the user
            // effectively completed the challenge in this one
            // response.
            lorica_api::metrics::inc_bot_challenge(route_id, mode_str, "passed");

            let body = chrender::render_cookie_refresh_page(return_url, None);
            let mut header = ResponseHeader::build(200, None)?;
            header.insert_header("Content-Type", "text/html; charset=utf-8")?;
            header.insert_header("Content-Length", body.len().to_string())?;
            header.insert_header("Set-Cookie", set_cookie)?;
            header.insert_header("Cache-Control", "no-store")?;
            session
                .write_response_header(Box::new(header), false)
                .await?;
            session
                .write_response_body(Some(Bytes::from(body)), true)
                .await?;
            return Ok(true);
        }

        BotProtectionMode::Javascript => {
            let (raw, nonce_hex) = engine.fresh_nonce();
            let challenge = pow::Challenge {
                nonce: raw,
                difficulty: cfg.pow_difficulty,
                expires_at: (now as u64) + PENDING_TTL_S,
            };
            let html = chrender::render_pow_page(&challenge, BOT_SOLVE_PATH, None);

            engine
                .insert(
                    nonce_hex.clone(),
                    PendingEntry {
                        kind: Pending::Pow {
                            nonce_hex: nonce_hex.clone(),
                            difficulty: cfg.pow_difficulty,
                        },
                        mode: Mode::Javascript,
                        route_id: route_id.to_string(),
                        ip_prefix,
                        return_url: return_url.to_string(),
                        cookie_ttl_s: cfg.cookie_ttl_s,
                        expires_at: now + PENDING_TTL_S as i64,
                    },
                )
                .await;
            html
        }

        BotProtectionMode::Captcha => {
            // Build the captcha image + expected text from the
            // configured alphabet. The alphabet was validated at
            // write time so `validate_alphabet` here only fails on
            // a regression we want to surface at 500.
            let chars = match lorica_challenge::captcha::validate_alphabet(&cfg.captcha_alphabet) {
                Ok(c) => c,
                Err(_) => {
                    warn!("captcha alphabet invalid at request time; failing closed");
                    return write_plain(session, 503, "bot-protection misconfigured").await;
                }
            };
            let (text, png) = match lorica_challenge::captcha::generate(
                &chars,
                lorica_challenge::captcha::DEFAULT_CODE_LEN,
            ) {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = ?e, "captcha generation failed");
                    return write_plain(session, 503, "captcha unavailable").await;
                }
            };

            // Captcha path uses the hex string for both the cookie
            // lookup key and the image URL; the raw 16 bytes are not
            // needed here (no PoW payload).
            let (_, nonce) = engine.fresh_nonce();
            let image_url = format!("{BOT_CAPTCHA_PATH_PREFIX}{nonce}");
            let html = chrender::render_captcha_page(&image_url, BOT_SOLVE_PATH, &nonce, None);

            engine
                .insert(
                    nonce,
                    PendingEntry {
                        kind: Pending::Captcha {
                            expected_text: text,
                            png_bytes: png,
                        },
                        mode: Mode::Captcha,
                        route_id: route_id.to_string(),
                        ip_prefix,
                        return_url: return_url.to_string(),
                        cookie_ttl_s: cfg.cookie_ttl_s,
                        expires_at: now + PENDING_TTL_S as i64,
                    },
                )
                .await;
            html
        }
    };

    // Challenge HTML page served for PoW / Captcha modes. Cookie
    // mode took an early return above (its page IS the verdict
    // issuance; counted as "passed" there when the user follows
    // the refresh). Increment "shown" here so Prometheus sees
    // every challenge-served event.
    lorica_api::metrics::inc_bot_challenge(route_id, mode_str, "shown");

    let mut header = ResponseHeader::build(200, None)?;
    header.insert_header("Content-Type", "text/html; charset=utf-8")?;
    header.insert_header("Content-Length", html.len().to_string())?;
    header.insert_header("Cache-Control", "no-store")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::from(html)), true)
        .await?;
    Ok(true)
}

/// Read at most `max_bytes` of the request body, or fail with the
/// reason string when the bound is exceeded. Drains the remainder
/// on success so the HTTP/1.1 connection can be reused (pingora's
/// keepalive contract).
async fn read_bounded_body(
    session: &mut Session,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, &'static str> {
    // Fast path: Content-Length header greater than the cap means
    // we reject without pulling any chunk.
    if let Some(len_str) = session
        .req_header()
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
    {
        if let Ok(len) = len_str.parse::<usize>() {
            if len > max_bytes {
                return Err("content-length exceeds bound");
            }
        }
    }

    let mut out = Vec::with_capacity(256);
    loop {
        let chunk = match session.read_request_body().await {
            Ok(Some(b)) => b,
            Ok(None) => break,
            Err(_) => return Err("body read error"),
        };
        if out.len() + chunk.len() > max_bytes {
            return Err("chunked body exceeds bound");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Minimal application/x-www-form-urlencoded parser. Accepts
/// percent-encoding and `+` for space. Skips malformed pairs.
/// Returns a `HashMap` keyed by the raw field name.
///
/// Kept local (not `serde_urlencoded`) to avoid adding a dep for
/// what is ~50 lines of parsing for the three fields we actually
/// consume (`nonce`, `counter`, `answer`).
pub(crate) fn parse_form_urlencoded(body: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let s = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => return out, // non-UTF-8 form body → empty map
    };
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        let k = match percent_decode(k) {
            Some(k) => k,
            None => continue,
        };
        let v = match percent_decode(v) {
            Some(v) => v,
            None => continue,
        };
        out.insert(k, v);
    }
    out
}

/// Percent-decode a form field. `+` → space, `%XX` → byte XX. Any
/// malformed percent sequence returns `None` (caller skips).
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex_digit(bytes[i + 1])?;
                let lo = hex_digit(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Return true iff the `Accept` header on the request advertises
/// HTML. Case-insensitive substring match — covers `text/html`,
/// `application/xhtml+xml`, and the various `*/*` weighted forms
/// every browser sends. Missing header = treat as "not HTML"
/// (conservative: scripts get the plain-text fallback).
pub(crate) fn accept_prefers_html(accept_header: Option<&str>) -> bool {
    let Some(h) = accept_header else { return false };
    let lowered = h.to_ascii_lowercase();
    lowered.contains("text/html") || lowered.contains("application/xhtml")
}

/// Build a `Set-Cookie` header value for the verdict cookie.
/// `SameSite=Lax` so a cross-origin navigation that requires auth
/// (OAuth redirect, IdP hop) still carries the verdict. `HttpOnly`
/// so JavaScript cannot read or exfiltrate the cookie. `Secure`
/// `Secure` is set unconditionally: verdict cookies are security
/// tokens and must never transit over plaintext. Dev environments
/// running plain HTTP will not receive the cookie (correct
/// behaviour - the challenge re-fires on every request, which is
/// the safe degradation).
fn build_set_cookie_header(value: &str, max_age_s: u32) -> String {
    format!(
        "{VERDICT_COOKIE_NAME}={value}; Max-Age={max_age_s}; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
}

/// Cheap shared path for small status responses (405 / 400 / 403 /
/// 404 / 413 / 503 / plaintext). Kept private because every caller
/// uses a literal status + message.
async fn write_plain(session: &mut Session, status: u16, msg: &str) -> lorica_core::Result<bool> {
    let mut header = ResponseHeader::build(status, None)?;
    header.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    header.insert_header("Content-Length", msg.len().to_string())?;
    header.insert_header("Cache-Control", "no-store")?;
    session
        .write_response_header(Box::new(header), false)
        .await?;
    session
        .write_response_body(Some(Bytes::copy_from_slice(msg.as_bytes())), true)
        .await?;
    Ok(true)
}

impl PendingEntry {
    /// Compute the 16-byte route-id hash stored in the verdict
    /// cookie. Kept here (rather than on `BotEngine`) because the
    /// cookie wire format is a `bot_handlers` concern —
    /// `PendingEntry.route_id` is a plain String and does not
    /// otherwise need a derived-form lookup.
    pub(super) fn route_id_bytes_cached(&self) -> [u8; 16] {
        route_id_bytes(&self.route_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_parser_handles_basic_pairs() {
        let m = parse_form_urlencoded(b"a=1&b=2");
        assert_eq!(m.get("a"), Some(&"1".to_string()));
        assert_eq!(m.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn form_parser_decodes_percent_escaped() {
        let m = parse_form_urlencoded(b"answer=abc%20def%21");
        assert_eq!(m.get("answer"), Some(&"abc def!".to_string()));
    }

    #[test]
    fn form_parser_decodes_plus_as_space() {
        let m = parse_form_urlencoded(b"q=hello+world");
        assert_eq!(m.get("q"), Some(&"hello world".to_string()));
    }

    #[test]
    fn form_parser_tolerates_empty_and_missing_equals() {
        let m = parse_form_urlencoded(b"&&a=1&novalue&b=2");
        assert_eq!(m.get("a"), Some(&"1".to_string()));
        assert_eq!(m.get("b"), Some(&"2".to_string()));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn form_parser_skips_bad_percent_escape() {
        // `%XY` where X or Y is not a hex digit is dropped.
        let m = parse_form_urlencoded(b"good=ok&bad=%ZZ&other=v");
        assert_eq!(m.get("good"), Some(&"ok".to_string()));
        assert_eq!(m.get("other"), Some(&"v".to_string()));
        assert!(!m.contains_key("bad"));
    }

    #[test]
    fn form_parser_rejects_truncated_percent() {
        // `%` at end of string without two following chars: that
        // pair drops.
        let m = parse_form_urlencoded(b"a=b&trunc=%");
        assert_eq!(m.get("a"), Some(&"b".to_string()));
        assert!(!m.contains_key("trunc"));
    }

    #[test]
    fn accept_html_detection() {
        assert!(accept_prefers_html(Some("text/html")));
        assert!(accept_prefers_html(Some(
            "text/html,application/xhtml+xml,*/*;q=0.8"
        )));
        assert!(accept_prefers_html(Some("application/xhtml+xml")));
        assert!(!accept_prefers_html(Some("application/json")));
        assert!(!accept_prefers_html(Some("*/*")));
        assert!(!accept_prefers_html(None));
    }

    #[test]
    fn set_cookie_includes_the_right_flags() {
        let s = build_set_cookie_header("abc", 86400);
        assert!(s.starts_with("lorica_bot_verdict=abc"));
        assert!(s.contains("Max-Age=86400"));
        assert!(s.contains("HttpOnly"));
        assert!(s.contains("SameSite=Lax"));
        assert!(s.contains("Path=/"));
    }

}
