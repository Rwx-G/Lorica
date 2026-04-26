// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Pure helpers extracted from `proxy_wiring.rs` (audit M-8 step 5).
//!
//! Stateless / single-static functions that are unit-testable in
//! isolation. Grouped here rather than spread across many tiny
//! modules:
//!   - HTML sanitization regexes + `sanitize_html` (used to render
//!     custom error pages and the WAF block page without XSS).
//!   - `extract_host` (Host header / URI authority pick).
//!   - `match_header_rule_backends` (header-based routing override
//!     selection).
//!   - `evaluate_mtls` (per-route mTLS policy gate).
//!   - `canary_bucket` + `pick_traffic_split_backends` (canary
//!     traffic split assignment, FNV-1a deterministic).
//!   - `cache_vary_for_request` + `compute_cache_variance` (cache
//!     partitioning by request headers).

// `Arc` + `Backend` are only consumed by the `#[cfg(test)]` helpers
// below (`match_header_rule_backends`, `pick_traffic_split_backends`).
// Gating their `use`s keeps `-D unused-imports` clean in lib builds.
#[cfg(test)]
use std::sync::Arc;

use lorica_cache::key::HashBinary;
use lorica_cache::{CacheMeta, VarianceBuilder};
use lorica_config::models::Route;
use lorica_proxy::Session;
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};

#[cfg(test)]
use super::Backend;
use super::MtlsEnforcer;

/// Singleton `ammonia::Builder` configured for the operator-supplied
/// `error_page_html` use case. Built once at first access (Lazy) so the
/// `HashMap` allocations happen outside the hot path.
///
/// Replaces the regex-based sanitizer that used to live in this module
/// (3-pass strip of `<script>`, `on*=`, `javascript:`). Regex HTML
/// filters are historically contournable via `<svg onload>`, HTML
/// malformé, encoded bypasses. ammonia parses the input through
/// `html5ever` and walks the DOM against an allow-list, so the attack
/// surface collapses onto what the Servo team already hardens (v1.5.0
/// audit finding HIGH-1).
///
/// Policy:
/// - Default ammonia allow-list covers the structural + inline tags
///   operators need for readable error pages (h1..h6, p, div, span,
///   strong, em, code, pre, ul, ol, li, br, hr, a, blockquote, etc).
/// - Explicitly allows the document-level tags (`html`, `head`, `body`,
///   `title`) so an operator can supply a full standalone document.
///   These carry no scripting semantics on their own.
/// - `<style>`, `<link>`, `<script>`, `<iframe>`, `<object>`, `<embed>`,
///   `<meta>`, `<base>`, `<form>`, `<input>` are rejected (kept out of
///   the default allow-list and not re-added here).
/// - URL schemes on `href` / `src` restricted to `http`, `https`,
///   `mailto`. `javascript:`, `data:`, `file:`, `vbscript:` are
///   rejected. (Ammonia defaults already reject `javascript:`; we
///   tighten to an explicit allow-list.)
/// - Event handler attributes (`on*=`) never survive parsing.
/// - `<a>` gets `rel="noopener noreferrer"` forced + target-restricted
///   (ammonia default for external links).
static SANITIZER: Lazy<ammonia::Builder<'static>> = Lazy::new(|| {
    let mut b = ammonia::Builder::default();

    // Structural document tags. ammonia's default strips these because
    // in a CMS-comment / wiki-edit context they are noise; here we
    // serve the sanitized HTML as the FULL response body, so an
    // operator who supplies `<html><body>...` should see it preserved.
    let mut extra_tags: HashSet<&'static str> = HashSet::new();
    extra_tags.insert("html");
    extra_tags.insert("head");
    extra_tags.insert("body");
    extra_tags.insert("title");
    b.add_tags(extra_tags);

    // Tighten URL schemes: ammonia default is fairly permissive
    // (http, https, mailto, tel, ...). For an error page served from
    // a reverse proxy, `tel:` and friends have no business use, so we
    // cap to the minimum set.
    let mut schemes: HashSet<&'static str> = HashSet::new();
    schemes.insert("http");
    schemes.insert("https");
    schemes.insert("mailto");
    b.url_schemes(schemes);

    // Lock down `href` / `src` to the scheme allow-list above and
    // keep relative URLs disabled - the error page is served from
    // an arbitrary origin and a relative link would chase that.
    b.url_relative(ammonia::UrlRelative::Deny);

    // Per-tag attribute allow-list stays on the default. We do NOT
    // re-add `style` on any tag - inline CSS is a known XSS vector
    // via `background-image: url(javascript:...)` on some old
    // browsers and `expression()` on IE. Operators who need styling
    // should ship the CSS externally in a dedicated hosted page.
    let _ = HashMap::<&str, HashSet<&str>>::new();

    b
});

/// Sanitize operator-supplied HTML before rendering it as an error
/// page body. Whitelist-based via ammonia; rejects scripts, event
/// handlers, `javascript:` / `data:` URIs, `<style>`, `<link>`,
/// `<iframe>`, etc.
///
/// Input size is capped upstream by `validate_error_page_html`
/// (128 KiB, see `lorica-api`). We do NOT re-check the size here;
/// the API has already rejected oversize payloads before they are
/// persisted.
pub(crate) fn sanitize_html(html: &str) -> String {
    SANITIZER.clean(html).to_string()
}

pub(crate) fn extract_host(req: &lorica_http::RequestHeader) -> &str {
    req.headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri.authority().map(|a| a.as_str()))
        .unwrap_or("")
}

/// Evaluate header-based routing rules against a request's headers.
/// Returns pre-resolved backends from the first rule that matches and
/// carries an override. A rule with an empty `backend_ids` ("match but
/// keep route defaults") is treated as not-an-override: the caller should
/// leave `matched_backends` alone when this returns `None`.
///
/// Extracted so the matching + extraction path is exercised by unit
/// tests without needing a Session or ProxyConfig. The production path
/// in `request_filter` inlines the same logic to capture the matched
/// rule index for the Prometheus metric label.
#[cfg(test)]
pub(crate) fn match_header_rule_backends<'a>(
    rules: &[lorica_config::models::HeaderRule],
    regexes: &[Option<Arc<regex::Regex>>],
    backends: &'a [Option<Vec<Backend>>],
    headers: &http::HeaderMap,
) -> Option<&'a [Backend]> {
    for (i, rule) in rules.iter().enumerate() {
        // Missing / non-UTF-8 header values act as the empty string. A
        // Prefix rule with `value = ""` would otherwise spuriously match
        // every request, so Exact and Prefix rules must set a non-empty
        // `value` to be useful - this is documented on `HeaderRule`.
        let value = headers
            .get(rule.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let regex: Option<&regex::Regex> = regexes.get(i).and_then(|opt| opt.as_deref());
        if rule.matches(value, |v| regex.is_some_and(|re| re.is_match(v))) {
            // Matched. If this rule has an override, return it; otherwise
            // the rule matched but inherits the route's default backend
            // set, which the caller expresses by NOT touching
            // matched_backends.
            return backends.get(i).and_then(|b| b.as_deref());
        }
    }
    None
}

/// Evaluate the per-route mTLS policy against the connection's client
/// certificate organization. Returns `None` when the request passes,
/// and `Some(status)` with the HTTP status the caller should reject
/// with. Pure so it is trivially unit-testable against synthesized
/// ssl digests.
///
/// Status contract:
/// - `required = true` and no cert → 496 ("SSL certificate required")
/// - `allowed_organizations` non-empty, cert org not in list → 495
///   ("SSL certificate error"). The org check applies whether
///   required is true or false: an operator who configured an
///   allowlist meant to enforce it on presented certs.
/// - `required = false` and no cert presented → pass (opportunistic).
///
/// The cert chain itself is validated at the TLS layer by the
/// listener's WebPkiClientVerifier; the organization string arrives
/// pre-extracted in `client_organization` (None when no cert was
/// presented, Some("") for a cert without an O= field).
pub fn evaluate_mtls(enforcer: &MtlsEnforcer, client_organization: Option<&str>) -> Option<u16> {
    match client_organization {
        None => {
            if enforcer.required {
                Some(496)
            } else {
                None
            }
        }
        Some(org) => {
            // Empty allowlist = accept any authenticated client.
            if enforcer.allowed_organizations.is_empty()
                || enforcer.allowed_organizations.iter().any(|a| a == org)
            {
                None
            } else {
                Some(495)
            }
        }
    }
}

/// Extract the client-certificate organization (O= DN field) from a
/// downstream TLS session, or None when the session is plaintext / the
/// client did not present a cert / the cert has no O= field.
///
/// We go through `downstream_session.digest().ssl_digest` because that
/// is the only shared abstraction over rustls / boringssl; rustls
/// populates `organization` from the first cert in the peer chain.
pub(crate) fn downstream_ssl_digest(session: &Session) -> Option<String> {
    let digest = session.as_downstream().digest()?;
    let ssl = digest.ssl_digest.as_ref()?;
    // cert_digest empty = no client cert was presented (rustls leaves
    // the digest empty when the handshake completed via
    // allow_unauthenticated).
    if ssl.cert_digest.is_empty() {
        return None;
    }
    // An authenticated cert may still lack an O= field. Return Some("")
    // in that case so the route-level allowlist check correctly fails
    // (empty string is never in a non-empty allowlist).
    Some(ssl.organization.clone().unwrap_or_default())
}

/// Compute a stable bucket in `0..100` for `(route_id, client_ip)`. Same
/// inputs always map to the same bucket within a single process, which
/// gives the canary its "sticky" property - one user stays on the same
/// version across multiple requests on the same route. Mixing the route
/// ID into the hash means an unlucky client IP doesn't land in every
/// service's canary bucket simultaneously.
///
/// `pub` so integration tests can pick synthetic client IPs that are
/// guaranteed to fall in a specific bucket band without running the
/// law-of-large-numbers gauntlet.
///
/// Uses FNV-1a (64-bit) with fixed constants rather than
/// `DefaultHasher`, which in Rust is seeded from a random
/// `RandomState` at process start: same inputs would land in a
/// different bucket after every restart, silently shuffling canary
/// assignments across rolling upgrades. FNV-1a gives cross-restart
/// stability and is uniform enough for a `% 100` bucketing.
pub fn canary_bucket(route_id: &str, client_ip: &str) -> u8 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = FNV_OFFSET;
    for byte in route_id.as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    // NUL separator so "r1" + "ab" and "r1a" + "b" don't collide.
    h ^= 0;
    h = h.wrapping_mul(FNV_PRIME);
    for byte in client_ip.as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    (h % 100) as u8
}

/// Select the backends for a traffic split given a deterministic bucket
/// value in `0..100`. Splits are consumed in declaration order and their
/// weights accumulate: the first split whose cumulative ceiling strictly
/// exceeds `bucket` wins. When a split in the range has been normalised
/// away (e.g. dangling backend IDs, see `from_store`), it still consumes
/// its weight band but yields `None`, so the caller keeps route defaults
/// for that bucket rather than rebalancing the remaining traffic.
///
/// The caller is responsible for computing `bucket`; extracting this
/// function keeps weighted-selection math independent of the actual
/// client-IP hash, so both are trivially unit-testable. The production
/// path in `request_filter` inlines the same logic to capture the
/// matched split name for the Prometheus metric label.
#[cfg(test)]
pub(crate) fn pick_traffic_split_backends<'a>(
    splits: &[lorica_config::models::TrafficSplit],
    resolved: &'a [Option<Vec<Backend>>],
    bucket: u8,
) -> Option<&'a [Backend]> {
    let mut cumulative: u32 = 0;
    for (i, split) in splits.iter().enumerate() {
        let w = split.weight_percent.min(100) as u32;
        if w == 0 {
            continue;
        }
        cumulative = cumulative.saturating_add(w).min(100);
        if (bucket as u32) < cumulative {
            return resolved.get(i).and_then(|b| b.as_deref());
        }
    }
    None
}

/// Glue used by `cache_vary_filter`: pull the three inputs - route config,
/// response Vary, request headers+URI - out of a session-level state and
/// hand them to [`compute_cache_variance`]. Extracted from the trait method
/// so the full extraction path is exercised by unit tests, without needing
/// to build a `Session` or a `LoricaProxy` instance.
pub(crate) fn cache_vary_for_request(
    route: Option<&Route>,
    meta: &CacheMeta,
    req: &lorica_http::RequestHeader,
) -> Option<HashBinary> {
    let route_headers: &[String] = route
        .map(|r| r.cache_vary_headers.as_slice())
        .unwrap_or(&[]);
    let response_vary = meta
        .headers()
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let request_uri = req
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    compute_cache_variance(route_headers, response_vary, &req.headers, request_uri)
}

/// Compute a cache variance hash from a union of operator-configured vary
/// headers (route config) and the origin response's `Vary` header.
///
/// Returns `None` when there is no variance to apply - the caller then
/// caches the asset under its primary key. Extracted from
/// `cache_vary_filter` as a pure helper so the merging, `Vary: *` handling,
/// and case-insensitive deduplication are unit-testable without a full
/// proxy session.
pub(crate) fn compute_cache_variance(
    route_headers: &[String],
    response_vary: &str,
    request_headers: &http::HeaderMap,
    request_uri: &str,
) -> Option<HashBinary> {
    // Lower-case and deduplicate header names across both sources.
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for h in route_headers {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            names.insert(trimmed.to_ascii_lowercase());
        }
    }

    for part in response_vary.split(',') {
        let t = part.trim();
        if t == "*" {
            // Per RFC 7234, `Vary: *` means every request is a unique
            // variant. Anchor the variance on the request URI so repeat
            // requests to the same URL still hit a stable slot - prevents
            // unbounded cardinality growth while respecting the contract
            // that two different URLs must not share a variant.
            let mut vb = VarianceBuilder::new();
            vb.add_value("*uri", request_uri);
            return vb.finalize();
        }
        if !t.is_empty() {
            names.insert(t.to_ascii_lowercase());
        }
    }

    if names.is_empty() {
        return None;
    }

    let mut vb = VarianceBuilder::new();
    for name in names {
        // Bytes (not only valid UTF-8) so request headers carrying
        // binary-encoded values still partition the cache deterministically.
        let value = request_headers
            .get(name.as_str())
            .map(|v| v.as_bytes().to_vec())
            .unwrap_or_default();
        vb.add_owned_name_value(name, value);
    }
    vb.finalize()
}

/// Compute the upstream keepalive pool size based on the number of backends.
/// - <= 15 backends: 128 (Pingora default)
/// - 16+ backends: 8 connections per backend, capped at 1024
pub fn compute_pool_size(backend_count: usize) -> usize {
    if backend_count <= 15 {
        128
    } else {
        (backend_count * 8).min(1024)
    }
}

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
