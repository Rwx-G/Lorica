// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Default static error-page renderer.
//!
//! Renders a Cloudflare-style three-tier diagnostic page (You /
//! Network / Host) with a per-status `BrokenTier` marker for the
//! status codes Lorica surfaces directly: 5xx (proxy + origin), 429
//! (rate limit), 403 (WAF / ban / blocklist), 495 / 496 (mTLS).
//!
//! Operator-facing customisation continues to flow through the
//! per-route `error_page_html` field; the default page below only
//! applies when no custom HTML is configured for the route - and is
//! the only thing rendered when there is no matched route at all
//! (early request_filter rejects, mTLS gate before route lookup).
//!
//! Anti-fingerprint: the page carries no proxy product name, no
//! version, no hostname leak. The Wikipedia link educates rather
//! than identifies. The Host tier label is the request's `Host`
//! header (already known to the requester) - no extra surface.

use super::{escape_html, sanitize_html};

/// Which of the three diagnostic tiers (You / Network / Host) is
/// flagged as the failing hop on the rendered page. Determines
/// which icon shows the red X badge and where the white triangular
/// notch points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrokenTier {
    /// 4xx client-side errors: 403 (WAF / ban / blocklist), 429
    /// (rate limit), 495 / 496 (mTLS). The browser tier is flagged
    /// as the request originator that the proxy chose to refuse.
    You,
    /// 5xx proxy-side errors: 500 (internal), 503 (proxy
    /// unavailable, max-conns), 504 (proxy-side timeout). The
    /// failure happened inside the network layer between client
    /// and origin.
    Network,
    /// 5xx origin-side errors: 502 (bad gateway), 522 / 523 / 524
    /// (origin connection / unreachable / timeout). The proxy
    /// reached the origin but the origin failed.
    Host,
}

/// Static metadata for one HTTP status: the visible title, the two
/// explanation paragraphs, and the diagnostic-tier marker. Held as
/// `&'static str` so rendering allocates only the final string and
/// the substituted variable values - no template-level fmtargs.
#[derive(Debug, Clone, Copy)]
struct StatusInfo {
    title: &'static str,
    what_happened: &'static str,
    what_can_i_do: &'static str,
    broken_tier: BrokenTier,
    /// Wikipedia anchor on `List_of_HTTP_status_codes` for the
    /// "more information" link. Stable HTML id format upstream.
    wiki_anchor: &'static str,
}

fn info_for_status(status: u16) -> StatusInfo {
    match status {
        500 => StatusInfo {
            title: "Internal server error",
            what_happened: "The proxy encountered an unexpected condition that prevented it from \
                            fulfilling the request. This is a server-side issue, not a problem \
                            with your browser.",
            what_can_i_do: "Please try again in a few moments. If the issue persists, contact \
                            the site administrator with the Request ID below so they can locate \
                            the failure in the access logs.",
            broken_tier: BrokenTier::Network,
            wiki_anchor: "500_Internal_Server_Error",
        },
        502 => StatusInfo {
            title: "Bad gateway",
            what_happened: "The origin server reported a bad gateway error. The network reached \
                            the host but received a malformed response, or the host rejected \
                            the connection.",
            what_can_i_do: "Please try again in a few moments. If the issue persists, contact \
                            the site administrator with the Request ID below so they can locate \
                            the failure in the access logs.",
            broken_tier: BrokenTier::Host,
            wiki_anchor: "502_Bad_Gateway",
        },
        503 => StatusInfo {
            title: "Service unavailable",
            what_happened: "The host is temporarily unable to handle the request. This may be \
                            due to maintenance, capacity limits, or a downstream service \
                            being offline.",
            what_can_i_do: "Please try again later. If a Retry-After delay was returned, wait \
                            at least that long before retrying.",
            broken_tier: BrokenTier::Host,
            wiki_anchor: "503_Service_Unavailable",
        },
        504 => StatusInfo {
            title: "Gateway timeout",
            what_happened: "The origin server did not respond within the configured timeout. \
                            The network reached the host but did not receive a reply in time.",
            what_can_i_do: "Please try again in a few moments. If the issue persists, contact \
                            the site administrator with the Request ID below.",
            broken_tier: BrokenTier::Host,
            wiki_anchor: "504_Gateway_Timeout",
        },
        522 => StatusInfo {
            title: "Connection timed out",
            what_happened: "The network could not establish a connection to the origin host \
                            within the configured timeout.",
            what_can_i_do: "Please try again in a few moments. If the issue persists, contact \
                            the site administrator.",
            broken_tier: BrokenTier::Host,
            wiki_anchor: "504_Gateway_Timeout",
        },
        408 => StatusInfo {
            title: "Request timeout",
            what_happened: "The request was not completed in time. The proxy stopped waiting for \
                            the request headers or body to finish arriving (possible slow client, \
                            slow connection, or slowloris-style attack).",
            what_can_i_do: "Retry the request on a faster connection. If the issue persists, \
                            contact the site administrator with the Request ID below.",
            broken_tier: BrokenTier::You,
            wiki_anchor: "408_Request_Timeout",
        },
        429 => StatusInfo {
            title: "Too many requests",
            what_happened: "Your client sent too many requests in a short period and the rate \
                            limit was exceeded.",
            what_can_i_do: "Please wait a few moments before retrying. If a Retry-After delay \
                            was returned in the response headers, wait at least that long.",
            broken_tier: BrokenTier::You,
            wiki_anchor: "429_Too_Many_Requests",
        },
        403 => StatusInfo {
            title: "Forbidden",
            what_happened: "The request was blocked by a security rule (web application firewall, \
                            IP allowlist, or auto-ban).",
            what_can_i_do: "If you believe this is a mistake, contact the site administrator \
                            with the Request ID below so they can review the security event.",
            broken_tier: BrokenTier::You,
            wiki_anchor: "403_Forbidden",
        },
        495 => StatusInfo {
            title: "SSL certificate error",
            what_happened: "The client certificate you presented is valid but its subject \
                            organization is not in the route's allowlist.",
            what_can_i_do: "Use a client certificate whose subject organization is permitted, \
                            or contact the site administrator to request access.",
            broken_tier: BrokenTier::You,
            wiki_anchor: "495_SSL_Certificate_Error",
        },
        496 => StatusInfo {
            title: "SSL certificate required",
            what_happened: "This route requires mutual TLS authentication, but no client \
                            certificate was presented during the TLS handshake.",
            what_can_i_do: "Configure your client to present a valid client certificate signed \
                            by a CA accepted by this route, then retry.",
            broken_tier: BrokenTier::You,
            wiki_anchor: "496_SSL_Certificate_Required",
        },
        _ => StatusInfo {
            title: "Error",
            what_happened: "The request could not be completed.",
            what_can_i_do: "Please try again in a few moments. If the issue persists, contact \
                            the site administrator with the Request ID below.",
            broken_tier: BrokenTier::Network,
            wiki_anchor: "List_of_HTTP_status_codes",
        },
    }
}

/// HTML template - placeholders are simple `__NAME__` markers
/// (substituted via `replace`), chosen so they are safe inside CSS
/// blocks where `{` / `}` / `{{` would clash with `format!` syntax.
const TEMPLATE: &str = include_str!("error_pages.html");

/// Render the default error page for a given status code. The
/// returned String is plain HTML, ready to write as the response
/// body. Caller sets `Content-Type: text/html; charset=utf-8` and
/// the appropriate `Content-Length`.
///
/// `request_id` is treated as opaque text and rendered verbatim
/// (it comes from `generate_request_id` - 32 hex chars, no escape
/// needed). `host_header` IS escaped because it comes from the
/// request and may contain attacker-controlled bytes; an empty
/// string is rendered as a literal "-" so the layout doesn't
/// collapse on hosts with no Host header.
pub(crate) fn render_error_page(status: u16, request_id: &str, host_header: &str) -> String {
    let info = info_for_status(status);
    let host_label = if host_header.is_empty() {
        "-".to_string()
    } else {
        escape_html(host_header)
    };

    let timestamp = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();

    // Per-tier modifiers: which tier carries the `broken` CSS
    // class (drops the white triangle notch underneath) and which
    // badge variant + glyph + state text each tier shows.
    let (you_broken, network_broken, host_broken) = match info.broken_tier {
        BrokenTier::You => (" broken", "", ""),
        BrokenTier::Network => ("", " broken", ""),
        BrokenTier::Host => ("", "", " broken"),
    };
    let (you_badge, you_glyph, you_state, you_state_class) =
        badge(info.broken_tier == BrokenTier::You);
    let (net_badge, net_glyph, net_state, net_state_class) =
        badge(info.broken_tier == BrokenTier::Network);
    let (host_badge, host_glyph, host_state, host_state_class) =
        badge(info.broken_tier == BrokenTier::Host);

    let status_str = status.to_string();
    // Single-pass marker substitution. Each `String::replace` call
    // clones the entire ~5 KB template into a fresh buffer ; with
    // 24 markers that's 24 allocations + 24 linear scans per error
    // response (~120 KB intermediate allocations). A WAF block storm
    // or a 503 flood multiplied this. The single-pass walker below
    // does one allocation (pre-sized to template + average expansion)
    // and one linear scan. Audit M-11.
    let subs: &[(&str, &str)] = &[
        ("__STATUS__", &status_str),
        ("__TITLE__", info.title),
        ("__WIKI_ANCHOR__", info.wiki_anchor),
        ("__TIMESTAMP__", &timestamp),
        ("__HOST_LABEL__", &host_label),
        ("__REQUEST_ID__", request_id),
        ("__WHAT_HAPPENED__", info.what_happened),
        ("__WHAT_CAN_I_DO__", info.what_can_i_do),
        ("__YOU_BROKEN__", you_broken),
        ("__NETWORK_BROKEN__", network_broken),
        ("__HOST_BROKEN__", host_broken),
        ("__YOU_BADGE__", you_badge),
        ("__YOU_GLYPH__", you_glyph),
        ("__YOU_STATE__", you_state),
        ("__YOU_STATE_CLASS__", you_state_class),
        ("__NET_BADGE__", net_badge),
        ("__NET_GLYPH__", net_glyph),
        ("__NET_STATE__", net_state),
        ("__NET_STATE_CLASS__", net_state_class),
        ("__HOST_BADGE__", host_badge),
        ("__HOST_GLYPH__", host_glyph),
        ("__HOST_STATE__", host_state),
        ("__HOST_STATE_CLASS__", host_state_class),
    ];
    substitute_markers(TEMPLATE, subs)
}

/// Single-pass `__MARKER__` substitution. Walks the template once,
/// emitting chunks into a pre-sized String. Each marker is matched
/// at every `__` position via linear scan over the substitution
/// table - 23 markers means each `__` site does at most 23 prefix
/// comparisons, which is cheap vs the alternative of 23 full-template
/// `String::replace` passes.
///
/// Markers MUST be of the form `__NAME__` (double underscore on both
/// sides). Any `__NAME__` not in `subs` is emitted literally - the
/// template author's safety net against an unmapped marker silently
/// going missing in the rendered output.
fn substitute_markers(template: &str, subs: &[(&str, &str)]) -> String {
    let bytes = template.as_bytes();
    // Pre-size : template + average ~30 char per substitution.
    let mut out = String::with_capacity(template.len() + subs.len() * 32);
    let mut i = 0;
    while i < bytes.len() {
        // Find next `__` from position i. If none, copy the rest
        // and we're done.
        let next = match memchr_dunder(bytes, i) {
            Some(p) => p,
            None => {
                out.push_str(&template[i..]);
                break;
            }
        };
        // Copy everything before the `__` verbatim.
        if next > i {
            out.push_str(&template[i..next]);
        }
        // Try to match a known marker at `next`.
        let mut consumed = 0usize;
        for (marker, value) in subs {
            if bytes[next..].starts_with(marker.as_bytes()) {
                out.push_str(value);
                consumed = marker.len();
                break;
            }
        }
        if consumed == 0 {
            // Unknown marker prefix : emit the `__` literally and
            // resume after them so the next iteration scans past.
            out.push_str("__");
            consumed = 2;
        }
        i = next + consumed;
    }
    out
}

/// Find the next occurrence of the byte pair `__` at or after `from`.
fn memchr_dunder(bytes: &[u8], from: usize) -> Option<usize> {
    if from >= bytes.len() {
        return None;
    }
    let mut i = from;
    while i + 1 < bytes.len() {
        if bytes[i] == b'_' && bytes[i + 1] == b'_' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Resolve the body served for a status-code-driven error response.
///
/// The per-route `error_page_html` override takes precedence when set
/// (sanitized, with `{{status}}` and `{{message}}` substitution). When
/// no override is configured, renders the default Lorica error page.
///
/// `error_message` is only meaningful for operator-configured HTML
/// overrides; the default page ignores it and uses the per-status
/// explanation copy instead.
pub(crate) fn render_error_body(
    status: u16,
    request_id: &str,
    host_header: &str,
    custom_html: Option<&str>,
    error_message: &str,
) -> String {
    if let Some(html) = custom_html {
        sanitize_html(html)
            .replace("{{status}}", &status.to_string())
            .replace("{{message}}", &escape_html(error_message))
    } else {
        render_error_page(status, request_id, host_header)
    }
}

/// Returns (badge_class, glyph, state_text, state_class) for a tier
/// based on whether it is the broken one. `badge_class` and
/// `state_class` map onto the CSS rules in the HTML template.
fn badge(is_broken: bool) -> (&'static str, &'static str, &'static str, &'static str) {
    if is_broken {
        ("err", "&#10005;", "Error", "err")
    } else {
        ("ok", "&#10003;", "Working", "ok")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_502_with_host_broken_tier() {
        let html = render_error_page(502, "abc123", "gitlab.example.com");
        assert!(html.contains("Bad gateway"));
        assert!(html.contains("Error code 502"));
        assert!(html.contains("502_Bad_Gateway"));
        assert!(html.contains("gitlab.example.com"));
        assert!(html.contains("abc123"));
        // Host should be the broken tier (and only Host).
        assert!(html.contains(r#"class="tier broken""#));
        let broken_count = html.matches(" broken\"").count();
        assert_eq!(broken_count, 1, "exactly one tier marked broken");
    }

    #[test]
    fn renders_503_with_host_broken_tier() {
        let html = render_error_page(503, "req-503", "api.example.com");
        assert!(html.contains("Service unavailable"));
        assert!(html.contains("Error code 503"));
    }

    #[test]
    fn renders_500_with_network_broken_tier() {
        let html = render_error_page(500, "req-500", "host");
        assert!(html.contains("Internal server error"));
        // Network is the second tier; the broken class should land
        // on it (not Host or You).
        assert!(html.contains(r#"class="tier broken""#));
    }

    #[test]
    fn renders_408_with_you_broken_tier() {
        let html = render_error_page(408, "req-408", "host");
        assert!(html.contains("Request timeout"));
        assert!(html.contains("Error code 408"));
        assert!(html.contains("408_Request_Timeout"));
    }

    #[test]
    fn renders_429_with_you_broken_tier() {
        let html = render_error_page(429, "req-429", "host");
        assert!(html.contains("Too many requests"));
        assert!(html.contains("Error code 429"));
    }

    #[test]
    fn renders_403_with_you_broken_tier() {
        let html = render_error_page(403, "req-403", "host");
        assert!(html.contains("Forbidden"));
        assert!(html.contains("security rule"));
    }

    #[test]
    fn renders_495_with_you_broken_tier() {
        let html = render_error_page(495, "req-495", "host");
        assert!(html.contains("SSL certificate error"));
        assert!(html.contains("subject organization"));
    }

    #[test]
    fn renders_496_with_you_broken_tier() {
        let html = render_error_page(496, "req-496", "host");
        assert!(html.contains("SSL certificate required"));
        assert!(html.contains("mutual TLS"));
    }

    #[test]
    fn unknown_status_falls_back_to_generic() {
        let html = render_error_page(599, "req-599", "host");
        assert!(html.contains("Error code 599"));
        assert!(html.contains("Error</h1>"));
    }

    #[test]
    fn empty_host_renders_dash() {
        let html = render_error_page(502, "rid", "");
        // Host label area should show a dash, not collapse.
        assert!(html.contains(">-</div>"));
    }

    #[test]
    fn host_header_is_html_escaped() {
        // An attacker-controlled Host header containing `<script>`
        // must NOT round-trip into the rendered HTML as live markup.
        let html = render_error_page(502, "rid", "<script>alert(1)</script>");
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn timestamp_is_utc_iso_like() {
        let html = render_error_page(502, "rid", "host");
        // 2026-04-14 09:24:55 UTC pattern
        let re = regex::Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC").unwrap();
        assert!(re.is_match(&html));
    }

    #[test]
    fn page_carries_no_lorica_string() {
        // Anti-fingerprint guard: the rendered page must not leak
        // the proxy product name. Audit-driven invariant.
        let html = render_error_page(502, "rid", "host");
        assert!(!html.to_lowercase().contains("lorica"));
        assert!(!html.to_lowercase().contains("pingora"));
    }
}
