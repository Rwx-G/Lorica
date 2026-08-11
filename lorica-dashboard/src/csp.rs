//! Content-Security-Policy construction for the dashboard (Story 8.8
//! AC #7).
//!
//! The policy was previously a single `const &str` inlined in
//! `lib.rs`. It now lives here so the directive set is reviewable in
//! one place and so the `style-src` directive can gain a per-request
//! nonce (AC #6) without touching the asset-serving code.
//!
//! Every directive except `style-src` is fixed. `style-src` takes an
//! optional per-request nonce:
//!
//! - `None` keeps the legacy `'unsafe-inline'` fallback (used until
//!   the CSP3 nonce path is fully wired end to end).
//! - `Some(nonce)` emits `'self' 'nonce-<nonce>'` and drops
//!   `'unsafe-inline'`, the hardened CSP3 posture.

/// The connect-src source list: same-origin document plus same-host
/// WebSocket schemes scoped to the loopback addresses the management
/// API binds to. A `:*` port wildcard keeps the policy honest across
/// operator `management_port` overrides without admitting arbitrary
/// remote `ws://attacker.example` connections (v1.5.1 audit L-2).
const CONNECT_SRC: &str = "connect-src 'self' \
ws://localhost:* ws://127.0.0.1:* ws://[::1]:* \
wss://localhost:* wss://127.0.0.1:* wss://[::1]:*";

/// Build the `Content-Security-Policy` header value.
///
/// When `style_nonce` is `Some`, the `style-src` directive is
/// `'self' 'nonce-<nonce>'` (no `'unsafe-inline'`); when `None` it is
/// `'self' 'unsafe-inline'` (the pre-CSP3 fallback).
///
/// ```
/// let with_nonce = lorica_dashboard::csp::build_csp(Some("abc123"));
/// assert!(with_nonce.contains("style-src 'self' 'nonce-abc123'"));
/// assert!(!with_nonce.contains("'unsafe-inline'"));
///
/// let fallback = lorica_dashboard::csp::build_csp(None);
/// assert!(fallback.contains("style-src 'self' 'unsafe-inline'"));
/// ```
pub fn build_csp(style_nonce: Option<&str>) -> String {
    let style_src = match style_nonce {
        Some(nonce) => format!("style-src 'self' 'nonce-{nonce}'"),
        None => "style-src 'self' 'unsafe-inline'".to_string(),
    };
    format!(
        "default-src 'self'; \
script-src 'self'; \
{style_src}; \
img-src 'self' data:; \
{CONNECT_SRC}; \
frame-ancestors 'none'; \
form-action 'self'; \
base-uri 'none'; \
object-src 'none'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_variant_drops_unsafe_inline() {
        let csp = build_csp(Some("R4nd0mNonce"));
        assert!(csp.contains("style-src 'self' 'nonce-R4nd0mNonce'"));
        assert!(!csp.contains("'unsafe-inline'"));
        // The other directives are unchanged.
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("img-src 'self' data:"));
        assert!(csp.contains("ws://127.0.0.1:*"));
    }

    #[test]
    fn fallback_variant_keeps_unsafe_inline() {
        let csp = build_csp(None);
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
    }
}
