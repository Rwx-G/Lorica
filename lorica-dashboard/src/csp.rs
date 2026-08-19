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
/// secure WebSocket scoped to the loopback addresses the management API
/// binds to. The management listener is TLS-only (Story 8.8), so the
/// dashboard is always served over https and the frontend opens `wss://`
/// (a plaintext `ws://` would be blocked as mixed content anyway); the
/// `ws://` loopback sources were dropped as dead policy surface. A `:*`
/// port wildcard keeps the policy honest across operator
/// `management_port` overrides without admitting arbitrary remote
/// `wss://attacker.example` connections (v1.5.1 audit L-2).
const CONNECT_SRC: &str = "connect-src 'self' \
wss://localhost:* wss://127.0.0.1:* wss://[::1]:*";

/// Build the `Content-Security-Policy` header value.
///
/// When `style_nonce` is `Some`, `style-src` is `'self' 'nonce-<nonce>'`
/// (no `'unsafe-inline'`, so an injected `<style>` block is blocked) and a
/// companion `style-src-attr 'unsafe-inline'` is emitted so Svelte 5's
/// runtime inline `style=` attributes keep working - a `style-src` nonce
/// authorizes `<style>` elements, not `style=` attributes (Story 8.8
/// AC #6). When `None`, `style-src` keeps the pre-CSP3 `'unsafe-inline'`
/// fallback and no `style-src-attr` is set.
///
/// ```
/// let with_nonce = lorica_dashboard::csp::build_csp(Some("abc123"));
/// // style-src carries the nonce and NOT 'unsafe-inline'.
/// assert!(with_nonce.contains("style-src 'self' 'nonce-abc123';"));
/// assert!(!with_nonce.contains("style-src 'self' 'unsafe-inline'"));
/// // Inline style= attributes stay allowed via style-src-attr.
/// assert!(with_nonce.contains("style-src-attr 'unsafe-inline'"));
///
/// let fallback = lorica_dashboard::csp::build_csp(None);
/// assert!(fallback.contains("style-src 'self' 'unsafe-inline'"));
/// assert!(!fallback.contains("style-src-attr"));
/// ```
pub fn build_csp(style_nonce: Option<&str>) -> String {
    // `style-src` governs `<style>` elements and `<link rel=stylesheet>`;
    // `style-src-attr` governs inline `style=` attributes. A nonce cannot
    // cover attributes, so the CSP3 posture drops `'unsafe-inline'` from
    // `style-src` (blocking injected stylesheets) while keeping it on
    // `style-src-attr` (Svelte emits `style=` at runtime).
    let style_directives = match style_nonce {
        Some(nonce) => {
            format!("style-src 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'")
        }
        None => "style-src 'self' 'unsafe-inline'".to_string(),
    };
    format!(
        "default-src 'self'; \
script-src 'self'; \
{style_directives}; \
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
    fn nonce_variant_drops_unsafe_inline_from_style_src() {
        let csp = build_csp(Some("R4nd0mNonce"));
        // style-src carries the nonce and drops 'unsafe-inline' (an
        // injected <style> block is blocked).
        assert!(csp.contains("style-src 'self' 'nonce-R4nd0mNonce';"));
        assert!(
            !csp.contains("style-src 'self' 'unsafe-inline'"),
            "style-src must not keep 'unsafe-inline' in the nonce variant"
        );
        // Inline style= attributes (Svelte runtime) stay allowed via
        // the companion style-src-attr directive.
        assert!(csp.contains("style-src-attr 'unsafe-inline'"));
        // The other directives are unchanged.
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("img-src 'self' data:"));
        assert!(csp.contains("wss://127.0.0.1:*"));
        assert!(!csp.contains("ws://127.0.0.1"));
    }

    #[test]
    fn fallback_variant_keeps_unsafe_inline_and_no_attr_directive() {
        let csp = build_csp(None);
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(!csp.contains("style-src-attr"));
    }
}
