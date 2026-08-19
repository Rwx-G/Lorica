#![deny(clippy::all)]

use std::sync::LazyLock;

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

pub mod csp;

#[derive(Embed)]
#[folder = "frontend/dist"]
struct DashboardAssets;

/// Content-Security-Policy emitted on non-document dashboard assets
/// (JS/CSS/images). CSP is only enforced against documents, so the
/// static nonce-less variant is fine here; the served `index.html`
/// document gets the hardened per-request nonce variant in
/// [`serve_html_with_nonce`]. Directive set lives in [`csp::build_csp`].
static CSP_HEADER: LazyLock<String> = LazyLock::new(|| csp::build_csp(None));

/// Placeholder the frontend build stamps into the `csp-nonce` meta (and,
/// via Vite, onto the tags it emits). Replaced per request with a fresh
/// random nonce in [`serve_html_with_nonce`] (Story 8.8 AC #6).
const NONCE_PLACEHOLDER: &str = "__LORICA_CSP_NONCE__";

/// Build the dashboard router for serving embedded frontend assets.
///
/// Mount this alongside the API router to serve the dashboard on the
/// same management port:
///
/// ```ignore
/// let app = api_router.merge(lorica_dashboard::router());
/// ```
pub fn router() -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/assets/{*path}", get(static_handler))
        .route(
            "/favicon.png",
            get(|| async { serve_embedded_file("favicon.png") }),
        )
        .route(
            "/logo.png",
            get(|| async { serve_embedded_file("logo.png") }),
        )
        .route(
            "/favicon.svg",
            get(|| async { serve_embedded_file("favicon.svg") }),
        )
        .fallback(get(spa_fallback))
}

async fn index_handler() -> impl IntoResponse {
    serve_html_with_nonce()
}

async fn static_handler(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    serve_embedded_file(path)
}

async fn spa_fallback(uri: Uri) -> impl IntoResponse {
    // API routes should not be handled by the SPA
    let path = uri.path();
    if path.starts_with("/api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_html_with_nonce()
}

/// Generate a 128-bit CSP nonce, hex-encoded (Story 8.8 AC #6). The OS
/// CSPRNG is a platform guarantee on the Linux runtime; a failure here is
/// an unrecoverable fault, so the request panics into a 500 rather than
/// serving the dashboard without a valid nonce.
fn generate_nonce() -> String {
    use std::fmt::Write;
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG unavailable for the CSP nonce");
    // Hex-encode into a single pre-sized buffer (one allocation) rather
    // than a per-byte `format!`.
    let mut nonce = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(nonce, "{b:02x}");
    }
    nonce
}

/// Serve the `index.html` document with a fresh per-request CSP nonce.
///
/// The `__LORICA_CSP_NONCE__` placeholder (in the `csp-nonce` meta and on
/// every tag Vite stamped from it) is replaced with the fresh nonce, and
/// the `Content-Security-Policy` header carries the matching
/// `style-src 'self' 'nonce-<nonce>'` directive (no `'unsafe-inline'`,
/// plus `style-src-attr 'unsafe-inline'` for Svelte's runtime `style=`
/// attributes). The document is never cached so each load gets its own
/// nonce.
fn serve_html_with_nonce() -> Response {
    let Some(content) = DashboardAssets::get("index.html") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let nonce = generate_nonce();
    let html = String::from_utf8_lossy(&content.data).replace(NONCE_PLACEHOLDER, &nonce);
    let mut response = (StatusCode::OK, html).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        "text/html; charset=utf-8".parse().unwrap(),
    );
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        csp::build_csp(Some(&nonce)).parse().unwrap(),
    );
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}

fn serve_embedded_file(path: &str) -> Response {
    match DashboardAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let body = content.data.to_vec();
            let cache_control = if path.starts_with("assets/") {
                "public, max-age=31536000, immutable".to_string()
            } else {
                "no-cache".to_string()
            };
            let mut response = (StatusCode::OK, body).into_response();
            let headers = response.headers_mut();
            headers.insert(header::CONTENT_TYPE, mime.as_ref().parse().unwrap());
            headers.insert(header::CACHE_CONTROL, cache_control.parse().unwrap());
            headers.insert(
                header::CONTENT_SECURITY_POLICY,
                CSP_HEADER.parse().unwrap(),
            );
            headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
            headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
            headers.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
            response
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests;
