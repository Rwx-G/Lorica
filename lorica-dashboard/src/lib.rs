#![deny(clippy::all)]

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "frontend/dist"]
struct DashboardAssets;

/// Content-Security-Policy emitted on every dashboard asset.
///
/// `connect-src` is restricted to the same-origin HTTP(S) document
/// (via `'self'`) plus same-host WebSocket schemes scoped to the
/// loopback addresses Lorica binds the management API to. The
/// management port can be reconfigured via `management_port`, so a
/// `:*` port wildcard keeps the policy honest across operator
/// deployments without admitting arbitrary remote `ws://attacker.example`
/// connections (v1.5.1 audit L-2 - the previous bare `ws:` token
/// allowed any host).
///
/// `style-src 'unsafe-inline'` is still needed for Svelte's runtime-
/// injected scoped styles (audit L-1 - a CSP3 nonce migration is
/// tracked in `docs/backlog.md` as a v2.0 candidate).
const CSP_HEADER: &str = "default-src 'self'; \
script-src 'self'; \
style-src 'self' 'unsafe-inline'; \
img-src 'self' data:; \
connect-src 'self' \
ws://localhost:* ws://127.0.0.1:* ws://[::1]:* \
wss://localhost:* wss://127.0.0.1:* wss://[::1]:*";

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
        .route("/assets/*path", get(static_handler))
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
    serve_embedded_file("index.html")
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
    serve_embedded_file("index.html")
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
