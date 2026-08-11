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

/// Content-Security-Policy emitted on every dashboard asset.
///
/// The directive set lives in [`csp::build_csp`] (Story 8.8 AC #7).
/// The served value uses the `None` (pre-CSP3) variant: `style-src`
/// keeps `'unsafe-inline'` because the production Vite build extracts
/// component CSS to linked stylesheets while Svelte still emits inline
/// `style=` attributes at runtime, which a `style-src` nonce would not
/// authorize. The nonce-capable variant is wired and unit-tested in
/// `csp.rs` for the follow-up that patches the runtime style emitter.
static CSP_HEADER: LazyLock<String> = LazyLock::new(|| csp::build_csp(None));

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
