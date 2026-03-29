#![deny(clippy::all)]

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "frontend/dist"]
struct DashboardAssets;

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
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, mime.as_ref().to_string()),
                    (
                        header::CACHE_CONTROL,
                        if path.starts_with("assets/") {
                            "public, max-age=31536000, immutable".to_string()
                        } else {
                            "no-cache".to_string()
                        },
                    ),
                ],
                body,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests;
