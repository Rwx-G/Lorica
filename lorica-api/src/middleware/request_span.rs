//! Minimal per-request tracing span for the management API
//! (Story 8.9 AC #4).
//!
//! The proxy data plane has a rich `http_request` span; the API had
//! none, so `lorica::audit` events fell outside any request span and
//! OTel users could not pivot from a trace to its audit footprint.
//! This wraps every API request in an `api_request` span carrying the
//! method and path. It stays deliberately thin: the API is a
//! low-volume management surface, not the hot path.

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// Axum middleware wrapping the request in an `api_request` span.
pub async fn api_request_span(req: Request, next: Next) -> Response {
    let span = tracing::info_span!(
        "api_request",
        "http.request.method" = %req.method(),
        "url.path" = %req.uri().path(),
    );
    next.run(req).instrument(span).await
}
