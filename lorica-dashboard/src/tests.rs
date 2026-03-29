use axum::http::StatusCode;
use tower::ServiceExt;

use super::*;

fn app() -> Router {
    router()
}

#[tokio::test]
async fn test_index_returns_html() {
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(
        content_type.contains("text/html"),
        "expected text/html, got {content_type}"
    );
}

#[tokio::test]
async fn test_spa_fallback_serves_index() {
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/routes")
        .body(axum::body::Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    // SPA fallback should serve index.html for non-API, non-asset paths
    assert_eq!(res.status(), StatusCode::OK);
    let content_type = res.headers().get("content-type").unwrap().to_str().unwrap();
    assert!(
        content_type.contains("text/html"),
        "SPA fallback should serve HTML, got {content_type}"
    );
}

#[tokio::test]
async fn test_api_routes_not_intercepted() {
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/api/v1/status")
        .body(axum::body::Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    // API routes should return 404 from the dashboard (not serve index.html)
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_nonexistent_asset_returns_404() {
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/assets/nonexistent.js")
        .body(axum::body::Body::empty())
        .unwrap();

    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_asset_cache_headers() {
    let app = app();

    // Index should have no-cache
    let req = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let cache = res
        .headers()
        .get("cache-control")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cache, "no-cache", "index.html should not be cached");
}
