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
async fn test_csp_header_restricts_websocket_to_loopback() {
    // v1.5.1 audit L-2 : the previous CSP carried a bare `ws:`
    // token in `connect-src` which admitted WebSocket connections
    // to any host (`ws://attacker.example`). Verify the header
    // restricts to same-host loopback only.
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/")
        .body(axum::body::Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let csp = res
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be set on dashboard responses")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("default-src 'self'"),
        "CSP must keep default-src 'self', got: {csp}"
    );
    assert!(
        csp.contains("ws://localhost:*"),
        "CSP must allow same-host WebSocket on localhost, got: {csp}"
    );
    assert!(
        csp.contains("ws://127.0.0.1:*"),
        "CSP must allow same-host WebSocket on 127.0.0.1, got: {csp}"
    );
    // Regression pin : the bare `ws:` token must NOT appear (no
    // host = matches any host).
    assert!(
        !csp.contains(" ws: ") && !csp.ends_with(" ws:") && !csp.contains(" ws:;"),
        "CSP must not carry a bare `ws:` token (admits any host), got: {csp}"
    );
    // v1.5.2 audit L-5 : defense-in-depth directives.
    assert!(
        csp.contains("frame-ancestors 'none'"),
        "CSP must carry `frame-ancestors 'none'` (CSP-level XFO supersede), got: {csp}"
    );
    assert!(
        csp.contains("form-action 'self'"),
        "CSP must carry `form-action 'self'` (XSS-injected form defense), got: {csp}"
    );
    assert!(
        csp.contains("base-uri 'none'"),
        "CSP must carry `base-uri 'none'` (defends against `<base href>` redirection), got: {csp}"
    );
    assert!(
        csp.contains("object-src 'none'"),
        "CSP must carry `object-src 'none'` (Flash / plugin block), got: {csp}"
    );
}

#[tokio::test]
async fn test_csp_header_present_on_spa_fallback() {
    // The SPA fallback path also serves index.html ; it must
    // carry the same CSP so a deep-link refresh isn't a security
    // downgrade.
    let app = app();
    let req = axum::http::Request::builder()
        .uri("/routes")
        .body(axum::body::Body::empty())
        .unwrap();
    let res = app.oneshot(req).await.unwrap();
    let csp = res
        .headers()
        .get("content-security-policy")
        .expect("CSP header must be set on SPA fallback responses")
        .to_str()
        .unwrap();
    assert!(csp.contains("connect-src 'self'"));
    assert!(!csp.contains(" ws: "));
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
