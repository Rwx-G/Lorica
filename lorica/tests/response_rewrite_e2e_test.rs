// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Phase 4.1 - response body rewriting end-to-end.
//!
//! Drives real HTTP requests through a Pingora `Server` configured
//! with `response_rewrite` rules, against a mock origin that can emit:
//!   - various Content-Types (text/html, application/json, image/png)
//!   - chunked transfer encoding with body split across many chunks
//!   - Content-Encoding: gzip (must be left alone)
//!   - large bodies (overflow path)
//!
//! Asserts: rewritten body matches expectations byte-for-byte, the
//! Content-Length header is dropped (we can't predict rewritten size
//! ahead of time), Content-Encoding=gzip responses are NOT rewritten,
//! and oversize bodies stream through verbatim.

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Configurable mock origin.
//
// Spawned with a closure that receives the raw request text and returns
// the raw bytes to send back (headers + body). This lets each test
// script a precise response - including odd framings like chunked
// transfer encoding or Content-Encoding: gzip - without per-test
// scaffolding.
// ---------------------------------------------------------------------------

async fn spawn_scripted_origin(
    responder: Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let responder = Arc::clone(&responder);
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(4096);
                let mut tmp = [0u8; 4096];
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                            if buf.len() > 64 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let req = String::from_utf8_lossy(&buf);
                let resp_bytes = responder(&req);
                let _ = stream.write_all(&resp_bytes).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn static_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(body);
    out
}

/// Emit the body in `chunk_size`-sized pieces using HTTP/1.1 chunked
/// transfer encoding. Lets us exercise the cross-chunk rewrite path:
/// if our engine only rewrote one chunk at a time, a pattern straddling
/// a chunk boundary would be missed. Our implementation buffers the
/// whole body (up to max_body_bytes) before running the regex, so
/// straddling patterns are covered - this test pins the behaviour.
fn chunked_response(content_type: &str, body: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Transfer-Encoding: chunked\r\n\
         Connection: close\r\n\
         \r\n"
    )
    .into_bytes();
    for piece in body.chunks(chunk_size) {
        out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        out.extend_from_slice(piece);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"0\r\n\r\n");
    out
}

fn gzip_response(content_type: &str, gzipped_body: &[u8]) -> Vec<u8> {
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Encoding: gzip\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        gzipped_body.len()
    );
    let mut out = header.into_bytes();
    out.extend_from_slice(gzipped_body);
    out
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct ManualShutdown {
    rx: tokio::sync::watch::Receiver<bool>,
}

#[async_trait]
impl ShutdownSignalWatch for ManualShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.rx.clone();
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                break;
            }
        }
        ShutdownSignal::FastShutdown
    }
}

fn reserve_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("proxy never bound 127.0.0.1:{port}");
}

fn init_crypto_provider_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn test_route(rewrite: Option<ResponseRewriteConfig>) -> Route {
    Route {
        id: "r-rw".into(),
        hostname: "_".into(),
        path_prefix: "/".into(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: false,
        waf_mode: WafMode::Detection,
        enabled: true,
        force_https: false,
        redirect_hostname: None,
        redirect_to: None,
        hostname_aliases: Vec::new(),
        proxy_headers: std::collections::HashMap::new(),
        response_headers: std::collections::HashMap::new(),
        security_headers: "none".into(),
        connect_timeout_s: 5,
        read_timeout_s: 30,
        send_timeout_s: 30,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: false,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: false,
        rate_limit_rps: None,
        rate_limit_burst: None,
        ip_allowlist: Vec::new(),
        ip_denylist: Vec::new(),
        cors_allowed_origins: Vec::new(),
        cors_allowed_methods: Vec::new(),
        cors_max_age_s: None,
        compression_enabled: false,
        retry_attempts: None,
        cache_enabled: false,
        cache_ttl_s: 300,
        cache_max_bytes: 52_428_800,
        max_connections: None,
        slowloris_threshold_ms: 5_000,
        auto_ban_threshold: None,
        auto_ban_duration_s: 3_600,
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 0,
        stale_if_error_s: 0,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: rewrite,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn test_backend(id: &str, addr: SocketAddr) -> Backend {
    Backend {
        id: id.into(),
        address: addr.to_string(),
        name: id.into(),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
        health_check_enabled: false,
        health_check_interval_s: 10,
        health_check_path: None,
        lifecycle_state: LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: false,
        tls_skip_verify: false,
        tls_sni: None,
        h2_upstream: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

struct ProxyHarness {
    port: u16,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProxyHarness {
    async fn start(config: Arc<ArcSwap<ProxyConfig>>) -> Self {
        init_crypto_provider_once();
        let log_buffer = Arc::new(lorica_api::logs::LogBuffer::new(128));
        let active_conns = Arc::new(AtomicU64::new(0));
        let sla = Arc::new(lorica_bench::passive_sla::SlaCollector::new());
        let proxy = LoricaProxy::new(config, log_buffer, active_conns, sla);

        let port = reserve_port();
        let proxy_addr = format!("127.0.0.1:{port}");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let thread = std::thread::spawn(move || {
            let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
                upstream_keepalive_pool_size: 0,
                ..Default::default()
            });
            let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, proxy);
            proxy_service.add_tcp(&proxy_addr);
            let mut server = Server::new(None).unwrap();
            server.add_service(proxy_service);
            server.bootstrap();
            server.run(RunArgs {
                shutdown_signal: Box::new(ManualShutdown { rx: shutdown_rx }),
            });
        });
        wait_for_port(port).await;
        Self {
            port,
            shutdown_tx,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }
}

impl Drop for ProxyHarness {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.thread.take() {
            std::thread::spawn(move || {
                let _ = t.join();
            });
        }
    }
}

fn literal(pattern: &str, replacement: &str) -> ResponseRewriteRule {
    ResponseRewriteRule {
        pattern: pattern.into(),
        replacement: replacement.into(),
        is_regex: false,
        max_replacements: None,
    }
}

fn simple_cfg(rules: Vec<ResponseRewriteRule>) -> ResponseRewriteConfig {
    ResponseRewriteConfig {
        rules,
        max_body_bytes: 1_048_576,
        content_type_prefixes: vec![],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_literal_html_body_end_to_end() {
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        static_response(
            "text/html; charset=utf-8",
            b"<html><body>backend at http://internal.svc:8080/api</body></html>",
        )
    }))
    .await;

    let route = test_route(Some(simple_cfg(vec![literal(
        "http://internal.svc:8080",
        "https://api.example.com",
    )])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    // Content-Length must be gone: the rewrite produces a body of
    // different length, so the header would lie.
    assert!(
        resp.headers().get("content-length").is_none(),
        "Content-Length must be stripped for rewritten responses"
    );
    let body = resp.text().await.unwrap();
    assert_eq!(
        body,
        "<html><body>backend at https://api.example.com/api</body></html>"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_across_chunk_boundaries() {
    // Emit "secret-key-123" split across 3 chunks, with the pattern
    // "secret-key-123" straddling at least one chunk boundary. A
    // naive chunk-local rewrite would miss the match; our buffered
    // implementation catches it.
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        chunked_response("text/plain", b"before-secret-key-123-after", 7)
    }))
    .await;
    let route = test_route(Some(simple_cfg(vec![literal(
        "secret-key-123",
        "[redacted]",
    )])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    assert_eq!(resp.text().await.unwrap(), "before-[redacted]-after");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_skips_non_text_content_type() {
    // Default prefix is "text/" when the list is empty, so a PNG
    // response must NOT be rewritten even if its body happens to
    // contain bytes matching a literal pattern.
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        // Fake PNG: include literal "secret" bytes that would match
        // the rule if the filter wrongly applied.
        static_response("image/png", b"\x89PNG\r\n\x1a\nsecret-bytes-inside")
    }))
    .await;
    let route = test_route(Some(simple_cfg(vec![literal("secret-bytes-inside", "[R]")])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        b"\x89PNG\r\n\x1a\nsecret-bytes-inside",
        "non-text responses must pass through unchanged"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_skips_gzip_encoded_responses() {
    // Pretend-gzip body: a fake payload that CONTAINS the literal
    // "v1" sequence. If the engine wrongly rewrote it, the supposedly-
    // compressed bytes would come back altered.
    let payload: Vec<u8> = b"\x1f\x8b\x08-fake-gzip-with-v1-inside".to_vec();
    let payload_cloned = payload.clone();
    let origin = spawn_scripted_origin(Arc::new(move |_req| {
        gzip_response("text/plain", &payload_cloned)
    }))
    .await;
    let route = test_route(Some(simple_cfg(vec![literal("v1", "v2")])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    // Tell reqwest not to decompress so we observe exactly what the
    // proxy emits on the wire.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        payload.as_slice(),
        "gzip-encoded responses must NOT be rewritten (would corrupt the compressed stream)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_regex_with_capture_groups_end_to_end() {
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        static_response("text/plain", b"user=alice email=alice@example.com")
    }))
    .await;
    // Redact everything after `email=` up to the next whitespace.
    let route = test_route(Some(simple_cfg(vec![ResponseRewriteRule {
        pattern: r"email=(\S+)".into(),
        replacement: "email=[redacted:$1]".into(),
        is_regex: true,
        max_replacements: None,
    }])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    assert_eq!(
        resp.text().await.unwrap(),
        "user=alice email=[redacted:alice@example.com]"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_oversize_body_streams_unchanged() {
    // max_body_bytes = 128 so a 512-byte payload blows the cap. The
    // engine falls back to streaming the original body through the
    // client. Better to pass through than emit a half-rewritten body.
    let payload = vec![b'a'; 512];
    let payload_cloned = payload.clone();
    let origin = spawn_scripted_origin(Arc::new(move |_req| {
        // Use chunked so the engine exercises the multi-chunk path.
        chunked_response("text/plain", &payload_cloned, 64)
    }))
    .await;
    let mut cfg = simple_cfg(vec![literal("aa", "XX")]);
    cfg.max_body_bytes = 128;
    let route = test_route(Some(cfg));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    let body = resp.bytes().await.unwrap();
    assert_eq!(
        body.as_ref(),
        payload.as_slice(),
        "oversize body must pass through verbatim (no partial rewrite)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_disabled_route_passes_body_through() {
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        static_response("text/html", b"nothing-to-see")
    }))
    .await;
    let route = test_route(None);
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    // Content-Length MUST still be present when rewrite is off -
    // proves we only drop it on the rewrite path.
    assert!(resp.headers().get("content-length").is_some());
    assert_eq!(resp.text().await.unwrap(), "nothing-to-see");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_skipped_for_head_requests_preserves_content_length() {
    // HEAD responses MUST report the same Content-Length a GET would
    // produce (RFC 7231 §4.3.2). If we stripped Content-Length on
    // HEAD just because the route has a rewrite config, clients
    // sizing range requests off HEAD responses would break.
    let origin = spawn_scripted_origin(Arc::new(|req| {
        let method = req.lines().next().unwrap_or("").split_whitespace().next().unwrap_or("GET");
        if method == "HEAD" {
            // HEAD: headers only, no body (origin server-side we
            // send empty body + matching Content-Length).
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: 42\r\n\
                 Connection: close\r\n\
                 \r\n"
            )
            .into_bytes()
        } else {
            static_response("text/html", b"<html>backend response body</html>")
        }
    }))
    .await;
    let route = test_route(Some(simple_cfg(vec![literal("backend", "frontend")])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.head(&harness.url()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-length").and_then(|v| v.to_str().ok()),
        Some("42"),
        "HEAD response must preserve Content-Length even on rewrite-enabled routes"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_is_disabled_when_cache_enabled_on_same_route() {
    // v1 contract: response_rewrite and cache_enabled are mutually
    // exclusive per route (the cache captures raw upstream bytes and
    // re-streams them through response_body_filter, which would
    // either double-rewrite or collide with our Content-Length
    // stripping). The engine logs a warning and disables rewrite
    // for that response - rather than silently emitting corrupt
    // output. This test pins that escape hatch.
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        static_response("text/html", b"<html>backend response body</html>")
    }))
    .await;
    let mut route = test_route(Some(simple_cfg(vec![literal("backend", "frontend")])));
    route.cache_enabled = true;
    route.cache_ttl_s = 60;
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    // Rewrite is suppressed: the original "backend" substring must
    // still appear in the client-visible body. If a future version
    // wires cache + rewrite together this test will fail - that's
    // the signal to remove the warning and update the contract.
    assert_eq!(
        body, "<html>backend response body</html>",
        "cache_enabled must suppress response_rewrite in v1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrite_multiple_rules_compose_in_declaration_order() {
    let origin = spawn_scripted_origin(Arc::new(|_req| {
        static_response("text/plain", b"one fish, two fish, red fish, blue fish")
    }))
    .await;
    let route = test_route(Some(simple_cfg(vec![
        literal("fish", "bird"),
        // Second rule operates on the output of the first.
        literal("red bird", "crow"),
    ])));
    let backends = vec![test_backend("b1", origin)];
    let links = vec![("r-rw".into(), "b1".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = client.get(&harness.url()).send().await.unwrap();
    assert_eq!(
        resp.text().await.unwrap(),
        "one bird, two bird, crow, blue bird"
    );
}
