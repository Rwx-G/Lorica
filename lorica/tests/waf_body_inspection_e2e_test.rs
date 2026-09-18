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

//! True HTTP end-to-end for content-type-aware WAF body inspection.
//!
//! Stands up a real `LoricaProxy` with the WAF in Blocking mode in
//! front of an origin that counts the body bytes it actually receives,
//! and asserts the contract Story 10.6 AC #1 to #4 states:
//!
//! 1. A body the engine cannot parse (`application/octet-stream`) is
//!    never buffered and never measured against the scan window: it
//!    reaches the upstream whole, well past 1 MiB, on a Blocking
//!    route. This is the Nextcloud upload shape.
//! 2. A body the engine can parse is unchanged: over the window it is
//!    still 413, under it a payload is still 403.
//! 3. The v1.5.1 audit H-2 padding bypass stays closed: 1 MiB of
//!    inert text ahead of a payload is still text, so the cap still
//!    applies and the request is still rejected.
//! 4. `max_request_body_bytes` remains the ceiling for the bodies
//!    inspection no longer bounds.
//! 5. Chunked parity: the same verdicts through `request_body_filter`
//!    with no `Content-Length`.
//! 6. Detection mode over the window forwards the whole body after
//!    scanning the prefix, which is the half of audit H-2 that
//!    shipped without a test.
//! 7. AC #5: the per-route `waf_body_scan_max_bytes` widens the window
//!    for the route that sets it and for no other, and a body past the
//!    widened window is still rejected. The oversize semantics of AC
//!    #6 are the same ones, measured against the effective cap.
//!
//! The node-wide in-flight budget (AC #7) is exercised in
//! `waf_body_scan_budget_e2e_test.rs`, which needs a process to itself
//! because the budget is process-wide.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const SCAN_WINDOW: usize = 1_048_576;
const ROUTE_BODY_LIMIT: u64 = 8 * 1_048_576;

// ---------------------------------------------------------------------------
// Origin that counts the body bytes it receives, de-chunking when needed.
// ---------------------------------------------------------------------------

async fn spawn_body_counting_origin() -> (SocketAddr, Arc<AtomicU64>) {
    let received = Arc::new(AtomicU64::new(0));
    let received_c = Arc::clone(&received);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let received = Arc::clone(&received_c);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut scratch = [0u8; 16384];

                // Headers first.
                let header_end = loop {
                    match stream.read(&mut scratch).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&scratch[..n]),
                    }
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                let body_so_far = buf.split_off(header_end);

                let counted = if headers.contains("transfer-encoding: chunked") {
                    read_chunked_body(&mut stream, body_so_far).await
                } else {
                    let want = headers
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    read_sized_body(&mut stream, body_so_far, want).await
                };

                received.fetch_add(counted as u64, Ordering::SeqCst);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, received)
}

async fn read_sized_body(
    stream: &mut tokio::net::TcpStream,
    already: Vec<u8>,
    want: usize,
) -> usize {
    let mut have = already.len();
    let mut scratch = [0u8; 16384];
    while have < want {
        match stream.read(&mut scratch).await {
            Ok(0) | Err(_) => break,
            Ok(n) => have += n,
        }
    }
    have
}

/// Counts payload bytes only, so the assertion compares like for like
/// with what the client sent whichever framing the proxy chose.
async fn read_chunked_body(stream: &mut tokio::net::TcpStream, already: Vec<u8>) -> usize {
    let mut buf = already;
    let mut scratch = [0u8; 16384];
    let mut payload = 0usize;
    let mut cursor = 0usize;
    loop {
        // One chunk header per iteration: `<hex size>\r\n`.
        let line_end = loop {
            if let Some(pos) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                break cursor + pos;
            }
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => return payload,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        };
        let size_hex = String::from_utf8_lossy(&buf[cursor..line_end]).to_string();
        let size = usize::from_str_radix(size_hex.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        if size == 0 {
            return payload;
        }
        payload += size;
        // Skip the chunk body and its trailing CRLF.
        let chunk_end = line_end + 2 + size + 2;
        while buf.len() < chunk_end {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => return payload,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        cursor = chunk_end;
    }
}

// ---------------------------------------------------------------------------
// Raw client: reqwest has no `stream` feature here, and the chunked
// cases need exact control over the framing.
// ---------------------------------------------------------------------------

/// Sends a request and returns the response status code.
///
/// The body is written from a detached task, because a Blocking-mode
/// rejection answers and stops reading before the last byte is on the
/// wire and `write_all` would then block forever. The task parks
/// instead of returning once the write is done: dropping an
/// `OwnedWriteHalf` shuts the write side down, the proxy reads that
/// FIN as a client that went away, and it drops the upstream request
/// mid-flight. A real client keeps the socket open while it waits for
/// the response, so this one does too, until the caller aborts it.
async fn send_request(port: u16, request: Vec<u8>) -> u16 {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut rd, mut wr) = stream.into_split();
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(&request).await;
        let _ = wr.flush().await;
        std::future::pending::<()>().await;
    });

    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    let status = loop {
        match tokio::time::timeout(Duration::from_secs(10), rd.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break 0u16,
            Ok(Ok(n)) => buf.extend_from_slice(&scratch[..n]),
        }
        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..pos]).to_string();
            break line
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
        }
    };
    writer.abort();
    status
}

fn sized_request(port: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    sized_request_to(port, "/upload", content_type, body)
}

fn chunked_request(port: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    chunked_request_to(port, "/upload", content_type, body)
}

// ---------------------------------------------------------------------------
// Shared harness (duplicated from other e2e files; matches their pattern).
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

// ---------------------------------------------------------------------------
// Route / backend fixtures.
// ---------------------------------------------------------------------------

fn waf_route(mode: WafMode) -> Route {
    Route {
        id: "r-waf-body".into(),
        hostname: "_".into(),
        path_prefix: "/".into(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: true,
        waf_mode: mode,
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
        max_request_body_bytes: Some(ROUTE_BODY_LIMIT),
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
        slowloris_threshold_ms: 60_000,
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
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: String::new(),
        node_selector: Vec::new(),
        ai_bot_policy: None,
        ai_bot_spoofed_fallback: None,
        serve_robots_txt: false,
        managed_by: None,
        waf_body_scan_max_bytes: None,
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
        managed_by: None,
        tls_sni: None,
        h2_upstream: false,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

async fn harness(mode: WafMode) -> (ProxyHarness, Arc<AtomicU64>) {
    let (origin, received) = spawn_body_counting_origin().await;
    let route = waf_route(mode);
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![("r-waf-body".into(), "b-primary".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, received)
}

/// Bytes the widened route admits, well past what its scan cap does, so
/// a rejection on that route is the scan cap talking and not
/// `max_request_body_bytes`.
const WIDE_ROUTE_BODY_LIMIT: u64 = 16 * 1_048_576;
/// The per-route scan window of the widened route (Story 10.6 AC #5).
///
/// Twice the default rather than the API's 64 MiB ceiling: what the
/// tests have to show is a window that moved, and every byte under it
/// is a byte the engine really scans, which is wall-clock time in a
/// suite that also has to finish.
const WIDE_SCAN_WINDOW: u64 = 2 * 1_048_576;
/// A body over the default window and under the widened one.
const OVER_DEFAULT_UNDER_WIDE: usize = 1_536 * 1024;
/// Where the payload sits in it: past the default window, so only the
/// widened one reaches it.
const PAYLOAD_OFFSET: usize = 1_280 * 1024;
/// A body over the widened window too.
const OVER_WIDE: usize = 3 * 1_048_576;

/// A second route on the same node, identical to the default one except
/// for the raised per-route scan window and the path that selects it.
///
/// Two routes rather than two harnesses because the claim under test is
/// that the cap is per route: only a config carrying both can show one
/// body rejected on one and scanned on the other.
fn wide_scan_route(mode: WafMode) -> Route {
    Route {
        id: "r-waf-body-wide".into(),
        path_prefix: "/wide".into(),
        max_request_body_bytes: Some(WIDE_ROUTE_BODY_LIMIT),
        waf_body_scan_max_bytes: Some(WIDE_SCAN_WINDOW),
        ..waf_route(mode)
    }
}

async fn harness_with_wide_route(mode: WafMode) -> (ProxyHarness, Arc<AtomicU64>) {
    let (origin, received) = spawn_body_counting_origin().await;
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![
        ("r-waf-body".into(), "b-primary".into()),
        ("r-waf-body-wide".into(), "b-primary".into()),
    ];
    let config = ProxyConfig::from_store(
        vec![waf_route(mode.clone()), wide_scan_route(mode)],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, received)
}

fn sized_request_to(port: u16, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

fn chunked_request_to(port: u16, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for chunk in body.chunks(64 * 1024) {
        req.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        req.extend_from_slice(chunk);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    req
}

/// An inert-text body of `len` bytes carrying a SQLi payload at
/// `payload_at`, which is how a padding attack is shaped.
fn padded_json(len: usize, payload_at: usize) -> Vec<u8> {
    let payload = sqli_json();
    let mut body = vec![b'a'; len];
    body[payload_at..payload_at + payload.len()].copy_from_slice(&payload);
    body
}

fn sqli_json() -> Vec<u8> {
    br#"{"q":"1' UNION SELECT password FROM users--"}"#.to_vec()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_upload_past_the_scan_window_reaches_the_upstream_whole() {
    // The Nextcloud shape: a large PUT the engine cannot parse, on a
    // WAF-Blocking route. Before content-type gating this was a 413
    // for a scan that would have returned Pass on the first byte.
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "binary upload must pass a WAF-Blocking route");
    assert_eq!(
        received.load(Ordering::SeqCst),
        body.len() as u64,
        "the upstream must receive every byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_upload_past_the_route_limit_is_still_rejected() {
    // `max_request_body_bytes` is the only ceiling left once the WAF
    // stops bounding this body. It must still bite.
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; (ROUTE_BODY_LIMIT + 4096) as usize];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 413, "route body limit must still apply");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_past_the_scan_window_is_still_rejected() {
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = vec![b'a'; SCAN_WINDOW + 4096];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "an inspectable body keeps the scan window");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_in_an_inspectable_body_is_still_blocked() {
    let (harness, received) = harness(WafMode::Blocking).await;

    let status = send_request(
        harness.port,
        sized_request(
            harness.port,
            "application/json; charset=utf-8",
            &sqli_json(),
        ),
    )
    .await;

    assert_eq!(status, 403, "the body scan must still fire");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_padding_bypass_stays_closed() {
    // v1.5.1 audit H-2, verbatim: 1 MiB of inert text ahead of the
    // payload. The prefix is text, so the body is inspectable, so the
    // cap applies and the request is rejected before the upstream
    // sees a byte.
    let (harness, received) = harness(WafMode::Blocking).await;
    let mut body = vec![b'a'; SCAN_WINDOW];
    body.extend_from_slice(&sqli_json());

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "padding past the window must not slip through");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_declared_as_binary_is_not_inspected() {
    // The residual risk of trusting the declared type, asserted so it
    // is a documented behaviour and not a surprise: `docs/security.md`
    // says exactly this.
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = sqli_json();

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "a spoofed content type skips inspection");
    assert_eq!(received.load(Ordering::SeqCst), body.len() as u64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_binary_upload_past_the_scan_window_reaches_the_upstream_whole() {
    // No Content-Length, so the verdict is taken in
    // `request_body_filter` rather than on the advertised header.
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "chunked binary upload must pass");
    assert_eq!(
        received.load(Ordering::SeqCst),
        body.len() as u64,
        "the upstream must receive every byte"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_json_past_the_scan_window_is_still_rejected() {
    let (harness, received) = harness(WafMode::Blocking).await;
    let body = vec![b'a'; SCAN_WINDOW + 4096];

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "chunked inspectable body keeps the window");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_mode_scans_the_prefix_and_forwards_the_whole_body() {
    // The other half of the v1.5.1 audit H-2 stance, which shipped
    // without a test: an INSPECTABLE body past the window is not
    // rejected in Detection mode. The scan runs on the buffered
    // prefix, one `BodyTruncated` event is emitted, and every byte
    // still reaches the upstream. The payload sits at the front so it
    // falls inside the prefix that is actually scanned.
    let (harness, received) = harness(WafMode::Detection).await;
    let mut body = sqli_json();
    body.resize(SCAN_WINDOW + 4096, b'a');

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 200, "Detection never rejects on the window");
    assert_eq!(
        received.load(Ordering::SeqCst),
        body.len() as u64,
        "the body past the window still goes upstream untouched"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_mode_forwards_a_binary_upload_unchanged() {
    // AC #4: the gate behaves identically in both modes. Detection
    // forwarded this body before the gate too (it only emits a
    // `BodyTruncated` event and proceeds), so what this asserts is
    // that the new branch did not change Detection's outcome. The
    // discriminating assertions are the Blocking ones above.
    let (harness, received) = harness(WafMode::Detection).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200);
    assert_eq!(received.load(Ordering::SeqCst), body.len() as u64);
}

// ---------------------------------------------------------------------------
// Story 10.6 AC #5 / AC #6: the per-route scan window.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_raised_scan_window_catches_a_payload_the_default_would_have_missed() {
    // IV2. 1.5 MiB of JSON with the payload at offset 1.25 MiB. Under
    // the 1 MiB default this body is rejected without ever being
    // scanned; under the route's 2 MiB window the scan runs the whole
    // way and the payload is found, which is the point of the setting.
    let (harness, received) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(OVER_DEFAULT_UNDER_WIDE, PAYLOAD_OFFSET);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 403, "the widened window must scan to the payload");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_past_the_raised_window_is_still_rejected() {
    // IV2, second half: the route raised the window, it did not remove
    // it. 3 MiB is past the 2 MiB window and well under the route's 16
    // MiB body limit, so a 413 here is the scan window talking.
    let (harness, received) = harness_with_wide_route(WafMode::Blocking).await;
    let body = vec![b'a'; OVER_WIDE];

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "the raised window is still a window");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sibling_route_keeps_the_default_window_for_the_same_body() {
    // IV2, third half, and the one that proves the cap is per route
    // rather than global: the same body, the same node, the same
    // configuration snapshot, the route that did not raise its window.
    let (harness, received) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(OVER_DEFAULT_UNDER_WIDE, PAYLOAD_OFFSET);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "the default route keeps the 1 MiB window");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_padding_bypass_stays_closed_at_the_raised_window() {
    // AC #6 against the effective cap rather than the constant: the
    // v1.5.1 audit H-2 case, 1 MiB of inert text ahead of the payload,
    // on a route whose window is 2 MiB. The padding no longer pushes
    // the body out of the window, so the answer is a scan that finds
    // the payload rather than a 413 that never looked. Either way the
    // request does not reach the upstream, which is what H-2 requires.
    let (harness, received) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(SCAN_WINDOW + sqli_json().len(), SCAN_WINDOW);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 403, "padding inside the window is scanned through");
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "nothing reaches upstream"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_parity_for_the_raised_window() {
    // IV3 applied to AC #5: no Content-Length, so the window is read
    // from the cached field inside `request_body_filter` rather than
    // from the advertised header, and the route's value has to be the
    // one that bites. 3 MiB is past the route's 2 MiB window and well
    // under its 16 MiB body limit.
    //
    // The scanned-and-blocked half of the pair is asserted on the
    // Content-Length path instead
    // (`a_raised_scan_window_catches_a_payload_the_default_would_have_missed`):
    // a 403 decided at end of stream races the upstream's own response
    // for the downstream socket, because a chunked body is forwarded
    // as it arrives. The window check here is the part that is
    // specific to the streaming path, and it is decided mid-body.
    //
    // There is no byte assertion here, and it is worth saying why
    // rather than leaving the next reader to wonder: a chunked body is
    // forwarded as it arrives, so the bytes ahead of the window have
    // already left for the upstream when the window is crossed. What
    // the 413 guarantees is that the rest does not follow, which is
    // the audit H-2 stance. The byte-level claim belongs to the
    // Content-Length cases, where nothing is forwarded at all.
    let (harness, _origin_bytes) = harness_with_wide_route(WafMode::Blocking).await;

    let oversize = send_request(
        harness.port,
        chunked_request_to(
            harness.port,
            "/wide/upload",
            "application/json",
            &vec![b'a'; OVER_WIDE],
        ),
    )
    .await;

    assert_eq!(oversize, 413, "chunked body past the raised window");
}
