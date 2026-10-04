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
//! front of an origin that records the body bytes it actually receives,
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
//! 8. The Blocking-mode hold: a body the engine scans is read in full
//!    before the upstream is dialled. A refused one, whatever refused
//!    it and whatever its framing, never reaches the origin, not even
//!    as a connection; a clean one arrives byte for byte; a client
//!    that sent `Expect: 100-continue` is answered by the proxy.
//!    Detection mode still streams.
//!
//! "The origin never saw it" is asserted with a probe rather than a
//! wait (`assert_origin_untouched`), so no assertion here depends on
//! timing.
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
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

const SCAN_WINDOW: usize = 1_048_576;
const ROUTE_BODY_LIMIT: u64 = 8 * 1_048_576;
/// Size of the chunks the raw client frames a chunked body into.
const CLIENT_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// Origin that records the body bytes it receives, de-chunking when needed.
// ---------------------------------------------------------------------------

/// What one upstream connection carried, reported once the origin has
/// stopped reading it.
struct UpstreamRequest {
    /// Request line and headers, lowercased.
    head: String,
    /// Payload bytes, whichever framing the proxy chose. Only whole
    /// chunks count, so a body cut off mid-chunk reports the bytes that
    /// actually arrived rather than the size its last header promised.
    body: Vec<u8>,
    /// The body ended on its own framing: the terminating chunk, or the
    /// last byte of the advertised `Content-Length`. An origin only acts
    /// on a request that completes; one cut off mid-body is discarded.
    complete: bool,
}

impl std::fmt::Debug for UpstreamRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamRequest")
            .field("request_line", &self.head.lines().next().unwrap_or(""))
            .field("body_len", &self.body.len())
            .field("complete", &self.complete)
            .finish()
    }
}

/// The test's view of the origin.
struct Upstream {
    /// Payload bytes received across every connection.
    received: Arc<AtomicU64>,
    /// Connections the origin accepted, counted at `accept`.
    accepted: Arc<AtomicU64>,
    requests: mpsc::UnboundedReceiver<UpstreamRequest>,
    /// One message per connection, as soon as its first payload bytes
    /// arrive, before the body is over.
    body_started: mpsc::UnboundedReceiver<()>,
}

async fn spawn_origin() -> (SocketAddr, Upstream) {
    let received = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let (requests_tx, requests) = mpsc::unbounded_channel();
    let (started_tx, body_started) = mpsc::unbounded_channel();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let received_c = Arc::clone(&received);
    let accepted_c = Arc::clone(&accepted);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            accepted_c.fetch_add(1, Ordering::SeqCst);
            let received = Arc::clone(&received_c);
            let requests_tx = requests_tx.clone();
            let started_tx = started_tx.clone();
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
                let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                let body_so_far = buf.split_off(header_end);

                let request = if head.contains("transfer-encoding: chunked") {
                    read_chunked_body(&mut stream, head, body_so_far, &started_tx).await
                } else {
                    let want = head
                        .split("content-length:")
                        .nth(1)
                        .and_then(|rest| rest.split("\r\n").next())
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    read_sized_body(&mut stream, head, body_so_far, want, &started_tx).await
                };

                received.fetch_add(request.body.len() as u64, Ordering::SeqCst);
                let complete = request.complete;
                let _ = requests_tx.send(request);
                if !complete {
                    return;
                }
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (
        addr,
        Upstream {
            received,
            accepted,
            requests,
            body_started,
        },
    )
}

async fn read_sized_body(
    stream: &mut tokio::net::TcpStream,
    head: String,
    already: Vec<u8>,
    want: usize,
    started: &mpsc::UnboundedSender<()>,
) -> UpstreamRequest {
    let mut body = already;
    let mut announced = false;
    let mut scratch = [0u8; 16384];
    loop {
        if !announced && !body.is_empty() {
            announced = true;
            let _ = started.send(());
        }
        if body.len() >= want {
            break;
        }
        match stream.read(&mut scratch).await {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&scratch[..n]),
        }
    }
    let complete = body.len() >= want;
    UpstreamRequest {
        head,
        body,
        complete,
    }
}

async fn read_chunked_body(
    stream: &mut tokio::net::TcpStream,
    head: String,
    already: Vec<u8>,
    started: &mpsc::UnboundedSender<()>,
) -> UpstreamRequest {
    let mut buf = already;
    let mut scratch = [0u8; 16384];
    let mut body = Vec::new();
    let mut cursor = 0usize;
    loop {
        // One chunk header per iteration: `<hex size>\r\n`.
        let line_end = loop {
            if let Some(pos) = buf[cursor..].windows(2).position(|w| w == b"\r\n") {
                break cursor + pos;
            }
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => {
                    return UpstreamRequest {
                        head,
                        body,
                        complete: false,
                    }
                }
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        };
        let size_hex = String::from_utf8_lossy(&buf[cursor..line_end]).to_string();
        let size = usize::from_str_radix(size_hex.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        if size == 0 {
            return UpstreamRequest {
                head,
                body,
                complete: true,
            };
        }
        // The chunk body and its trailing CRLF.
        let data_start = line_end + 2;
        let chunk_end = data_start + size + 2;
        while buf.len() < chunk_end {
            match stream.read(&mut scratch).await {
                Ok(0) | Err(_) => {
                    return UpstreamRequest {
                        head,
                        body,
                        complete: false,
                    }
                }
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        if body.is_empty() {
            let _ = started.send(());
        }
        body.extend_from_slice(&buf[data_start..data_start + size]);
        cursor = chunk_end;
    }
}

/// The next request the origin finished reading, however it ended.
///
/// This is the synchronisation point the byte counter cannot give: the
/// origin reports a request only once it has stopped reading it, so an
/// assertion made after this returns no longer races the proxy's
/// upstream leg. The timeout bounds a hang, it is not a wait for a
/// condition to settle.
async fn next_upstream_request(
    requests: &mut mpsc::UnboundedReceiver<UpstreamRequest>,
) -> UpstreamRequest {
    tokio::time::timeout(Duration::from_secs(10), requests.recv())
        .await
        .expect("the origin never finished reading an upstream request")
        .expect("the origin stopped accepting connections")
}

fn probe_request(port: u16) -> Vec<u8> {
    format!("GET /probe HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Asserts the origin never saw the request the proxy just refused:
/// not a byte, not even a connection.
///
/// A probe sent after the refusal's response reaches the origin on a
/// connection of its own. The origin accepts connections one at a time
/// in arrival order, and any connection the proxy opened for the
/// refused request was opened before that response was written, so by
/// the time the origin has read the probe it has accepted that
/// connection too. Nothing here waits for anything to settle.
async fn assert_origin_untouched(port: u16, upstream: &mut Upstream) {
    let status = send_request(port, probe_request(port)).await;
    assert_eq!(status, 200, "the probe must be proxied");
    let seen = next_upstream_request(&mut upstream.requests).await;
    assert!(
        seen.head.starts_with("get /probe "),
        "the first request the origin read must be the probe, not the refused one: {seen:?}"
    );
    assert_eq!(
        upstream.accepted.load(Ordering::SeqCst),
        1,
        "the refused request must never have been dialled upstream"
    );
    assert_eq!(
        upstream.received.load(Ordering::SeqCst),
        0,
        "the origin must hold zero bytes of the refused body"
    );
}

/// Asserts the origin received exactly `body`, complete, on one request.
async fn assert_arrived_whole(upstream: &mut Upstream, body: &[u8]) {
    let seen = next_upstream_request(&mut upstream.requests).await;
    assert!(seen.complete, "the body must complete upstream: {seen:?}");
    assert_eq!(
        seen.body.len(),
        body.len(),
        "the upstream must receive every byte: {seen:?}"
    );
    assert!(
        seen.body == body,
        "the upstream must receive the body byte for byte"
    );
}

// ---------------------------------------------------------------------------
// Raw client: reqwest has no `stream` feature here, and the chunked
// cases need exact control over the framing.
// ---------------------------------------------------------------------------

/// Reads one response header block and returns its status code, `0` on
/// a closed or silent connection. Bytes past the block stay in `buf`.
async fn read_status(rd: &mut OwnedReadHalf, buf: &mut Vec<u8>) -> u16 {
    let mut scratch = [0u8; 4096];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let block: Vec<u8> = buf.drain(..end + 4).collect();
            let line = String::from_utf8_lossy(&block);
            return line
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
        }
        match tokio::time::timeout(Duration::from_secs(10), rd.read(&mut scratch)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return 0,
            Ok(Ok(n)) => buf.extend_from_slice(&scratch[..n]),
        }
    }
}

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
    let status = read_status(&mut rd, &mut Vec::new()).await;
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

/// Every route given, all linked to one origin.
async fn harness_with_routes(routes: Vec<Route>) -> (ProxyHarness, Upstream) {
    let (origin, upstream) = spawn_origin().await;
    let links = routes
        .iter()
        .map(|r| (r.id.clone(), "b-primary".to_string()))
        .collect();
    let config = ProxyConfig::from_store(
        routes,
        vec![test_backend("b-primary", origin)],
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, upstream)
}

async fn harness(mode: WafMode) -> (ProxyHarness, Upstream) {
    harness_with_routes(vec![waf_route(mode)]).await
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

async fn harness_with_wide_route(mode: WafMode) -> (ProxyHarness, Upstream) {
    harness_with_routes(vec![waf_route(mode.clone()), wide_scan_route(mode)]).await
}

/// A route whose `max_request_body_bytes` sits under the scan window,
/// so a chunked body is refused by the route limit before the window.
const SMALL_ROUTE_BODY_LIMIT: u64 = 256 * 1024;

fn small_limit_route(mode: WafMode) -> Route {
    Route {
        id: "r-waf-body-small".into(),
        path_prefix: "/small".into(),
        max_request_body_bytes: Some(SMALL_ROUTE_BODY_LIMIT),
        ..waf_route(mode)
    }
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

fn chunked_head(port: u16, path: &str, content_type: &str) -> Vec<u8> {
    format!(
        "PUT {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

/// `body` framed as `CLIENT_CHUNK`-sized chunks, without the
/// terminating chunk.
fn chunk_frames(body: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(body.len() + 64);
    for chunk in body.chunks(CLIENT_CHUNK) {
        framed.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        framed.extend_from_slice(chunk);
        framed.extend_from_slice(b"\r\n");
    }
    framed
}

const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

fn chunked_request_to(port: u16, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = chunked_head(port, path, content_type);
    req.extend_from_slice(&chunk_frames(body));
    req.extend_from_slice(LAST_CHUNK);
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

/// A clean inspectable body of `len` bytes in which every position
/// differs from its neighbours, so a dropped, duplicated or reordered
/// run of bytes changes the content and not just the length. Lowercase
/// hex digits and spaces only, which no WAF rule matches.
fn patterned_text(len: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(len + 9);
    let mut counter = 0u32;
    while body.len() < len {
        body.extend_from_slice(format!("{counter:08x} ").as_bytes());
        counter += 1;
    }
    body.truncate(len);
    body
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_upload_past_the_scan_window_reaches_the_upstream_whole() {
    // The Nextcloud shape: a large PUT the engine cannot parse, on a
    // WAF-Blocking route. Before content-type gating this was a 413
    // for a scan that would have returned Pass on the first byte.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "binary upload must pass a WAF-Blocking route");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn binary_upload_past_the_route_limit_is_still_rejected() {
    // `max_request_body_bytes` is the only ceiling left once the WAF
    // stops bounding this body. It must still bite.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; (ROUTE_BODY_LIMIT + 4096) as usize];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 413, "route body limit must still apply");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn json_past_the_scan_window_is_still_rejected() {
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = vec![b'a'; SCAN_WINDOW + 4096];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "an inspectable body keeps the scan window");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_in_an_inspectable_body_is_still_blocked() {
    // The body is read and scanned before the upstream is dialled, so a
    // block leaves the origin with nothing at all.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;

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
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_padding_bypass_stays_closed() {
    // v1.5.1 audit H-2, verbatim: 1 MiB of inert text ahead of the
    // payload. The prefix is text, so the body is inspectable, so the
    // cap applies and the request is rejected before the upstream
    // sees a byte.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let mut body = vec![b'a'; SCAN_WINDOW];
    body.extend_from_slice(&sqli_json());

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "padding past the window must not slip through");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_declared_as_binary_is_not_inspected() {
    // The residual risk of trusting the declared type, asserted so it
    // is a documented behaviour and not a surprise: `docs/security.md`
    // says exactly this.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = sqli_json();

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "a spoofed content type skips inspection");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_binary_upload_past_the_scan_window_reaches_the_upstream_whole() {
    // No Content-Length, so the verdict is taken in
    // `request_body_filter` rather than on the advertised header.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200, "chunked binary upload must pass");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_json_past_the_scan_window_is_still_rejected() {
    // No Content-Length, so the window is crossed mid-body. The body is
    // held until the verdict rather than forwarded as it arrives, so
    // the unscanned first window never leaves the proxy: the origin is
    // not even dialled.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = vec![b'a'; SCAN_WINDOW + 4096];

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "chunked inspectable body keeps the window");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_in_a_chunked_body_never_reaches_upstream() {
    // The end-of-stream half of the same contract. The verdict needs the
    // terminating chunk; until it arrives every chunk before it is held,
    // so a 403 leaves nothing behind upstream.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/json", &sqli_json()),
    )
    .await;

    assert_eq!(status, 403, "the body scan must fire on a chunked body");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payload_at_the_end_of_a_long_chunked_body_never_reaches_upstream() {
    // Many chunks, the payload in the last ones, on the route whose
    // window admits the whole body: every chunk ahead of the payload is
    // clean and would have been forwarded by a streaming proxy.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(OVER_DEFAULT_UNDER_WIDE, PAYLOAD_OFFSET);

    let status = send_request(
        harness.port,
        chunked_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 403, "the payload past the default window is found");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_json_past_the_route_limit_never_reaches_upstream() {
    // The third refusal a held body can meet: `max_request_body_bytes`
    // under the scan window, crossed mid-body on a chunked request.
    let (harness, mut upstream) = harness_with_routes(vec![
        waf_route(WafMode::Blocking),
        small_limit_route(WafMode::Blocking),
    ])
    .await;
    let body = patterned_text(2 * SMALL_ROUTE_BODY_LIMIT as usize);

    let status = send_request(
        harness.port,
        chunked_request_to(harness.port, "/small/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "the route limit bites before the window");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_body_of_the_scan_window_arrives_whole() {
    // The largest body the default window admits, held, scanned and
    // then forwarded in one piece: nothing lost, nothing reordered.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = patterned_text(SCAN_WINDOW);

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 200, "a clean body at the window is admitted");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_chunked_body_of_the_scan_window_arrives_whole() {
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = patterned_text(SCAN_WINDOW);

    let status = send_request(
        harness.port,
        chunked_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(
        status, 200,
        "a clean chunked body at the window is admitted"
    );
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_clean_body_past_the_default_window_arrives_whole_where_the_route_allows_it() {
    // Larger than the default window, under the route's widened one,
    // with both framings: the hold is bounded by the route's window,
    // not by the default.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = patterned_text(OVER_DEFAULT_UNDER_WIDE);

    let sized = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;
    assert_eq!(sized, 200, "Content-Length body under the widened window");
    assert_arrived_whole(&mut upstream, &body).await;

    let chunked = send_request(
        harness.port,
        chunked_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;
    assert_eq!(chunked, 200, "chunked body under the widened window");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expect_continue_is_answered_by_the_proxy_while_the_body_is_held() {
    // The client waits for `100 Continue` before it sends the body. The
    // upstream that would normally give it is not dialled until the body
    // has been scanned, and this origin never sends one anyway, so the
    // go-ahead has to come from the proxy. The upstream request then
    // carries the body and no `Expect` of its own.
    let (harness, mut upstream) = harness(WafMode::Blocking).await;
    let body = patterned_text(256 * 1024);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", harness.port))
        .await
        .unwrap();
    let (mut rd, mut wr) = stream.into_split();
    let head = format!(
        "PUT /upload HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        harness.port,
        body.len()
    );
    wr.write_all(head.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    assert_eq!(
        read_status(&mut rd, &mut buf).await,
        100,
        "the proxy must give the go-ahead itself"
    );
    // Nothing has been dialled while the body is outstanding: the probe
    // is the first and only request the origin has seen.
    let probe = send_request(harness.port, probe_request(harness.port)).await;
    assert_eq!(probe, 200);
    let seen = next_upstream_request(&mut upstream.requests).await;
    assert!(seen.head.starts_with("get /probe "), "{seen:?}");
    assert_eq!(upstream.accepted.load(Ordering::SeqCst), 1);

    wr.write_all(&body).await.unwrap();
    assert_eq!(read_status(&mut rd, &mut buf).await, 200);
    let seen = next_upstream_request(&mut upstream.requests).await;
    assert!(seen.complete, "{seen:?}");
    assert!(seen.body == body, "the body arrives byte for byte");
    assert!(
        !seen.head.contains("\r\nexpect:"),
        "the upstream is not asked for a go-ahead of its own"
    );
    drop(wr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_mode_streams_the_body_as_it_arrives() {
    // Detection never refuses a body, so it has nothing to hold it for.
    // The client sends the first chunk and stops: the origin must have
    // it before the client sends the rest.
    let (harness, mut upstream) = harness(WafMode::Detection).await;
    let body = patterned_text(4 * CLIENT_CHUNK);
    let (first, rest) = body.split_at(CLIENT_CHUNK);

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", harness.port))
        .await
        .unwrap();
    let (mut rd, mut wr) = stream.into_split();
    let mut opening = chunked_head(harness.port, "/upload", "application/json");
    opening.extend_from_slice(&chunk_frames(first));
    wr.write_all(&opening).await.unwrap();

    tokio::time::timeout(Duration::from_secs(10), upstream.body_started.recv())
        .await
        .expect("Detection mode must forward the body before it ends")
        .expect("the origin stopped accepting connections");

    let mut closing = chunk_frames(rest);
    closing.extend_from_slice(LAST_CHUNK);
    wr.write_all(&closing).await.unwrap();
    assert_eq!(read_status(&mut rd, &mut Vec::new()).await, 200);
    assert_arrived_whole(&mut upstream, &body).await;
    drop(wr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_mode_scans_the_prefix_and_forwards_the_whole_body() {
    // The other half of the v1.5.1 audit H-2 stance, which shipped
    // without a test: an INSPECTABLE body past the window is not
    // rejected in Detection mode. The scan runs on the buffered
    // prefix, one `BodyTruncated` event is emitted, and every byte
    // still reaches the upstream. The payload sits at the front so it
    // falls inside the prefix that is actually scanned.
    let (harness, mut upstream) = harness(WafMode::Detection).await;
    let mut body = sqli_json();
    body.resize(SCAN_WINDOW + 4096, b'a');

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(status, 200, "Detection never rejects on the window");
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_mode_forwards_a_binary_upload_unchanged() {
    // AC #4: the gate behaves identically in both modes. Detection
    // forwarded this body before the gate too (it only emits a
    // `BodyTruncated` event and proceeds), so what this asserts is
    // that the new branch did not change Detection's outcome. The
    // discriminating assertions are the Blocking ones above.
    let (harness, mut upstream) = harness(WafMode::Detection).await;
    let body = vec![0xABu8; 2 * SCAN_WINDOW];

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/octet-stream", &body),
    )
    .await;

    assert_eq!(status, 200);
    assert_arrived_whole(&mut upstream, &body).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blocked_body_is_not_mirrored_either() {
    // The shadow backend of a mirrored route is an upstream too. The
    // mirror fires once the body is complete, and it must fire after
    // the verdict, not before it. The probe GET is mirrored as soon as
    // its headers pass, so it is the first request a shadow that never
    // saw the blocked body reads.
    let (primary, mut upstream) = spawn_origin().await;
    let (shadow, mut shadow_upstream) = spawn_origin().await;
    let route = Route {
        mirror: Some(MirrorConfig {
            backend_ids: vec!["b-shadow".into()],
            sample_percent: 100,
            timeout_ms: 3_000,
            max_body_bytes: 1_048_576,
        }),
        ..waf_route(WafMode::Blocking)
    };
    let config = ProxyConfig::from_store(
        vec![route],
        vec![
            test_backend("b-primary", primary),
            test_backend("b-shadow", shadow),
        ],
        vec![],
        vec![("r-waf-body".into(), "b-primary".into())],
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &sqli_json()),
    )
    .await;
    assert_eq!(status, 403);
    assert_origin_untouched(harness.port, &mut upstream).await;

    let seen = next_upstream_request(&mut shadow_upstream.requests).await;
    assert!(
        seen.head.starts_with("get /probe "),
        "the shadow must never read the blocked body: {seen:?}"
    );
    assert_eq!(shadow_upstream.received.load(Ordering::SeqCst), 0);
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
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(OVER_DEFAULT_UNDER_WIDE, PAYLOAD_OFFSET);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 403, "the widened window must scan to the payload");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_past_the_raised_window_is_still_rejected() {
    // IV2, second half: the route raised the window, it did not remove
    // it. 3 MiB is past the 2 MiB window and well under the route's 16
    // MiB body limit, so a 413 here is the scan window talking.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = vec![b'a'; OVER_WIDE];

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "the raised window is still a window");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_sibling_route_keeps_the_default_window_for_the_same_body() {
    // IV2, third half, and the one that proves the cap is per route
    // rather than global: the same body, the same node, the same
    // configuration snapshot, the route that did not raise its window.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(OVER_DEFAULT_UNDER_WIDE, PAYLOAD_OFFSET);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 413, "the default route keeps the 1 MiB window");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_padding_bypass_stays_closed_at_the_raised_window() {
    // AC #6 against the effective cap rather than the constant: the
    // v1.5.1 audit H-2 case, 1 MiB of inert text ahead of the payload,
    // on a route whose window is 2 MiB. The padding no longer pushes
    // the body out of the window, so the answer is a scan that finds
    // the payload rather than a 413 that never looked. Either way the
    // upstream never sees the request, which is what H-2 requires.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;
    let body = padded_json(SCAN_WINDOW + sqli_json().len(), SCAN_WINDOW);

    let status = send_request(
        harness.port,
        sized_request_to(harness.port, "/wide/upload", "application/json", &body),
    )
    .await;

    assert_eq!(status, 403, "padding inside the window is scanned through");
    assert_origin_untouched(harness.port, &mut upstream).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn chunked_parity_for_the_raised_window() {
    // IV3 applied to AC #5: no Content-Length, so the window is read
    // from the cached field inside `request_body_filter` rather than
    // from the advertised header, and the route's value has to be the
    // one that bites. 3 MiB is past the route's 2 MiB window and well
    // under its 16 MiB body limit. The 2 MiB ahead of the window are
    // held, never forwarded, so the origin is not dialled.
    let (harness, mut upstream) = harness_with_wide_route(WafMode::Blocking).await;

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
    assert_origin_untouched(harness.port, &mut upstream).await;
}

// ---------------------------------------------------------------------------
// Latency of the hold, measured on demand.
// ---------------------------------------------------------------------------

/// Median time from the first byte sent to the status line received,
/// over `rounds` clean Content-Length bodies of `body.len()` bytes.
async fn median_round_trip(port: u16, body: &[u8], rounds: usize) -> Duration {
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let request = sized_request(port, "application/json", body);
        let started = Instant::now();
        let status = send_request(port, request).await;
        samples.push(started.elapsed());
        assert_eq!(status, 200);
    }
    samples.sort();
    samples[rounds / 2]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing probe, not a gate: run with --ignored --nocapture"]
async fn hold_latency_for_a_clean_body_of_the_default_window() {
    // Blocking holds the body until the scan has passed, Detection
    // streams it; both scan the same bytes at the end of the body. The
    // difference between the two medians is what the hold costs: the
    // upstream dial and the write of the held body, no longer
    // overlapped with the client's upload.
    const ROUNDS: usize = 31;
    let body = patterned_text(SCAN_WINDOW);
    let (blocking, _upstream_b) = harness(WafMode::Blocking).await;
    let (detection, _upstream_d) = harness(WafMode::Detection).await;

    // One unmeasured round each, so first-request setup is not sampled.
    median_round_trip(blocking.port, &body, 1).await;
    median_round_trip(detection.port, &body, 1).await;

    let held = median_round_trip(blocking.port, &body, ROUNDS).await;
    let streamed = median_round_trip(detection.port, &body, ROUNDS).await;
    eprintln!(
        "clean {SCAN_WINDOW}-byte body, median of {ROUNDS}: Blocking (held) {held:?}, Detection (streamed) {streamed:?}, difference {:?}",
        held.saturating_sub(streamed)
    );
}
