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

//! Slowloris over a real socket: `header_timeout_s` bounds the whole
//! HTTP/1.1 request header while it is read, and a route's
//! `slowloris_threshold_ms` refuses a request whose header took longer.
//!
//! Until v1.9.0 both were measured from a context created after the
//! header had been read, so a client trickling header bytes was never
//! cut by either. The forked server's own tests
//! (`lorica-core/src/protocols/http/v1/server.rs`) pin the read-loop
//! bound on an in-memory stream; these show the settings travel from
//! `ProxyConfig` to the read loop and to `request_filter`.
//!
//! The pieces of a trickled header are sent with real pauses: the
//! pauses are the behaviour under test. The idle timeout is left at 30 s
//! so no gap here comes near it.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Origin that answers every request 200 with a two-byte body, counting them.
// ---------------------------------------------------------------------------

async fn spawn_origin() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut scratch = [0u8; 4096];
                loop {
                    match stream.read(&mut scratch).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&scratch[..n]),
                    }
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, hits)
}

/// One keepalive request, cut into pieces: the request line, one header
/// line per piece, then the blank line.
const PIECES: [&[u8]; 5] = [
    b"GET /slow HTTP/1.1\r\n",
    b"Host: slow.example\r\n",
    b"X-One: 1\r\n",
    b"X-Two: 2\r\n",
    b"\r\n",
];

/// Sends `PIECES` with `gap` between consecutive pieces.
async fn send_trickled(stream: &mut TcpStream, gap: Duration) {
    for (i, piece) in PIECES.iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(gap).await;
        }
        stream.write_all(piece).await.unwrap();
    }
}

/// Reads exactly one response on `stream` and returns its status line.
async fn read_response(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut scratch))
            .await
            .expect("the proxy answers in time")
            .expect("read");
        assert!(n > 0, "the proxy closed instead of answering");
        buf.extend_from_slice(&scratch[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .map(|v| v.trim().parse().expect("a numeric content-length"))
                .unwrap_or(0);
            if buf.len() >= end + 4 + length {
                return head.lines().next().unwrap_or_default().to_string();
            }
        }
    }
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

fn passthrough_route(slowloris_threshold_ms: i32) -> Route {
    Route {
        id: "r-header".into(),
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
        slowloris_threshold_ms,
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

fn config(origin: SocketAddr, header_timeout_s: u32, slowloris_threshold_ms: i32) -> ProxyConfig {
    ProxyConfig::from_store(
        vec![passthrough_route(slowloris_threshold_ms)],
        vec![test_backend("b-primary", origin)],
        vec![],
        vec![("r-header".into(), "b-primary".into())],
        ProxyConfigGlobals {
            header_timeout_s,
            downstream_idle_timeout_s: 30,
            ..ProxyConfigGlobals::default()
        },
    )
}

async fn connect(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trickled_header_is_answered_408_once_header_timeout_s_elapses() {
    let (origin, hits) = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 1, 60_000)));
    let harness = ProxyHarness::start(config).await;

    let (mut reader, mut writer) = connect(harness.port).await.into_split();
    let started = Instant::now();
    // One header line every 300 ms, never ending: every gap is far inside
    // the 30 s idle timeout, so only the header timeout can stop it. The
    // writes land at 0.9 s and 1.2 s, clear of the 1 s cut: a byte that
    // arrives while the proxy closes would turn its close into a reset.
    let trickle = tokio::spawn(async move {
        writer
            .write_all(b"GET /slow HTTP/1.1\r\nHost: slow.example\r\n")
            .await?;
        for i in 0u32.. {
            tokio::time::sleep(Duration::from_millis(300)).await;
            writer
                .write_all(format!("X-Pad-{i}: x\r\n").as_bytes())
                .await?;
        }
        Ok::<(), std::io::Error>(())
    });

    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    let closed_after = loop {
        let n = tokio::time::timeout(Duration::from_secs(10), reader.read(&mut scratch))
            .await
            .expect("a trickled header held the connection past 10 s")
            .unwrap_or(0);
        if n == 0 {
            break started.elapsed();
        }
        buf.extend_from_slice(&scratch[..n]);
    };
    trickle.abort();

    let response = String::from_utf8_lossy(&buf);
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "expected a 408 before the close, got {response:?}"
    );
    // The window opens at the first byte, sent right after `started`.
    assert!(
        closed_after >= Duration::from_millis(900),
        "cut before the header timeout: {closed_after:?}"
    );
    assert!(
        closed_after < Duration::from_secs(4),
        "cut late: {closed_after:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the backend saw the request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_slow_header_inside_header_timeout_s_is_served() {
    let (origin, hits) = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 2, 60_000)));
    let harness = ProxyHarness::start(config).await;

    // Four gaps of 150 ms: 600 ms of header, inside a 2 s window.
    let mut stream = connect(harness.port).await;
    send_trickled(&mut stream, Duration::from_millis(150)).await;
    assert!(read_response(&mut stream).await.contains(" 200"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_keepalive_reuse_gets_a_fresh_header_window() {
    let (origin, hits) = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 1, 60_000)));
    let harness = ProxyHarness::start(config).await;

    // Each header takes 600 ms and the connection idles 700 ms between
    // the two requests: 1.9 s on one connection against a 1 s window,
    // which passes only if the window restarts at the next first byte.
    let mut stream = connect(harness.port).await;
    send_trickled(&mut stream, Duration::from_millis(150)).await;
    assert!(
        read_response(&mut stream).await.contains(" 200"),
        "first request"
    );
    tokio::time::sleep(Duration::from_millis(700)).await;
    send_trickled(&mut stream, Duration::from_millis(150)).await;
    assert!(
        read_response(&mut stream).await.contains(" 200"),
        "reused connection"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_threshold_refuses_a_request_whose_header_took_longer() {
    let (origin, hits) = spawn_origin().await;
    // The route allows 300 ms of header; the 10 s global window is not
    // what refuses it.
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 10, 300)));
    let harness = ProxyHarness::start(config).await;

    let mut slow = connect(harness.port).await;
    send_trickled(&mut slow, Duration::from_millis(150)).await;
    assert!(read_response(&mut slow).await.contains(" 408"));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the backend saw the request"
    );

    // A client that connects, waits, then sends its header at once (a
    // browser preconnect) is served: the wait before the first byte is
    // not part of the header.
    let mut prompt = connect(harness.port).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    prompt.write_all(&PIECES.concat()).await.unwrap();
    assert!(read_response(&mut prompt).await.contains(" 200"));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_route_threshold_refusal_closes_the_connection() {
    let (origin, hits) = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 10, 300)));
    let harness = ProxyHarness::start(config).await;

    // A keepalive request refused as slow: the 408 says `Connection:
    // close` and the proxy closes, well inside the 30 s idle timeout, so
    // the client cannot send its next header slowly on the same socket.
    let mut slow = connect(harness.port).await;
    send_trickled(&mut slow, Duration::from_millis(150)).await;
    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), slow.read(&mut scratch))
            .await
            .expect("the refused connection stayed open")
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    let response = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    assert!(response.starts_with("http/1.1 408"), "{response:?}");
    assert!(
        response.contains("\r\nconnection: close\r\n"),
        "{response:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the backend saw the request"
    );
}
