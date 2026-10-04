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

//! Backlog #82 over a real socket: a downstream connection that sits
//! idle is closed after `downstream_idle_timeout_s`, one that keeps
//! sending requests inside the window is not, and a changed value
//! reaches the next connection without a restart.
//!
//! The forked server's own tests (`lorica-core/src/apps/mod.rs`) pin
//! the mechanism on an in-memory stream, HTTP/2 included. What they
//! cannot show is that the setting travels from `ProxyConfig` through
//! `LoricaProxy` and `HttpProxy` to the accept loop, which is the part
//! an operator relies on. HTTP/2 is not driven here: this crate has no
//! HTTP/2 client, and the HTTP/2 half of the same method is covered in
//! `lorica-core`.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
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
// Origin that answers every request 200 with a two-byte body.
// ---------------------------------------------------------------------------

async fn spawn_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
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
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

const REQUEST: &[u8] = b"GET /idle HTTP/1.1\r\nHost: idle.example\r\n\r\n";

/// Sends one keepalive request on `stream` and reads exactly one
/// response, returning its status line.
async fn exchange(stream: &mut TcpStream) -> String {
    stream.write_all(REQUEST).await.unwrap();
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
                .expect("a framed response, or the connection could not be reused");
            if buf.len() >= end + 4 + length {
                return head.lines().next().unwrap_or_default().to_string();
            }
        }
    }
}

/// How long until the proxy closes `stream`, waiting at most `limit`.
/// `None` when it is still open at the limit.
async fn time_to_close(stream: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    let mut scratch = [0u8; 64];
    match tokio::time::timeout(limit, stream.read(&mut scratch)).await {
        Ok(Ok(0)) | Ok(Err(_)) => Some(started.elapsed()),
        Ok(Ok(n)) => panic!("unexpected {n} bytes on an idle connection"),
        Err(_) => None,
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

fn passthrough_route() -> Route {
    Route {
        id: "r-idle".into(),
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

fn config_with_idle_timeout(origin: SocketAddr, seconds: u32) -> ProxyConfig {
    ProxyConfig::from_store(
        vec![passthrough_route()],
        vec![test_backend("b-primary", origin)],
        vec![],
        vec![("r-idle".into(), "b-primary".into())],
        ProxyConfigGlobals {
            downstream_idle_timeout_s: seconds,
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
async fn an_idle_keepalive_connection_is_closed_after_the_timeout() {
    let origin = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config_with_idle_timeout(origin, 1)));
    let harness = ProxyHarness::start(config).await;

    let mut stream = connect(harness.port).await;
    assert!(exchange(&mut stream).await.contains(" 200"));
    let closed = time_to_close(&mut stream, Duration::from_secs(10))
        .await
        .expect("an idle keepalive connection was never closed");
    // One second, in whole seconds, measured from the end of the
    // response; the lower bound is loose for scheduler jitter.
    assert!(
        closed >= Duration::from_millis(800),
        "closed too early: {closed:?}"
    );
    assert!(
        closed < Duration::from_secs(5),
        "closed too late: {closed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_inside_the_window_keep_the_connection_open() {
    let origin = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config_with_idle_timeout(origin, 1)));
    let harness = ProxyHarness::start(config).await;

    // Four requests 600 ms apart: the connection outlives two timeouts
    // because the wait restarts with every request.
    let mut stream = connect(harness.port).await;
    for round in 0..4 {
        assert!(
            exchange(&mut stream).await.contains(" 200"),
            "request {round} on the same connection"
        );
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_never_sends_a_request_is_closed_after_the_timeout() {
    let origin = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config_with_idle_timeout(origin, 1)));
    let harness = ProxyHarness::start(config).await;

    let mut stream = connect(harness.port).await;
    let closed = time_to_close(&mut stream, Duration::from_secs(10))
        .await
        .expect("a silent connection was never closed");
    assert!(
        closed < Duration::from_secs(5),
        "closed too late: {closed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_changed_timeout_reaches_the_next_connection_without_a_restart() {
    let origin = spawn_origin().await;
    let config = Arc::new(ArcSwap::from_pointee(config_with_idle_timeout(origin, 30)));
    let harness = ProxyHarness::start(Arc::clone(&config)).await;

    let mut long_lived = connect(harness.port).await;
    assert!(exchange(&mut long_lived).await.contains(" 200"));
    assert_eq!(
        time_to_close(&mut long_lived, Duration::from_millis(1500)).await,
        None,
        "30 s is in force before the reload"
    );

    // What a reload does: swap the snapshot.
    config.store(Arc::new(config_with_idle_timeout(origin, 1)));

    let mut fresh = connect(harness.port).await;
    assert!(exchange(&mut fresh).await.contains(" 200"));
    let closed = time_to_close(&mut fresh, Duration::from_secs(10))
        .await
        .expect("the new value did not reach the next connection");
    assert!(
        closed < Duration::from_secs(5),
        "closed too late: {closed:?}"
    );

    // The connection that was already waiting took its value when its
    // wait began; its next request picks up the new one.
    assert!(exchange(&mut long_lived).await.contains(" 200"));
    let closed = time_to_close(&mut long_lived, Duration::from_secs(10))
        .await
        .expect("the reused connection did not take the new value");
    assert!(
        closed < Duration::from_secs(5),
        "closed too late: {closed:?}"
    );
}
