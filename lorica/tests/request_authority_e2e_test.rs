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

//! True HTTP end-to-end for the request-authority rejection added in
//! v1.7.2 (upstream Pingora `ffab8302`, reduced to the reachable checks).
//!
//! The predicate has unit tests in `lorica-core`. What those cannot show
//! is what a client on a socket actually receives, which is the part an
//! operator feels: `validate_request` fails inside `read_request`,
//! `lorica-proxy` turns an `InvalidHTTPHeader` into `respond_error(400)`,
//! and the connection closes. This asserts that whole path.
//!
//! It also pins the other half of the contract, that one unambiguous
//! authority still reaches the upstream. The gate sits on the ingress
//! path of every request, so a false positive here is an outage rather
//! than an inconvenience, and it deserves a regression test on both
//! sides.

#![cfg(unix)]

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

// ---------------------------------------------------------------------------
// Origin that answers 200 and counts what reached it.
// ---------------------------------------------------------------------------

async fn spawn_origin() -> (SocketAddr, Arc<AtomicU64>) {
    let hits = Arc::new(AtomicU64::new(0));
    let hits_c = Arc::clone(&hits);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let hits = Arc::clone(&hits_c);
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
                hits.fetch_add(1, Ordering::SeqCst);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, hits)
}

/// Sends raw request bytes and returns the response status code, or 0
/// when the proxy closed without answering.
async fn send_raw(port: u16, request: &str) -> u16 {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut rd, mut wr) = stream.into_split();
    let bytes = request.as_bytes().to_vec();
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(&bytes).await;
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
            break String::from_utf8_lossy(&buf[..pos])
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
        }
    };
    writer.abort();
    status
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
        id: "r-authority".into(),
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

async fn harness() -> (ProxyHarness, Arc<AtomicU64>) {
    let (origin, hits) = spawn_origin().await;
    let route = passthrough_route();
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![("r-authority".into(), "b-primary".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, hits)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_unambiguous_authority_still_reaches_the_upstream() {
    let (harness, hits) = harness().await;
    let status = send_raw(
        harness.port,
        "GET /ok HTTP/1.1\r\nHost: one.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_host_headers_are_answered_400() {
    // The routing split this closes: Lorica matches on the first Host, an
    // upstream that takes the last serves a different vhost than the one
    // whose WAF rules and IP lists were applied.
    let (harness, hits) = harness().await;
    let status = send_raw(
        harness.port,
        "GET /split HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400, "duplicate Host must be refused, not resolved");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reaches upstream");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn userinfo_in_the_host_header_is_answered_400() {
    // `http::Uri::host` strips userinfo, so a check comparing bytes and a
    // router parsing the authority disagree about which host this is.
    let (harness, hits) = harness().await;
    let status = send_raw(
        harness.port,
        "GET /u HTTP/1.1\r\nHost: evil.example@one.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_absolute_form_target_never_reaches_the_authority_check() {
    // The reason `lorica-core`'s authority module does not carry upstream's
    // raw-target classifier: the pinned `http` refuses such a target inside
    // `RequestHeader::build`, so the request dies at parse time. That
    // argument is load-bearing, so it is asserted over a real socket and
    // not only in a unit test.
    let (harness, hits) = harness().await;
    let status = send_raw(
        harness.port,
        "GET http://other.example/admin HTTP/1.1\r\nHost: one.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}
