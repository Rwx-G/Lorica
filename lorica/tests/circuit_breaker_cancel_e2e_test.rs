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

//! Regression: a client that aborts an in-flight request (navigates away
//! while a slow page is still loading) must NOT be counted as a backend
//! failure by the circuit breaker.
//!
//! Reproduces the production report: loading a slow-first-load site (GitLab)
//! and clicking elsewhere mid-load yields a 502 for ~the breaker cooldown,
//! even though the backend is healthy. The local breaker opens after 5
//! consecutive failures (`BreakerEngine::local(5, 10)`); if each client abort
//! is mis-recorded as a backend failure, five aborts open the breaker and the
//! only backend is denied, so the next request gets a spurious
//! "no healthy backends" 502.

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
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Slow origin: reads the request, waits `delay`, then answers 200. The delay
// keeps the request in flight long enough for the client to abort it.
// ---------------------------------------------------------------------------

async fn spawn_slow_origin(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                tokio::time::sleep(delay).await;
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Open a connection to the proxy, send a complete request, then reset it
/// while the upstream response is still pending - exactly a browser cancelling
/// an in-flight page load. `set_linger(0)` forces a TCP RST so the proxy sees a
/// downstream connection error rather than an ambiguous half-close.
async fn abort_inflight_request(port: u16) {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut stream = stream;
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: _\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    // Let the proxy select the backend, dial the (slow) origin, and enter the
    // duplex loop, so the abort lands strictly mid-flight.
    tokio::time::sleep(Duration::from_millis(120)).await;
    let _ = stream.set_linger(Some(Duration::from_secs(0)));
    drop(stream);
    // Small gap so the proxy finishes its failure bookkeeping before the next
    // abort, keeping the five failures consecutive.
    tokio::time::sleep(Duration::from_millis(60)).await;
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

fn test_route() -> Route {
    Route {
        id: "r-cb".into(),
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
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: String::new(),
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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_cancel_must_not_open_circuit_breaker() {
    // Slow origin keeps each request in flight while the client aborts it.
    let origin = spawn_slow_origin(Duration::from_millis(1500)).await;
    let route = test_route();
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![("r-cb".into(), "b-primary".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;

    // Five in-flight aborts. The breaker threshold is 5: if a client abort is
    // mis-recorded as a backend failure, the breaker opens after these.
    for _ in 0..5 {
        abort_inflight_request(harness.port).await;
    }

    // A healthy follow-up must still reach the backend and get 200. With the
    // bug, the breaker is Open and this returns a spurious 502 immediately.
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "client-cancelled requests must not trip the circuit breaker (got {})",
        r.status()
    );
}
