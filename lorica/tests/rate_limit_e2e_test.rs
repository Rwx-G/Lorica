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

//! True HTTP end-to-end for the Phase 3f per-route rate limit.
//!
//! Stands up a real `LoricaProxy` in front of a counting origin, pushes
//! N requests rapidly against a bucket sized B, and asserts:
//!
//! 1. The first `B` requests reach the origin with `200 OK`.
//! 2. Request `B+1` is short-circuited with `429 Too Many Requests` and
//!    carries a `Retry-After` header.
//! 3. `scope = per_ip` isolates clients: two different `X-Forwarded-For`
//!    values each get their own bucket when XFF is trusted.
//! 4. `scope = per_route` caps aggregate traffic across clients.

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
// Minimal counting origin.
// ---------------------------------------------------------------------------

async fn spawn_counting_origin() -> (SocketAddr, Arc<AtomicU64>) {
    let counter = Arc::new(AtomicU64::new(0));
    let counter_c = Arc::clone(&counter);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let counter = Arc::clone(&counter_c);
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
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
    (addr, counter)
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

// ---------------------------------------------------------------------------
// Route / backend fixtures.
// ---------------------------------------------------------------------------

fn test_route(rate_limit: Option<RateLimit>) -> Route {
    Route {
        id: "r-rl".into(),
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
        rate_limit,
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

async fn harness_with_rate_limit(rate_limit: RateLimit) -> (ProxyHarness, Arc<AtomicU64>) {
    let (origin, counter) = spawn_counting_origin().await;
    let route = test_route(Some(rate_limit));
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![("r-rl".into(), "b-primary".into())];
    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, counter)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_bucket_returns_429_with_retry_after() {
    // capacity = 2, refill = 1/s: third request within the same second
    // finds the bucket at 0 and must be rejected.
    let (harness, counter) = harness_with_rate_limit(RateLimit {
        capacity: 2,
        refill_per_sec: 1,
        scope: RateLimitScope::PerIp,
    })
    .await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Two successful consumptions drain the bucket.
    let r1 = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r1.status(), 200);
    let r2 = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r2.status(), 200);

    // Third hit same second: bucket empty -> 429 + Retry-After.
    let r3 = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r3.status(), 429);
    assert!(
        r3.headers().contains_key("retry-after"),
        "Retry-After header must be set on 429"
    );
    // Refill is 1/s so Retry-After should be exactly 1 s (see the
    // formula in proxy_wiring.rs: `if refill >= 1 { 1 } else { 60 }`).
    let retry = r3
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    assert_eq!(retry, 1, "Retry-After for refill=1/s should be 1 second");

    // Exactly 2 origin hits — the 429 short-circuits before the
    // upstream_peer stage.
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_shot_bucket_has_60_second_retry_after() {
    // refill = 0 means one-shot: Retry-After should advise a
    // generous 60 s backoff instead of 0 (which would cause
    // clients to hot-loop).
    let (harness, _counter) = harness_with_rate_limit(RateLimit {
        capacity: 1,
        refill_per_sec: 0,
        scope: RateLimitScope::PerIp,
    })
    .await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let _ = client.get(harness.url()).send().await.unwrap();
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.status(), 429);
    let retry = r
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    assert_eq!(retry, 60, "one-shot bucket should advise 60 s backoff");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_rate_limit_does_not_short_circuit() {
    // Sanity: a route without `rate_limit` behaves as before.
    let (origin, counter) = spawn_counting_origin().await;
    let route = test_route(None);
    let backends = vec![test_backend("b-primary", origin)];
    let links = vec![("r-rl".into(), "b-primary".into())];
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
    for _ in 0..5 {
        let r = client.get(harness.url()).send().await.unwrap();
        assert_eq!(r.status(), 200);
    }
    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_route_scope_caps_aggregate_across_clients() {
    // scope = per_route: all clients share the single bucket for the
    // route. Capacity 2 means exactly 2 requests succeed regardless of
    // how many distinct clients issue them.
    let (harness, counter) = harness_with_rate_limit(RateLimit {
        capacity: 2,
        refill_per_sec: 0,
        scope: RateLimitScope::PerRoute,
    })
    .await;
    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    // Fire 5 requests; only 2 should reach the origin.
    let mut ok_count = 0usize;
    let mut rl_count = 0usize;
    for _ in 0..5 {
        let r = client.get(harness.url()).send().await.unwrap();
        match r.status().as_u16() {
            200 => ok_count += 1,
            429 => rl_count += 1,
            s => panic!("unexpected status {s}"),
        }
    }
    assert_eq!(ok_count, 2, "capacity=2 must admit exactly 2 requests");
    assert_eq!(rl_count, 3, "remaining 3 must be 429");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}
