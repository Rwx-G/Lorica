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

//! True HTTP end-to-end for Phase 3.2 request mirroring.
//!
//! Stands up:
//!   - a primary upstream that always replies 200
//!   - one or more mock shadow backends that atomically count each
//!     request they see plus whether it carried the `X-Lorica-Mirror: 1`
//!     tag
//!   - a real `LoricaProxy` driving a Pingora `Server`
//!
//! Verifies: every primary request produces one copy on each configured
//! shadow (sampling=100%), the shadow sees the `X-Lorica-Mirror` tag,
//! primary latency is unaffected by a dead shadow, sampling=0 disables,
//! and a dead shadow backend never poisons the primary path.

#![cfg(unix)]

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
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Mock origin with a visit counter + mirror-tag observation.
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct OriginStats {
    total: AtomicU64,
    tagged: AtomicU64,
    /// Aggregate body bytes received across all requests the origin
    /// has seen. Primary and shadow origins share this instrumentation
    /// so body-mirroring tests can assert that the shadow actually
    /// received the same body as the primary.
    body_bytes: AtomicU64,
    /// Last body seen, for equality checks.
    last_body: std::sync::Mutex<Vec<u8>>,
}

async fn spawn_counting_origin(id: &'static str) -> (SocketAddr, Arc<OriginStats>) {
    let stats = Arc::new(OriginStats::default());
    let stats_c = Arc::clone(&stats);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let stats = Arc::clone(&stats_c);
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(8192);
                let mut tmp = [0u8; 4096];
                // Parse headers; record Content-Length so we know how
                // many body bytes to expect after \r\n\r\n.
                let header_end;
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                header_end = pos + 4;
                                break;
                            }
                            if buf.len() > 64 * 1024 {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let mut content_length: usize = 0;
                for line in header_text.lines() {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                // Read remaining body bytes up to Content-Length.
                let already_body = buf.len() - header_end;
                let mut body_buf = Vec::with_capacity(content_length);
                body_buf.extend_from_slice(&buf[header_end..]);
                while body_buf.len() < content_length {
                    match stream.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => body_buf.extend_from_slice(&tmp[..n]),
                        Err(_) => break,
                    }
                }
                let _ = already_body;

                stats.total.fetch_add(1, Ordering::SeqCst);
                stats
                    .body_bytes
                    .fetch_add(body_buf.len() as u64, Ordering::SeqCst);
                {
                    let mut lb = stats.last_body.lock().unwrap();
                    *lb = body_buf.clone();
                }
                if header_text
                    .lines()
                    .any(|l| l.to_ascii_lowercase().starts_with("x-lorica-mirror:"))
                {
                    stats.tagged.fetch_add(1, Ordering::SeqCst);
                }

                let body = format!("origin:{id}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     X-Origin: {id}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\
                     \r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, stats)
}

// ---------------------------------------------------------------------------
// Shared plumbing
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

fn test_route(mirror: Option<MirrorConfig>) -> Route {
    Route {
        id: "r-mir".into(),
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
        mirror,
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
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

/// Poll-wait for a counter to reach `target`, up to `deadline`. Mirror
/// sub-requests are fire-and-forget so the primary response returns
/// before the shadow has necessarily been hit.
async fn wait_for_count(counter: &AtomicU64, target: u64, deadline: Duration) {
    let start = Instant::now();
    while Instant::now().duration_since(start) < deadline {
        if counter.load(Ordering::SeqCst) >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_100_percent_duplicates_every_request_to_each_shadow() {
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow_a, stats_a) = spawn_counting_origin("shadow-a").await;
    let (shadow_b, stats_b) = spawn_counting_origin("shadow-b").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow-a".into(), "shadow-b".into()],
        sample_percent: 100,
        timeout_ms: 3_000,
        max_body_bytes: 1_048_576,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow-a", shadow_a),
        test_backend("shadow-b", shadow_b),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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
    let base = harness.url();

    const N: u64 = 5;
    for _ in 0..N {
        let resp = client.get(&base).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(
            resp.headers().get("x-origin").and_then(|v| v.to_str().ok()),
            Some("primary"),
            "primary response must come from b-primary"
        );
    }

    wait_for_count(&stats_a.total, N, Duration::from_secs(3)).await;
    wait_for_count(&stats_b.total, N, Duration::from_secs(3)).await;

    assert_eq!(primary_stats.total.load(Ordering::SeqCst), N);
    assert_eq!(
        stats_a.total.load(Ordering::SeqCst),
        N,
        "shadow-a should have seen {N} mirror requests"
    );
    assert_eq!(
        stats_b.total.load(Ordering::SeqCst),
        N,
        "shadow-b should have seen {N} mirror requests"
    );
    // Every mirror request MUST carry X-Lorica-Mirror: 1 so the shadow
    // can filter it from its own metrics.
    assert_eq!(stats_a.tagged.load(Ordering::SeqCst), N);
    assert_eq!(stats_b.tagged.load(Ordering::SeqCst), N);
    // Primary must NOT have received the mirror tag.
    assert_eq!(primary_stats.tagged.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_zero_percent_disables_mirroring() {
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow, shadow_stats) = spawn_counting_origin("shadow").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow".into()],
        sample_percent: 0,
        timeout_ms: 3_000,
        max_body_bytes: 1_048_576,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow", shadow),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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
        let resp = client.get(harness.url()).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Give any accidental mirrors time to land, then assert zero.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 5);
    assert_eq!(
        shadow_stats.total.load(Ordering::SeqCst),
        0,
        "sample_percent=0 must not produce any shadow traffic"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_dead_shadow_does_not_affect_primary() {
    // Primary upstream works, shadow points at a refused port. Proves
    // the fire-and-forget design: primary completes normally regardless
    // of shadow outcome, and no timeout on the primary path.
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let dead_port = reserve_port();
    let dead_addr: SocketAddr = format!("127.0.0.1:{dead_port}").parse().unwrap();

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow-dead".into()],
        sample_percent: 100,
        timeout_ms: 1_000,
        max_body_bytes: 1_048_576,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow-dead", dead_addr),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let t0 = Instant::now();
    let resp = client.get(harness.url()).send().await.unwrap();
    let elapsed = t0.elapsed();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-origin").and_then(|v| v.to_str().ok()),
        Some("primary")
    );
    // Primary hop should be ~local-loopback fast. If the proxy blocked
    // on the shadow's 1 s timeout, elapsed would be close to 1 s. Use
    // 600 ms as a generous ceiling.
    assert!(
        elapsed < Duration::from_millis(600),
        "primary latency {elapsed:?} suggests the proxy is waiting on the dead shadow"
    );
    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_disabled_route_never_produces_shadow_traffic() {
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow, shadow_stats) = spawn_counting_origin("shadow").await;

    let route = test_route(None);
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow", shadow),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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

    for _ in 0..3 {
        let resp = client.get(harness.url()).send().await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 3);
    assert_eq!(shadow_stats.total.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_post_body_is_forwarded_to_shadow() {
    // Critical contract: POST /something with a body must land on the
    // shadow with the SAME body the primary saw. Anything less and the
    // shadow would be testing an incomplete request.
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow, shadow_stats) = spawn_counting_origin("shadow").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow".into()],
        sample_percent: 100,
        timeout_ms: 5_000,
        max_body_bytes: 65_536,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow", shadow),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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

    // A distinctive payload (not a round number) so Content-Length
    // drift is easy to see in test failure output.
    let payload = b"hello-shadow-this-is-a-specific-payload-1234567";
    let resp = client
        .post(harness.url())
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    wait_for_count(&shadow_stats.total, 1, Duration::from_secs(3)).await;

    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 1);
    assert_eq!(shadow_stats.total.load(Ordering::SeqCst), 1);
    assert_eq!(
        primary_stats.body_bytes.load(Ordering::SeqCst),
        payload.len() as u64
    );
    assert_eq!(
        shadow_stats.body_bytes.load(Ordering::SeqCst),
        payload.len() as u64,
        "shadow must receive the full request body"
    );
    let shadow_body = shadow_stats.last_body.lock().unwrap().clone();
    assert_eq!(
        shadow_body, payload,
        "shadow body must match primary byte-for-byte"
    );
    assert_eq!(shadow_stats.tagged.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_oversize_body_is_not_mirrored() {
    // Body > max_body_bytes: primary is unaffected, shadow sees nothing.
    // Truncating would be the subtle wrong call here - the shadow's
    // behaviour on a partial body would be misleading.
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow, shadow_stats) = spawn_counting_origin("shadow").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow".into()],
        sample_percent: 100,
        timeout_ms: 5_000,
        // 512 bytes cap; we POST 2 KiB.
        max_body_bytes: 512,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow", shadow),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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

    let payload = vec![b'x'; 2048];
    let resp = client
        .post(harness.url())
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Give a generous window for any mirror that would have fired.
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 1);
    assert_eq!(
        primary_stats.body_bytes.load(Ordering::SeqCst),
        payload.len() as u64,
        "primary must receive the full body even when mirror is skipped"
    );
    assert_eq!(
        shadow_stats.total.load(Ordering::SeqCst),
        0,
        "body > max_body_bytes must skip the mirror entirely"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_max_body_bytes_zero_is_headers_only() {
    // max_body_bytes = 0 = operator-chosen headers-only mode. A POST
    // still mirrors, but the shadow receives no body.
    let (primary, primary_stats) = spawn_counting_origin("primary").await;
    let (shadow, shadow_stats) = spawn_counting_origin("shadow").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["shadow".into()],
        sample_percent: 100,
        timeout_ms: 5_000,
        max_body_bytes: 0,
    }));
    let backends = vec![
        test_backend("b-primary", primary),
        test_backend("shadow", shadow),
    ];
    let links = vec![("r-mir".into(), "b-primary".into())];
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

    let payload = b"some-body-the-operator-doesnt-want-mirrored";
    let resp = client
        .post(harness.url())
        .body(payload.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    wait_for_count(&shadow_stats.total, 1, Duration::from_secs(3)).await;

    assert_eq!(shadow_stats.total.load(Ordering::SeqCst), 1);
    assert_eq!(
        shadow_stats.body_bytes.load(Ordering::SeqCst),
        0,
        "max_body_bytes=0 -> shadow receives zero body bytes"
    );
    assert_eq!(
        primary_stats.body_bytes.load(Ordering::SeqCst),
        payload.len() as u64
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mirror_dangling_backend_id_is_inert() {
    // Route references a backend ID that doesn't exist. The route must
    // still function normally; no sub-requests spawn.
    let (primary, primary_stats) = spawn_counting_origin("primary").await;

    let route = test_route(Some(MirrorConfig {
        backend_ids: vec!["does-not-exist".into()],
        sample_percent: 100,
        timeout_ms: 3_000,
        max_body_bytes: 1_048_576,
    }));
    let backends = vec![test_backend("b-primary", primary)];
    let links = vec![("r-mir".into(), "b-primary".into())];
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
    let resp = client.get(harness.url()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(primary_stats.total.load(Ordering::SeqCst), 1);
}
