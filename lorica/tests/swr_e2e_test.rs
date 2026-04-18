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

//! Phase 3.3 - stale-while-revalidate end-to-end.
//!
//! Proves that a stale-but-SWR-valid cache hit:
//!   1. serves the stale body to the client immediately (< fresh cache hit
//!      latency, since there's no upstream fetch on the critical path)
//!   2. triggers a background refresh that hits the origin once
//!   3. the next request sees the refreshed body without hitting the
//!      origin again
//!
//! And: once the SWR window expires, the cache behaves as a plain stale
//! hit (synchronous upstream fetch blocks the response).

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
// Versioned mock origin: serves `/` with a body that starts as "v1" and
// can be bumped to "v2", "v3", ... by the test. Every request is
// counted so SWR triggers can be asserted. No Cache-Control is sent
// by the origin so the route's configured TTL / SWR values apply.
// ---------------------------------------------------------------------------

#[derive(Default, Debug)]
struct OriginState {
    hits: AtomicU64,
    version: AtomicU64, // body = format!("v{version}")
}

async fn spawn_versioned_origin() -> (SocketAddr, Arc<OriginState>) {
    let state = Arc::new(OriginState {
        hits: AtomicU64::new(0),
        version: AtomicU64::new(1),
    });
    let state_c = Arc::clone(&state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let state = Arc::clone(&state_c);
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
                let hit = state.hits.fetch_add(1, Ordering::SeqCst) + 1;
                let v = state.version.load(Ordering::SeqCst);
                // version=0 is a test-controlled "failure mode": the
                // origin emits 503 so stale-if-error and failed-SWR-
                // refresh scenarios can be driven deterministically
                // by the test.
                let resp = if v == 0 {
                    let body = "service unavailable";
                    format!(
                        "HTTP/1.1 503 Service Unavailable\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n{body}",
                        body.len()
                    )
                } else {
                    let body = format!("v{v}-hit{hit}");
                    // NO Cache-Control header; the proxy's route config
                    // dictates TTL + SWR via its CacheMeta defaults.
                    format!(
                        "HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, state)
}

// ---------------------------------------------------------------------------
// Shared harness (replicated across the Phase 2-3 e2e binaries).
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

fn cacheable_route(ttl_s: i32, swr_s: i32, sie_s: i32) -> Route {
    Route {
        id: "r-swr".into(),
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
        cache_enabled: true,
        cache_ttl_s: ttl_s,
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
        stale_while_revalidate_s: swr_s,
        stale_if_error_s: sie_s,
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

async fn wait_for_origin_hits(state: &OriginState, target: u64, deadline: Duration) {
    let start = std::time::Instant::now();
    while std::time::Instant::now().duration_since(start) < deadline {
        if state.hits.load(Ordering::SeqCst) >= target {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swr_serves_stale_immediately_and_refreshes_in_background() {
    let (origin, state) = spawn_versioned_origin().await;

    // TTL 1s, SWR 10s, SIE 60s. After 1s the cache entry is stale but
    // within the SWR window; a request in this window should get the
    // stale body immediately while a background task refreshes the
    // cache.
    let route = cacheable_route(1, 10, 60);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    // Request 1: cache miss, populates cache with v1-hit1. Origin = 1.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body1 = r.text().await.unwrap();
    assert_eq!(body1, "v1-hit1");
    assert_eq!(state.hits.load(Ordering::SeqCst), 1);

    // Bump origin to v2 so the background refresh will fetch fresh
    // content we can later see.
    state.version.store(2, Ordering::SeqCst);

    // Wait past the TTL (1s) but stay well inside the SWR window (10s).
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // Request 2: stale hit within SWR. The client MUST see the still-
    // cached v1 body immediately; the background refresh will bump the
    // origin hit counter to 2 asynchronously.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body2 = r.text().await.unwrap();
    assert_eq!(
        body2, "v1-hit1",
        "SWR must serve stale content synchronously"
    );

    // Wait for the background revalidation to reach the origin. This
    // proves it actually happened - without SWR background refresh,
    // origin hits would stay at 1.
    wait_for_origin_hits(&state, 2, Duration::from_secs(3)).await;
    assert_eq!(
        state.hits.load(Ordering::SeqCst),
        2,
        "SWR background refresh must hit the origin exactly once"
    );

    // Give the cache a moment to finalise writing the fresh entry.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Request 3: cache is fresh again. Client sees v2 content. Origin
    // is NOT hit a third time (stays at 2).
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let body3 = r.text().await.unwrap();
    assert_eq!(body3, "v2-hit2", "post-refresh hit must serve the fresh v2");
    // Allow a brief moment for any late background task; the
    // expectation is still 2.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        state.hits.load(Ordering::SeqCst),
        2,
        "fresh cache hit must not touch the origin"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swr_disabled_route_revalidates_synchronously() {
    // With swr = 0, a stale hit has no stale-while-revalidate window.
    // The proxy must fetch fresh content on the critical path - no
    // background refresh. A request after expiry therefore returns
    // the NEW body (not the stale one), and the origin hit count
    // increments exactly in step with client requests.
    let (origin, state) = spawn_versioned_origin().await;
    let route = cacheable_route(1, 0, 0);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1-hit1");

    state.version.store(2, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // With SWR=0, the expired-but-within-SIE window uses stale-if-
    // error semantics only (and there's no error), so the proxy has
    // to revalidate synchronously. The client sees v2 immediately.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.text().await.unwrap(),
        "v2-hit2",
        "without SWR, the stale hit must block on a fresh fetch"
    );
    assert_eq!(state.hits.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_if_error_serves_cached_body_when_upstream_fails() {
    // TTL 1s, SWR 0, SIE 60s. After expiry the cache entry is stale
    // but still serveable under stale-if-error. If the origin returns
    // an upstream error, the client must get the cached body (not the
    // error).
    let (origin, state) = spawn_versioned_origin().await;

    // Switch the mock to a failing origin after the first hit: we
    // bring it down by setting a "fail" flag. Simpler: just close the
    // listener by dropping it. But we need to keep the origin address
    // bound... Instead, the mock can be extended to emit 5xx based on
    // state.version = 0 (or similar). Let me use a dedicated signal.
    // Simplest: bind a new mock that always 500s after we populate
    // the cache via the first request; then shut down the good origin
    // and the route's backend address switches? That's too complex.
    //
    // Pragmatic workaround: use a single origin that returns 503 when
    // a flag is set. Piggyback on `state.version = 0` as the signal.
    let route = cacheable_route(1, 0, 60);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    // Populate cache with v1.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1-hit1");

    // Flip the origin into "fail mode" by setting version=0. The mock
    // treats 0 as "emit 503"; see failure-mode branch in
    // spawn_versioned_origin (added below).
    state.version.store(0, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // Origin is now returning 503 -> stale-if-error must kick in and
    // the client gets the cached v1-hit1 body.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "stale-if-error must mask upstream failures with the cached body"
    );
    assert_eq!(r.text().await.unwrap(), "v1-hit1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swr_concurrent_requests_spawn_exactly_one_background_refresh() {
    // Ten clients race on the stale entry within the SWR window.
    // Anti-thundering-herd: the cache lock must let exactly one
    // background refresh through while the other nine serve stale
    // from cache. Origin hit count must go from 1 (initial populate)
    // to 2 (single refresh) - never to 11.
    let (origin, state) = spawn_versioned_origin().await;
    let route = cacheable_route(1, 30, 60);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    // Populate cache (hit 1).
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1-hit1");
    state.version.store(2, Ordering::SeqCst);

    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // Fire 10 concurrent requests at the stale entry.
    let url = harness.url();
    let mut handles = Vec::with_capacity(10);
    for _ in 0..10 {
        let c = client.clone();
        let u = url.clone();
        handles.push(tokio::spawn(async move {
            let r = c.get(&u).send().await.unwrap();
            r.text().await.unwrap()
        }));
    }
    for h in handles {
        let body = h.await.unwrap();
        // Every concurrent request must receive the stale v1 body
        // (the refresh doesn't finish synchronously on the critical
        // path of any of them).
        assert_eq!(
            body, "v1-hit1",
            "concurrent SWR readers must all see stale v1"
        );
    }

    // Wait for the background refresh to reach the origin, then
    // assert exactly ONE refresh was spawned regardless of how many
    // clients raced.
    wait_for_origin_hits(&state, 2, Duration::from_secs(3)).await;
    // Give a brief settle window in case any late refresh arrives.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        state.hits.load(Ordering::SeqCst),
        2,
        "concurrent SWR readers must share ONE background refresh, not spawn one each"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swr_background_refresh_failure_does_not_poison_cache() {
    // TTL 1s, SWR 10s, SIE 60s. Populate cache with v1. Flip origin
    // to fail mode. Trigger a stale read: client gets stale v1
    // (SWR path), background refresh fires and fails. The cache
    // entry should NOT be overwritten with an error response - a
    // subsequent read (still inside SWR+SIE windows) must still
    // return v1, not the 503 body.
    let (origin, state) = spawn_versioned_origin().await;
    let route = cacheable_route(1, 10, 60);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1-hit1");

    // Flip origin to failure mode.
    state.version.store(0, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_300)).await;

    // Request 2: stale hit, SWR refresh fires, refresh fails.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.text().await.unwrap(),
        "v1-hit1",
        "SWR must serve stale even when the forthcoming refresh is doomed"
    );

    // Wait for the failed refresh to have happened and the write
    // lock to release.
    wait_for_origin_hits(&state, 2, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Request 3: entry is still within SIE (60s). A failed refresh
    // must NOT have written a 503 over the cached v1. The client
    // must still see v1, not an error body.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.status(),
        200,
        "failed SWR refresh must not corrupt the cached entry"
    );
    assert_eq!(r.text().await.unwrap(), "v1-hit1");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn swr_window_expiry_falls_back_to_synchronous_fetch() {
    // TTL 1s, SWR 2s. After the SWR window closes the stale entry is
    // no longer eligible for background refresh - the proxy must fall
    // back to a synchronous upstream fetch.
    let (origin, state) = spawn_versioned_origin().await;
    let route = cacheable_route(1, 2, 60);
    let backends = vec![test_backend("b-origin", origin)];
    let links = vec![("r-swr".into(), "b-origin".into())];
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

    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(r.text().await.unwrap(), "v1-hit1");

    state.version.store(2, Ordering::SeqCst);
    // Wait past TTL + SWR (1 + 2 = 3s). Pick a generous 4s to avoid
    // flaky edges.
    tokio::time::sleep(Duration::from_millis(4_000)).await;

    // Outside the SWR window, the stale hit doesn't qualify for
    // background refresh - the response must be the fresh v2 fetched
    // synchronously.
    let r = client.get(harness.url()).send().await.unwrap();
    assert_eq!(
        r.text().await.unwrap(),
        "v2-hit2",
        "past SWR window, stale must be revalidated synchronously"
    );
    assert_eq!(state.hits.load(Ordering::SeqCst), 2);
}
