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

//! True HTTP end-to-end test for Phase 2.1 header-based routing.
//!
//! Stands up three tokio mock origins, a real `LoricaProxy` driving a
//! Pingora `Server` in a background thread, and drives requests through
//! `reqwest`. Verifies that the `X-Tenant` header selects the correct
//! origin (or falls back to the default backend) end-to-end - through
//! the actual `ProxyHttp::request_filter` + `upstream_peer` path and
//! real upstream HTTP, not a mocked session.
//!
//! Unix only: Pingora `Server` uses Unix signals in its default shutdown
//! watcher. We replace that with a manual tokio::sync::watch channel so
//! the test can stop the server cleanly without raising SIGTERM on the
//! test runner process.

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
// Mock origin
// ---------------------------------------------------------------------------

/// Spawn a minimal HTTP/1.1 origin that always replies `200 OK` with
/// `backend:<id>` in the body and an `X-Backend` response header. The
/// parser only looks for end-of-headers and ignores the request body -
/// sufficient for the small GETs this test issues.
async fn spawn_mock_backend(id: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = Vec::with_capacity(8192);
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
                let body = format!("backend:{id}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     X-Backend: {id}\r\n\
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
    addr
}

// ---------------------------------------------------------------------------
// Config helpers
// ---------------------------------------------------------------------------

fn test_route(id: &str, hostname: &str, header_rules: Vec<HeaderRule>) -> Route {
    Route {
        id: id.into(),
        hostname: hostname.into(),
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
        header_rules,
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
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

// ---------------------------------------------------------------------------
// Manual shutdown signal - replaces the default Unix-signal watcher so the
// test can tear down the Pingora server without raising SIGTERM on the
// surrounding test runner process.
// ---------------------------------------------------------------------------

struct ManualShutdown {
    rx: tokio::sync::watch::Receiver<bool>,
}

#[async_trait]
impl ShutdownSignalWatch for ManualShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.rx.clone();
        // Starts false; loop until it flips true.
        while rx.changed().await.is_ok() {
            if *rx.borrow() {
                break;
            }
        }
        ShutdownSignal::FastShutdown
    }
}

// ---------------------------------------------------------------------------
// Port helpers
// ---------------------------------------------------------------------------

/// Reserve a free port by binding 0, then release it. There is a race
/// with the subsequent Pingora bind, but in a quiet test environment it
/// almost always wins. The kernel tends to not re-issue the same port
/// within milliseconds.
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

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Install rustls's default CryptoProvider exactly once per test binary.
/// Normally done in `main.rs`; required here because Pingora initialises
/// rustls internals on service construction.
fn init_crypto_provider_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_rules_route_to_correct_backend_end_to_end() {
    init_crypto_provider_once();
    // Mock origins - each tags its response so we can assert routing.
    let b_default = spawn_mock_backend("default").await;
    let b_acme = spawn_mock_backend("acme").await;
    let b_beta = spawn_mock_backend("beta").await;

    // Route: catch-all hostname "_". First-match-wins on X-Tenant Exact.
    // Default backend = "b-default" (linked). Header-matched backends are
    // registered as Backend rows but NOT linked to the route's native
    // backend set; they're only reachable via header rule backend_ids.
    let route = test_route(
        "r-e2e",
        "_",
        vec![
            HeaderRule {
                header_name: "X-Tenant".into(),
                match_type: HeaderMatchType::Exact,
                value: "acme".into(),
                backend_ids: vec!["b-acme".into()],
            },
            HeaderRule {
                header_name: "X-Tenant".into(),
                match_type: HeaderMatchType::Exact,
                value: "beta".into(),
                backend_ids: vec!["b-beta".into()],
            },
        ],
    );

    let backends = vec![
        test_backend("b-default", b_default),
        test_backend("b-acme", b_acme),
        test_backend("b-beta", b_beta),
    ];
    let links = vec![("r-e2e".into(), "b-default".into())];

    let config = ProxyConfig::from_store(
        vec![route],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let config = Arc::new(ArcSwap::from_pointee(config));

    let log_buffer = Arc::new(lorica_api::logs::LogBuffer::new(128));
    let active_conns = Arc::new(AtomicU64::new(0));
    let sla = Arc::new(lorica_bench::passive_sla::SlaCollector::new());
    let proxy = LoricaProxy::new(config, log_buffer, active_conns, sla);

    // Reserve a port for the proxy and set up manual shutdown.
    let proxy_port = reserve_port();
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server_thread = std::thread::spawn(move || {
        let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
            upstream_keepalive_pool_size: 0,
            ..Default::default()
        });
        let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, proxy);
        proxy_service.add_tcp(&proxy_addr);

        let mut server = Server::new(None).expect("pingora Server::new failed");
        server.add_service(proxy_service);
        server.bootstrap();
        server.run(RunArgs {
            shutdown_signal: Box::new(ManualShutdown { rx: shutdown_rx }),
        });
    });

    wait_for_port(proxy_port).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0) // force a fresh connection per request
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{proxy_port}/");

    // No tenant header -> default backend.
    let resp = client.get(&base).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");
    assert_eq!(resp.text().await.unwrap(), "backend:default");

    // Matching header routes to acme.
    let resp = client
        .get(&base)
        .header("X-Tenant", "acme")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-backend").unwrap(), "acme");

    // Second rule (beta) also matches - validates first-match-wins would
    // NOT misroute this one since beta-specific value hits the 2nd rule.
    let resp = client
        .get(&base)
        .header("X-Tenant", "beta")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-backend").unwrap(), "beta");

    // Value with no matching rule -> falls back to default.
    let resp = client
        .get(&base)
        .header("X-Tenant", "unknown-tenant")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");

    // Case sensitivity on VALUE: "ACME" (uppercase) is not exact-equal to
    // "acme", so it falls through to default. Documents the contract.
    let resp = client
        .get(&base)
        .header("X-Tenant", "ACME")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");

    // Case insensitivity on NAME (RFC 7230): "x-tenant" works just like
    // "X-Tenant". This exercises http::HeaderMap's canonical lookup.
    let resp = client
        .get(&base)
        .header("x-tenant", "acme")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-backend").unwrap(), "acme");

    // (Hot-reload behaviour is exercised by the sibling test
    // `header_rules_hot_reload_end_to_end`, which keeps a second Arc
    // clone of the `ArcSwap` specifically for that purpose.)

    // Clean shutdown.
    shutdown_tx.send(true).unwrap();
    // Give Pingora a moment to drain.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = server_thread.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_rules_hot_reload_end_to_end() {
    init_crypto_provider_once();
    // Same setup, but keep a clone of the Arc<ArcSwap> so we can swap the
    // config at runtime. Verifies that adding a rule to a live route
    // takes effect on the next accepted request, without restarting the
    // server.
    let b_default = spawn_mock_backend("default").await;
    let b_new = spawn_mock_backend("new").await;

    let initial = test_route("r-hr", "_", vec![]); // no rules yet
    let backends = vec![
        test_backend("b-default", b_default),
        test_backend("b-new", b_new),
    ];
    let links = vec![("r-hr".into(), "b-default".into())];
    let config = ProxyConfig::from_store(
        vec![initial],
        backends,
        vec![],
        links,
        ProxyConfigGlobals::default(),
    );
    let config = Arc::new(ArcSwap::from_pointee(config));
    let config_ref = Arc::clone(&config);

    let log_buffer = Arc::new(lorica_api::logs::LogBuffer::new(128));
    let active_conns = Arc::new(AtomicU64::new(0));
    let sla = Arc::new(lorica_bench::passive_sla::SlaCollector::new());
    let proxy = LoricaProxy::new(config, log_buffer, active_conns, sla);

    let proxy_port = reserve_port();
    let proxy_addr = format!("127.0.0.1:{proxy_port}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let server_thread = std::thread::spawn(move || {
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

    wait_for_port(proxy_port).await;

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{proxy_port}/");

    // Baseline: no rules, everything goes to default.
    let resp = client
        .get(&base)
        .header("X-Variant", "new")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");

    // Install a rule routing X-Variant: new to b-new, via ArcSwap. This
    // is the exact swap semantics `reload_proxy_config` uses in workers,
    // without the SQLite round-trip.
    let updated_route = test_route(
        "r-hr",
        "_",
        vec![HeaderRule {
            header_name: "X-Variant".into(),
            match_type: HeaderMatchType::Exact,
            value: "new".into(),
            backend_ids: vec!["b-new".into()],
        }],
    );
    let updated_backends = vec![
        test_backend("b-default", b_default),
        test_backend("b-new", b_new),
    ];
    let updated_links = vec![("r-hr".into(), "b-default".into())];
    let new_config = ProxyConfig::from_store(
        vec![updated_route],
        updated_backends,
        vec![],
        updated_links,
        ProxyConfigGlobals::default(),
    );
    config_ref.store(Arc::new(new_config));

    // Next request picks up the new policy.
    let resp = client
        .get(&base)
        .header("X-Variant", "new")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "new",
        "hot-reloaded rule must take effect without restarting the listener"
    );

    // Other values still hit default.
    let resp = client
        .get(&base)
        .header("X-Variant", "other")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = server_thread.join();
}
