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

//! True HTTP end-to-end test for Phase 2.2 canary traffic splits.
//!
//! The deterministic per-client bucket makes this testable without a
//! statistical sample: we use the public `canary_bucket` helper to find
//! one client IP that falls into the canary band and one that does not,
//! then drive real HTTP requests whose observed `X-Forwarded-For` is
//! honoured as the client IP (via the route's trusted proxies config).
//! This proves the full path - client IP extraction, bucket computation,
//! split selection, upstream peer override - not just the pure helper.

#![cfg(unix)]

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{canary_bucket, LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Shared infra (mock origin, manual shutdown, port helpers)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Canary-specific helpers
// ---------------------------------------------------------------------------

fn test_route(
    id: &str,
    hostname: &str,
    traffic_splits: Vec<TrafficSplit>,
    header_rules: Vec<HeaderRule>,
) -> Route {
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
        traffic_splits,
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

/// Find one IP in each bucket band (canary vs. default) under the given
/// split weight, using the same deterministic hash the proxy uses at
/// request time. Iterates through synthetic RFC 5737 documentation IPs
/// so no real address ranges collide with test environments.
fn find_bucketed_ips(route_id: &str, canary_weight: u8) -> (String, String) {
    let mut canary = None;
    let mut default = None;
    for i in 0..2048u32 {
        let ip = format!("203.0.{}.{}", (i >> 8) & 0xff, i & 0xff);
        let b = canary_bucket(route_id, &ip);
        if b < canary_weight && canary.is_none() {
            canary = Some(ip.clone());
        } else if b >= canary_weight && default.is_none() {
            default = Some(ip.clone());
        }
        if canary.is_some() && default.is_some() {
            break;
        }
    }
    (
        canary.expect("no synthetic IP fell into the canary band - change search space"),
        default.expect("no synthetic IP fell into the default band"),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canary_split_end_to_end_routes_by_client_ip_bucket() {
    init_crypto_provider_once();

    let b_default = spawn_mock_backend("default").await;
    let b_v2 = spawn_mock_backend("v2").await;

    // 20% canary to v2. With route_id = "r-canary" we'll pick one client
    // IP that hashes into 0..20 and one into 20..100, then drive real
    // requests setting X-Forwarded-For to each.
    let route_id = "r-canary";
    let route = test_route(
        route_id,
        "_",
        vec![TrafficSplit {
            name: "v2-canary".into(),
            weight_percent: 20,
            backend_ids: vec!["b-v2".into()],
        }],
        vec![],
    );
    let backends = vec![
        test_backend("b-default", b_default),
        test_backend("b-v2", b_v2),
    ];
    let links = vec![(route_id.into(), "b-default".into())];

    // Trust the test's own loopback so X-Forwarded-For is honoured as the
    // client IP - the proxy's XFF handling requires the direct TCP peer
    // to match a trusted proxy CIDR first (secure default).
    let globals = ProxyConfigGlobals {
        trusted_proxy_cidrs: vec!["127.0.0.0/8".into()],
        ..Default::default()
    };

    let config = ProxyConfig::from_store(vec![route], backends, vec![], links, globals);
    let config = Arc::new(ArcSwap::from_pointee(config));

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
        let mut server = Server::new(None).expect("pingora Server::new failed");
        server.add_service(proxy_service);
        server.bootstrap();
        server.run(RunArgs {
            shutdown_signal: Box::new(ManualShutdown { rx: shutdown_rx }),
        });
    });

    wait_for_port(proxy_port).await;

    let (canary_ip, default_ip) = find_bucketed_ips(route_id, 20);

    let client = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{proxy_port}/");

    // Client IP in the canary band -> v2 backend.
    let resp = client
        .get(&base)
        .header("X-Forwarded-For", canary_ip.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "v2",
        "client IP {canary_ip} (bucket < 20) should hit v2"
    );

    // Client IP outside the canary band -> default backend.
    let resp = client
        .get(&base)
        .header("X-Forwarded-For", default_ip.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "default",
        "client IP {default_ip} (bucket >= 20) should hit default"
    );

    // Same canary client again -> still v2 (sticky property).
    for _ in 0..3 {
        let resp = client
            .get(&base)
            .header("X-Forwarded-For", canary_ip.as_str())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.headers().get("x-backend").unwrap(),
            "v2",
            "canary bucket must be sticky across repeats for IP {canary_ip}"
        );
    }

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = server_thread.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn header_rule_overrides_canary_end_to_end() {
    // A route with BOTH a header rule and a 100% canary. The header rule
    // must always win over the canary so an explicit `X-Variant: stable`
    // opt-out always reaches the stable backend, even when the canary
    // would otherwise divert 100% of traffic. Pins the evaluation order
    // contract documented on `Route::traffic_splits`.
    init_crypto_provider_once();

    let b_default = spawn_mock_backend("default").await;
    let b_stable = spawn_mock_backend("stable").await;
    let b_canary = spawn_mock_backend("canary").await;

    let route_id = "r-prec";
    let route = test_route(
        route_id,
        "_",
        vec![TrafficSplit {
            // 100% canary: without the header rule, every request would
            // hit `canary`.
            name: "all".into(),
            weight_percent: 100,
            backend_ids: vec!["b-canary".into()],
        }],
        vec![HeaderRule {
            header_name: "X-Variant".into(),
            match_type: HeaderMatchType::Exact,
            value: "stable".into(),
            backend_ids: vec!["b-stable".into()],
        }],
    );
    let backends = vec![
        test_backend("b-default", b_default),
        test_backend("b-stable", b_stable),
        test_backend("b-canary", b_canary),
    ];
    let links = vec![(route_id.into(), "b-default".into())];
    let globals = ProxyConfigGlobals {
        trusted_proxy_cidrs: vec!["127.0.0.0/8".into()],
        ..Default::default()
    };
    let config = ProxyConfig::from_store(vec![route], backends, vec![], links, globals);
    let config = Arc::new(ArcSwap::from_pointee(config));

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

    // With header rule match: stable backend, canary bypassed.
    let resp = client
        .get(&base)
        .header("X-Forwarded-For", "203.0.113.7")
        .header("X-Variant", "stable")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "stable",
        "header rule must win over a 100% canary"
    );

    // Without header rule: canary catches everything (100%).
    let resp = client
        .get(&base)
        .header("X-Forwarded-For", "203.0.113.7")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "canary",
        "requests without the opt-out header fall into the 100% canary"
    );

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = server_thread.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canary_split_hot_reload_reshuffles_buckets_end_to_end() {
    // Start with 0% canary (everyone on default), swap to 100% canary via
    // ArcSwap without restarting the listener, then back to 0. The same
    // client IP must flip between default and v2 accordingly - proving
    // config reloads affect the canary decision path live.
    init_crypto_provider_once();

    let b_default = spawn_mock_backend("default").await;
    let b_v2 = spawn_mock_backend("v2").await;

    let route_id = "r-hr-canary";
    let initial_route = test_route(route_id, "_", vec![], vec![]);
    let backends_vec = vec![
        test_backend("b-default", b_default),
        test_backend("b-v2", b_v2),
    ];
    let links = vec![(route_id.into(), "b-default".into())];
    let globals = ProxyConfigGlobals {
        trusted_proxy_cidrs: vec!["127.0.0.0/8".into()],
        ..Default::default()
    };

    let config = ProxyConfig::from_store(
        vec![initial_route],
        backends_vec.clone(),
        vec![],
        links.clone(),
        globals.clone(),
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
    // Any IP works with 0% / 100% splits since the bucket comparison is
    // always < weight (false for 0, true for 100 since bucket is 0..99).
    let ip = "203.0.113.42";

    // Baseline: no splits, always default.
    let resp = client
        .get(&base)
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.headers().get("x-backend").unwrap(), "default");

    // Swap to 100% canary.
    let route_all = test_route(
        route_id,
        "_",
        vec![TrafficSplit {
            name: "all".into(),
            weight_percent: 100,
            backend_ids: vec!["b-v2".into()],
        }],
        vec![],
    );
    let new_config = ProxyConfig::from_store(
        vec![route_all],
        backends_vec.clone(),
        vec![],
        links.clone(),
        globals.clone(),
    );
    config_ref.store(Arc::new(new_config));

    let resp = client
        .get(&base)
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "v2",
        "100% split must route every request to the canary backend"
    );

    // Swap back to 0% canary.
    let route_none = test_route(route_id, "_", vec![], vec![]);
    let final_config =
        ProxyConfig::from_store(vec![route_none], backends_vec, vec![], links, globals);
    config_ref.store(Arc::new(final_config));

    let resp = client
        .get(&base)
        .header("X-Forwarded-For", ip)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.headers().get("x-backend").unwrap(),
        "default",
        "removing splits via ArcSwap must fall back to defaults live"
    );

    shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = server_thread.join();
}
