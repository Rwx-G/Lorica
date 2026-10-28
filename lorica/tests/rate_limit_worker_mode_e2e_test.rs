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

//! HTTP end-to-end for the worker-mode rate limiter (issue #45).
//!
//! A real `LoricaProxy` runs with the worker engine (`LocalBucket`
//! cache) and its production sync task, wired over a Unix socketpair
//! to the production supervisor handler, which sizes its authoritative
//! buckets from a route store. Covers:
//!
//! 1. A route configured with the legacy `rate_limit_rps` /
//!    `rate_limit_burst` pair keeps admitting after the first sync, is
//!    refused once drained, and admits again after the refill time.
//! 2. A `per_route` bucket drained by one client recovers for another
//!    client once the refill time has passed.
//! 3. A path rule with its own rate limit is enforced with its own
//!    capacity, in worker and single-process mode alike.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::rate_limit::handle_rate_limit_delta;
use lorica::proxy_wiring::{
    LoricaProxy, ProxyConfig, ProxyConfigGlobals, RateLimitEngine, SupervisorRateLimits,
};
use lorica_command::{CommandType, IncomingCommands, RpcEndpoint};
use lorica_config::models::*;
use lorica_config::ConfigStore;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The worker's production sync cadence.
const SYNC_INTERVAL: Duration = Duration::from_millis(100);
/// Several sync ticks: long enough for a push and its reply to land.
const AFTER_SYNC: Duration = Duration::from_millis(400);
/// Longer than any bucket below takes to refill, plus sync ticks.
const AFTER_REFILL: Duration = Duration::from_millis(900);

const CLIENT_A: &str = "192.0.2.10";
const CLIENT_B: &str = "192.0.2.20";

// ---------------------------------------------------------------------------
// Origin and proxy harness (same pattern as the other e2e files).
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
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
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

#[derive(Clone, Copy, Debug)]
enum Mode {
    SingleProcess,
    Worker,
}

/// Supervisor side of the RPC plane, served by the production handler.
fn spawn_supervisor(
    endpoint: RpcEndpoint,
    mut incoming: IncomingCommands,
    store: Arc<tokio::sync::Mutex<ConfigStore>>,
) {
    let limits = SupervisorRateLimits::new();
    tokio::spawn(async move {
        let _keep_open = endpoint;
        while let Some(inc) = incoming.recv().await {
            if inc.command_type() == CommandType::RateLimitDelta {
                handle_rate_limit_delta(inc, &limits, &store).await;
            } else {
                let _ = inc.reply_error("unsupported").await;
            }
        }
    });
}

struct ProxyHarness {
    port: u16,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
    _worker_incoming: Option<IncomingCommands>,
}

impl ProxyHarness {
    async fn start(route: Route, mode: Mode) -> Self {
        init_crypto_provider_once();
        let origin = spawn_origin().await;
        let links = vec![(route.id.clone(), "b-primary".to_string())];
        let globals = ProxyConfigGlobals {
            // Lets each test name its client through X-Forwarded-For.
            trusted_proxy_cidrs: vec!["127.0.0.1/32".to_string()],
            ..ProxyConfigGlobals::default()
        };
        let config = ProxyConfig::from_store(
            vec![route.clone()],
            vec![test_backend("b-primary", origin)],
            vec![],
            links,
            globals,
        );
        let mut proxy = LoricaProxy::new(
            Arc::new(ArcSwap::from_pointee(config)),
            Arc::new(lorica_api::logs::LogBuffer::new(128)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(lorica_bench::passive_sla::SlaCollector::new()),
        );

        let mut worker_incoming = None;
        if let Mode::Worker = mode {
            let store = ConfigStore::open_in_memory().unwrap();
            store.create_route(&route).unwrap();
            let (worker_end, supervisor_end) = tokio::net::UnixStream::pair().unwrap();
            let (worker_ep, incoming) = RpcEndpoint::new(worker_end);
            let (supervisor_ep, supervisor_incoming) = RpcEndpoint::new(supervisor_end);
            spawn_supervisor(
                supervisor_ep,
                supervisor_incoming,
                Arc::new(tokio::sync::Mutex::new(store)),
            );
            proxy.rate_limit_buckets = RateLimitEngine::local();
            let tracker = tokio_util::task::TaskTracker::new();
            proxy.spawn_rate_limit_sync(&tracker, worker_ep, SYNC_INTERVAL);
            worker_incoming = Some(incoming);
        }

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
            _worker_incoming: worker_incoming,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
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

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn status(client: &reqwest::Client, url: &str, client_ip: &str) -> u16 {
    client
        .get(url)
        .header("X-Forwarded-For", client_ip)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Fire `n` requests at once so they land well inside one refill
/// period and one sync tick, whatever the host speed. Returns
/// `(admitted, refused)`.
async fn burst(client: &reqwest::Client, url: &str, client_ip: &str, n: usize) -> (usize, usize) {
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..n {
        let client = client.clone();
        let url = url.to_string();
        let client_ip = client_ip.to_string();
        set.spawn(async move { status(&client, &url, &client_ip).await });
    }
    let (mut admitted, mut refused) = (0, 0);
    while let Some(code) = set.join_next().await {
        match code.unwrap() {
            200 => admitted += 1,
            429 => refused += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    (admitted, refused)
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

fn test_route(id: &str) -> Route {
    Route {
        id: id.into(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_route_admits_after_sync_refuses_when_drained_and_recovers() {
    // The self-proxy guide's configuration: legacy fields only.
    let mut route = test_route("r-legacy");
    route.rate_limit_rps = Some(20);
    route.rate_limit_burst = Some(5);
    let harness = ProxyHarness::start(route, Mode::Worker).await;
    let client = http_client();
    let url = harness.url("/");

    assert_eq!(status(&client, &url, CLIENT_A).await, 200);
    // Issue #45: the first sync used to refresh the bucket to 0 and
    // every later request on the route was refused.
    tokio::time::sleep(AFTER_SYNC).await;
    for i in 0..3 {
        assert_eq!(
            status(&client, &url, CLIENT_A).await,
            200,
            "request {i} after the first sync"
        );
    }

    let (admitted, refused) = burst(&client, &url, CLIENT_A, 30).await;
    assert!(
        refused > 0,
        "a burst of 30 against a bucket of 5 must be refused at some point ({admitted} admitted)"
    );

    // Refused requests consume nothing: a bucket left drained after its
    // consumption was pushed used to never be refreshed again.
    tokio::time::sleep(AFTER_REFILL).await;
    for i in 0..3 {
        assert_eq!(
            status(&client, &url, CLIENT_A).await,
            200,
            "request {i} after the refill time"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn per_route_bucket_drained_by_one_client_recovers_for_another() {
    let mut route = test_route("r-per-route");
    route.rate_limit = Some(RateLimit {
        capacity: 3,
        refill_per_sec: 10,
        scope: RateLimitScope::PerRoute,
    });
    let harness = ProxyHarness::start(route, Mode::Worker).await;
    let client = http_client();
    let url = harness.url("/");

    let (admitted, refused) = burst(&client, &url, CLIENT_A, 20).await;
    assert!(
        refused > 0,
        "client A must drain the shared bucket ({admitted} admitted)"
    );

    tokio::time::sleep(AFTER_REFILL).await;
    assert_eq!(
        status(&client, &url, CLIENT_B).await,
        200,
        "one client draining a per_route bucket must not lock the route for everyone"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn path_rule_rate_limit_is_enforced_with_its_own_capacity() {
    for mode in [Mode::SingleProcess, Mode::Worker] {
        let mut route = test_route(&format!("r-rule-{mode:?}"));
        route.rate_limit_rps = Some(100);
        route.rate_limit_burst = Some(100);
        route.path_rules = vec![PathRule {
            path: "/login".to_string(),
            match_type: PathMatchType::Prefix,
            rate_limit_rps: Some(1),
            rate_limit_burst: Some(2),
            ..Default::default()
        }];
        let harness = ProxyHarness::start(route, mode).await;
        let client = http_client();

        let login = harness.url("/login");
        let (admitted, refused) = burst(&client, &login, CLIENT_A, 8).await;
        // One extra admission is the design § 6 bound: a sync reply can
        // land between two consumptions of the burst.
        assert!(
            (2..=3).contains(&admitted),
            "{mode:?}: the rule's burst of 2 applies, not the route's 100 ({admitted} admitted)"
        );
        assert_eq!(admitted + refused, 8, "{mode:?}");

        // A couple of sync ticks later, well under the rule's one-second
        // refill, the rule's bucket is still empty: the supervisor
        // tracks it with the rule's own limit rather than dropping it.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            status(&client, &login, CLIENT_A).await,
            429,
            "{mode:?}: drained rule bucket"
        );

        let (admitted, refused) = burst(&client, &harness.url("/other"), CLIENT_A, 8).await;
        assert_eq!(
            (admitted, refused),
            (8, 0),
            "{mode:?}: the route-level bucket is not the rule's"
        );
    }
}
