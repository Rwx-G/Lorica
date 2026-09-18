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

//! True HTTP end-to-end for the node-wide WAF scan budget
//! (Story 10.6 AC #7, IV5).
//!
//! A file of its own rather than more tests in
//! `waf_body_inspection_e2e_test.rs`, and the reason is the thing under
//! test: the budget is a process-wide static, on purpose, because a
//! reservation outlives the configuration snapshot it was taken under.
//! Lowering it is therefore not a per-test setting, it is a change
//! every test in the same binary would see. One integration file is one
//! binary, so this one runs the whole process under a 4 KiB ceiling and
//! nothing else has to know.
//!
//! What it asserts is the fail-open direction, which is the part of AC
//! #7 that is a decision rather than a mechanism: over budget, a body
//! carrying a payload the WAF would certainly have blocked is forwarded
//! to the upstream instead, on a Blocking route, with the skip counted.
//! Failing closed would turn a saturated shared budget into a
//! node-wide 413 storm.

#![cfg(unix)]

mod common;

use common::reserve_port;

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

/// Small enough that the first buffered chunk of any real body is
/// refused, so the outcome does not depend on chunk sizing.
const TINY_BUDGET: u64 = 4_096;

// ---------------------------------------------------------------------------
// Origin that counts the body bytes it receives.
// ---------------------------------------------------------------------------

async fn spawn_body_counting_origin() -> (SocketAddr, Arc<AtomicU64>) {
    let received = Arc::new(AtomicU64::new(0));
    let received_c = Arc::clone(&received);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let received = Arc::clone(&received_c);
            tokio::spawn(async move {
                let mut buf: Vec<u8> = Vec::new();
                let mut scratch = [0u8; 16384];
                let header_end = loop {
                    match stream.read(&mut scratch).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&scratch[..n]),
                    }
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
                let want = headers
                    .split("content-length:")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                let mut have = buf.len() - header_end;
                while have < want {
                    match stream.read(&mut scratch).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => have += n,
                    }
                }
                received.fetch_add(have as u64, Ordering::SeqCst);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, received)
}

// ---------------------------------------------------------------------------
// Raw client (same shape as the sibling e2e file).
// ---------------------------------------------------------------------------

async fn send_request(port: u16, request: Vec<u8>) -> u16 {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let (mut rd, mut wr) = stream.into_split();
    // Parks rather than returning: dropping the write half would look
    // like a client that went away and the proxy would abandon the
    // upstream request mid-flight.
    let writer = tokio::spawn(async move {
        let _ = wr.write_all(&request).await;
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
            let line = String::from_utf8_lossy(&buf[..pos]).to_string();
            break line
                .split_whitespace()
                .nth(1)
                .and_then(|c| c.parse::<u16>().ok())
                .unwrap_or(0);
        }
    };
    writer.abort();
    status
}

fn sized_request(port: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut req = format!(
        "PUT /upload HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    req.extend_from_slice(body);
    req
}

// ---------------------------------------------------------------------------
// Harness.
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

fn waf_route() -> Route {
    Route {
        id: "r-waf-budget".into(),
        hostname: "_".into(),
        path_prefix: "/".into(),
        certificate_id: None,
        load_balancing: LoadBalancing::RoundRobin,
        waf_enabled: true,
        waf_mode: WafMode::Blocking,
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
        max_request_body_bytes: Some(8 * 1_048_576),
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

/// Builds the snapshot, which is also what lowers the process-wide
/// ceiling: `ProxyConfig::from_store` is the reload hook for it.
async fn harness_under_a_tiny_budget() -> (ProxyHarness, Arc<AtomicU64>) {
    let (origin, received) = spawn_body_counting_origin().await;
    let config = ProxyConfig::from_store(
        vec![waf_route()],
        vec![test_backend("b-primary", origin)],
        vec![],
        vec![("r-waf-budget".into(), "b-primary".into())],
        ProxyConfigGlobals {
            waf_body_scan_max_inflight_bytes: TINY_BUDGET,
            ..ProxyConfigGlobals::default()
        },
    );
    let harness = ProxyHarness::start(Arc::new(ArcSwap::from_pointee(config))).await;
    (harness, received)
}

fn sqli_json() -> Vec<u8> {
    br#"{"q":"1' UNION SELECT password FROM users--"}"#.to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_budget_the_body_is_forwarded_unscanned_instead_of_rejected() {
    // IV5. A JSON body the WAF would block, on a Blocking route, with
    // the node's scan budget too small to hold it. The request must be
    // answered by the upstream, not by a 413 and not by a 403: the
    // budget is a memory bound, not a policy, and a shared bound that
    // rejected traffic would be a self-inflicted outage.
    let (harness, received) = harness_under_a_tiny_budget().await;
    let before = lorica_api::metrics::waf_body_scan_outcome_value("skipped_budget");
    let mut body = sqli_json();
    body.resize(64 * 1024, b'a');

    let status = send_request(
        harness.port,
        sized_request(harness.port, "application/json", &body),
    )
    .await;

    assert_eq!(
        status, 200,
        "over budget the request is allowed through, not rejected"
    );
    assert_eq!(
        received.load(Ordering::SeqCst),
        body.len() as u64,
        "the upstream receives the body whole"
    );
    assert_eq!(
        lorica_api::metrics::waf_body_scan_outcome_value("skipped_budget"),
        before + 1,
        "the skip is counted exactly once, which is what an operator alarms on"
    );

    // The status line reaches this task before the proxy has finished
    // dropping the request context the reservation lives on, so the
    // gauge is read with a bounded wait rather than on the same tick.
    for _ in 0..40 {
        if lorica_api::metrics::waf_body_scan_inflight_bytes_value() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        lorica_api::metrics::waf_body_scan_inflight_bytes_value(),
        0,
        "the reservation is released once the request ends"
    );
}
