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

//! Story 12.8 end to end on a real socket: a `LoricaProxy` whose HTTP
//! endpoint is registered the way `run_worker` and `run_single_process`
//! register it, with the connection filter's PROXY protocol gate.
//!
//! 1. Live apply: with the gate off, a PROXY header is bytes the HTTP
//!    parser refuses; after a reload to `required` the same header is
//!    read, and the carried client reaches the origin as `X-Real-IP` and
//!    the last `X-Forwarded-For` entry, and the access log, while the
//!    client's forged `X-Forwarded-For` names nobody.
//! 2. A peer outside the trust list that sends a header is disconnected
//!    without an answer and counted as `untrusted_peer`; a plain request
//!    from it is served.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::connection_filter::{GlobalConnectionFilter, HttpListener, ProxyProtocolSettings};
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::listeners::{ConnectionFilter, ServerAddress};
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The client address the balancer's header carries.
const CARRIED: &str = "203.0.113.7";
/// What the client writes in its own `X-Forwarded-For`.
const FORGED: &str = "198.51.100.9";

/// An origin answering every request with the request head it received
/// as its body, lowercased.
async fn spawn_echo_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buf[..n]);
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let body = String::from_utf8_lossy(&head).to_lowercase();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

fn init_crypto_provider_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct ProxyHarness {
    port: u16,
    filter: Arc<GlobalConnectionFilter>,
    log_buffer: Arc<lorica_api::logs::LogBuffer>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl ProxyHarness {
    /// A proxy in front of an echo origin, `trusted_proxies` holding the
    /// loopback network, its HTTP endpoint registered with the gate.
    async fn start() -> Self {
        init_crypto_provider_once();
        let origin = spawn_echo_origin().await;
        let config = ProxyConfig::from_store(
            vec![test_route()],
            vec![test_backend(origin)],
            vec![],
            vec![("r-pp".into(), "b-echo".into())],
            ProxyConfigGlobals {
                trusted_proxy_cidrs: vec!["127.0.0.0/8".to_string(), "203.0.113.0/24".to_string()],
                ..ProxyConfigGlobals::default()
            },
        );
        let log_buffer = Arc::new(lorica_api::logs::LogBuffer::new(128));
        let proxy = LoricaProxy::new(
            Arc::new(ArcSwap::from_pointee(config)),
            Arc::clone(&log_buffer),
            Arc::new(AtomicU64::new(0)),
            Arc::new(lorica_bench::passive_sla::SlaCollector::new()),
        );
        let filter = Arc::new(GlobalConnectionFilter::empty());

        let port = reserve_port();
        let proxy_addr = format!("127.0.0.1:{port}");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let service_filter = Arc::clone(&filter);
        let thread = std::thread::spawn(move || {
            let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
                upstream_keepalive_pool_size: 0,
                ..Default::default()
            });
            let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, proxy);
            proxy_service
                .set_connection_filter(Arc::clone(&service_filter) as Arc<dyn ConnectionFilter>);
            proxy_service.endpoints().add_endpoint_with_proxy_protocol(
                ServerAddress::Tcp(proxy_addr, None),
                None,
                service_filter.proxy_protocol().policy(HttpListener::Http),
            );
            let mut server = Server::new(None).unwrap();
            server.add_service(proxy_service);
            server.bootstrap();
            server.run(RunArgs {
                shutdown_signal: Box::new(ManualShutdown { rx: shutdown_rx }),
            });
        });
        for _ in 0..100 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return Self {
                    port,
                    filter,
                    log_buffer,
                    shutdown_tx,
                    thread: Some(thread),
                };
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("proxy never bound 127.0.0.1:{port}");
    }

    fn set_http_mode(&self, mode: ProxyProtocolMode, trusted: &[&str]) {
        self.filter.proxy_protocol().reload(&ProxyProtocolSettings {
            http: mode,
            https: ProxyProtocolMode::Off,
            trusted_cidrs: trusted.iter().map(|e| (*e).to_string()).collect(),
        });
    }

    /// Writes `bytes` on a fresh connection and reads until the proxy
    /// closes it: the whole answer, empty when it answered nothing.
    async fn exchange(&self, bytes: &[u8]) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        let mut answer = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), async {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => answer.extend_from_slice(&buf[..n]),
                }
            }
        })
        .await;
        assert!(read.is_ok(), "the proxy neither answered nor closed");
        String::from_utf8_lossy(&answer).to_string()
    }

    fn last_logged_client(&self) -> Option<String> {
        self.log_buffer
            .snapshot()
            .last()
            .map(|entry| entry.client_ip.clone())
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

fn request_with_forged_xff() -> String {
    format!(
        "GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: {FORGED}\r\nConnection: close\r\n\r\n"
    )
}

fn v1_header() -> String {
    format!("PROXY TCP4 {CARRIED} 192.0.2.1 40000 80\r\n")
}

#[tokio::test]
async fn a_reload_turns_proxy_accept_on_and_the_carried_client_reaches_every_control() {
    let harness = ProxyHarness::start().await;
    let proxied = format!("{}{}", v1_header(), request_with_forged_xff());

    // Off, as every listener ships: the header is bytes the HTTP parser
    // refuses, exactly as before Story 12.8.
    harness.set_http_mode(ProxyProtocolMode::Off, &["127.0.0.1/32"]);
    let answer = harness.exchange(proxied.as_bytes()).await;
    assert!(!answer.starts_with("HTTP/1.1 200"), "{answer}");

    // Required from loopback, applied without touching the listener.
    harness.set_http_mode(ProxyProtocolMode::Required, &["127.0.0.1/32"]);
    let accepted_before = lorica_api::metrics::proxy_protocol_accepted_value("http", "v1");
    let answer = harness.exchange(proxied.as_bytes()).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(
        answer.contains(&format!("x-real-ip: {CARRIED}")),
        "{answer}"
    );
    assert!(
        answer.contains(&format!("x-forwarded-for: {FORGED}, {CARRIED}")),
        "{answer}"
    );
    // The carried address is in `trusted_proxies` too: the forged header
    // is still not read.
    assert_eq!(harness.last_logged_client().as_deref(), Some(CARRIED));
    assert!(lorica_api::metrics::proxy_protocol_accepted_value("http", "v1") > accepted_before);

    // `required`: a trusted peer that sends no header is closed unanswered.
    let answer = harness.exchange(request_with_forged_xff().as_bytes()).await;
    assert!(answer.is_empty(), "{answer}");
}

#[tokio::test]
async fn a_header_from_outside_the_trust_list_is_disconnected_and_counted() {
    let harness = ProxyHarness::start().await;
    harness.set_http_mode(ProxyProtocolMode::Required, &["192.0.2.0/24"]);
    let refused_before =
        lorica_api::metrics::proxy_protocol_refused_value("http", "untrusted_peer");

    let proxied = format!("{}{}", v1_header(), request_with_forged_xff());
    let answer = harness.exchange(proxied.as_bytes()).await;
    assert!(answer.is_empty(), "{answer}");
    assert!(
        lorica_api::metrics::proxy_protocol_refused_value("http", "untrusted_peer")
            > refused_before
    );

    // The same peer without a header is a direct client: served, and
    // since loopback is in `trusted_proxies`, its header is read as before,
    // and `X-Real-IP` names the client it resolved (1.10.10).
    let answer = harness.exchange(request_with_forged_xff().as_bytes()).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains(&format!("x-real-ip: {FORGED}")), "{answer}");
    assert_eq!(harness.last_logged_client().as_deref(), Some(FORGED));
}

fn test_route() -> Route {
    Route {
        id: "r-pp".into(),
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
        access_log_enabled: true,
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
        case_insensitive_paths: false,
        managed_by: None,
        waf_body_scan_max_bytes: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn test_backend(addr: SocketAddr) -> Backend {
    Backend {
        id: "b-echo".into(),
        address: addr.to_string(),
        name: "b-echo".into(),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
        health_check_enabled: false,
        health_check_interval_s: 10,
        health_check_path: None,
        health_check: lorica_config::models::HealthCheck::TcpConnect,
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
