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

//! Issue #56 over a real socket: once a backend accepts an upgrade
//! (`101`), the client side of the tunnel follows the route's
//! `read_timeout_s` and `send_timeout_s`, not the forked HTTP/1
//! session's own defaults.
//!
//! Inside a tunnel each direction's read restarts whenever the other
//! direction carries data, so an idle tunnel is cut by whichever side's
//! read timeout is shorter. The backend side always used the route
//! value; the client side used the session default whatever the route
//! said, and a write to a client that stopped reading had no bound.

#![cfg(unix)]

mod common;

use common::reserve_port;

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use lorica::proxy_wiring::{LoricaProxy, ProxyConfig, ProxyConfigGlobals};
use lorica_config::models::*;
use lorica_core::protocols::http::v1::server::HttpSession;
use lorica_core::server::{RunArgs, Server, ShutdownSignal, ShutdownSignalWatch};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Origin that accepts a WebSocket upgrade, then echoes or floods.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum AfterUpgrade {
    /// Write back every byte received.
    Echo,
    /// Write as fast as the proxy accepts, and report how long after the
    /// `101` a write failed, which is when the proxy dropped the tunnel.
    Flood,
}

const SWITCHING_PROTOCOLS: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n\
    Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

async fn spawn_origin(after: AfterUpgrade) -> (SocketAddr, mpsc::UnboundedReceiver<Duration>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (cut_tx, cut_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            let cut_tx = cut_tx.clone();
            tokio::spawn(async move {
                if read_head(&mut stream).await.is_none() {
                    return;
                }
                if stream.write_all(SWITCHING_PROTOCOLS).await.is_err() {
                    return;
                }
                let upgraded_at = Instant::now();
                match after {
                    AfterUpgrade::Echo => {
                        let mut scratch = [0u8; 4096];
                        loop {
                            match stream.read(&mut scratch).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if stream.write_all(&scratch[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    AfterUpgrade::Flood => {
                        let chunk = vec![b'x'; 64 * 1024];
                        while stream.write_all(&chunk).await.is_ok() {}
                        let _ = cut_tx.send(upgraded_at.elapsed());
                    }
                }
            });
        }
    });
    (addr, cut_rx)
}

/// Reads until the end of an HTTP header block and returns it, or `None`
/// when the peer closes first.
async fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        match stream.read(&mut scratch).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&scratch[..n]),
        }
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
    }
}

const UPGRADE_REQUEST: &[u8] = b"GET /ws HTTP/1.1\r\n\
    Host: ws.example\r\n\
    Upgrade: websocket\r\n\
    Connection: Upgrade\r\n\
    Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
    Sec-WebSocket-Version: 13\r\n\r\n";

/// Sends the upgrade request on `stream` and asserts the proxy relays
/// the backend's `101`.
async fn upgrade(stream: &mut TcpStream) {
    stream.write_all(UPGRADE_REQUEST).await.unwrap();
    let head = tokio::time::timeout(Duration::from_secs(10), read_head(stream))
        .await
        .expect("the proxy answers the upgrade in time")
        .expect("the proxy closed instead of answering the upgrade");
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "the upgrade was not accepted: {head}"
    );
}

/// The read timeout the forked HTTP/1 session applies when nothing
/// overrides it, read from the session itself.
fn session_default_read_timeout() -> Duration {
    let (stream, _peer) = tokio::io::duplex(64);
    HttpSession::new(Box::new(stream))
        .get_read_timeout()
        .expect("this test assumes the HTTP/1 session bounds reads by default")
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

fn websocket_route(read_timeout_s: i32, send_timeout_s: i32) -> Route {
    Route {
        id: "r-ws".into(),
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
        read_timeout_s,
        send_timeout_s,
        strip_path_prefix: None,
        add_path_prefix: None,
        path_rewrite_pattern: None,
        path_rewrite_replacement: None,
        access_log_enabled: false,
        proxy_headers_remove: Vec::new(),
        response_headers_remove: Vec::new(),
        max_request_body_bytes: None,
        websocket_enabled: true,
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
        case_insensitive_paths: false,
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

fn config(origin: SocketAddr, read_timeout_s: i32, send_timeout_s: i32) -> ProxyConfig {
    ProxyConfig::from_store(
        vec![websocket_route(read_timeout_s, send_timeout_s)],
        vec![test_backend("b-ws", origin)],
        vec![],
        vec![("r-ws".into(), "b-ws".into())],
        ProxyConfigGlobals::default(),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_idle_tunnel_outlives_the_session_default_read_timeout() {
    // The case of the issue: both sides silent for longer than the
    // session default, on a route whose read timeout is longer still.
    let idle = session_default_read_timeout() + Duration::from_secs(2);
    let route_read_s = i32::try_from(idle.as_secs()).unwrap() + 30;

    let (origin, _) = spawn_origin(AfterUpgrade::Echo).await;
    let config = Arc::new(ArcSwap::from_pointee(config(
        origin,
        route_read_s,
        route_read_s,
    )));
    let harness = ProxyHarness::start(config).await;

    let mut stream = TcpStream::connect(("127.0.0.1", harness.port))
        .await
        .unwrap();
    upgrade(&mut stream).await;
    tokio::time::sleep(idle).await;

    stream
        .write_all(b"ping")
        .await
        .expect("the tunnel was closed while idle");
    let mut echoed = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
        .await
        .expect("the echo arrives in time")
        .expect("the tunnel was closed while idle");
    assert_eq!(&echoed, b"ping");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_stops_reading_is_cut_after_the_route_send_timeout() {
    // The read timeout is far past the test's wait, so only the send
    // timeout can end this tunnel.
    let (origin, mut cut) = spawn_origin(AfterUpgrade::Flood).await;
    let config = Arc::new(ArcSwap::from_pointee(config(origin, 120, 2)));
    let harness = ProxyHarness::start(config).await;

    // A small receive buffer, so the proxy's writes back to this client
    // block soon after it stops reading.
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stream = socket
        .connect(SocketAddr::from(([127, 0, 0, 1], harness.port)))
        .await
        .unwrap();
    upgrade(&mut stream).await;

    let cut_after = tokio::time::timeout(Duration::from_secs(20), cut.recv())
        .await
        .expect("the proxy kept the tunnel open to a client that stopped reading")
        .expect("the origin reports the cut");
    // Two seconds of blocked write, measured from the 101; the origin
    // fills the buffers in far less than the margin.
    assert!(
        cut_after >= Duration::from_millis(1500),
        "cut before the send timeout: {cut_after:?}"
    );
    drop(stream);
}
