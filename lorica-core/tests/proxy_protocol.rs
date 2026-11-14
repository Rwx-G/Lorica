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

//! Lorica: PROXY protocol accept on a listening endpoint, end to end over
//! real sockets (Story 12.8). A listening service runs an application that
//! reports what its connection says about itself: the socket digest's
//! addresses, `proxied_from`, and the request line the HTTP parser read.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use lorica_core::apps::ServerApp;
use lorica_core::listeners::{
    AcceptPermit, AcceptVerdict, ConnectionFilter, ProxyHeaderOutcome, ProxyProtocolMode,
    ProxyProtocolPolicy, ServerAddress,
};
use lorica_core::protocols::proxy_protocol::V2_SIGNATURE;
use lorica_core::protocols::Stream;
use lorica_core::server::ShutdownWatch;
use lorica_core::services::listening::Service;
use lorica_core::services::Service as ServiceTrait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;

const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

type Record = (ProxyHeaderOutcome, Option<SocketAddr>, Option<&'static str>);

#[derive(Debug)]
struct TestPolicy {
    mode: ProxyProtocolMode,
    trusted: Vec<IpAddr>,
    records: Mutex<Vec<Record>>,
}

impl TestPolicy {
    fn new(mode: ProxyProtocolMode, trusted: &[IpAddr]) -> Arc<TestPolicy> {
        Arc::new(TestPolicy {
            mode,
            trusted: trusted.to_vec(),
            records: Mutex::new(Vec::new()),
        })
    }

    fn outcomes(&self) -> Vec<ProxyHeaderOutcome> {
        let records = self.records.lock().expect("records lock");
        records.iter().map(|record| record.0).collect()
    }
}

impl ProxyProtocolPolicy for TestPolicy {
    fn mode(&self) -> ProxyProtocolMode {
        self.mode
    }

    fn is_trusted(&self, peer: &SocketAddr) -> bool {
        self.trusted.contains(&peer.ip())
    }

    fn record(
        &self,
        outcome: ProxyHeaderOutcome,
        peer: Option<&SocketAddr>,
        detail: Option<&'static str>,
    ) {
        let mut records = self.records.lock().expect("records lock");
        records.push((outcome, peer.copied(), detail));
    }
}

/// A connection filter with a deny list and a per-IP count of live
/// connections, decremented by its permit's `Drop`.
#[derive(Debug, Default)]
struct TestFilter {
    deny: Vec<IpAddr>,
    seen: Mutex<Vec<Option<SocketAddr>>>,
    live: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl TestFilter {
    fn denying(deny: &[IpAddr]) -> Arc<TestFilter> {
        Arc::new(TestFilter {
            deny: deny.to_vec(),
            ..TestFilter::default()
        })
    }

    fn seen_ips(&self) -> Vec<Option<IpAddr>> {
        let seen = self.seen.lock().expect("seen lock");
        seen.iter().map(|addr| addr.map(|a| a.ip())).collect()
    }

    fn live(&self, ip: IpAddr) -> usize {
        let live = self.live.lock().expect("live lock");
        live.get(&ip).copied().unwrap_or(0)
    }
}

#[derive(Debug)]
struct LivePermit {
    ip: IpAddr,
    live: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl AcceptPermit for LivePermit {}

impl Drop for LivePermit {
    fn drop(&mut self) {
        let mut live = self.live.lock().expect("live lock");
        if let Some(count) = live.get_mut(&self.ip) {
            *count -= 1;
        }
    }
}

#[async_trait]
impl ConnectionFilter for TestFilter {
    async fn try_accept(&self, addr: Option<&SocketAddr>) -> AcceptVerdict {
        self.seen.lock().expect("seen lock").push(addr.copied());
        let Some(addr) = addr else {
            return AcceptVerdict::Accept(None);
        };
        if self.deny.contains(&addr.ip()) {
            return AcceptVerdict::Reject;
        }
        *self
            .live
            .lock()
            .expect("live lock")
            .entry(addr.ip())
            .or_insert(0) += 1;
        AcceptVerdict::Accept(Some(Box::new(LivePermit {
            ip: addr.ip(),
            live: Arc::clone(&self.live),
        })))
    }
}

/// Reads the request head, then answers with what the connection says
/// about itself, one `key=value` per line.
struct ReportApp;

#[async_trait]
impl ServerApp for ReportApp {
    async fn process_new(
        self: &Arc<Self>,
        mut session: Stream,
        _shutdown: &ShutdownWatch,
    ) -> Option<Stream> {
        let mut head = Vec::new();
        let mut chunk = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match session.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut request = httparse::Request::new(&mut headers);
        let request_line = match request.parse(&head) {
            Ok(httparse::Status::Complete(_)) => format!(
                "{} {}",
                request.method.unwrap_or_default(),
                request.path.unwrap_or_default()
            ),
            _ => {
                let first = head.split(|b| *b == b'\n').next().unwrap_or_default();
                format!("invalid: {}", String::from_utf8_lossy(first).trim_end())
            }
        };
        let digest = session.get_socket_digest();
        let peer = digest
            .as_ref()
            .and_then(|d| d.peer_addr().and_then(|a| a.as_inet()).copied());
        let local = digest
            .as_ref()
            .and_then(|d| d.local_addr().and_then(|a| a.as_inet()).copied());
        let proxied = digest.as_ref().and_then(|d| d.proxied_from().copied());
        let body = format!(
            "peer={}\nlocal={}\nproxied={}\nrequest={}\n",
            peer.map(|a| a.to_string()).unwrap_or_default(),
            local.map(|a| a.to_string()).unwrap_or_default(),
            proxied
                .map(|p| format!(
                    "{} {} {:?}",
                    p.peer,
                    p.local.map(|a| a.to_string()).unwrap_or_default(),
                    p.version
                ))
                .unwrap_or_default(),
            request_line
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = session.write_all(response.as_bytes()).await;
        let _ = session.flush().await;
        None
    }
}

struct Report(HashMap<String, String>);

impl Report {
    fn parse(response: &str) -> Option<Report> {
        let (_, body) = response.split_once("\r\n\r\n")?;
        Some(Report(
            body.lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        ))
    }

    fn get(&self, key: &str) -> &str {
        self.0.get(key).map(String::as_str).unwrap_or_default()
    }
}

struct TestServer {
    addr: String,
    _shutdown: watch::Sender<bool>,
}

/// Starts a plaintext or TLS listening service with `filter` and, when
/// given, a PROXY protocol `policy`, and waits until it accepts. The probe
/// connections made while waiting are wiped from the records.
async fn start(
    policy: Option<Arc<TestPolicy>>,
    filter: Arc<TestFilter>,
    tls: Option<lorica_core::listeners::tls::TlsSettings>,
) -> TestServer {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("test setup: free port")
        .port();
    let addr = format!("127.0.0.1:{port}");
    let mut service = Service::new("proxy-protocol-test".to_string(), ReportApp);
    service.set_connection_filter(filter.clone());
    let endpoint = ServerAddress::Tcp(addr.clone(), None);
    match &policy {
        Some(policy) => service.endpoints().add_endpoint_with_proxy_protocol(
            endpoint,
            tls,
            Arc::clone(policy) as Arc<dyn ProxyProtocolPolicy>,
        ),
        None => service.endpoints().add_endpoint(endpoint, tls),
    }
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        ServiceTrait::start_service(&mut service, None, shutdown_rx, 1).await;
    });
    for _ in 0..100 {
        if TcpStream::connect(&addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    if let Some(policy) = &policy {
        policy.records.lock().expect("records lock").clear();
    }
    filter.seen.lock().expect("seen lock").clear();
    TestServer {
        addr,
        _shutdown: shutdown_tx,
    }
}

fn v1_header(source: &str, destination: &str) -> Vec<u8> {
    let source: SocketAddr = source.parse().expect("test vector");
    let destination: SocketAddr = destination.parse().expect("test vector");
    format!(
        "PROXY TCP4 {} {} {} {}\r\n",
        source.ip(),
        destination.ip(),
        source.port(),
        destination.port()
    )
    .into_bytes()
}

const V2_PROXY: u8 = 0x21;
const V2_LOCAL: u8 = 0x20;
const V2_INET_STREAM: u8 = 0x11;

fn v2_header(command: u8, source: &str, destination: &str) -> Vec<u8> {
    let source: SocketAddr = source.parse().expect("test vector");
    let destination: SocketAddr = destination.parse().expect("test vector");
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (source.ip(), destination.ip()) else {
        panic!("test vectors are IPv4");
    };
    let mut header = V2_SIGNATURE.to_vec();
    header.extend_from_slice(&[command, V2_INET_STREAM, 0, 12]);
    header.extend_from_slice(&src.octets());
    header.extend_from_slice(&dst.octets());
    header.extend_from_slice(&source.port().to_be_bytes());
    header.extend_from_slice(&destination.port().to_be_bytes());
    header
}

const REQUEST: &[u8] = b"GET /probe HTTP/1.1\r\nHost: example.com\r\n\r\n";

fn with_request(header: Vec<u8>) -> Vec<u8> {
    let mut wire = header;
    wire.extend_from_slice(REQUEST);
    wire
}

/// Writes `wire` in one segment and reads until the server closes. An
/// empty answer means the connection was closed without one.
async fn exchange(addr: &str, wire: &[u8]) -> String {
    let mut client = TcpStream::connect(addr).await.expect("connect");
    client.write_all(wire).await.expect("write");
    read_to_close(&mut client).await
}

async fn read_to_close(client: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response));
    match read
        .await
        .expect("the server answers or closes within 10 s")
    {
        Ok(_) => String::from_utf8_lossy(&response).into_owned(),
        // A reset is a close without an answer.
        Err(_) => String::new(),
    }
}

/// Waits for `check` to hold, the server side of a test running on its
/// own tasks.
async fn eventually(check: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[tokio::test]
async fn a_v1_header_carries_the_client_and_the_bytes_behind_it_reach_the_parser() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert_eq!(report.get("peer"), "192.0.2.10:51000");
    assert_eq!(report.get("local"), "198.51.100.1:80");
    assert_eq!(report.get("request"), "GET /probe");
    let proxied = report.get("proxied");
    assert!(proxied.starts_with("127.0.0.1:"), "{proxied}");
    assert!(proxied.contains(&server.addr), "{proxied}");
    assert!(proxied.ends_with(" V1"), "{proxied}");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::V1]);
    assert_eq!(filter.seen_ips(), [Some("192.0.2.10".parse().unwrap())]);
}

#[tokio::test]
async fn a_v2_header_carries_the_client() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v2_header(V2_PROXY, "203.0.113.7:4000", "198.51.100.2:8080")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert_eq!(report.get("peer"), "203.0.113.7:4000");
    assert_eq!(report.get("local"), "198.51.100.2:8080");
    assert!(report.get("proxied").ends_with(" V2"));
    assert_eq!(report.get("request"), "GET /probe");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::V2]);
}

#[tokio::test]
async fn a_v2_local_header_keeps_the_socket_addresses() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v2_header(V2_LOCAL, "203.0.113.7:4000", "198.51.100.2:8080")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert!(report.get("peer").starts_with("127.0.0.1:"));
    assert_eq!(report.get("local"), server.addr);
    assert_eq!(report.get("proxied"), "");
    assert_eq!(report.get("request"), "GET /probe");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::Local]);
    assert_eq!(filter.seen_ips(), [Some(LOOPBACK)]);
}

#[tokio::test]
async fn an_untrusted_peer_sending_a_header_is_closed_and_one_without_is_served() {
    let elsewhere: IpAddr = "192.0.2.1".parse().unwrap();
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[elsewhere]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    let v1 = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;
    assert_eq!(v1, "", "a v1 header from an untrusted peer is not answered");
    let v2 = exchange(
        &server.addr,
        &with_request(v2_header(V2_PROXY, "192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;
    assert_eq!(v2, "", "a v2 header from an untrusted peer is not answered");

    let direct = exchange(&server.addr, REQUEST).await;
    let report = Report::parse(&direct).expect("a direct client is served");
    assert!(report.get("peer").starts_with("127.0.0.1:"));
    assert_eq!(report.get("proxied"), "");
    assert_eq!(report.get("request"), "GET /probe");

    let records = policy.records.lock().unwrap().clone();
    assert_eq!(records.len(), 2, "{records:?}");
    for (outcome, peer, detail) in records {
        assert_eq!(outcome, ProxyHeaderOutcome::UntrustedPeer);
        assert_eq!(peer.map(|p| p.ip()), Some(LOOPBACK));
        assert!(detail.is_some());
    }
}

#[tokio::test]
async fn a_post_from_a_direct_client_is_not_taken_for_a_signature() {
    let elsewhere: IpAddr = "192.0.2.1".parse().unwrap();
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[elsewhere]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    let mut client = TcpStream::connect(&server.addr).await.expect("connect");
    // One byte first: the sniff must wait for the second to decide.
    client.write_all(b"P").await.expect("write");
    tokio::time::sleep(Duration::from_millis(100)).await;
    client
        .write_all(b"OST /form HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write");
    let response = read_to_close(&mut client).await;

    let report = Report::parse(&response).expect("a direct client is served");
    assert_eq!(report.get("request"), "POST /form");
    assert!(policy.outcomes().is_empty());
}

#[tokio::test]
async fn required_without_a_header_is_closed() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    assert_eq!(exchange(&server.addr, REQUEST).await, "");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::Missing]);
    assert!(
        filter.seen_ips().is_empty(),
        "a refusal never reaches the filter"
    );
}

#[tokio::test]
async fn optional_without_a_header_is_served_on_the_socket_address() {
    let policy = TestPolicy::new(ProxyProtocolMode::Optional, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let report = Report::parse(&exchange(&server.addr, REQUEST).await).expect("a response");
    assert!(report.get("peer").starts_with("127.0.0.1:"));
    assert_eq!(report.get("proxied"), "");
    assert_eq!(report.get("request"), "GET /probe");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::Absent]);
    assert_eq!(filter.seen_ips(), [Some(LOOPBACK)]);
}

#[tokio::test]
async fn a_header_trickled_past_the_read_timeout_is_closed() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    let mut client = TcpStream::connect(&server.addr).await.expect("connect");
    let started = tokio::time::Instant::now();
    let header = v1_header("192.0.2.10:51000", "198.51.100.1:80");
    let mut closed = false;
    for byte in header {
        if client.write_all(&[byte]).await.is_err() {
            closed = true;
            break;
        }
        let mut probe = [0u8; 1];
        match tokio::time::timeout(Duration::from_millis(500), client.read(&mut probe)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {
                closed = true;
                break;
            }
            Ok(Ok(_)) => panic!("no answer is expected"),
            Err(_) => {}
        }
    }
    let elapsed = started.elapsed();
    assert!(closed, "the trickled header was never refused");
    assert!(elapsed >= Duration::from_millis(4500), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::Timeout]);
}

#[tokio::test]
async fn a_v2_header_declaring_one_byte_over_the_bound_is_closed() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    let total = lorica_core::protocols::proxy_protocol::MAX_HEADER_LEN + 1;
    let declared = u16::try_from(total - 16).expect("fits");
    let mut wire = V2_SIGNATURE.to_vec();
    wire.extend_from_slice(&[V2_PROXY, V2_INET_STREAM]);
    wire.extend_from_slice(&declared.to_be_bytes());

    assert_eq!(exchange(&server.addr, &wire).await, "");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::Oversized]);
}

#[tokio::test]
async fn a_deny_list_holding_the_carried_address_rejects_the_connection() {
    let client: IpAddr = "192.0.2.66".parse().unwrap();
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[client]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.66:40000", "198.51.100.1:80")),
    )
    .await;

    assert_eq!(response, "");
    assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::V1]);
    assert_eq!(filter.seen_ips(), [Some(client)]);
}

#[tokio::test]
async fn a_deny_list_holding_only_the_balancer_lets_a_proxied_connection_through() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[LOOPBACK]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert_eq!(report.get("peer"), "192.0.2.10:51000");
    assert_eq!(filter.seen_ips(), [Some("192.0.2.10".parse().unwrap())]);
}

#[tokio::test]
async fn the_per_ip_permit_is_charged_to_the_carried_address_and_released_on_close() {
    let client_ip: IpAddr = "192.0.2.30".parse().unwrap();
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let mut client = TcpStream::connect(&server.addr).await.expect("connect");
    let mut wire = v1_header("192.0.2.30:42000", "198.51.100.1:80");
    // An unfinished request head keeps the connection open.
    wire.extend_from_slice(b"GET /held HTTP/1.1\r\n");
    client.write_all(&wire).await.expect("write");

    assert!(eventually(|| filter.live(client_ip) == 1).await);
    assert_eq!(filter.live(LOOPBACK), 0);

    drop(client);
    assert!(
        eventually(|| filter.live(client_ip) == 0).await,
        "the permit is released when the connection closes"
    );
}

#[tokio::test]
async fn with_the_mode_off_a_header_reaches_the_parser_as_bytes() {
    let policy = TestPolicy::new(ProxyProtocolMode::Off, &[LOOPBACK]);
    let filter = TestFilter::denying(&[]);
    let server = start(Some(policy.clone()), filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert_eq!(
        report.get("request"),
        "invalid: PROXY TCP4 192.0.2.10 198.51.100.1 51000 80"
    );
    assert!(report.get("peer").starts_with("127.0.0.1:"));
    assert_eq!(report.get("proxied"), "");
    assert!(policy.outcomes().is_empty());
    assert_eq!(filter.seen_ips(), [Some(LOOPBACK)], "filtered at accept");
}

#[tokio::test]
async fn without_a_policy_a_header_reaches_the_parser_as_bytes() {
    let filter = TestFilter::denying(&[]);
    let server = start(None, filter.clone(), None).await;

    let response = exchange(
        &server.addr,
        &with_request(v2_header(V2_PROXY, "192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;

    let report = Report::parse(&response).expect("a response");
    assert!(report.get("request").starts_with("invalid: "));
    assert!(report.get("peer").starts_with("127.0.0.1:"));
    assert_eq!(filter.seen_ips(), [Some(LOOPBACK)]);
}

#[tokio::test]
async fn a_slow_trusted_peer_does_not_delay_another_connection() {
    let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
    let server = start(Some(policy.clone()), TestFilter::denying(&[]), None).await;

    // Sends nothing: its connection task waits for a header.
    let _silent = TcpStream::connect(&server.addr).await.expect("connect");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = tokio::time::Instant::now();
    let response = exchange(
        &server.addr,
        &with_request(v1_header("192.0.2.10:51000", "198.51.100.1:80")),
    )
    .await;
    assert!(Report::parse(&response).is_some());
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[cfg(feature = "rustls")]
mod tls {
    use super::*;
    use lorica_core::listeners::tls::TlsSettings;
    use lorica_tls::cert_resolver::{build_certified_key, ResolvesServerCertByLocalIp};
    use rustls::server::ClientHello;
    use rustls::sign::CertifiedKey;

    /// Serves its one certificate only to a connection without SNI whose
    /// local address is `local_ip`, and keeps every address it was asked.
    #[derive(Debug)]
    struct ByLocalIp {
        key: Arc<CertifiedKey>,
        local_ip: IpAddr,
        asked: Mutex<Vec<IpAddr>>,
    }

    impl lorica_tls::ResolvesServerCert for ByLocalIp {
        fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
            None
        }
    }

    impl ResolvesServerCertByLocalIp for ByLocalIp {
        fn resolve_by_local_ip(&self, local_ip: IpAddr) -> Option<Arc<CertifiedKey>> {
            self.asked.lock().expect("asked lock").push(local_ip);
            (local_ip == self.local_ip).then(|| Arc::clone(&self.key))
        }
    }

    #[tokio::test]
    async fn tls_completes_after_a_v2_header_and_the_no_sni_path_reads_the_carried_destination() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = env!("CARGO_MANIFEST_DIR");
        let cert = std::fs::read_to_string(format!("{dir}/tests/keys/server.crt")).unwrap();
        let key = std::fs::read_to_string(format!("{dir}/tests/keys/key.pem")).unwrap();
        let destination: IpAddr = "198.51.100.9".parse().unwrap();
        let resolver = Arc::new(ByLocalIp {
            key: Arc::new(build_certified_key(&cert, &key, None).expect("test key")),
            local_ip: destination,
            asked: Mutex::new(Vec::new()),
        });
        let policy = TestPolicy::new(ProxyProtocolMode::Required, &[LOOPBACK]);
        let settings = TlsSettings::with_resolver(resolver.clone());
        let server = start(
            Some(policy.clone()),
            TestFilter::denying(&[]),
            Some(settings),
        )
        .await;

        let mut tcp = TcpStream::connect(&server.addr).await.expect("connect");
        tcp.write_all(&v2_header(V2_PROXY, "203.0.113.5:5000", "198.51.100.9:443"))
            .await
            .expect("write");
        let connector =
            lorica_tls::TlsConnector::from(Arc::new(lorica_tls::http_client::unverified()));
        // An IP server name: rustls sends no SNI for it.
        let name = lorica_tls::ServerName::from(LOOPBACK);
        let mut tls = connector
            .connect(name, tcp)
            .await
            .expect("the handshake completes on the carried destination's certificate");
        tls.write_all(REQUEST).await.expect("write");
        let mut response = Vec::new();
        tls.read_to_end(&mut response).await.ok();

        let report =
            Report::parse(&String::from_utf8_lossy(&response)).expect("a response over TLS");
        assert_eq!(report.get("peer"), "203.0.113.5:5000");
        assert_eq!(report.get("local"), "198.51.100.9:443");
        assert_eq!(report.get("request"), "GET /probe");
        let asked = resolver.asked.lock().unwrap().clone();
        assert!(!asked.is_empty() && asked.iter().all(|ip| *ip == destination));
        assert_eq!(policy.outcomes(), [ProxyHeaderOutcome::V2]);
    }
}
