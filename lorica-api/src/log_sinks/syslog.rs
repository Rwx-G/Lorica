//! RFC 5424 syslog sink (Story 9.8 AC #1), implemented in-tree over
//! the already-present `tokio` / `tokio-rustls` stack. No syslog
//! crate: the obvious one is unmaintained since 2022 and
//! Unix-socket-oriented, and RFC 5424 is a header line plus
//! structured data.
//!
//! Wire formats:
//! - UDP (RFC 5426): one message per datagram.
//! - TCP (RFC 6587) and TLS (RFC 5425): octet-counting framing
//!   (`MSG-LEN SP MSG`); non-transparent LF framing is deliberately
//!   not offered because the JSON body may contain newlines once
//!   collectors re-encode it.
//!
//! Delivery is fire-and-forget: a connect failure or a dead collector
//! drops the message, bumps the drop counter, and backs off
//! exponentially (1 s doubling to 30 s cap). The request path is
//! never affected.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

use super::{SinkEvent, SinkKind, SyslogSinkConfig, SyslogTransport};

/// Timeout applied to connect + TLS handshake and to each write.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Initial reconnect backoff after a failed connect or a broken
/// stream.
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Reconnect backoff cap.
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Private-enterprise number used in the structured-data SD-ID
/// (`lorica@32473`). 32473 is the IANA-reserved example enterprise
/// number (RFC 5612); collectors treat the SD-ID as an opaque key, so
/// a documentation-reserved number avoids squatting a real vendor id.
const SD_ID: &str = "lorica@32473";

/// Split a `host:port` endpoint, accepting `[v6]:port` bracket
/// notation. Returns `None` when the port is missing or not a u16.
pub fn split_host_port(endpoint: &str) -> Option<(String, u16)> {
    let (host, port) = endpoint.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Spawn the syslog consumer: a plain OS thread owning a
/// current-thread tokio runtime (Story 9.8 AC #5). The thread exits
/// when the producer side of `rx` is dropped (hub replaced or process
/// teardown) and the queue is drained.
pub(super) fn spawn_syslog_sink(
    rx: Receiver<SinkEvent>,
    config: SyslogSinkConfig,
    node_id: String,
    node_name: String,
) {
    let spawned = std::thread::Builder::new()
        .name("lorica-syslog-sink".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Ok(rt) => rt.block_on(consumer_loop(rx, config, node_id, node_name)),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to build syslog sink runtime; sink disabled");
                }
            }
        });
    if let Err(e) = spawned {
        // Same policy as spawn_log_writer: thread creation only fails
        // on resource exhaustion; every enqueue then counts as a drop
        // once the queue fills.
        tracing::warn!(error = %e, "failed to spawn syslog sink thread; sink disabled");
    }
}

/// One established transport connection.
enum Conn {
    Udp(UdpSocket),
    Tcp(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

async fn consumer_loop(
    mut rx: Receiver<SinkEvent>,
    config: SyslogSinkConfig,
    node_id: String,
    node_name: String,
) {
    let hostname = if node_name.trim().is_empty() {
        machine_hostname()
    } else {
        sanitize_header_field(&node_name)
    };
    let tls = match build_tls_connector(&config) {
        Ok(tls) => tls,
        Err(e) => {
            tracing::warn!(error = %e, "invalid syslog TLS configuration; sink disabled");
            return;
        }
    };
    let mut conn: Option<Conn> = None;
    let mut backoff = BACKOFF_INITIAL;
    let mut next_attempt = Instant::now();

    while let Some(event) = rx.recv().await {
        let kind = event.kind();
        let message = encode_rfc5424(&event, &config, &hostname, &node_id, &node_name);

        if conn.is_none() {
            if Instant::now() < next_attempt {
                crate::metrics::inc_log_sink_dropped("syslog", kind.as_str());
                continue;
            }
            match connect(&config, tls.as_ref()).await {
                Ok(c) => {
                    conn = Some(c);
                    backoff = BACKOFF_INITIAL;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        endpoint = %config.endpoint,
                        "syslog collector unreachable; backing off"
                    );
                    next_attempt = Instant::now() + backoff;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    crate::metrics::inc_log_sink_dropped("syslog", kind.as_str());
                    continue;
                }
            }
        }

        let send_failed = match conn.as_mut() {
            Some(c) => send_message(c, &message).await.is_err(),
            None => true,
        };
        if send_failed {
            crate::metrics::inc_log_sink_dropped("syslog", kind.as_str());
            // A UDP socket survives transient send errors (ICMP port
            // unreachable); a broken stream must reconnect.
            if config.transport != SyslogTransport::Udp {
                conn = None;
                next_attempt = Instant::now() + backoff;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Connect to the collector over the configured transport.
async fn connect(config: &SyslogSinkConfig, tls: Option<&TlsConnector>) -> Result<Conn, String> {
    let (host, port) = split_host_port(&config.endpoint)
        .ok_or_else(|| format!("invalid syslog endpoint {:?}", config.endpoint))?;
    match config.transport {
        SyslogTransport::Udp => {
            // Bind family follows the resolved peer address.
            let peer = tokio::net::lookup_host((host.as_str(), port))
                .await
                .map_err(|e| format!("resolve failed: {e}"))?
                .next()
                .ok_or_else(|| "resolve returned no address".to_string())?;
            let bind_addr = if peer.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let socket = UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| format!("udp bind failed: {e}"))?;
            socket
                .connect(peer)
                .await
                .map_err(|e| format!("udp connect failed: {e}"))?;
            Ok(Conn::Udp(socket))
        }
        SyslogTransport::Tcp => {
            let stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| "connect timeout".to_string())?
                .map_err(|e| format!("tcp connect failed: {e}"))?;
            Ok(Conn::Tcp(stream))
        }
        SyslogTransport::TcpTls => {
            let tls = tls.ok_or_else(|| "TLS connector unavailable".to_string())?;
            let stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| "connect timeout".to_string())?
                .map_err(|e| format!("tcp connect failed: {e}"))?;
            let server_name = ServerName::try_from(host.clone())
                .map_err(|e| format!("invalid TLS server name {host:?}: {e}"))?;
            let stream = tokio::time::timeout(IO_TIMEOUT, tls.connect(server_name, stream))
                .await
                .map_err(|_| "TLS handshake timeout".to_string())?
                .map_err(|e| format!("TLS handshake failed: {e}"))?;
            Ok(Conn::Tls(Box::new(stream)))
        }
    }
}

/// Send one encoded message over an established connection. Stream
/// transports use RFC 6587 octet-counting framing.
async fn send_message(conn: &mut Conn, message: &str) -> Result<(), String> {
    match conn {
        Conn::Udp(socket) => {
            socket
                .send(message.as_bytes())
                .await
                .map_err(|e| format!("udp send failed: {e}"))?;
        }
        Conn::Tcp(stream) => {
            let framed = octet_frame(message);
            tokio::time::timeout(IO_TIMEOUT, stream.write_all(framed.as_bytes()))
                .await
                .map_err(|_| "write timeout".to_string())?
                .map_err(|e| format!("tcp write failed: {e}"))?;
        }
        Conn::Tls(stream) => {
            let framed = octet_frame(message);
            tokio::time::timeout(IO_TIMEOUT, stream.write_all(framed.as_bytes()))
                .await
                .map_err(|_| "write timeout".to_string())?
                .map_err(|e| format!("tls write failed: {e}"))?;
        }
    }
    Ok(())
}

/// RFC 6587 octet-counting framing: `MSG-LEN SP MSG` with the length
/// in bytes.
fn octet_frame(message: &str) -> String {
    format!("{} {}", message.len(), message)
}

/// Build the TLS connector when the transport needs one. `Ok(None)`
/// for UDP / plain TCP.
fn build_tls_connector(config: &SyslogSinkConfig) -> Result<Option<TlsConnector>, String> {
    if config.transport != SyslogTransport::TcpTls {
        return Ok(None);
    }
    let mut roots = RootCertStore::empty();
    match &config.tls_ca_pem {
        Some(ca_pem) => {
            let mut added = 0usize;
            for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
                let cert = cert.map_err(|e| format!("invalid CA PEM: {e:?}"))?;
                roots
                    .add(cert)
                    .map_err(|e| format!("CA certificate rejected: {e}"))?;
                added += 1;
            }
            if added == 0 {
                return Err("CA PEM contains no certificate".to_string());
            }
        }
        None => {
            lorica_tls::load_platform_certs_incl_env_into_store(&mut roots)
                .map_err(|e| format!("platform trust store unavailable: {e}"))?;
        }
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let client_config = match (&config.tls_client_cert_pem, &config.tls_client_key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .collect::<Result<_, _>>()
                    .map_err(|e| format!("invalid client certificate PEM: {e:?}"))?;
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
                .map_err(|e| format!("invalid client key PEM: {e:?}"))?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("client certificate rejected: {e}"))?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(
                "syslog mTLS needs both the client certificate and the client key".to_string(),
            )
        }
    };
    Ok(Some(TlsConnector::from(Arc::new(client_config))))
}

/// Encode one event as an RFC 5424 message (no framing).
fn encode_rfc5424(
    event: &SinkEvent,
    config: &SyslogSinkConfig,
    hostname: &str,
    node_id: &str,
    node_name: &str,
) -> String {
    let kind = event.kind();
    let severity = match kind {
        SinkKind::Access => config.severity_access,
        SinkKind::Waf => config.severity_waf,
        SinkKind::Audit => config.severity_audit,
    };
    let pri = u32::from(config.facility) * 8 + u32::from(severity);
    let timestamp = event_timestamp(event);
    let procid = std::process::id();
    let msgid = kind.as_str();

    let mut sd = String::with_capacity(128);
    sd.push('[');
    sd.push_str(SD_ID);
    push_sd_param(&mut sd, "kind", kind.as_str());
    if !node_id.is_empty() {
        push_sd_param(&mut sd, "node_id", node_id);
    }
    if !node_name.is_empty() {
        push_sd_param(&mut sd, "node_name", node_name);
    }
    if let Some(trace_id) = &event.trace_id {
        push_sd_param(&mut sd, "trace_id", trace_id);
    }
    if let Some(span_id) = &event.span_id {
        push_sd_param(&mut sd, "span_id", span_id);
    }
    for (key, value) in &config.extra_sd {
        push_sd_param(&mut sd, key, value);
    }
    sd.push(']');

    let body = serde_json::to_string(&event.payload).unwrap_or_else(|_| "{}".to_string());
    format!("<{pri}>1 {timestamp} {hostname} lorica {procid} {msgid} {sd} {body}")
}

/// Push one `key="value"` structured-data parameter, escaping the
/// value per RFC 5424 §6.3.3 and sanitizing the name (printable
/// US-ASCII without `= ] "` or spaces).
fn push_sd_param(sd: &mut String, name: &str, value: &str) {
    sd.push(' ');
    for c in name.chars() {
        if c.is_ascii_graphic() && c != '=' && c != ']' && c != '"' {
            sd.push(c);
        }
    }
    sd.push_str("=\"");
    for c in value.chars() {
        match c {
            '\\' => sd.push_str("\\\\"),
            '"' => sd.push_str("\\\""),
            ']' => sd.push_str("\\]"),
            other => sd.push(other),
        }
    }
    sd.push('"');
}

/// Timestamp for the HEADER: the event's own RFC 3339 timestamp when
/// it parses, otherwise now. RFC 5424 TIMESTAMP is RFC 3339 with an
/// upper-case `T` / offset, which `to_rfc3339` produces.
fn event_timestamp(event: &SinkEvent) -> String {
    let raw = match &event.payload {
        super::SinkPayload::Access(entry) => entry.timestamp.as_str(),
        super::SinkPayload::Waf(waf) => waf.timestamp.as_str(),
        super::SinkPayload::Audit(audit) => audit.timestamp.as_str(),
    };
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(ts) => ts.to_rfc3339(),
        Err(_) => chrono::Utc::now().to_rfc3339(),
    }
}

/// RFC 5424 HOSTNAME: the kernel hostname, `HOSTNAME` env fallback,
/// NILVALUE (`-`) when neither is available. Linux-first by design
/// (the runtime target is Linux; dev on Windows runs through Docker).
fn machine_hostname() -> String {
    let from_proc = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let raw = from_proc
        .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
        .unwrap_or_else(|| "-".to_string());
    sanitize_header_field(&raw)
}

/// HEADER fields are printable US-ASCII without spaces, max 255
/// bytes. Anything else is replaced with `_`.
fn sanitize_header_field(raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .take(255)
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    if sanitized.is_empty() {
        "-".to_string()
    } else {
        sanitized
    }
}

/// Send a single synthetic test message over the configured
/// transport, for the `POST /api/v1/settings/syslog/test` endpoint
/// (Story 9.8 AC #6). Returns `Err` with the failure reason. Note
/// that UDP is connectionless: a successful send proves resolution
/// and a writable socket, not collector receipt.
pub async fn send_test_message(
    config: &SyslogSinkConfig,
    node_id: &str,
    node_name: &str,
) -> Result<(), String> {
    let tls = build_tls_connector(config)?;
    let mut conn = connect(config, tls.as_ref()).await?;
    let event = SinkEvent {
        payload: super::SinkPayload::Audit(super::AuditSinkRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            operator_username: "test".to_string(),
            operator_role: "-".to_string(),
            action: "log_sink.test".to_string(),
            target_type: "syslog".to_string(),
            target_id: String::new(),
            ip: String::new(),
            chain_hash: String::new(),
        }),
        trace_id: None,
        span_id: None,
    };
    let hostname = if node_name.trim().is_empty() {
        machine_hostname()
    } else {
        sanitize_header_field(node_name)
    };
    let message = encode_rfc5424(&event, config, &hostname, node_id, node_name);
    send_message(&mut conn, &message).await?;
    // Flush stream transports so the frame is on the wire before the
    // round-trip time is reported.
    match &mut conn {
        Conn::Tcp(stream) => stream
            .flush()
            .await
            .map_err(|e| format!("tcp flush failed: {e}"))?,
        Conn::Tls(stream) => stream
            .flush()
            .await
            .map_err(|e| format!("tls flush failed: {e}"))?,
        Conn::Udp(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{AuditSinkRecord, LogSinksConfig, SinkPayload};
    use super::*;

    fn test_config(endpoint: &str, transport: SyslogTransport) -> SyslogSinkConfig {
        SyslogSinkConfig {
            endpoint: endpoint.to_string(),
            transport,
            facility: 16,
            severity_access: 6,
            severity_waf: 4,
            severity_audit: 5,
            access_enabled: true,
            waf_enabled: true,
            audit_enabled: true,
            tls_ca_pem: None,
            tls_client_cert_pem: None,
            tls_client_key_pem: None,
            extra_sd: vec![("env".to_string(), "prod".to_string())],
        }
    }

    fn audit_event() -> SinkEvent {
        SinkEvent {
            payload: SinkPayload::Audit(AuditSinkRecord {
                timestamp: "2026-06-10T00:00:00+00:00".to_string(),
                operator_username: "admin".to_string(),
                operator_role: "SuperAdmin".to_string(),
                action: "route.create".to_string(),
                target_type: "route".to_string(),
                target_id: "r-1".to_string(),
                ip: "192.0.2.10".to_string(),
                chain_hash: "abc".to_string(),
            }),
            trace_id: Some("4bf92f3577b34da6a3ce929d0e0e4736".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
        }
    }

    #[test]
    fn split_host_port_handles_v4_v6_and_names() {
        assert_eq!(
            split_host_port("collector.example.com:514"),
            Some(("collector.example.com".to_string(), 514))
        );
        assert_eq!(
            split_host_port("192.0.2.10:6514"),
            Some(("192.0.2.10".to_string(), 6514))
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:514"),
            Some(("2001:db8::1".to_string(), 514))
        );
        assert_eq!(split_host_port("no-port"), None);
        assert_eq!(split_host_port(":514"), None);
        assert_eq!(split_host_port("host:notaport"), None);
    }

    #[test]
    fn encode_produces_well_formed_header_and_sd() {
        let config = test_config("host01:514", SyslogTransport::Udp);
        let msg = encode_rfc5424(&audit_event(), &config, "edge01", "node-1", "edge01");
        // PRI = 16*8 + 5 (audit severity) = 133, VERSION 1.
        assert!(msg.starts_with("<133>1 2026-06-10T00:00:00+00:00 edge01 lorica "));
        assert!(msg.contains(" audit [lorica@32473 kind=\"audit\""));
        assert!(msg.contains("node_id=\"node-1\""));
        assert!(msg.contains("trace_id=\"4bf92f3577b34da6a3ce929d0e0e4736\""));
        assert!(msg.contains("env=\"prod\""));
        // JSON body carries the event fields.
        assert!(msg.contains("\"action\":\"route.create\""));
    }

    #[test]
    fn encode_escapes_sd_values() {
        let mut config = test_config("host01:514", SyslogTransport::Udp);
        config.extra_sd = vec![("k".to_string(), "a\"b\\c]d".to_string())];
        let msg = encode_rfc5424(&audit_event(), &config, "edge01", "", "");
        assert!(msg.contains(r#"k="a\"b\\c\]d""#));
    }

    #[test]
    fn octet_frame_prefixes_byte_length() {
        assert_eq!(octet_frame("abc"), "3 abc");
        // Multi-byte UTF-8: the length is in bytes, not chars.
        assert_eq!(octet_frame("é"), "2 é");
    }

    #[test]
    fn sanitize_header_field_replaces_non_graphic() {
        assert_eq!(sanitize_header_field("edge 01\n"), "edge_01_");
        assert_eq!(sanitize_header_field(""), "-");
    }

    #[test]
    fn tls_connector_rejects_key_without_cert() {
        let mut config = test_config("host01:6514", SyslogTransport::TcpTls);
        config.tls_client_key_pem = Some("-----BEGIN PRIVATE KEY-----".to_string());
        // expect_err needs Debug on the Ok side, which TlsConnector
        // does not implement; match instead.
        let err = match build_tls_connector(&config) {
            Err(e) => e,
            Ok(_) => panic!("half an mTLS identity must fail"),
        };
        assert!(err.contains("both"));
    }

    #[tokio::test]
    async fn udp_sink_delivers_datagram_end_to_end() {
        let _guard = super::super::test_hub_lock().lock().expect("hub test lock");
        let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let sinks = LogSinksConfig {
            syslog: Some(test_config(&addr.to_string(), SyslogTransport::Udp)),
            otlp: false,
            node_id: "node-1".to_string(),
            node_name: "edge01".to_string(),
        };
        super::super::install(&sinks);
        super::super::publish_audit(AuditSinkRecord {
            timestamp: "2026-06-10T00:00:00+00:00".to_string(),
            operator_username: "admin".to_string(),
            operator_role: "SuperAdmin".to_string(),
            action: "route.create".to_string(),
            target_type: "route".to_string(),
            target_id: "r-1".to_string(),
            ip: "192.0.2.10".to_string(),
            chain_hash: "abc".to_string(),
        });

        let mut buf = vec![0u8; 65536];
        let received = tokio::time::timeout(Duration::from_secs(5), listener.recv(&mut buf))
            .await
            .expect("datagram within 5s")
            .expect("recv succeeds");
        let msg = String::from_utf8_lossy(&buf[..received]);
        assert!(msg.starts_with("<133>1 "), "got: {msg}");
        assert!(msg.contains("node_id=\"node-1\""));
        super::super::install(&LogSinksConfig::default());
    }

    #[tokio::test]
    async fn tcp_sink_delivers_octet_counted_frame() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let config = test_config(&addr.to_string(), SyslogTransport::Tcp);
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut data = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut data)
                .await
                .expect("read frame");
            data
        });

        send_test_message(&config, "node-1", "edge01")
            .await
            .expect("test message sends");
        // send_test_message returns without closing; the connection is
        // dropped when `conn` goes out of scope, ending read_to_end.
        let data = tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .expect("frame within 5s")
            .expect("accept task");
        let text = String::from_utf8_lossy(&data);
        let (len, rest) = text.split_once(' ').expect("octet-count prefix");
        let len: usize = len.parse().expect("numeric length");
        assert_eq!(rest.len(), len, "frame length matches payload");
        // The synthetic test message is audit-shaped: MSGID "audit",
        // action "log_sink.test".
        assert!(rest.contains(" audit ["), "MSGID-adjacent content: {rest}");
        assert!(rest.contains("log_sink.test"));
    }
}
