//! Log-export sinks (Story 9.8): ship access logs, WAF events and
//! audit entries to an operator-run syslog collector (RFC 5424) and,
//! when the binary is built with `--features otel`, to an OTLP logs
//! endpoint.
//!
//! Execution model (Story 9.8 AC #5): each sink consumer is a **plain
//! OS thread that owns its own current-thread tokio runtime**, fed by
//! a second bounded queue. This keeps the mode-independence argument
//! of `log_writer.rs` (the thread behaves identically in supervisor,
//! worker and single-process modes regardless of which runtime, if
//! any, is current at spawn time) while still giving the sink async
//! sockets for TCP+TLS and the OTLP exporter. Producers use the same
//! bounded / `try_send` / drop-and-count contract as `log_writer.rs`:
//! on a full queue the event is dropped and
//! `lorica_log_sink_dropped_total{sink, kind}` is bumped. The request
//! path is never blocked by a sink.
//!
//! Trace correlation (AC #2) is captured **at publish time** on the
//! hot path (the consumer thread has no ambient span context), and
//! carried on the [`SinkEvent`] envelope.
//!
//! Process topology: access logs and WAF events are produced in the
//! proxy process (worker or single-process), audit entries in the
//! management process (supervisor or single-process). The hub is
//! installed per process by the reload path
//! (`lorica::reload::apply_per_process_reload_state`), so each
//! process ships exactly the kinds it produces.

pub mod syslog;

use std::sync::Arc;
use std::sync::OnceLock;

use lorica_config::models::GlobalSettings;
use serde::Serialize;

use crate::logs::LogEntry;

/// Bounded per-sink queue capacity. Same order of magnitude as
/// `log_writer::QUEUE_CAP`: at ~500 bytes per encoded event the
/// worst-case resident size stays a few MiB per sink.
const SINK_QUEUE_CAP: usize = 8192;

/// Event kinds a sink can receive. Used for per-kind toggles and as
/// the `kind` label on the drop counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkKind {
    /// Access-log row.
    Access,
    /// WAF event.
    Waf,
    /// Audit-trail entry.
    Audit,
}

impl SinkKind {
    /// Stable label value (`access` / `waf` / `audit`) used in
    /// metrics and as the syslog MSGID.
    pub fn as_str(self) -> &'static str {
        match self {
            SinkKind::Access => "access",
            SinkKind::Waf => "waf",
            SinkKind::Audit => "audit",
        }
    }
}

/// Audit entry as exported to sinks. A projection of
/// [`crate::audit::NewAuditEntry`] plus the committed chain hash;
/// payload hashes are omitted (they are internal chain material, not
/// operator-facing event data).
#[derive(Debug, Clone, Serialize)]
pub struct AuditSinkRecord {
    /// RFC 3339 event timestamp.
    pub timestamp: String,
    /// Operator username.
    pub operator_username: String,
    /// Operator role at the time of the action.
    pub operator_role: String,
    /// Dotted action name (e.g. `settings.update`).
    pub action: String,
    /// Target entity type.
    pub target_type: String,
    /// Target entity id (may be empty).
    pub target_id: String,
    /// Source IP of the management request.
    pub ip: String,
    /// Committed audit chain hash; empty when persistence failed or
    /// no store is attached (the sink copy is best-effort either way).
    pub chain_hash: String,
}

/// One event payload as exported to sinks.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SinkPayload {
    /// Access-log row.
    Access(LogEntry),
    /// WAF event.
    Waf(lorica_waf::WafEvent),
    /// Audit entry.
    Audit(AuditSinkRecord),
}

/// Envelope delivered to sink consumers: the payload plus the trace
/// context captured at publish time on the hot path (AC #2) and the
/// node identity (AC #3; empty on a standalone install until Story
/// 9.6 wires cluster identity).
#[derive(Debug, Clone)]
pub struct SinkEvent {
    /// Event payload.
    pub payload: SinkPayload,
    /// 32-hex-char W3C trace id of the request, when one was active.
    pub trace_id: Option<String>,
    /// 16-hex-char span id of the request, when one was active.
    pub span_id: Option<String>,
}

impl SinkEvent {
    /// Kind of the wrapped payload.
    pub fn kind(&self) -> SinkKind {
        match self.payload {
            SinkPayload::Access(_) => SinkKind::Access,
            SinkPayload::Waf(_) => SinkKind::Waf,
            SinkPayload::Audit(_) => SinkKind::Audit,
        }
    }
}

/// Syslog transport selector (Story 9.8 AC #1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyslogTransport {
    /// RFC 5426: one message per UDP datagram.
    Udp,
    /// RFC 6587 octet-counting framing over plain TCP.
    Tcp,
    /// RFC 5425: octet-counting framing over TLS.
    TcpTls,
}

impl SyslogTransport {
    /// Parse the stored-config string. Returns `None` for anything
    /// but `udp` / `tcp` / `tcp-tls` (API validation rejects other
    /// values at write time; a foreign value here means a hand-edited
    /// DB row and disables the sink rather than guessing).
    pub fn from_settings(value: &str) -> Option<Self> {
        match value {
            "udp" => Some(SyslogTransport::Udp),
            "tcp" => Some(SyslogTransport::Tcp),
            "tcp-tls" => Some(SyslogTransport::TcpTls),
            _ => None,
        }
    }
}

/// Resolved syslog sink configuration, derived from
/// [`GlobalSettings`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogSinkConfig {
    /// Collector `host:port`.
    pub endpoint: String,
    /// Transport.
    pub transport: SyslogTransport,
    /// RFC 5424 facility (0-23).
    pub facility: u8,
    /// Severity for access-log messages (0-7).
    pub severity_access: u8,
    /// Severity for WAF-event messages (0-7).
    pub severity_waf: u8,
    /// Severity for audit messages (0-7).
    pub severity_audit: u8,
    /// Ship access logs.
    pub access_enabled: bool,
    /// Ship WAF events.
    pub waf_enabled: bool,
    /// Ship audit entries.
    pub audit_enabled: bool,
    /// PEM CA bundle for `tcp-tls`; `None` = platform trust store.
    pub tls_ca_pem: Option<String>,
    /// PEM client certificate chain for collector mTLS.
    pub tls_client_cert_pem: Option<String>,
    /// PEM client key paired with `tls_client_cert_pem`.
    pub tls_client_key_pem: Option<String>,
    /// Static structured-data parameters appended to every message.
    pub extra_sd: Vec<(String, String)>,
}

/// Per-process log-sink configuration snapshot. `PartialEq` so the
/// reload path can dedup re-installs exactly like the OTel snapshot.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LogSinksConfig {
    /// Syslog sink; `None` = disabled.
    pub syslog: Option<SyslogSinkConfig>,
    /// Whether the OTLP logs lane should be created. The caller is
    /// responsible for only setting this when the `otel` feature is
    /// compiled in and an OTLP endpoint is configured, and for
    /// draining the receiver returned by [`install`].
    pub otlp: bool,
    /// Stable node id (empty on standalone installs; Story 9.6).
    pub node_id: String,
    /// Display node name (empty on standalone installs; Story 9.6).
    pub node_name: String,
}

impl LogSinksConfig {
    /// Derive the sink configuration from persisted settings.
    ///
    /// `otlp_available` states whether the running binary can drain
    /// an OTLP logs lane (`cfg!(feature = "otel")` at the caller);
    /// the lane is only requested when it is true AND
    /// `otlp_logs_enabled` AND an `otlp_endpoint` is set.
    pub fn from_settings(settings: &GlobalSettings, otlp_available: bool) -> Self {
        let syslog = settings
            .syslog_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .and_then(|endpoint| {
                let transport = SyslogTransport::from_settings(&settings.syslog_transport)?;
                Some(SyslogSinkConfig {
                    endpoint: endpoint.to_string(),
                    transport,
                    // u32 in the KV projection for parse convenience;
                    // API validation enforces the RFC ranges, clamp is
                    // the hand-edited-DB-row guard.
                    facility: settings.syslog_facility.min(23) as u8,
                    severity_access: settings.syslog_severity_access.min(7) as u8,
                    severity_waf: settings.syslog_severity_waf.min(7) as u8,
                    severity_audit: settings.syslog_severity_audit.min(7) as u8,
                    access_enabled: settings.syslog_access_enabled,
                    waf_enabled: settings.syslog_waf_enabled,
                    audit_enabled: settings.syslog_audit_enabled,
                    tls_ca_pem: settings.syslog_tls_ca_pem.clone(),
                    tls_client_cert_pem: settings.syslog_tls_client_cert_pem.clone(),
                    tls_client_key_pem: settings.syslog_tls_client_key_pem.clone(),
                    extra_sd: parse_extra_sd(settings.syslog_extra_sd.as_deref()),
                })
            });
        let otlp = otlp_available
            && settings.otlp_logs_enabled
            && settings
                .otlp_endpoint
                .as_deref()
                .is_some_and(|e| !e.trim().is_empty());
        LogSinksConfig {
            syslog,
            otlp,
            node_id: String::new(),
            node_name: String::new(),
        }
    }

    /// True when no sink is configured (installing this config just
    /// tears the previous hub down).
    pub fn is_empty(&self) -> bool {
        self.syslog.is_none() && !self.otlp
    }
}

/// Parse the `key=value,key2=value2` extra structured-data setting.
/// Pairs without `=` or with an empty key are skipped (API validation
/// rejects them at write time).
fn parse_extra_sd(raw: Option<&str>) -> Vec<(String, String)> {
    raw.unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            let k = k.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.trim().to_string()))
        })
        .collect()
}

/// One sink lane: the producer side of a bounded queue plus the kind
/// filter for that sink.
struct SinkLane {
    tx: tokio::sync::mpsc::Sender<SinkEvent>,
    access: bool,
    waf: bool,
    audit: bool,
    label: &'static str,
}

impl SinkLane {
    fn wants(&self, kind: SinkKind) -> bool {
        match kind {
            SinkKind::Access => self.access,
            SinkKind::Waf => self.waf,
            SinkKind::Audit => self.audit,
        }
    }

    fn offer(&self, event: &SinkEvent) {
        let kind = event.kind();
        if !self.wants(kind) {
            return;
        }
        if self.tx.try_send(event.clone()).is_err() {
            crate::metrics::inc_log_sink_dropped(self.label, kind.as_str());
        }
    }
}

/// Installed hub state for this process.
#[derive(Default)]
struct HubState {
    syslog: Option<SinkLane>,
    otlp: Option<SinkLane>,
}

impl HubState {
    fn wants(&self, kind: SinkKind) -> bool {
        self.syslog.as_ref().is_some_and(|l| l.wants(kind))
            || self.otlp.as_ref().is_some_and(|l| l.wants(kind))
    }
}

static HUB: OnceLock<parking_lot::RwLock<Arc<HubState>>> = OnceLock::new();

fn hub_slot() -> &'static parking_lot::RwLock<Arc<HubState>> {
    HUB.get_or_init(|| parking_lot::RwLock::new(Arc::new(HubState::default())))
}

/// Install (or replace) this process's sink hub from a configuration
/// snapshot. Spawns the syslog consumer thread when a syslog sink is
/// configured; when `config.otlp` is set, creates the OTLP lane and
/// returns its receiver, which the caller must hand to the OTLP logs
/// consumer (`lorica::otel`). Replacing the hub drops the previous
/// lanes' senders; each old consumer drains its queue and exits.
pub fn install(config: &LogSinksConfig) -> Option<tokio::sync::mpsc::Receiver<SinkEvent>> {
    let mut state = HubState::default();
    if let Some(syslog_cfg) = &config.syslog {
        let (tx, rx) = tokio::sync::mpsc::channel::<SinkEvent>(SINK_QUEUE_CAP);
        state.syslog = Some(SinkLane {
            tx,
            access: syslog_cfg.access_enabled,
            waf: syslog_cfg.waf_enabled,
            audit: syslog_cfg.audit_enabled,
            label: "syslog",
        });
        syslog::spawn_syslog_sink(
            rx,
            syslog_cfg.clone(),
            config.node_id.clone(),
            config.node_name.clone(),
        );
    }
    let mut otlp_rx = None;
    if config.otlp {
        let (tx, rx) = tokio::sync::mpsc::channel::<SinkEvent>(SINK_QUEUE_CAP);
        state.otlp = Some(SinkLane {
            tx,
            access: true,
            waf: true,
            audit: true,
            label: "otlp",
        });
        otlp_rx = Some(rx);
    }
    *hub_slot().write() = Arc::new(state);
    otlp_rx
}

/// Cheap hot-path guard: is any sink interested in `kind` right now?
/// Lets callers skip building the event when nothing is installed.
pub fn wants(kind: SinkKind) -> bool {
    match HUB.get() {
        Some(slot) => slot.read().wants(kind),
        None => false,
    }
}

/// Publish one event to every interested sink. Never blocks: full
/// queues drop the event and bump
/// `lorica_log_sink_dropped_total{sink, kind}`.
pub fn publish(event: SinkEvent) {
    let Some(slot) = HUB.get() else {
        return;
    };
    let state = slot.read().clone();
    if let Some(lane) = &state.syslog {
        lane.offer(&event);
    }
    if let Some(lane) = &state.otlp {
        lane.offer(&event);
    }
}

/// Publish an access-log entry with its request trace context.
pub fn publish_access(entry: &LogEntry, trace_id: Option<&str>, span_id: Option<&str>) {
    if !wants(SinkKind::Access) {
        return;
    }
    publish(SinkEvent {
        payload: SinkPayload::Access(entry.clone()),
        trace_id: trace_id.map(str::to_string),
        span_id: span_id.map(str::to_string),
    });
}

/// Publish a WAF event with its request trace context.
pub fn publish_waf(
    event: &lorica_waf::WafEvent,
    trace_id: Option<&str>,
    span_id: Option<&str>,
) {
    if !wants(SinkKind::Waf) {
        return;
    }
    publish(SinkEvent {
        payload: SinkPayload::Waf(event.clone()),
        trace_id: trace_id.map(str::to_string),
        span_id: span_id.map(str::to_string),
    });
}

/// Publish an audit entry. Management actions carry no request span,
/// so there is no trace context on this path.
pub fn publish_audit(record: AuditSinkRecord) {
    if !wants(SinkKind::Audit) {
        return;
    }
    publish(SinkEvent {
        payload: SinkPayload::Audit(record),
        trace_id: None,
        span_id: None,
    });
}

/// Serialises tests that install the process-global hub (this module
/// and `syslog::tests`), so parallel test threads cannot replace each
/// other's hub between install and publish.
#[cfg(test)]
pub(crate) fn test_hub_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_settings() -> GlobalSettings {
        GlobalSettings::default()
    }

    #[test]
    fn from_settings_disabled_by_default() {
        let cfg = LogSinksConfig::from_settings(&base_settings(), true);
        assert!(cfg.is_empty());
    }

    #[test]
    fn from_settings_builds_syslog_config() {
        let mut s = base_settings();
        s.syslog_endpoint = Some("collector.example.com:6514".into());
        s.syslog_transport = "tcp-tls".into();
        s.syslog_facility = 17;
        s.syslog_severity_waf = 2;
        s.syslog_audit_enabled = false;
        s.syslog_extra_sd = Some("env=prod, dc=eu-west".into());
        let cfg = LogSinksConfig::from_settings(&s, false);
        let syslog = cfg.syslog.expect("syslog sink configured");
        assert_eq!(syslog.endpoint, "collector.example.com:6514");
        assert_eq!(syslog.transport, SyslogTransport::TcpTls);
        assert_eq!(syslog.facility, 17);
        assert_eq!(syslog.severity_waf, 2);
        assert!(syslog.access_enabled);
        assert!(!syslog.audit_enabled);
        assert_eq!(
            syslog.extra_sd,
            vec![
                ("env".to_string(), "prod".to_string()),
                ("dc".to_string(), "eu-west".to_string()),
            ]
        );
        assert!(!cfg.otlp);
    }

    #[test]
    fn from_settings_unknown_transport_disables_sink() {
        let mut s = base_settings();
        s.syslog_endpoint = Some("host01:514".into());
        s.syslog_transport = "carrier-pigeon".into();
        let cfg = LogSinksConfig::from_settings(&s, false);
        assert!(cfg.syslog.is_none());
    }

    #[test]
    fn from_settings_clamps_out_of_range_values() {
        let mut s = base_settings();
        s.syslog_endpoint = Some("host01:514".into());
        s.syslog_facility = 99;
        s.syslog_severity_access = 42;
        let cfg = LogSinksConfig::from_settings(&s, false);
        let syslog = cfg.syslog.expect("syslog sink configured");
        assert_eq!(syslog.facility, 23);
        assert_eq!(syslog.severity_access, 7);
    }

    #[test]
    fn otlp_lane_requires_feature_flag_and_endpoint() {
        let mut s = base_settings();
        s.otlp_logs_enabled = true;
        // No endpoint: no lane even when the feature is available.
        assert!(!LogSinksConfig::from_settings(&s, true).otlp);
        s.otlp_endpoint = Some("http://collector:4318".into());
        assert!(LogSinksConfig::from_settings(&s, true).otlp);
        // Feature not compiled in: no lane.
        assert!(!LogSinksConfig::from_settings(&s, false).otlp);
    }

    #[test]
    fn parse_extra_sd_skips_malformed_pairs() {
        assert_eq!(
            parse_extra_sd(Some("a=1,broken,=nokey,b = 2 ")),
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string()),
            ]
        );
        assert!(parse_extra_sd(None).is_empty());
    }

    #[tokio::test]
    async fn publish_without_install_is_a_noop() {
        // Must not panic or block when no hub was ever installed.
        publish_audit(AuditSinkRecord {
            timestamp: "2026-06-10T00:00:00Z".into(),
            operator_username: "admin".into(),
            operator_role: "SuperAdmin".into(),
            action: "settings.update".into(),
            target_type: "settings".into(),
            target_id: String::new(),
            ip: "192.0.2.10".into(),
            chain_hash: String::new(),
        });
    }

    #[tokio::test]
    async fn otlp_lane_receives_published_events() {
        let _guard = test_hub_lock().lock().expect("hub test lock");
        let cfg = LogSinksConfig {
            syslog: None,
            otlp: true,
            node_id: String::new(),
            node_name: String::new(),
        };
        let mut rx = install(&cfg).expect("otlp lane requested");
        publish_audit(AuditSinkRecord {
            timestamp: "2026-06-10T00:00:00Z".into(),
            operator_username: "admin".into(),
            operator_role: "SuperAdmin".into(),
            action: "route.create".into(),
            target_type: "route".into(),
            target_id: "r1".into(),
            ip: "192.0.2.10".into(),
            chain_hash: "abc".into(),
        });
        let event = rx.recv().await.expect("event delivered");
        assert_eq!(event.kind(), SinkKind::Audit);
        // Tear the hub down so other tests see a clean slate.
        install(&LogSinksConfig::default());
    }
}
