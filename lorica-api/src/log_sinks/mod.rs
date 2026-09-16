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
//!
//! # Per-kind toggles (backlog #50)
//!
//! Every lane carries one flag per [`SinkKind`], and every flag is a
//! `GlobalSettings` field of its own: `syslog_{access,waf,audit,
//! capture}_enabled` for the syslog lane, `otlp_logs_{access,waf,
//! audit,capture}_enabled` for the OTLP lane. The four kinds are
//! symmetric on both sinks; [`SinkKind::Capture`] (Story 10.2 AC #3)
//! rides the same filter as the three original kinds. The toggles are
//! node-local (a sink is where THIS node ships its logs), which is the
//! decision `lorica_config::canonical` forces per field.

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
    /// Traffic capture record (Story 10.2).
    Capture,
}

impl SinkKind {
    /// Stable label value (`access` / `waf` / `audit` / `capture`)
    /// used in metrics and as the syslog MSGID.
    pub fn as_str(self) -> &'static str {
        match self {
            SinkKind::Access => "access",
            SinkKind::Waf => "waf",
            SinkKind::Audit => "audit",
            SinkKind::Capture => "capture",
        }
    }
}

/// One flag per [`SinkKind`]: which kinds a lane wants. The OTLP
/// lane's filter is carried by this type from settings to
/// [`register_lane`]; the syslog lane keeps its flags inline on
/// [`SyslogSinkConfig`] beside the per-kind severities they pair with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SinkKindToggles {
    /// Ship access-log rows.
    pub access: bool,
    /// Ship WAF events.
    pub waf: bool,
    /// Ship audit entries.
    pub audit: bool,
    /// Ship traffic capture records.
    pub capture: bool,
}

/// A capture record as exported to sinks: the record's JSON document
/// plus the three values the consumers read without parsing it (the
/// syslog HEADER timestamp, the drop counter's `rule_id` label, the
/// join key).
///
/// The document is carried as a [`serde_json::Value`] rather than as
/// the proxy's typed record because the record type lives in the
/// `lorica` binary crate, which depends on this one and not the other
/// way round. `Serialize` writes the document alone, so
/// [`body_json`] flattens the record's own fields at the top level
/// like every other kind.
#[derive(Debug, Clone)]
pub struct CaptureSinkRecord {
    /// The rule that admitted the exchange; the `rule_id` label of
    /// `lorica_captures_total{outcome="dropped_sink"}`.
    pub rule_id: String,
    /// The access-log row's `request_id`.
    pub request_id: String,
    /// RFC 3339 event timestamp, copied from the access-log row.
    pub timestamp: String,
    /// The capture record as one JSON object.
    pub document: serde_json::Value,
}

impl Serialize for CaptureSinkRecord {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.document.serialize(serializer)
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
    /// Traffic capture record.
    Capture(CaptureSinkRecord),
}

/// Envelope delivered to sink consumers: the payload plus the trace
/// context captured at publish time on the hot path (AC #2) and the
/// node identity (AC #3; empty on a standalone install until Story
/// 9.6 wires cluster identity).
#[derive(Debug, Clone)]
pub struct SinkEvent {
    /// Event payload.
    ///
    /// Behind an `Arc` because the hub hands the same event to every
    /// enabled lane and each hand-off is a clone: with syslog and OTLP
    /// both on, an access row used to pay three deep copies of a
    /// struct that is almost entirely owned strings (method, path,
    /// user agent, referer, host). The payload is read-only from the
    /// moment it is published, so sharing it costs a refcount bump and
    /// nothing else. The trace and span ids stay owned: they are
    /// bounded at 32 and 16 hex characters and an `Arc` each would buy
    /// less than it costs (backlog #49).
    pub payload: Arc<SinkPayload>,
    /// 32-hex-char W3C trace id of the request, when one was active.
    pub trace_id: Option<String>,
    /// 16-hex-char span id of the request, when one was active.
    pub span_id: Option<String>,
}

impl SinkEvent {
    /// Kind of the wrapped payload.
    pub fn kind(&self) -> SinkKind {
        match *self.payload {
            SinkPayload::Access(_) => SinkKind::Access,
            SinkPayload::Waf(_) => SinkKind::Waf,
            SinkPayload::Audit(_) => SinkKind::Audit,
            SinkPayload::Capture(_) => SinkKind::Capture,
        }
    }
}

/// Version stamped inside every exported JSON body (`"v"` key), so
/// downstream SIEM parsers can detect a future shape change instead
/// of silently mis-parsing it (QA finding: an unversioned externally
/// consumed surface is a breaking change waiting to happen).
pub const SINK_BODY_VERSION: u32 = 1;

/// Serialize an event's payload as the exported JSON body: the
/// event's own fields plus `"v"` ([`SINK_BODY_VERSION`]) and
/// `"kind"` so a record is self-describing without the transport
/// envelope (syslog MSGID / OTLP attribute). Shared by both sink
/// consumers so the two wire formats cannot drift.
pub fn body_json(event: &SinkEvent) -> String {
    let mut value = serde_json::to_value(&*event.payload).unwrap_or_default();
    if let Some(map) = value.as_object_mut() {
        map.insert("v".to_string(), serde_json::json!(SINK_BODY_VERSION));
        map.insert("kind".to_string(), serde_json::json!(event.kind().as_str()));
    }
    serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string())
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
/// [`GlobalSettings`]. `Debug` is hand-implemented so a stray
/// `debug!(?config)` can never dump the mTLS client key into the
/// journal (QA finding).
#[derive(Clone, PartialEq, Eq)]
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
    /// Ship capture records.
    pub capture_enabled: bool,
    /// PEM CA bundle for `tcp-tls`; `None` = platform trust store.
    pub tls_ca_pem: Option<String>,
    /// PEM client certificate chain for collector mTLS.
    pub tls_client_cert_pem: Option<String>,
    /// PEM client key paired with `tls_client_cert_pem`.
    pub tls_client_key_pem: Option<String>,
    /// Static structured-data parameters appended to every message.
    pub extra_sd: Vec<(String, String)>,
}

impl std::fmt::Debug for SyslogSinkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyslogSinkConfig")
            .field("endpoint", &self.endpoint)
            .field("transport", &self.transport)
            .field("facility", &self.facility)
            .field("severity_access", &self.severity_access)
            .field("severity_waf", &self.severity_waf)
            .field("severity_audit", &self.severity_audit)
            .field("access_enabled", &self.access_enabled)
            .field("waf_enabled", &self.waf_enabled)
            .field("audit_enabled", &self.audit_enabled)
            .field("capture_enabled", &self.capture_enabled)
            .field("tls_ca_pem", &self.tls_ca_pem.as_ref().map(|_| "<pem>"))
            .field(
                "tls_client_cert_pem",
                &self.tls_client_cert_pem.as_ref().map(|_| "<pem>"),
            )
            .field(
                "tls_client_key_pem",
                &self.tls_client_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("extra_sd", &self.extra_sd)
            .finish()
    }
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
    /// Which kinds the OTLP lane ships (backlog #50). Meaningless
    /// while `otlp` is false; carried here so a flip of one toggle
    /// changes the snapshot the reload path compares and re-registers
    /// the lane with the new filter.
    pub otlp_kinds: SinkKindToggles,
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
                    capture_enabled: settings.syslog_capture_enabled,
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
            otlp_kinds: SinkKindToggles {
                access: settings.otlp_logs_access_enabled,
                waf: settings.otlp_logs_waf_enabled,
                audit: settings.otlp_logs_audit_enabled,
                capture: settings.otlp_logs_capture_enabled,
            },
            node_id: String::new(),
            node_name: String::new(),
        }
    }

    /// True when no sink is configured (installing this config just
    /// tears the previous hub down).
    pub fn is_empty(&self) -> bool {
        self.syslog.is_none() && !self.otlp
    }

    /// Stamp the cluster node identity onto this configuration.
    /// Story 9.6 wires the real values; standalone installs keep the
    /// empty defaults. Kept as a builder-style seam so 9.6 is a
    /// one-line call-site change instead of a signature change.
    pub fn with_node_identity(mut self, node_id: &str, node_name: &str) -> Self {
        self.node_id = node_id.to_string();
        self.node_name = node_name.to_string();
        self
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

/// What happened to an event offered to a lane, from the hub's point
/// of view. `Dropped` is a full queue: a drop, but the consumer is
/// alive and will catch up. `Gone` means the receiver is closed and
/// the lane should be torn out. A lane that does not want the kind
/// reports `Delivered`: nothing was lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LaneOutcome {
    Delivered,
    Dropped,
    Gone,
}

/// One sink lane: the producer side of a bounded queue plus the kind
/// filter for that sink. `id` is a process-monotonic lane id so a
/// consumer that dies can tear out exactly its own lane and never a
/// replacement installed concurrently (QA finding: a live lane with
/// a dead consumer counted every event as a drop forever).
#[derive(Clone)]
struct SinkLane {
    id: u64,
    tx: tokio::sync::mpsc::Sender<SinkEvent>,
    access: bool,
    waf: bool,
    audit: bool,
    capture: bool,
    label: &'static str,
}

impl SinkLane {
    fn wants(&self, kind: SinkKind) -> bool {
        match kind {
            SinkKind::Access => self.access,
            SinkKind::Waf => self.waf,
            SinkKind::Audit => self.audit,
            SinkKind::Capture => self.capture,
        }
    }

    fn offer(&self, event: &SinkEvent) -> LaneOutcome {
        let kind = event.kind();
        if !self.wants(kind) {
            return LaneOutcome::Delivered;
        }
        match self.tx.try_send(event.clone()) {
            Ok(()) => LaneOutcome::Delivered,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                crate::metrics::inc_log_sink_dropped(self.label, kind.as_str());
                LaneOutcome::Dropped
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                crate::metrics::inc_log_sink_dropped(self.label, kind.as_str());
                LaneOutcome::Gone
            }
        }
    }
}

/// Installed hub state for this process.
///
/// A list rather than one field per sink: a lane's identity is its
/// `id`, removal already worked by id, and the two named fields meant
/// every new consumer had to be threaded through `wants`, `offer_all`,
/// `install` and a removal function of its own. Story 10.2 adds a
/// capture lane; it costs one `register_lane` call.
#[derive(Default, Clone)]
struct HubState {
    lanes: Vec<SinkLane>,
}

impl HubState {
    fn wants(&self, kind: SinkKind) -> bool {
        self.lanes.iter().any(|l| l.wants(kind))
    }

    /// Offer `event` to every lane. Returns how many lanes wanted it
    /// and lost it (full or gone), so a publisher whose kind has its
    /// own drop counter can bump it once per lost copy.
    fn offer_all(&self, event: &SinkEvent) -> usize {
        let mut lost = 0;
        for lane in &self.lanes {
            match lane.offer(event) {
                LaneOutcome::Delivered => {}
                LaneOutcome::Dropped => lost += 1,
                LaneOutcome::Gone => {
                    lost += 1;
                    // The consumer dropped its receiver without saying
                    // so. Tear the lane out rather than counting every
                    // future event as a drop for the life of the
                    // process.
                    remove_lane(lane.id);
                }
            }
        }
        lost
    }
}

static HUB: OnceLock<parking_lot::RwLock<Arc<HubState>>> = OnceLock::new();

static LANE_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn hub_slot() -> &'static parking_lot::RwLock<Arc<HubState>> {
    HUB.get_or_init(|| parking_lot::RwLock::new(Arc::new(HubState::default())))
}

/// Latest syslog consumer thread handle, kept so
/// [`shutdown_and_drain`] can join it on process teardown. Handles of
/// lanes replaced by a reinstall are detached (their threads exit on
/// their own once their senders drop).
fn syslog_thread_slot() -> &'static parking_lot::Mutex<Option<std::thread::JoinHandle<()>>> {
    static SLOT: OnceLock<parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>> =
        OnceLock::new();
    SLOT.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Install (or replace) this process's sink hub from a configuration
/// snapshot.
///
/// Installs only the lanes whose consumer this function starts itself:
/// the syslog thread is spawned FIRST and its lane installed only on a
/// successful spawn. A consumer that lives elsewhere registers its own
/// lane with [`register_lane`] once it is running, which is the point
/// of that split.
///
/// Replacing the hub drops the previous lanes' senders; each old
/// consumer drains its remaining queue and exits. A consumer owned
/// elsewhere must therefore re-register after a reinstall, which is
/// what the settings-reload path does.
pub fn install(config: &LogSinksConfig) {
    use std::sync::atomic::Ordering;

    let mut state = HubState::default();
    if let Some(syslog_cfg) = &config.syslog {
        let (tx, rx) = tokio::sync::mpsc::channel::<SinkEvent>(SINK_QUEUE_CAP);
        let id = LANE_ID.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(handle) = syslog::spawn_syslog_sink(
            id,
            rx,
            syslog_cfg.clone(),
            config.node_id.clone(),
            config.node_name.clone(),
        ) {
            state.lanes.push(SinkLane {
                id,
                tx,
                access: syslog_cfg.access_enabled,
                waf: syslog_cfg.waf_enabled,
                audit: syslog_cfg.audit_enabled,
                capture: syslog_cfg.capture_enabled,
                label: "syslog",
            });
            *syslog_thread_slot().lock() = Some(handle);
        }
    }
    *hub_slot().write() = Arc::new(state);
}

/// Add a lane for a consumer this module does not own, and hand back
/// the receiving end.
///
/// The caller is the consumer: it calls this **after** it is able to
/// consume, and the returned `Receiver` is the proof. The previous
/// arrangement had `install` create the OTLP lane and return its
/// receiver for someone else to wire up, so a failed `init_logs` left
/// a lane with no consumer behind it, publishing into a queue nobody
/// read. The settings-reload path logged exactly that and carried on
/// (backlog #51).
///
/// A lane whose receiver is later dropped is torn out on the next
/// event rather than accumulating drops forever, so the invariant
/// survives a consumer that dies as well as one that never started.
pub fn register_lane(
    label: &'static str,
    access: bool,
    waf: bool,
    audit: bool,
    capture: bool,
) -> tokio::sync::mpsc::Receiver<SinkEvent> {
    use std::sync::atomic::Ordering;

    let (tx, rx) = tokio::sync::mpsc::channel::<SinkEvent>(SINK_QUEUE_CAP);
    let id = LANE_ID.fetch_add(1, Ordering::Relaxed) + 1;
    let slot = hub_slot();
    let mut guard = slot.write();
    let mut next = (**guard).clone();
    next.lanes.retain(|l| l.label != label);
    next.lanes.push(SinkLane {
        id,
        tx,
        access,
        waf,
        audit,
        capture,
        label,
    });
    *guard = Arc::new(next);
    rx
}

/// Tear the lane with `id` out of the hub. Called by a consumer on a
/// terminal failure (invalid TLS material, runtime build failure) and
/// by the hub itself when a lane's receiver turns out to be closed, so
/// the hub never keeps offering events to a lane whose consumer is
/// gone. Matching on the id makes a racing reinstall win: a lane
/// replaced in the meantime has a different id and survives.
pub(super) fn remove_lane(id: u64) {
    let slot = hub_slot();
    let mut guard = slot.write();
    if guard.lanes.iter().any(|l| l.id == id) {
        let mut next = (**guard).clone();
        next.lanes.retain(|l| l.id != id);
        *guard = Arc::new(next);
    }
}

/// Tear the hub down and give the syslog consumer a bounded window to
/// drain its remaining queue (QA finding: without this, a restart or
/// hot binary upgrade silently discarded up to a queue's worth of
/// exported audit/access events). Called from `lorica::otel::shutdown`
/// on every process exit path, before the OTLP logs provider flush.
pub fn shutdown_and_drain(timeout: std::time::Duration) {
    if let Some(slot) = HUB.get() {
        *slot.write() = Arc::new(HubState::default());
    }
    let handle = syslog_thread_slot().lock().take();
    if let Some(handle) = handle {
        let deadline = std::time::Instant::now() + timeout;
        while !handle.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
        // Not finished within budget (e.g. mid-write against a stalled
        // collector): detach. The process is exiting anyway and the
        // remaining events were already accounted as best-effort.
    }
}

/// Cheap hot-path guard: is any sink interested in `kind` right now?
/// Lets callers skip building the event when nothing is installed.
pub fn wants(kind: SinkKind) -> bool {
    match HUB.get() {
        Some(slot) => slot.read().wants(kind),
        None => false,
    }
}

/// Single-read variant of [`wants`]: returns the hub state when it
/// wants `kind`, so the caller pays one lock acquisition, not two
/// (QA finding).
fn state_if_wants(kind: SinkKind) -> Option<Arc<HubState>> {
    let state = HUB.get()?.read().clone();
    if state.wants(kind) {
        Some(state)
    } else {
        None
    }
}

/// Publish an access-log entry with its request trace context. Never
/// blocks: full queues drop the event and bump
/// `lorica_log_sink_dropped_total{sink, kind}`.
pub fn publish_access(entry: &LogEntry, trace_id: Option<&str>, span_id: Option<&str>) {
    let Some(state) = state_if_wants(SinkKind::Access) else {
        return;
    };
    state.offer_all(&SinkEvent {
        payload: Arc::new(SinkPayload::Access(entry.clone())),
        trace_id: trace_id.map(str::to_string),
        span_id: span_id.map(str::to_string),
    });
}

/// Publish a WAF event with its request trace context. Same
/// non-blocking contract as [`publish_access`].
pub fn publish_waf(event: &lorica_waf::WafEvent, trace_id: Option<&str>, span_id: Option<&str>) {
    let Some(state) = state_if_wants(SinkKind::Waf) else {
        return;
    };
    state.offer_all(&SinkEvent {
        payload: Arc::new(SinkPayload::Waf(event.clone())),
        trace_id: trace_id.map(str::to_string),
        span_id: span_id.map(str::to_string),
    });
}

/// Publish an audit entry. Management actions carry no request span,
/// so there is no trace context on this path. Same non-blocking
/// contract as [`publish_access`].
pub fn publish_audit(record: AuditSinkRecord) {
    let Some(state) = state_if_wants(SinkKind::Audit) else {
        return;
    };
    state.offer_all(&SinkEvent {
        payload: Arc::new(SinkPayload::Audit(record)),
        trace_id: None,
        span_id: None,
    });
}

/// Publish a capture record with its request trace context (Story
/// 10.2 AC #3). Same non-blocking contract as [`publish_access`].
///
/// Returns how many lanes wanted the record and lost it, so the
/// caller can count each lost copy as
/// `lorica_captures_total{outcome="dropped_sink"}` (AC #4): the
/// per-sink drop counter is bumped here, but the per-rule one carries
/// a label only the capture path knows.
pub fn publish_capture(
    record: CaptureSinkRecord,
    trace_id: Option<&str>,
    span_id: Option<&str>,
) -> usize {
    let Some(state) = state_if_wants(SinkKind::Capture) else {
        return 0;
    };
    state.offer_all(&SinkEvent {
        payload: Arc::new(SinkPayload::Capture(record)),
        trace_id: trace_id.map(str::to_string),
        span_id: span_id.map(str::to_string),
    })
}

/// Serialises tests that install the process-global hub (this module
/// and `syslog::tests`), so parallel test threads cannot replace each
/// other's hub between install and publish.
#[cfg(test)]
pub(crate) fn test_hub_lock() -> &'static tokio::sync::Mutex<()> {
    // An async mutex: the guard is held across the awaits of the
    // tests that install a hub, and a `std` guard there is exactly
    // the `await_holding_lock` clippy refuses (backlog #65).
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
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
        assert!(syslog.capture_enabled);
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
    fn body_json_carries_version_and_kind() {
        let event = SinkEvent {
            payload: Arc::new(SinkPayload::Audit(AuditSinkRecord {
                timestamp: "2026-06-10T00:00:00Z".into(),
                operator_username: "admin".into(),
                operator_role: "SuperAdmin".into(),
                action: "route.create".into(),
                target_type: "route".into(),
                target_id: "r1".into(),
                ip: "192.0.2.10".into(),
                chain_hash: "abc".into(),
            })),
            trace_id: None,
            span_id: None,
        };
        let value: serde_json::Value =
            serde_json::from_str(&body_json(&event)).expect("body is valid JSON");
        assert_eq!(value["v"], SINK_BODY_VERSION);
        assert_eq!(value["kind"], "audit");
        // Event fields stay flattened at the top level.
        assert_eq!(value["action"], "route.create");
    }

    #[test]
    fn debug_never_prints_the_client_key() {
        let cfg = SyslogSinkConfig {
            endpoint: "host01:6514".into(),
            transport: SyslogTransport::TcpTls,
            facility: 16,
            severity_access: 6,
            severity_waf: 4,
            severity_audit: 5,
            access_enabled: true,
            waf_enabled: true,
            audit_enabled: true,
            capture_enabled: true,
            tls_ca_pem: None,
            tls_client_cert_pem: None,
            tls_client_key_pem: Some("-----BEGIN PRIVATE KEY-----\ntopsecret".into()),
            extra_sd: Vec::new(),
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("topsecret"));
        assert!(rendered.contains("<redacted>"));
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
    async fn a_registered_lane_receives_published_events() {
        let _guard = test_hub_lock().lock().await;
        install(&LogSinksConfig::default());
        let mut rx = register_lane("otlp", true, true, true, true);
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

    #[tokio::test]
    async fn install_alone_registers_no_consumerless_lane() {
        // The defect this inversion removes: `install` used to create
        // the otlp lane and hand its receiver to someone else to wire
        // up, so a failed `init_logs` left the hub publishing into a
        // queue nobody read (backlog #51). With registration owned by
        // the consumer, asking for otlp in the config creates nothing.
        let _guard = test_hub_lock().lock().await;
        let cfg = LogSinksConfig {
            syslog: None,
            otlp: true,
            ..LogSinksConfig::default()
        };
        install(&cfg);
        assert!(!wants(SinkKind::Audit), "no consumer, no lane");
        install(&LogSinksConfig::default());
    }

    #[tokio::test]
    async fn a_lane_whose_receiver_is_dropped_is_torn_out() {
        // And the other half: a consumer that dies later does not
        // leave the hub counting every event as a drop forever.
        let _guard = test_hub_lock().lock().await;
        install(&LogSinksConfig::default());
        let rx = register_lane("otlp", true, true, true, true);
        assert!(wants(SinkKind::Audit));
        drop(rx);
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
        assert!(!wants(SinkKind::Audit), "the dead lane is gone");
        install(&LogSinksConfig::default());
    }

    fn capture_record(rule_id: &str) -> CaptureSinkRecord {
        CaptureSinkRecord {
            rule_id: rule_id.to_string(),
            request_id: "0123456789abcdef0123456789abcdef".into(),
            timestamp: "2026-06-10T00:00:00+00:00".into(),
            document: serde_json::json!({
                "kind": "capture",
                "rule_id": rule_id,
                "request_id": "0123456789abcdef0123456789abcdef",
                "timestamp": "2026-06-10T00:00:00+00:00",
                "request": { "method": "POST" },
            }),
        }
    }

    #[test]
    fn syslog_capture_toggle_is_its_own_setting() {
        // Until backlog #50 closed, the capture lane followed
        // `syslog_access_enabled`. It now answers to
        // `syslog_capture_enabled` alone, in both directions.
        let mut s = base_settings();
        s.syslog_endpoint = Some("host01:514".into());
        s.syslog_access_enabled = false;
        s.syslog_capture_enabled = true;
        let syslog = LogSinksConfig::from_settings(&s, false)
            .syslog
            .expect("syslog sink configured");
        assert!(!syslog.access_enabled);
        assert!(syslog.capture_enabled);

        s.syslog_access_enabled = true;
        s.syslog_capture_enabled = false;
        let syslog = LogSinksConfig::from_settings(&s, false)
            .syslog
            .expect("syslog sink configured");
        assert!(syslog.access_enabled);
        assert!(!syslog.capture_enabled);
    }

    #[test]
    fn otlp_kinds_follow_their_settings() {
        let mut s = base_settings();
        s.otlp_logs_enabled = true;
        s.otlp_endpoint = Some("http://collector:4318".into());
        assert_eq!(
            LogSinksConfig::from_settings(&s, true).otlp_kinds,
            SinkKindToggles {
                access: true,
                waf: true,
                audit: true,
                capture: true,
            },
            "every kind ships by default"
        );
        s.otlp_logs_audit_enabled = false;
        s.otlp_logs_capture_enabled = false;
        assert_eq!(
            LogSinksConfig::from_settings(&s, true).otlp_kinds,
            SinkKindToggles {
                access: true,
                waf: true,
                audit: false,
                capture: false,
            }
        );
    }

    #[tokio::test]
    async fn an_otlp_lane_registered_from_settings_skips_a_kind_toggled_off() {
        // The path `otel::init_logs` takes: settings -> `otlp_kinds` ->
        // `register_lane`. With `otlp_logs_audit_enabled` off, an
        // audit entry never reaches the lane while an access row does.
        let _guard = test_hub_lock().lock().await;
        install(&LogSinksConfig::default());

        let mut s = base_settings();
        s.otlp_logs_enabled = true;
        s.otlp_endpoint = Some("http://collector:4318".into());
        s.otlp_logs_audit_enabled = false;
        let kinds = LogSinksConfig::from_settings(&s, true).otlp_kinds;
        let mut rx = register_lane("otlp", kinds.access, kinds.waf, kinds.audit, kinds.capture);

        assert!(!wants(SinkKind::Audit));
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
        assert!(
            matches!(
                rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "audit is toggled off for the otlp lane"
        );

        assert!(wants(SinkKind::Access));
        publish_access(
            &LogEntry {
                id: 1,
                timestamp: "2026-06-10T00:00:00Z".into(),
                method: "GET".into(),
                path: "/".into(),
                host: "example.com".into(),
                status: 200,
                latency_ms: 3,
                backend: "10.0.0.10:8080".into(),
                error: None,
                client_ip: "192.0.2.10".into(),
                is_xff: false,
                xff_proxy_ip: String::new(),
                source: String::new(),
                request_id: "0123456789abcdef0123456789abcdef".into(),
            },
            None,
            None,
        );
        let event = rx.recv().await.expect("access row delivered");
        assert_eq!(event.kind(), SinkKind::Access);
        install(&LogSinksConfig::default());
    }

    #[test]
    fn body_json_flattens_a_capture_document_and_stamps_its_kind() {
        let event = SinkEvent {
            payload: Arc::new(SinkPayload::Capture(capture_record("cap-1"))),
            trace_id: None,
            span_id: None,
        };
        assert_eq!(event.kind(), SinkKind::Capture);
        let value: serde_json::Value =
            serde_json::from_str(&body_json(&event)).expect("body is valid JSON");
        assert_eq!(value["v"], SINK_BODY_VERSION);
        assert_eq!(value["kind"], "capture");
        assert_eq!(value["rule_id"], "cap-1");
        assert_eq!(value["request"]["method"], "POST");
        // The transport wrapper never nests the document.
        assert!(value.get("document").is_none());
    }

    #[tokio::test]
    async fn a_capture_reaches_a_lane_with_the_flag_on_and_not_one_with_it_off() {
        let _guard = test_hub_lock().lock().await;
        install(&LogSinksConfig::default());

        let mut off = register_lane("otlp", true, true, true, false);
        assert!(!wants(SinkKind::Capture));
        assert_eq!(publish_capture(capture_record("cap-1"), None, None), 0);
        assert!(
            matches!(
                off.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "a lane with the capture flag off receives nothing"
        );

        let mut on = register_lane("otlp", true, true, true, true);
        assert!(wants(SinkKind::Capture));
        assert_eq!(
            publish_capture(capture_record("cap-1"), Some("4bf9"), Some("00f0")),
            0
        );
        let event = on.recv().await.expect("event delivered");
        assert_eq!(event.kind(), SinkKind::Capture);
        assert_eq!(event.trace_id.as_deref(), Some("4bf9"));
        match &*event.payload {
            SinkPayload::Capture(record) => assert_eq!(record.rule_id, "cap-1"),
            other => panic!("expected a capture payload, got {other:?}"),
        }
        install(&LogSinksConfig::default());
    }

    #[tokio::test]
    async fn a_full_capture_lane_reports_each_lost_copy() {
        let _guard = test_hub_lock().lock().await;
        install(&LogSinksConfig::default());
        // The receiver is held and never drained, so the lane fills.
        let _rx = register_lane("otlp", false, false, false, true);
        for _ in 0..SINK_QUEUE_CAP {
            assert_eq!(publish_capture(capture_record("cap-full"), None, None), 0);
        }
        assert_eq!(
            publish_capture(capture_record("cap-full"), None, None),
            1,
            "the lane is full: the publisher learns that one copy was lost"
        );
        install(&LogSinksConfig::default());
    }
}
