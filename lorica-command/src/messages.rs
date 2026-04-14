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

//! Protobuf message types for the command channel protocol.
//!
//! Defined using prost derive macros to avoid requiring protoc at build time.
//! See `proto/command.proto` for the canonical schema documentation.

use std::time::{SystemTime, UNIX_EPOCH};

/// Command types exchanged between supervisor and worker.
///
/// Variants 1-5 are legacy supervisor -> worker messages. Variants 6+
/// belong to the pipelined RPC framework and can flow in either
/// direction depending on the operation (see `docs/architecture/
/// worker-shared-state.md` § 4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum CommandType {
    Unspecified = 0,
    ConfigReload = 1,
    Heartbeat = 2,
    Shutdown = 3,
    MetricsRequest = 4,
    BanIp = 5,
    /// Worker -> supervisor: query the authoritative rate-limit bucket.
    RateLimitQuery = 6,
    /// Worker -> supervisor: push accumulated consumption deltas.
    RateLimitDelta = 7,
    /// Worker -> supervisor: look up a cached forward-auth verdict.
    VerdictLookup = 8,
    /// Worker -> supervisor: push a freshly computed verdict into the cache.
    VerdictPush = 9,
    /// Worker -> supervisor: ask whether a request should be admitted.
    BreakerQuery = 10,
    /// Worker -> supervisor: report request outcome to update breaker state.
    BreakerReport = 11,
    /// Supervisor -> worker: prepare a new ProxyConfig generation.
    ConfigReloadPrepare = 12,
    /// Supervisor -> worker: commit the prepared generation via ArcSwap.
    ConfigReloadCommit = 13,
    /// Supervisor -> worker: abandon the prepared generation. Sent when
    /// Prepare succeeded on this worker but the coordinator is giving up
    /// (peer worker failed Prepare, timeout, etc.). The worker drops
    /// its `pending_proxy_config` entry if its generation matches, so
    /// the orphan `Arc<ProxyConfig>` is freed instead of pinning memory
    /// until the next reload (audit M-7).
    ConfigReloadAbort = 14,
}

impl CommandType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::ConfigReload,
            2 => Self::Heartbeat,
            3 => Self::Shutdown,
            4 => Self::MetricsRequest,
            5 => Self::BanIp,
            6 => Self::RateLimitQuery,
            7 => Self::RateLimitDelta,
            8 => Self::VerdictLookup,
            9 => Self::VerdictPush,
            10 => Self::BreakerQuery,
            11 => Self::BreakerReport,
            12 => Self::ConfigReloadPrepare,
            13 => Self::ConfigReloadCommit,
            14 => Self::ConfigReloadAbort,
            _ => Self::Unspecified,
        }
    }
}

/// Forward-auth verdict for a (route, cookie) pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Verdict {
    Unspecified = 0,
    Allow = 1,
    Deny = 2,
}

impl Verdict {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Allow,
            2 => Self::Deny,
            _ => Self::Unspecified,
        }
    }
}

/// Circuit breaker decision returned to a worker on `BreakerQuery`.
///
/// `AllowProbe` is used to admit a single HalfOpen probe; on success
/// the supervisor's state machine transitions to Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum BreakerDecision {
    Unspecified = 0,
    Allow = 1,
    Deny = 2,
    AllowProbe = 3,
}

impl BreakerDecision {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Allow,
            2 => Self::Deny,
            3 => Self::AllowProbe,
            _ => Self::Unspecified,
        }
    }
}

/// Response status codes from worker to supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ResponseStatus {
    Unspecified = 0,
    Ok = 1,
    Error = 2,
    Processing = 3,
}

impl ResponseStatus {
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::Error,
            3 => Self::Processing,
            _ => Self::Unspecified,
        }
    }
}

/// Command message. Flows supervisor -> worker for legacy variants and
/// supervisor <-> worker for the pipelined RPC framework.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Command {
    #[prost(int32, tag = "1")]
    pub command_type: i32,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(uint64, tag = "3")]
    pub timestamp_ms: u64,
    /// IP address to ban (only used with BanIp command type).
    #[prost(string, tag = "4")]
    pub ban_ip: ::prost::alloc::string::String,
    /// Ban duration in seconds (only used with BanIp command type).
    #[prost(uint64, tag = "5")]
    pub ban_duration_s: u64,
    /// Typed payload for RPC framework variants (CommandType 6+).
    /// None for legacy variants.
    #[prost(
        oneof = "command::Payload",
        tags = "100, 101, 102, 103, 104, 105, 106, 107, 108"
    )]
    pub payload: ::core::option::Option<command::Payload>,
}

/// Typed payload variants for pipelined RPC commands.
pub mod command {
    use super::{
        BreakerQuery, BreakerReport, ConfigReloadAbort, ConfigReloadCommit, ConfigReloadPrepare,
        RateLimitDelta, RateLimitQuery, VerdictLookup, VerdictPush,
    };

    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "100")]
        RateLimitQuery(RateLimitQuery),
        #[prost(message, tag = "101")]
        RateLimitDelta(RateLimitDelta),
        #[prost(message, tag = "102")]
        VerdictLookup(VerdictLookup),
        #[prost(message, tag = "103")]
        VerdictPush(VerdictPush),
        #[prost(message, tag = "104")]
        BreakerQuery(BreakerQuery),
        #[prost(message, tag = "105")]
        BreakerReport(BreakerReport),
        #[prost(message, tag = "106")]
        ConfigReloadPrepare(ConfigReloadPrepare),
        #[prost(message, tag = "107")]
        ConfigReloadCommit(ConfigReloadCommit),
        #[prost(message, tag = "108")]
        ConfigReloadAbort(ConfigReloadAbort),
    }
}

impl Command {
    /// Create a new command with auto-populated timestamp.
    pub fn new(command_type: CommandType, sequence: u64) -> Self {
        Self {
            command_type: command_type as i32,
            sequence,
            timestamp_ms: now_ms(),
            ban_ip: String::new(),
            ban_duration_s: 0,
            payload: None,
        }
    }

    /// Create a BanIp command with the specified IP and duration.
    pub fn ban_ip(sequence: u64, ip: impl Into<String>, duration_s: u64) -> Self {
        Self {
            command_type: CommandType::BanIp as i32,
            sequence,
            timestamp_ms: now_ms(),
            ban_ip: ip.into(),
            ban_duration_s: duration_s,
            payload: None,
        }
    }

    /// Build a typed RPC command. `command_type` must match `payload`;
    /// the two are kept in sync for wire-compat routing by old readers.
    pub fn rpc(sequence: u64, command_type: CommandType, payload: command::Payload) -> Self {
        Self {
            command_type: command_type as i32,
            sequence,
            timestamp_ms: now_ms(),
            ban_ip: String::new(),
            ban_duration_s: 0,
            payload: Some(payload),
        }
    }

    /// Get the typed command type.
    pub fn typed_command(&self) -> CommandType {
        CommandType::from_i32(self.command_type)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Response message. Flows worker -> supervisor for legacy variants and
/// supervisor <-> worker for the pipelined RPC framework. Match by
/// `sequence` against the originating `Command`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Response {
    #[prost(int32, tag = "1")]
    pub status: i32,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(string, tag = "3")]
    pub message: ::prost::alloc::string::String,
    /// Typed payload for RPC responses (verdict, breaker decision, rate
    /// limit snapshot, metrics report). None for legacy status-only
    /// responses.
    #[prost(oneof = "response::Payload", tags = "100, 101, 102, 103, 104")]
    pub payload: ::core::option::Option<response::Payload>,
}

/// Typed payload variants for pipelined RPC responses.
pub mod response {
    use super::{
        BreakerResult, MetricsReport, RateLimitDeltaResult, RateLimitResult, VerdictResult,
    };

    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "100")]
        VerdictResult(VerdictResult),
        #[prost(message, tag = "101")]
        BreakerResult(BreakerResult),
        #[prost(message, tag = "102")]
        RateLimitResult(RateLimitResult),
        #[prost(message, tag = "103")]
        RateLimitDeltaResult(RateLimitDeltaResult),
        /// Worker-provided metrics snapshot in reply to a pipelined
        /// `MetricsRequest`. Used by the /metrics pull-on-scrape path
        /// (WPAR-7) to dedup and aggregate concurrent Prometheus
        /// scrapes into a single supervisor fan-out.
        #[prost(message, tag = "104")]
        MetricsReport(MetricsReport),
    }
}

impl Response {
    /// Create an Ok response with no typed payload.
    pub fn ok(sequence: u64) -> Self {
        Self {
            status: ResponseStatus::Ok as i32,
            sequence,
            message: String::new(),
            payload: None,
        }
    }

    /// Create an Ok response carrying a typed RPC payload.
    pub fn ok_with(sequence: u64, payload: response::Payload) -> Self {
        Self {
            status: ResponseStatus::Ok as i32,
            sequence,
            message: String::new(),
            payload: Some(payload),
        }
    }

    /// Create an Error response.
    pub fn error(sequence: u64, message: impl Into<String>) -> Self {
        Self {
            status: ResponseStatus::Error as i32,
            sequence,
            message: message.into(),
            payload: None,
        }
    }

    /// Create a Processing response.
    pub fn processing(sequence: u64, message: impl Into<String>) -> Self {
        Self {
            status: ResponseStatus::Processing as i32,
            sequence,
            message: message.into(),
            payload: None,
        }
    }

    /// Get the typed response status.
    pub fn typed_status(&self) -> ResponseStatus {
        ResponseStatus::from_i32(self.status)
    }
}

/// A single banned IP entry in a metrics report.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BanReportEntry {
    /// Banned IP address.
    #[prost(string, tag = "1")]
    pub ip: String,
    /// Seconds remaining before the ban expires.
    #[prost(uint64, tag = "2")]
    pub remaining_seconds: u64,
    /// Total ban duration in seconds.
    #[prost(uint64, tag = "3")]
    pub ban_duration_seconds: u64,
}

/// Per-route/status HTTP request count entry.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RequestCountEntry {
    #[prost(string, tag = "1")]
    pub route_id: String,
    #[prost(uint32, tag = "2")]
    pub status_code: u32,
    #[prost(uint64, tag = "3")]
    pub count: u64,
}

/// Per-category/action WAF event count entry.
#[derive(Clone, PartialEq, prost::Message)]
pub struct WafCountEntry {
    #[prost(string, tag = "1")]
    pub category: String,
    #[prost(string, tag = "2")]
    pub action: String,
    #[prost(uint64, tag = "3")]
    pub count: u64,
}

/// A single backend active connection count in a metrics report.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BackendConnEntry {
    /// Backend address (e.g. "10.0.0.1:8080").
    #[prost(string, tag = "1")]
    pub backend_address: String,
    /// Active connections to this backend.
    #[prost(uint64, tag = "2")]
    pub connections: u64,
}

/// A single backend EWMA latency entry in a metrics report.
#[derive(Clone, PartialEq, prost::Message)]
pub struct EwmaReportEntry {
    /// Backend address (e.g. "10.0.0.1:8080").
    #[prost(string, tag = "1")]
    pub backend_address: String,
    /// EWMA latency score in microseconds.
    #[prost(double, tag = "2")]
    pub score_us: f64,
}

/// Metrics data sent from worker to supervisor for aggregation.
///
/// Workers report their metrics on MetricsRequest.
/// The supervisor aggregates them into the global /metrics and API endpoints.
#[derive(Clone, PartialEq, prost::Message)]
pub struct MetricsReport {
    /// Worker ID.
    #[prost(uint32, tag = "1")]
    pub worker_id: u32,
    /// Total requests processed by this worker.
    #[prost(uint64, tag = "2")]
    pub total_requests: u64,
    /// Active connections on this worker.
    #[prost(uint64, tag = "3")]
    pub active_connections: u64,
    /// Timestamp of the report.
    #[prost(uint64, tag = "4")]
    pub timestamp_ms: u64,
    /// Cumulative cache hits.
    #[prost(uint64, tag = "5")]
    pub cache_hits: u64,
    /// Cumulative cache misses.
    #[prost(uint64, tag = "6")]
    pub cache_misses: u64,
    /// Active ban entries (non-expired).
    #[prost(message, repeated, tag = "7")]
    pub ban_entries: Vec<BanReportEntry>,
    /// Per-backend EWMA latency scores.
    #[prost(message, repeated, tag = "8")]
    pub ewma_entries: Vec<EwmaReportEntry>,
    /// Per-backend active connection counts.
    #[prost(message, repeated, tag = "9")]
    pub backend_conn_entries: Vec<BackendConnEntry>,
    /// Per-route/status HTTP request counts (cumulative).
    #[prost(message, repeated, tag = "10")]
    pub request_entries: Vec<RequestCountEntry>,
    /// Per-category/action WAF event counts (cumulative).
    #[prost(message, repeated, tag = "11")]
    pub waf_entries: Vec<WafCountEntry>,
}

impl MetricsReport {
    pub fn new(worker_id: u32, total_requests: u64, active_connections: u64) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            worker_id,
            total_requests,
            active_connections,
            timestamp_ms,
            cache_hits: 0,
            cache_misses: 0,
            ban_entries: Vec::new(),
            ewma_entries: Vec::new(),
            backend_conn_entries: Vec::new(),
            request_entries: Vec::new(),
            waf_entries: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Envelope: top-level wire frame for the pipelined RPC channel.
//
// A duplex stream interleaves `Command` and `Response` messages originating
// from either endpoint. Because `Command` and `Response` share the same
// leading prost tags at the byte level, we cannot distinguish them without
// a discriminator. `Envelope` provides one. All pipelined traffic uses
// `Envelope` as the framed message; legacy `CommandChannel` users that
// send bare `Command`/`Response` are not compatible with `RpcEndpoint`
// and vice versa.
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq, prost::Message)]
pub struct Envelope {
    #[prost(oneof = "envelope::Kind", tags = "1, 2")]
    pub kind: ::core::option::Option<envelope::Kind>,
}

pub mod envelope {
    use super::{Command, Response};

    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        Command(Command),
        #[prost(message, tag = "2")]
        Response(Response),
    }
}

impl Envelope {
    pub fn command(cmd: Command) -> Self {
        Self {
            kind: Some(envelope::Kind::Command(cmd)),
        }
    }

    pub fn response(resp: Response) -> Self {
        Self {
            kind: Some(envelope::Kind::Response(resp)),
        }
    }
}

// ---------------------------------------------------------------------------
// RPC payload message types (CommandType 6+, used with `command::Payload`).
// See docs/architecture/worker-shared-state.md § 4.2.
// ---------------------------------------------------------------------------

/// Worker -> supervisor: query the authoritative rate-limit bucket.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitQuery {
    /// Composite key: `{route_id}:{ip}` or route-scoped identifier.
    #[prost(string, tag = "1")]
    pub key: String,
    /// Number of tokens the worker wants to consume.
    #[prost(uint32, tag = "2")]
    pub cost: u32,
}

/// Single key/consumed pair for a batched rate-limit delta push.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitEntry {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(uint32, tag = "2")]
    pub consumed: u32,
}

/// Worker -> supervisor: push accumulated consumption since last sync.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitDelta {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<RateLimitEntry>,
}

/// Worker -> supervisor: look up a cached forward-auth verdict.
#[derive(Clone, PartialEq, prost::Message)]
pub struct VerdictLookup {
    #[prost(string, tag = "1")]
    pub route_id: String,
    #[prost(string, tag = "2")]
    pub cookie: String,
}

/// Worker -> supervisor: cache a freshly computed verdict.
#[derive(Clone, PartialEq, prost::Message)]
pub struct VerdictPush {
    #[prost(string, tag = "1")]
    pub route_id: String,
    #[prost(string, tag = "2")]
    pub cookie: String,
    /// Encoded as `Verdict` enum.
    #[prost(int32, tag = "3")]
    pub verdict: i32,
    #[prost(uint64, tag = "4")]
    pub ttl_ms: u64,
    /// Forward-auth response headers captured from the upstream auth
    /// service (Remote-User, Remote-Groups, etc.). Stored alongside the
    /// verdict so a subsequent lookup can inject them without a fresh
    /// auth round trip.
    #[prost(message, repeated, tag = "5")]
    pub response_headers: Vec<ForwardAuthHeader>,
}

/// Single header pair propagated from a cached forward-auth verdict.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ForwardAuthHeader {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub value: String,
}

/// Worker -> supervisor: ask whether a request should be admitted.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BreakerQuery {
    #[prost(string, tag = "1")]
    pub route_id: String,
    #[prost(string, tag = "2")]
    pub backend: String,
}

/// Worker -> supervisor: report request outcome to drive breaker state.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BreakerReport {
    #[prost(string, tag = "1")]
    pub route_id: String,
    #[prost(string, tag = "2")]
    pub backend: String,
    #[prost(bool, tag = "3")]
    pub success: bool,
    /// True if this report is for a request admitted via `AllowProbe`.
    /// On `success == true`, supervisor transitions HalfOpen -> Closed.
    #[prost(bool, tag = "4")]
    pub was_probe: bool,
}

/// Supervisor -> worker: prepare a new ProxyConfig generation.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigReloadPrepare {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

/// Supervisor -> worker: commit the prepared generation via ArcSwap.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigReloadCommit {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

/// Supervisor -> worker: discard the prepared generation if it matches.
///
/// Sent when the coordinator gives up on a reload after a peer worker
/// failed Prepare; the receiving worker drops its pending slot so the
/// orphan `Arc<ProxyConfig>` isn't pinned until the next reload
/// (audit M-7).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigReloadAbort {
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

// ---------------------------------------------------------------------------
// RPC response payload types (used with `response::Payload`).
// ---------------------------------------------------------------------------

/// Supervisor -> worker: result of a `VerdictLookup`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct VerdictResult {
    /// True if the cache held a non-expired entry for the (route, cookie).
    #[prost(bool, tag = "1")]
    pub found: bool,
    /// Encoded as `Verdict` enum. Meaningful only when `found == true`.
    #[prost(int32, tag = "2")]
    pub verdict: i32,
    /// Remaining TTL in milliseconds (informative).
    #[prost(uint64, tag = "3")]
    pub ttl_ms: u64,
    /// Headers the worker injects on an Allow hit. Empty on miss / Deny.
    #[prost(message, repeated, tag = "4")]
    pub response_headers: Vec<ForwardAuthHeader>,
}

/// Supervisor -> worker: result of a `BreakerQuery`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct BreakerResult {
    /// Encoded as `BreakerDecision` enum.
    #[prost(int32, tag = "1")]
    pub decision: i32,
}

/// Supervisor -> worker: result of a `RateLimitQuery`. Worker uses this
/// to overwrite its local view of the bucket.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitResult {
    #[prost(bool, tag = "1")]
    pub allowed: bool,
    /// Tokens remaining in the authoritative bucket.
    #[prost(uint32, tag = "2")]
    pub remaining: u32,
}

/// One authoritative-bucket snapshot entry returned by
/// [`RateLimitDeltaResult`]. Pairs by `key` with the `RateLimitDelta`
/// request; absent keys default to the initial capacity client-side.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitSnapshot {
    #[prost(string, tag = "1")]
    pub key: String,
    /// Tokens remaining in the authoritative bucket after applying the
    /// worker's pushed delta.
    #[prost(uint32, tag = "2")]
    pub remaining: u32,
}

/// Supervisor -> worker: batched authoritative snapshots in reply to a
/// `RateLimitDelta` push. Worker matches each entry by `key` and calls
/// `LocalBucket::refresh(remaining)`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RateLimitDeltaResult {
    #[prost(message, repeated, tag = "1")]
    pub snapshots: Vec<RateLimitSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_new() {
        let cmd = Command::new(CommandType::ConfigReload, 42);
        assert_eq!(cmd.typed_command(), CommandType::ConfigReload);
        assert_eq!(cmd.sequence, 42);
        assert!(cmd.timestamp_ms > 0);
    }

    #[test]
    fn test_command_type_roundtrip() {
        for ct in [
            CommandType::Unspecified,
            CommandType::ConfigReload,
            CommandType::Heartbeat,
            CommandType::Shutdown,
            CommandType::MetricsRequest,
            CommandType::BanIp,
        ] {
            assert_eq!(CommandType::from_i32(ct as i32), ct);
        }
    }

    #[test]
    fn test_response_ok() {
        let resp = Response::ok(1);
        assert_eq!(resp.typed_status(), ResponseStatus::Ok);
        assert_eq!(resp.sequence, 1);
        assert!(resp.message.is_empty());
    }

    #[test]
    fn test_response_error() {
        let resp = Response::error(5, "config load failed");
        assert_eq!(resp.typed_status(), ResponseStatus::Error);
        assert_eq!(resp.sequence, 5);
        assert_eq!(resp.message, "config load failed");
    }

    #[test]
    fn test_response_processing() {
        let resp = Response::processing(3, "draining connections");
        assert_eq!(resp.typed_status(), ResponseStatus::Processing);
    }

    #[test]
    fn test_response_status_roundtrip() {
        for rs in [
            ResponseStatus::Unspecified,
            ResponseStatus::Ok,
            ResponseStatus::Error,
            ResponseStatus::Processing,
        ] {
            assert_eq!(ResponseStatus::from_i32(rs as i32), rs);
        }
    }

    #[test]
    fn test_command_prost_encode_decode() {
        use prost::Message;

        let cmd = Command::new(CommandType::Heartbeat, 99);
        let encoded = cmd.encode_to_vec();
        let decoded = Command::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn test_ban_ip_command() {
        use prost::Message;

        let cmd = Command::ban_ip(42, "192.168.1.100", 3600);
        assert_eq!(cmd.typed_command(), CommandType::BanIp);
        assert_eq!(cmd.sequence, 42);
        assert_eq!(cmd.ban_ip, "192.168.1.100");
        assert_eq!(cmd.ban_duration_s, 3600);
        assert!(cmd.timestamp_ms > 0);

        // Verify protobuf roundtrip
        let encoded = cmd.encode_to_vec();
        let decoded = Command::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn test_metrics_report_prost_encode_decode() {
        use prost::Message;

        let report = MetricsReport {
            worker_id: 1,
            total_requests: 5000,
            active_connections: 42,
            timestamp_ms: 1234567890,
            cache_hits: 3000,
            cache_misses: 2000,
            ban_entries: vec![BanReportEntry {
                ip: "192.168.1.100".into(),
                remaining_seconds: 300,
                ban_duration_seconds: 600,
            }],
            ewma_entries: vec![
                EwmaReportEntry {
                    backend_address: "10.0.0.1:8080".into(),
                    score_us: 1500.5,
                },
                EwmaReportEntry {
                    backend_address: "10.0.0.2:8080".into(),
                    score_us: 2300.0,
                },
            ],
            backend_conn_entries: Vec::new(),
            request_entries: Vec::new(),
            waf_entries: Vec::new(),
        };
        let encoded = report.encode_to_vec();
        let decoded = MetricsReport::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, report);
        assert_eq!(decoded.ban_entries.len(), 1);
        assert_eq!(decoded.ewma_entries.len(), 2);
        assert_eq!(decoded.cache_hits, 3000);
    }

    #[test]
    fn test_response_prost_encode_decode() {
        use prost::Message;

        let resp = Response::error(7, "test error");
        let encoded = resp.encode_to_vec();
        let decoded = Response::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, resp);
    }

    #[test]
    fn test_command_type_rpc_variants_roundtrip() {
        for ct in [
            CommandType::RateLimitQuery,
            CommandType::RateLimitDelta,
            CommandType::VerdictLookup,
            CommandType::VerdictPush,
            CommandType::BreakerQuery,
            CommandType::BreakerReport,
            CommandType::ConfigReloadPrepare,
            CommandType::ConfigReloadCommit,
        ] {
            assert_eq!(CommandType::from_i32(ct as i32), ct);
        }
    }

    #[test]
    fn test_verdict_enum_roundtrip() {
        for v in [Verdict::Unspecified, Verdict::Allow, Verdict::Deny] {
            assert_eq!(Verdict::from_i32(v as i32), v);
        }
    }

    #[test]
    fn test_breaker_decision_enum_roundtrip() {
        for d in [
            BreakerDecision::Unspecified,
            BreakerDecision::Allow,
            BreakerDecision::Deny,
            BreakerDecision::AllowProbe,
        ] {
            assert_eq!(BreakerDecision::from_i32(d as i32), d);
        }
    }

    #[test]
    fn test_rate_limit_query_roundtrip() {
        use prost::Message;

        let cmd = Command::rpc(
            42,
            CommandType::RateLimitQuery,
            command::Payload::RateLimitQuery(RateLimitQuery {
                key: "route-1:10.0.0.1".into(),
                cost: 3,
            }),
        );
        let encoded = cmd.encode_to_vec();
        let decoded = Command::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, cmd);
        assert_eq!(decoded.typed_command(), CommandType::RateLimitQuery);
        match decoded.payload {
            Some(command::Payload::RateLimitQuery(q)) => {
                assert_eq!(q.key, "route-1:10.0.0.1");
                assert_eq!(q.cost, 3);
            }
            _ => panic!("expected RateLimitQuery payload"),
        }
    }

    #[test]
    fn test_rate_limit_delta_roundtrip() {
        use prost::Message;

        let cmd = Command::rpc(
            7,
            CommandType::RateLimitDelta,
            command::Payload::RateLimitDelta(RateLimitDelta {
                entries: vec![
                    RateLimitEntry {
                        key: "k1".into(),
                        consumed: 5,
                    },
                    RateLimitEntry {
                        key: "k2".into(),
                        consumed: 1,
                    },
                ],
            }),
        );
        let encoded = cmd.encode_to_vec();
        let decoded = Command::decode(&encoded[..]).expect("decode failed");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn test_verdict_lookup_and_push_roundtrip() {
        use prost::Message;

        let lookup = Command::rpc(
            1,
            CommandType::VerdictLookup,
            command::Payload::VerdictLookup(VerdictLookup {
                route_id: "r".into(),
                cookie: "c".into(),
            }),
        );
        let roundtrip = Command::decode(&lookup.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, lookup);

        let push = Command::rpc(
            2,
            CommandType::VerdictPush,
            command::Payload::VerdictPush(VerdictPush {
                route_id: "r".into(),
                cookie: "c".into(),
                verdict: Verdict::Allow as i32,
                ttl_ms: 60_000,
                response_headers: vec![ForwardAuthHeader {
                    name: "Remote-User".into(),
                    value: "alice".into(),
                }],
            }),
        );
        let roundtrip = Command::decode(&push.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, push);
    }

    #[test]
    fn test_breaker_query_and_report_roundtrip() {
        use prost::Message;

        let q = Command::rpc(
            1,
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(BreakerQuery {
                route_id: "r".into(),
                backend: "10.0.0.1:8080".into(),
            }),
        );
        assert_eq!(Command::decode(&q.encode_to_vec()[..]).unwrap(), q);

        let r = Command::rpc(
            2,
            CommandType::BreakerReport,
            command::Payload::BreakerReport(BreakerReport {
                route_id: "r".into(),
                backend: "10.0.0.1:8080".into(),
                success: true,
                was_probe: true,
            }),
        );
        assert_eq!(Command::decode(&r.encode_to_vec()[..]).unwrap(), r);
    }

    #[test]
    fn test_config_reload_prepare_commit_roundtrip() {
        use prost::Message;

        let p = Command::rpc(
            10,
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 42 }),
        );
        assert_eq!(Command::decode(&p.encode_to_vec()[..]).unwrap(), p);

        let c = Command::rpc(
            11,
            CommandType::ConfigReloadCommit,
            command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 42 }),
        );
        assert_eq!(Command::decode(&c.encode_to_vec()[..]).unwrap(), c);
    }

    #[test]
    fn test_response_with_verdict_result_roundtrip() {
        use prost::Message;

        let resp = Response::ok_with(
            7,
            response::Payload::VerdictResult(VerdictResult {
                found: true,
                verdict: Verdict::Deny as i32,
                ttl_ms: 30_000,
                response_headers: Vec::new(),
            }),
        );
        let roundtrip = Response::decode(&resp.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, resp);
        match roundtrip.payload {
            Some(response::Payload::VerdictResult(v)) => {
                assert!(v.found);
                assert_eq!(Verdict::from_i32(v.verdict), Verdict::Deny);
            }
            _ => panic!("expected VerdictResult payload"),
        }
    }

    #[test]
    fn test_response_with_breaker_result_roundtrip() {
        use prost::Message;

        let resp = Response::ok_with(
            8,
            response::Payload::BreakerResult(BreakerResult {
                decision: BreakerDecision::AllowProbe as i32,
            }),
        );
        let roundtrip = Response::decode(&resp.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, resp);
    }

    #[test]
    fn test_response_with_rate_limit_result_roundtrip() {
        use prost::Message;

        let resp = Response::ok_with(
            9,
            response::Payload::RateLimitResult(RateLimitResult {
                allowed: true,
                remaining: 17,
            }),
        );
        let roundtrip = Response::decode(&resp.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, resp);
    }

    #[test]
    fn test_response_with_rate_limit_delta_result_roundtrip() {
        use prost::Message;

        let resp = Response::ok_with(
            10,
            response::Payload::RateLimitDeltaResult(RateLimitDeltaResult {
                snapshots: vec![
                    RateLimitSnapshot {
                        key: "r1:1.2.3.4".into(),
                        remaining: 42,
                    },
                    RateLimitSnapshot {
                        key: "r1:5.6.7.8".into(),
                        remaining: 0,
                    },
                ],
            }),
        );
        let roundtrip = Response::decode(&resp.encode_to_vec()[..]).unwrap();
        assert_eq!(roundtrip, resp);
    }

    #[test]
    fn test_legacy_command_decodes_into_extended_schema() {
        // An old encoder (pre-RPC) never sets the oneof; make sure we
        // can still decode such a payload as the extended Command.
        use prost::Message;

        // Manually build "legacy" wire bytes by encoding a Command with
        // payload=None (no oneof field serialized by prost).
        let legacy = Command {
            command_type: CommandType::Heartbeat as i32,
            sequence: 1,
            timestamp_ms: 123,
            ban_ip: String::new(),
            ban_duration_s: 0,
            payload: None,
        };
        let bytes = legacy.encode_to_vec();
        let decoded = Command::decode(&bytes[..]).expect("decode");
        assert_eq!(decoded.typed_command(), CommandType::Heartbeat);
        assert!(decoded.payload.is_none());
    }
}
