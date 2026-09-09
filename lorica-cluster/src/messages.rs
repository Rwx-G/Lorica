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

//! Protobuf message types for the cluster-plane protocol.
//!
//! Defined using prost derive macros to avoid requiring protoc at build
//! time. See `proto/cluster.proto` for the canonical schema
//! documentation, including the tag-disjointness argument against the
//! worker plane's `lorica.command` package (Story 9.2 AC #6) and the
//! tag ranges reserved for Stories 9.4/9.5/9.6.

/// Response status for a [`ClusterResponse`].
///
/// `Unspecified` doubles as the OPAQUE refusal for pre-authentication
/// paths (Story 9.2 AC #4): an unauthenticated peer must not learn
/// build or protocol facts from refusal shapes. Callers on the
/// enrollment listener map every refusal through
/// [`ClusterStatus::opaque`] before it reaches the wire and log the
/// real cause locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
#[non_exhaustive]
pub enum ClusterStatus {
    /// Opaque refusal (and proto3 default for unknown values). Note
    /// that an OLDER peer also sees any status it does not know as
    /// this value, so it cannot tell a newer status from a deliberate
    /// opaque refusal; acceptable, and documented in the .proto.
    Unspecified = 0,
    /// Session admitted / request served.
    Ok = 1,
    /// Admission control queue is full (AC #10); retry after
    /// `retry_after_s`.
    RetryLater = 2,
    /// No overlap between the peers' protocol version ranges (AC #4).
    IncompatibleVersion = 3,
    /// The follower's schema version is below the control plane's
    /// (AC #5); configuration apply is refused with this distinct
    /// diagnostic.
    SchemaTooOld = 4,
    /// The peer sent a malformed or wrong-plane frame (AC #6).
    ProtocolViolation = 5,
    /// The request had a well-formed shape but a `body_kind` this
    /// build does not implement: the peer is NEWER, the request is
    /// refused, the connection stays up (rolling-upgrade tolerance).
    UnsupportedMethod = 6,
}

impl ClusterStatus {
    /// Decode from the wire representation; unknown values collapse to
    /// [`ClusterStatus::Unspecified`].
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::RetryLater,
            3 => Self::IncompatibleVersion,
            4 => Self::SchemaTooOld,
            5 => Self::ProtocolViolation,
            6 => Self::UnsupportedMethod,
            _ => Self::Unspecified,
        }
    }

    /// The status an unauthenticated (enrollment-path) peer sees for
    /// ANY refusal: [`ClusterStatus::Unspecified`]. The real cause is
    /// for the local log only.
    pub fn opaque() -> Self {
        Self::Unspecified
    }
}

/// First request on every operational connection, sent AFTER mutual
/// TLS has verified the client certificate (AC #4).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    /// Lowest protocol version the sender still speaks (AC #4).
    #[prost(uint32, tag = "1")]
    pub protocol_min: u32,
    /// Highest protocol version the sender speaks.
    #[prost(uint32, tag = "2")]
    pub protocol_max: u32,
    /// The sender's database schema version (AC #5).
    #[prost(uint32, tag = "3")]
    pub schema_version: u32,
    /// Display name only. Node IDENTITY is the peer-certificate
    /// fingerprint recorded at enrollment (Story 9.3 AC #8); never an
    /// authorization input, never a metric label (AC #12).
    #[prost(string, tag = "4")]
    pub node_name: ::prost::alloc::string::String,
    /// The sender's build version, display only (Story 9.3 AC #9);
    /// bounded like `node_name`.
    #[prost(string, tag = "5")]
    pub build_version: ::prost::alloc::string::String,
    /// The configuration generation the follower runs (Story 9.4
    /// AC #7); `0` when nothing was ever applied.
    #[prost(uint64, tag = "6")]
    pub applied_generation: u64,
    /// Canonical hash of the applied configuration (lowercase hex,
    /// bounded by [`MAX_CONFIG_HASH_BYTES`]); empty with generation 0.
    #[prost(string, tag = "7")]
    pub applied_hash: ::prost::alloc::string::String,
    /// Whether the follower is in break-glass (Story 9.4 AC #11): it
    /// is excluded from commit sets until the window ends.
    #[prost(bool, tag = "8")]
    pub break_glass: bool,
}

/// Control-plane answer to a [`Hello`] when the session is admitted.
#[derive(Clone, PartialEq, prost::Message)]
pub struct HelloAck {
    /// Highest protocol version both sides speak.
    #[prost(uint32, tag = "1")]
    pub negotiated_version: u32,
    /// The control plane's schema version.
    #[prost(uint32, tag = "2")]
    pub schema_version: u32,
    /// Approximate fleet size so the follower can scale its reconnect
    /// backoff cap (AC #9) without knowing the roster.
    #[prost(uint32, tag = "3")]
    pub fleet_size_hint: u32,
    /// The control plane's current configuration generation (Story 9.4
    /// AC #7): a follower behind it pulls at the handshake.
    #[prost(uint64, tag = "4")]
    pub current_generation: u64,
    /// Canonical hash of the current configuration (lowercase hex).
    #[prost(string, tag = "5")]
    pub current_hash: ::prost::alloc::string::String,
}

/// Current resource usage, sampled by the sender at heartbeat time
/// (Story 9.7 AC #3).
///
/// Current values, never a series: a gauge on a node drawer needs one
/// number, and anything with history belongs on the telemetry fan-in
/// channel instead.
///
/// Carried as an optional message rather than as scalar fields on
/// [`Heartbeat`] so that absence is representable. A node whose
/// runtime installs no sampler omits it and the dashboard shows a
/// dash; scalars would report zero, which reads as an idle node
/// rather than an unknown one.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct NodeResources {
    /// Whole percent, 0 to 100, rounded by the sender.
    #[prost(uint32, tag = "1")]
    pub cpu_percent: u32,
    /// Resident memory in use, bytes.
    #[prost(uint64, tag = "2")]
    pub memory_used_bytes: u64,
    /// Total memory, bytes. Zero when the sender could not read it.
    #[prost(uint64, tag = "3")]
    pub memory_total_bytes: u64,
    /// Bytes used on the filesystem holding the data directory.
    #[prost(uint64, tag = "4")]
    pub disk_used_bytes: u64,
    /// Total bytes on that filesystem. Zero when unreadable.
    #[prost(uint64, tag = "5")]
    pub disk_total_bytes: u64,
}

/// Liveness probe, either direction.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Heartbeat {
    /// Sender's clock, unix milliseconds.
    #[prost(uint64, tag = "1")]
    pub timestamp_ms: u64,
    /// The configuration generation the follower runs (Story 9.4
    /// AC #6/#7: a missed commit converges within one interval).
    #[prost(uint64, tag = "2")]
    pub applied_generation: u64,
    /// Canonical hash of the applied configuration (lowercase hex).
    #[prost(string, tag = "3")]
    pub applied_hash: ::prost::alloc::string::String,
    /// Whether the follower is in break-glass (Story 9.4 AC #11).
    #[prost(bool, tag = "4")]
    pub break_glass: bool,
    /// What the node is currently using (Story 9.7 AC #3). `None` from
    /// a node whose runtime installs no sampler, which the dashboard
    /// must render as unknown rather than as zero.
    #[prost(message, optional, tag = "5")]
    pub resources: Option<NodeResources>,
}

/// Answer to a [`Heartbeat`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeartbeatAck {
    /// Echo of the probe's `timestamp_ms`.
    #[prost(uint64, tag = "1")]
    pub timestamp_ms: u64,
    /// Refreshed backoff-cap input (AC #9).
    #[prost(uint32, tag = "2")]
    pub fleet_size_hint: u32,
    /// The control plane's current configuration generation.
    #[prost(uint64, tag = "3")]
    pub current_generation: u64,
    /// Canonical hash of the current configuration (lowercase hex).
    #[prost(string, tag = "4")]
    pub current_hash: ::prost::alloc::string::String,
}

/// Token redemption (Story 9.3 AC #1/#3): the only frame the
/// enrollment listener accepts. No CSR: the node sends its bare
/// public key and the control plane assigns every certificate
/// parameter.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Enroll {
    /// Token lookup half.
    #[prost(string, tag = "1")]
    pub public_id: ::prost::alloc::string::String,
    /// Token secret half (32 bytes); never logged.
    #[prost(bytes = "vec", tag = "2")]
    pub secret: ::prost::alloc::vec::Vec<u8>,
    /// The node's `SubjectPublicKeyInfo`, DER.
    #[prost(bytes = "vec", tag = "3")]
    pub public_key_der: ::prost::alloc::vec::Vec<u8>,
    /// Requested display name (bounded).
    #[prost(string, tag = "4")]
    pub node_name: ::prost::alloc::string::String,
    /// Display only (bounded).
    #[prost(string, tag = "5")]
    pub build_version: ::prost::alloc::string::String,
    /// The node's database schema version.
    #[prost(uint32, tag = "6")]
    pub schema_version: u32,
}

/// A granted enrollment. Refusals carry the opaque status and no
/// body.
#[derive(Clone, PartialEq, prost::Message)]
pub struct EnrollAck {
    /// Server-assigned identity.
    #[prost(string, tag = "1")]
    pub node_id: ::prost::alloc::string::String,
    /// The node's `clientAuth` leaf, PEM.
    #[prost(string, tag = "2")]
    pub cert_pem: ::prost::alloc::string::String,
    /// The cluster CA bundle, PEM.
    #[prost(string, tag = "3")]
    pub ca_pem: ::prost::alloc::string::String,
    /// `pending` or `active` (Story 9.3 AC #5).
    #[prost(string, tag = "4")]
    pub status: ::prost::alloc::string::String,
    /// RFC 3339 `notAfter` of the leaf.
    #[prost(string, tag = "5")]
    pub cert_not_after: ::prost::alloc::string::String,
}

/// Certificate renewal over an established session (Story 9.3
/// AC #12): a NEW bare public key.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Renew {
    /// The node's new `SubjectPublicKeyInfo`, DER.
    #[prost(bytes = "vec", tag = "1")]
    pub public_key_der: ::prost::alloc::vec::Vec<u8>,
}

/// A renewed certificate.
#[derive(Clone, PartialEq, prost::Message)]
pub struct RenewAck {
    /// The new leaf, PEM.
    #[prost(string, tag = "1")]
    pub cert_pem: ::prost::alloc::string::String,
    /// RFC 3339 `notAfter` of the new leaf.
    #[prost(string, tag = "2")]
    pub cert_not_after: ::prost::alloc::string::String,
}

/// The node is leaving the fleet (Story 9.3 AC #13).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Leave {}

/// Leave acknowledged; the session ends with it.
#[derive(Clone, PartialEq, prost::Message)]
pub struct LeaveAck {}

/// Phase one of a configuration push (Story 9.4 AC #4), control plane
/// to follower: stage this generation, do not apply it yet.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigPrepare {
    /// The generation being replicated.
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    /// Canonical SHA-256 of `blob`, lowercase hex.
    #[prost(string, tag = "2")]
    pub hash: ::prost::alloc::string::String,
    /// The canonical configuration blob (bounded by the 4 MiB frame
    /// cap).
    #[prost(bytes = "vec", tag = "3")]
    pub blob: ::prost::alloc::vec::Vec<u8>,
}

/// Answer to a [`ConfigPrepare`]. A refusal here is SEMANTIC (the
/// follower could not stage the blob: unknown field, hash mismatch,
/// store failure) and aborts the round fleet-wide (AC #5).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigPrepareAck {
    /// Whether the generation is staged and can be committed.
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    /// Empty when accepted; otherwise names the cause without embedding
    /// configuration values.
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}

/// Phase two: apply the staged generation.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigCommit {
    /// The generation to apply (must match the staged one).
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

/// The follower applied a generation.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigCommitAck {
    /// What the follower now runs.
    #[prost(uint64, tag = "1")]
    pub applied_generation: u64,
    /// Canonical hash of what the follower now runs.
    #[prost(string, tag = "2")]
    pub applied_hash: ::prost::alloc::string::String,
}

/// Drop a staged generation (another follower rejected it).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigAbort {
    /// The staged generation to drop.
    #[prost(uint64, tag = "1")]
    pub generation: u64,
}

/// Abort acknowledged.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigAbortAck {}

/// Convergence pull (AC #7), follower to control plane: "this is what
/// I run; send me the current generation if it differs".
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigPull {
    /// The generation the follower runs.
    #[prost(uint64, tag = "1")]
    pub applied_generation: u64,
    /// Canonical hash of what the follower runs.
    #[prost(string, tag = "2")]
    pub applied_hash: ::prost::alloc::string::String,
}

/// Answer to a [`ConfigPull`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigPullAck {
    /// The control plane's current generation.
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    /// Canonical hash of the current generation.
    #[prost(string, tag = "2")]
    pub hash: ::prost::alloc::string::String,
    /// The canonical blob; empty when `up_to_date`.
    #[prost(bytes = "vec", tag = "3")]
    pub blob: ::prost::alloc::vec::Vec<u8>,
    /// `true` when the follower already holds the current generation
    /// and nothing needs to transfer.
    #[prost(bool, tag = "4")]
    pub up_to_date: bool,
}

/// One certificate's material as it travels on the wire (Story 9.5
/// AC #7).
///
/// The in-crate twin is [`crate::certs::CertBundle`], exactly as
/// [`ConfigPrepare`] is the wire twin of
/// [`crate::replication::ConfigPayload`]: peer-supplied strings are
/// bounded once, at the bridge, and only the validated form travels
/// further in.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertMaterial {
    /// The certificate's stable id (its `certificates.id`).
    #[prost(string, tag = "1")]
    pub cert_id: ::prost::alloc::string::String,
    /// The primary hostname the certificate binds to. Display and
    /// diagnostics only; never an authorization input.
    #[prost(string, tag = "2")]
    pub domain: ::prost::alloc::string::String,
    /// PEM leaf plus chain.
    #[prost(string, tag = "3")]
    pub cert_pem: ::prost::alloc::string::String,
    /// PEM private key, in the clear INSIDE the mutual-TLS channel
    /// (Story 9.5 D5: that channel is the confidentiality boundary,
    /// because no per-node public key exists to wrap a key to). Never
    /// logged, never echoed in a refusal reason.
    #[prost(string, tag = "4")]
    pub key_pem: ::prost::alloc::string::String,
    /// `sha256:<lowercase hex>` of `key_pem`, the same shape the
    /// canonical blob carries, so a follower can verify what arrived
    /// matches what the configuration announced before writing it.
    #[prost(string, tag = "5")]
    pub key_digest: ::prost::alloc::string::String,
}

/// Longest a telemetry batch may be in either row list.
///
/// A follower drains its shared store on a timer, so a batch is one
/// interval of traffic, not a backlog. The cap bounds the frame well
/// under the transport limit and bounds what a peer can make the
/// control plane allocate before its quota (AC #8) even runs.
pub const MAX_TELEMETRY_ROWS: usize = 512;

/// Longest a ban snapshot may be.
///
/// Bans are an in-memory map on each node (decision D3), and a node
/// with more live bans than this has a problem the fleet view is not
/// going to help with.
pub const MAX_TELEMETRY_BANS: usize = 256;

/// Longest display field a fanned-in audit row may carry.
///
/// The local writer bounds nothing, because a local row's fields come
/// from this node's own session and request. A fanned-in row's come
/// from another machine, and every other peer-supplied string in this
/// crate is bounded where it is decoded.
pub const MAX_AUDIT_FIELD_BYTES: usize = 512;

/// Whether a fanned-in audit row is malformed, and how
/// (Story 9.9, the decode boundary).
///
/// Applied at the bridge like `config_hash_is_valid` and
/// `challenge_defect`, and for the same reason: these eleven strings
/// ride from another machine into a table an operator reads and a
/// retention pass deletes by. Unbounded, they are a disk-growth vector
/// that no quota can price; unvalidated, the two chain hashes are the
/// one field whose shape is exactly known and worth refusing.
///
/// Returns `None` when the row is acceptable.
#[must_use]
pub fn telemetry_audit_row_defect(row: &TelemetryAuditRow) -> Option<&'static str> {
    // The origin's own rowid. Zero is the LOCAL-row marker on the
    // receiving side, so a fanned-in row claiming it would be filed as
    // one of the control plane's own.
    if row.origin_id == 0 {
        return Some("origin_id is zero, which marks a local row");
    }
    if i64::try_from(row.origin_id).is_err() {
        return Some("origin_id does not fit the column");
    }
    for hash in [&row.prev_chain_hash, &row.chain_hash] {
        if !config_hash_is_valid(hash) {
            return Some("a chain hash is not 64 lowercase hex characters");
        }
    }
    // The payload hashes are empty when absent, hex otherwise.
    for hash in [&row.before_payload_hash, &row.after_payload_hash] {
        if !hash.is_empty() && !config_hash_is_valid(hash) {
            return Some("a payload hash is neither empty nor 64 lowercase hex characters");
        }
    }
    for field in [
        &row.timestamp,
        &row.operator_username,
        &row.operator_role,
        &row.action,
        &row.target_type,
        &row.target_id,
        &row.ip,
        &row.user_agent,
    ] {
        if field.len() > MAX_AUDIT_FIELD_BYTES {
            return Some("an audit field is over its length bound");
        }
        // Control characters reach a table an operator reads and, one
        // careless `warn!` away, a log line.
        if field.chars().any(char::is_control) {
            return Some("an audit field carries a control character");
        }
    }
    if row.timestamp.is_empty() {
        return Some("an audit row carries no timestamp");
    }
    None
}

/// Audit rows one [`TelemetryPush`] may carry (Story 9.9 AC #2).
///
/// Smaller than [`MAX_TELEMETRY_ROWS`] because audit rows are orders
/// of magnitude rarer than access rows: they are written by operator
/// actions, not by traffic. A backlog this size still clears in one
/// drain tick, and the bound is what stops a peer sending an unbounded
/// batch, which is a different concern from the load shedding these
/// rows are exempt from.
pub const MAX_TELEMETRY_AUDIT: usize = 256;

/// One access-log row on its way to the control plane (Story 9.6).
///
/// Mirrors the local `access_logs` columns minus the rowid, which is
/// meaningless on another machine, and minus any node identity: the
/// control plane stamps that from the session (decision D2).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryAccessRow {
    /// RFC 3339 timestamp as the origin node recorded it.
    #[prost(string, tag = "1")]
    pub timestamp: ::prost::alloc::string::String,
    /// HTTP method.
    #[prost(string, tag = "2")]
    pub method: ::prost::alloc::string::String,
    /// Request path.
    #[prost(string, tag = "3")]
    pub path: ::prost::alloc::string::String,
    /// Request host.
    #[prost(string, tag = "4")]
    pub host: ::prost::alloc::string::String,
    /// Response status.
    #[prost(uint32, tag = "5")]
    pub status: u32,
    /// End-to-end latency in milliseconds.
    #[prost(uint64, tag = "6")]
    pub latency_ms: u64,
    /// Backend that served it.
    #[prost(string, tag = "7")]
    pub backend: ::prost::alloc::string::String,
    /// Error text, empty when there was none.
    #[prost(string, tag = "8")]
    pub error: ::prost::alloc::string::String,
    /// Client address as the origin node resolved it.
    #[prost(string, tag = "9")]
    pub client_ip: ::prost::alloc::string::String,
    /// Whether `client_ip` came from a forwarded header.
    #[prost(bool, tag = "10")]
    pub is_xff: bool,
    /// The proxy that supplied the forwarded header.
    #[prost(string, tag = "11")]
    pub xff_proxy_ip: ::prost::alloc::string::String,
    /// Origin marker the local row carries.
    #[prost(string, tag = "12")]
    pub source: ::prost::alloc::string::String,
    /// Correlation id, matching the trace when tracing is on.
    #[prost(string, tag = "13")]
    pub request_id: ::prost::alloc::string::String,
}

/// One WAF event on its way to the control plane (Story 9.6).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryWafRow {
    /// Rule that matched.
    #[prost(uint32, tag = "1")]
    pub rule_id: u32,
    /// Human-readable rule description.
    #[prost(string, tag = "2")]
    pub description: ::prost::alloc::string::String,
    /// Rule category.
    #[prost(string, tag = "3")]
    pub category: ::prost::alloc::string::String,
    /// Rule severity.
    #[prost(uint32, tag = "4")]
    pub severity: u32,
    /// Which part of the request matched.
    #[prost(string, tag = "5")]
    pub matched_field: ::prost::alloc::string::String,
    /// The matching value, already truncated by the origin node.
    #[prost(string, tag = "6")]
    pub matched_value: ::prost::alloc::string::String,
    /// RFC 3339 timestamp as the origin node recorded it.
    #[prost(string, tag = "7")]
    pub timestamp: ::prost::alloc::string::String,
    /// Client address.
    #[prost(string, tag = "8")]
    pub client_ip: ::prost::alloc::string::String,
    /// Route hostname the event fired on.
    #[prost(string, tag = "9")]
    pub route_hostname: ::prost::alloc::string::String,
    /// What the WAF did.
    #[prost(string, tag = "10")]
    pub action: ::prost::alloc::string::String,
}

/// One live ban, as a snapshot (Story 9.6 AC #10, decision D3).
///
/// Bans have no table: they are an in-memory map rebuilt from nothing
/// on restart, so this is a periodic snapshot for visibility and is
/// lossy across a restart by construction.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryBan {
    /// The banned client address.
    #[prost(string, tag = "1")]
    pub client_ip: ::prost::alloc::string::String,
    /// Seconds left on the ban when the snapshot was taken.
    #[prost(uint64, tag = "2")]
    pub remaining_s: u64,
    /// Why it was banned (`BanReason::as_str`).
    #[prost(string, tag = "3")]
    pub reason: ::prost::alloc::string::String,
}

/// One audit row as the ORIGIN node wrote it (Story 9.9 AC #2).
///
/// Both chain hashes ride verbatim and the control plane stores them
/// unchanged. Nothing recomputes them: the aggregated copy is worth
/// something only if it is byte-identical to what the node published
/// on its own `lorica::audit` stream, which is the out-of-band anchor
/// the whole feature leans on.
///
/// No node identity in the payload, like every other fanned-in row.
/// The control plane stamps it from the mutual-TLS session, so a
/// follower cannot write rows into another node's history.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryAuditRow {
    /// The row id the origin node assigned.
    #[prost(uint64, tag = "1")]
    pub origin_id: u64,
    /// RFC 3339 UTC timestamp of the mutation.
    #[prost(string, tag = "2")]
    pub timestamp: ::prost::alloc::string::String,
    /// RBAC username of the operator.
    #[prost(string, tag = "3")]
    pub operator_username: ::prost::alloc::string::String,
    /// RBAC role at mutation time.
    #[prost(string, tag = "4")]
    pub operator_role: ::prost::alloc::string::String,
    /// Dotted action verb.
    #[prost(string, tag = "5")]
    pub action: ::prost::alloc::string::String,
    /// Entity kind.
    #[prost(string, tag = "6")]
    pub target_type: ::prost::alloc::string::String,
    /// Entity id.
    #[prost(string, tag = "7")]
    pub target_id: ::prost::alloc::string::String,
    /// SHA-256 hex of the pre-mutation payload, empty when absent.
    #[prost(string, tag = "8")]
    pub before_payload_hash: ::prost::alloc::string::String,
    /// SHA-256 hex of the post-mutation payload, empty when absent.
    #[prost(string, tag = "9")]
    pub after_payload_hash: ::prost::alloc::string::String,
    /// Source IP.
    #[prost(string, tag = "10")]
    pub ip: ::prost::alloc::string::String,
    /// Client User-Agent.
    #[prost(string, tag = "11")]
    pub user_agent: ::prost::alloc::string::String,
    /// The origin's `prev_chain_hash`, verbatim.
    #[prost(string, tag = "12")]
    pub prev_chain_hash: ::prost::alloc::string::String,
    /// The origin's `chain_hash`, verbatim.
    #[prost(string, tag = "13")]
    pub chain_hash: ::prost::alloc::string::String,
}

/// A batch of telemetry (Story 9.6 AC #5), follower to control plane.
///
/// Upwards only: a control plane sending one is inverting the fan-in
/// and is a `PROTOCOL_VIOLATION`.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryPush {
    /// Access-log rows, at most [`MAX_TELEMETRY_ROWS`].
    #[prost(message, repeated, tag = "1")]
    pub access: ::prost::alloc::vec::Vec<TelemetryAccessRow>,
    /// WAF events, at most [`MAX_TELEMETRY_ROWS`].
    #[prost(message, repeated, tag = "2")]
    pub waf: ::prost::alloc::vec::Vec<TelemetryWafRow>,
    /// Live bans, at most [`MAX_TELEMETRY_BANS`].
    #[prost(message, repeated, tag = "3")]
    pub bans: ::prost::alloc::vec::Vec<TelemetryBan>,
    /// The sender's own rowid for the last access row in this batch.
    /// Opaque to the control plane, which only echoes it back.
    #[prost(uint64, tag = "4")]
    pub access_cursor: u64,
    /// The same for the last WAF event.
    #[prost(uint64, tag = "5")]
    pub waf_cursor: u64,
    /// Rows the follower dropped since its last push, for the gauge.
    #[prost(uint64, tag = "6")]
    pub dropped_since_last: u64,
    /// Audit rows, at most [`MAX_TELEMETRY_AUDIT`] (Story 9.9 AC #2).
    ///
    /// Counted against the ingest quota but never shed by it. Losing
    /// an access row costs a line of traffic; losing an audit row
    /// costs the record of an operator action, on the one table whose
    /// entire purpose is that the record exists. A compliance feature
    /// that drops rows silently under load is worse than one that does
    /// not exist, because it is believed.
    #[prost(message, repeated, tag = "7")]
    pub audit: ::prost::alloc::vec::Vec<TelemetryAuditRow>,
    /// The sender's own rowid for the last audit row in this batch.
    #[prost(uint64, tag = "8")]
    pub audit_cursor: u64,
}

/// What the control plane stored (Story 9.6).
///
/// `accepted_*` may be lower than what was sent when a quota shed
/// part of the batch; a non-zero `retry_after_s` tells the node to
/// back off (AC #8).
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct TelemetryPushAck {
    /// Access rows written.
    #[prost(uint64, tag = "1")]
    pub accepted_access: u64,
    /// WAF events written.
    #[prost(uint64, tag = "2")]
    pub accepted_waf: u64,
    /// Bans recorded.
    #[prost(uint64, tag = "3")]
    pub accepted_bans: u64,
    /// Seconds to wait before pushing again; `0` means carry on.
    #[prost(uint32, tag = "4")]
    pub retry_after_s: u32,
    /// The access cursor from the request, echoed unmodified.
    #[prost(uint64, tag = "5")]
    pub access_cursor: u64,
    /// The WAF cursor from the request, echoed unmodified.
    #[prost(uint64, tag = "6")]
    pub waf_cursor: u64,
    /// Audit rows written. Equals what was sent, or the push failed:
    /// unlike the other three, these are never partially accepted.
    #[prost(uint64, tag = "7")]
    pub accepted_audit: u64,
    /// The audit cursor from the request, echoed unmodified.
    #[prost(uint64, tag = "8")]
    pub audit_cursor: u64,
}

/// A fleet-wide ban (Story 9.6 AC #10), control plane to follower.
///
/// Operator-issued only. Automatic per-node auto-ban is NOT
/// replicated: it is a local reflex to local traffic, and replicating
/// it would turn one node's false positive into a fleet-wide outage
/// for that client.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct BanPush {
    /// Address to ban.
    #[prost(string, tag = "1")]
    pub client_ip: ::prost::alloc::string::String,
    /// How long the ban lasts, in seconds.
    #[prost(uint64, tag = "2")]
    pub duration_s: u64,
    /// Reason recorded on the node.
    #[prost(string, tag = "3")]
    pub reason: ::prost::alloc::string::String,
}

/// Whether the node applied the fleet-wide ban.
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct BanPushAck {
    /// `true` when the ban is now live on this node.
    #[prost(bool, tag = "1")]
    pub applied: bool,
}

/// Certificate distribution (Story 9.5 AC #7), control plane to
/// follower: install this material now, independently of any
/// configuration commit.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertPush {
    /// The batch, at most [`crate::certs::MAX_CERT_BUNDLES`] entries.
    #[prost(message, repeated, tag = "1")]
    pub bundles: ::prost::alloc::vec::Vec<CertMaterial>,
}

/// One certificate a follower would not or could not install.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertRefusal {
    /// The certificate that was refused.
    #[prost(string, tag = "1")]
    pub cert_id: ::prost::alloc::string::String,
    /// Why, without echoing key material; bounded by
    /// [`crate::replication::safe_reason`] before it reaches a report.
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}

/// What a follower did with a [`CertPush`].
///
/// A push is best effort by Story 9.5 D2: a refusal here is recorded
/// and logged, never fatal, and the follower converges on the pull
/// path instead.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertPushAck {
    /// Certificate ids now installed with a usable key.
    #[prost(string, repeated, tag = "1")]
    pub installed: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Certificates refused or failed.
    #[prost(message, repeated, tag = "2")]
    pub refused: ::prost::alloc::vec::Vec<CertRefusal>,
}

/// Certificate convergence pull (Story 9.5 AC #8), follower to control
/// plane: "I count these certificates as missing a usable key".
///
/// The list is peer-supplied and is a REQUEST, never an authorization
/// input: the control plane resolves entitlement itself and may answer
/// with fewer bundles than were asked for, or none.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertPull {
    /// The ids the follower lacks, at most
    /// [`crate::certs::MAX_CERT_PULL_IDS`] entries.
    #[prost(string, repeated, tag = "1")]
    pub cert_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

/// Answer to a [`CertPull`]: the subset the node is entitled to.
#[derive(Clone, PartialEq, prost::Message)]
pub struct CertPullAck {
    /// The material, at most [`crate::certs::MAX_CERT_BUNDLES`]
    /// entries.
    #[prost(message, repeated, tag = "1")]
    pub bundles: ::prost::alloc::vec::Vec<CertMaterial>,
}

/// An HTTP-01 challenge token to serve (Story 9.5 AC #6), control
/// plane to follower.
///
/// # There is deliberately NO expiry field, and adding one is a bug
///
/// The follower stamps its own deadline from its OWN clock when it
/// writes the entry. An expiry on the wire would be a timestamp taken
/// on the control plane's clock and evaluated on the follower's: a
/// skew either way produces a token that is already expired the moment
/// it arrives, or one that outlives the validation window on a node
/// nobody is looking at. Neither failure is visible at the point it is
/// caused. A duration would have the same problem in transit. The
/// window is short and identical on every node, so the node that owns
/// the clock owns the deadline.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengePublish {
    /// The per-SAN hostname being validated, NOT the order's primary
    /// domain: node selection is per hostname.
    #[prost(string, tag = "1")]
    pub identifier: ::prost::alloc::string::String,
    /// The challenge token, base64url (RFC 8555 section 8.3). It
    /// becomes the last path segment of
    /// `/.well-known/acme-challenge/<token>`, which is why its
    /// alphabet is checked and not merely its length.
    #[prost(string, tag = "2")]
    pub token: ::prost::alloc::string::String,
    /// The key authorization the node serves for that token: the token
    /// joined to the account key's JWK thumbprint.
    #[prost(string, tag = "3")]
    pub key_authorization: ::prost::alloc::string::String,
}

/// The follower is serving the token. An error is a REFUSAL status,
/// not a field: the caller aborts the order on anything but this
/// acknowledgement.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengePublishAck {}

/// Stop serving a token (Story 9.5 AC #6), control plane to follower.
///
/// The token alone identifies the entry; the follower needs neither
/// the identifier nor the key authorization to delete it, and sending
/// them again would put a second copy of the key authorization on the
/// wire for no gain.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengeRetract {
    /// The token to stop serving.
    #[prost(string, tag = "1")]
    pub token: ::prost::alloc::string::String,
}

/// Retraction acknowledged. Retraction is best effort by contract: the
/// entry's own deadline removes it on a node that never answered.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ChallengeRetractAck {}

/// `body_kind` value of a [`Hello`] request (its oneof tag).
pub const BODY_KIND_HELLO: u32 = 10;
/// `body_kind` value of a [`Heartbeat`] request (its oneof tag).
pub const BODY_KIND_HEARTBEAT: u32 = 11;
/// `body_kind` value of an [`Enroll`] request (its oneof tag).
pub const BODY_KIND_ENROLL: u32 = 12;
/// `body_kind` value of a [`Renew`] request (its oneof tag).
pub const BODY_KIND_RENEW: u32 = 13;
/// `body_kind` value of a [`Leave`] request (its oneof tag).
pub const BODY_KIND_LEAVE: u32 = 14;
/// `body_kind` value of a [`ConfigPrepare`] request (its oneof tag).
pub const BODY_KIND_CONFIG_PREPARE: u32 = 20;
/// `body_kind` value of a [`ConfigCommit`] request (its oneof tag).
pub const BODY_KIND_CONFIG_COMMIT: u32 = 21;
/// `body_kind` value of a [`ConfigAbort`] request (its oneof tag).
pub const BODY_KIND_CONFIG_ABORT: u32 = 22;
/// `body_kind` value of a [`ConfigPull`] request (its oneof tag).
pub const BODY_KIND_CONFIG_PULL: u32 = 23;
/// `body_kind` value of a [`TelemetryPush`] request (its oneof tag).
pub const BODY_KIND_TELEMETRY_PUSH: u32 = 40;
/// `body_kind` value of a [`BanPush`] request (its oneof tag).
pub const BODY_KIND_BAN_PUSH: u32 = 41;
/// `body_kind` value of a [`CertPush`] request (its oneof tag).
pub const BODY_KIND_CERT_PUSH: u32 = 60;
/// `body_kind` value of a [`CertPull`] request (its oneof tag).
pub const BODY_KIND_CERT_PULL: u32 = 61;
/// `body_kind` value of a [`ChallengePublish`] request (its oneof tag).
pub const BODY_KIND_CHALLENGE_PUBLISH: u32 = 62;
/// `body_kind` value of a [`ChallengeRetract`] request (its oneof tag).
pub const BODY_KIND_CHALLENGE_RETRACT: u32 = 63;

/// Longest configuration hash any message may carry: a SHA-256 in
/// lowercase hex.
pub const MAX_CONFIG_HASH_BYTES: usize = 64;

/// Whether a peer-supplied configuration hash has the expected shape:
/// at most [`MAX_CONFIG_HASH_BYTES`] lowercase hexadecimal characters.
/// The empty string is valid (generation 0, nothing applied). Checked
/// at every decode boundary before the value can reach a log line, a
/// registry entry or a comparison.
pub fn config_hash_is_valid(hash: &str) -> bool {
    hash.len() <= MAX_CONFIG_HASH_BYTES
        && hash
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Prefix every key digest carries, matching what the canonical blob
/// writes in place of a secret.
pub const CERT_DIGEST_PREFIX: &str = "sha256:";

/// Longest certificate id any message may carry. Ids are UUIDs (36
/// characters); the margin covers a future scheme without letting a
/// peer name a certificate with a paragraph.
pub const MAX_CERT_ID_BYTES: usize = 64;

/// Longest hostname a certificate bundle may announce: the DNS limit.
pub const MAX_CERT_DOMAIN_BYTES: usize = 253;

/// Whether a peer-supplied key digest has the shape the canonical blob
/// uses: [`CERT_DIGEST_PREFIX`] followed by exactly
/// [`MAX_CONFIG_HASH_BYTES`] lowercase hexadecimal characters.
///
/// Unlike [`config_hash_is_valid`] the empty string is NOT valid: a
/// bundle with no digest cannot be checked against the configuration
/// that announced it, which is the whole point of carrying one.
pub fn cert_digest_is_valid(digest: &str) -> bool {
    match digest.strip_prefix(CERT_DIGEST_PREFIX) {
        Some(hex) => hex.len() == MAX_CONFIG_HASH_BYTES && config_hash_is_valid(hex),
        None => false,
    }
}

/// Whether a peer-supplied certificate id is acceptable: non-empty, at
/// most [`MAX_CERT_ID_BYTES`], no control characters. The id reaches a
/// log line, a report and a store lookup.
pub fn cert_id_is_valid(cert_id: &str) -> bool {
    !cert_id.is_empty()
        && cert_id.len() <= MAX_CERT_ID_BYTES
        && !cert_id.chars().any(char::is_control)
}

/// Whether a peer-supplied certificate hostname is acceptable:
/// non-empty, at most [`MAX_CERT_DOMAIN_BYTES`], no control
/// characters.
pub fn cert_domain_is_valid(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= MAX_CERT_DOMAIN_BYTES
        && !domain.chars().any(char::is_control)
}

/// Longest HTTP-01 challenge token any message may carry. A real one
/// is base64url of at least 128 bits of entropy, so around 43
/// characters; the cap is generous enough to survive a CA that uses
/// more entropy and finite enough that a peer cannot name a token with
/// a paragraph.
pub const MAX_CHALLENGE_TOKEN_BYTES: usize = 128;

/// Longest key authorization any message may carry. It is the token
/// joined to a base64url JWK thumbprint, so a little over twice a
/// token; the cap keeps the same generous margin.
pub const MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES: usize = 256;

/// Whether `b` is in the base64url alphabet (RFC 4648 section 5, the
/// unpadded form ACME uses).
fn is_base64url(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_')
}

/// Longest a ban target may be: an IPv6 address with a zone id has
/// room here, and nothing legitimate is longer.
pub const MAX_BAN_TARGET_BYTES: usize = 64;

/// Longest a ban reason may be.
pub const MAX_BAN_REASON_BYTES: usize = 64;

/// Whether a peer-supplied ban target is acceptable (Story 9.6).
///
/// The value becomes a key in the data-plane ban map, which the
/// request path consults on every request, and reaches the `/bans`
/// API. It must parse as an IP address: a ban on something that is
/// not an address can never match a client and would sit in the map
/// forever, and accepting arbitrary text here would let a control
/// plane write log lines through a follower.
pub fn ban_target_is_valid(client_ip: &str) -> bool {
    !client_ip.is_empty()
        && client_ip.len() <= MAX_BAN_TARGET_BYTES
        && client_ip.parse::<std::net::IpAddr>().is_ok()
}

/// Longest a fleet-wide ban may last: a day.
///
/// Bounded HERE as well as at the API, because this file's rule is
/// that a peer-supplied quantity is bounded at the decode boundary or
/// nowhere. `duration_s` was the one field on this message that took
/// the API's word for it.
pub const MAX_BAN_DURATION_S: u64 = 24 * 3600;

/// Whether a peer-supplied ban duration is acceptable (Story 9.6):
/// non-zero and at most [`MAX_BAN_DURATION_S`].
pub fn ban_duration_is_valid(duration_s: u64) -> bool {
    duration_s > 0 && duration_s <= MAX_BAN_DURATION_S
}

/// Whether a peer-supplied ban reason is acceptable (Story 9.6):
/// non-empty, bounded, and free of control characters, since it
/// reaches a log line and a JSON response.
pub fn ban_reason_is_valid(reason: &str) -> bool {
    !reason.is_empty()
        && reason.len() <= MAX_BAN_REASON_BYTES
        && !reason.chars().any(char::is_control)
}

/// Whether a peer-supplied challenge token is acceptable: non-empty,
/// at most [`MAX_CHALLENGE_TOKEN_BYTES`], base64url alphabet only.
///
/// The alphabet is checked rather than just the control characters,
/// and it is the stricter rule on purpose. RFC 8555 section 8.3 makes
/// base64url normative, and the token becomes the last path segment of
/// `/.well-known/acme-challenge/<token>` and a primary key in the
/// challenge table. A token carrying `/` or `.` is a path-traversal
/// shape reaching a filesystem-adjacent name, and no legitimate CA
/// produces one.
pub fn challenge_token_is_valid(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_CHALLENGE_TOKEN_BYTES
        && token.bytes().all(is_base64url)
}

/// Whether a peer-supplied key authorization is acceptable: non-empty,
/// at most [`MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES`], base64url
/// alphabet plus the `.` that joins the token to the thumbprint.
///
/// The value is served verbatim as an HTTP response body, so the same
/// argument as [`challenge_token_is_valid`] applies: what a node will
/// hand to an unauthenticated caller is bounded here or nowhere.
pub fn challenge_key_authorization_is_valid(key_authorization: &str) -> bool {
    !key_authorization.is_empty()
        && key_authorization.len() <= MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES
        && key_authorization
            .bytes()
            .all(|b| is_base64url(b) || b == b'.')
}

/// A request from either side of the cluster plane.
///
/// Body tags: 10-19 session control (Story 9.2) and lifecycle
/// (Story 9.3), 20-39 configuration replication (Story 9.4: 20-23 in
/// use, 24-39 reserved), 40-59 telemetry fan-in (Story 9.6: 40-41 in
/// use, 42-59 reserved), 60-79 certificate distribution and HTTP-01 challenge
/// fan-out (Story 9.5: 60-63 in use, 64-79 reserved).
///
/// `body_kind` duplicates the body's oneof tag as a scalar so a
/// receiver that does NOT know the body (an older build talking to a
/// newer peer) can still tell "a method I do not implement" (answer
/// `UNSUPPORTED_METHOD`, keep the connection) from "no body at all"
/// (protocol violation, drop). prost decodes an unknown oneof tag as an
/// unknown field, leaving `body = None`; without the scalar the two
/// cases are indistinguishable and the wire format would freeze at
/// this release.
///
/// # Invariant
///
/// When a body IS present, `body_kind` MUST equal that body's oneof
/// tag. The constructors guarantee it on the sending side; every
/// decode boundary (the handshake opener and the bridge) checks it
/// with [`ClusterRequest::body_kind_matches`] and treats a mismatch as
/// a `PROTOCOL_VIOLATION`, so the scalar can never be used to make the
/// two readings of one request disagree.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterRequest {
    /// Monotonic per direction, managed by `RpcEndpoint`.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// The body's oneof tag, set by the constructors; `0` means the
    /// sender put no body at all.
    #[prost(uint32, tag = "3")]
    pub body_kind: u32,
    /// Typed request body.
    #[prost(
        oneof = "cluster_request::Body",
        tags = "10, 11, 12, 13, 14, 20, 21, 22, 23, 40, 41, 60, 61, 62, 63"
    )]
    pub body: ::core::option::Option<cluster_request::Body>,
}

/// Typed body variants for [`ClusterRequest`].
pub mod cluster_request {
    use super::{
        BanPush, CertPull, CertPush, ChallengePublish, ChallengeRetract, ConfigAbort, ConfigCommit,
        ConfigPrepare, ConfigPull, Enroll, Heartbeat, Hello, Leave, Renew, TelemetryPush,
    };

    /// Request payloads (see the tag-range note on `ClusterRequest`).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        /// Session opener (post-TLS on the operational path).
        #[prost(message, tag = "10")]
        Hello(Hello),
        /// Liveness probe.
        #[prost(message, tag = "11")]
        Heartbeat(Heartbeat),
        /// Token redemption (enrollment listener only).
        #[prost(message, tag = "12")]
        Enroll(Enroll),
        /// Certificate renewal (established session).
        #[prost(message, tag = "13")]
        Renew(Renew),
        /// Leaving the fleet (established session).
        #[prost(message, tag = "14")]
        Leave(Leave),
        /// Stage a configuration generation (control plane to
        /// follower, Story 9.4).
        #[prost(message, tag = "20")]
        ConfigPrepare(ConfigPrepare),
        /// Apply the staged generation.
        #[prost(message, tag = "21")]
        ConfigCommit(ConfigCommit),
        /// Drop the staged generation.
        #[prost(message, tag = "22")]
        ConfigAbort(ConfigAbort),
        /// Convergence pull (follower to control plane).
        #[prost(message, tag = "23")]
        ConfigPull(ConfigPull),
        /// A batch of telemetry (follower to control plane,
        /// Story 9.6). Upwards only: a control plane pushing
        /// telemetry at a follower is inverting the fan-in.
        #[prost(message, tag = "40")]
        TelemetryPush(TelemetryPush),
        /// A fleet-wide ban (control plane to follower, Story 9.6).
        /// Downwards only, and only ever operator-issued: automatic
        /// per-node auto-ban stays local.
        #[prost(message, tag = "41")]
        BanPush(BanPush),
        /// Certificate material (control plane to follower,
        /// Story 9.5). It travels DOWNWARDS only: a follower sending
        /// one is pushing private keys at its control plane.
        #[prost(message, tag = "60")]
        CertPush(CertPush),
        /// A follower asks for certificates it lacks (Story 9.5); the
        /// mirror image, upwards only.
        #[prost(message, tag = "61")]
        CertPull(CertPull),
        /// An HTTP-01 token to serve (control plane to follower,
        /// Story 9.5). Downwards only: a follower that publishes a
        /// challenge to its control plane is choosing what the fleet
        /// answers a certificate authority.
        #[prost(message, tag = "62")]
        ChallengePublish(ChallengePublish),
        /// Stop serving a token (control plane to follower); downwards
        /// only for the same reason.
        #[prost(message, tag = "63")]
        ChallengeRetract(ChallengeRetract),
    }

    impl Body {
        /// The oneof tag of this body, for `ClusterRequest::body_kind`.
        pub fn kind(&self) -> u32 {
            match self {
                Body::Hello(_) => super::BODY_KIND_HELLO,
                Body::Heartbeat(_) => super::BODY_KIND_HEARTBEAT,
                Body::Enroll(_) => super::BODY_KIND_ENROLL,
                Body::Renew(_) => super::BODY_KIND_RENEW,
                Body::Leave(_) => super::BODY_KIND_LEAVE,
                Body::ConfigPrepare(_) => super::BODY_KIND_CONFIG_PREPARE,
                Body::ConfigCommit(_) => super::BODY_KIND_CONFIG_COMMIT,
                Body::ConfigAbort(_) => super::BODY_KIND_CONFIG_ABORT,
                Body::ConfigPull(_) => super::BODY_KIND_CONFIG_PULL,
                Body::TelemetryPush(_) => super::BODY_KIND_TELEMETRY_PUSH,
                Body::BanPush(_) => super::BODY_KIND_BAN_PUSH,
                Body::CertPush(_) => super::BODY_KIND_CERT_PUSH,
                Body::CertPull(_) => super::BODY_KIND_CERT_PULL,
                Body::ChallengePublish(_) => super::BODY_KIND_CHALLENGE_PUBLISH,
                Body::ChallengeRetract(_) => super::BODY_KIND_CHALLENGE_RETRACT,
            }
        }
    }
}

impl ClusterRequest {
    /// A request carrying `body`, with `body_kind` set to match. The
    /// sequence is stamped by `RpcEndpoint` on send.
    pub fn with_body(body: cluster_request::Body) -> Self {
        Self {
            sequence: 0,
            body_kind: body.kind(),
            body: Some(body),
        }
    }

    /// A session opener.
    pub fn hello(hello: Hello) -> Self {
        Self::with_body(cluster_request::Body::Hello(hello))
    }

    /// A liveness probe.
    pub fn heartbeat(heartbeat: Heartbeat) -> Self {
        Self::with_body(cluster_request::Body::Heartbeat(heartbeat))
    }

    /// A token redemption (enrollment listener).
    pub fn enroll(enroll: Enroll) -> Self {
        Self::with_body(cluster_request::Body::Enroll(enroll))
    }

    /// A certificate renewal.
    pub fn renew(renew: Renew) -> Self {
        Self::with_body(cluster_request::Body::Renew(renew))
    }

    /// A leave announcement.
    pub fn leave() -> Self {
        Self::with_body(cluster_request::Body::Leave(Leave {}))
    }

    /// Phase one of a configuration push (Story 9.4).
    pub fn config_prepare(prepare: ConfigPrepare) -> Self {
        Self::with_body(cluster_request::Body::ConfigPrepare(prepare))
    }

    /// Phase two: apply the staged generation.
    pub fn config_commit(generation: u64) -> Self {
        Self::with_body(cluster_request::Body::ConfigCommit(ConfigCommit {
            generation,
        }))
    }

    /// Drop a staged generation.
    pub fn config_abort(generation: u64) -> Self {
        Self::with_body(cluster_request::Body::ConfigAbort(ConfigAbort { generation }))
    }

    /// A convergence pull from a follower.
    pub fn config_pull(pull: ConfigPull) -> Self {
        Self::with_body(cluster_request::Body::ConfigPull(pull))
    }

    /// A telemetry batch (Story 9.6), follower to control plane.
    pub fn telemetry_push(push: TelemetryPush) -> Self {
        Self::with_body(cluster_request::Body::TelemetryPush(push))
    }

    /// A fleet-wide ban (Story 9.6), control plane to follower.
    pub fn ban_push(push: BanPush) -> Self {
        Self::with_body(cluster_request::Body::BanPush(push))
    }

    /// A certificate push (Story 9.5), control plane to follower.
    pub fn cert_push(push: CertPush) -> Self {
        Self::with_body(cluster_request::Body::CertPush(push))
    }

    /// A certificate pull (Story 9.5), follower to control plane.
    pub fn cert_pull(pull: CertPull) -> Self {
        Self::with_body(cluster_request::Body::CertPull(pull))
    }

    /// An HTTP-01 challenge publication (Story 9.5), control plane to
    /// follower.
    pub fn challenge_publish(publish: ChallengePublish) -> Self {
        Self::with_body(cluster_request::Body::ChallengePublish(publish))
    }

    /// An HTTP-01 challenge retraction (Story 9.5), control plane to
    /// follower.
    pub fn challenge_retract(token: &str) -> Self {
        Self::with_body(cluster_request::Body::ChallengeRetract(ChallengeRetract {
            token: token.to_string(),
        }))
    }

    /// Whether `body_kind` names a method THIS build implements.
    pub fn is_known_body_kind(body_kind: u32) -> bool {
        matches!(
            body_kind,
            BODY_KIND_HELLO
                | BODY_KIND_HEARTBEAT
                | BODY_KIND_ENROLL
                | BODY_KIND_RENEW
                | BODY_KIND_LEAVE
                | BODY_KIND_CONFIG_PREPARE
                | BODY_KIND_CONFIG_COMMIT
                | BODY_KIND_CONFIG_ABORT
                | BODY_KIND_CONFIG_PULL
                | BODY_KIND_TELEMETRY_PUSH
                | BODY_KIND_BAN_PUSH
                | BODY_KIND_CERT_PUSH
                | BODY_KIND_CERT_PULL
                | BODY_KIND_CHALLENGE_PUBLISH
                | BODY_KIND_CHALLENGE_RETRACT
        )
    }

    /// The invariant every decode boundary enforces: a present body's
    /// oneof tag equals `body_kind`. An absent body always passes
    /// (the scalar alone then decides between "unknown method" and
    /// "no body at all").
    pub fn body_kind_matches(&self) -> bool {
        match &self.body {
            Some(body) => self.body_kind == body.kind(),
            None => true,
        }
    }
}

/// A response matched to a [`ClusterRequest`] by `sequence`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterResponse {
    /// Sequence of the request being answered.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// [`ClusterStatus`] as its wire integer.
    #[prost(int32, tag = "2")]
    pub status: i32,
    /// Only meaningful with [`ClusterStatus::RetryLater`] (AC #10).
    #[prost(uint32, tag = "3")]
    pub retry_after_s: u32,
    /// Typed response body; `None` on refusals.
    #[prost(
        oneof = "cluster_response::Body",
        tags = "10, 11, 12, 13, 14, 20, 21, 22, 23, 40, 41, 60, 61, 62, 63"
    )]
    pub body: ::core::option::Option<cluster_response::Body>,
}

/// Typed body variants for [`ClusterResponse`].
pub mod cluster_response {
    use super::{
        BanPushAck, CertPullAck, CertPushAck, ChallengePublishAck, ChallengeRetractAck,
        ConfigAbortAck, ConfigCommitAck, ConfigPrepareAck, ConfigPullAck, EnrollAck, HeartbeatAck,
        HelloAck, LeaveAck, RenewAck, TelemetryPushAck,
    };

    /// Response payloads (tag ranges mirror `cluster_request::Body`).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        /// Session admitted.
        #[prost(message, tag = "10")]
        HelloAck(HelloAck),
        /// Liveness answer.
        #[prost(message, tag = "11")]
        HeartbeatAck(HeartbeatAck),
        /// Enrollment granted.
        #[prost(message, tag = "12")]
        EnrollAck(EnrollAck),
        /// Certificate renewed.
        #[prost(message, tag = "13")]
        RenewAck(RenewAck),
        /// Leave acknowledged.
        #[prost(message, tag = "14")]
        LeaveAck(LeaveAck),
        /// Prepare verdict (Story 9.4).
        #[prost(message, tag = "20")]
        ConfigPrepareAck(ConfigPrepareAck),
        /// Commit outcome.
        #[prost(message, tag = "21")]
        ConfigCommitAck(ConfigCommitAck),
        /// Abort acknowledged.
        #[prost(message, tag = "22")]
        ConfigAbortAck(ConfigAbortAck),
        /// Pull answer.
        #[prost(message, tag = "23")]
        ConfigPullAck(ConfigPullAck),
        /// What the control plane stored of a telemetry batch, and
        /// whether the node should back off (Story 9.6).
        #[prost(message, tag = "40")]
        TelemetryPushAck(TelemetryPushAck),
        /// Whether the fleet-wide ban was applied (Story 9.6).
        #[prost(message, tag = "41")]
        BanPushAck(BanPushAck),
        /// What the follower did with a pushed batch (Story 9.5).
        #[prost(message, tag = "60")]
        CertPushAck(CertPushAck),
        /// The certificates a follower was entitled to (Story 9.5).
        #[prost(message, tag = "61")]
        CertPullAck(CertPullAck),
        /// The follower is serving the token (Story 9.5).
        #[prost(message, tag = "62")]
        ChallengePublishAck(ChallengePublishAck),
        /// The follower stopped serving the token (Story 9.5).
        #[prost(message, tag = "63")]
        ChallengeRetractAck(ChallengeRetractAck),
    }
}

impl ClusterResponse {
    /// An admitted-or-served response carrying `body`. The sequence is
    /// stamped by `RpcEndpoint::reply_frame` from the request being
    /// answered; constructors never take one.
    pub fn ok(body: cluster_response::Body) -> Self {
        Self {
            sequence: 0,
            status: ClusterStatus::Ok as i32,
            retry_after_s: 0,
            body: Some(body),
        }
    }

    /// A refusal with `status` and no body. Enrollment-path callers
    /// must pass [`ClusterStatus::opaque()`] here (AC #4).
    pub fn refusal(status: ClusterStatus) -> Self {
        Self {
            sequence: 0,
            status: status as i32,
            retry_after_s: 0,
            body: None,
        }
    }

    /// The AC #10 admission-control answer.
    pub fn retry_later(retry_after_s: u32) -> Self {
        Self {
            sequence: 0,
            status: ClusterStatus::RetryLater as i32,
            retry_after_s,
            body: None,
        }
    }

    /// Decoded [`ClusterStatus`] of this response.
    pub fn cluster_status(&self) -> ClusterStatus {
        ClusterStatus::from_i32(self.status)
    }
}

/// Top-level cluster frame.
///
/// The oneof tags are 101/102, deliberately DISJOINT from the worker
/// plane's `Envelope` (tags 1/2): bytes of one frame type decode to an
/// empty frame (`kind = None`) on the other plane, never to a valid
/// message (Story 9.2 AC #6, type-level half; the bridge whitelist is
/// the enforced half).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterFrame {
    /// Request or response.
    #[prost(oneof = "cluster_frame::Kind", tags = "101, 102")]
    pub kind: ::core::option::Option<cluster_frame::Kind>,
}

/// Kind variants for [`ClusterFrame`].
pub mod cluster_frame {
    use super::{ClusterRequest, ClusterResponse};

    /// Request or response (tags 101/102; see the disjointness note).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// A request from the peer.
        #[prost(message, tag = "101")]
        Request(ClusterRequest),
        /// A response to one of our requests.
        #[prost(message, tag = "102")]
        Response(ClusterResponse),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use prost::Message;

    use super::*;

    /// The published wire contract. The Rust types are hand-written
    /// prost derives (no protoc at build time); this test is the drift
    /// gate between the two.
    const PROTO: &str = include_str!("../proto/cluster.proto");

    /// `(block, field) -> tag` for every message field (oneof members
    /// included, attributed to their enclosing message) and enum
    /// value declared in the .proto.
    fn proto_tags() -> HashMap<(String, String), u32> {
        let mut out = HashMap::new();
        let mut block: Option<String> = None;
        let mut depth: usize = 0;
        for raw in PROTO.lines() {
            let line = raw.split("//").next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if depth == 0 {
                if let Some(rest) = line
                    .strip_prefix("message ")
                    .or_else(|| line.strip_prefix("enum "))
                {
                    block = Some(rest.trim_end_matches('{').trim().to_string());
                }
            }
            if let (Some(b), Some((lhs, rhs))) = (&block, line.split_once('=')) {
                if line.ends_with(';') {
                    let name = lhs.split_whitespace().last().expect("field name").to_string();
                    let tag: u32 = rhs
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .parse()
                        .expect("numeric tag");
                    out.insert((b.clone(), name), tag);
                }
            }
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
            if depth == 0 && line.contains('}') {
                block = None;
            }
        }
        out
    }

    fn varint(bytes: &[u8]) -> (u64, usize) {
        let mut value = 0u64;
        let mut shift = 0u32;
        for (i, byte) in bytes.iter().enumerate() {
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return (value, i + 1);
            }
            shift += 7;
        }
        panic!("truncated varint");
    }

    /// The field numbers present in an encoded message, in wire order.
    fn field_numbers(bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let (key, n) = varint(&bytes[i..]);
            i += n;
            out.push((key >> 3) as u32);
            match key & 7 {
                0 => {
                    let (_, n) = varint(&bytes[i..]);
                    i += n;
                }
                1 => i += 8,
                2 => {
                    let (len, n) = varint(&bytes[i..]);
                    i += n + len as usize;
                }
                5 => i += 4,
                other => panic!("unexpected wire type {other}"),
            }
        }
        out
    }

    #[test]
    fn rust_tags_match_the_published_proto() {
        let tags = proto_tags();
        let tag = |block: &str, field: &str| -> u32 {
            *tags
                .get(&(block.to_string(), field.to_string()))
                .unwrap_or_else(|| panic!("{block}.{field} missing from cluster.proto"))
        };

        // Every scalar is non-zero so prost emits it.
        let hello = Hello {
            protocol_min: 1,
            protocol_max: 1,
            schema_version: 1,
            node_name: "n".to_string(),
            build_version: "v".to_string(),
            applied_generation: 1,
            applied_hash: "ab".to_string(),
            break_glass: true,
        };
        assert_eq!(
            field_numbers(&hello.encode_to_vec()),
            vec![
                tag("Hello", "protocol_min"),
                tag("Hello", "protocol_max"),
                tag("Hello", "schema_version"),
                tag("Hello", "node_name"),
                tag("Hello", "build_version"),
                tag("Hello", "applied_generation"),
                tag("Hello", "applied_hash"),
                tag("Hello", "break_glass"),
            ]
        );
        let enroll = Enroll {
            public_id: "p".to_string(),
            secret: vec![1],
            public_key_der: vec![1],
            node_name: "n".to_string(),
            build_version: "v".to_string(),
            schema_version: 1,
        };
        assert_eq!(
            field_numbers(&enroll.encode_to_vec()),
            vec![
                tag("Enroll", "public_id"),
                tag("Enroll", "secret"),
                tag("Enroll", "public_key_der"),
                tag("Enroll", "node_name"),
                tag("Enroll", "build_version"),
                tag("Enroll", "schema_version"),
            ]
        );
        let enroll_ack = EnrollAck {
            node_id: "n".to_string(),
            cert_pem: "c".to_string(),
            ca_pem: "a".to_string(),
            status: "s".to_string(),
            cert_not_after: "t".to_string(),
        };
        assert_eq!(
            field_numbers(&enroll_ack.encode_to_vec()),
            vec![
                tag("EnrollAck", "node_id"),
                tag("EnrollAck", "cert_pem"),
                tag("EnrollAck", "ca_pem"),
                tag("EnrollAck", "status"),
                tag("EnrollAck", "cert_not_after"),
            ]
        );
        assert_eq!(
            field_numbers(
                &Renew {
                    public_key_der: vec![1]
                }
                .encode_to_vec()
            ),
            vec![tag("Renew", "public_key_der")]
        );
        assert_eq!(
            field_numbers(
                &RenewAck {
                    cert_pem: "c".to_string(),
                    cert_not_after: "t".to_string()
                }
                .encode_to_vec()
            ),
            vec![tag("RenewAck", "cert_pem"), tag("RenewAck", "cert_not_after")]
        );
        for (request, block_field) in [
            (ClusterRequest::enroll(Enroll::default()), "enroll"),
            (ClusterRequest::renew(Renew::default()), "renew"),
            (ClusterRequest::leave(), "leave"),
        ] {
            let mut request = request;
            request.sequence = 1;
            assert_eq!(
                *field_numbers(&request.encode_to_vec()).last().expect("body"),
                tag("ClusterRequest", block_field),
                "{block_field}"
            );
            assert_eq!(request.body_kind, tag("ClusterRequest", block_field));
        }
        for (body, block_field) in [
            (cluster_response::Body::EnrollAck(EnrollAck::default()), "enroll_ack"),
            (cluster_response::Body::RenewAck(RenewAck::default()), "renew_ack"),
            (cluster_response::Body::LeaveAck(LeaveAck::default()), "leave_ack"),
        ] {
            let response = ClusterResponse::ok(body);
            assert_eq!(
                *field_numbers(&response.encode_to_vec()).last().expect("body"),
                tag("ClusterResponse", block_field),
                "{block_field}"
            );
        }
        let ack = HelloAck {
            negotiated_version: 1,
            schema_version: 1,
            fleet_size_hint: 1,
            current_generation: 1,
            current_hash: "ab".to_string(),
        };
        assert_eq!(
            field_numbers(&ack.encode_to_vec()),
            vec![
                tag("HelloAck", "negotiated_version"),
                tag("HelloAck", "schema_version"),
                tag("HelloAck", "fleet_size_hint"),
                tag("HelloAck", "current_generation"),
                tag("HelloAck", "current_hash"),
            ]
        );
        assert_eq!(
            field_numbers(
                &Heartbeat {
                    timestamp_ms: 1,
                    applied_generation: 1,
                    applied_hash: "ab".to_string(),
                    break_glass: true,
                    resources: Some(NodeResources {
                        cpu_percent: 1,
                        memory_used_bytes: 1,
                        memory_total_bytes: 1,
                        disk_used_bytes: 1,
                        disk_total_bytes: 1,
                    }),
                }
                .encode_to_vec()
            ),
            vec![
                tag("Heartbeat", "timestamp_ms"),
                tag("Heartbeat", "applied_generation"),
                tag("Heartbeat", "applied_hash"),
                tag("Heartbeat", "break_glass"),
                tag("Heartbeat", "resources"),
            ]
        );
        assert_eq!(
            field_numbers(
                &NodeResources {
                    cpu_percent: 1,
                    memory_used_bytes: 1,
                    memory_total_bytes: 1,
                    disk_used_bytes: 1,
                    disk_total_bytes: 1,
                }
                .encode_to_vec()
            ),
            vec![
                tag("NodeResources", "cpu_percent"),
                tag("NodeResources", "memory_used_bytes"),
                tag("NodeResources", "memory_total_bytes"),
                tag("NodeResources", "disk_used_bytes"),
                tag("NodeResources", "disk_total_bytes"),
            ]
        );
        // An absent sampler must encode as an absent field, not as a
        // present message full of zeros: the dashboard distinguishes
        // "unknown" from "idle" on exactly this.
        assert_eq!(
            field_numbers(
                &Heartbeat {
                    timestamp_ms: 1,
                    applied_generation: 1,
                    applied_hash: "ab".to_string(),
                    break_glass: true,
                    resources: None,
                }
                .encode_to_vec()
            ),
            vec![
                tag("Heartbeat", "timestamp_ms"),
                tag("Heartbeat", "applied_generation"),
                tag("Heartbeat", "applied_hash"),
                tag("Heartbeat", "break_glass"),
            ]
        );
        assert_eq!(
            field_numbers(
                &HeartbeatAck {
                    timestamp_ms: 1,
                    fleet_size_hint: 1,
                    current_generation: 1,
                    current_hash: "ab".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("HeartbeatAck", "timestamp_ms"),
                tag("HeartbeatAck", "fleet_size_hint"),
                tag("HeartbeatAck", "current_generation"),
                tag("HeartbeatAck", "current_hash"),
            ]
        );

        // Story 9.4 replication bodies.
        assert_eq!(
            field_numbers(
                &ConfigPrepare {
                    generation: 1,
                    hash: "ab".to_string(),
                    blob: vec![1],
                }
                .encode_to_vec()
            ),
            vec![
                tag("ConfigPrepare", "generation"),
                tag("ConfigPrepare", "hash"),
                tag("ConfigPrepare", "blob"),
            ]
        );
        assert_eq!(
            field_numbers(
                &ConfigPrepareAck {
                    accepted: true,
                    reason: "r".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("ConfigPrepareAck", "accepted"),
                tag("ConfigPrepareAck", "reason"),
            ]
        );
        assert_eq!(
            field_numbers(&ConfigCommit { generation: 1 }.encode_to_vec()),
            vec![tag("ConfigCommit", "generation")]
        );
        assert_eq!(
            field_numbers(
                &ConfigCommitAck {
                    applied_generation: 1,
                    applied_hash: "ab".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("ConfigCommitAck", "applied_generation"),
                tag("ConfigCommitAck", "applied_hash"),
            ]
        );
        assert_eq!(
            field_numbers(&ConfigAbort { generation: 1 }.encode_to_vec()),
            vec![tag("ConfigAbort", "generation")]
        );
        assert_eq!(
            field_numbers(
                &ConfigPull {
                    applied_generation: 1,
                    applied_hash: "ab".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("ConfigPull", "applied_generation"),
                tag("ConfigPull", "applied_hash"),
            ]
        );
        assert_eq!(
            field_numbers(
                &ConfigPullAck {
                    generation: 1,
                    hash: "ab".to_string(),
                    blob: vec![1],
                    up_to_date: true,
                }
                .encode_to_vec()
            ),
            vec![
                tag("ConfigPullAck", "generation"),
                tag("ConfigPullAck", "hash"),
                tag("ConfigPullAck", "blob"),
                tag("ConfigPullAck", "up_to_date"),
            ]
        );
        for (request, block_field) in [
            (
                ClusterRequest::config_prepare(ConfigPrepare::default()),
                "config_prepare",
            ),
            (ClusterRequest::config_commit(0), "config_commit"),
            (ClusterRequest::config_abort(0), "config_abort"),
            (
                ClusterRequest::config_pull(ConfigPull::default()),
                "config_pull",
            ),
        ] {
            let mut request = request;
            request.sequence = 1;
            assert_eq!(
                *field_numbers(&request.encode_to_vec()).last().expect("body"),
                tag("ClusterRequest", block_field),
                "{block_field}"
            );
            assert_eq!(request.body_kind, tag("ClusterRequest", block_field));
        }
        for (body, block_field) in [
            (
                cluster_response::Body::ConfigPrepareAck(ConfigPrepareAck::default()),
                "config_prepare_ack",
            ),
            (
                cluster_response::Body::ConfigCommitAck(ConfigCommitAck::default()),
                "config_commit_ack",
            ),
            (
                cluster_response::Body::ConfigAbortAck(ConfigAbortAck::default()),
                "config_abort_ack",
            ),
            (
                cluster_response::Body::ConfigPullAck(ConfigPullAck::default()),
                "config_pull_ack",
            ),
        ] {
            let response = ClusterResponse::ok(body);
            assert_eq!(
                *field_numbers(&response.encode_to_vec()).last().expect("body"),
                tag("ClusterResponse", block_field),
                "{block_field}"
            );
        }
        assert_eq!(
            BODY_KIND_CONFIG_PREPARE,
            tag("ClusterRequest", "config_prepare")
        );
        assert_eq!(
            BODY_KIND_CONFIG_COMMIT,
            tag("ClusterRequest", "config_commit")
        );
        assert_eq!(BODY_KIND_CONFIG_ABORT, tag("ClusterRequest", "config_abort"));
        assert_eq!(BODY_KIND_CONFIG_PULL, tag("ClusterRequest", "config_pull"));

        // Story 9.5 certificate-distribution bodies.
        assert_eq!(
            field_numbers(
                &CertMaterial {
                    cert_id: "c".to_string(),
                    domain: "d".to_string(),
                    cert_pem: "p".to_string(),
                    key_pem: "k".to_string(),
                    key_digest: "s".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("CertMaterial", "cert_id"),
                tag("CertMaterial", "domain"),
                tag("CertMaterial", "cert_pem"),
                tag("CertMaterial", "key_pem"),
                tag("CertMaterial", "key_digest"),
            ]
        );
        assert_eq!(
            field_numbers(
                &CertPush {
                    bundles: vec![CertMaterial::default()],
                }
                .encode_to_vec()
            ),
            vec![tag("CertPush", "bundles")]
        );
        assert_eq!(
            field_numbers(
                &CertRefusal {
                    cert_id: "c".to_string(),
                    reason: "r".to_string(),
                }
                .encode_to_vec()
            ),
            vec![tag("CertRefusal", "cert_id"), tag("CertRefusal", "reason")]
        );
        assert_eq!(
            field_numbers(
                &CertPushAck {
                    installed: vec!["c".to_string()],
                    refused: vec![CertRefusal::default()],
                }
                .encode_to_vec()
            ),
            vec![
                tag("CertPushAck", "installed"),
                tag("CertPushAck", "refused"),
            ]
        );
        assert_eq!(
            field_numbers(
                &CertPull {
                    cert_ids: vec!["c".to_string()],
                }
                .encode_to_vec()
            ),
            vec![tag("CertPull", "cert_ids")]
        );
        assert_eq!(
            field_numbers(
                &CertPullAck {
                    bundles: vec![CertMaterial::default()],
                }
                .encode_to_vec()
            ),
            vec![tag("CertPullAck", "bundles")]
        );
        for (request, block_field) in [
            (ClusterRequest::cert_push(CertPush::default()), "cert_push"),
            (ClusterRequest::cert_pull(CertPull::default()), "cert_pull"),
            (
                ClusterRequest::telemetry_push(TelemetryPush::default()),
                "telemetry_push",
            ),
            (ClusterRequest::ban_push(BanPush::default()), "ban_push"),
        ] {
            let mut request = request;
            request.sequence = 1;
            assert_eq!(
                *field_numbers(&request.encode_to_vec()).last().expect("body"),
                tag("ClusterRequest", block_field),
                "{block_field}"
            );
            assert_eq!(request.body_kind, tag("ClusterRequest", block_field));
        }
        for (body, block_field) in [
            (
                cluster_response::Body::CertPushAck(CertPushAck::default()),
                "cert_push_ack",
            ),
            (
                cluster_response::Body::CertPullAck(CertPullAck::default()),
                "cert_pull_ack",
            ),
            (
                cluster_response::Body::TelemetryPushAck(TelemetryPushAck::default()),
                "telemetry_push_ack",
            ),
            (
                cluster_response::Body::BanPushAck(BanPushAck::default()),
                "ban_push_ack",
            ),
        ] {
            let response = ClusterResponse::ok(body);
            assert_eq!(
                *field_numbers(&response.encode_to_vec()).last().expect("body"),
                tag("ClusterResponse", block_field),
                "{block_field}"
            );
        }
        assert_eq!(
            BODY_KIND_TELEMETRY_PUSH,
            tag("ClusterRequest", "telemetry_push")
        );
        assert_eq!(BODY_KIND_BAN_PUSH, tag("ClusterRequest", "ban_push"));
        assert_eq!(BODY_KIND_CERT_PUSH, tag("ClusterRequest", "cert_push"));
        assert_eq!(BODY_KIND_CERT_PULL, tag("ClusterRequest", "cert_pull"));

        // Story 9.5 HTTP-01 challenge fan-out.
        assert_eq!(
            field_numbers(
                &ChallengePublish {
                    identifier: "d".to_string(),
                    token: "t".to_string(),
                    key_authorization: "k".to_string(),
                }
                .encode_to_vec()
            ),
            vec![
                tag("ChallengePublish", "identifier"),
                tag("ChallengePublish", "token"),
                tag("ChallengePublish", "key_authorization"),
            ]
        );
        assert_eq!(
            field_numbers(
                &ChallengeRetract {
                    token: "t".to_string(),
                }
                .encode_to_vec()
            ),
            vec![tag("ChallengeRetract", "token")]
        );
        for (request, block_field) in [
            (
                ClusterRequest::challenge_publish(ChallengePublish::default()),
                "challenge_publish",
            ),
            (ClusterRequest::challenge_retract("t"), "challenge_retract"),
        ] {
            let mut request = request;
            request.sequence = 1;
            assert_eq!(
                *field_numbers(&request.encode_to_vec()).last().expect("body"),
                tag("ClusterRequest", block_field),
                "{block_field}"
            );
            assert_eq!(request.body_kind, tag("ClusterRequest", block_field));
        }
        for (body, block_field) in [
            (
                cluster_response::Body::ChallengePublishAck(ChallengePublishAck {}),
                "challenge_publish_ack",
            ),
            (
                cluster_response::Body::ChallengeRetractAck(ChallengeRetractAck {}),
                "challenge_retract_ack",
            ),
        ] {
            let response = ClusterResponse::ok(body);
            assert_eq!(
                *field_numbers(&response.encode_to_vec()).last().expect("body"),
                tag("ClusterResponse", block_field),
                "{block_field}"
            );
        }
        assert_eq!(
            BODY_KIND_CHALLENGE_PUBLISH,
            tag("ClusterRequest", "challenge_publish")
        );
        assert_eq!(
            BODY_KIND_CHALLENGE_RETRACT,
            tag("ClusterRequest", "challenge_retract")
        );
        // The absence that matters: no expiry, no ttl, no deadline
        // anywhere on the challenge messages. The follower stamps its
        // own from its own clock, and a field here would be a
        // cross-clock timestamp nobody can evaluate correctly.
        for forbidden in ["expiry", "expires_at", "ttl_s", "deadline"] {
            assert!(
                !tags.contains_key(&("ChallengePublish".to_string(), forbidden.to_string())),
                "ChallengePublish must not carry {forbidden}"
            );
        }

        let mut request = ClusterRequest::hello(Hello::default());
        request.sequence = 1;
        assert_eq!(
            field_numbers(&request.encode_to_vec()),
            vec![
                tag("ClusterRequest", "sequence"),
                tag("ClusterRequest", "body_kind"),
                tag("ClusterRequest", "hello"),
            ]
        );
        let mut request = ClusterRequest::heartbeat(Heartbeat::default());
        request.sequence = 1;
        assert_eq!(
            field_numbers(&request.encode_to_vec()),
            vec![
                tag("ClusterRequest", "sequence"),
                tag("ClusterRequest", "body_kind"),
                tag("ClusterRequest", "heartbeat"),
            ]
        );
        // `body_kind` IS the body's tag by definition.
        assert_eq!(BODY_KIND_HELLO, tag("ClusterRequest", "hello"));
        assert_eq!(BODY_KIND_HEARTBEAT, tag("ClusterRequest", "heartbeat"));

        let mut response = ClusterResponse::retry_later(1);
        response.sequence = 1;
        response.body = Some(cluster_response::Body::HelloAck(HelloAck::default()));
        assert_eq!(
            field_numbers(&response.encode_to_vec()),
            vec![
                tag("ClusterResponse", "sequence"),
                tag("ClusterResponse", "status"),
                tag("ClusterResponse", "retry_after_s"),
                tag("ClusterResponse", "hello_ack"),
            ]
        );
        response.body = Some(cluster_response::Body::HeartbeatAck(HeartbeatAck::default()));
        assert_eq!(
            *field_numbers(&response.encode_to_vec()).last().expect("body"),
            tag("ClusterResponse", "heartbeat_ack")
        );

        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Request(ClusterRequest::default())),
        };
        assert_eq!(
            field_numbers(&frame.encode_to_vec()),
            vec![tag("ClusterFrame", "request")]
        );
        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Response(ClusterResponse::default())),
        };
        assert_eq!(
            field_numbers(&frame.encode_to_vec()),
            vec![tag("ClusterFrame", "response")]
        );
    }

    #[test]
    fn status_values_match_the_published_enum() {
        let tags = proto_tags();
        let value = |name: &str| -> i32 {
            *tags
                .get(&("ClusterStatus".to_string(), name.to_string()))
                .unwrap_or_else(|| panic!("ClusterStatus.{name} missing from cluster.proto"))
                as i32
        };
        let pairs = [
            ("CLUSTER_STATUS_UNSPECIFIED", ClusterStatus::Unspecified),
            ("OK", ClusterStatus::Ok),
            ("RETRY_LATER", ClusterStatus::RetryLater),
            ("INCOMPATIBLE_VERSION", ClusterStatus::IncompatibleVersion),
            ("SCHEMA_TOO_OLD", ClusterStatus::SchemaTooOld),
            ("PROTOCOL_VIOLATION", ClusterStatus::ProtocolViolation),
            ("UNSUPPORTED_METHOD", ClusterStatus::UnsupportedMethod),
        ];
        for (name, status) in pairs {
            assert_eq!(status as i32, value(name), "{name}");
            assert_eq!(ClusterStatus::from_i32(status as i32), status, "{name}");
        }
        // Every published value has a Rust arm (and vice versa).
        let published = tags.keys().filter(|(b, _)| b == "ClusterStatus").count();
        assert_eq!(published, pairs.len());
        assert_eq!(ClusterStatus::from_i32(99), ClusterStatus::Unspecified);
    }

    #[test]
    fn body_kind_invariant_holds_for_constructors_and_flags_mismatches() {
        assert!(ClusterRequest::hello(Hello::default()).body_kind_matches());
        assert!(ClusterRequest::heartbeat(Heartbeat::default()).body_kind_matches());
        // No body: the scalar alone is authoritative.
        assert!(ClusterRequest {
            sequence: 0,
            body_kind: 25,
            body: None
        }
        .body_kind_matches());
        let mut forged = ClusterRequest::heartbeat(Heartbeat::default());
        forged.body_kind = BODY_KIND_HELLO;
        assert!(!forged.body_kind_matches());
        // Reserved ranges are unknown to this build. 20-23 are Story
        // 9.4's, 40-41 Story 9.6's and 60-63 Story 9.5's, all now
        // known; 24-39, 42-59 and 64-79 stay reserved.
        for kind in [0, 15, 19, 24, 39, 42, 59, 64, 79] {
            assert!(!ClusterRequest::is_known_body_kind(kind), "{kind}");
        }
        for kind in [
            BODY_KIND_ENROLL,
            BODY_KIND_RENEW,
            BODY_KIND_LEAVE,
            BODY_KIND_CONFIG_PREPARE,
            BODY_KIND_CONFIG_COMMIT,
            BODY_KIND_CONFIG_ABORT,
            BODY_KIND_CONFIG_PULL,
            BODY_KIND_TELEMETRY_PUSH,
            BODY_KIND_BAN_PUSH,
            BODY_KIND_CERT_PUSH,
            BODY_KIND_CERT_PULL,
            BODY_KIND_CHALLENGE_PUBLISH,
            BODY_KIND_CHALLENGE_RETRACT,
        ] {
            assert!(ClusterRequest::is_known_body_kind(kind), "{kind}");
        }
    }

    #[test]
    fn config_hash_shape_is_checked_at_the_decode_boundary() {
        assert!(config_hash_is_valid(""));
        assert!(config_hash_is_valid(&"a".repeat(MAX_CONFIG_HASH_BYTES)));
        assert!(config_hash_is_valid("0123456789abcdef"));
        // Too long, uppercase, or non-hex: refused before the value can
        // reach a log line or a comparison.
        assert!(!config_hash_is_valid(&"a".repeat(MAX_CONFIG_HASH_BYTES + 1)));
        assert!(!config_hash_is_valid("ABCDEF"));
        assert!(!config_hash_is_valid("zz"));
        assert!(!config_hash_is_valid("ab cd"));
    }

    #[test]
    fn a_key_digest_is_checked_against_the_canonical_blob_shape() {
        let hex = "a".repeat(MAX_CONFIG_HASH_BYTES);
        assert!(cert_digest_is_valid(&format!("sha256:{hex}")));
        // Missing prefix, wrong prefix, short or long hex, uppercase,
        // and the empty string: all refused before the value can be
        // compared against what the configuration announced.
        assert!(!cert_digest_is_valid(""));
        assert!(!cert_digest_is_valid(&hex));
        assert!(!cert_digest_is_valid(&format!("sha512:{hex}")));
        assert!(!cert_digest_is_valid("sha256:"));
        assert!(!cert_digest_is_valid(&format!("sha256:{}", "a".repeat(63))));
        assert!(!cert_digest_is_valid(&format!("sha256:{}", "a".repeat(65))));
        assert!(!cert_digest_is_valid(&format!(
            "sha256:{}",
            "A".repeat(MAX_CONFIG_HASH_BYTES)
        )));
    }

    #[test]
    fn a_certificate_id_and_domain_are_bounded_at_the_decode_boundary() {
        assert!(cert_id_is_valid("3f1b0d2e-0000-4000-8000-000000000001"));
        assert!(!cert_id_is_valid(""));
        assert!(!cert_id_is_valid(&"c".repeat(MAX_CERT_ID_BYTES + 1)));
        assert!(!cert_id_is_valid("forged\nlog line"));
        assert!(cert_domain_is_valid("edge.example.com"));
        assert!(!cert_domain_is_valid(""));
        assert!(!cert_domain_is_valid(&"d".repeat(MAX_CERT_DOMAIN_BYTES + 1)));
        assert!(!cert_domain_is_valid("edge.example.com\r\n"));
    }

    #[test]
    fn a_challenge_token_is_held_to_the_alphabet_the_rfc_makes_normative() {
        assert!(challenge_token_is_valid("LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"));
        assert!(challenge_token_is_valid(&"a".repeat(MAX_CHALLENGE_TOKEN_BYTES)));
        assert!(!challenge_token_is_valid(""));
        assert!(!challenge_token_is_valid(
            &"a".repeat(MAX_CHALLENGE_TOKEN_BYTES + 1)
        ));
        // The reason the alphabet is checked and not just the control
        // characters: the token is the last path segment of
        // /.well-known/acme-challenge/<token>.
        assert!(!challenge_token_is_valid("../../etc/passwd"));
        assert!(!challenge_token_is_valid("tok/en"));
        assert!(!challenge_token_is_valid("tok.en"));
        assert!(!challenge_token_is_valid("tok en"));
        assert!(!challenge_token_is_valid("tok\nen"));
    }

    #[test]
    fn a_key_authorization_is_bounded_because_a_node_serves_it_verbatim() {
        assert!(challenge_key_authorization_is_valid("token.thumbprint-_9"));
        assert!(challenge_key_authorization_is_valid(
            &"a".repeat(MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES)
        ));
        assert!(!challenge_key_authorization_is_valid(""));
        assert!(!challenge_key_authorization_is_valid(
            &"a".repeat(MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES + 1)
        ));
        assert!(!challenge_key_authorization_is_valid("token thumbprint"));
        assert!(!challenge_key_authorization_is_valid("token\r\nInjected: 1"));
        assert!(!challenge_key_authorization_is_valid("<script>"));
    }
}
