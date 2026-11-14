//! The layer-4 stream model (Story 12.1): a TCP or UDP listener that
//! forwards to backends it shares with HTTP routes, the rules that keep
//! that sharing sound, where a stream binds, and the closed vocabulary a
//! stream connection ends with.
//!
//! Nothing here binds a socket. Story 12.2 binds, by the rules stated
//! here: [`binds_here`] decides on which node, and
//! `crate::listen_ports::listen_addresses_conflict` how an address is
//! bound.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr, VariantArray};

use super::backend::{backend_address_port, Backend, RouteBackend};
use super::route::validate_node_selector_names;

/// The most ports one stream's range may span, both ends included.
///
/// A constant enforced by [`Stream::validate`] rather than a `CHECK` on
/// the table, so a later story can turn it into a setting without
/// rebuilding `streams`.
pub const STREAM_PORT_RANGE_MAX: u16 = 1024;

/// The longest stream name, in bytes (the alphabet is ASCII).
pub const STREAM_NAME_MAX_LEN: usize = 64;

/// The length of a stream id, in bytes: a UUID in its canonical
/// lowercase hyphenated form.
pub const STREAM_ID_LEN: usize = 36;

/// Whether `id` is a UUID in its canonical lowercase hyphenated form,
/// the form the management API mints (`Uuid::new_v4().to_string()`).
///
/// An id is a key the data plane carries further than the database (the
/// supervisor's stream control channel, log rows, metric labels), so an
/// id arriving by import or replication is held to the form a server
/// mints rather than to whatever a file or a blob spells. Any UUID
/// version is accepted; only the spelling is fixed.
pub fn is_canonical_stream_id(id: &str) -> bool {
    id.len() == STREAM_ID_LEN
        && uuid::Uuid::try_parse(id).is_ok_and(|parsed| parsed.hyphenated().to_string() == id)
}

/// The transport a stream listens on.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    EnumString,
    IntoStaticStr,
    VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum StreamProtocol {
    /// A TCP listener: one backend connection per client connection.
    Tcp,
    /// A UDP listener: datagrams grouped into sessions per client.
    Udp,
}

impl StreamProtocol {
    /// Snake_case wire and database representation (`tcp`, `udp`).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// A layer-4 listener (Story 12.1 AC #1).
///
/// Replicated, targeted by `node_selector` and audited like a route. A
/// disabled stream is stored, replicated and conflict-checked like an
/// enabled one, and bound on no node ([`binds_here`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    /// Stable UUID; primary key of the `streams` table. Always its
    /// canonical text form, [`STREAM_ID_LEN`] bytes (see
    /// [`is_canonical_stream_id`]).
    pub id: String,
    /// Unique fleet-wide; errors, audit rows, logs and metrics name the
    /// stream by it. ASCII lowercase letters, digits, `-` and `_`, the
    /// `node_selector` alphabet, 1 to [`STREAM_NAME_MAX_LEN`] bytes.
    pub name: String,
    /// Free-form classification label (same rule as `Route.group_name`).
    #[serde(default)]
    pub group_name: String,
    /// TCP or UDP.
    pub protocol: StreamProtocol,
    /// Whether the stream is bound where it is targeted. Default true.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// The one address the stream listens on, IPv4 or IPv6, stored in
    /// its canonical text form (RFC 5952 for IPv6). The unspecified
    /// address of either family is allowed; `[::]` is bound dual-stack
    /// (`crate::listen_ports::listen_addresses_conflict`). An
    /// IPv4-mapped IPv6 address is refused by [`Stream::validate`].
    pub listen_address: IpAddr,
    /// First listen port of the range, 1 to 65535.
    pub port_first: u16,
    /// Last listen port of the range, `port_first` for a single port. A
    /// range forwards listen port N to backend port N, so its backends
    /// carry no port.
    pub port_last: u16,
    /// Node names this stream is pinned to, empty = fleet-wide. Same rule
    /// as `Route::node_selector`.
    #[serde(default)]
    pub node_selector: Vec<String>,
    /// First-insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

fn enabled_by_default() -> bool {
    true
}

/// Whether `value` is over the `node_selector` alphabet: ASCII lowercase
/// letters, digits, `-` and `_`. Length is the caller's rule.
/// `a_stream_name_and_a_selector_entry_share_one_alphabet` pins it to
/// [`validate_node_selector_names`].
fn is_identifier_alphabet(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

impl Stream {
    /// Whether the stream spans more than one port, which decides the
    /// port shape of its backends (D-6).
    pub fn is_range(&self) -> bool {
        self.port_first != self.port_last
    }

    /// Whether `node_name` is targeted by this stream: an empty selector
    /// targets every node. The predicate the replication path keeps, as
    /// `Route::applies_to_node` is for routes; where a stream BINDS is
    /// [`binds_here`].
    pub fn applies_to_node(&self, node_name: &str) -> bool {
        self.node_selector.is_empty() || self.node_selector.iter().any(|n| n == node_name)
    }

    /// The stream's own rules: id ([`is_canonical_stream_id`]), name,
    /// group, listen address, ports, the [`STREAM_PORT_RANGE_MAX`] cap
    /// and the selector rule shared with routes. Which backends it may
    /// reach is [`check_backend_attachments`]; which ports it may hold
    /// on a node is `crate::listen_ports::stream_port_conflicts`.
    ///
    /// # Errors
    ///
    /// A message naming the first violated rule, fit for a refusal body.
    pub fn validate(&self) -> Result<(), String> {
        if !is_canonical_stream_id(&self.id) {
            // Debug-quoted and cut: the value came from a file or a blob,
            // and a refusal body is no place for its control characters
            // or its whole length.
            let shown: String = self.id.chars().take(STREAM_ID_LEN + 1).collect();
            return Err(format!(
                "stream id {shown:?} is not a UUID in canonical lowercase hyphenated form \
                 ({STREAM_ID_LEN} characters)"
            ));
        }
        if self.name.is_empty() || self.name.len() > STREAM_NAME_MAX_LEN {
            return Err(format!(
                "stream name must be 1..={STREAM_NAME_MAX_LEN} characters long"
            ));
        }
        if !is_identifier_alphabet(&self.name) {
            return Err(format!(
                "stream name `{}` may only contain ASCII lowercase letters, digits, `-` and `_`",
                self.name
            ));
        }
        if self.group_name.len() > 64 {
            return Err("group_name must be <= 64 characters".to_string());
        }
        if !is_identifier_alphabet(&self.group_name) {
            return Err(
                "group_name may only contain ASCII lowercase letters, digits, `-` and `_`"
                    .to_string(),
            );
        }
        if let IpAddr::V6(v6) = self.listen_address {
            if v6.to_ipv4_mapped().is_some() {
                return Err(format!(
                    "stream `{}`: listen address {} is an IPv4-mapped IPv6 address; \
                     give the IPv4 address itself",
                    self.name, self.listen_address
                ));
            }
        }
        if self.port_first == 0 {
            return Err(format!(
                "stream `{}`: port_first must be 1..=65535",
                self.name
            ));
        }
        if self.port_last < self.port_first {
            return Err(format!(
                "stream `{}`: port_last {} is below port_first {}",
                self.name, self.port_last, self.port_first
            ));
        }
        let span = u32::from(self.port_last) - u32::from(self.port_first) + 1;
        if span > u32::from(STREAM_PORT_RANGE_MAX) {
            return Err(format!(
                "stream `{}`: a range spans at most {STREAM_PORT_RANGE_MAX} ports \
                 ({}-{} spans {span})",
                self.name, self.port_first, self.port_last
            ));
        }
        validate_node_selector_names(&self.node_selector)
            .map_err(|e| format!("stream `{}`: {e}", self.name))
    }
}

/// Many-to-many association row between a [`Stream`] and a [`Backend`],
/// the counterpart of [`RouteBackend`]. Per-link fields are added by the
/// story that gives them a meaning.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamBackend {
    /// ID of the associated `Stream`.
    pub stream_id: String,
    /// ID of the associated `Backend`.
    pub backend_id: String,
}

/// The fleet role of the node deciding whether it binds a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole<'a> {
    /// A node with no cluster role.
    Standalone,
    /// The control plane. It holds every stream to replicate it and has
    /// no roster name of its own.
    ControlPlane,
    /// An enrolled follower, break-glass included.
    Follower {
        /// The follower's roster name.
        node_name: &'a str,
    },
}

/// Whether a node in `role` binds `stream` (Story 12.1, D-8): never when
/// the stream is disabled, otherwise as
/// [`binds_here_when_enabled`].
///
/// The one rule every bind decision, every port-conflict check and the
/// replication tests read. It deliberately differs from routes: the
/// control plane serves every route it holds, but a stream opens a
/// port, so holding one to replicate it must not open it there.
pub fn binds_here(stream: &Stream, role: NodeRole<'_>) -> bool {
    stream.enabled && binds_here_when_enabled(stream, role)
}

/// Whether a node in `role` would bind `stream` if it were enabled: a
/// standalone node binds every stream, the control plane only those with
/// an empty selector, a follower those its selector targets
/// ([`Stream::applies_to_node`]).
///
/// The port-conflict check reads this rather than [`binds_here`]: a
/// disabled stream keeps its ports, so enabling it can never fail on a
/// conflict accepted while it was off.
pub fn binds_here_when_enabled(stream: &Stream, role: NodeRole<'_>) -> bool {
    match role {
        NodeRole::Standalone => true,
        NodeRole::ControlPlane => stream.node_selector.is_empty(),
        NodeRole::Follower { node_name } => stream.applies_to_node(node_name),
    }
}

/// What [`check_backend_attachments`] reads: the backends to check, and
/// every stream and link that may reach them. Links naming a backend
/// absent from `backends` are not checked, so a caller narrows the check
/// to the backends a write touched by passing only those.
#[derive(Debug, Clone, Copy)]
pub struct AttachmentSnapshot<'a> {
    /// The backends whose attachments are checked.
    pub backends: &'a [Backend],
    /// Every stream a link may name.
    pub streams: &'a [Stream],
    /// Every stream-to-backend link.
    pub stream_backends: &'a [StreamBackend],
    /// Every route-to-backend link.
    pub route_backends: &'a [RouteBackend],
}

/// Which rule of D-6 an attachment breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentRule {
    /// A backend an environment's pipeline manages is linked to a
    /// stream: a pipeline would steer a listener.
    ManagedBackend,
    /// A backend of a UDP stream is also linked to an HTTP route.
    UdpSharedWithRoute {
        /// The route.
        route_id: String,
    },
    /// A backend of a UDP stream is also linked to a TCP stream.
    UdpSharedWithTcpStream {
        /// The TCP stream's name.
        tcp_stream: String,
    },
    /// A backend of a UDP stream has active checks on; until UDP checks
    /// exist (Story 12.14) it relies on passive detection.
    UdpWithActiveChecks,
    /// A backend with a port is linked to a port-range stream, which
    /// forwards each listen port to the same backend port.
    PortedOnRangeStream,
    /// A portless backend is linked to a single-port stream, which has
    /// no port to give it.
    PortlessOnSinglePortStream,
    /// A portless backend is linked to an HTTP route.
    PortlessOnRoute {
        /// The route.
        route_id: String,
    },
    /// A portless backend has active checks on: there is no port to
    /// probe.
    PortlessWithActiveChecks,
}

/// A refused attachment, naming the backend and, where one is involved,
/// the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentConflict {
    /// The backend's id.
    pub backend_id: String,
    /// The backend's address, which is how an operator knows it.
    pub backend_address: String,
    /// The stream the refusal is about, by name. `None` only for a
    /// portless backend refused on its own or on a route alone.
    pub stream: Option<String>,
    /// The rule broken.
    pub rule: AttachmentRule,
}

impl std::fmt::Display for AttachmentConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backend = &self.backend_address;
        let on_stream = match &self.stream {
            Some(name) => format!("stream `{name}`"),
            None => "no stream".to_string(),
        };
        match &self.rule {
            AttachmentRule::ManagedBackend => write!(
                f,
                "backend {backend} is managed by an automation environment and cannot serve \
                 {on_stream}"
            ),
            AttachmentRule::UdpSharedWithRoute { route_id } => write!(
                f,
                "backend {backend} serves UDP {on_stream} and cannot also serve route {route_id}"
            ),
            AttachmentRule::UdpSharedWithTcpStream { tcp_stream } => write!(
                f,
                "backend {backend} serves UDP {on_stream} and cannot also serve TCP stream \
                 `{tcp_stream}`"
            ),
            AttachmentRule::UdpWithActiveChecks => write!(
                f,
                "backend {backend} serves UDP {on_stream}, which has no active health check \
                 yet; disable its health check first"
            ),
            AttachmentRule::PortedOnRangeStream => write!(
                f,
                "backend {backend} carries a port and cannot serve port-range {on_stream}, \
                 which forwards each port to the same backend port; give the host without a port"
            ),
            AttachmentRule::PortlessOnSinglePortStream => write!(
                f,
                "backend {backend} has no port and cannot serve single-port {on_stream}"
            ),
            AttachmentRule::PortlessOnRoute { route_id } => write!(
                f,
                "backend {backend} has no port and cannot serve route {route_id} \
                 (it may serve port-range streams only; {on_stream} involved)"
            ),
            AttachmentRule::PortlessWithActiveChecks => write!(
                f,
                "backend {backend} has no port to probe and must have its health check \
                 disabled ({on_stream} involved)"
            ),
        }
    }
}

impl std::error::Error for AttachmentConflict {}

/// The one rule for which backends a stream may reach (Story 12.1,
/// D-6), checked on every write path: the store's management writes,
/// the replica apply and the import.
///
/// Refused, for each backend of the snapshot:
///
/// 1. a backend with `managed_by` linked to any stream;
/// 2. a backend linked to a UDP stream and also to a route or a TCP
///    stream, or with active checks on (refused, never switched off: a
///    write to a stream must not change a backend another surface may
///    share);
/// 3. a backend with a port on a port-range stream, a portless one on a
///    single-port stream or a route, or portless with active checks on.
///
/// Backends are checked in snapshot order and their streams by name, so
/// the first conflict reported is deterministic.
///
/// # Errors
///
/// The first [`AttachmentConflict`] found.
pub fn check_backend_attachments(
    snapshot: &AttachmentSnapshot<'_>,
) -> Result<(), AttachmentConflict> {
    let streams_by_id: BTreeMap<&str, &Stream> = snapshot
        .streams
        .iter()
        .map(|s| (s.id.as_str(), s))
        .collect();
    let mut streams_of: BTreeMap<&str, Vec<&Stream>> = BTreeMap::new();
    for link in snapshot.stream_backends {
        if let Some(stream) = streams_by_id.get(link.stream_id.as_str()) {
            streams_of
                .entry(link.backend_id.as_str())
                .or_default()
                .push(stream);
        }
    }
    let mut routes_of: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for link in snapshot.route_backends {
        routes_of
            .entry(link.backend_id.as_str())
            .or_default()
            .insert(link.route_id.as_str());
    }

    for backend in snapshot.backends {
        let mut streams: Vec<&Stream> = streams_of
            .get(backend.id.as_str())
            .cloned()
            .unwrap_or_default();
        streams.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        let first_route = routes_of
            .get(backend.id.as_str())
            .and_then(|routes| routes.iter().next().copied());
        let conflict = |stream: Option<&Stream>, rule: AttachmentRule| AttachmentConflict {
            backend_id: backend.id.clone(),
            backend_address: backend.address.clone(),
            stream: stream.map(|s| s.name.clone()),
            rule,
        };

        if backend.managed_by.is_some() {
            if let Some(stream) = streams.first() {
                return Err(conflict(Some(stream), AttachmentRule::ManagedBackend));
            }
        }

        if let Some(udp) = streams.iter().find(|s| s.protocol == StreamProtocol::Udp) {
            if let Some(route_id) = first_route {
                return Err(conflict(
                    Some(udp),
                    AttachmentRule::UdpSharedWithRoute {
                        route_id: route_id.to_string(),
                    },
                ));
            }
            if let Some(tcp) = streams.iter().find(|s| s.protocol == StreamProtocol::Tcp) {
                return Err(conflict(
                    Some(udp),
                    AttachmentRule::UdpSharedWithTcpStream {
                        tcp_stream: tcp.name.clone(),
                    },
                ));
            }
            if backend.health_check_enabled {
                return Err(conflict(Some(udp), AttachmentRule::UdpWithActiveChecks));
            }
        }

        // An address the store would refuse is the store's error to
        // report, not this rule's; it is read as carrying a port here.
        let portless = matches!(backend_address_port(&backend.address), Ok(None));
        for stream in &streams {
            if stream.is_range() && !portless {
                return Err(conflict(Some(stream), AttachmentRule::PortedOnRangeStream));
            }
            if !stream.is_range() && portless {
                return Err(conflict(
                    Some(stream),
                    AttachmentRule::PortlessOnSinglePortStream,
                ));
            }
        }
        if portless {
            if let Some(route_id) = first_route {
                return Err(conflict(
                    streams.first().copied(),
                    AttachmentRule::PortlessOnRoute {
                        route_id: route_id.to_string(),
                    },
                ));
            }
            if backend.health_check_enabled {
                return Err(conflict(
                    streams.first().copied(),
                    AttachmentRule::PortlessWithActiveChecks,
                ));
            }
        }
    }
    Ok(())
}

/// Why a stream connection or session was refused. A closed set each
/// refusing story extends with its own variants; PRD D7 seeds it with
/// [`StreamRefusal::NoMatch`] for the whole epic.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, IntoStaticStr, VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum StreamRefusal {
    /// No rule of the stream matched the connection.
    NoMatch,
}

/// How a stream connection or session ended (Story 12.1 AC #8): the one
/// closed set every later story, log row and metric uses.
///
/// Serialised as `{"reason":"idle_timeout"}`, or
/// `{"reason":"refused","refusal":"no_match"}` for the one variant
/// carrying data. A transfer (Story 12.16) is an event, not an end, and
/// is not a variant. The published word list is
/// [`StreamEndKind::VARIANTS`], never a typed-out copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "reason", content = "refusal", rename_all = "snake_case")]
pub enum StreamEndReason {
    /// The client closed.
    ClientClose,
    /// The backend closed.
    BackendClose,
    /// No traffic for the idle timeout.
    IdleTimeout,
    /// The total duration cap was reached.
    TotalTimeout,
    /// No backend connection could be opened.
    ConnectFailed,
    /// Every backend was down or draining.
    NoHealthyBackend,
    /// Refused before forwarding, with the reason.
    Refused(StreamRefusal),
    /// The TLS ClientHello did not arrive in time.
    ClienthelloTimeout,
    /// A PROXY protocol header was missing or invalid.
    ProxyHeaderInvalid,
    /// Protocol detection did not conclude in time.
    DetectionTimeout,
    /// The per-connection request byte bound was reached.
    RequestBoundReached,
    /// The per-connection response byte bound was reached.
    ResponseBoundReached,
    /// The backend serving the connection went down.
    BackendDown,
    /// The stream was removed or changed so it no longer holds the
    /// connection.
    ConfigRemoved,
    /// The connection was drained by a hot upgrade.
    DrainedByUpgrade,
    /// The node stopped.
    NodeShutdown,
}

/// The fieldless twin of [`StreamEndReason`], one variant per word of
/// AC #8, from which every surface derives its word list.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, IntoStaticStr, VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum StreamEndKind {
    /// See [`StreamEndReason::ClientClose`].
    ClientClose,
    /// See [`StreamEndReason::BackendClose`].
    BackendClose,
    /// See [`StreamEndReason::IdleTimeout`].
    IdleTimeout,
    /// See [`StreamEndReason::TotalTimeout`].
    TotalTimeout,
    /// See [`StreamEndReason::ConnectFailed`].
    ConnectFailed,
    /// See [`StreamEndReason::NoHealthyBackend`].
    NoHealthyBackend,
    /// See [`StreamEndReason::Refused`].
    Refused,
    /// See [`StreamEndReason::ClienthelloTimeout`].
    ClienthelloTimeout,
    /// See [`StreamEndReason::ProxyHeaderInvalid`].
    ProxyHeaderInvalid,
    /// See [`StreamEndReason::DetectionTimeout`].
    DetectionTimeout,
    /// See [`StreamEndReason::RequestBoundReached`].
    RequestBoundReached,
    /// See [`StreamEndReason::ResponseBoundReached`].
    ResponseBoundReached,
    /// See [`StreamEndReason::BackendDown`].
    BackendDown,
    /// See [`StreamEndReason::ConfigRemoved`].
    ConfigRemoved,
    /// See [`StreamEndReason::DrainedByUpgrade`].
    DrainedByUpgrade,
    /// See [`StreamEndReason::NodeShutdown`].
    NodeShutdown,
}

impl StreamEndKind {
    /// The snake_case word this kind is published as.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl StreamEndReason {
    /// The kind of this end, dropping the refusal reason.
    pub fn kind(&self) -> StreamEndKind {
        match self {
            Self::ClientClose => StreamEndKind::ClientClose,
            Self::BackendClose => StreamEndKind::BackendClose,
            Self::IdleTimeout => StreamEndKind::IdleTimeout,
            Self::TotalTimeout => StreamEndKind::TotalTimeout,
            Self::ConnectFailed => StreamEndKind::ConnectFailed,
            Self::NoHealthyBackend => StreamEndKind::NoHealthyBackend,
            Self::Refused(_) => StreamEndKind::Refused,
            Self::ClienthelloTimeout => StreamEndKind::ClienthelloTimeout,
            Self::ProxyHeaderInvalid => StreamEndKind::ProxyHeaderInvalid,
            Self::DetectionTimeout => StreamEndKind::DetectionTimeout,
            Self::RequestBoundReached => StreamEndKind::RequestBoundReached,
            Self::ResponseBoundReached => StreamEndKind::ResponseBoundReached,
            Self::BackendDown => StreamEndKind::BackendDown,
            Self::ConfigRemoved => StreamEndKind::ConfigRemoved,
            Self::DrainedByUpgrade => StreamEndKind::DrainedByUpgrade,
            Self::NodeShutdown => StreamEndKind::NodeShutdown,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::models::{HealthCheck, HealthStatus, LifecycleState, ManagedBy};

    fn at() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z")
            .expect("test setup: timestamp")
            .with_timezone(&Utc)
    }

    /// The canonical stream id a test names `label`: the label's bytes
    /// in hex, right-padded with zeros, so ids sort as their labels do
    /// and a failure still shows which fixture it is (`s-1` is
    /// `732d3100-0000-...`). At most 16 bytes of label.
    pub(crate) fn stream_id(label: &str) -> String {
        assert!(
            !label.is_empty() && label.len() <= 16,
            "test setup: a stream id label is 1 to 16 bytes, got {label:?}"
        );
        let hex: String = label.bytes().map(|b| format!("{b:02x}")).collect();
        let digits = format!("{hex:0<32}");
        format!(
            "{}-{}-{}-{}-{}",
            &digits[0..8],
            &digits[8..12],
            &digits[12..16],
            &digits[16..20],
            &digits[20..32]
        )
    }

    /// A valid enabled fleet-wide stream on `0.0.0.0:port`, whose id is
    /// [`stream_id`] of `label`.
    pub(crate) fn stream(label: &str, name: &str, protocol: StreamProtocol, port: u16) -> Stream {
        Stream {
            id: stream_id(label),
            name: name.to_string(),
            group_name: String::new(),
            protocol,
            enabled: true,
            listen_address: "0.0.0.0".parse().expect("test setup: address"),
            port_first: port,
            port_last: port,
            node_selector: Vec::new(),
            created_at: at(),
            updated_at: at(),
        }
    }

    /// A backend at `address` with active checks off.
    pub(crate) fn backend(id: &str, address: &str) -> Backend {
        Backend {
            id: id.to_string(),
            address: address.to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 100,
            health_status: HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            health_check: HealthCheck::TcpConnect,
            lifecycle_state: LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: at(),
            updated_at: at(),
        }
    }

    fn link(stream_id: &str, backend_id: &str) -> StreamBackend {
        StreamBackend {
            stream_id: stream_id.to_string(),
            backend_id: backend_id.to_string(),
        }
    }

    // ---- Stream::validate ----

    #[test]
    fn a_minted_id_is_canonical_and_every_other_spelling_is_refused() {
        let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
        for _ in 0..32 {
            s.id = uuid::Uuid::new_v4().to_string();
            assert_eq!(s.id.len(), STREAM_ID_LEN);
            assert!(s.validate().is_ok(), "{}", s.id);
        }
        let minted = uuid::Uuid::new_v4();
        let refused = [
            String::new(),
            "s-1".to_string(),
            minted.hyphenated().to_string().to_uppercase(),
            minted.simple().to_string(),
            minted.braced().to_string(),
            minted.urn().to_string(),
            format!(" {minted}"),
            format!("{minted}\n"),
            format!("{minted}0"),
            minted.hyphenated().to_string().replacen('-', "_", 1),
            "g".repeat(STREAM_ID_LEN),
        ];
        for id in refused {
            s.id = id.clone();
            let err = s.validate().expect_err("not the minted form");
            assert!(err.contains("stream id"), "{id:?}: {err}");
        }
    }

    #[test]
    fn a_refused_id_is_shown_quoted_and_cut() {
        let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
        s.id = format!("bad\u{1b}[31m{}", "x".repeat(4096));
        let err = s.validate().expect_err("refused");
        assert!(!err.contains('\u{1b}'), "{err}");
        assert!(err.len() < 200, "{err}");
    }

    #[test]
    fn the_test_ids_are_canonical_and_keep_their_labels_order() {
        let labels = ["a", "s", "s-1", "s-10", "s-2", "stream-edge", "u"];
        let ids: Vec<String> = labels.iter().map(|l| stream_id(l)).collect();
        for id in &ids {
            assert!(is_canonical_stream_id(id), "{id}");
        }
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(sorted, ids);
    }

    #[test]
    fn port_zero_and_inverted_ranges_are_refused() {
        let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
        assert!(s.validate().is_ok());
        s.port_first = 0;
        assert!(s.validate().expect_err("port 0").contains("port_first"));
        s.port_first = 60;
        s.port_last = 53;
        assert!(s.validate().expect_err("inverted").contains("below"));
    }

    #[test]
    fn a_range_of_the_cap_is_accepted_and_one_more_port_is_refused() {
        let mut s = stream("s", "range", StreamProtocol::Tcp, 6000);
        s.port_last = s.port_first + STREAM_PORT_RANGE_MAX - 1;
        assert!(s.validate().is_ok());
        s.port_last += 1;
        assert!(s.validate().expect_err("over the cap").contains("at most"));
        // The top of the port space is reachable.
        s.port_first = u16::MAX - STREAM_PORT_RANGE_MAX + 1;
        s.port_last = u16::MAX;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn an_ipv4_mapped_listen_address_is_refused() {
        let mut s = stream("s", "mapped", StreamProtocol::Tcp, 5000);
        s.listen_address = "::ffff:192.0.2.10".parse().expect("test setup: address");
        assert!(s.validate().expect_err("mapped").contains("IPv4-mapped"));
        for fine in ["192.0.2.10", "0.0.0.0", "::", "2001:db8::1"] {
            s.listen_address = fine.parse().expect("test setup: address");
            assert!(s.validate().is_ok(), "{fine}");
        }
    }

    #[test]
    fn the_listen_address_is_kept_in_its_rfc_5952_form() {
        let json = serde_json::json!({
            "id": "s", "name": "v6", "protocol": "tcp",
            "listen_address": "2001:DB8:0:0:0:0:0:1",
            "port_first": 5000, "port_last": 5000,
            "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
        });
        let s: Stream = serde_json::from_value(json).expect("a non-canonical spelling parses");
        let out = serde_json::to_value(&s).expect("serialize");
        assert_eq!(out["listen_address"], "2001:db8::1");
        assert!(
            serde_json::from_value::<Stream>(serde_json::json!({
                "id": "s", "name": "host", "protocol": "tcp",
                "listen_address": "listener.example.com",
                "port_first": 5000, "port_last": 5000,
                "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
            }))
            .is_err(),
            "a hostname is not a listen address"
        );
    }

    #[test]
    fn enabled_defaults_to_true_and_unknown_fields_are_refused() {
        let base = serde_json::json!({
            "id": "s", "name": "dns", "protocol": "udp",
            "listen_address": "0.0.0.0",
            "port_first": 53, "port_last": 53,
            "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
        });
        let s: Stream = serde_json::from_value(base.clone()).expect("parses");
        assert!(s.enabled);
        assert!(s.node_selector.is_empty());
        let mut with_unknown = base;
        with_unknown["managed_by"] = serde_json::json!(null);
        assert!(serde_json::from_value::<Stream>(with_unknown).is_err());
        assert!(serde_json::from_value::<StreamBackend>(
            serde_json::json!({"stream_id": "s", "backend_id": "b", "backup": true})
        )
        .is_err());
    }

    #[test]
    fn the_name_alphabet_and_length_are_enforced() {
        let mut s = stream("s", "edge_dns-1", StreamProtocol::Udp, 53);
        assert!(s.validate().is_ok());
        for bad in ["", "DNS", "dns.udp", "dns stream", "dns/1"] {
            s.name = bad.to_string();
            assert!(s.validate().is_err(), "{bad:?}");
        }
        s.name = "a".repeat(STREAM_NAME_MAX_LEN);
        assert!(s.validate().is_ok());
        s.name.push('a');
        assert!(s.validate().is_err());
    }

    #[test]
    fn a_stream_name_and_a_selector_entry_share_one_alphabet() {
        // The name rule is the selector rule: whatever one accepts the
        // other does, over every ASCII character.
        for c in (0u8..128).map(char::from) {
            let candidate = format!("a{c}");
            let as_selector = validate_node_selector_names(std::slice::from_ref(&candidate));
            let mut s = stream("s", &candidate, StreamProtocol::Tcp, 5000);
            assert_eq!(
                s.validate().is_ok(),
                as_selector.is_ok(),
                "character {c:?} judged differently"
            );
            s.name = "ok".to_string();
            s.group_name = candidate.clone();
            assert_eq!(s.validate().is_ok(), as_selector.is_ok(), "group {c:?}");
        }
    }

    #[test]
    fn the_selector_rule_is_the_route_rule() {
        let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
        s.node_selector = vec!["edge-1".to_string()];
        assert!(s.validate().is_ok());
        for bad in [
            vec!["Edge-1".to_string()],
            vec![String::new()],
            vec!["x".to_string(); crate::models::NODE_SELECTOR_MAX_ENTRIES + 1],
        ] {
            let route_rule = validate_node_selector_names(&bad).expect_err("route refuses");
            s.node_selector = bad;
            let err = s.validate().expect_err("stream refuses");
            assert!(err.contains(&route_rule), "{err}");
        }
    }

    // ---- binds_here ----

    /// The rows 12.2 reads: (role, selector, enabled, binds).
    const BINDS_HERE: &[(NodeRole<'static>, &[&str], bool, bool)] = &[
        (NodeRole::Standalone, &[], true, true),
        (NodeRole::Standalone, &["edge-1"], true, true),
        (NodeRole::Standalone, &["edge-2"], true, true),
        (NodeRole::Standalone, &[], false, false),
        (NodeRole::Standalone, &["edge-1"], false, false),
        (NodeRole::Standalone, &["edge-2"], false, false),
        (NodeRole::ControlPlane, &[], true, true),
        (NodeRole::ControlPlane, &["edge-1"], true, false),
        (NodeRole::ControlPlane, &["edge-2"], true, false),
        (NodeRole::ControlPlane, &[], false, false),
        (NodeRole::ControlPlane, &["edge-1"], false, false),
        (NodeRole::ControlPlane, &["edge-2"], false, false),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &[],
            true,
            true,
        ),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &["edge-1"],
            true,
            true,
        ),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &["edge-2"],
            true,
            false,
        ),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &[],
            false,
            false,
        ),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &["edge-1"],
            false,
            false,
        ),
        (
            NodeRole::Follower {
                node_name: "edge-1",
            },
            &["edge-2"],
            false,
            false,
        ),
    ];

    #[test]
    fn binds_here_over_every_role_selector_and_enabled_flag() {
        for &(role, selector, enabled, expected) in BINDS_HERE {
            let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
            s.node_selector = selector.iter().map(|n| (*n).to_string()).collect();
            s.enabled = enabled;
            assert_eq!(
                binds_here(&s, role),
                expected,
                "{role:?}, selector {selector:?}, enabled {enabled}"
            );
            // The enabled-agnostic predicate is the same row with the
            // flag on.
            s.enabled = true;
            let when_enabled = BINDS_HERE
                .iter()
                .find(|row| row.0 == role && row.1 == selector && row.2)
                .expect("the table covers the enabled twin of every row")
                .3;
            assert_eq!(binds_here_when_enabled(&s, role), when_enabled);
        }
    }

    // ---- check_backend_attachments ----

    struct Fixture {
        backends: Vec<Backend>,
        streams: Vec<Stream>,
        stream_backends: Vec<StreamBackend>,
        route_backends: Vec<RouteBackend>,
    }

    impl Fixture {
        fn check(&self) -> Result<(), AttachmentConflict> {
            check_backend_attachments(&AttachmentSnapshot {
                backends: &self.backends,
                streams: &self.streams,
                stream_backends: &self.stream_backends,
                route_backends: &self.route_backends,
            })
        }
    }

    fn fixture(backend: Backend, streams: Vec<Stream>, routes: &[&str]) -> Fixture {
        let stream_backends = streams.iter().map(|s| link(&s.id, &backend.id)).collect();
        let route_backends = routes
            .iter()
            .map(|r| RouteBackend {
                route_id: (*r).to_string(),
                backend_id: backend.id.clone(),
            })
            .collect();
        Fixture {
            backends: vec![backend],
            streams,
            stream_backends,
            route_backends,
        }
    }

    fn range(id: &str, name: &str, protocol: StreamProtocol) -> Stream {
        let mut s = stream(id, name, protocol, 6000);
        s.port_last = 6099;
        s
    }

    fn refused(f: &Fixture) -> AttachmentConflict {
        f.check().expect_err("the attachment is refused")
    }

    #[test]
    fn every_refusal_names_the_stream() {
        let udp = || stream("u", "dns", StreamProtocol::Udp, 53);
        let tcp = || stream("t", "smtp", StreamProtocol::Tcp, 25);

        let shared_with_route = refused(&fixture(
            backend("b", "192.0.2.10:53"),
            vec![udp()],
            &["r-1"],
        ));
        assert_eq!(
            shared_with_route.rule,
            AttachmentRule::UdpSharedWithRoute {
                route_id: "r-1".to_string()
            }
        );

        let shared_with_tcp = refused(&fixture(
            backend("b", "192.0.2.10:53"),
            vec![udp(), tcp()],
            &[],
        ));
        assert_eq!(
            shared_with_tcp.rule,
            AttachmentRule::UdpSharedWithTcpStream {
                tcp_stream: "smtp".to_string()
            }
        );

        let mut checked = backend("b", "192.0.2.10:53");
        checked.health_check_enabled = true;
        let with_checks = refused(&fixture(checked, vec![udp()], &[]));
        assert_eq!(with_checks.rule, AttachmentRule::UdpWithActiveChecks);

        let mut managed = backend("b", "192.0.2.10:25");
        managed.managed_by = Some(ManagedBy::Automation {
            environment: "env-1".to_string(),
        });
        let managed = refused(&fixture(managed, vec![tcp()], &[]));
        assert_eq!(managed.rule, AttachmentRule::ManagedBackend);

        let portless_single = refused(&fixture(backend("b", "192.0.2.10"), vec![tcp()], &[]));
        assert_eq!(
            portless_single.rule,
            AttachmentRule::PortlessOnSinglePortStream
        );

        let ported_range = refused(&fixture(
            backend("b", "192.0.2.10:6000"),
            vec![range("g", "game", StreamProtocol::Udp)],
            &[],
        ));
        assert_eq!(ported_range.rule, AttachmentRule::PortedOnRangeStream);

        for conflict in [
            &shared_with_route,
            &shared_with_tcp,
            &with_checks,
            &managed,
            &portless_single,
            &ported_range,
        ] {
            let stream = conflict.stream.as_deref().expect("a stream is named");
            assert!(
                conflict.to_string().contains(&format!("`{stream}`")),
                "{conflict}"
            );
        }
    }

    #[test]
    fn a_portless_backend_on_a_route_or_with_checks_on_is_refused() {
        let game = || range("g", "game", StreamProtocol::Tcp);
        let on_route = refused(&fixture(
            backend("b", "backend.example.com"),
            vec![game()],
            &["r-1"],
        ));
        assert_eq!(
            on_route.rule,
            AttachmentRule::PortlessOnRoute {
                route_id: "r-1".to_string()
            }
        );
        assert!(on_route.to_string().contains("`game`"), "{on_route}");
        assert!(on_route.to_string().contains("r-1"), "{on_route}");

        let mut checked = backend("b", "[2001:db8::1]");
        checked.health_check_enabled = true;
        let with_checks = refused(&fixture(checked.clone(), vec![game()], &[]));
        assert_eq!(with_checks.rule, AttachmentRule::PortlessWithActiveChecks);
        assert!(with_checks.to_string().contains("`game`"), "{with_checks}");

        // Unattached, the rule still holds: there is nothing to probe.
        let alone = refused(&fixture(checked, Vec::new(), &[]));
        assert_eq!(alone.rule, AttachmentRule::PortlessWithActiveChecks);
        assert_eq!(alone.stream, None);
    }

    #[test]
    fn the_allowed_sharings_are_accepted() {
        // One backend on two UDP streams.
        let mut second = stream("u2", "dns-b", StreamProtocol::Udp, 5353);
        second.listen_address = "192.0.2.20".parse().expect("test setup: address");
        assert!(fixture(
            backend("b", "192.0.2.10:53"),
            vec![stream("u1", "dns-a", StreamProtocol::Udp, 53), second],
            &[]
        )
        .check()
        .is_ok());
        // One backend on a route and a TCP stream, checks on.
        let mut checked = backend("b", "192.0.2.10:443");
        checked.health_check_enabled = true;
        assert!(fixture(
            checked,
            vec![stream("t", "tls", StreamProtocol::Tcp, 8443)],
            &["r-1"]
        )
        .check()
        .is_ok());
        // A portless backend with checks off on a range stream.
        assert!(fixture(
            backend("b", "backend.example.com"),
            vec![range("g", "game", StreamProtocol::Udp)],
            &[]
        )
        .check()
        .is_ok());
    }

    #[test]
    fn only_the_backends_of_the_snapshot_are_checked() {
        let mut f = fixture(
            backend("b", "192.0.2.10:53"),
            vec![stream("u", "dns", StreamProtocol::Udp, 53)],
            &["r-1"],
        );
        assert!(f.check().is_err());
        f.backends.clear();
        assert!(f.check().is_ok());
    }

    // ---- StreamEndReason ----

    fn sample_reason(kind: StreamEndKind) -> StreamEndReason {
        match kind {
            StreamEndKind::ClientClose => StreamEndReason::ClientClose,
            StreamEndKind::BackendClose => StreamEndReason::BackendClose,
            StreamEndKind::IdleTimeout => StreamEndReason::IdleTimeout,
            StreamEndKind::TotalTimeout => StreamEndReason::TotalTimeout,
            StreamEndKind::ConnectFailed => StreamEndReason::ConnectFailed,
            StreamEndKind::NoHealthyBackend => StreamEndReason::NoHealthyBackend,
            StreamEndKind::Refused => StreamEndReason::Refused(StreamRefusal::NoMatch),
            StreamEndKind::ClienthelloTimeout => StreamEndReason::ClienthelloTimeout,
            StreamEndKind::ProxyHeaderInvalid => StreamEndReason::ProxyHeaderInvalid,
            StreamEndKind::DetectionTimeout => StreamEndReason::DetectionTimeout,
            StreamEndKind::RequestBoundReached => StreamEndReason::RequestBoundReached,
            StreamEndKind::ResponseBoundReached => StreamEndReason::ResponseBoundReached,
            StreamEndKind::BackendDown => StreamEndReason::BackendDown,
            StreamEndKind::ConfigRemoved => StreamEndReason::ConfigRemoved,
            StreamEndKind::DrainedByUpgrade => StreamEndReason::DrainedByUpgrade,
            StreamEndKind::NodeShutdown => StreamEndReason::NodeShutdown,
        }
    }

    #[test]
    fn every_end_kind_round_trips_and_names_its_reason() {
        for &kind in StreamEndKind::VARIANTS {
            let reason = sample_reason(kind);
            assert_eq!(reason.kind(), kind);
            let json = serde_json::to_value(reason).expect("serialize");
            assert_eq!(json["reason"], kind.as_str(), "{json}");
            assert_eq!(
                serde_json::to_value(kind).expect("serialize kind"),
                kind.as_str()
            );
            let back: StreamEndReason = serde_json::from_value(json).expect("deserialize");
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn a_refusal_carries_its_reason() {
        for &refusal in StreamRefusal::VARIANTS {
            let json = serde_json::to_value(StreamEndReason::Refused(refusal)).expect("serialize");
            let word: &'static str = refusal.into();
            assert_eq!(
                json,
                serde_json::json!({"reason": "refused", "refusal": word})
            );
        }
        assert_eq!(
            serde_json::to_value(StreamEndReason::IdleTimeout).expect("serialize"),
            serde_json::json!({"reason": "idle_timeout"})
        );
    }
}
