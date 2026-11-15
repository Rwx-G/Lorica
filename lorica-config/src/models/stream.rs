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
use std::fmt::Display;
use std::net::IpAddr;
use std::ops::RangeInclusive;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use strum::{EnumString, IntoStaticStr, VariantArray};

use super::backend::{backend_address_host, backend_address_port, Backend, RouteBackend};
use super::enums::LoadBalancing;
use super::route::{validate_node_selector_names, MtlsConfig};
use super::ProxyProtocolMode;
use crate::connection_filter::validate_proxy_protocol;
use crate::host_shape::names_an_address;
use crate::local_address::is_local_host;
use crate::route_selection::{
    canonical_hostname, validate_hostname_syntax, ROUTE_REDIRECT_HOSTNAME_SHAPE,
    STREAM_SERVER_NAME_SHAPE,
};

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

    // The engine settings of Story 12.3 (D-q). Each carries a serde
    // default so a document written before they existed still reads,
    // and each states in its doc comment which protocols it applies to;
    // [`TCP_ENGINE_FIELDS`] is where a UDP stream's refusal of them is
    // decided.
    /// How a backend is chosen for a connection or a UDP session. Both
    /// protocols; `peak_ewma` is refused on UDP, which has no connect
    /// latency to feed it (Story 12.5 D-i), and `least_conn` counts
    /// sessions there.
    #[serde(default = "default_load_balancing")]
    pub load_balancing: LoadBalancing,
    /// Per connect attempt, in milliseconds,
    /// [`Stream::CONNECT_TIMEOUT_MS_RANGE`]. TCP only.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u32,
    /// A connection or UDP session with no forwarded byte either way for
    /// this long is closed, in seconds. Its default and range depend on
    /// the protocol: [`Stream::default_idle_timeout_s`] and
    /// [`Stream::idle_timeout_s_range`]. Both protocols.
    #[serde(default = "default_tcp_idle_timeout_s")]
    pub idle_timeout_s: u32,
    /// The longest a connection may last from accept, or a UDP session
    /// from its first datagram, in seconds,
    /// [`Stream::TOTAL_TIMEOUT_S_RANGE`]; `None` for no limit. Both
    /// protocols.
    #[serde(default)]
    pub total_timeout_s: Option<u32>,
    /// Connect attempts per connection, the first one included,
    /// [`Stream::MAX_CONNECT_ATTEMPTS_RANGE`]. TCP only.
    #[serde(default = "default_max_connect_attempts")]
    pub max_connect_attempts: u8,
    /// Whether TCP keepalive is set on the backend socket. TCP only.
    #[serde(default = "default_backend_keepalive")]
    pub backend_keepalive: bool,
    /// Idle time before the first keepalive probe, in seconds,
    /// [`Stream::BACKEND_KEEPALIVE_IDLE_S_RANGE`]. TCP only.
    #[serde(default = "default_backend_keepalive_idle_s")]
    pub backend_keepalive_idle_s: u32,
    /// Whether established connections or sessions to a backend that
    /// goes down are closed with `backend_down` (HAProxy's
    /// `on-marked-down shutdown-sessions`). Both protocols.
    #[serde(default)]
    pub close_on_backend_down: bool,
    /// The PROXY protocol header sent to the backend: after connect on
    /// TCP, in front of every datagram on UDP. `v1` is refused on UDP:
    /// its text format has no UDP transport (Story 12.5 D-j).
    #[serde(default)]
    pub proxy_protocol_send: StreamProxyProtocol,
    /// Whether a PROXY header is required from a peer of
    /// `proxy_protocol_trusted_cidrs`. TCP only, for good: a UDP source
    /// address is spoofable, so "trusted source" means nothing there.
    #[serde(default)]
    pub proxy_protocol_accept: bool,
    /// The peers allowed to send a PROXY header, at most
    /// [`Stream::PROXY_PROTOCOL_TRUSTED_CIDRS_MAX`] entries, by the rule
    /// of the HTTP listeners' list
    /// (`crate::connection_filter::validate_proxy_protocol`). TCP only.
    #[serde(default)]
    pub proxy_protocol_trusted_cidrs: Vec<String>,
    /// Local addresses backend connections or UDP sessions leave from,
    /// used in turn per attempt or per session among those of the
    /// destination's family (nginx's `proxy_bind`, as a list); empty lets
    /// the kernel choose. At most [`Stream::SOURCE_ADDRESSES_MAX`] unicast
    /// literals. Both protocols.
    #[serde(default)]
    pub source_addresses: Vec<IpAddr>,
    /// Whether a backend on a local address (loopback, link-local,
    /// unspecified, `localhost`, or an address of the node) may be
    /// reached. Never settable from the automation or MCP surfaces. Both
    /// protocols.
    #[serde(default)]
    pub allow_local_backend: bool,
    /// Client-to-backend bytes per second per connection,
    /// [`Stream::RATE_BPS_RANGE`]; `None` for no limit. TCP only.
    #[serde(default)]
    pub upload_rate_bps: Option<u64>,
    /// Backend-to-client bytes per second per connection,
    /// [`Stream::RATE_BPS_RANGE`]; `None` for no limit. TCP only.
    #[serde(default)]
    pub download_rate_bps: Option<u64>,
    /// The most concurrent connections of this stream, per worker
    /// process until Story 12.6, per node from then on (the same field,
    /// moved onto shared counters), [`Stream::MAX_CONNECTIONS_RANGE`].
    /// TCP only: a UDP stream's session cap is its own setting.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// The UDP settings (Story 12.5 D-l): present on every UDP stream,
    /// absent on every TCP one, so no UDP field is ever stored on a TCP
    /// stream or ignored on one. [`Stream::new`] fills the defaults.
    #[serde(default)]
    pub udp: Option<UdpSettings>,

    // TLS at layer 4 (Story 12.4, D-k). TCP only: a UDP stream refuses
    // every one of them (no DTLS in this epic). Which of them a mode
    // takes is `Stream::validate`'s table (D-g); each carries a serde
    // default so a document written before them still reads.
    /// Whether the stream reads TLS at all, and whether it terminates it.
    #[serde(default)]
    pub tls_mode: StreamTlsMode,
    /// The rules a TLS stream routes by (D-d), at most
    /// [`Stream::MATCH_RULES_MAX`]; empty on a stream whose `tls_mode`
    /// is `none`. Their order never decides anything.
    #[serde(default)]
    pub match_rules: Vec<StreamMatchRule>,
    /// The operator's acknowledgement that a `no_sni` rule admits a
    /// client naming no server (D7), required by
    /// [`Stream::no_sni_needs_acknowledgement`]; refused without such a
    /// rule.
    #[serde(default)]
    pub no_sni_acknowledged: bool,
    /// How long a TLS stream waits for a complete ClientHello, from
    /// accept, in milliseconds, [`Stream::CLIENTHELLO_TIMEOUT_MS_RANGE`];
    /// `None` is [`Stream::DEFAULT_CLIENTHELLO_TIMEOUT_MS`]. Refused when
    /// set on a stream whose `tls_mode` is `none`.
    #[serde(default)]
    pub clienthello_timeout_ms: Option<u32>,
    /// What a terminating stream presents and verifies (D-f, D-h);
    /// required in `terminate` mode, refused in the others.
    #[serde(default)]
    pub tls_terminate: Option<StreamTlsTerminate>,
    /// TLS from Lorica to the backend (D-i): origination on a stream
    /// whose `tls_mode` is `none`, re-encryption on a terminating one,
    /// refused in passthrough.
    #[serde(default)]
    pub upstream_tls: Option<StreamUpstreamTls>,

    /// First-insert timestamp.
    pub created_at: DateTime<Utc>,
    /// Last-write timestamp.
    pub updated_at: DateTime<Utc>,
}

fn enabled_by_default() -> bool {
    true
}

fn default_load_balancing() -> LoadBalancing {
    LoadBalancing::RoundRobin
}

fn default_connect_timeout_ms() -> u32 {
    Stream::DEFAULT_CONNECT_TIMEOUT_MS
}

/// A document carries no protocol context for a serde default, so the
/// field defaults to the TCP value; [`Stream::default_idle_timeout_s`]
/// is what a protocol-aware writer reads.
fn default_tcp_idle_timeout_s() -> u32 {
    Stream::default_idle_timeout_s(StreamProtocol::Tcp)
}

fn default_max_connect_attempts() -> u8 {
    Stream::DEFAULT_MAX_CONNECT_ATTEMPTS
}

fn default_backend_keepalive() -> bool {
    Stream::DEFAULT_BACKEND_KEEPALIVE
}

fn default_backend_keepalive_idle_s() -> u32 {
    Stream::DEFAULT_BACKEND_KEEPALIVE_IDLE_S
}

fn default_max_connections() -> u32 {
    Stream::DEFAULT_MAX_CONNECTIONS
}

/// Which PROXY protocol header a stream sends its backends (Story 12.3,
/// D-j).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumString,
    IntoStaticStr,
    VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum StreamProxyProtocol {
    /// No header.
    #[default]
    Off,
    /// The text header of version 1.
    V1,
    /// The binary header of version 2.
    V2,
}

impl StreamProxyProtocol {
    /// Snake_case wire and database representation (`off`, `v1`, `v2`).
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// How a TCP stream treats TLS (Story 12.4, D-g).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumString,
    IntoStaticStr,
    VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum StreamTlsMode {
    /// Bytes are forwarded as they come; no ClientHello is read.
    #[default]
    None,
    /// The ClientHello is read to choose a rule, then forwarded with
    /// everything after it, unchanged (D-e).
    Passthrough,
    /// The ClientHello is read to choose a rule, then TLS is terminated
    /// with a certificate of the node's resolver (D-f).
    Terminate,
}

impl StreamTlsMode {
    /// Snake_case wire and database representation.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }

    /// Whether a stream in this mode reads the ClientHello and routes by
    /// its [`StreamMatchRule`]s.
    pub fn reads_client_hello(&self) -> bool {
        !matches!(self, StreamTlsMode::None)
    }
}

/// One rule of a TLS stream (D-d): a name its links refer to, and what
/// a ClientHello must carry to match it.
///
/// A struct with `matcher` as a field rather than a flattened enum: the
/// canonical decoder refuses unknown fields, which serde cannot combine
/// with `flatten`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMatchRule {
    /// Unique in the stream, 1 to [`Stream::MATCH_RULE_NAME_MAX_LEN`]
    /// bytes of ASCII lowercase letters, digits, `-` and `_`.
    pub name: String,
    /// What the ClientHello must carry.
    pub matcher: StreamMatcher,
}

/// What a ClientHello must carry to match a rule (D-d). Story 12.15 adds
/// its protocol matchers as more kinds here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StreamMatcher {
    /// A ClientHello naming one of `server_names`, exactly or under a
    /// wildcard (`*.example.com` covers every depth, as a route's does).
    Tls {
        /// 1 to [`Stream::RULE_SERVER_NAMES_MAX`] names, stored in
        /// `canonical_hostname` form ([`Stream::canonicalise_server_names`]).
        server_names: Vec<String>,
        /// 0 to [`Stream::ALPN_MAX`] protocols; empty matches any offer
        /// and no offer.
        #[serde(default)]
        alpn: Vec<String>,
    },
    /// A ClientHello naming no server (D7): explicit, acknowledged or
    /// behind a source allowlist, and counted.
    NoSni {
        /// As on [`StreamMatcher::Tls`].
        #[serde(default)]
        alpn: Vec<String>,
    },
}

impl StreamMatcher {
    /// The kind as the API and the logs spell it.
    pub fn kind(&self) -> &'static str {
        match self {
            StreamMatcher::Tls { .. } => "tls",
            StreamMatcher::NoSni { .. } => "no_sni",
        }
    }

    /// The server names of a `tls` matcher; none for `no_sni`.
    pub fn server_names(&self) -> &[String] {
        match self {
            StreamMatcher::Tls { server_names, .. } => server_names,
            StreamMatcher::NoSni { .. } => &[],
        }
    }

    /// The ALPN protocols the rule asks for, empty for any.
    pub fn alpn(&self) -> &[String] {
        match self {
            StreamMatcher::Tls { alpn, .. } | StreamMatcher::NoSni { alpn } => alpn,
        }
    }
}

/// What a terminating stream presents and verifies (D-f, D-h).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamTlsTerminate {
    /// The stored certificates the stream serves, 1 to
    /// [`Stream::TERMINATE_CERTIFICATES_MAX`]: the fleet entitlement for
    /// their private keys, as `Route::certificate_id` is for a route's.
    /// The handshake itself answers from the node's resolver, so these
    /// decide which keys reach the stream's nodes, and the API checks
    /// that they cover the rules' names.
    pub certificate_ids: Vec<String>,
    /// Client certificate verification against the stream's own CA
    /// bundle, in the route's shape; none verifies nobody.
    #[serde(default)]
    pub client_auth: Option<MtlsConfig>,
}

/// TLS from Lorica to the backend (D-i). The backend's HTTP TLS fields
/// (`tls_upstream`, `tls_sni`, `tls_skip_verify`) never apply to a
/// stream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamUpstreamTls {
    /// The name sent as SNI and verified.
    #[serde(default)]
    pub server_name: UpstreamServerName,
    /// A PEM bundle that replaces the public trust; none trusts the
    /// public roots.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// Accept any certificate. Refused beside `ca_cert_pem` or
    /// `client_certificate_id`.
    #[serde(default)]
    pub skip_verify: bool,
    /// A stored certificate presented to the backend; its key reaches
    /// the stream's nodes like `tls_terminate.certificate_ids`.
    #[serde(default)]
    pub client_certificate_id: Option<String>,
    /// 0 to [`Stream::ALPN_MAX`] protocols offered to the backend, in
    /// order.
    #[serde(default)]
    pub alpn: Vec<String>,
}

/// The name a stream's upstream TLS sends and verifies (D-i).
///
/// The two modes without a field are empty struct variants, not unit
/// variants: serde enforces `deny_unknown_fields` on the fields of an
/// internally tagged struct variant, and ignores extra keys beside a
/// unit variant's tag, which the strict canonical decode must not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamServerName {
    /// The backend's host part: a DNS name is sent and verified; an IP
    /// literal sends no SNI and is verified against an `iPAddress` SAN.
    BackendAddress {},
    /// The client's SNI as matched, on a terminating stream; a client
    /// without SNI falls back to the backend's address.
    Client {},
    /// A fixed DNS name or IP literal.
    Fixed {
        /// The name.
        name: String,
    },
}

impl Default for UpstreamServerName {
    fn default() -> UpstreamServerName {
        UpstreamServerName::BackendAddress {}
    }
}

impl UpstreamServerName {
    /// The mode as the API and the logs spell it.
    pub fn mode(&self) -> &'static str {
        match self {
            UpstreamServerName::BackendAddress {} => "backend_address",
            UpstreamServerName::Client {} => "client",
            UpstreamServerName::Fixed { .. } => "fixed",
        }
    }
}

/// A rule's or an upstream's ALPN protocols: at most
/// [`Stream::ALPN_MAX`], each 1 to [`Stream::ALPN_PROTOCOL_MAX_LEN`]
/// bytes of visible ASCII (0x21 to 0x7e), none twice.
fn validate_alpn(stream: &str, field: &str, alpn: &[String]) -> Result<(), String> {
    if alpn.len() > Stream::ALPN_MAX {
        return Err(format!(
            "stream `{stream}`: {field} holds at most {} protocols (got {})",
            Stream::ALPN_MAX,
            alpn.len()
        ));
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for protocol in alpn {
        if protocol.is_empty()
            || protocol.len() > Stream::ALPN_PROTOCOL_MAX_LEN
            || !protocol.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(format!(
                "stream `{stream}`: {field} protocol {protocol:?} must be 1..={} bytes of \
                 visible ASCII",
                Stream::ALPN_PROTOCOL_MAX_LEN
            ));
        }
        if !seen.insert(protocol) {
            return Err(format!(
                "stream `{stream}`: {field} lists {protocol:?} twice"
            ));
        }
    }
    Ok(())
}

/// A PEM bundle field: not blank, at most [`Stream::PEM_BUNDLE_MAX_BYTES`],
/// with at least one certificate block. That every block is a valid
/// certificate is the API's check (`build_mtls_config`), which parses
/// X.509; here the shape alone, on every writer.
fn validate_pem_bundle(stream: &str, field: &str, pem: &str) -> Result<(), String> {
    if pem.trim().is_empty() {
        return Err(format!("stream `{stream}`: {field} is empty"));
    }
    if pem.len() > Stream::PEM_BUNDLE_MAX_BYTES {
        return Err(format!(
            "stream `{stream}`: {field} is larger than {} bytes",
            Stream::PEM_BUNDLE_MAX_BYTES
        ));
    }
    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(format!(
            "stream `{stream}`: {field} holds no PEM certificate block"
        ));
    }
    Ok(())
}

/// A reference to a stored certificate: not blank, no control
/// character, at most [`Stream::CERTIFICATE_ID_MAX_LEN`] bytes. That it
/// names a stored row is the API's check, where the rows are.
fn validate_certificate_id(stream: &str, field: &str, id: &str) -> Result<(), String> {
    if id.trim().is_empty()
        || id.len() > Stream::CERTIFICATE_ID_MAX_LEN
        || id.chars().any(char::is_control)
    {
        return Err(format!(
            "stream `{stream}`: {field} entry {:?} is not a certificate id",
            id.chars()
                .take(Stream::CERTIFICATE_ID_MAX_LEN + 1)
                .collect::<String>()
        ));
    }
    Ok(())
}

/// A server name of a rule as it is stored and matched: trimmed, in
/// `canonical_hostname` form (D-c).
pub fn canonical_server_name(raw: &str) -> String {
    canonical_hostname(raw.trim()).into_owned()
}

/// The settings of a UDP stream (Story 12.5 D-l), each with its default,
/// its range and, in its doc comment, what the PRD's survey of other
/// proxies found (2026-09-28). The defaults and ranges are the associated
/// constants, which every surface reads.
///
/// The bound towards one source key per node and per second (IV1's
/// documented bound) is
/// `min(source_byte_rate x response_bytes_ratio, source_datagram_rate x
/// responses_per_request x max_datagram_bytes)` bytes, plus one second's
/// worth again as burst; [`UdpSettings::reflection_bound`] computes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpSettings {
    /// Concurrent sessions of the stream per node, exact across workers:
    /// the stream's share of the node's session ceiling,
    /// [`UdpSettings::MAX_SESSIONS_RANGE`]. Not surveyed as a
    /// per-listener default.
    #[serde(default = "UdpSettings::default_max_sessions")]
    pub max_sessions: u32,
    /// Concurrent sessions per source key (an IPv4 address or an IPv6
    /// /64) per node, [`UdpSettings::SOURCE_SESSION_CAP_RANGE`]; `None`
    /// is [`UdpSettings::DEFAULT_SOURCE_SESSION_CAP`]. Workers admitting
    /// one source at once can pass it by at most the worker count minus
    /// one. Only an explicit value at or below
    /// [`UDP_EXPOSED_SOURCE_SESSION_CAP_MAX`] satisfies the
    /// listen-address rule ([`udp_exposure_check`]). Survey: nginx
    /// `limit_conn` (no default); HAProxy Enterprise and Envoy not
    /// surveyed for UDP.
    #[serde(default)]
    pub source_session_cap: Option<u32>,
    /// Client datagrams forwarded per session before it is retired and
    /// the next datagram opens a new one,
    /// [`UdpSettings::REQUESTS_PER_SESSION_RANGE`]; `None` for no bound.
    /// It shortens a session's life and bounds no reflection, so no
    /// bound needs no badge. Survey: nginx `proxy_requests`, default 0
    /// (unbounded).
    ///
    /// Absent from a document, it reads as no bound: TOML has no null, so
    /// an exported `None` is an absent key, and reading it back as the
    /// default would turn an unbounded stream bounded on re-import. A
    /// document without the whole `udp` object takes every default
    /// ([`Stream::fill_protocol_defaults`]).
    #[serde(default)]
    pub requests_per_session: Option<u32>,
    /// Backend datagrams forwarded per client datagram,
    /// [`UdpSettings::RESPONSES_PER_REQUEST_RANGE`]; 0 for a one-way
    /// protocol (syslog). Survey: nginx `proxy_responses` (unbounded
    /// unless set); HAProxy Enterprise exposes a bound; Traefik, Envoy
    /// and caddy-l4 none.
    #[serde(default = "UdpSettings::default_responses_per_request")]
    pub responses_per_request: u32,
    /// Response bytes forwarded per request byte of the session,
    /// [`UdpSettings::RESPONSE_BYTES_RATIO_RANGE`]. The default serves a
    /// DNSSEC or large TXT answer (about 25 times a 50-byte query inside
    /// the 1,232-byte EDNS buffer of the 2020 DNS flag day). No surveyed
    /// product bounds bytes.
    #[serde(default = "UdpSettings::default_response_bytes_ratio")]
    pub response_bytes_ratio: u32,
    /// Lifts both response bounds, for protocols whose backend speaks
    /// unasked (games, VoIP signalling). `responses_per_request` and
    /// `response_bytes_ratio` keep their stored values, unapplied, and
    /// apply again when it is cleared. Shown as a permanent badge.
    #[serde(default)]
    pub unbounded_responses: bool,
    /// Client datagrams per second per source key per node, burst one
    /// second, [`UdpSettings::SOURCE_DATAGRAM_RATE_RANGE`]. None in the
    /// survey.
    #[serde(default = "UdpSettings::default_source_datagram_rate")]
    pub source_datagram_rate: u32,
    /// Client bytes per second per source key per node, burst one
    /// second, [`UdpSettings::SOURCE_BYTE_RATE_RANGE`], and at least
    /// `max_datagram_bytes` so a datagram of the largest size can pass.
    /// None in the survey.
    #[serde(default = "UdpSettings::default_source_byte_rate")]
    pub source_byte_rate: u32,
    /// The largest payload forwarded, both directions; a larger datagram
    /// is dropped and counted, [`UdpSettings::MAX_DATAGRAM_BYTES_RANGE`].
    /// Not surveyed.
    #[serde(default = "UdpSettings::default_max_datagram_bytes")]
    pub max_datagram_bytes: u32,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            max_sessions: Self::DEFAULT_MAX_SESSIONS,
            source_session_cap: None,
            requests_per_session: Some(Self::DEFAULT_REQUESTS_PER_SESSION),
            responses_per_request: Self::DEFAULT_RESPONSES_PER_REQUEST,
            response_bytes_ratio: Self::DEFAULT_RESPONSE_BYTES_RATIO,
            unbounded_responses: false,
            source_datagram_rate: Self::DEFAULT_SOURCE_DATAGRAM_RATE,
            source_byte_rate: Self::DEFAULT_SOURCE_BYTE_RATE,
            max_datagram_bytes: Self::DEFAULT_MAX_DATAGRAM_BYTES,
        }
    }
}

impl UdpSettings {
    /// Default of `max_sessions`.
    pub const DEFAULT_MAX_SESSIONS: u32 = 4_096;
    /// Accepted `max_sessions`; the node ceiling bounds it further.
    pub const MAX_SESSIONS_RANGE: RangeInclusive<u32> = 1..=1_048_576;
    /// The per-source cap an absent `source_session_cap` means.
    pub const DEFAULT_SOURCE_SESSION_CAP: u32 = 256;
    /// Accepted `source_session_cap` when set.
    pub const SOURCE_SESSION_CAP_RANGE: RangeInclusive<u32> = 1..=65_535;
    /// Default of `requests_per_session`.
    pub const DEFAULT_REQUESTS_PER_SESSION: u32 = 64;
    /// Accepted `requests_per_session` when set.
    pub const REQUESTS_PER_SESSION_RANGE: RangeInclusive<u32> = 1..=65_535;
    /// Default of `responses_per_request`.
    pub const DEFAULT_RESPONSES_PER_REQUEST: u32 = 1;
    /// Accepted `responses_per_request`.
    pub const RESPONSES_PER_REQUEST_RANGE: RangeInclusive<u32> = 0..=64;
    /// Default of `response_bytes_ratio`.
    pub const DEFAULT_RESPONSE_BYTES_RATIO: u32 = 32;
    /// Accepted `response_bytes_ratio`.
    pub const RESPONSE_BYTES_RATIO_RANGE: RangeInclusive<u32> = 1..=64;
    /// Default of `source_datagram_rate`, per second.
    pub const DEFAULT_SOURCE_DATAGRAM_RATE: u32 = 1_000;
    /// Accepted `source_datagram_rate`.
    pub const SOURCE_DATAGRAM_RATE_RANGE: RangeInclusive<u32> = 1..=1_000_000;
    /// Default of `source_byte_rate`, bytes per second (512 KiB/s).
    pub const DEFAULT_SOURCE_BYTE_RATE: u32 = 524_288;
    /// Accepted `source_byte_rate`.
    pub const SOURCE_BYTE_RATE_RANGE: RangeInclusive<u32> = 1_024..=1_073_741_824;
    /// Default of `max_datagram_bytes`.
    pub const DEFAULT_MAX_DATAGRAM_BYTES: u32 = 8_192;
    /// Accepted `max_datagram_bytes`: the largest UDP payload over IPv4
    /// tops it.
    pub const MAX_DATAGRAM_BYTES_RANGE: RangeInclusive<u32> = 512..=65_507;

    fn default_max_sessions() -> u32 {
        Self::DEFAULT_MAX_SESSIONS
    }

    fn default_responses_per_request() -> u32 {
        Self::DEFAULT_RESPONSES_PER_REQUEST
    }

    fn default_response_bytes_ratio() -> u32 {
        Self::DEFAULT_RESPONSE_BYTES_RATIO
    }

    fn default_source_datagram_rate() -> u32 {
        Self::DEFAULT_SOURCE_DATAGRAM_RATE
    }

    fn default_source_byte_rate() -> u32 {
        Self::DEFAULT_SOURCE_BYTE_RATE
    }

    fn default_max_datagram_bytes() -> u32 {
        Self::DEFAULT_MAX_DATAGRAM_BYTES
    }

    /// The per-source session cap the engine applies.
    pub fn effective_source_session_cap(&self) -> u32 {
        self.source_session_cap
            .unwrap_or(Self::DEFAULT_SOURCE_SESSION_CAP)
    }

    /// Response bytes per second Lorica forwards at most towards one
    /// source key on one node, burst excluded; `None` with
    /// `unbounded_responses`, which lifts the bound.
    pub fn reflection_bound(&self) -> Option<u64> {
        if self.unbounded_responses {
            return None;
        }
        let by_bytes = u64::from(self.source_byte_rate) * u64::from(self.response_bytes_ratio);
        let by_datagrams = u64::from(self.source_datagram_rate)
            * u64::from(self.responses_per_request)
            * u64::from(self.max_datagram_bytes);
        Some(by_bytes.min(by_datagrams))
    }

    /// Ranges, and a byte rate that lets a datagram of the largest size
    /// through.
    fn validate(&self, stream: &str) -> Result<(), String> {
        within(
            stream,
            "udp.max_sessions",
            self.max_sessions,
            &Self::MAX_SESSIONS_RANGE,
        )?;
        if let Some(cap) = self.source_session_cap {
            within(
                stream,
                "udp.source_session_cap",
                cap,
                &Self::SOURCE_SESSION_CAP_RANGE,
            )?;
        }
        if let Some(requests) = self.requests_per_session {
            within(
                stream,
                "udp.requests_per_session",
                requests,
                &Self::REQUESTS_PER_SESSION_RANGE,
            )?;
        }
        within(
            stream,
            "udp.responses_per_request",
            self.responses_per_request,
            &Self::RESPONSES_PER_REQUEST_RANGE,
        )?;
        within(
            stream,
            "udp.response_bytes_ratio",
            self.response_bytes_ratio,
            &Self::RESPONSE_BYTES_RATIO_RANGE,
        )?;
        within(
            stream,
            "udp.source_datagram_rate",
            self.source_datagram_rate,
            &Self::SOURCE_DATAGRAM_RATE_RANGE,
        )?;
        within(
            stream,
            "udp.source_byte_rate",
            self.source_byte_rate,
            &Self::SOURCE_BYTE_RATE_RANGE,
        )?;
        within(
            stream,
            "udp.max_datagram_bytes",
            self.max_datagram_bytes,
            &Self::MAX_DATAGRAM_BYTES_RANGE,
        )?;
        if self.source_byte_rate < self.max_datagram_bytes {
            return Err(format!(
                "stream `{stream}`: udp.source_byte_rate ({}) is below udp.max_datagram_bytes \
                 ({}): a datagram of the largest size could never pass the per-source byte rate",
                self.source_byte_rate, self.max_datagram_bytes
            ));
        }
        Ok(())
    }
}

/// The highest explicit `udp.source_session_cap` that lets a UDP stream
/// listen on an exposed address without a source allowlist (Story 12.5
/// D-k): it bounds the upstream sockets one spoofed address can pin on a
/// node while leaving room for a NATed site with dozens of queries in
/// flight.
pub const UDP_EXPOSED_SOURCE_SESSION_CAP_MAX: u32 = 64;

/// Whether `address` is loopback, RFC 1918 or ULA, the addresses a UDP
/// stream may listen on with no further condition. Everything else is
/// exposed, the unspecified addresses (they bind every address of the
/// host), link-local and shared address space included.
pub fn is_unexposed_udp_listen_address(address: IpAddr) -> bool {
    match address.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// The listen-address rule of a UDP stream (Story 12.5 D-k, PRD AC #3):
/// on an exposed address ([`is_unexposed_udp_listen_address`]) the
/// stream needs a source allowlist or an explicit `udp.source_session_cap`
/// at or below [`UDP_EXPOSED_SOURCE_SESSION_CAP_MAX`]. The default cap
/// does not count: the rule makes the operator choose a number. A TCP
/// stream, or a UDP stream without its settings, passes; the latter is
/// [`Stream::validate`]'s to refuse.
///
/// Called by `Stream::validate` from Story 12.5 Lot G, with
/// `has_source_allowlist = false` until Story 12.6 adds the allowlist.
///
/// # Errors
///
/// The refusal, naming the address, the rule and both remedies.
pub fn udp_exposure_check(stream: &Stream, has_source_allowlist: bool) -> Result<(), String> {
    let Some(udp) = stream
        .udp
        .filter(|_| stream.protocol == StreamProtocol::Udp)
    else {
        return Ok(());
    };
    if has_source_allowlist || is_unexposed_udp_listen_address(stream.listen_address) {
        return Ok(());
    }
    if udp
        .source_session_cap
        .is_some_and(|cap| cap <= UDP_EXPOSED_SOURCE_SESSION_CAP_MAX)
    {
        return Ok(());
    }
    Err(format!(
        "stream `{}`: UDP listen address {} is exposed (not loopback, RFC 1918 or ULA), so the \
         stream needs a source allowlist or an explicit udp.source_session_cap of at most \
         {UDP_EXPOSED_SOURCE_SESSION_CAP_MAX}",
        stream.name, stream.listen_address
    ))
}

/// What a UDP stream may do with one Story 12.3 setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnUdp {
    /// It has a UDP meaning (Story 12.5 D-l) and is validated on UDP
    /// as on TCP, plus any UDP-only refusal of a value.
    Applies,
    /// It must hold its default on a UDP stream, for the reason given.
    KeepsDefault(&'static str),
}

/// One Story 12.3 setting as the UDP rule sees it.
#[derive(Debug, Clone, Copy)]
pub struct TcpEngineField {
    /// The field name, as every surface spells it.
    pub name: &'static str,
    /// Whether the stream leaves it at its default for its protocol.
    pub at_default: fn(&Stream) -> bool,
    /// What a UDP stream may do with it.
    pub on_udp: OnUdp,
}

/// Every Story 12.3 setting, in declaration order, with what a UDP
/// stream may do with it (Story 12.3 D-q, Story 12.5 D-l). A setting
/// gains or loses a UDP meaning by changing its [`OnUdp`] here, not by
/// adding a second rule somewhere else.
pub const TCP_ENGINE_FIELDS: &[TcpEngineField] = &[
    TcpEngineField {
        name: "load_balancing",
        at_default: |s| s.load_balancing == LoadBalancing::RoundRobin,
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "connect_timeout_ms",
        at_default: |s| s.connect_timeout_ms == Stream::DEFAULT_CONNECT_TIMEOUT_MS,
        on_udp: OnUdp::KeepsDefault("a UDP session opens no connection to time"),
    },
    TcpEngineField {
        name: "idle_timeout_s",
        at_default: |s| s.idle_timeout_s == Stream::default_idle_timeout_s(s.protocol),
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "total_timeout_s",
        at_default: |s| s.total_timeout_s.is_none(),
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "max_connect_attempts",
        at_default: |s| s.max_connect_attempts == Stream::DEFAULT_MAX_CONNECT_ATTEMPTS,
        on_udp: OnUdp::KeepsDefault(
            "a UDP session is never retried once its first datagram is sent",
        ),
    },
    TcpEngineField {
        name: "backend_keepalive",
        at_default: |s| s.backend_keepalive == Stream::DEFAULT_BACKEND_KEEPALIVE,
        on_udp: OnUdp::KeepsDefault("TCP keepalive has no UDP counterpart"),
    },
    TcpEngineField {
        name: "backend_keepalive_idle_s",
        at_default: |s| s.backend_keepalive_idle_s == Stream::DEFAULT_BACKEND_KEEPALIVE_IDLE_S,
        on_udp: OnUdp::KeepsDefault("TCP keepalive has no UDP counterpart"),
    },
    TcpEngineField {
        name: "close_on_backend_down",
        at_default: |s| !s.close_on_backend_down,
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "proxy_protocol_send",
        at_default: |s| s.proxy_protocol_send == StreamProxyProtocol::Off,
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "proxy_protocol_accept",
        at_default: |s| !s.proxy_protocol_accept,
        on_udp: OnUdp::KeepsDefault(
            "a UDP source address is spoofable, so a trusted PROXY source means nothing on UDP",
        ),
    },
    TcpEngineField {
        name: "proxy_protocol_trusted_cidrs",
        at_default: |s| s.proxy_protocol_trusted_cidrs.is_empty(),
        on_udp: OnUdp::KeepsDefault("PROXY accept is refused on UDP, so there is no peer to trust"),
    },
    TcpEngineField {
        name: "source_addresses",
        at_default: |s| s.source_addresses.is_empty(),
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "allow_local_backend",
        at_default: |s| !s.allow_local_backend,
        on_udp: OnUdp::Applies,
    },
    TcpEngineField {
        name: "upload_rate_bps",
        at_default: |s| s.upload_rate_bps.is_none(),
        on_udp: OnUdp::KeepsDefault("a UDP stream is bounded per source by udp.source_byte_rate"),
    },
    TcpEngineField {
        name: "download_rate_bps",
        at_default: |s| s.download_rate_bps.is_none(),
        on_udp: OnUdp::KeepsDefault(
            "a UDP stream's responses are bounded by udp.response_bytes_ratio",
        ),
    },
    TcpEngineField {
        name: "max_connections",
        at_default: |s| s.max_connections == Stream::DEFAULT_MAX_CONNECTIONS,
        on_udp: OnUdp::KeepsDefault("a UDP stream's session cap is udp.max_sessions"),
    },
];

/// Refuse `value` outside `range`, naming the stream and the field.
fn within<T: PartialOrd + Display>(
    stream: &str,
    field: &str,
    value: T,
    range: &RangeInclusive<T>,
) -> Result<(), String> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "stream `{stream}`: {field} must be {}..={} (got {value})",
            range.start(),
            range.end()
        ))
    }
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
    /// Default of `connect_timeout_ms`.
    pub const DEFAULT_CONNECT_TIMEOUT_MS: u32 = 5_000;
    /// Accepted `connect_timeout_ms`.
    pub const CONNECT_TIMEOUT_MS_RANGE: RangeInclusive<u32> = 100..=60_000;
    /// Default of `idle_timeout_s` on a TCP stream (nginx's
    /// `proxy_timeout`).
    pub const DEFAULT_TCP_IDLE_TIMEOUT_S: u32 = 600;
    /// Accepted `idle_timeout_s` on a TCP stream.
    pub const TCP_IDLE_TIMEOUT_S_RANGE: RangeInclusive<u32> = 1..=86_400;
    /// Default of `idle_timeout_s` on a UDP stream (Story 12.5 D-l).
    /// Survey: Traefik 3 s, HAProxy Enterprise 10 s, caddy-l4 30 s, Envoy
    /// 1 min; nginx `proxy_timeout` 10 min.
    pub const DEFAULT_UDP_IDLE_TIMEOUT_S: u32 = 10;
    /// Accepted `idle_timeout_s` on a UDP stream: a session holds an
    /// upstream socket and an ephemeral port for as long as it idles.
    pub const UDP_IDLE_TIMEOUT_S_RANGE: RangeInclusive<u32> = 1..=3_600;
    /// Accepted `total_timeout_s` when set.
    pub const TOTAL_TIMEOUT_S_RANGE: RangeInclusive<u32> = 1..=604_800;
    /// Default of `max_connect_attempts`.
    pub const DEFAULT_MAX_CONNECT_ATTEMPTS: u8 = 3;
    /// Accepted `max_connect_attempts`.
    pub const MAX_CONNECT_ATTEMPTS_RANGE: RangeInclusive<u8> = 1..=10;
    /// Default of `backend_keepalive`.
    pub const DEFAULT_BACKEND_KEEPALIVE: bool = true;
    /// Default of `backend_keepalive_idle_s`.
    pub const DEFAULT_BACKEND_KEEPALIVE_IDLE_S: u32 = 60;
    /// Accepted `backend_keepalive_idle_s`.
    pub const BACKEND_KEEPALIVE_IDLE_S_RANGE: RangeInclusive<u32> = 1..=7_200;
    /// The most entries `proxy_protocol_trusted_cidrs` holds.
    pub const PROXY_PROTOCOL_TRUSTED_CIDRS_MAX: usize = 256;
    /// The most entries `source_addresses` holds.
    pub const SOURCE_ADDRESSES_MAX: usize = 16;
    /// Accepted `upload_rate_bps` and `download_rate_bps` when set.
    pub const RATE_BPS_RANGE: RangeInclusive<u64> = 1_024..=10_000_000_000;
    /// Default of `max_connections`.
    pub const DEFAULT_MAX_CONNECTIONS: u32 = 1_024;
    /// Accepted `max_connections`.
    pub const MAX_CONNECTIONS_RANGE: RangeInclusive<u32> = 1..=65_535;
    /// What a TLS stream waits for a ClientHello when
    /// `clienthello_timeout_ms` is unset: a client's first flight, sent
    /// the moment TCP completes, with room for several retransmissions.
    pub const DEFAULT_CLIENTHELLO_TIMEOUT_MS: u32 = 5_000;
    /// Accepted `clienthello_timeout_ms` (Story 12.4 Resolved 7): the
    /// minimum keeps a client on a lossy link able to retransmit its
    /// first flight, the maximum bounds how long a pending connection
    /// holds an fd and its ClientHello buffer.
    pub const CLIENTHELLO_TIMEOUT_MS_RANGE: RangeInclusive<u32> = 1_000..=60_000;
    /// The most rules a TLS stream holds.
    pub const MATCH_RULES_MAX: usize = 64;
    /// The longest rule name, in bytes.
    pub const MATCH_RULE_NAME_MAX_LEN: usize = 64;
    /// The most server names one `tls` rule lists.
    pub const RULE_SERVER_NAMES_MAX: usize = 64;
    /// The most server names a stream's rules list together.
    pub const SERVER_NAMES_MAX: usize = 1_024;
    /// The most ALPN protocols a rule asks for or an upstream offers.
    pub const ALPN_MAX: usize = 8;
    /// The longest ALPN protocol name, in bytes (RFC 7301).
    pub const ALPN_PROTOCOL_MAX_LEN: usize = 255;
    /// The most certificates `tls_terminate.certificate_ids` lists.
    pub const TERMINATE_CERTIFICATES_MAX: usize = 16;
    /// The longest certificate id a stream refers to, in bytes.
    pub const CERTIFICATE_ID_MAX_LEN: usize = 128;
    /// The largest PEM bundle a stream carries, the route's mTLS limit.
    pub const PEM_BUNDLE_MAX_BYTES: usize = 1_048_576;
    /// The most `client_auth.allowed_organizations` entries, the route's
    /// limit.
    pub const ALLOWED_ORGANIZATIONS_MAX: usize = 100;

    /// A stream with every setting at its default for `protocol`:
    /// enabled, fleet-wide, no group, the Story 12.3 defaults, and on UDP
    /// the default [`UdpSettings`]. The one place a writer that builds a
    /// new stream takes its defaults from, so a protocol-dependent
    /// default cannot be missed.
    pub fn new(
        id: String,
        name: String,
        protocol: StreamProtocol,
        listen_address: IpAddr,
        port_first: u16,
        port_last: u16,
        at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name,
            group_name: String::new(),
            protocol,
            enabled: true,
            listen_address,
            port_first,
            port_last,
            node_selector: Vec::new(),
            load_balancing: default_load_balancing(),
            connect_timeout_ms: Self::DEFAULT_CONNECT_TIMEOUT_MS,
            idle_timeout_s: Self::default_idle_timeout_s(protocol),
            total_timeout_s: None,
            max_connect_attempts: Self::DEFAULT_MAX_CONNECT_ATTEMPTS,
            backend_keepalive: Self::DEFAULT_BACKEND_KEEPALIVE,
            backend_keepalive_idle_s: Self::DEFAULT_BACKEND_KEEPALIVE_IDLE_S,
            close_on_backend_down: false,
            proxy_protocol_send: StreamProxyProtocol::Off,
            proxy_protocol_accept: false,
            proxy_protocol_trusted_cidrs: Vec::new(),
            source_addresses: Vec::new(),
            allow_local_backend: false,
            upload_rate_bps: None,
            download_rate_bps: None,
            max_connections: Self::DEFAULT_MAX_CONNECTIONS,
            udp: Self::default_udp_settings(protocol),
            tls_mode: StreamTlsMode::None,
            match_rules: Vec::new(),
            no_sni_acknowledged: false,
            clienthello_timeout_ms: None,
            tls_terminate: None,
            upstream_tls: None,
            created_at: at,
            updated_at: at,
        }
    }

    /// The ClientHello deadline from accept, in milliseconds:
    /// `clienthello_timeout_ms` or its default.
    pub fn effective_clienthello_timeout_ms(&self) -> u32 {
        self.clienthello_timeout_ms
            .unwrap_or(Self::DEFAULT_CLIENTHELLO_TIMEOUT_MS)
    }

    /// Whether the stream's connections are drained by a hot upgrade
    /// even once live transfer exists (D8, Story 12.4 D-j): a TLS session
    /// Lorica terminates or originates holds rustls state no other
    /// process can take over. The one rule the API, the dashboard's
    /// badge, the upgrade preview and the transfer exclusion read.
    pub fn drains_on_upgrade(&self) -> bool {
        self.tls_mode == StreamTlsMode::Terminate || self.upstream_tls.is_some()
    }

    /// Whether any rule admits a client naming no server.
    pub fn has_no_sni_rule(&self) -> bool {
        self.match_rules
            .iter()
            .any(|rule| matches!(rule.matcher, StreamMatcher::NoSni { .. }))
    }

    /// Whether the stream's `no_sni` rule needs `no_sni_acknowledged`
    /// (D-d, D7): it does unless the stream restricts its sources.
    /// Story 12.4 calls it with `false`; Story 12.6 passes whether the
    /// stream has a source allowlist.
    pub fn no_sni_needs_acknowledgement(&self, has_source_allowlist: bool) -> bool {
        self.has_no_sni_rule() && !has_source_allowlist
    }

    /// The rule named `name`.
    pub fn match_rule(&self, name: &str) -> Option<&StreamMatchRule> {
        self.match_rules.iter().find(|rule| rule.name == name)
    }

    /// Every stored certificate the stream refers to, each once:
    /// `tls_terminate.certificate_ids` then
    /// `upstream_tls.client_certificate_id`. The fleet entitlement to a
    /// certificate's private key, and the certificate delete guard,
    /// read this list.
    pub fn certificate_references(&self) -> Vec<&str> {
        let mut references: Vec<&str> = Vec::new();
        let terminate = self
            .tls_terminate
            .iter()
            .flat_map(|t| t.certificate_ids.iter().map(String::as_str));
        let client = self
            .upstream_tls
            .iter()
            .filter_map(|u| u.client_certificate_id.as_deref());
        for id in terminate.chain(client) {
            if !references.contains(&id) {
                references.push(id);
            }
        }
        references
    }

    /// Put every rule's server names in the form they are stored and
    /// matched in ([`canonical_server_name`]). The store applies it on
    /// every write, so `App.Example.COM.` is stored `app.example.com`.
    pub fn canonicalise_server_names(&mut self) {
        for rule in &mut self.match_rules {
            if let StreamMatcher::Tls { server_names, .. } = &mut rule.matcher {
                for name in server_names.iter_mut() {
                    let canonical = canonical_server_name(name);
                    if *name != canonical {
                        *name = canonical;
                    }
                }
            }
        }
    }

    /// The UDP settings a new stream of `protocol` holds: the defaults
    /// on UDP, none on TCP.
    pub fn default_udp_settings(protocol: StreamProtocol) -> Option<UdpSettings> {
        match protocol {
            StreamProtocol::Tcp => None,
            StreamProtocol::Udp => Some(UdpSettings::default()),
        }
    }

    /// Give a stream decoded from a document the protocol-dependent
    /// defaults a serde default cannot know: the [`UdpSettings`] of a UDP
    /// stream that carries none. A UDP stream's `idle_timeout_s` is the
    /// reader's to fill before decoding, where an absent key is still
    /// visible (`crate::import`).
    pub fn fill_protocol_defaults(&mut self) {
        if self.udp.is_none() {
            self.udp = Self::default_udp_settings(self.protocol);
        }
    }

    /// The default `idle_timeout_s` of a stream of `protocol`: one field
    /// whose default depends on the protocol (Story 12.5 Interface edit
    /// E1), read by the create path, the import and migration 76.
    pub fn default_idle_timeout_s(protocol: StreamProtocol) -> u32 {
        match protocol {
            StreamProtocol::Tcp => Self::DEFAULT_TCP_IDLE_TIMEOUT_S,
            StreamProtocol::Udp => Self::DEFAULT_UDP_IDLE_TIMEOUT_S,
        }
    }

    /// The accepted `idle_timeout_s` of a stream of `protocol`.
    pub fn idle_timeout_s_range(protocol: StreamProtocol) -> RangeInclusive<u32> {
        match protocol {
            StreamProtocol::Tcp => Self::TCP_IDLE_TIMEOUT_S_RANGE,
            StreamProtocol::Udp => Self::UDP_IDLE_TIMEOUT_S_RANGE,
        }
    }

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
    /// group, listen address, ports, the [`STREAM_PORT_RANGE_MAX`] cap,
    /// the selector rule shared with routes, the engine settings, and on
    /// UDP its settings. The listen-address rule
    /// ([`udp_exposure_check`]) joins it with Story 12.5 Lot G, which
    /// makes `udp.source_session_cap` settable from the management API. Which backends it may
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
            .map_err(|e| format!("stream `{}`: {e}", self.name))?;
        self.validate_engine_settings()
    }

    /// The Story 12.3 settings (D-q): ranges, the PROXY trust list
    /// (D-k), the source addresses (D-l), the UDP rule over
    /// [`TCP_ENGINE_FIELDS`], and the UDP settings of Story 12.5.
    fn validate_engine_settings(&self) -> Result<(), String> {
        let name = self.name.as_str();
        // First, so a UDP stream is told a setting does not apply rather
        // than how to make it valid.
        self.validate_protocol_settings()?;
        within(
            name,
            "connect_timeout_ms",
            self.connect_timeout_ms,
            &Self::CONNECT_TIMEOUT_MS_RANGE,
        )?;
        within(
            name,
            "idle_timeout_s",
            self.idle_timeout_s,
            &Self::idle_timeout_s_range(self.protocol),
        )?;
        if let Some(total) = self.total_timeout_s {
            within(name, "total_timeout_s", total, &Self::TOTAL_TIMEOUT_S_RANGE)?;
        }
        within(
            name,
            "max_connect_attempts",
            self.max_connect_attempts,
            &Self::MAX_CONNECT_ATTEMPTS_RANGE,
        )?;
        within(
            name,
            "backend_keepalive_idle_s",
            self.backend_keepalive_idle_s,
            &Self::BACKEND_KEEPALIVE_IDLE_S_RANGE,
        )?;
        for (field, rate) in [
            ("upload_rate_bps", self.upload_rate_bps),
            ("download_rate_bps", self.download_rate_bps),
        ] {
            if let Some(rate) = rate {
                within(name, field, rate, &Self::RATE_BPS_RANGE)?;
            }
        }
        within(
            name,
            "max_connections",
            self.max_connections,
            &Self::MAX_CONNECTIONS_RANGE,
        )?;
        self.validate_proxy_protocol_trust()?;
        self.validate_source_addresses()?;
        self.validate_tls()
    }

    /// The names of the TLS fields of Story 12.4 (D-k), as every surface
    /// spells them, read from the one list [`Stream::validate`] judges
    /// them by.
    pub fn tls_field_names() -> [&'static str; 6] {
        let any = Stream::new(
            String::new(),
            String::new(),
            StreamProtocol::Tcp,
            IpAddr::from([0, 0, 0, 0]),
            0,
            0,
            DateTime::<Utc>::default(),
        );
        any.tls_fields_set().map(|(name, _)| name)
    }

    /// The TLS fields that are set, by name, in declaration order: what
    /// a mode that does not take one of them refuses (D-g).
    fn tls_fields_set(&self) -> [(&'static str, bool); 6] {
        [
            ("tls_mode", self.tls_mode != StreamTlsMode::None),
            ("match_rules", !self.match_rules.is_empty()),
            ("no_sni_acknowledged", self.no_sni_acknowledged),
            (
                "clienthello_timeout_ms",
                self.clienthello_timeout_ms.is_some(),
            ),
            ("tls_terminate", self.tls_terminate.is_some()),
            ("upstream_tls", self.upstream_tls.is_some()),
        ]
    }

    /// Story 12.4: which TLS fields the mode takes (D-g), the rules
    /// (D-c, D-d), termination (D-f, D-h), upstream TLS (D-i) and the
    /// ClientHello deadline. A field that does not apply is refused
    /// naming the field and the mode, never dropped.
    fn validate_tls(&self) -> Result<(), String> {
        let name = self.name.as_str();
        if self.protocol == StreamProtocol::Udp {
            if let Some((field, _)) = self.tls_fields_set().into_iter().find(|(_, set)| *set) {
                return Err(format!(
                    "stream `{name}`: {field} is refused on a UDP stream: there is no TLS over \
                     UDP (DTLS) for streams"
                ));
            }
            return Ok(());
        }
        let mode = self.tls_mode;
        let refused = |field: &str| {
            Err(format!(
                "stream `{name}`: {field} is refused on a stream whose tls_mode is {}",
                mode.as_str()
            ))
        };
        let required = |field: &str| {
            Err(format!(
                "stream `{name}`: tls_mode {} requires {field}",
                mode.as_str()
            ))
        };
        match mode {
            StreamTlsMode::None => {
                if !self.match_rules.is_empty() {
                    return refused("match_rules");
                }
                if self.clienthello_timeout_ms.is_some() {
                    return refused("clienthello_timeout_ms");
                }
                if self.tls_terminate.is_some() {
                    return refused("tls_terminate");
                }
            }
            StreamTlsMode::Passthrough => {
                if self.match_rules.is_empty() {
                    return required("at least one of match_rules");
                }
                if self.tls_terminate.is_some() {
                    return refused("tls_terminate");
                }
                if self.upstream_tls.is_some() {
                    return refused("upstream_tls");
                }
            }
            StreamTlsMode::Terminate => {
                if self.match_rules.is_empty() {
                    return required("at least one of match_rules");
                }
                if self.tls_terminate.is_none() {
                    return required("tls_terminate");
                }
            }
        }
        if let Some(upstream) = &self.upstream_tls {
            if matches!(upstream.server_name, UpstreamServerName::Client {})
                && mode != StreamTlsMode::Terminate
            {
                return refused("upstream_tls.server_name client");
            }
        }
        if self.no_sni_acknowledged && !self.has_no_sni_rule() {
            return Err(format!(
                "stream `{name}`: no_sni_acknowledged is refused on a stream without a no_sni rule"
            ));
        }
        if self.no_sni_needs_acknowledgement(false) && !self.no_sni_acknowledged {
            return Err(format!(
                "stream `{name}`: a no_sni rule admits clients that name no server; restrict \
                 the stream to a source allowlist or set no_sni_acknowledged"
            ));
        }
        if let Some(timeout) = self.clienthello_timeout_ms {
            within(
                name,
                "clienthello_timeout_ms",
                timeout,
                &Self::CLIENTHELLO_TIMEOUT_MS_RANGE,
            )?;
        }
        self.validate_match_rules()?;
        if let Some(terminate) = &self.tls_terminate {
            self.validate_terminate(terminate)?;
        }
        if let Some(upstream) = &self.upstream_tls {
            self.validate_upstream_tls(upstream)?;
        }
        Ok(())
    }

    /// The rules (D-c, D-d): names, caps, server names in their stored
    /// shape, ALPN, and no two rules a ClientHello could match alike.
    fn validate_match_rules(&self) -> Result<(), String> {
        let name = self.name.as_str();
        if self.match_rules.len() > Self::MATCH_RULES_MAX {
            return Err(format!(
                "stream `{name}`: match_rules holds at most {} rules (got {})",
                Self::MATCH_RULES_MAX,
                self.match_rules.len()
            ));
        }
        let mut rule_names: BTreeSet<&str> = BTreeSet::new();
        let mut total_names: usize = 0;
        // Each canonical server name (`None` for `no_sni`) with the rules
        // listing it, for the ambiguity rule.
        let mut claims: BTreeMap<Option<String>, Vec<&StreamMatchRule>> = BTreeMap::new();
        for rule in &self.match_rules {
            if rule.name.is_empty()
                || rule.name.len() > Self::MATCH_RULE_NAME_MAX_LEN
                || !is_identifier_alphabet(&rule.name)
            {
                return Err(format!(
                    "stream `{name}`: rule name {:?} must be 1..={} characters of ASCII \
                     lowercase letters, digits, `-` and `_`",
                    rule.name,
                    Self::MATCH_RULE_NAME_MAX_LEN
                ));
            }
            if !rule_names.insert(&rule.name) {
                return Err(format!(
                    "stream `{name}`: two rules are named `{}`",
                    rule.name
                ));
            }
            validate_alpn(
                name,
                &format!("rule `{}` alpn", rule.name),
                rule.matcher.alpn(),
            )?;
            match &rule.matcher {
                StreamMatcher::Tls { server_names, .. } => {
                    if server_names.is_empty() || server_names.len() > Self::RULE_SERVER_NAMES_MAX {
                        return Err(format!(
                            "stream `{name}`: rule `{}` lists 1..={} server names (got {})",
                            rule.name,
                            Self::RULE_SERVER_NAMES_MAX,
                            server_names.len()
                        ));
                    }
                    total_names += server_names.len();
                    let mut own: BTreeSet<String> = BTreeSet::new();
                    for raw in server_names {
                        let canonical = canonical_server_name(raw);
                        validate_hostname_syntax(&canonical, STREAM_SERVER_NAME_SHAPE)
                            .map_err(|e| format!("stream `{name}`: rule `{}`: {e}", rule.name))?;
                        let body = canonical.strip_prefix("*.").unwrap_or(&canonical);
                        if names_an_address(body) {
                            return Err(format!(
                                "stream `{name}`: rule `{}`: server name `{canonical}` is an \
                                 address; a ClientHello never names one (RFC 6066)",
                                rule.name
                            ));
                        }
                        if !own.insert(canonical.clone()) {
                            return Err(format!(
                                "stream `{name}`: rule `{}` lists `{canonical}` twice",
                                rule.name
                            ));
                        }
                        claims.entry(Some(canonical)).or_default().push(rule);
                    }
                }
                StreamMatcher::NoSni { .. } => claims.entry(None).or_default().push(rule),
            }
        }
        if total_names > Self::SERVER_NAMES_MAX {
            return Err(format!(
                "stream `{name}`: the rules list at most {} server names together (got \
                 {total_names})",
                Self::SERVER_NAMES_MAX
            ));
        }
        for (server_name, rules) in &claims {
            for (index, first) in rules.iter().enumerate() {
                for second in &rules[index + 1..] {
                    let (a, b) = (first.matcher.alpn(), second.matcher.alpn());
                    let overlap = (a.is_empty() && b.is_empty()) || a.iter().any(|p| b.contains(p));
                    if overlap {
                        let what = match server_name {
                            Some(server_name) => format!("server name `{server_name}`"),
                            None => "clients without SNI".to_string(),
                        };
                        return Err(format!(
                            "stream `{name}`: rules `{}` and `{}` both match {what} with the \
                             same ALPN; give them disjoint alpn lists or merge them",
                            first.name, second.name
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// `tls_terminate` (D-f, D-h): its certificates and, when set, the
    /// shape of its client verification.
    fn validate_terminate(&self, terminate: &StreamTlsTerminate) -> Result<(), String> {
        let name = self.name.as_str();
        let ids = &terminate.certificate_ids;
        if ids.is_empty() || ids.len() > Self::TERMINATE_CERTIFICATES_MAX {
            return Err(format!(
                "stream `{name}`: tls_terminate.certificate_ids lists 1..={} certificates (got {})",
                Self::TERMINATE_CERTIFICATES_MAX,
                ids.len()
            ));
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for id in ids {
            validate_certificate_id(name, "tls_terminate.certificate_ids", id)?;
            if !seen.insert(id) {
                return Err(format!(
                    "stream `{name}`: tls_terminate.certificate_ids lists {id} twice"
                ));
            }
        }
        if let Some(client_auth) = &terminate.client_auth {
            validate_pem_bundle(
                name,
                "tls_terminate.client_auth.ca_cert_pem",
                &client_auth.ca_cert_pem,
            )?;
            let organizations = &client_auth.allowed_organizations;
            if organizations.len() > Self::ALLOWED_ORGANIZATIONS_MAX {
                return Err(format!(
                    "stream `{name}`: tls_terminate.client_auth.allowed_organizations holds at \
                     most {} entries (got {})",
                    Self::ALLOWED_ORGANIZATIONS_MAX,
                    organizations.len()
                ));
            }
            for organization in organizations {
                if organization.trim().is_empty() || organization.chars().any(char::is_control) {
                    return Err(format!(
                        "stream `{name}`: tls_terminate.client_auth.allowed_organizations \
                         entry {organization:?} is empty or holds a control character"
                    ));
                }
            }
        }
        Ok(())
    }

    /// `upstream_tls` (D-i): the name, the trust and the client
    /// certificate, and the combinations refused.
    fn validate_upstream_tls(&self, upstream: &StreamUpstreamTls) -> Result<(), String> {
        let name = self.name.as_str();
        if let UpstreamServerName::Fixed { name: fixed } = &upstream.server_name {
            if fixed.trim().parse::<IpAddr>().is_err() {
                if fixed.trim().is_empty() {
                    return Err(format!(
                        "stream `{name}`: upstream_tls.server_name fixed needs a name"
                    ));
                }
                validate_hostname_syntax(fixed, ROUTE_REDIRECT_HOSTNAME_SHAPE)
                    .map_err(|e| format!("stream `{name}`: upstream_tls.server_name fixed: {e}"))?;
            }
        }
        if upstream.skip_verify && upstream.client_certificate_id.is_some() {
            return Err(format!(
                "stream `{name}`: upstream_tls.skip_verify is refused with a \
                 client_certificate_id: a credential is never presented to an unverified backend"
            ));
        }
        if upstream.skip_verify && upstream.ca_cert_pem.is_some() {
            return Err(format!(
                "stream `{name}`: upstream_tls.skip_verify contradicts upstream_tls.ca_cert_pem; \
                 set one of them"
            ));
        }
        if let Some(pem) = &upstream.ca_cert_pem {
            validate_pem_bundle(name, "upstream_tls.ca_cert_pem", pem)?;
        }
        if let Some(id) = &upstream.client_certificate_id {
            validate_certificate_id(name, "upstream_tls.client_certificate_id", id)?;
        }
        validate_alpn(name, "upstream_tls.alpn", &upstream.alpn)
    }

    /// What a protocol allows: on TCP no UDP settings; on UDP its
    /// settings present and valid, every Story 12.3 setting without a
    /// UDP meaning at its default, and the values a UDP stream cannot
    /// use of the ones it has (Story 12.5 D-i, D-j).
    fn validate_protocol_settings(&self) -> Result<(), String> {
        let name = self.name.as_str();
        match self.protocol {
            StreamProtocol::Tcp => {
                if self.udp.is_some() {
                    return Err(format!(
                        "stream `{name}`: udp settings are refused on a TCP stream"
                    ));
                }
                Ok(())
            }
            StreamProtocol::Udp => {
                let refused_default = TCP_ENGINE_FIELDS.iter().find_map(|f| match f.on_udp {
                    OnUdp::KeepsDefault(reason) if !(f.at_default)(self) => Some((f.name, reason)),
                    _ => None,
                });
                if let Some((field, reason)) = refused_default {
                    return Err(format!(
                        "stream `{name}`: {field} must keep its default on a UDP stream: {reason}"
                    ));
                }
                if self.load_balancing == LoadBalancing::PeakEwma {
                    return Err(format!(
                        "stream `{name}`: load_balancing peak_ewma is refused on a UDP stream: \
                         a session has no connect latency to feed it"
                    ));
                }
                if self.proxy_protocol_send == StreamProxyProtocol::V1 {
                    return Err(format!(
                        "stream `{name}`: proxy_protocol_send v1 is refused on a UDP stream: the \
                         v1 text format has no UDP transport; use v2"
                    ));
                }
                let Some(udp) = &self.udp else {
                    return Err(format!(
                        "stream `{name}`: a UDP stream carries its udp settings"
                    ));
                };
                udp.validate(name)
            }
        }
    }

    /// The trust list by the rule of the HTTP listeners' list (Story
    /// 12.8 D-d, the same function), its size cap, and accept on with no
    /// trusted entry refused: no peer could ever send the header.
    fn validate_proxy_protocol_trust(&self) -> Result<(), String> {
        let name = self.name.as_str();
        let list = &self.proxy_protocol_trusted_cidrs;
        if list.len() > Self::PROXY_PROTOCOL_TRUSTED_CIDRS_MAX {
            return Err(format!(
                "stream `{name}`: proxy_protocol_trusted_cidrs holds at most {} entries (got {})",
                Self::PROXY_PROTOCOL_TRUSTED_CIDRS_MAX,
                list.len()
            ));
        }
        // Both listener modes off: the shared function then checks the
        // list's entries alone; the stream's own accept rule follows.
        validate_proxy_protocol(ProxyProtocolMode::Off, ProxyProtocolMode::Off, list)
            .map_err(|e| format!("stream `{name}`: {e}"))?;
        if self.proxy_protocol_accept && list.iter().all(|entry| entry.trim().is_empty()) {
            return Err(format!(
                "stream `{name}`: proxy_protocol_accept is on but proxy_protocol_trusted_cidrs \
                 is empty: no peer could send a PROXY header; list the load balancers first"
            ));
        }
        Ok(())
    }

    /// At most [`Stream::SOURCE_ADDRESSES_MAX`] distinct unicast
    /// literals, none unspecified (the kernel's choice is the empty
    /// list) and none IPv4-mapped (give the IPv4 address itself).
    fn validate_source_addresses(&self) -> Result<(), String> {
        let name = self.name.as_str();
        if self.source_addresses.len() > Self::SOURCE_ADDRESSES_MAX {
            return Err(format!(
                "stream `{name}`: source_addresses holds at most {} addresses (got {})",
                Self::SOURCE_ADDRESSES_MAX,
                self.source_addresses.len()
            ));
        }
        let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
        for &address in &self.source_addresses {
            let refusal = match address {
                IpAddr::V4(v4) if v4.is_unspecified() => Some("is unspecified"),
                IpAddr::V6(v6) if v6.is_unspecified() => Some("is unspecified"),
                IpAddr::V4(v4) if v4.is_multicast() || v4.is_broadcast() => {
                    Some("is not a unicast address")
                }
                IpAddr::V6(v6) if v6.is_multicast() => Some("is not a unicast address"),
                IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => {
                    Some("is an IPv4-mapped IPv6 address; give the IPv4 address itself")
                }
                _ if !seen.insert(address) => Some("is listed twice"),
                _ => None,
            };
            if let Some(refusal) = refusal {
                return Err(format!(
                    "stream `{name}`: source address {address} {refusal}"
                ));
            }
        }
        Ok(())
    }

    /// The families `source_addresses` covers, `None` when the list is
    /// empty (the kernel chooses, so every family is reachable).
    fn source_families(&self) -> Option<(bool, bool)> {
        if self.source_addresses.is_empty() {
            return None;
        }
        Some((
            self.source_addresses.iter().any(IpAddr::is_ipv4),
            self.source_addresses.iter().any(IpAddr::is_ipv6),
        ))
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
    /// Whether the backend is a backup of the stream (Story 12.3, D-f):
    /// a candidate only when no primary is, on either protocol. A stream
    /// with links has at least one primary
    /// ([`check_backend_attachments`]).
    #[serde(default)]
    pub backup: bool,
    /// The rule of the stream this link serves (Story 12.4, D-d): on a
    /// TLS stream every link names one of its rules, on any other stream
    /// none ([`check_backend_attachments`]). A backend serves at most one
    /// rule of a stream.
    #[serde(default)]
    pub rule: Option<String>,
}

impl StreamBackend {
    /// A primary link serving no rule.
    pub fn primary(stream_id: &str, backend_id: &str) -> StreamBackend {
        StreamBackend {
            stream_id: stream_id.to_string(),
            backend_id: backend_id.to_string(),
            backup: false,
            rule: None,
        }
    }
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
    /// A backend whose address is local
    /// (`crate::local_address::is_local_host`) is linked to a stream
    /// that does not set `allow_local_backend` (Story 12.3, D-m rule A).
    LocalBackend,
    /// Every backend linked to the stream is a backup, so none would
    /// ever be selected first (Story 12.3, D-f).
    NoPrimaryBackend,
    /// An IP-literal backend's family is none of the stream's
    /// `source_addresses` (Story 12.3, D-l): no attempt could leave for
    /// it.
    SourceFamilyMismatch,
    /// A link of a TLS stream names no rule (Story 12.4, D-d).
    LinkWithoutRule,
    /// A link names a rule the stream does not have.
    UnknownRule {
        /// The rule the link names.
        rule: String,
    },
    /// Every link of a rule is a backup, so none would ever be selected
    /// first for it (Story 12.3 D-f, per rule).
    RuleWithoutPrimary {
        /// The rule.
        rule: String,
    },
    /// A link names a rule on a stream that reads no ClientHello.
    RuleOnNonTlsStream {
        /// The rule the link names.
        rule: String,
    },
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
            AttachmentRule::LocalBackend => write!(
                f,
                "backend {backend} is a local address and cannot serve {on_stream} unless the \
                 stream sets allow_local_backend"
            ),
            AttachmentRule::NoPrimaryBackend => write!(
                f,
                "every backend of {on_stream} is a backup ({backend} included); make at least \
                 one a primary"
            ),
            AttachmentRule::SourceFamilyMismatch => write!(
                f,
                "backend {backend} is of an address family none of the source_addresses of \
                 {on_stream} has, so no connection could leave for it"
            ),
            AttachmentRule::LinkWithoutRule => write!(
                f,
                "backend {backend} serves TLS {on_stream} without naming one of its rules"
            ),
            AttachmentRule::UnknownRule { rule } => write!(
                f,
                "backend {backend} serves rule `{rule}`, which {on_stream} does not have"
            ),
            AttachmentRule::RuleWithoutPrimary { rule } => write!(
                f,
                "every backend of rule `{rule}` of {on_stream} is a backup ({backend} included); \
                 make at least one a primary"
            ),
            AttachmentRule::RuleOnNonTlsStream { rule } => write!(
                f,
                "backend {backend} serves rule `{rule}`, but {on_stream} reads no ClientHello \
                 (tls_mode none); its links name no rule"
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
///    single-port stream or a route, or portless with active checks on;
/// 4. (Story 12.3) a local backend on a stream without
///    `allow_local_backend` (D-m rule A, IP literals and `localhost`
///    names: a name is not resolved here), a backup link on a stream
///    with no primary (D-f), and an IP-literal backend of a family none
///    of the stream's `source_addresses` has (D-l);
/// 5. (Story 12.4, D-d) a link of a TLS stream naming no rule or a rule
///    the stream lacks, a rule whose links are all backups, and a link
///    naming a rule on a stream that reads no ClientHello. A rule with
///    no link at all, like a stream with none, is accepted and answers
///    `no_healthy_backend`: there is no backend to report it against.
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
    let mut links_by_pair: BTreeMap<(&str, &str), &StreamBackend> = BTreeMap::new();
    let mut streams_with_a_primary: BTreeSet<&str> = BTreeSet::new();
    let mut rules_with_a_primary: BTreeSet<(&str, &str)> = BTreeSet::new();
    for link in snapshot.stream_backends {
        if let Some(stream) = streams_by_id.get(link.stream_id.as_str()) {
            streams_of
                .entry(link.backend_id.as_str())
                .or_default()
                .push(stream);
            links_by_pair.insert((link.stream_id.as_str(), link.backend_id.as_str()), link);
            if !link.backup {
                streams_with_a_primary.insert(link.stream_id.as_str());
                if let Some(rule) = &link.rule {
                    rules_with_a_primary.insert((link.stream_id.as_str(), rule.as_str()));
                }
            }
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

        let host = backend_address_host(&backend.address);
        let local = is_local_host(host);
        let literal_family = host
            .parse::<IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical().is_ipv4());
        for stream in &streams {
            let Some(link) = links_by_pair.get(&(stream.id.as_str(), backend.id.as_str())) else {
                continue;
            };
            if link.backup && !streams_with_a_primary.contains(stream.id.as_str()) {
                return Err(conflict(Some(stream), AttachmentRule::NoPrimaryBackend));
            }
            let tls =
                stream.protocol == StreamProtocol::Tcp && stream.tls_mode.reads_client_hello();
            match (&link.rule, tls) {
                (None, true) => {
                    return Err(conflict(Some(stream), AttachmentRule::LinkWithoutRule))
                }
                (Some(rule), false) => {
                    return Err(conflict(
                        Some(stream),
                        AttachmentRule::RuleOnNonTlsStream { rule: rule.clone() },
                    ))
                }
                (Some(rule), true) => {
                    if stream.match_rule(rule).is_none() {
                        return Err(conflict(
                            Some(stream),
                            AttachmentRule::UnknownRule { rule: rule.clone() },
                        ));
                    }
                    if link.backup
                        && !rules_with_a_primary.contains(&(stream.id.as_str(), rule.as_str()))
                    {
                        return Err(conflict(
                            Some(stream),
                            AttachmentRule::RuleWithoutPrimary { rule: rule.clone() },
                        ));
                    }
                }
                (None, false) => {}
            }
            if local && !stream.allow_local_backend {
                return Err(conflict(Some(stream), AttachmentRule::LocalBackend));
            }
            if let (Some(is_v4), Some((has_v4, has_v6))) =
                (literal_family, stream.source_families())
            {
                if (is_v4 && !has_v4) || (!is_v4 && !has_v6) {
                    return Err(conflict(Some(stream), AttachmentRule::SourceFamilyMismatch));
                }
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
    /// The stream's `max_connections` was reached (Story 12.3, D-p):
    /// per worker process until Story 12.6, per node from then on.
    ConnectionCap,
    /// The UDP stream holds its `udp.max_sessions` on this node (Story
    /// 12.5 D-n).
    SessionCap,
    /// The source key holds its `udp.source_session_cap` on this node.
    SourceSessionCap,
    /// The stream's session table on this node has no room for the
    /// source (its probe window is full); other streams are unaffected.
    SessionTableFull,
    /// The first bytes of a TLS stream's client are no ClientHello the
    /// stream accepts (Story 12.4 D-b), or the server name rustls read
    /// differs from the one the rule was chosen by (D-f).
    InvalidClientHello,
    /// No certificate of the node serves the name (or, for a `no_sni`
    /// rule, the local address) a terminating stream's client asked for.
    NoCertificate,
    /// A terminating stream's handshake failed for another reason, its
    /// deadline included.
    TlsHandshake,
    /// A terminating stream refused the client's certificate, or its
    /// absence, or its organization.
    ClientCertificate,
}

/// Why a UDP datagram was dropped rather than forwarded (Story 12.5
/// D-n). A datagram whose session is refused is counted as the
/// [`StreamRefusal`], never also as a drop. Every surface derives its
/// word list from [`DatagramDropReason::VARIANTS`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, IntoStaticStr, VariantArray,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DatagramDropReason {
    /// A client datagram over `udp.max_datagram_bytes`, or one the PROXY
    /// v2 header would push past the largest UDP payload.
    RequestOversize,
    /// A backend datagram over `udp.max_datagram_bytes`.
    ResponseOversize,
    /// Over the source key's `udp.source_datagram_rate`.
    SourceDatagramRate,
    /// Over the source key's `udp.source_byte_rate`.
    SourceByteRate,
    /// A response past `udp.responses_per_request` times the session's
    /// requests.
    ResponseCountBound,
    /// A response past `udp.response_bytes_ratio` times the session's
    /// request bytes.
    ResponseByteBound,
    /// A datagram that would open a session on a draining binding.
    BindingDraining,
    /// A send that found the socket's buffer full or failed.
    SendFailed,
}

impl DatagramDropReason {
    /// The snake_case word this reason is published as.
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
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
    /// A UDP session took its `udp.requests_per_session` datagrams and
    /// received every response they were owed (Story 12.5 D-b).
    RequestBoundReached,
    /// A UDP session spent its response allowance: every response owed
    /// arrived, or one was dropped for the byte bound (Story 12.5 D-b).
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

/// A terminating stream with every TLS field set and two rules, and the
/// links its two backends serve them by, for the round trips of the
/// store, the export and the import.
#[cfg(test)]
pub(crate) fn sample_tls_stream(label: &str, name: &str, port: u16) -> Stream {
    let mut s = tests::stream(label, name, StreamProtocol::Tcp, port);
    s.tls_mode = StreamTlsMode::Terminate;
    s.match_rules = vec![
        StreamMatchRule {
            name: "web".to_string(),
            matcher: StreamMatcher::Tls {
                server_names: vec!["app.example.com".to_string(), "*.example.com".to_string()],
                alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            },
        },
        StreamMatchRule {
            name: "bare".to_string(),
            matcher: StreamMatcher::NoSni { alpn: Vec::new() },
        },
    ];
    s.no_sni_acknowledged = true;
    s.clienthello_timeout_ms = Some(2_500);
    s.tls_terminate = Some(StreamTlsTerminate {
        certificate_ids: vec!["cert-1".to_string(), "cert-ip".to_string()],
        client_auth: Some(MtlsConfig {
            ca_cert_pem: "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n".to_string(),
            required: false,
            allowed_organizations: vec!["Acme".to_string()],
        }),
    });
    s.upstream_tls = Some(StreamUpstreamTls {
        server_name: UpstreamServerName::Client {},
        ca_cert_pem: Some(
            "-----BEGIN CERTIFICATE-----\ny\n-----END CERTIFICATE-----\n".to_string(),
        ),
        client_certificate_id: Some("cert-2".to_string()),
        alpn: vec!["h2".to_string()],
        ..StreamUpstreamTls::default()
    });
    s
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
    /// [`stream_id`] of `label`. A UDP one sets the highest explicit
    /// per-source cap the listen-address rule accepts on an exposed
    /// address, so it validates there.
    pub(crate) fn stream(label: &str, name: &str, protocol: StreamProtocol, port: u16) -> Stream {
        let mut s = Stream::new(
            stream_id(label),
            name.to_string(),
            protocol,
            "0.0.0.0".parse().expect("test setup: address"),
            port,
            port,
            at(),
        );
        if let Some(udp) = &mut s.udp {
            udp.source_session_cap = Some(UDP_EXPOSED_SOURCE_SESSION_CAP_MAX);
        }
        s
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
        StreamBackend::primary(stream_id, backend_id)
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
            serde_json::json!({"stream_id": "s", "backend_id": "b", "weight": 1})
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

    // ---- Story 12.3: engine settings ----

    /// A valid TCP stream with every Story 12.3 setting away from its
    /// default.
    pub(crate) fn every_engine_setting_off_default(mut s: Stream) -> Stream {
        s.load_balancing = LoadBalancing::LeastConn;
        s.connect_timeout_ms = 1_000;
        s.idle_timeout_s = 30;
        s.total_timeout_s = Some(3_600);
        s.max_connect_attempts = 1;
        s.backend_keepalive = false;
        s.backend_keepalive_idle_s = 30;
        s.close_on_backend_down = true;
        s.proxy_protocol_send = StreamProxyProtocol::V2;
        s.proxy_protocol_accept = true;
        s.proxy_protocol_trusted_cidrs = vec!["192.0.2.0/24".to_string()];
        s.source_addresses = vec!["192.0.2.50".parse().expect("test setup: address")];
        s.allow_local_backend = true;
        s.upload_rate_bps = Some(1_048_576);
        s.download_rate_bps = Some(2_097_152);
        s.max_connections = 64;
        s
    }

    #[test]
    fn a_stream_written_before_the_engine_settings_reads_as_a_new_stream() {
        // A 12.1-shaped document: none of the Story 12.3 keys.
        let json = serde_json::json!({
            "id": stream_id("s"), "name": "smtp", "protocol": "tcp",
            "listen_address": "0.0.0.0", "port_first": 25, "port_last": 25,
            "created_at": "2026-11-14T00:00:00Z", "updated_at": "2026-11-14T00:00:00Z",
        });
        let read: Stream = serde_json::from_value(json).expect("a 12.1 stream parses");
        assert_eq!(read, stream("s", "smtp", StreamProtocol::Tcp, 25));
        assert!(read.validate().is_ok());
        let link: StreamBackend =
            serde_json::from_value(serde_json::json!({"stream_id": "s", "backend_id": "b"}))
                .expect("a 12.1 link parses");
        assert!(!link.backup);
    }

    #[test]
    fn a_new_stream_holds_the_documented_defaults() {
        for &protocol in StreamProtocol::VARIANTS {
            let s = stream("s", "edge", protocol, 5000);
            assert_eq!(s.load_balancing, LoadBalancing::RoundRobin);
            assert_eq!(s.connect_timeout_ms, 5_000);
            assert_eq!(s.idle_timeout_s, Stream::default_idle_timeout_s(protocol));
            assert_eq!(s.total_timeout_s, None);
            assert_eq!(s.max_connect_attempts, 3);
            assert!(s.backend_keepalive);
            assert_eq!(s.backend_keepalive_idle_s, 60);
            assert!(!s.close_on_backend_down);
            assert_eq!(s.proxy_protocol_send, StreamProxyProtocol::Off);
            assert!(!s.proxy_protocol_accept);
            assert!(s.proxy_protocol_trusted_cidrs.is_empty());
            assert!(s.source_addresses.is_empty());
            assert!(!s.allow_local_backend);
            assert_eq!(s.upload_rate_bps, None);
            assert_eq!(s.download_rate_bps, None);
            assert_eq!(s.max_connections, 1_024);
            for field in TCP_ENGINE_FIELDS {
                assert!((field.at_default)(&s), "{protocol:?}: {}", field.name);
            }
            assert!(s.validate().is_ok(), "{protocol:?}");
        }
        assert_eq!(Stream::default_idle_timeout_s(StreamProtocol::Tcp), 600);
        assert_eq!(Stream::default_idle_timeout_s(StreamProtocol::Udp), 10);
        assert_eq!(stream("s", "edge", StreamProtocol::Tcp, 5000).udp, None);
    }

    #[test]
    fn a_new_udp_stream_holds_the_documented_udp_defaults() {
        let s = Stream::new(
            stream_id("s"),
            "dns".to_string(),
            StreamProtocol::Udp,
            "10.0.0.53".parse().expect("test setup: address"),
            53,
            53,
            at(),
        );
        let udp = s.udp.expect("a UDP stream carries its settings");
        assert_eq!(udp, UdpSettings::default());
        assert_eq!(udp.max_sessions, 4_096);
        assert_eq!(udp.source_session_cap, None);
        assert_eq!(udp.effective_source_session_cap(), 256);
        assert_eq!(udp.requests_per_session, Some(64));
        assert_eq!(udp.responses_per_request, 1);
        assert_eq!(udp.response_bytes_ratio, 32);
        assert!(!udp.unbounded_responses);
        assert_eq!(udp.source_datagram_rate, 1_000);
        assert_eq!(udp.source_byte_rate, 524_288);
        assert_eq!(udp.max_datagram_bytes, 8_192);
        assert_eq!(s.idle_timeout_s, 10);
        assert!(s.validate().is_ok(), "{:?}", s.validate());
        // The documented reflection bound at the defaults.
        assert_eq!(udp.reflection_bound(), Some(8_192_000));
        let unbounded = UdpSettings {
            unbounded_responses: true,
            ..udp
        };
        assert_eq!(unbounded.reflection_bound(), None);
        // An empty `udp` object reads the defaults, but for the request
        // bound, which a document spells by its absence.
        let read: UdpSettings = serde_json::from_value(serde_json::json!({})).expect("defaults");
        assert_eq!(
            read,
            UdpSettings {
                requests_per_session: None,
                ..udp
            }
        );
    }

    #[test]
    fn every_udp_range_holds_at_both_bounds_and_refuses_one_past() {
        type Setter = fn(&mut UdpSettings, u32);
        let cases: [(&str, Setter, RangeInclusive<u32>); 8] = [
            (
                "udp.max_sessions",
                |u, v| u.max_sessions = v,
                UdpSettings::MAX_SESSIONS_RANGE,
            ),
            (
                "udp.source_session_cap",
                |u, v| u.source_session_cap = Some(v),
                UdpSettings::SOURCE_SESSION_CAP_RANGE,
            ),
            (
                "udp.requests_per_session",
                |u, v| u.requests_per_session = Some(v),
                UdpSettings::REQUESTS_PER_SESSION_RANGE,
            ),
            (
                "udp.responses_per_request",
                |u, v| u.responses_per_request = v,
                UdpSettings::RESPONSES_PER_REQUEST_RANGE,
            ),
            (
                "udp.response_bytes_ratio",
                |u, v| u.response_bytes_ratio = v,
                UdpSettings::RESPONSE_BYTES_RATIO_RANGE,
            ),
            (
                "udp.source_datagram_rate",
                |u, v| u.source_datagram_rate = v,
                UdpSettings::SOURCE_DATAGRAM_RATE_RANGE,
            ),
            (
                "udp.source_byte_rate",
                |u, v| {
                    u.source_byte_rate = v;
                    // Keep the datagram size under the rate, a rule of
                    // its own tested below.
                    u.max_datagram_bytes = *UdpSettings::MAX_DATAGRAM_BYTES_RANGE.start();
                },
                UdpSettings::SOURCE_BYTE_RATE_RANGE,
            ),
            (
                "udp.max_datagram_bytes",
                |u, v| u.max_datagram_bytes = v,
                UdpSettings::MAX_DATAGRAM_BYTES_RANGE,
            ),
        ];
        // A private address, so the listen-address rule is not what
        // answers whatever the per-source cap.
        let private = || {
            let mut s = stream("s", "edge", StreamProtocol::Udp, 5000);
            s.listen_address = "10.0.0.1".parse().expect("test setup: address");
            s
        };
        for (field, set, range) in cases {
            let (low, high) = (*range.start(), *range.end());
            let mut probes = vec![(low, true), (high, true), (high + 1, false)];
            if low > 0 {
                probes.push((low - 1, false));
            }
            for (value, accepted) in probes {
                let mut s = private();
                set(s.udp.as_mut().expect("test setup: udp"), value);
                match s.validate() {
                    Ok(()) => assert!(accepted, "{field} = {value} was accepted"),
                    Err(e) => {
                        assert!(!accepted, "{field} = {value} was refused: {e}");
                        assert!(e.contains(field), "{e}");
                    }
                }
            }
        }
        // The two nullable ones also accept null.
        let mut s = private();
        let udp = s.udp.as_mut().expect("test setup: udp");
        udp.source_session_cap = None;
        udp.requests_per_session = None;
        assert!(s.validate().is_ok());
        // And the UDP idle range, which stops below the TCP one.
        let udp_idle = Stream::idle_timeout_s_range(StreamProtocol::Udp);
        assert_eq!(udp_idle, Stream::UDP_IDLE_TIMEOUT_S_RANGE);
        for (value, accepted) in [
            (*udp_idle.start(), true),
            (*udp_idle.end(), true),
            (*udp_idle.start() - 1, false),
            (*udp_idle.end() + 1, false),
        ] {
            let mut s = private();
            s.idle_timeout_s = value;
            assert_eq!(s.validate().is_ok(), accepted, "idle_timeout_s = {value}");
        }
    }

    #[test]
    fn a_byte_rate_below_the_largest_datagram_is_refused() {
        let mut s = stream("s", "edge", StreamProtocol::Udp, 5000);
        let udp = s.udp.as_mut().expect("test setup: udp");
        udp.max_datagram_bytes = 4_096;
        udp.source_byte_rate = 4_095;
        let err = s
            .validate()
            .expect_err("no datagram of the largest size could pass");
        assert!(err.contains("udp.source_byte_rate"), "{err}");
        assert!(err.contains("udp.max_datagram_bytes"), "{err}");
        s.udp.as_mut().expect("test setup: udp").source_byte_rate = 4_096;
        assert!(s.validate().is_ok());
    }

    #[test]
    fn the_udp_object_is_required_on_udp_and_refused_on_tcp() {
        let mut udp = stream("s", "dns", StreamProtocol::Udp, 53);
        let settings = udp.udp.take();
        let err = udp
            .validate()
            .expect_err("a UDP stream without its settings");
        assert!(err.contains("udp settings"), "{err}");
        udp.fill_protocol_defaults();
        assert_eq!(udp.udp, Some(UdpSettings::default()));

        let mut tcp = stream("t", "smtp", StreamProtocol::Tcp, 25);
        tcp.udp = settings;
        let err = tcp.validate().expect_err("udp settings on a TCP stream");
        assert!(err.contains("refused on a TCP stream"), "{err}");
        tcp.udp = None;
        tcp.fill_protocol_defaults();
        assert_eq!(tcp.udp, None, "nothing to fill on TCP");
    }

    /// The listen-address rule of D-k over each kind of address, with the
    /// per-source cap absent, at the maximum and one past, and with an
    /// allowlist.
    #[test]
    fn an_exposed_udp_listen_address_needs_an_allowlist_or_a_low_explicit_cap() {
        let unexposed = [
            "127.0.0.1",
            "127.255.0.9",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
        ];
        let exposed = [
            "0.0.0.0",
            "::",
            "192.0.2.10",
            "172.32.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "2001:db8::1",
            "fe80::1",
        ];
        let with = |address: &str, cap: Option<u32>| {
            let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
            s.listen_address = address.parse().expect("test setup: address");
            s.udp.as_mut().expect("test setup: udp").source_session_cap = cap;
            s
        };
        let max = UDP_EXPOSED_SOURCE_SESSION_CAP_MAX;
        let check = |s: &Stream| udp_exposure_check(s, false);
        for address in unexposed {
            assert!(is_unexposed_udp_listen_address(
                address.parse().expect("test setup: address")
            ));
            for cap in [None, Some(max), Some(max + 1)] {
                let s = with(address, cap);
                assert!(check(&s).is_ok(), "{address} {cap:?}: {:?}", check(&s));
                assert!(s.validate().is_ok(), "{address} {cap:?}");
            }
        }
        for address in exposed {
            assert!(!is_unexposed_udp_listen_address(
                address.parse().expect("test setup: address")
            ));
            let refused = with(address, None);
            let err = check(&refused).expect_err(address);
            assert!(err.contains(address), "{err}");
            assert!(err.contains("source allowlist"), "{err}");
            assert!(err.contains("udp.source_session_cap"), "{err}");
            assert!(udp_exposure_check(&refused, true).is_ok(), "{address}");
            assert!(check(&with(address, Some(max))).is_ok(), "{address}");
            assert!(check(&with(address, Some(1))).is_ok(), "{address}");
            assert!(
                check(&with(address, Some(max + 1))).is_err(),
                "{address} at {}",
                max + 1
            );
        }
        // A TCP stream is not concerned.
        let tcp = stream("t", "smtp", StreamProtocol::Tcp, 25);
        assert!(udp_exposure_check(&tcp, false).is_ok());
    }

    #[test]
    fn udp_refuses_peak_ewma_and_proxy_protocol_v1() {
        let mut s = stream("s", "dns", StreamProtocol::Udp, 53);
        for algorithm in [
            LoadBalancing::RoundRobin,
            LoadBalancing::ConsistentHash,
            LoadBalancing::Random,
            LoadBalancing::LeastConn,
        ] {
            s.load_balancing = algorithm.clone();
            assert!(s.validate().is_ok(), "{algorithm:?}: {:?}", s.validate());
        }
        s.load_balancing = LoadBalancing::PeakEwma;
        let err = s.validate().expect_err("peak_ewma on UDP");
        assert!(err.contains("peak_ewma"), "{err}");
        let mut tcp = stream("t", "smtp", StreamProtocol::Tcp, 25);
        tcp.load_balancing = LoadBalancing::PeakEwma;
        assert!(tcp.validate().is_ok(), "peak_ewma stays a TCP choice");
        s.load_balancing = LoadBalancing::RoundRobin;
        for &mode in StreamProxyProtocol::VARIANTS {
            s.proxy_protocol_send = mode;
            let verdict = s.validate();
            if mode == StreamProxyProtocol::V1 {
                let err = verdict.expect_err("v1 on UDP");
                assert!(err.contains("v1"), "{err}");
            } else {
                assert!(verdict.is_ok(), "{mode:?}: {verdict:?}");
            }
        }
    }

    #[test]
    fn the_refusal_and_drop_words_come_from_their_enums() {
        for &refusal in StreamRefusal::VARIANTS {
            let word: &'static str = refusal.into();
            assert_eq!(serde_json::to_value(refusal).expect("serialize"), word);
        }
        let udp_refusals: Vec<&'static str> = [
            StreamRefusal::SessionCap,
            StreamRefusal::SourceSessionCap,
            StreamRefusal::SessionTableFull,
        ]
        .into_iter()
        .map(Into::into)
        .collect();
        assert_eq!(
            udp_refusals,
            ["session_cap", "source_session_cap", "session_table_full"]
        );
        for &reason in DatagramDropReason::VARIANTS {
            assert_eq!(
                serde_json::to_value(reason).expect("serialize"),
                reason.as_str()
            );
            let back: DatagramDropReason =
                serde_json::from_value(serde_json::json!(reason.as_str())).expect("deserialize");
            assert_eq!(back, reason);
        }
        assert_eq!(
            DatagramDropReason::RequestOversize.as_str(),
            "request_oversize"
        );
        assert_eq!(DatagramDropReason::SendFailed.as_str(), "send_failed");
    }

    #[test]
    fn every_range_holds_at_both_bounds_and_refuses_one_past() {
        type Setter = fn(&mut Stream, u64);
        let tcp_idle = Stream::idle_timeout_s_range(StreamProtocol::Tcp);
        let cases: [(&str, Setter, u64, u64); 7] = [
            (
                "connect_timeout_ms",
                |s, v| s.connect_timeout_ms = v as u32,
                u64::from(*Stream::CONNECT_TIMEOUT_MS_RANGE.start()),
                u64::from(*Stream::CONNECT_TIMEOUT_MS_RANGE.end()),
            ),
            (
                "idle_timeout_s",
                |s, v| s.idle_timeout_s = v as u32,
                u64::from(*tcp_idle.start()),
                u64::from(*tcp_idle.end()),
            ),
            (
                "total_timeout_s",
                |s, v| s.total_timeout_s = Some(v as u32),
                u64::from(*Stream::TOTAL_TIMEOUT_S_RANGE.start()),
                u64::from(*Stream::TOTAL_TIMEOUT_S_RANGE.end()),
            ),
            (
                "max_connect_attempts",
                |s, v| s.max_connect_attempts = v as u8,
                u64::from(*Stream::MAX_CONNECT_ATTEMPTS_RANGE.start()),
                u64::from(*Stream::MAX_CONNECT_ATTEMPTS_RANGE.end()),
            ),
            (
                "backend_keepalive_idle_s",
                |s, v| s.backend_keepalive_idle_s = v as u32,
                u64::from(*Stream::BACKEND_KEEPALIVE_IDLE_S_RANGE.start()),
                u64::from(*Stream::BACKEND_KEEPALIVE_IDLE_S_RANGE.end()),
            ),
            (
                "upload_rate_bps",
                |s, v| s.upload_rate_bps = Some(v),
                *Stream::RATE_BPS_RANGE.start(),
                *Stream::RATE_BPS_RANGE.end(),
            ),
            (
                "max_connections",
                |s, v| s.max_connections = v as u32,
                u64::from(*Stream::MAX_CONNECTIONS_RANGE.start()),
                u64::from(*Stream::MAX_CONNECTIONS_RANGE.end()),
            ),
        ];
        for (field, set, low, high) in cases {
            for (value, accepted) in [
                (low, true),
                (high, true),
                (low - 1, false),
                (high + 1, false),
            ] {
                let mut s = stream("s", "edge", StreamProtocol::Tcp, 5000);
                set(&mut s, value);
                match s.validate() {
                    Ok(()) => assert!(accepted, "{field} = {value} was accepted"),
                    Err(e) => {
                        assert!(!accepted, "{field} = {value} was refused: {e}");
                        assert!(e.contains(field), "{e}");
                    }
                }
            }
        }
        // The download rate shares the upload rate's range.
        let mut s = stream("s", "edge", StreamProtocol::Tcp, 5000);
        s.download_rate_bps = Some(*Stream::RATE_BPS_RANGE.start() - 1);
        assert!(s
            .validate()
            .expect_err("below the range")
            .contains("download_rate_bps"));
        s.download_rate_bps = Some(*Stream::RATE_BPS_RANGE.end());
        assert!(s.validate().is_ok());
    }

    #[test]
    fn the_proxy_protocol_trust_list_follows_the_listener_rule() {
        let mut s = stream("s", "edge", StreamProtocol::Tcp, 5000);
        s.proxy_protocol_accept = true;
        let err = s.validate().expect_err("accept with no trusted peer");
        assert!(err.contains("proxy_protocol_accept"), "{err}");
        s.proxy_protocol_trusted_cidrs = vec!["  ".to_string()];
        assert!(s.validate().is_err(), "a blank entry trusts nobody");

        s.proxy_protocol_trusted_cidrs =
            vec!["192.0.2.0/24".to_string(), "2001:db8::1".to_string()];
        assert!(s.validate().is_ok());
        for refused in ["0.0.0.0/0", "::/0", "192.0.2.0/33", "lb.example.com"] {
            s.proxy_protocol_trusted_cidrs = vec![refused.to_string()];
            let err = s.validate().expect_err(refused);
            assert!(err.contains("proxy_protocol_trusted_cidrs"), "{err}");
            assert!(err.contains("`edge`"), "{err}");
        }

        // A list with accept off is kept as written (an operator may
        // stage it before turning accept on).
        s.proxy_protocol_accept = false;
        s.proxy_protocol_trusted_cidrs = vec!["192.0.2.0/24".to_string()];
        assert!(s.validate().is_ok());

        s.proxy_protocol_trusted_cidrs = (0..Stream::PROXY_PROTOCOL_TRUSTED_CIDRS_MAX)
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        assert!(s.validate().is_ok());
        s.proxy_protocol_trusted_cidrs
            .push("10.255.0.0/24".to_string());
        assert!(s.validate().expect_err("one too many").contains("at most"));
    }

    #[test]
    fn source_addresses_are_distinct_unicast_literals() {
        let mut s = stream("s", "edge", StreamProtocol::Tcp, 5000);
        s.source_addresses = (0..Stream::SOURCE_ADDRESSES_MAX)
            .map(|i| IpAddr::from([192, 0, 2, u8::try_from(i + 1).expect("test setup: small")]))
            .collect();
        assert!(s.validate().is_ok());
        s.source_addresses
            .push("2001:db8::1".parse().expect("test setup: address"));
        assert!(s.validate().expect_err("one too many").contains("at most"));

        for (refused, why) in [
            ("0.0.0.0", "unspecified"),
            ("::", "unspecified"),
            ("::ffff:192.0.2.10", "IPv4-mapped"),
            ("224.0.0.1", "unicast"),
            ("255.255.255.255", "unicast"),
            ("ff02::1", "unicast"),
        ] {
            s.source_addresses = vec![refused.parse().expect("test setup: address")];
            let err = s.validate().expect_err(refused);
            assert!(err.contains(why), "{refused}: {err}");
        }
        s.source_addresses = vec![
            "192.0.2.10".parse().expect("test setup: address"),
            "192.0.2.10".parse().expect("test setup: address"),
        ];
        assert!(s.validate().expect_err("a duplicate").contains("twice"));
        s.source_addresses = vec![
            "192.0.2.10".parse().expect("test setup: address"),
            "2001:db8::10".parse().expect("test setup: address"),
        ];
        assert!(s.validate().is_ok());
    }

    #[test]
    fn a_udp_stream_keeps_the_settings_without_a_udp_meaning_at_their_default() {
        let tcp = every_engine_setting_off_default(stream("s", "edge", StreamProtocol::Tcp, 5000));
        assert!(tcp.validate().is_ok(), "{:?}", tcp.validate());
        // The fixture moves every entry of the table, so the loop below
        // reaches each one.
        for field in TCP_ENGINE_FIELDS {
            assert!(
                !(field.at_default)(&tcp),
                "{} is at its default",
                field.name
            );
        }

        let off_default = serde_json::to_value(&tcp).expect("serialize");
        let udp_default =
            serde_json::to_value(stream("s", "edge", StreamProtocol::Udp, 5000)).expect("ser");
        for field in TCP_ENGINE_FIELDS {
            // A default UDP stream with this one setting moved, by the
            // name every surface spells it with.
            let mut value = udp_default.clone();
            value[field.name] = off_default[field.name].clone();
            let udp: Stream = serde_json::from_value(value)
                .unwrap_or_else(|e| panic!("{} is not a field name: {e}", field.name));
            let moved: Vec<&str> = TCP_ENGINE_FIELDS
                .iter()
                .filter(|f| !(f.at_default)(&udp))
                .map(|f| f.name)
                .collect();
            assert_eq!(moved, vec![field.name]);
            match field.on_udp {
                OnUdp::KeepsDefault(reason) => {
                    let err = udp.validate().expect_err(field.name);
                    assert!(err.contains(field.name), "{err}");
                    assert!(err.contains(reason), "{err}");
                }
                OnUdp::Applies => assert!(
                    udp.validate().is_ok(),
                    "{} has a UDP meaning: {:?}",
                    field.name,
                    udp.validate()
                ),
            }
        }
        let lifted: Vec<&str> = TCP_ENGINE_FIELDS
            .iter()
            .filter(|f| f.on_udp == OnUdp::Applies)
            .map(|f| f.name)
            .collect();
        // Story 12.5 D-l's list of what it gives a UDP meaning.
        assert_eq!(
            lifted,
            [
                "load_balancing",
                "idle_timeout_s",
                "total_timeout_s",
                "close_on_backend_down",
                "proxy_protocol_send",
                "source_addresses",
                "allow_local_backend",
            ]
        );
    }

    #[test]
    fn the_proxy_protocol_send_words() {
        for &mode in StreamProxyProtocol::VARIANTS {
            assert_eq!(
                serde_json::to_value(mode).expect("serialize"),
                mode.as_str(),
                "{mode:?}"
            );
            assert_eq!(mode.as_str().parse::<StreamProxyProtocol>(), Ok(mode));
        }
        assert_eq!(StreamProxyProtocol::default(), StreamProxyProtocol::Off);
        assert_eq!(StreamProxyProtocol::V2.as_str(), "v2");
    }

    // ---- Story 12.4: TLS ----

    fn tls_rule(name: &str, server_names: &[&str], alpn: &[&str]) -> StreamMatchRule {
        StreamMatchRule {
            name: name.to_string(),
            matcher: StreamMatcher::Tls {
                server_names: server_names.iter().map(|n| n.to_string()).collect(),
                alpn: alpn.iter().map(|p| p.to_string()).collect(),
            },
        }
    }

    fn no_sni_rule(name: &str, alpn: &[&str]) -> StreamMatchRule {
        StreamMatchRule {
            name: name.to_string(),
            matcher: StreamMatcher::NoSni {
                alpn: alpn.iter().map(|p| p.to_string()).collect(),
            },
        }
    }

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n";

    /// A valid passthrough stream with one rule for `app.example.com`.
    fn passthrough() -> Stream {
        let mut s = stream("s-tls", "tls", StreamProtocol::Tcp, 443);
        s.tls_mode = StreamTlsMode::Passthrough;
        s.match_rules = vec![tls_rule("web", &["app.example.com"], &[])];
        s
    }

    /// A valid terminating stream with one rule and one certificate.
    fn terminating() -> Stream {
        let mut s = passthrough();
        s.tls_mode = StreamTlsMode::Terminate;
        s.tls_terminate = Some(StreamTlsTerminate {
            certificate_ids: vec!["cert-1".to_string()],
            client_auth: None,
        });
        s
    }

    fn tls_refusal(s: &Stream) -> String {
        s.validate().expect_err("refused")
    }

    #[test]
    fn a_new_stream_reads_no_tls_and_a_document_without_the_fields_reads_alike() {
        for &protocol in StreamProtocol::VARIANTS {
            let s = stream("s", "edge", protocol, 5000);
            assert_eq!(s.tls_mode, StreamTlsMode::None);
            assert!(s.match_rules.is_empty());
            assert!(!s.no_sni_acknowledged);
            assert_eq!(s.clienthello_timeout_ms, None);
            assert_eq!(
                s.effective_clienthello_timeout_ms(),
                Stream::DEFAULT_CLIENTHELLO_TIMEOUT_MS
            );
            assert_eq!(s.tls_terminate, None);
            assert_eq!(s.upstream_tls, None);
            assert!(!s.drains_on_upgrade());
        }
        let mut json =
            serde_json::to_value(stream("s", "smtp", StreamProtocol::Tcp, 25)).expect("serialize");
        let object = json.as_object_mut().expect("an object");
        for field in [
            "tls_mode",
            "match_rules",
            "no_sni_acknowledged",
            "clienthello_timeout_ms",
            "tls_terminate",
            "upstream_tls",
        ] {
            assert!(object.remove(field).is_some(), "{field} on the wire");
        }
        let read: Stream = serde_json::from_value(json).expect("a 12.5 stream parses");
        assert_eq!(read, stream("s", "smtp", StreamProtocol::Tcp, 25));
        let link: StreamBackend = serde_json::from_value(
            serde_json::json!({"stream_id": "s", "backend_id": "b", "backup": true}),
        )
        .expect("a 12.3 link parses");
        assert_eq!(link.rule, None);
        assert_eq!(StreamTlsMode::default(), StreamTlsMode::None);
        assert_eq!(
            UpstreamServerName::default(),
            UpstreamServerName::BackendAddress {}
        );
    }

    #[test]
    fn the_tls_field_names_are_the_model_s_own_keys() {
        let json = serde_json::to_value(terminating()).expect("serialize");
        let keys = json.as_object().expect("an object");
        for name in Stream::tls_field_names() {
            assert!(keys.contains_key(name), "{name}");
        }
    }

    #[test]
    fn the_tls_types_refuse_unknown_fields_and_keep_their_spelling() {
        let rule: StreamMatchRule = serde_json::from_value(serde_json::json!({
            "name": "pg", "matcher": {"kind": "tls", "server_names": ["db.example.com"]}
        }))
        .expect("alpn defaults to empty");
        assert_eq!(rule, tls_rule("pg", &["db.example.com"], &[]));
        assert_eq!(
            serde_json::to_value(no_sni_rule("bare", &["h2"])).expect("serialize"),
            serde_json::json!({"name": "bare", "matcher": {"kind": "no_sni", "alpn": ["h2"]}})
        );
        for bad in [
            serde_json::json!({"name": "x", "matcher": {"kind": "tls", "server_names": [], "sni": 1}}),
            serde_json::json!({"name": "x", "matcher": {"kind": "postgres"}}),
            serde_json::json!({"name": "x", "matcher": {"kind": "no_sni"}, "extra": 1}),
        ] {
            assert!(
                serde_json::from_value::<StreamMatchRule>(bad.clone()).is_err(),
                "{bad}"
            );
        }
        let upstream: StreamUpstreamTls = serde_json::from_value(serde_json::json!({
            "server_name": {"mode": "fixed", "name": "origin.example.org"}
        }))
        .expect("parses");
        assert_eq!(
            upstream.server_name,
            UpstreamServerName::Fixed {
                name: "origin.example.org".to_string()
            }
        );
        assert_eq!(upstream.server_name.mode(), "fixed");
        assert!(serde_json::from_value::<StreamUpstreamTls>(
            serde_json::json!({"server_name": {"mode": "client", "name": "x"}})
        )
        .is_err());
        for &mode in StreamTlsMode::VARIANTS {
            assert_eq!(mode.as_str().parse::<StreamTlsMode>(), Ok(mode));
            assert_eq!(
                serde_json::to_value(mode).expect("serialize"),
                mode.as_str()
            );
        }
    }

    #[test]
    fn valid_tls_streams_validate() {
        passthrough().validate().expect("passthrough");
        terminating().validate().expect("terminate");
        let mut reencrypting = terminating();
        reencrypting.upstream_tls = Some(StreamUpstreamTls {
            server_name: UpstreamServerName::Client {},
            client_certificate_id: Some("cert-2".to_string()),
            ca_cert_pem: Some(PEM.to_string()),
            alpn: vec!["h2".to_string()],
            ..StreamUpstreamTls::default()
        });
        reencrypting
            .validate()
            .expect("re-encryption with the client's name");
        let mut originating = stream("s", "orig", StreamProtocol::Tcp, 5432);
        originating.upstream_tls = Some(StreamUpstreamTls {
            server_name: UpstreamServerName::Fixed {
                name: "192.0.2.10".to_string(),
            },
            skip_verify: true,
            ..StreamUpstreamTls::default()
        });
        originating
            .validate()
            .expect("origination on a plain stream");
    }

    /// Every refused cell of D-g, each alone on a stream otherwise valid
    /// for its mode, answers with the field and the mode.
    #[test]
    fn every_field_a_mode_does_not_take_is_refused_naming_field_and_mode() {
        let upstream = Some(StreamUpstreamTls::default());
        let terminate = terminating().tls_terminate;
        let rules = passthrough().match_rules;
        let mut cells: Vec<(Stream, &str, &str)> = Vec::new();

        let mut none = stream("s", "plain", StreamProtocol::Tcp, 25);
        none.match_rules = rules.clone();
        cells.push((none, "match_rules", "none"));
        let mut none = stream("s", "plain", StreamProtocol::Tcp, 25);
        none.clienthello_timeout_ms = Some(2_000);
        cells.push((none, "clienthello_timeout_ms", "none"));
        let mut none = stream("s", "plain", StreamProtocol::Tcp, 25);
        none.tls_terminate = terminate.clone();
        cells.push((none, "tls_terminate", "none"));
        let mut none = stream("s", "plain", StreamProtocol::Tcp, 25);
        none.upstream_tls = Some(StreamUpstreamTls {
            server_name: UpstreamServerName::Client {},
            ..StreamUpstreamTls::default()
        });
        cells.push((none, "upstream_tls.server_name client", "none"));
        let mut none = stream("s", "plain", StreamProtocol::Tcp, 25);
        none.no_sni_acknowledged = true;
        cells.push((none, "no_sni_acknowledged", "no_sni rule"));

        let mut pass = passthrough();
        pass.tls_terminate = terminate.clone();
        cells.push((pass, "tls_terminate", "passthrough"));
        let mut pass = passthrough();
        pass.upstream_tls = upstream.clone();
        cells.push((pass, "upstream_tls", "passthrough"));
        let mut pass = passthrough();
        pass.match_rules.clear();
        cells.push((pass, "match_rules", "passthrough"));
        let mut pass = passthrough();
        pass.no_sni_acknowledged = true;
        cells.push((pass, "no_sni_acknowledged", "no_sni rule"));

        let mut term = terminating();
        term.tls_terminate = None;
        cells.push((term, "tls_terminate", "terminate"));
        let mut term = terminating();
        term.match_rules.clear();
        cells.push((term, "match_rules", "terminate"));

        for (field, value) in [
            ("tls_mode", 0),
            ("match_rules", 1),
            ("no_sni_acknowledged", 2),
            ("clienthello_timeout_ms", 3),
            ("tls_terminate", 4),
            ("upstream_tls", 5),
        ] {
            let mut udp = stream("u", "dns", StreamProtocol::Udp, 53);
            match value {
                0 => udp.tls_mode = StreamTlsMode::Passthrough,
                1 => udp.match_rules = rules.clone(),
                2 => udp.no_sni_acknowledged = true,
                3 => udp.clienthello_timeout_ms = Some(2_000),
                4 => udp.tls_terminate = terminate.clone(),
                _ => udp.upstream_tls = upstream.clone(),
            }
            cells.push((udp, field, "UDP"));
        }

        for (s, field, mode) in cells {
            let err = tls_refusal(&s);
            assert!(err.contains(field), "{field} on {mode}: {err}");
            assert!(err.contains(mode), "{field} on {mode}: {err}");
        }
    }

    #[test]
    fn the_clienthello_timeout_is_bounded() {
        let mut s = passthrough();
        for (value, ok) in [
            (999, false),
            (1_000, true),
            (Stream::DEFAULT_CLIENTHELLO_TIMEOUT_MS, true),
            (60_000, true),
            (60_001, false),
        ] {
            s.clienthello_timeout_ms = Some(value);
            assert_eq!(s.validate().is_ok(), ok, "{value}");
            if ok {
                assert_eq!(s.effective_clienthello_timeout_ms(), value);
            }
        }
    }

    #[test]
    fn rules_sharing_a_name_with_intersecting_or_empty_alpn_are_refused() {
        let mut s = passthrough();
        s.match_rules = vec![
            tls_rule("a", &["app.example.com"], &["h2", "http/1.1"]),
            tls_rule("b", &["App.Example.COM."], &["http/1.1"]),
        ];
        let err = tls_refusal(&s);
        assert!(err.contains("`a`") && err.contains("`b`"), "{err}");
        assert!(err.contains("app.example.com"), "{err}");

        s.match_rules = vec![
            tls_rule("a", &["app.example.com"], &[]),
            tls_rule("b", &["app.example.com"], &[]),
        ];
        assert!(tls_refusal(&s).contains("same ALPN"));

        s.match_rules = vec![no_sni_rule("a", &[]), no_sni_rule("b", &[])];
        s.no_sni_acknowledged = true;
        assert!(tls_refusal(&s).contains("without SNI"));

        s.match_rules = vec![no_sni_rule("a", &["h2"]), no_sni_rule("b", &["postgresql"])];
        s.validate().expect("disjoint no_sni rules");
        s.match_rules = vec![
            tls_rule("pg", &["db.example.com"], &["postgresql"]),
            tls_rule("web", &["db.example.com"], &["h2", "http/1.1"]),
            tls_rule("any", &["db.example.com"], &[]),
            tls_rule("wild", &["*.example.com"], &[]),
        ];
        s.no_sni_acknowledged = false;
        s.validate()
            .expect("disjoint ALPN on one name, one empty fallback, and a wildcard");
    }

    #[test]
    fn rule_caps_hold_at_both_bounds() {
        let mut s = passthrough();
        s.match_rules = (0..Stream::MATCH_RULES_MAX)
            .map(|i| {
                tls_rule(
                    &format!("r{i}"),
                    &[format!("h{i}.example.com").as_str()],
                    &[],
                )
            })
            .collect();
        s.validate().expect("the most rules");
        s.match_rules
            .push(tls_rule("one-more", &["more.example.com"], &[]));
        assert!(tls_refusal(&s).contains("at most"));

        let names: Vec<String> = (0..Stream::RULE_SERVER_NAMES_MAX)
            .map(|i| format!("h{i}.example.com"))
            .collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        s.match_rules = vec![tls_rule("web", &refs, &[])];
        s.validate().expect("the most names in a rule");
        let mut more = refs.clone();
        more.push("more.example.com");
        s.match_rules = vec![tls_rule("web", &more, &[])];
        assert!(tls_refusal(&s).contains("server names"));
        s.match_rules = vec![tls_rule("web", &[], &[])];
        assert!(tls_refusal(&s).contains("server names"));

        let rules_needed = Stream::SERVER_NAMES_MAX / Stream::RULE_SERVER_NAMES_MAX;
        s.match_rules = (0..rules_needed)
            .map(|r| {
                let names: Vec<String> = (0..Stream::RULE_SERVER_NAMES_MAX)
                    .map(|i| format!("h{i}.r{r}.example.com"))
                    .collect();
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                tls_rule(&format!("r{r}"), &refs, &[])
            })
            .collect();
        s.validate().expect("the most names in a stream");
        s.match_rules
            .push(tls_rule("extra", &["extra.example.com"], &[]));
        assert!(tls_refusal(&s).contains("together"));

        let alpn: Vec<String> = (0..Stream::ALPN_MAX).map(|i| format!("p{i}")).collect();
        let alpn_refs: Vec<&str> = alpn.iter().map(String::as_str).collect();
        s.match_rules = vec![tls_rule("web", &["app.example.com"], &alpn_refs)];
        s.validate().expect("the most ALPN protocols");
        let mut alpn_more = alpn_refs.clone();
        alpn_more.push("p-more");
        s.match_rules = vec![tls_rule("web", &["app.example.com"], &alpn_more)];
        assert!(tls_refusal(&s).contains("protocols"));
        let longest = "x".repeat(Stream::ALPN_PROTOCOL_MAX_LEN);
        s.match_rules = vec![tls_rule("web", &["app.example.com"], &[longest.as_str()])];
        s.validate().expect("the longest protocol");
        for bad in [
            String::new(),
            "x".repeat(Stream::ALPN_PROTOCOL_MAX_LEN + 1),
            "h 2".to_string(),
        ] {
            s.match_rules = vec![tls_rule("web", &["app.example.com"], &[bad.as_str()])];
            assert!(tls_refusal(&s).contains("visible ASCII"), "{bad:?}");
        }
        s.match_rules = vec![tls_rule("web", &["app.example.com"], &["h2", "h2"])];
        assert!(tls_refusal(&s).contains("twice"));

        let longest_name = "r".repeat(Stream::MATCH_RULE_NAME_MAX_LEN);
        s.match_rules = vec![tls_rule(&longest_name, &["app.example.com"], &[])];
        s.validate().expect("the longest rule name");
        for bad in [
            "r".repeat(Stream::MATCH_RULE_NAME_MAX_LEN + 1),
            String::new(),
            "Web".to_string(),
        ] {
            s.match_rules = vec![tls_rule(&bad, &["app.example.com"], &[])];
            assert!(tls_refusal(&s).contains("rule name"), "{bad:?}");
        }
        s.match_rules = vec![
            tls_rule("web", &["a.example.com"], &[]),
            tls_rule("web", &["b.example.com"], &[]),
        ];
        assert!(tls_refusal(&s).contains("two rules"));
    }

    #[test]
    fn server_names_are_canonicalised_and_addresses_refused() {
        let mut s = passthrough();
        s.match_rules = vec![tls_rule(
            "web",
            &[" App.Example.COM. ", "*.Example.org"],
            &[],
        )];
        s.validate().expect("any spelling of a name validates");
        s.canonicalise_server_names();
        assert_eq!(
            s.match_rules[0].matcher.server_names(),
            ["app.example.com".to_string(), "*.example.org".to_string()]
        );
        for bad in [
            "192.0.2.10",
            "*.0.2.10",
            "[2001:db8::1]",
            "010.0.0.1",
            "_",
            "https://app.example.com",
            "app.example.com:443",
            "",
        ] {
            s.match_rules = vec![tls_rule("web", &[bad], &[])];
            let err = tls_refusal(&s);
            assert!(err.contains("rule `web`"), "{bad:?}: {err}");
        }
        s.match_rules = vec![tls_rule(
            "web",
            &["app.example.com", "APP.example.com"],
            &[],
        )];
        assert!(tls_refusal(&s).contains("twice"));
    }

    #[test]
    fn a_no_sni_rule_needs_its_acknowledgement_and_nothing_else_takes_one() {
        let mut s = passthrough();
        s.match_rules.push(no_sni_rule("bare", &[]));
        assert!(s.no_sni_needs_acknowledgement(false));
        assert!(
            !s.no_sni_needs_acknowledgement(true),
            "a source allowlist suffices"
        );
        let err = tls_refusal(&s);
        assert!(
            err.contains("source allowlist") && err.contains("no_sni_acknowledged"),
            "both remedies named: {err}"
        );
        s.no_sni_acknowledged = true;
        s.validate().expect("acknowledged");

        let mut plain = passthrough();
        assert!(!plain.no_sni_needs_acknowledgement(false));
        plain.no_sni_acknowledged = true;
        assert!(tls_refusal(&plain).contains("without a no_sni rule"));
    }

    #[test]
    fn terminate_and_upstream_fields_are_checked() {
        let mut s = terminating();
        let terminate = s.tls_terminate.as_mut().expect("set");
        terminate.certificate_ids = (0..Stream::TERMINATE_CERTIFICATES_MAX)
            .map(|i| format!("cert-{i}"))
            .collect();
        s.validate().expect("the most certificates");
        for ids in [
            Vec::new(),
            (0..=Stream::TERMINATE_CERTIFICATES_MAX)
                .map(|i| format!("cert-{i}"))
                .collect(),
            vec!["cert-1".to_string(), "cert-1".to_string()],
            vec![" ".to_string()],
            vec!["cert\n1".to_string()],
        ] {
            let mut bad = terminating();
            bad.tls_terminate.as_mut().expect("set").certificate_ids = ids.clone();
            assert!(tls_refusal(&bad).contains("certificate_ids"), "{ids:?}");
        }

        let mut auth = terminating();
        auth.tls_terminate.as_mut().expect("set").client_auth = Some(MtlsConfig {
            ca_cert_pem: PEM.to_string(),
            required: true,
            allowed_organizations: vec!["Acme".to_string()],
        });
        auth.validate().expect("client verification");
        for (pem, organizations) in [
            ("", vec![]),
            ("not a bundle", vec![]),
            (PEM, vec![" ".to_string()]),
            (PEM, vec!["Ac\u{7}me".to_string()]),
            (
                PEM,
                (0..=Stream::ALLOWED_ORGANIZATIONS_MAX)
                    .map(|i| format!("o{i}"))
                    .collect(),
            ),
        ] {
            let mut bad = auth.clone();
            let client_auth = bad
                .tls_terminate
                .as_mut()
                .and_then(|t| t.client_auth.as_mut())
                .expect("set");
            client_auth.ca_cert_pem = pem.to_string();
            client_auth.allowed_organizations = organizations;
            assert!(tls_refusal(&bad).contains("client_auth"), "{pem:?}");
        }

        for (upstream, word) in [
            (
                StreamUpstreamTls {
                    skip_verify: true,
                    client_certificate_id: Some("cert-2".to_string()),
                    ..StreamUpstreamTls::default()
                },
                "credential",
            ),
            (
                StreamUpstreamTls {
                    skip_verify: true,
                    ca_cert_pem: Some(PEM.to_string()),
                    ..StreamUpstreamTls::default()
                },
                "contradicts",
            ),
            (
                StreamUpstreamTls {
                    ca_cert_pem: Some(String::new()),
                    ..StreamUpstreamTls::default()
                },
                "ca_cert_pem",
            ),
            (
                StreamUpstreamTls {
                    server_name: UpstreamServerName::Fixed {
                        name: "https://origin.example.org".to_string(),
                    },
                    ..StreamUpstreamTls::default()
                },
                "fixed",
            ),
            (
                StreamUpstreamTls {
                    server_name: UpstreamServerName::Fixed {
                        name: String::new(),
                    },
                    ..StreamUpstreamTls::default()
                },
                "fixed",
            ),
            (
                StreamUpstreamTls {
                    alpn: vec![String::new()],
                    ..StreamUpstreamTls::default()
                },
                "upstream_tls.alpn",
            ),
            (
                StreamUpstreamTls {
                    client_certificate_id: Some(String::new()),
                    ..StreamUpstreamTls::default()
                },
                "client_certificate_id",
            ),
        ] {
            let mut bad = terminating();
            bad.upstream_tls = Some(upstream);
            assert!(tls_refusal(&bad).contains(word), "{word}");
        }
    }

    #[test]
    fn drains_on_upgrade_follows_termination_and_upstream_tls() {
        let mut plain = stream("s", "plain", StreamProtocol::Tcp, 25);
        assert!(!plain.drains_on_upgrade());
        plain.upstream_tls = Some(StreamUpstreamTls::default());
        assert!(plain.drains_on_upgrade(), "origination");
        assert!(!passthrough().drains_on_upgrade());
        assert!(terminating().drains_on_upgrade());
        let mut reencrypting = terminating();
        reencrypting.upstream_tls = Some(StreamUpstreamTls::default());
        assert!(reencrypting.drains_on_upgrade());
        assert!(!stream("u", "dns", StreamProtocol::Udp, 53).drains_on_upgrade());
    }

    #[test]
    fn certificate_references_list_each_named_certificate_once() {
        assert!(passthrough().certificate_references().is_empty());
        let mut s = terminating();
        s.tls_terminate.as_mut().expect("set").certificate_ids =
            vec!["cert-1".to_string(), "cert-2".to_string()];
        s.upstream_tls = Some(StreamUpstreamTls {
            client_certificate_id: Some("cert-2".to_string()),
            ..StreamUpstreamTls::default()
        });
        assert_eq!(s.certificate_references(), ["cert-1", "cert-2"]);
        s.upstream_tls.as_mut().expect("set").client_certificate_id = Some("cert-3".to_string());
        assert_eq!(s.certificate_references(), ["cert-1", "cert-2", "cert-3"]);
    }

    fn rule_link(stream_id: &str, backend_id: &str, rule: &str, backup: bool) -> StreamBackend {
        StreamBackend {
            backup,
            rule: Some(rule.to_string()),
            ..link(stream_id, backend_id)
        }
    }

    #[test]
    fn links_of_a_tls_stream_name_its_rules_and_each_rule_has_a_primary() {
        let mut s = passthrough();
        s.match_rules
            .push(tls_rule("api", &["api.example.com"], &[]));
        let streams = [s.clone()];
        let backends = [
            backend("b-1", "192.0.2.10:443"),
            backend("b-2", "192.0.2.11:443"),
        ];
        let check = |links: &[StreamBackend]| {
            check_backend_attachments(&AttachmentSnapshot {
                backends: &backends,
                streams: &streams,
                stream_backends: links,
                route_backends: &[],
            })
        };
        check(&[
            rule_link(&s.id, "b-1", "web", false),
            rule_link(&s.id, "b-2", "api", false),
        ])
        .expect("one primary per rule");
        check(&[
            rule_link(&s.id, "b-1", "web", false),
            rule_link(&s.id, "b-2", "web", true),
        ])
        .expect("a backup beside its rule's primary; a rule without a link is accepted");

        let err = check(&[link(&s.id, "b-1")]).expect_err("no rule");
        assert_eq!(err.rule, AttachmentRule::LinkWithoutRule);
        let err = check(&[rule_link(&s.id, "b-1", "gone", false)]).expect_err("unknown");
        assert_eq!(
            err.rule,
            AttachmentRule::UnknownRule {
                rule: "gone".to_string()
            }
        );
        let err = check(&[
            rule_link(&s.id, "b-1", "web", false),
            rule_link(&s.id, "b-2", "api", true),
        ])
        .expect_err("api has only a backup");
        assert_eq!(
            err.rule,
            AttachmentRule::RuleWithoutPrimary {
                rule: "api".to_string()
            }
        );
        assert!(err.to_string().contains("rule `api`"), "{err}");

        let plain = stream("s-plain", "plain", StreamProtocol::Tcp, 25);
        let plain_streams = [plain.clone()];
        let err = check_backend_attachments(&AttachmentSnapshot {
            backends: &backends,
            streams: &plain_streams,
            stream_backends: &[rule_link(&plain.id, "b-1", "web", false)],
            route_backends: &[],
        })
        .expect_err("a rule on a stream without TLS");
        assert_eq!(
            err.rule,
            AttachmentRule::RuleOnNonTlsStream {
                rule: "web".to_string()
            }
        );
        assert!(err.to_string().contains("tls_mode none"), "{err}");
    }

    #[test]
    fn the_tls_refusals_have_their_words() {
        for (refusal, word) in [
            (StreamRefusal::InvalidClientHello, "invalid_client_hello"),
            (StreamRefusal::NoCertificate, "no_certificate"),
            (StreamRefusal::TlsHandshake, "tls_handshake"),
            (StreamRefusal::ClientCertificate, "client_certificate"),
        ] {
            let spelled: &'static str = refusal.into();
            assert_eq!(spelled, word);
            assert!(StreamRefusal::VARIANTS.contains(&refusal));
        }
    }

    // ---- Story 12.3: attachment rules ----

    fn backup(stream_id: &str, backend_id: &str) -> StreamBackend {
        StreamBackend {
            backup: true,
            ..link(stream_id, backend_id)
        }
    }

    #[test]
    fn a_local_backend_needs_the_flag() {
        let local = [
            "127.0.0.1:5432",
            "[::1]:5432",
            "[::ffff:127.0.0.1]:5432",
            "169.254.1.1:5432",
            "[fe80::1]:5432",
            "0.0.0.0:5432",
            "localhost:5432",
            "db.localhost:5432",
        ];
        for address in local {
            let tcp = stream("t", "pg", StreamProtocol::Tcp, 5432);
            let conflict = refused(&fixture(backend("b", address), vec![tcp.clone()], &[]));
            assert_eq!(conflict.rule, AttachmentRule::LocalBackend, "{address}");
            assert!(
                conflict.to_string().contains("allow_local_backend"),
                "{conflict}"
            );
            let flagged = Stream {
                allow_local_backend: true,
                ..tcp
            };
            assert!(
                fixture(backend("b", address), vec![flagged], &[])
                    .check()
                    .is_ok(),
                "{address} with the flag"
            );
        }
        // Remote addresses and names that resolve elsewhere pass.
        for address in [
            "192.0.2.10:5432",
            "pg.example.com:5432",
            "[2001:db8::1]:5432",
        ] {
            let tcp = stream("t", "pg", StreamProtocol::Tcp, 5432);
            assert!(
                fixture(backend("b", address), vec![tcp], &[])
                    .check()
                    .is_ok(),
                "{address}"
            );
        }
    }

    #[test]
    fn backups_need_a_primary_on_either_protocol() {
        let tcp = stream("t", "pg", StreamProtocol::Tcp, 5432);
        let mut f = fixture(backend("b-1", "192.0.2.10:5432"), vec![tcp.clone()], &[]);
        f.stream_backends = vec![backup(&tcp.id, "b-1")];
        assert_eq!(refused(&f).rule, AttachmentRule::NoPrimaryBackend);
        assert!(refused(&f).to_string().contains("`pg`"));

        f.backends.push(backend("b-2", "192.0.2.20:5432"));
        f.stream_backends.push(link(&tcp.id, "b-2"));
        assert!(f.check().is_ok(), "a primary and a backup");

        let udp = stream("u", "dns", StreamProtocol::Udp, 53);
        let mut f = fixture(backend("b-1", "192.0.2.10:53"), vec![udp.clone()], &[]);
        f.backends.push(backend("b-2", "192.0.2.20:53"));
        f.stream_backends.push(backup(&udp.id, "b-2"));
        assert!(f.check().is_ok(), "a UDP stream takes backups (Story 12.5)");
        f.stream_backends = vec![backup(&udp.id, "b-1"), backup(&udp.id, "b-2")];
        assert_eq!(refused(&f).rule, AttachmentRule::NoPrimaryBackend);
    }

    #[test]
    fn source_addresses_must_cover_an_ip_literal_backend_s_family() {
        let mut tcp = stream("t", "pg", StreamProtocol::Tcp, 5432);
        tcp.source_addresses = vec!["192.0.2.50".parse().expect("test setup: address")];
        let v6 = refused(&fixture(
            backend("b", "[2001:db8::1]:5432"),
            vec![tcp.clone()],
            &[],
        ));
        assert_eq!(v6.rule, AttachmentRule::SourceFamilyMismatch);
        for fine in [
            "192.0.2.10:5432",
            "[::ffff:192.0.2.10]:5432",
            "pg.example.com:5432",
        ] {
            assert!(
                fixture(backend("b", fine), vec![tcp.clone()], &[])
                    .check()
                    .is_ok(),
                "{fine}"
            );
        }
        tcp.source_addresses = vec!["2001:db8::50".parse().expect("test setup: address")];
        assert_eq!(
            refused(&fixture(
                backend("b", "192.0.2.10:5432"),
                vec![tcp.clone()],
                &[]
            ))
            .rule,
            AttachmentRule::SourceFamilyMismatch
        );
        tcp.source_addresses.clear();
        assert!(fixture(backend("b", "192.0.2.10:5432"), vec![tcp], &[])
            .check()
            .is_ok());
    }

    #[test]
    fn the_connection_cap_refusal_is_published_as_connection_cap() {
        let word: &'static str = StreamRefusal::ConnectionCap.into();
        assert_eq!(word, "connection_cap");
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
