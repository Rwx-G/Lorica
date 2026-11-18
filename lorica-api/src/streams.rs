//! Stream CRUD HTTP handlers (Story 12.1, D-10) and the per-node checks
//! every stream write runs: the port conflict check (D-5) and the local
//! backend rule (Story 12.3, D-m rule B).
//!
//! A stream is managed like a route: reads at Viewer, writes at
//! Operator (the defaults of `required_role`), the same group and
//! selector validators, one audit row per mutation with the response
//! view before and after, and the reload signal after every commit. On
//! top of that a stream opens a port, so every create, update and
//! import is checked against the reserved ports and the other streams
//! of each node that would bind it, under the store lock that writes,
//! and refused `409` naming the node and the object
//! ([`STREAM_PORT_CONFLICT_CODE`]). Under the same lock a backend that
//! is local without resolution (loopback, unspecified, link-local,
//! `localhost`) may not reach a reserved port or a stream listen port of
//! such a node, `allow_local_backend` or not: refused `409` too
//! ([`STREAM_LOCAL_BACKEND_CODE`]). A create or an update is then
//! checked against the fd budget of each node that would bind it
//! (Story 12.2 D-e, [`crate::stream_budget`]), and the reads carry this
//! node's bind state of each stream.
//!
//! A TLS stream (Story 12.4) routes by its `match_rules`, and its links
//! travel inside each rule as `backend_ids` and `backup_backend_ids`;
//! the stream-level lists are then empty, and the reverse on a stream
//! that reads no ClientHello. Its PEM bundles and the certificates it
//! names are checked by [`tls_checks`] on every write.
//!
//! The source controls of Story 12.6 (the CIDR lists, GeoIP, the
//! per-source and pending caps, the open rates) are stream fields like
//! any other; a link's cap (`max_active`, D-h) travels beside the lists
//! that make the link, as `backend_max_active`, a map from backend id to
//! cap, at the stream level or in each rule of a TLS stream.
//!
//! Status codes: `400` for a body this API's shared route validators
//! refuse (group name, selector) and for a body that does not parse;
//! `422` for a body that parses and breaks a model rule
//! (`Stream::validate`, the UDP listen-address rule of Story 12.5 D-k
//! and the `udp` settings' ranges included, the source controls, a
//! link's `max_active` out of its range or naming a backend the body
//! does not link, a backend id naming no backend, a name already
//! taken, the attachment rules of D-6 and of Story 12.3, a local backend
//! without `allow_local_backend` among them, the TLS field a mode does
//! not take, a PEM bundle that does not parse, a certificate that does
//! not exist or does not cover a rule's name), the rule
//! `ApiError::Unprocessable` documents, and a write a node's fd budget
//! cannot hold ([`crate::stream_budget::STREAM_FD_BUDGET_CODE`]); `404`
//! for an unknown id; `409` for a port conflict, a local backend on a
//! node's port, and, on a follower outside break-glass, for every
//! write.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_config::listen_ports::{
    local_backend_conflicts, stream_port_conflicts, LocalBackendConflict, LocalBackendObject,
    NodeLabel, NodePorts, PortConflict, ReservedPorts,
};
use lorica_config::models::{
    binds_here_when_enabled, Backend, ClusterNode, GeoIpConfig, LoadBalancing, MtlsConfig,
    NodeRole, NodeStatus, Stream, StreamBackend, StreamMatchRule, StreamMatcher, StreamProtocol,
    StreamProxyProtocol, StreamTlsMode, StreamTlsTerminate, StreamUpstreamTls, UdpSettings,
    UpstreamServerName,
};
use lorica_config::ConfigStore;
use serde::{Deserialize, Deserializer, Serialize};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::routes::crud::{selector_roster, validate_group_name, validate_node_selector};
use crate::server::AppState;
use crate::stream_budget::{check_write, reported_fds, BudgetNode, NodeFds, StreamPlaneState};

pub mod status;
#[cfg(test)]
mod tests;
pub(crate) mod tls_checks;

pub use status::get_stream_status;

/// The `error.code` of a `409` refusing a stream's ports, so a client
/// tells it from the follower read-only `409` without reading the
/// message.
pub const STREAM_PORT_CONFLICT_CODE: &str = "stream_port_conflict";

/// The `error.code` of a `409` refusing a stream write because a local
/// backend would reach a node's own listener or a stream listen port
/// there (Story 12.3 D-m, rule B), which `allow_local_backend` does not
/// lift.
pub const STREAM_LOCAL_BACKEND_CODE: &str = "stream_local_backend";

/// Model fields deliberately absent from [`StreamResponse`]. Empty: a
/// stream carries no secret, and the PROXY trust list and the local
/// backend flag are exactly what an operator reviewing a stream must
/// see (Story 12.3 D-q). Its TLS fields hold none either: a client
/// certificate is named by its stored id, never pasted with its key,
/// and a CA bundle is public (Story 12.4 D-i). A later secret-bearing
/// field is withheld by adding it here, and the view test fails until
/// it is either here or in the view.
pub const STREAM_WITHHELD_FIELDS: &[&str] = &[];

/// JSON view of a stream returned by every stream endpoint. Built field
/// by field from the model, never a `Serialize` of it, so a field the
/// model gains is not published until it is added here on purpose.
#[derive(Debug, Serialize)]
pub struct StreamResponse {
    /// Mirror of `Stream.id`.
    pub id: String,
    /// Mirror of `Stream.name`.
    pub name: String,
    /// Mirror of `Stream.group_name`.
    pub group_name: String,
    /// Mirror of `Stream.protocol` (`tcp` or `udp`).
    pub protocol: StreamProtocol,
    /// Mirror of `Stream.enabled`.
    pub enabled: bool,
    /// Mirror of `Stream.listen_address`, in its canonical text form.
    pub listen_address: IpAddr,
    /// Mirror of `Stream.port_first`.
    pub port_first: u16,
    /// Mirror of `Stream.port_last`.
    pub port_last: u16,
    /// Mirror of `Stream.node_selector`.
    pub node_selector: Vec<String>,
    /// Mirror of `Stream.load_balancing`.
    pub load_balancing: LoadBalancing,
    /// Mirror of `Stream.connect_timeout_ms`.
    pub connect_timeout_ms: u32,
    /// Mirror of `Stream.idle_timeout_s`.
    pub idle_timeout_s: u32,
    /// Mirror of `Stream.total_timeout_s`; `null` for no limit.
    pub total_timeout_s: Option<u32>,
    /// Mirror of `Stream.max_connect_attempts`.
    pub max_connect_attempts: u8,
    /// Mirror of `Stream.backend_keepalive`.
    pub backend_keepalive: bool,
    /// Mirror of `Stream.backend_keepalive_idle_s`.
    pub backend_keepalive_idle_s: u32,
    /// Mirror of `Stream.close_on_backend_down`.
    pub close_on_backend_down: bool,
    /// Mirror of `Stream.proxy_protocol_send` (`off`, `v1` or `v2`).
    pub proxy_protocol_send: StreamProxyProtocol,
    /// Mirror of `Stream.proxy_protocol_accept`.
    pub proxy_protocol_accept: bool,
    /// Mirror of `Stream.proxy_protocol_trusted_cidrs`.
    pub proxy_protocol_trusted_cidrs: Vec<String>,
    /// Mirror of `Stream.source_addresses`, each in its canonical text
    /// form.
    pub source_addresses: Vec<IpAddr>,
    /// Mirror of `Stream.allow_local_backend`.
    pub allow_local_backend: bool,
    /// Mirror of `Stream.upload_rate_bps`; `null` for no limit.
    pub upload_rate_bps: Option<u64>,
    /// Mirror of `Stream.download_rate_bps`; `null` for no limit.
    pub download_rate_bps: Option<u64>,
    /// Mirror of `Stream.max_connections`, per node.
    pub max_connections: u32,
    /// Mirror of `Stream.source_max_connections`; `null` bounds a source
    /// by `max_connections` alone.
    pub source_max_connections: Option<u32>,
    /// Mirror of `Stream.max_pending_connections`.
    pub max_pending_connections: u32,
    /// Mirror of `Stream.source_allow_cidrs`.
    pub source_allow_cidrs: Vec<String>,
    /// Mirror of `Stream.source_deny_cidrs`.
    pub source_deny_cidrs: Vec<String>,
    /// Mirror of `Stream.geoip`, in the route's shape (`mode`,
    /// `countries`), the codes as stored; `null` for none.
    pub geoip: Option<GeoIpConfig>,
    /// Mirror of `Stream.source_open_rate`; `null` for no limit.
    pub source_open_rate: Option<u32>,
    /// Mirror of `Stream.open_rate`; `null` for no limit.
    pub open_rate: Option<u32>,
    /// Mirror of `Stream.udp`: the settings of a UDP stream, `null` on a
    /// TCP stream, which carries none (Story 12.5 D-l).
    pub udp: Option<StreamUdpResponse>,
    /// Mirror of `Stream.tls_mode` (`none`, `passthrough` or
    /// `terminate`).
    pub tls_mode: StreamTlsMode,
    /// Mirror of `Stream.match_rules`, each with the backends that
    /// serve it.
    pub match_rules: Vec<StreamMatchRuleResponse>,
    /// Mirror of `Stream.no_sni_acknowledged`.
    pub no_sni_acknowledged: bool,
    /// Mirror of `Stream.clienthello_timeout_ms`; `null` for the
    /// default.
    pub clienthello_timeout_ms: Option<u32>,
    /// Mirror of `Stream.tls_terminate`; `null` unless the stream
    /// terminates TLS.
    pub tls_terminate: Option<StreamTlsTerminateResponse>,
    /// Mirror of `Stream.upstream_tls`; `null` when the stream opens no
    /// TLS towards its backends.
    pub upstream_tls: Option<StreamUpstreamTlsResponse>,
    /// `Stream::drains_on_upgrade`: a hot upgrade drains this stream's
    /// connections even once live transfer exists (D8). Read-only.
    pub drains_on_upgrade: bool,
    /// IDs of the primary backends linked through `stream_backends`,
    /// sorted; empty on a TLS stream, whose links are per rule.
    pub backend_ids: Vec<String>,
    /// IDs of the backup backends, sorted: candidates only when no
    /// primary is (Story 12.3 D-f); empty on a TLS stream.
    pub backup_backend_ids: Vec<String>,
    /// The cap of each link in `backend_ids` and `backup_backend_ids`
    /// that has one (`StreamBackend.max_active`), by backend id; a link
    /// absent from it is uncapped. Empty on a TLS stream.
    pub backend_max_active: BTreeMap<String, u32>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
}

/// One rule of a TLS stream's view (Story 12.4 D-d): the model's rule
/// and the backends linked to serve it.
#[derive(Debug, Serialize)]
pub struct StreamMatchRuleResponse {
    /// Mirror of `StreamMatchRule.name`.
    pub name: String,
    /// Mirror of `StreamMatchRule.matcher`, tagged by `kind`. A kind is
    /// a matcher's whole shape, so the model's own form is the view.
    pub matcher: StreamMatcher,
    /// IDs of the primary backends serving the rule, sorted.
    pub backend_ids: Vec<String>,
    /// IDs of the backup backends serving the rule, sorted.
    pub backup_backend_ids: Vec<String>,
    /// The cap of each of the rule's links that has one, by backend id.
    pub backend_max_active: BTreeMap<String, u32>,
}

/// The `tls_terminate` object of a stream's view (Story 12.4 D-f, D-h).
#[derive(Debug, Serialize)]
pub struct StreamTlsTerminateResponse {
    /// Mirror of `StreamTlsTerminate.certificate_ids`.
    pub certificate_ids: Vec<String>,
    /// Mirror of `StreamTlsTerminate.client_auth`; `null` verifies no
    /// client.
    pub client_auth: Option<StreamClientAuthResponse>,
}

/// The client certificate verification of a terminating stream's view,
/// in the shape of a route's `mtls`.
#[derive(Debug, Serialize)]
pub struct StreamClientAuthResponse {
    /// Mirror of `MtlsConfig.ca_cert_pem`: the CA certificates trusted,
    /// public material.
    pub ca_cert_pem: String,
    /// Mirror of `MtlsConfig.required`.
    pub required: bool,
    /// Mirror of `MtlsConfig.allowed_organizations`.
    pub allowed_organizations: Vec<String>,
}

/// The `upstream_tls` object of a stream's view (Story 12.4 D-i).
#[derive(Debug, Serialize)]
pub struct StreamUpstreamTlsResponse {
    /// Mirror of `StreamUpstreamTls.server_name`, tagged by `mode`.
    pub server_name: UpstreamServerName,
    /// Mirror of `StreamUpstreamTls.ca_cert_pem`; `null` trusts the
    /// public roots.
    pub ca_cert_pem: Option<String>,
    /// Mirror of `StreamUpstreamTls.skip_verify`.
    pub skip_verify: bool,
    /// Mirror of `StreamUpstreamTls.client_certificate_id`: the stored
    /// certificate presented, by id; its key is never in the view.
    pub client_certificate_id: Option<String>,
    /// Mirror of `StreamUpstreamTls.alpn`.
    pub alpn: Vec<String>,
}

impl StreamTlsTerminateResponse {
    fn of(terminate: &StreamTlsTerminate) -> Self {
        StreamTlsTerminateResponse {
            certificate_ids: terminate.certificate_ids.clone(),
            client_auth: terminate.client_auth.as_ref().map(|auth: &MtlsConfig| {
                StreamClientAuthResponse {
                    ca_cert_pem: auth.ca_cert_pem.clone(),
                    required: auth.required,
                    allowed_organizations: auth.allowed_organizations.clone(),
                }
            }),
        }
    }
}

impl StreamUpstreamTlsResponse {
    fn of(upstream: &StreamUpstreamTls) -> Self {
        StreamUpstreamTlsResponse {
            server_name: upstream.server_name.clone(),
            ca_cert_pem: upstream.ca_cert_pem.clone(),
            skip_verify: upstream.skip_verify,
            client_certificate_id: upstream.client_certificate_id.clone(),
            alpn: upstream.alpn.clone(),
        }
    }
}

/// The `udp` object of a stream's view (Story 12.5 D-l), built field by
/// field from `UdpSettings` like the view around it. The response bounds
/// keep their stored values while `unbounded_responses` lifts them, so
/// the view shows what clearing the flag would apply again.
#[derive(Debug, Serialize)]
pub struct StreamUdpResponse {
    /// Mirror of `UdpSettings.max_sessions`.
    pub max_sessions: u32,
    /// Mirror of `UdpSettings.source_session_cap`; `null` for the
    /// default cap, which does not satisfy the listen-address rule.
    pub source_session_cap: Option<u32>,
    /// Mirror of `UdpSettings.requests_per_session`; `null` for no bound.
    pub requests_per_session: Option<u32>,
    /// Mirror of `UdpSettings.responses_per_request`.
    pub responses_per_request: u32,
    /// Mirror of `UdpSettings.response_bytes_ratio`.
    pub response_bytes_ratio: u32,
    /// Mirror of `UdpSettings.unbounded_responses` (PRD AC #4: the flag
    /// every listing carries).
    pub unbounded_responses: bool,
    /// Mirror of `UdpSettings.source_datagram_rate`.
    pub source_datagram_rate: u32,
    /// Mirror of `UdpSettings.source_byte_rate`.
    pub source_byte_rate: u32,
    /// Mirror of `UdpSettings.max_datagram_bytes`.
    pub max_datagram_bytes: u32,
}

impl StreamUdpResponse {
    fn of(udp: &UdpSettings) -> Self {
        StreamUdpResponse {
            max_sessions: udp.max_sessions,
            source_session_cap: udp.source_session_cap,
            requests_per_session: udp.requests_per_session,
            responses_per_request: udp.responses_per_request,
            response_bytes_ratio: udp.response_bytes_ratio,
            unbounded_responses: udp.unbounded_responses,
            source_datagram_rate: udp.source_datagram_rate,
            source_byte_rate: udp.source_byte_rate,
            max_datagram_bytes: udp.max_datagram_bytes,
        }
    }
}

/// What `GET /api/v1/streams` and `GET /api/v1/streams/{id}` answer
/// per stream: the view, and this node's bind state of it (Story 12.2
/// D-h). The state is runtime, not configuration, so the view the
/// writes answer and audit does not carry it.
#[derive(Debug, Serialize)]
pub struct StreamReadResponse {
    /// The stream's configuration.
    #[serde(flatten)]
    pub stream: StreamResponse,
    /// This node's bind state (`pending`, `bound` or `failed` with its
    /// kind and OS error), `null` when this node does not bind the
    /// stream.
    pub bind: Option<lorica_stream::BindState>,
}

/// What a stream create or update answers: the view, the nodes the fd
/// budget check could not reach (Story 12.2 D-e), and what the TLS
/// checks accepted but the operator should know (Story 12.4).
#[derive(Debug, Serialize)]
pub struct StreamWriteResponse {
    /// The stream as written.
    #[serde(flatten)]
    pub stream: StreamResponse,
    /// One sentence per targeted node whose budget is unknown here, per
    /// client CA bundle finding and per wildcard rule name of a
    /// terminating stream ([`tls_checks`]); absent when there is none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn with_bind(state: &AppState, stream: StreamResponse) -> StreamReadResponse {
    StreamReadResponse {
        bind: state.stream_plane.bind_state(&stream.id),
        stream,
    }
}

/// The backends of one rule of a TLS stream, by role.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RuleLinks {
    /// The primaries, in the order given or sorted when read back.
    pub(crate) primaries: Vec<String>,
    /// The backups, likewise.
    pub(crate) backups: Vec<String>,
    /// The cap of each capped link, by backend id (Story 12.6 D-h).
    pub(crate) caps: BTreeMap<String, u32>,
}

/// The backends a stream links, by role (Story 12.3 D-f): the links
/// serving no rule, and on a TLS stream the links of each rule (Story
/// 12.4 D-d), each with its cap when it has one (Story 12.6 D-h).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StreamLinks {
    /// The primaries serving no rule, in the order given or sorted when
    /// read back.
    pub(crate) primaries: Vec<String>,
    /// The backups serving no rule, likewise.
    pub(crate) backups: Vec<String>,
    /// The cap of each capped link serving no rule, by backend id.
    pub(crate) caps: BTreeMap<String, u32>,
    /// The links of each rule, by rule name.
    pub(crate) rules: BTreeMap<String, RuleLinks>,
}

impl StreamLinks {
    /// The links of every stream, by stream id, each list sorted.
    fn by_stream(rows: Vec<StreamBackend>) -> HashMap<String, StreamLinks> {
        let mut by_stream: HashMap<String, StreamLinks> = HashMap::new();
        for row in rows {
            let links = by_stream.entry(row.stream_id).or_default();
            let (primaries, backups, caps) = match row.rule {
                Some(rule) => {
                    let rule = links.rules.entry(rule).or_default();
                    (&mut rule.primaries, &mut rule.backups, &mut rule.caps)
                }
                None => (&mut links.primaries, &mut links.backups, &mut links.caps),
            };
            if let Some(cap) = row.max_active {
                caps.insert(row.backend_id.clone(), cap);
            }
            if row.backup {
                backups.push(row.backend_id);
            } else {
                primaries.push(row.backend_id);
            }
        }
        by_stream
    }

    /// The links of `stream_id` as stored.
    fn of(store: &ConfigStore, stream_id: &str) -> Result<StreamLinks, ApiError> {
        Ok(Self::by_stream(store.list_stream_backends()?)
            .remove(stream_id)
            .unwrap_or_default())
    }

    /// Each list of backend ids with the field a body sets it in, the
    /// links serving no rule first.
    fn lists(&self) -> Vec<(String, &Vec<String>)> {
        let mut lists: Vec<(String, &Vec<String>)> = vec![
            ("backend_ids".to_string(), &self.primaries),
            ("backup_backend_ids".to_string(), &self.backups),
        ];
        for (rule, links) in &self.rules {
            lists.push((
                format!("match_rules `{rule}` backend_ids"),
                &links.primaries,
            ));
            lists.push((
                format!("match_rules `{rule}` backup_backend_ids"),
                &links.backups,
            ));
        }
        lists
    }

    /// Every backend id, the links serving no rule first.
    fn ids(&self) -> impl Iterator<Item = &String> {
        self.primaries.iter().chain(&self.backups).chain(
            self.rules
                .values()
                .flat_map(|rule| rule.primaries.iter().chain(&rule.backups)),
        )
    }

    /// The rows these links write for `stream`.
    ///
    /// # Errors
    ///
    /// `422` naming the stream when one backend is both a primary and a
    /// backup of the same rule (or of no rule), or when a cap names a
    /// backend its rule (or no rule) does not link. A backend serving two
    /// rules is refused by the store, which names it, as it refuses a cap
    /// out of its range.
    fn rows(&self, stream: &Stream) -> Result<Vec<StreamBackend>, ApiError> {
        let groups = std::iter::once((None, &self.primaries, &self.backups, &self.caps)).chain(
            self.rules
                .iter()
                .map(|(rule, links)| (Some(rule), &links.primaries, &links.backups, &links.caps)),
        );
        let mut rows: Vec<StreamBackend> = Vec::new();
        for (rule, primaries, backups, caps) in groups {
            let serving = rule.map_or(String::new(), |rule| format!(" for rule `{rule}`"));
            if let Some(both) = primaries.iter().find(|id| backups.contains(id)) {
                return Err(ApiError::Unprocessable(format!(
                    "stream `{}`: backend {both} is listed both as a primary and as a \
                     backup{serving}",
                    stream.name
                )));
            }
            if let Some(unlinked) = caps
                .keys()
                .find(|id| !primaries.contains(id) && !backups.contains(id))
            {
                return Err(ApiError::Unprocessable(format!(
                    "stream `{}`: backend_max_active names backend {unlinked}, which is \
                     neither a primary nor a backup{serving}",
                    stream.name
                )));
            }
            let roles = primaries
                .iter()
                .map(|id| (id, false))
                .chain(backups.iter().map(|id| (id, true)));
            for (backend_id, backup) in roles {
                rows.push(StreamBackend {
                    backup,
                    rule: rule.cloned(),
                    max_active: caps.get(backend_id).copied(),
                    ..StreamBackend::primary(&stream.id, backend_id)
                });
            }
        }
        Ok(rows)
    }
}

/// The view of `stream` with the backends it links.
pub(crate) fn stream_to_response(stream: &Stream, links: StreamLinks) -> StreamResponse {
    let StreamLinks {
        primaries,
        backups,
        caps,
        mut rules,
    } = links;
    let match_rules = stream
        .match_rules
        .iter()
        .map(|rule: &StreamMatchRule| {
            let links = rules.remove(&rule.name).unwrap_or_default();
            StreamMatchRuleResponse {
                name: rule.name.clone(),
                matcher: rule.matcher.clone(),
                backend_ids: links.primaries,
                backup_backend_ids: links.backups,
                backend_max_active: links.caps,
            }
        })
        .collect();
    StreamResponse {
        id: stream.id.clone(),
        name: stream.name.clone(),
        group_name: stream.group_name.clone(),
        protocol: stream.protocol,
        enabled: stream.enabled,
        listen_address: stream.listen_address,
        port_first: stream.port_first,
        port_last: stream.port_last,
        node_selector: stream.node_selector.clone(),
        load_balancing: stream.load_balancing.clone(),
        connect_timeout_ms: stream.connect_timeout_ms,
        idle_timeout_s: stream.idle_timeout_s,
        total_timeout_s: stream.total_timeout_s,
        max_connect_attempts: stream.max_connect_attempts,
        backend_keepalive: stream.backend_keepalive,
        backend_keepalive_idle_s: stream.backend_keepalive_idle_s,
        close_on_backend_down: stream.close_on_backend_down,
        proxy_protocol_send: stream.proxy_protocol_send,
        proxy_protocol_accept: stream.proxy_protocol_accept,
        proxy_protocol_trusted_cidrs: stream.proxy_protocol_trusted_cidrs.clone(),
        source_addresses: stream.source_addresses.clone(),
        allow_local_backend: stream.allow_local_backend,
        upload_rate_bps: stream.upload_rate_bps,
        download_rate_bps: stream.download_rate_bps,
        max_connections: stream.max_connections,
        source_max_connections: stream.source_max_connections,
        max_pending_connections: stream.max_pending_connections,
        source_allow_cidrs: stream.source_allow_cidrs.clone(),
        source_deny_cidrs: stream.source_deny_cidrs.clone(),
        geoip: stream.geoip.clone(),
        source_open_rate: stream.source_open_rate,
        open_rate: stream.open_rate,
        udp: stream.udp.as_ref().map(StreamUdpResponse::of),
        tls_mode: stream.tls_mode,
        match_rules,
        no_sni_acknowledged: stream.no_sni_acknowledged,
        clienthello_timeout_ms: stream.clienthello_timeout_ms,
        tls_terminate: stream
            .tls_terminate
            .as_ref()
            .map(StreamTlsTerminateResponse::of),
        upstream_tls: stream
            .upstream_tls
            .as_ref()
            .map(StreamUpstreamTlsResponse::of),
        drains_on_upgrade: stream.drains_on_upgrade(),
        backend_ids: primaries,
        backup_backend_ids: backups,
        backend_max_active: caps,
        created_at: stream.created_at.to_rfc3339(),
        updated_at: stream.updated_at.to_rfc3339(),
    }
}

/// A field a body may leave out (`None`), send as `null` (`Some(None)`,
/// no limit) or send with a value (`Some(Some(v))`). Used with
/// `#[serde(default)]`, which is what makes an absent field `None`.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// Body of `POST /api/v1/streams`. Every Story 12.3 setting is optional
/// and takes the model's default when absent (`Stream::new`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateStreamRequest {
    /// Unique fleet-wide identifier (`Stream.name` rule).
    pub name: String,
    /// Classification label; absent or blank means ungrouped.
    pub group_name: Option<String>,
    /// `tcp` or `udp`.
    pub protocol: StreamProtocol,
    /// Whether the stream is bound where it is targeted; default true.
    pub enabled: Option<bool>,
    /// The one IP address the stream listens on.
    pub listen_address: IpAddr,
    /// First listen port.
    pub port_first: u16,
    /// Last listen port; absent means a single port (`port_first`).
    pub port_last: Option<u16>,
    /// Node names the stream is pinned to; absent or empty is
    /// fleet-wide.
    pub node_selector: Option<Vec<String>>,
    /// `Stream.load_balancing`.
    pub load_balancing: Option<LoadBalancing>,
    /// `Stream.connect_timeout_ms`.
    pub connect_timeout_ms: Option<u32>,
    /// `Stream.idle_timeout_s`.
    pub idle_timeout_s: Option<u32>,
    /// `Stream.total_timeout_s`; absent or `null` for no limit.
    #[serde(default, deserialize_with = "nullable")]
    pub total_timeout_s: Option<Option<u32>>,
    /// `Stream.max_connect_attempts`.
    pub max_connect_attempts: Option<u8>,
    /// `Stream.backend_keepalive`.
    pub backend_keepalive: Option<bool>,
    /// `Stream.backend_keepalive_idle_s`.
    pub backend_keepalive_idle_s: Option<u32>,
    /// `Stream.close_on_backend_down`.
    pub close_on_backend_down: Option<bool>,
    /// `Stream.proxy_protocol_send`.
    pub proxy_protocol_send: Option<StreamProxyProtocol>,
    /// `Stream.proxy_protocol_accept`.
    pub proxy_protocol_accept: Option<bool>,
    /// `Stream.proxy_protocol_trusted_cidrs`.
    pub proxy_protocol_trusted_cidrs: Option<Vec<String>>,
    /// `Stream.source_addresses`.
    pub source_addresses: Option<Vec<IpAddr>>,
    /// `Stream.allow_local_backend`.
    pub allow_local_backend: Option<bool>,
    /// `Stream.upload_rate_bps`; absent or `null` for no limit.
    #[serde(default, deserialize_with = "nullable")]
    pub upload_rate_bps: Option<Option<u64>>,
    /// `Stream.download_rate_bps`; absent or `null` for no limit.
    #[serde(default, deserialize_with = "nullable")]
    pub download_rate_bps: Option<Option<u64>>,
    /// `Stream.max_connections`.
    pub max_connections: Option<u32>,
    /// `Stream.source_max_connections`; absent or `null` for none.
    #[serde(default, deserialize_with = "nullable")]
    pub source_max_connections: Option<Option<u32>>,
    /// `Stream.max_pending_connections`.
    pub max_pending_connections: Option<u32>,
    /// `Stream.source_allow_cidrs`; absent is none.
    pub source_allow_cidrs: Option<Vec<String>>,
    /// `Stream.source_deny_cidrs`; absent is none.
    pub source_deny_cidrs: Option<Vec<String>>,
    /// `Stream.geoip`; absent or `null` for none.
    #[serde(default, deserialize_with = "nullable")]
    pub geoip: Option<Option<GeoIpConfig>>,
    /// `Stream.source_open_rate`; absent or `null` for no limit.
    #[serde(default, deserialize_with = "nullable")]
    pub source_open_rate: Option<Option<u32>>,
    /// `Stream.open_rate`; absent or `null` for no limit.
    #[serde(default, deserialize_with = "nullable")]
    pub open_rate: Option<Option<u32>>,
    /// `Stream.udp`, UDP streams only: each setting absent takes its
    /// default, and the object absent (or `null`) takes every default.
    /// Refused on a TCP stream.
    pub udp: Option<UdpSettingsRequest>,
    /// `Stream.tls_mode`; absent is `none`.
    pub tls_mode: Option<StreamTlsMode>,
    /// `Stream.match_rules`, each with the backends serving it; absent
    /// is none.
    pub match_rules: Option<Vec<StreamMatchRuleRequest>>,
    /// `Stream.no_sni_acknowledged`.
    pub no_sni_acknowledged: Option<bool>,
    /// `Stream.clienthello_timeout_ms`; absent or `null` for the
    /// default.
    #[serde(default, deserialize_with = "nullable")]
    pub clienthello_timeout_ms: Option<Option<u32>>,
    /// `Stream.tls_terminate`; absent or `null` for none.
    #[serde(default, deserialize_with = "nullable")]
    pub tls_terminate: Option<Option<StreamTlsTerminate>>,
    /// `Stream.upstream_tls`; absent or `null` for none.
    #[serde(default, deserialize_with = "nullable")]
    pub upstream_tls: Option<Option<StreamUpstreamTls>>,
    /// Primary backends the stream forwards to; absent is none. Empty
    /// on a TLS stream, whose backends are listed per rule.
    pub backend_ids: Option<Vec<String>>,
    /// Backup backends, used only when no primary is a candidate; absent
    /// is none. A backend may not be in both lists. Empty on a TLS
    /// stream.
    pub backup_backend_ids: Option<Vec<String>>,
    /// The cap of each capped link, by backend id, every key in
    /// `backend_ids` or `backup_backend_ids`; absent caps none. Empty on
    /// a TLS stream, whose caps are listed per rule.
    pub backend_max_active: Option<BTreeMap<String, u32>>,
}

/// A rule of a TLS stream as a create or an update writes it (Story
/// 12.4 D-d, D-k): the model's rule and the backends that serve it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamMatchRuleRequest {
    /// `StreamMatchRule.name`.
    pub name: String,
    /// `StreamMatchRule.matcher`, tagged by `kind`.
    pub matcher: StreamMatcher,
    /// Primary backends serving the rule; absent is none.
    #[serde(default)]
    pub backend_ids: Vec<String>,
    /// Backup backends serving the rule, used only when none of its
    /// primaries is a candidate; absent is none.
    #[serde(default)]
    pub backup_backend_ids: Vec<String>,
    /// The cap of each of the rule's capped links, by backend id, every
    /// key one of the rule's backends; absent caps none.
    #[serde(default)]
    pub backend_max_active: BTreeMap<String, u32>,
}

/// Body of `PUT /api/v1/streams/{id}`: every field optional, an absent
/// field keeps its stored value, and `null` on a nullable field
/// (`total_timeout_s`, `upload_rate_bps`, `download_rate_bps`,
/// `source_max_connections`, `geoip`, `source_open_rate`, `open_rate`)
/// removes the limit.
///
/// The ports move together, as on create: `port_first` without
/// `port_last` makes the stream a single port, so moving a single-port
/// stream never turns it into a range by accident. `port_last` alone
/// moves the end of the range and keeps its start. `backend_ids`
/// replaces the primaries and `backup_backend_ids` the backups; a list
/// left out keeps its stored half. `backend_max_active` replaces every
/// cap; left out, each link still written keeps its stored cap. On a
/// TLS stream `match_rules`
/// replaces the rules and every link with the ones its rules carry, and
/// left out keeps both.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateStreamRequest {
    /// New name.
    pub name: Option<String>,
    /// New group; blank means ungrouped.
    pub group_name: Option<String>,
    /// New protocol.
    pub protocol: Option<StreamProtocol>,
    /// Enable or disable the stream.
    pub enabled: Option<bool>,
    /// New listen address.
    pub listen_address: Option<IpAddr>,
    /// New first port (see the type's doc for how `port_last` follows).
    pub port_first: Option<u16>,
    /// New last port.
    pub port_last: Option<u16>,
    /// New selector; empty is fleet-wide.
    pub node_selector: Option<Vec<String>>,
    /// New `Stream.load_balancing`.
    pub load_balancing: Option<LoadBalancing>,
    /// New `Stream.connect_timeout_ms`.
    pub connect_timeout_ms: Option<u32>,
    /// New `Stream.idle_timeout_s`.
    pub idle_timeout_s: Option<u32>,
    /// New `Stream.total_timeout_s`; `null` removes the limit.
    #[serde(default, deserialize_with = "nullable")]
    pub total_timeout_s: Option<Option<u32>>,
    /// New `Stream.max_connect_attempts`.
    pub max_connect_attempts: Option<u8>,
    /// New `Stream.backend_keepalive`.
    pub backend_keepalive: Option<bool>,
    /// New `Stream.backend_keepalive_idle_s`.
    pub backend_keepalive_idle_s: Option<u32>,
    /// New `Stream.close_on_backend_down`.
    pub close_on_backend_down: Option<bool>,
    /// New `Stream.proxy_protocol_send`.
    pub proxy_protocol_send: Option<StreamProxyProtocol>,
    /// New `Stream.proxy_protocol_accept`.
    pub proxy_protocol_accept: Option<bool>,
    /// New `Stream.proxy_protocol_trusted_cidrs`, replacing the list.
    pub proxy_protocol_trusted_cidrs: Option<Vec<String>>,
    /// New `Stream.source_addresses`, replacing the list.
    pub source_addresses: Option<Vec<IpAddr>>,
    /// New `Stream.allow_local_backend`.
    pub allow_local_backend: Option<bool>,
    /// New `Stream.upload_rate_bps`; `null` removes the limit.
    #[serde(default, deserialize_with = "nullable")]
    pub upload_rate_bps: Option<Option<u64>>,
    /// New `Stream.download_rate_bps`; `null` removes the limit.
    #[serde(default, deserialize_with = "nullable")]
    pub download_rate_bps: Option<Option<u64>>,
    /// New `Stream.max_connections`.
    pub max_connections: Option<u32>,
    /// New `Stream.source_max_connections`; `null` removes the cap.
    #[serde(default, deserialize_with = "nullable")]
    pub source_max_connections: Option<Option<u32>>,
    /// New `Stream.max_pending_connections`.
    pub max_pending_connections: Option<u32>,
    /// New `Stream.source_allow_cidrs`, replacing the list.
    pub source_allow_cidrs: Option<Vec<String>>,
    /// New `Stream.source_deny_cidrs`, replacing the list.
    pub source_deny_cidrs: Option<Vec<String>>,
    /// New `Stream.geoip`, replacing the object; `null` removes it.
    #[serde(default, deserialize_with = "nullable")]
    pub geoip: Option<Option<GeoIpConfig>>,
    /// New `Stream.source_open_rate`; `null` removes the limit.
    #[serde(default, deserialize_with = "nullable")]
    pub source_open_rate: Option<Option<u32>>,
    /// New `Stream.open_rate`; `null` removes the limit.
    #[serde(default, deserialize_with = "nullable")]
    pub open_rate: Option<Option<u32>>,
    /// New `Stream.udp` settings, each absent one kept (after a switch
    /// to UDP, each absent one takes its default); the object absent or
    /// `null` keeps them all. Refused on a TCP stream.
    pub udp: Option<UdpSettingsRequest>,
    /// New `Stream.tls_mode`.
    pub tls_mode: Option<StreamTlsMode>,
    /// New `Stream.match_rules` with the backends serving each,
    /// replacing the rules and every link.
    pub match_rules: Option<Vec<StreamMatchRuleRequest>>,
    /// New `Stream.no_sni_acknowledged`.
    pub no_sni_acknowledged: Option<bool>,
    /// New `Stream.clienthello_timeout_ms`; `null` restores the default.
    #[serde(default, deserialize_with = "nullable")]
    pub clienthello_timeout_ms: Option<Option<u32>>,
    /// New `Stream.tls_terminate`, replacing the object; `null` removes
    /// it.
    #[serde(default, deserialize_with = "nullable")]
    pub tls_terminate: Option<Option<StreamTlsTerminate>>,
    /// New `Stream.upstream_tls`, replacing the object; `null` removes
    /// it.
    #[serde(default, deserialize_with = "nullable")]
    pub upstream_tls: Option<Option<StreamUpstreamTls>>,
    /// New primaries, replacing the stored ones; empty on a TLS stream.
    pub backend_ids: Option<Vec<String>>,
    /// New backups, replacing the stored ones; empty on a TLS stream.
    pub backup_backend_ids: Option<Vec<String>>,
    /// New link caps, replacing every stored one; empty on a TLS stream.
    pub backend_max_active: Option<BTreeMap<String, u32>>,
}

/// The `udp` object of a create or an update (Story 12.5 D-l): every
/// setting optional, an absent one keeping the value it is applied over
/// (the defaults on a create or a switch to UDP, the stored value on an
/// update), and `null` on `source_session_cap` or `requests_per_session`
/// setting the default cap or no bound.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpSettingsRequest {
    /// `UdpSettings.max_sessions`.
    pub max_sessions: Option<u32>,
    /// `UdpSettings.source_session_cap`; `null` for the default cap.
    #[serde(default, deserialize_with = "nullable")]
    pub source_session_cap: Option<Option<u32>>,
    /// `UdpSettings.requests_per_session`; `null` for no bound.
    #[serde(default, deserialize_with = "nullable")]
    pub requests_per_session: Option<Option<u32>>,
    /// `UdpSettings.responses_per_request`.
    pub responses_per_request: Option<u32>,
    /// `UdpSettings.response_bytes_ratio`.
    pub response_bytes_ratio: Option<u32>,
    /// `UdpSettings.unbounded_responses`.
    pub unbounded_responses: Option<bool>,
    /// `UdpSettings.source_datagram_rate`.
    pub source_datagram_rate: Option<u32>,
    /// `UdpSettings.source_byte_rate`.
    pub source_byte_rate: Option<u32>,
    /// `UdpSettings.max_datagram_bytes`.
    pub max_datagram_bytes: Option<u32>,
}

impl UdpSettingsRequest {
    /// Write every setting the object carried onto `stream`'s `udp`, over
    /// the defaults when the stream holds none: a TCP stream then carries
    /// settings, which `Stream::validate` refuses with the model's words.
    fn apply(self, stream: &mut Stream) {
        let mut udp = stream.udp.unwrap_or_default();
        if let Some(v) = self.max_sessions {
            udp.max_sessions = v;
        }
        if let Some(v) = self.source_session_cap {
            udp.source_session_cap = v;
        }
        if let Some(v) = self.requests_per_session {
            udp.requests_per_session = v;
        }
        if let Some(v) = self.responses_per_request {
            udp.responses_per_request = v;
        }
        if let Some(v) = self.response_bytes_ratio {
            udp.response_bytes_ratio = v;
        }
        if let Some(v) = self.unbounded_responses {
            udp.unbounded_responses = v;
        }
        if let Some(v) = self.source_datagram_rate {
            udp.source_datagram_rate = v;
        }
        if let Some(v) = self.source_byte_rate {
            udp.source_byte_rate = v;
        }
        if let Some(v) = self.max_datagram_bytes {
            udp.max_datagram_bytes = v;
        }
        stream.udp = Some(udp);
    }
}

/// The Story 12.3 settings and the Story 12.5 `udp` object a create or
/// an update carries, each `None` when the body left it out. One type
/// for both bodies, so the two cannot apply a setting differently.
struct EngineSettings {
    load_balancing: Option<LoadBalancing>,
    connect_timeout_ms: Option<u32>,
    idle_timeout_s: Option<u32>,
    total_timeout_s: Option<Option<u32>>,
    max_connect_attempts: Option<u8>,
    backend_keepalive: Option<bool>,
    backend_keepalive_idle_s: Option<u32>,
    close_on_backend_down: Option<bool>,
    proxy_protocol_send: Option<StreamProxyProtocol>,
    proxy_protocol_accept: Option<bool>,
    proxy_protocol_trusted_cidrs: Option<Vec<String>>,
    source_addresses: Option<Vec<IpAddr>>,
    allow_local_backend: Option<bool>,
    upload_rate_bps: Option<Option<u64>>,
    download_rate_bps: Option<Option<u64>>,
    max_connections: Option<u32>,
    udp: Option<UdpSettingsRequest>,
}

impl EngineSettings {
    /// Write every setting the body carried onto `stream`, whose
    /// protocol is already the one it will have.
    fn apply(self, stream: &mut Stream) {
        if let Some(v) = self.load_balancing {
            stream.load_balancing = v;
        }
        if let Some(v) = self.connect_timeout_ms {
            stream.connect_timeout_ms = v;
        }
        if let Some(v) = self.idle_timeout_s {
            stream.idle_timeout_s = v;
        }
        if let Some(v) = self.total_timeout_s {
            stream.total_timeout_s = v;
        }
        if let Some(v) = self.max_connect_attempts {
            stream.max_connect_attempts = v;
        }
        if let Some(v) = self.backend_keepalive {
            stream.backend_keepalive = v;
        }
        if let Some(v) = self.backend_keepalive_idle_s {
            stream.backend_keepalive_idle_s = v;
        }
        if let Some(v) = self.close_on_backend_down {
            stream.close_on_backend_down = v;
        }
        if let Some(v) = self.proxy_protocol_send {
            stream.proxy_protocol_send = v;
        }
        if let Some(v) = self.proxy_protocol_accept {
            stream.proxy_protocol_accept = v;
        }
        if let Some(v) = self.proxy_protocol_trusted_cidrs {
            stream.proxy_protocol_trusted_cidrs = v;
        }
        if let Some(v) = self.source_addresses {
            stream.source_addresses = v;
        }
        if let Some(v) = self.allow_local_backend {
            stream.allow_local_backend = v;
        }
        if let Some(v) = self.upload_rate_bps {
            stream.upload_rate_bps = v;
        }
        if let Some(v) = self.download_rate_bps {
            stream.download_rate_bps = v;
        }
        if let Some(v) = self.max_connections {
            stream.max_connections = v;
        }
        if let Some(udp) = self.udp {
            udp.apply(stream);
        }
    }
}

/// The Story 12.6 source controls a create or an update carries, each
/// `None` when the body left it out. One type for both bodies, as
/// [`EngineSettings`].
struct SourceControls {
    source_max_connections: Option<Option<u32>>,
    max_pending_connections: Option<u32>,
    source_allow_cidrs: Option<Vec<String>>,
    source_deny_cidrs: Option<Vec<String>>,
    geoip: Option<Option<GeoIpConfig>>,
    source_open_rate: Option<Option<u32>>,
    open_rate: Option<Option<u32>>,
}

impl SourceControls {
    /// Write every control the body carried onto `stream`, its GeoIP
    /// list in the form it is stored in, so the view a write answers is
    /// the row it wrote.
    fn apply(self, stream: &mut Stream) {
        if let Some(v) = self.source_max_connections {
            stream.source_max_connections = v;
        }
        if let Some(v) = self.max_pending_connections {
            stream.max_pending_connections = v;
        }
        if let Some(v) = self.source_allow_cidrs {
            stream.source_allow_cidrs = v;
        }
        if let Some(v) = self.source_deny_cidrs {
            stream.source_deny_cidrs = v;
        }
        if let Some(v) = self.geoip {
            stream.geoip = v;
            stream.canonicalise_geoip();
        }
        if let Some(v) = self.source_open_rate {
            stream.source_open_rate = v;
        }
        if let Some(v) = self.open_rate {
            stream.open_rate = v;
        }
    }
}

/// The Story 12.4 fields a create or an update carries, each `None`
/// when the body left it out. One type for both bodies, as
/// [`EngineSettings`].
struct TlsSettings {
    tls_mode: Option<StreamTlsMode>,
    match_rules: Option<Vec<StreamMatchRuleRequest>>,
    no_sni_acknowledged: Option<bool>,
    clienthello_timeout_ms: Option<Option<u32>>,
    tls_terminate: Option<Option<StreamTlsTerminate>>,
    upstream_tls: Option<Option<StreamUpstreamTls>>,
}

impl TlsSettings {
    /// Write every field the body carried onto `stream`, its server
    /// names in the form they are stored in, and answer the links the
    /// rules carry when the body sent `match_rules`.
    fn apply(self, stream: &mut Stream) -> Option<BTreeMap<String, RuleLinks>> {
        if let Some(v) = self.tls_mode {
            stream.tls_mode = v;
        }
        if let Some(v) = self.no_sni_acknowledged {
            stream.no_sni_acknowledged = v;
        }
        if let Some(v) = self.clienthello_timeout_ms {
            stream.clienthello_timeout_ms = v;
        }
        if let Some(v) = self.tls_terminate {
            stream.tls_terminate = v;
        }
        if let Some(v) = self.upstream_tls {
            stream.upstream_tls = v;
        }
        let rules = self.match_rules?;
        let mut links: BTreeMap<String, RuleLinks> = BTreeMap::new();
        stream.match_rules = rules
            .into_iter()
            .map(|rule| {
                links.insert(
                    rule.name.clone(),
                    RuleLinks {
                        primaries: rule.backend_ids,
                        backups: rule.backup_backend_ids,
                        caps: rule.backend_max_active,
                    },
                );
                StreamMatchRule {
                    name: rule.name,
                    matcher: rule.matcher,
                }
            })
            .collect();
        stream.canonicalise_server_names();
        Some(links)
    }
}

/// The links a write of `stream` sets, `None` when it keeps `stored`.
///
/// On a stream that reads a ClientHello the links are the rules':
/// `rules` when the body sent `match_rules`, and the stream-level lists
/// and caps must be absent or empty. On any other stream they are the
/// stream-level lists, a list left out keeping its `stored` half, and
/// the caps left out keeping the stored cap of each link still written.
///
/// # Errors
///
/// `422` naming the field and the mode when a TLS stream's body carries
/// a stream-level backend or cap.
fn written_links(
    stream: &Stream,
    backend_ids: Option<Vec<String>>,
    backup_backend_ids: Option<Vec<String>>,
    backend_max_active: Option<BTreeMap<String, u32>>,
    rules: Option<BTreeMap<String, RuleLinks>>,
    stored: &StreamLinks,
) -> Result<Option<StreamLinks>, ApiError> {
    if stream.tls_mode.reads_client_hello() {
        for (field, given) in [
            (
                "backend_ids",
                backend_ids.as_ref().is_some_and(|ids| !ids.is_empty()),
            ),
            (
                "backup_backend_ids",
                backup_backend_ids
                    .as_ref()
                    .is_some_and(|ids| !ids.is_empty()),
            ),
            (
                "backend_max_active",
                backend_max_active
                    .as_ref()
                    .is_some_and(|caps| !caps.is_empty()),
            ),
        ] {
            if given {
                return Err(ApiError::Unprocessable(format!(
                    "stream `{}`: {field} is refused on a stream whose tls_mode is {}: its \
                     backends are listed in each of match_rules",
                    stream.name,
                    stream.tls_mode.as_str()
                )));
            }
        }
        return Ok(rules.map(|rules| StreamLinks {
            rules,
            ..StreamLinks::default()
        }));
    }
    if backend_ids.is_none() && backup_backend_ids.is_none() && backend_max_active.is_none() {
        return Ok(None);
    }
    let primaries = backend_ids.unwrap_or_else(|| stored.primaries.clone());
    let backups = backup_backend_ids.unwrap_or_else(|| stored.backups.clone());
    let caps = backend_max_active.unwrap_or_else(|| {
        stored
            .caps
            .iter()
            .filter(|(id, _)| primaries.contains(id) || backups.contains(id))
            .map(|(id, cap)| (id.clone(), *cap))
            .collect()
    });
    Ok(Some(StreamLinks {
        primaries,
        backups,
        caps,
        rules: BTreeMap::new(),
    }))
}

/// The fleet role of this process, owned so it crosses into a store
/// closure. [`LocalRole::node_role`] borrows it as the
/// [`NodeRole`] `binds_here` reads (D-8).
#[derive(Debug, Clone)]
pub(crate) enum LocalRole {
    Standalone,
    ControlPlane,
    Follower(String),
}

impl LocalRole {
    /// The role of the process `state` runs in.
    pub(crate) fn of(state: &AppState) -> LocalRole {
        match &state.cluster {
            crate::cluster::ClusterRuntime::Standalone => LocalRole::Standalone,
            crate::cluster::ClusterRuntime::ControlPlane(_) => LocalRole::ControlPlane,
            crate::cluster::ClusterRuntime::Follower(follower) => {
                LocalRole::Follower(follower.node_name.clone())
            }
        }
    }

    pub(crate) fn node_role(&self) -> NodeRole<'_> {
        match self {
            LocalRole::Standalone => NodeRole::Standalone,
            LocalRole::ControlPlane => NodeRole::ControlPlane,
            LocalRole::Follower(node_name) => NodeRole::Follower { node_name },
        }
    }
}

/// The nodes `candidate` is checked on (D-5): this node, with its own
/// reserved ports, whenever it would bind the candidate; and on a
/// control plane every active roster row the candidate's selector
/// resolves to, through the replication resolver, so "checked on" and
/// "delivered to" cannot disagree.
fn nodes_checking<'a>(
    candidate: &Stream,
    role: &'a LocalRole,
    reserved: ReservedPorts,
    roster: &'a [ClusterNode],
) -> Vec<NodePorts<'a>> {
    let mut nodes = Vec::new();
    let local_role = role.node_role();
    if binds_here_when_enabled(candidate, local_role) {
        nodes.push(NodePorts {
            label: NodeLabel::ThisNode,
            role: local_role,
            reserved: Some(reserved),
        });
    }
    if matches!(role, LocalRole::ControlPlane) {
        let resolution = lorica_config::canonical::SelectorResolution::from_rows(
            roster.iter().map(|n| (n.name.clone(), n.node_id.clone())),
        );
        for node in roster {
            if node.status == NodeStatus::Active
                && resolution.targets(&candidate.node_selector, &node.node_id)
            {
                nodes.push(NodePorts {
                    label: NodeLabel::Named(node.name.clone()),
                    role: NodeRole::Follower {
                        node_name: &node.name,
                    },
                    reserved: node.reserved_ports,
                });
            }
        }
    }
    nodes
}

/// The roster the per-node checks read: the enrolled nodes on a control
/// plane, none on any other role, where this node is the only one
/// checked.
fn roster_of(store: &ConfigStore, role: &LocalRole) -> Result<Vec<ClusterNode>, ApiError> {
    if matches!(role, LocalRole::ControlPlane) {
        Ok(store.list_cluster_nodes()?)
    } else {
        Ok(Vec::new())
    }
}

/// The first port conflict of `candidate` on the nodes that would bind
/// it, against `others` (which may hold the candidate's own row). Reads
/// the roster from `store`, so a caller holding the store lock that
/// writes checks and writes against the same rows.
pub(crate) fn first_port_conflict(
    store: &ConfigStore,
    role: &LocalRole,
    reserved: ReservedPorts,
    candidate: &Stream,
    others: &[Stream],
) -> Result<Option<PortConflict>, ApiError> {
    let roster = roster_of(store, role)?;
    let nodes = nodes_checking(candidate, role, reserved, &roster);
    Ok(stream_port_conflicts(candidate, &nodes, others)
        .into_iter()
        .next())
}

/// The first rule-B conflict (Story 12.3 D-m) of `candidate` linking
/// `backends`, on the nodes [`first_port_conflict`] checks, against
/// `others` (which may hold the candidate's own row). The first one
/// only, as a port conflict names one: fixing it shows the next.
pub(crate) fn first_local_backend_conflict(
    store: &ConfigStore,
    role: &LocalRole,
    reserved: ReservedPorts,
    candidate: &Stream,
    backends: &[Backend],
    others: &[Stream],
) -> Result<Option<LocalBackendConflict>, ApiError> {
    let roster = roster_of(store, role)?;
    let nodes = nodes_checking(candidate, role, reserved, &roster);
    Ok(local_backend_conflicts(candidate, backends, &nodes, others)
        .into_iter()
        .next())
}

/// The `409` refusing `stream` for a local backend `conflict`.
pub(crate) fn local_backend_error(stream: &Stream, conflict: &LocalBackendConflict) -> ApiError {
    ApiError::coded(
        StatusCode::CONFLICT,
        STREAM_LOCAL_BACKEND_CODE,
        format!("stream `{}`: {conflict}", stream.name),
    )
}

/// Rule B (Story 12.3 D-m) for a stream write, both ways: `candidate`'s
/// own local `backends` may not reach a node's port, and no other stored
/// stream's local backend may reach a listen port the candidate now
/// takes, which would make that stream forward into this one. `others`
/// is every stored stream, the candidate's old row included.
///
/// # Errors
///
/// The `409` of the first conflict, naming the stream whose backend
/// conflicts, or a store read failure.
fn refuse_local_backends(
    store: &ConfigStore,
    role: &LocalRole,
    reserved: ReservedPorts,
    candidate: &Stream,
    backends: &[Backend],
    others: &[Stream],
) -> Result<(), ApiError> {
    if let Some(conflict) =
        first_local_backend_conflict(store, role, reserved, candidate, backends, others)?
    {
        return Err(local_backend_error(candidate, &conflict));
    }
    let world: Vec<Stream> = others
        .iter()
        .filter(|s| s.id != candidate.id)
        .cloned()
        .chain(std::iter::once(candidate.clone()))
        .collect();
    let rows: HashMap<String, Backend> = store
        .list_backends()?
        .into_iter()
        .map(|b| (b.id.clone(), b))
        .collect();
    let roster = roster_of(store, role)?;
    for (stream_id, links) in StreamLinks::by_stream(store.list_stream_backends()?) {
        let Some(other) = world
            .iter()
            .find(|s| s.id == stream_id && s.id != candidate.id)
        else {
            continue;
        };
        let theirs: Vec<Backend> = links.ids().filter_map(|id| rows.get(id).cloned()).collect();
        let nodes = nodes_checking(other, role, reserved, &roster);
        let into_candidate = local_backend_conflicts(other, &theirs, &nodes, &world)
            .into_iter()
            .find(|conflict| {
                matches!(&conflict.object, LocalBackendObject::Stream { name } if *name == candidate.name)
            });
        if let Some(conflict) = into_candidate {
            return Err(local_backend_error(other, &conflict));
        }
    }
    Ok(())
}

/// Rule B (Story 12.3 D-m) for a backend write: `backend`, as it would
/// be written, checked as a link of every stream that links it, with
/// that stream's other backends as stored. Run by the backend update of
/// every plane, the automation one included.
///
/// # Errors
///
/// The `409` of the first stream the backend would make reach a node's
/// port, or a store read failure.
pub(crate) fn refuse_local_backend_on_its_streams(
    store: &ConfigStore,
    role: &LocalRole,
    reserved: ReservedPorts,
    backend: &Backend,
) -> Result<(), ApiError> {
    let stream_ids = store.list_streams_for_backend(&backend.id)?;
    if stream_ids.is_empty() {
        return Ok(());
    }
    let streams = store.list_streams()?;
    let rows: HashMap<String, Backend> = store
        .list_backends()?
        .into_iter()
        .map(|b| (b.id.clone(), b))
        .collect();
    let mut links = StreamLinks::by_stream(store.list_stream_backends()?);
    for stream in streams.iter().filter(|s| stream_ids.contains(&s.id)) {
        let linked = links.remove(&stream.id).unwrap_or_default();
        let backends: Vec<Backend> = linked
            .ids()
            .filter_map(|id| {
                if *id == backend.id {
                    Some(backend.clone())
                } else {
                    rows.get(id).cloned()
                }
            })
            .collect();
        if let Some(conflict) =
            first_local_backend_conflict(store, role, reserved, stream, &backends, &streams)?
        {
            return Err(local_backend_error(stream, &conflict));
        }
    }
    Ok(())
}

/// What the fd budget check of a stream write reads besides the store:
/// this node's figures and, on a control plane, the figures each
/// enrolled node reported in its heartbeat (D-i), taken before the
/// store lock.
#[derive(Debug, Clone)]
pub(crate) struct BudgetInputs {
    /// This process's own listeners, which decide whether it binds the
    /// candidate.
    pub(crate) reserved: ReservedPorts,
    /// This process's stream plane.
    pub(crate) plane: StreamPlaneState,
    /// Reported figures by node id; empty off a control plane.
    pub(crate) reported: HashMap<String, NodeFds>,
}

impl BudgetInputs {
    /// The inputs of the process `state` runs in.
    pub(crate) fn of(state: &AppState) -> Self {
        BudgetInputs {
            reserved: state.reserved_ports,
            plane: state.stream_plane.clone(),
            reported: reported_fds(state),
        }
    }
}

/// The fd budget check of D-e for a write of `candidate` replacing
/// `stored`, on the nodes [`first_port_conflict`] checks: this node with
/// its own figures, and on a control plane every active node the
/// selector targets, with the figures its heartbeat reported. Reads the
/// roster from `store`, under the caller's lock; `listen_socket_cap` is
/// the setting the write will run under.
///
/// A targeted node with no report on an open session (offline, a
/// 1.10.x follower, or connected and not reported yet) cannot be
/// checked here: it is named in a warning and refuses at bind with
/// `fd_budget`.
///
/// One function for every stream write: create, update, and the config
/// import and its preview, so none of them accepts what another refuses.
///
/// # Errors
///
/// The `422` of the first node whose budget the write breaks, or a
/// store read failure.
pub(crate) fn budget_warnings(
    store: &ConfigStore,
    role: &LocalRole,
    inputs: &BudgetInputs,
    listen_socket_cap: u32,
    candidate: &Stream,
    stored: Option<&Stream>,
    others: &[Stream],
) -> Result<Vec<String>, ApiError> {
    let roster = roster_of(store, role)?;
    let ids: HashMap<&str, &str> = roster
        .iter()
        .map(|n| (n.name.as_str(), n.node_id.as_str()))
        .collect();
    let nodes: Vec<BudgetNode<'_>> = nodes_checking(candidate, role, inputs.reserved, &roster)
        .into_iter()
        .map(|node| BudgetNode {
            fds: match &node.label {
                NodeLabel::ThisNode => Some(inputs.plane.fds()),
                NodeLabel::Named(name) => ids
                    .get(name.as_str())
                    .and_then(|id| inputs.reported.get(*id))
                    .copied(),
            },
            label: node.label,
            role: node.role,
        })
        .collect();
    check_write(candidate, stored, others, &nodes, listen_socket_cap)
        .map_err(|refusal| refusal.into_error(candidate))
}

/// The `409` refusing `stream` for `conflict`.
pub(crate) fn port_conflict_error(stream: &Stream, conflict: &PortConflict) -> ApiError {
    ApiError::coded(
        StatusCode::CONFLICT,
        STREAM_PORT_CONFLICT_CODE,
        format!("stream `{}`: {conflict}", stream.name),
    )
}

/// The rows `links` names, refusing an id that names no backend rather
/// than leaving it to the foreign key, whose error is not the caller's
/// to read.
fn linked_backends(store: &ConfigStore, links: &StreamLinks) -> Result<Vec<Backend>, ApiError> {
    let mut rows = Vec::new();
    for (field, ids) in links.lists() {
        for id in ids {
            match store.get_backend(id)? {
                Some(backend) => rows.push(backend),
                None => {
                    return Err(ApiError::Unprocessable(format!(
                        "{field}: backend {id} does not exist"
                    )))
                }
            }
        }
    }
    Ok(rows)
}

fn validated(stream: &Stream) -> Result<(), ApiError> {
    stream.validate().map_err(ApiError::Unprocessable)
}

/// GET /api/v1/streams - every stream, by name, with its backend ids.
pub async fn list_streams(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let streams = db_blocking(&state.store, |store| {
        let streams = store.list_streams()?;
        let mut links = StreamLinks::by_stream(store.list_stream_backends()?);
        Ok::<_, ApiError>(
            streams
                .into_iter()
                .map(|stream| {
                    let linked = links.remove(&stream.id).unwrap_or_default();
                    stream_to_response(&stream, linked)
                })
                .collect::<Vec<StreamResponse>>(),
        )
    })
    .await?;
    let streams: Vec<StreamReadResponse> = streams
        .into_iter()
        .map(|stream| with_bind(&state, stream))
        .collect();
    Ok(json_data(serde_json::json!({ "streams": streams })))
}

/// GET /api/v1/streams/{id} - one stream with its backend ids.
pub async fn get_stream(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let response = db_blocking(&state.store, move |store| {
        let stream = store
            .get_stream(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("stream {id}")))?;
        let links = StreamLinks::of(store, &stream.id)?;
        Ok::<_, ApiError>(stream_to_response(&stream, links))
    })
    .await?;
    Ok(json_data(with_bind(&state, response)))
}

/// POST /api/v1/streams - create a stream.
pub async fn create_stream(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<CreateStreamRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    create_stream_as(&state, &audit_ctx, body).await
}

/// The whole of [`create_stream`] as `actor`: the validation, the port
/// and local backend checks, the budget, the row and its links, the
/// reload signal and the `stream.create` audit row. Split from the
/// handler, as `create_route_as` is, so a later read or write surface
/// (Story 12.10) runs exactly this rather than a second implementation.
pub(crate) async fn create_stream_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    body: CreateStreamRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let CreateStreamRequest {
        name,
        group_name,
        protocol,
        enabled,
        listen_address,
        port_first,
        port_last,
        node_selector,
        load_balancing,
        connect_timeout_ms,
        idle_timeout_s,
        total_timeout_s,
        max_connect_attempts,
        backend_keepalive,
        backend_keepalive_idle_s,
        close_on_backend_down,
        proxy_protocol_send,
        proxy_protocol_accept,
        proxy_protocol_trusted_cidrs,
        source_addresses,
        allow_local_backend,
        upload_rate_bps,
        download_rate_bps,
        max_connections,
        source_max_connections,
        max_pending_connections,
        source_allow_cidrs,
        source_deny_cidrs,
        geoip,
        source_open_rate,
        open_rate,
        udp,
        tls_mode,
        match_rules,
        no_sni_acknowledged,
        clienthello_timeout_ms,
        tls_terminate,
        upstream_tls,
        backend_ids,
        backup_backend_ids,
        backend_max_active,
    } = body;
    let roster = match node_selector.as_deref() {
        Some(names) if !names.is_empty() => selector_roster(state).await?,
        _ => None,
    };
    let mut stream = Stream::new(
        uuid::Uuid::new_v4().to_string(),
        name,
        protocol,
        listen_address,
        port_first,
        port_last.unwrap_or(port_first),
        Utc::now(),
    );
    if let Some(raw) = group_name.as_deref() {
        stream.group_name = validate_group_name(raw)?;
    }
    stream.enabled = enabled.unwrap_or(true);
    if let Some(names) = node_selector.as_deref() {
        stream.node_selector = validate_node_selector(names, roster.as_deref())?;
    }
    EngineSettings {
        load_balancing,
        connect_timeout_ms,
        idle_timeout_s,
        total_timeout_s,
        max_connect_attempts,
        backend_keepalive,
        backend_keepalive_idle_s,
        close_on_backend_down,
        proxy_protocol_send,
        proxy_protocol_accept,
        proxy_protocol_trusted_cidrs,
        source_addresses,
        allow_local_backend,
        upload_rate_bps,
        download_rate_bps,
        max_connections,
        udp,
    }
    .apply(&mut stream);
    SourceControls {
        source_max_connections,
        max_pending_connections,
        source_allow_cidrs,
        source_deny_cidrs,
        geoip,
        source_open_rate,
        open_rate,
    }
    .apply(&mut stream);
    let rule_links = TlsSettings {
        tls_mode,
        match_rules,
        no_sni_acknowledged,
        clienthello_timeout_ms,
        tls_terminate,
        upstream_tls,
    }
    .apply(&mut stream);
    validated(&stream)?;
    let mut tls_warnings = tls_checks::check_bundles(&mut stream)?;
    let links = written_links(
        &stream,
        backend_ids,
        backup_backend_ids,
        backend_max_active,
        rule_links,
        &StreamLinks::default(),
    )?
    .unwrap_or_default();
    let rows = links.rows(&stream)?;
    let role = LocalRole::of(state);
    let budget = BudgetInputs::of(state);

    let (stream, links, warnings) = db_blocking(&state.store, move |store| {
        let backends = linked_backends(store, &links)?;
        tls_warnings.extend(tls_checks::check_certificates(
            &stream,
            &store.list_certificates_without_private_keys()?,
        )?);
        // Under the lock that writes, so two creates on one port cannot
        // both pass, nor two creates that each fit the budget alone.
        let others = store.list_streams()?;
        if let Some(conflict) =
            first_port_conflict(store, &role, budget.reserved, &stream, &others)?
        {
            return Err(port_conflict_error(&stream, &conflict));
        }
        refuse_local_backends(store, &role, budget.reserved, &stream, &backends, &others)?;
        let cap = store.get_global_settings()?.stream_listen_socket_cap;
        let mut warnings = budget_warnings(store, &role, &budget, cap, &stream, None, &others)?;
        warnings.extend(tls_warnings);
        store.in_transaction(|store| {
            store.create_stream(&stream)?;
            store.set_stream_links(&stream.id, &rows)
        })?;
        let links = StreamLinks::of(store, &stream.id)?;
        Ok::<_, ApiError>((stream, links, warnings))
    })
    .await?;
    state.notify_config_changed();

    let response = stream_to_response(&stream, links);
    let after = serde_json::to_value(&response).ok();
    crate::audit::record(
        state,
        actor,
        "stream.create",
        ("stream", &stream.id),
        None,
        after.as_ref(),
    )
    .await;
    Ok(json_data_with_status(
        StatusCode::CREATED,
        StreamWriteResponse {
            stream: response,
            warnings,
        },
    ))
}

/// PUT /api/v1/streams/{id} - patch a stream.
pub async fn update_stream(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
    Json(body): Json<UpdateStreamRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    update_stream_as(&state, &audit_ctx, id, body).await
}

/// The whole of [`update_stream`] as `actor`; see [`create_stream_as`].
/// The patch is applied, validated, checked and written under one store
/// lock, against the row as it stands.
pub(crate) async fn update_stream_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
    body: UpdateStreamRequest,
) -> Result<Json<serde_json::Value>, ApiError> {
    let UpdateStreamRequest {
        name,
        group_name,
        protocol,
        enabled,
        listen_address,
        port_first,
        port_last,
        node_selector,
        load_balancing,
        connect_timeout_ms,
        idle_timeout_s,
        total_timeout_s,
        max_connect_attempts,
        backend_keepalive,
        backend_keepalive_idle_s,
        close_on_backend_down,
        proxy_protocol_send,
        proxy_protocol_accept,
        proxy_protocol_trusted_cidrs,
        source_addresses,
        allow_local_backend,
        upload_rate_bps,
        download_rate_bps,
        max_connections,
        source_max_connections,
        max_pending_connections,
        source_allow_cidrs,
        source_deny_cidrs,
        geoip,
        source_open_rate,
        open_rate,
        udp,
        tls_mode,
        match_rules,
        no_sni_acknowledged,
        clienthello_timeout_ms,
        tls_terminate,
        upstream_tls,
        backend_ids,
        backup_backend_ids,
        backend_max_active,
    } = body;
    let selector = match node_selector.as_deref() {
        Some(names) => {
            let roster = selector_roster(state).await?;
            Some(validate_node_selector(names, roster.as_deref())?)
        }
        None => None,
    };
    let group_name = group_name.as_deref().map(validate_group_name).transpose()?;
    let engine = EngineSettings {
        load_balancing,
        connect_timeout_ms,
        idle_timeout_s,
        total_timeout_s,
        max_connect_attempts,
        backend_keepalive,
        backend_keepalive_idle_s,
        close_on_backend_down,
        proxy_protocol_send,
        proxy_protocol_accept,
        proxy_protocol_trusted_cidrs,
        source_addresses,
        allow_local_backend,
        upload_rate_bps,
        download_rate_bps,
        max_connections,
        udp,
    };
    let controls = SourceControls {
        source_max_connections,
        max_pending_connections,
        source_allow_cidrs,
        source_deny_cidrs,
        geoip,
        source_open_rate,
        open_rate,
    };
    let tls = TlsSettings {
        tls_mode,
        match_rules,
        no_sni_acknowledged,
        clienthello_timeout_ms,
        tls_terminate,
        upstream_tls,
    };
    let role = LocalRole::of(state);
    let budget = BudgetInputs::of(state);

    let (before, after, warnings) = db_blocking(&state.store, move |store| {
        let stored = store
            .get_stream(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("stream {id}")))?;
        let stored_links = StreamLinks::of(store, &id)?;
        let before = stream_to_response(&stored, stored_links.clone());

        let mut stream = stored.clone();
        if let Some(name) = name {
            stream.name = name;
        }
        if let Some(group_name) = group_name {
            stream.group_name = group_name;
        }
        if let Some(protocol) = protocol {
            if protocol != stream.protocol {
                // The UDP settings exist on a UDP stream only: a switch
                // takes the new protocol's (Story 12.5 D-l).
                stream.udp = Stream::default_udp_settings(protocol);
            }
            stream.protocol = protocol;
        }
        if let Some(enabled) = enabled {
            stream.enabled = enabled;
        }
        if let Some(listen_address) = listen_address {
            stream.listen_address = listen_address;
        }
        match (port_first, port_last) {
            (Some(first), last) => {
                stream.port_first = first;
                stream.port_last = last.unwrap_or(first);
            }
            (None, Some(last)) => stream.port_last = last,
            (None, None) => {}
        }
        if let Some(selector) = selector {
            stream.node_selector = selector;
        }
        engine.apply(&mut stream);
        controls.apply(&mut stream);
        let rule_links = tls.apply(&mut stream);
        stream.updated_at = Utc::now();
        validated(&stream)?;
        let mut tls_warnings = tls_checks::check_bundles(&mut stream)?;
        let new_links = written_links(
            &stream,
            backend_ids,
            backup_backend_ids,
            backend_max_active,
            rule_links,
            &stored_links,
        )?;
        let new_rows = new_links
            .as_ref()
            .map(|links| links.rows(&stream))
            .transpose()?;
        let backends = linked_backends(store, new_links.as_ref().unwrap_or(&stored_links))?;
        tls_warnings.extend(tls_checks::check_certificates(
            &stream,
            &store.list_certificates_without_private_keys()?,
        )?);

        let others = store.list_streams()?;
        if let Some(conflict) =
            first_port_conflict(store, &role, budget.reserved, &stream, &others)?
        {
            return Err(port_conflict_error(&stream, &conflict));
        }
        refuse_local_backends(store, &role, budget.reserved, &stream, &backends, &others)?;
        let cap = store.get_global_settings()?.stream_listen_socket_cap;
        let mut warnings =
            budget_warnings(store, &role, &budget, cap, &stream, Some(&stored), &others)?;
        warnings.extend(tls_warnings);
        store.in_transaction(|store| match &new_rows {
            // Unlinked first, then the row, then the new links: the
            // attachment rules then judge the row as written against the
            // links as they will stand, and neither half against the
            // other's old state (a stream turned UDP while its links
            // change, the local backend flag set with the backend it
            // allows, a rule renamed with the links that serve it).
            Some(rows) => {
                store.set_stream_links(&stream.id, &[])?;
                store.update_stream(&stream)?;
                store.set_stream_links(&stream.id, rows)
            }
            None => store.update_stream(&stream),
        })?;
        let after = stream_to_response(&stream, StreamLinks::of(store, &stream.id)?);
        Ok::<_, ApiError>((before, after, warnings))
    })
    .await?;
    state.notify_config_changed();

    let before_json = serde_json::to_value(&before).ok();
    let after_json = serde_json::to_value(&after).ok();
    crate::audit::record(
        state,
        actor,
        "stream.update",
        ("stream", &after.id),
        before_json.as_ref(),
        after_json.as_ref(),
    )
    .await;
    Ok(json_data(StreamWriteResponse {
        stream: after,
        warnings,
    }))
}

/// DELETE /api/v1/streams/{id} - delete a stream; its backend links go
/// with it, its backends stay.
pub async fn delete_stream(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    delete_stream_as(&state, &audit_ctx, id).await
}

/// The whole of [`delete_stream`] as `actor`; see [`create_stream_as`].
pub(crate) async fn delete_stream_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
) -> Result<Json<serde_json::Value>, ApiError> {
    let before = db_blocking(&state.store, move |store| {
        let stream = store
            .get_stream(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("stream {id}")))?;
        let before = stream_to_response(&stream, StreamLinks::of(store, &id)?);
        store.delete_stream(&id)?;
        Ok::<_, ApiError>(before)
    })
    .await?;
    state.notify_config_changed();

    let before_json = serde_json::to_value(&before).ok();
    crate::audit::record(
        state,
        actor,
        "stream.delete",
        ("stream", &before.id),
        before_json.as_ref(),
        None,
    )
    .await;
    Ok(json_data(
        serde_json::json!({ "message": "stream deleted" }),
    ))
}
