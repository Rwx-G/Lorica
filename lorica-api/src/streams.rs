//! Stream CRUD HTTP handlers (Story 12.1, D-10) and the per-node port
//! conflict check every stream write runs (D-5).
//!
//! A stream is managed like a route: reads at Viewer, writes at
//! Operator (the defaults of `required_role`), the same group and
//! selector validators, one audit row per mutation with the response
//! view before and after, and the reload signal after every commit. On
//! top of that a stream opens a port, so every create, update and
//! import is checked against the reserved ports and the other streams
//! of each node that would bind it, under the store lock that writes,
//! and refused `409` naming the node and the object
//! ([`STREAM_PORT_CONFLICT_CODE`]). Under the same lock a create or an
//! update is checked against the fd budget of each node that would bind
//! it (Story 12.2 D-e, [`crate::stream_budget`]), and the reads carry
//! this node's bind state of each stream.
//!
//! Status codes: `400` for a body this API's shared route validators
//! refuse (group name, selector) and for a body that does not parse;
//! `422` for a body that parses and breaks a model rule
//! (`Stream::validate`, a backend id naming no backend, a name already
//! taken, the attachment rule of D-6), the rule `ApiError::Unprocessable`
//! documents, and a write a node's fd budget cannot hold
//! ([`crate::stream_budget::STREAM_FD_BUDGET_CODE`]); `404` for an
//! unknown id; `409` for a port conflict and,
//! on a follower outside break-glass, for every write.

use std::collections::HashMap;
use std::net::IpAddr;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use lorica_config::listen_ports::{
    stream_port_conflicts, NodeLabel, NodePorts, PortConflict, ReservedPorts,
};
use lorica_config::models::{
    binds_here_when_enabled, ClusterNode, NodeRole, NodeStatus, Stream, StreamProtocol,
};
use lorica_config::ConfigStore;
use serde::{Deserialize, Serialize};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::routes::crud::{selector_roster, validate_group_name, validate_node_selector};
use crate::server::AppState;
use crate::stream_budget::{check_write, reported_fds, BudgetNode, NodeFds, StreamPlaneState};

#[cfg(test)]
mod tests;

/// The `error.code` of a `409` refusing a stream's ports, so a client
/// tells it from the follower read-only `409` without reading the
/// message.
pub const STREAM_PORT_CONFLICT_CODE: &str = "stream_port_conflict";

/// Model fields deliberately absent from [`StreamResponse`]. Empty: a
/// stream carries no secret yet. A later secret-bearing field is
/// withheld by adding it here, and the view test fails until it is
/// either here or in the view.
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
    /// IDs of the backends linked through `stream_backends`, sorted.
    pub backend_ids: Vec<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-write timestamp.
    pub updated_at: String,
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

/// What a stream create or update answers: the view, and the nodes the
/// fd budget check could not reach (Story 12.2 D-e).
#[derive(Debug, Serialize)]
pub struct StreamWriteResponse {
    /// The stream as written.
    #[serde(flatten)]
    pub stream: StreamResponse,
    /// One sentence per targeted node whose budget is unknown here;
    /// absent when there is none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

fn with_bind(state: &AppState, stream: StreamResponse) -> StreamReadResponse {
    StreamReadResponse {
        bind: state.stream_plane.bind_state(&stream.id),
        stream,
    }
}

/// The view of `stream` with the backends it links.
pub(crate) fn stream_to_response(stream: &Stream, backend_ids: Vec<String>) -> StreamResponse {
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
        backend_ids,
        created_at: stream.created_at.to_rfc3339(),
        updated_at: stream.updated_at.to_rfc3339(),
    }
}

/// Body of `POST /api/v1/streams`.
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
    /// Backends the stream forwards to; absent is none.
    pub backend_ids: Option<Vec<String>>,
}

/// Body of `PUT /api/v1/streams/{id}`: every field optional, an absent
/// field keeps its stored value.
///
/// The ports move together, as on create: `port_first` without
/// `port_last` makes the stream a single port, so moving a single-port
/// stream never turns it into a range by accident. `port_last` alone
/// moves the end of the range and keeps its start. `backend_ids`
/// replaces the whole set.
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
    /// New backend set, replacing the stored one.
    pub backend_ids: Option<Vec<String>>,
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
    let roster = if matches!(role, LocalRole::ControlPlane) {
        store.list_cluster_nodes()?
    } else {
        Vec::new()
    };
    let nodes = nodes_checking(candidate, role, reserved, &roster);
    Ok(stream_port_conflicts(candidate, &nodes, others)
        .into_iter()
        .next())
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
    let roster = if matches!(role, LocalRole::ControlPlane) {
        store.list_cluster_nodes()?
    } else {
        Vec::new()
    };
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

/// Refuse a backend id naming no backend, rather than leaving it to the
/// foreign key, whose error is not the caller's to read.
fn refuse_unknown_backends(store: &ConfigStore, backend_ids: &[String]) -> Result<(), ApiError> {
    for id in backend_ids {
        if store.get_backend(id)?.is_none() {
            return Err(ApiError::Unprocessable(format!(
                "backend_ids: backend {id} does not exist"
            )));
        }
    }
    Ok(())
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
        let mut links: HashMap<String, Vec<String>> = HashMap::new();
        for link in store.list_stream_backends()? {
            links
                .entry(link.stream_id)
                .or_default()
                .push(link.backend_id);
        }
        Ok::<_, ApiError>(
            streams
                .into_iter()
                .map(|stream| {
                    let backend_ids = links.remove(&stream.id).unwrap_or_default();
                    stream_to_response(&stream, backend_ids)
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
        let backend_ids = store.list_backends_for_stream(&stream.id)?;
        Ok::<_, ApiError>(stream_to_response(&stream, backend_ids))
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
/// check, the row and its links, the reload signal and the
/// `stream.create` audit row. Split from the handler, as
/// `create_route_as` is, so a later read or write surface (Story 12.10)
/// runs exactly this rather than a second implementation.
pub(crate) async fn create_stream_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    body: CreateStreamRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let roster = match body.node_selector.as_deref() {
        Some(names) if !names.is_empty() => selector_roster(state).await?,
        _ => None,
    };
    let now = Utc::now();
    let stream = Stream {
        group_name: match body.group_name.as_deref() {
            Some(raw) => validate_group_name(raw)?,
            None => String::new(),
        },
        enabled: body.enabled.unwrap_or(true),
        node_selector: match body.node_selector.as_deref() {
            Some(names) => validate_node_selector(names, roster.as_deref())?,
            None => Vec::new(),
        },
        ..Stream::new(
            uuid::Uuid::new_v4().to_string(),
            body.name,
            body.protocol,
            body.listen_address,
            body.port_first,
            body.port_last.unwrap_or(body.port_first),
            now,
        )
    };
    validated(&stream)?;
    let backend_ids = body.backend_ids.unwrap_or_default();
    let role = LocalRole::of(state);
    let budget = BudgetInputs::of(state);

    let (stream, backend_ids, warnings) = db_blocking(&state.store, move |store| {
        refuse_unknown_backends(store, &backend_ids)?;
        // Under the lock that writes, so two creates on one port cannot
        // both pass, nor two creates that each fit the budget alone.
        let others = store.list_streams()?;
        if let Some(conflict) =
            first_port_conflict(store, &role, budget.reserved, &stream, &others)?
        {
            return Err(port_conflict_error(&stream, &conflict));
        }
        let cap = store.get_global_settings()?.stream_listen_socket_cap;
        let warnings = budget_warnings(store, &role, &budget, cap, &stream, None, &others)?;
        store.in_transaction(|store| {
            store.create_stream(&stream)?;
            store.set_stream_backends(&stream.id, &backend_ids)
        })?;
        let backend_ids = store.list_backends_for_stream(&stream.id)?;
        Ok::<_, ApiError>((stream, backend_ids, warnings))
    })
    .await?;
    state.notify_config_changed();

    let response = stream_to_response(&stream, backend_ids);
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
/// The patch is applied, validated, port-checked and written under one
/// store lock, against the row as it stands.
pub(crate) async fn update_stream_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
    body: UpdateStreamRequest,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = match body.node_selector.as_deref() {
        Some(names) => {
            let roster = selector_roster(state).await?;
            Some(validate_node_selector(names, roster.as_deref())?)
        }
        None => None,
    };
    let group_name = body
        .group_name
        .as_deref()
        .map(validate_group_name)
        .transpose()?;
    let role = LocalRole::of(state);
    let budget = BudgetInputs::of(state);

    let (before, after, warnings) = db_blocking(&state.store, move |store| {
        let stored = store
            .get_stream(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("stream {id}")))?;
        let before = stream_to_response(&stored, store.list_backends_for_stream(&id)?);

        let mut stream = stored.clone();
        if let Some(name) = body.name {
            stream.name = name;
        }
        if let Some(group_name) = group_name {
            stream.group_name = group_name;
        }
        if let Some(protocol) = body.protocol {
            stream.protocol = protocol;
        }
        if let Some(enabled) = body.enabled {
            stream.enabled = enabled;
        }
        if let Some(listen_address) = body.listen_address {
            stream.listen_address = listen_address;
        }
        match (body.port_first, body.port_last) {
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
        stream.updated_at = Utc::now();
        validated(&stream)?;
        if let Some(backend_ids) = &body.backend_ids {
            refuse_unknown_backends(store, backend_ids)?;
        }

        let others = store.list_streams()?;
        if let Some(conflict) =
            first_port_conflict(store, &role, budget.reserved, &stream, &others)?
        {
            return Err(port_conflict_error(&stream, &conflict));
        }
        let cap = store.get_global_settings()?.stream_listen_socket_cap;
        let warnings =
            budget_warnings(store, &role, &budget, cap, &stream, Some(&stored), &others)?;
        // The new links before the row: the attachment rule then judges
        // the row as written against the links as they will stand,
        // whichever of the two the patch changed.
        store.in_transaction(|store| {
            if let Some(backend_ids) = &body.backend_ids {
                store.set_stream_backends(&stream.id, backend_ids)?;
            }
            store.update_stream(&stream)
        })?;
        let after = stream_to_response(&stream, store.list_backends_for_stream(&stream.id)?);
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
        let before = stream_to_response(&stream, store.list_backends_for_stream(&id)?);
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
