//! Cluster registry endpoints (Story 9.3 AC #5/#10/#13/#14, plus the
//! token-minting surface Story 9.7's dialog needs). The fleet runtime
//! rule (store first, serialized refresh, then the session registry)
//! lives in [`runtime`], a public module the control-plane binary
//! imports by name; the handlers here only call it and audit.
//!
//! Role floors live in the authorize middleware: token endpoints and
//! every node mutation are SuperAdmin, reads are Viewer+.

pub mod runtime;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_cluster::{leaf_spki_sha256, token, ClusterRequest, ControlPlane};
use lorica_config::models::{ClusterNode, JoinToken, NodeStatus, TokenState};
use serde::{Deserialize, Serialize};

use crate::cluster_telemetry_store::{FleetQuery, DEFAULT_PAGE, MAX_PAGE};
use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

pub use runtime::{ClusterRuntime, ControlPlaneRuntime, FollowerRuntime};

/// Default join-token lifetime.
pub const DEFAULT_TOKEN_TTL_S: u64 = 3600;
/// Longest join-token lifetime an operator may request (the TTL cap
/// the PRD relies on: past it a token is an identity, not a window).
pub const MAX_TOKEN_TTL_S: u64 = 24 * 3600;

/// How long `POST /api/v1/cluster/leave` waits for the control plane
/// to acknowledge before wiping locally anyway.
const LEAVE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// The control plane's runtime handle, or 409 on any other role.
fn control_plane_runtime(state: &AppState) -> Result<Arc<ControlPlaneRuntime>, ApiError> {
    match &state.cluster {
        ClusterRuntime::ControlPlane(runtime) => Ok(Arc::clone(runtime)),
        _ => Err(ApiError::Conflict(
            "this node is not a cluster control plane".into(),
        )),
    }
}

/// The transport crate's fleet handle, for the endpoints that need
/// only the roster, the sessions or the CA.
fn control_plane(state: &AppState) -> Result<Arc<ControlPlane>, ApiError> {
    Ok(Arc::clone(&control_plane_runtime(state)?.control))
}

/// The follower's runtime handle, or 409 on any other role.
fn follower_runtime(state: &AppState) -> Result<Arc<FollowerRuntime>, ApiError> {
    match &state.cluster {
        ClusterRuntime::Follower(follower) => Ok(Arc::clone(follower)),
        _ => Err(ApiError::Conflict(
            "this node is not a cluster follower".into(),
        )),
    }
}

// ---- Tokens ----

/// Body of `POST /api/v1/cluster/tokens`.
#[derive(Debug, Deserialize)]
pub struct MintTokenRequest {
    /// Lifetime in seconds (default 3600, max 86400).
    pub ttl_seconds: Option<u64>,
    /// When set, only a node presenting exactly this name may redeem.
    pub node_name: Option<String>,
    /// When set, only a connection from this CIDR may redeem.
    pub source_cidr: Option<String>,
}

/// Payload of `POST /api/v1/cluster/tokens`: the token, shown once.
#[derive(Debug, Serialize)]
pub struct MintedTokenResponse {
    /// The full token. Shown once; never stored, never logged.
    pub token: String,
    /// The lookup half (what the token list shows).
    pub public_id: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
    /// The name the redeeming node must present, if bound.
    pub bound_node_name: Option<String>,
    /// The CIDR the redeeming connection must come from, if bound.
    pub bound_source_cidr: Option<String>,
}

/// POST /api/v1/cluster/tokens - mint a join token (SuperAdmin).
pub async fn mint_token(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<MintTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let ttl = body.ttl_seconds.unwrap_or(DEFAULT_TOKEN_TTL_S);
    if ttl == 0 || ttl > MAX_TOKEN_TTL_S {
        return Err(ApiError::BadRequest(format!(
            "ttl_seconds must be between 1 and {MAX_TOKEN_TTL_S}"
        )));
    }
    // The name binding is MANDATORY (Story 9.5 QA, decision D15).
    //
    // A route's `node_selector` names nodes, and that name decides who
    // receives a private key. The name is written at enrollment from a
    // value the JOINING node supplies, so an unbound token lets its
    // holder claim any name no node currently holds, including one a
    // route already names because the operator wrote the routing
    // before provisioning the machine. Binding the token is what makes
    // the claim the operator's decision rather than the joiner's.
    //
    // This is Consul's node identity: the token, not the agent, decides
    // which name may be registered. It costs the operator one argument
    // and removes a whole class of impersonation.
    let Some(name) = &body.node_name else {
        return Err(ApiError::BadRequest(
            "node_name is required: a join token must name the node it may enrol, because that              name is what route selectors resolve against"
                .into(),
        ));
    };
    // The same alphabet a `node_selector` entry must satisfy. These
    // used to differ, so a node could register a name no selector could
    // ever reference (uppercase, spaces, homoglyphs), which made the
    // two sides of one string disagree.
    if let Err(reason) = lorica_config::models::validate_node_selector_names(
        std::slice::from_ref(name),
    ) {
        return Err(ApiError::BadRequest(format!("node_name: {reason}")));
    }
    if let Some(cidr) = &body.source_cidr {
        cidr.parse::<ipnet::IpNet>()
            .map_err(|e| ApiError::BadRequest(format!("source_cidr: {e}")))?;
    }
    let pin = leaf_spki_sha256(&control.leaf_cert_pem)
        .map_err(|e| ApiError::Internal(format!("control-plane leaf: {e}")))?;

    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(i64::try_from(ttl).unwrap_or(i64::MAX));
    let created_by = session.username.clone();
    let bound_node_name = body.node_name.clone();
    let bound_source_cidr = body.source_cidr.clone();
    let minted = db_blocking(&state.store, move |store| {
        let key = store
            .token_hmac_key()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let minted = token::mint(&key, &pin).map_err(|e| ApiError::Internal(e.to_string()))?;
        store
            .create_join_token(&JoinToken {
                public_id: minted.public_id.clone(),
                secret_hmac: minted.secret_hmac.clone(),
                state: TokenState::Unused,
                created_at: now,
                expires_at,
                created_by,
                bound_node_name,
                bound_source_cidr,
                burned_at: None,
                burned_by_node_id: None,
            })
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>(minted)
    })
    .await?;

    let live = runtime::publish_token_liveness(&control, &state.store).await?;
    tracing::warn!(
        public_id = %minted.public_id,
        live_tokens = live,
        expires_at = %expires_at.to_rfc3339(),
        "join token minted; enrollment window open"
    );

    let response = MintedTokenResponse {
        token: minted.token,
        public_id: minted.public_id,
        expires_at: expires_at.to_rfc3339(),
        bound_node_name: body.node_name,
        bound_source_cidr: body.source_cidr,
    };
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    // The audit payload carries the public half and the bindings,
    // never the token.
    let after = serde_json::json!({
        "public_id": response.public_id,
        "expires_at": response.expires_at,
        "bound_node_name": response.bound_node_name,
        "bound_source_cidr": response.bound_source_cidr,
    });
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.token.mint",
        ("cluster_token", &response.public_id),
        None,
        Some(&after),
    )
    .await;
    Ok(json_data_with_status(StatusCode::CREATED, response))
}

/// GET /api/v1/cluster/tokens - list join tokens (SuperAdmin; the
/// secret never exists to be shown).
pub async fn list_tokens(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    control_plane(&state)?;
    let tokens = db_blocking(&state.store, |store| {
        store
            .list_join_tokens()
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    Ok(json_data(tokens))
}

/// DELETE /api/v1/cluster/tokens/{public_id} - withdraw an unused
/// token (SuperAdmin).
pub async fn revoke_token(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(public_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let id = public_id.clone();
    let revoked = db_blocking(&state.store, move |store| {
        store
            .revoke_join_token(&id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    if !revoked {
        return Err(ApiError::NotFound(
            "no unused token with this public id".into(),
        ));
    }
    runtime::publish_token_liveness(&control, &state.store).await?;
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.token.revoke",
        ("cluster_token", &public_id),
        None,
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- Nodes ----

/// JSON shape of a registered node: the registry row plus the live
/// session facts.
#[derive(Debug, Serialize)]
pub struct NodeResponse {
    /// The registry row.
    #[serde(flatten)]
    pub node: ClusterNode,
    /// Whether the node holds an operational session right now.
    pub connected: bool,
    /// The live session's peer address, when connected.
    pub session_peer: Option<String>,
    /// Unix seconds of the live session's last activity.
    pub session_last_seen_unix: Option<u64>,
    /// Hostnames whose routes name this node in their selector, and
    /// whose certificate private keys it therefore receives (Story 9.5
    /// QA, decision D15).
    ///
    /// Present so activating a node is a decision rather than a
    /// button: the name is chosen by the joining machine, so an
    /// operator approving a `pending` node has to be able to see that
    /// a route is already waiting for that name with a private key
    /// attached. Fleet-wide routes are excluded; they apply to every
    /// node and would bury the entries that need thought.
    pub selected_for_hostnames: Vec<String>,
}

fn node_responses(
    control: &ControlPlane,
    nodes: Vec<ClusterNode>,
    selected: &HashMap<String, Vec<String>>,
) -> Vec<NodeResponse> {
    let live: HashMap<String, (String, u64)> = control
        .sessions
        .snapshot()
        .into_iter()
        .map(|s| (s.node_id, (s.peer_addr.to_string(), s.last_seen_unix)))
        .collect();
    nodes
        .into_iter()
        .map(|node| {
            let session = live.get(&node.node_id).cloned();
            NodeResponse {
                connected: session.is_some(),
                session_peer: session.as_ref().map(|(peer, _)| peer.clone()),
                session_last_seen_unix: session.map(|(_, seen)| seen),
                selected_for_hostnames: selected.get(&node.name).cloned().unwrap_or_default(),
                node,
            }
        })
        .collect()
}

/// Which hostnames each of these node NAMES is selected for, resolved
/// in one store pass rather than one per node.
fn selected_hostnames(
    store: &lorica_config::ConfigStore,
    nodes: &[ClusterNode],
) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for node in nodes {
        if out.contains_key(&node.name) {
            continue;
        }
        // A read failure here degrades the review to "no entries
        // known" rather than failing the roster: an operator who
        // cannot list the fleet is worse off than one whose advisory
        // column is empty.
        let hostnames = store
            .hostnames_selecting_node_name(&node.name)
            .unwrap_or_default();
        out.insert(node.name.clone(), hostnames);
    }
    out
}

/// GET /api/v1/cluster/nodes - the fleet roster (Viewer+).
pub async fn list_nodes(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let (nodes, selected) = db_blocking(&state.store, |store| {
        let nodes = store
            .list_cluster_nodes()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let selected = selected_hostnames(store, &nodes);
        Ok::<_, ApiError>((nodes, selected))
    })
    .await?;
    Ok(json_data(node_responses(&control, nodes, &selected)))
}

/// GET /api/v1/cluster/nodes/{id} - one node (Viewer+).
pub async fn get_node(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let (node, selected) = db_blocking(&state.store, move |store| {
        let node = store
            .get_cluster_node(&id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("node not found".into()))?;
        let selected = selected_hostnames(store, std::slice::from_ref(&node));
        Ok::<_, ApiError>((node, selected))
    })
    .await?;
    let mut responses = node_responses(&control, vec![node], &selected);
    Ok(json_data(responses.remove(0)))
}

/// POST /api/v1/cluster/nodes/{id}/activate - `Pending` -> `Active`
/// (SuperAdmin, AC #5).
pub async fn activate_node(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let node_id = id.clone();
    let (node, selected) = db_blocking(&state.store, move |store| {
        let before = store
            .get_cluster_node(&node_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("node not found".into()))?;
        if before.status != NodeStatus::Pending {
            return Err(ApiError::Conflict(format!(
                "node is {}, only a pending node can be activated",
                before.status.as_str()
            )));
        }
        store
            .activate_cluster_node(&node_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let node = store
            .get_cluster_node(&node_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("node not found".into()))?;
        let selected = selected_hostnames(store, std::slice::from_ref(&node));
        Ok::<_, ApiError>((node, selected))
    })
    .await?;
    runtime::refresh_control_plane(&control, &state.store).await?;
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.node.activate",
        ("cluster_node", &id),
        None,
        Some(&serde_json::json!({ "status": "active", "name": node.name })),
    )
    .await;
    let mut responses = node_responses(&control, vec![node], &selected);
    Ok(json_data(responses.remove(0)))
}

/// DELETE /api/v1/cluster/nodes/{id} - revoke (SuperAdmin, AC #7):
/// the serials go on the CRL, the acceptor is rebuilt, the live
/// session is ended synchronously. Idempotent: revoking an already
/// revoked node re-runs the CRL rebuild and the session kill, so a
/// half-applied first attempt can be retried; only an absent node is
/// 404. A refresh failure is audited (the row flip and the session
/// kill happened) and then answered 500, so the operator retries.
pub async fn revoke_node(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let outcome = runtime::revoke_node(&control, &state.store, &id, Utc::now())
        .await?
        .ok_or_else(|| ApiError::NotFound("node not found".into()))?;
    tracing::warn!(
        node_id = %id,
        name = %outcome.node.name,
        newly_revoked = outcome.newly_revoked,
        session_ended = outcome.session_ended,
        refresh_error = outcome.refresh_error.as_ref().map(|e| e.to_string()).as_deref().unwrap_or("-"),
        "cluster node revoked"
    );
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.node.revoke",
        ("cluster_node", &id),
        Some(&serde_json::json!({
            "status": outcome.node.status.as_str(),
            "name": outcome.node.name,
        })),
        Some(&serde_json::json!({
            "status": "revoked",
            "newly_revoked": outcome.newly_revoked,
            "session_ended": outcome.session_ended,
            "refresh_error": outcome.refresh_error.as_ref().map(|e| e.to_string()),
        })),
    )
    .await;
    if let Some(refresh_error) = outcome.refresh_error {
        return Err(refresh_error.into());
    }
    Ok(StatusCode::NO_CONTENT)
}

// ---- Status and leave ----

/// One roster line of `GET /api/v1/cluster/status` on a control plane.
#[derive(Debug, Serialize)]
pub struct FleetEntry {
    /// The node id.
    pub node_id: String,
    /// Display name.
    pub name: String,
    /// Lifecycle state.
    pub status: NodeStatus,
    /// Whether a session is live.
    pub connected: bool,
    /// Last persisted or live activity, RFC 3339.
    pub last_seen_at: Option<String>,
    /// Reported build version.
    pub version: String,
    /// Applied configuration generation (Story 9.4).
    pub applied_config_generation: i64,
}

/// Payload of `GET /api/v1/cluster/status` (AC #14).
#[derive(Debug, Serialize)]
pub struct ClusterStatusResponse {
    /// `standalone`, `control_plane` or `follower`.
    pub role: &'static str,
    /// This process's build version.
    pub build_version: String,
    /// This node's id (follower).
    pub node_id: Option<String>,
    /// This node's name (follower).
    pub node_name: Option<String>,
    /// The control plane dialed (follower).
    pub control_plane: Option<String>,
    /// `connected` / `disconnected` (follower).
    pub connection_state: Option<&'static str>,
    /// The live session's generation (follower).
    pub session_generation: Option<u64>,
    /// Applied configuration generation (Story 9.4).
    pub applied_config_generation: i64,
    /// Canonical hash of the applied configuration (Story 9.4).
    pub applied_config_hash: String,
    /// End of the break-glass window on a follower, RFC 3339 (Story
    /// 9.4 AC #11); `None` when closed. The dashboard banners it.
    pub break_glass_until: Option<String>,
    /// The roster (control plane).
    pub fleet: Vec<FleetEntry>,
}

/// GET /api/v1/cluster/status (Viewer+).
pub async fn get_status(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let build_version = env!("CARGO_PKG_VERSION").to_string();
    // A control plane reports the generation it OWNS; a follower and a
    // standalone node report what they last applied.
    let (applied_config_generation, applied_config_hash) = db_blocking(&state.store, |store| {
        let generation = store
            .cluster_config_generation()
            .map(|g| i64::try_from(g).unwrap_or(i64::MAX))
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let (applied, hash) = store
            .cluster_applied_config()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>((generation, applied, hash))
    })
    .await
    .map(|(generation, applied, hash)| match applied {
        0 => (generation, hash),
        applied => (i64::try_from(applied).unwrap_or(i64::MAX), hash),
    })?;
    let response = match &state.cluster {
        ClusterRuntime::Standalone => ClusterStatusResponse {
            role: "standalone",
            build_version,
            node_id: None,
            node_name: None,
            control_plane: None,
            connection_state: None,
            session_generation: None,
            applied_config_generation,
            applied_config_hash,
            break_glass_until: None,
            fleet: Vec::new(),
        },
        ClusterRuntime::ControlPlane(runtime) => {
            let control = &runtime.control;
            let nodes = db_blocking(&state.store, |store| {
                store
                    .list_cluster_nodes()
                    .map_err(|e| ApiError::Internal(e.to_string()))
            })
            .await?;
            // `FleetEntry` carries no selector column, so the status
            // summary skips the per-node store pass the roster does.
            let fleet = node_responses(control, nodes, &HashMap::new())
                .into_iter()
                .map(|n| FleetEntry {
                    node_id: n.node.node_id,
                    name: n.node.name,
                    status: n.node.status,
                    connected: n.connected,
                    last_seen_at: n
                        .session_last_seen_unix
                        .and_then(|s| DateTime::<Utc>::from_timestamp(i64::try_from(s).ok()?, 0))
                        .or(n.node.last_seen_at)
                        .map(|t| t.to_rfc3339()),
                    version: n.node.version,
                    applied_config_generation: n.node.applied_config_generation,
                })
                .collect();
            let version = control.config_version();
            ClusterStatusResponse {
                role: "control_plane",
                build_version,
                node_id: None,
                node_name: None,
                control_plane: None,
                connection_state: None,
                session_generation: None,
                applied_config_generation: i64::try_from(version.generation).unwrap_or(i64::MAX),
                applied_config_hash: version.hash,
                break_glass_until: None,
                fleet,
            }
        }
        ClusterRuntime::Follower(follower) => {
            let session = follower.connection.current();
            ClusterStatusResponse {
                role: "follower",
                build_version,
                node_id: Some(follower.node_id.clone()),
                node_name: Some(follower.node_name.clone()),
                control_plane: Some(follower.control_plane.clone()),
                connection_state: Some(if session.is_some() {
                    "connected"
                } else {
                    "disconnected"
                }),
                session_generation: session.map(|s| s.generation),
                applied_config_generation,
                applied_config_hash,
                break_glass_until: follower.break_glass_until().map(|t| t.to_rfc3339()),
                fleet: Vec::new(),
            }
        }
    };
    Ok(json_data(response))
}

/// Payload of `POST /api/v1/cluster/leave`.
#[derive(Debug, Serialize)]
pub struct LeaveResponse {
    /// The node that left.
    pub node_id: String,
    /// Whether the control plane acknowledged the leave (and so
    /// revoked, audited and alerted on its side). When `false`, the
    /// operator must revoke the node on the control plane.
    pub control_plane_notified: bool,
}

/// POST /api/v1/cluster/leave - leave the fleet (SuperAdmin, AC #13,
/// follower only): tell the control plane over the live session, wipe
/// the local identity, audit.
pub async fn leave(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<impl IntoResponse, ApiError> {
    let ClusterRuntime::Follower(follower) = &state.cluster else {
        return Err(ApiError::Conflict(
            "this node is not a cluster follower".into(),
        ));
    };
    let notified = match follower.connection.current() {
        Some(live) => {
            match tokio::time::timeout(
                LEAVE_NOTIFY_TIMEOUT,
                live.endpoint
                    .request(ClusterRequest::leave(), LEAVE_NOTIFY_TIMEOUT),
            )
            .await
            {
                Ok(Ok(response)) => response.cluster_status() == lorica_cluster::ClusterStatus::Ok,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "leave: control plane did not acknowledge");
                    false
                }
                Err(_) => {
                    tracing::warn!("leave: control plane did not answer in time");
                    false
                }
            }
        }
        None => false,
    };
    // Wipe locally regardless: a SuperAdmin decided this node leaves.
    // Replicated certificate private keys arrive with Story 9.5,
    // whose provenance column extends this wipe.
    let wiped = db_blocking(&state.store, |store| {
        store
            .delete_cluster_identity()
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    // `send_replace`, not `send`: a watch send is a no-op once every
    // receiver is gone, and the value here is authoritative state the
    // API reads back, not only a wake-up for a listener.
    follower.left.send_replace(true);
    tracing::warn!(
        node_id = %follower.node_id,
        control_plane_notified = notified,
        identity_wiped = wiped,
        "this node left the fleet"
    );
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.node.leave",
        ("cluster_node", &follower.node_id),
        None,
        Some(&serde_json::json!({
            "control_plane_notified": notified,
            "identity_wiped": wiped,
        })),
    )
    .await;
    Ok(json_data(LeaveResponse {
        node_id: follower.node_id.clone(),
        control_plane_notified: notified,
    }))
}

// ---- Configuration replication (Story 9.4) ----

/// Payload of `GET /api/v1/cluster/replication` (AC #8): the last
/// completed round plus the generation in flight, so the dashboard can
/// poll the outcome of a mutation instead of the handler blocking on
/// fleet latency.
#[derive(Debug, Serialize)]
pub struct ReplicationStatus {
    /// The control plane's current configuration generation.
    pub current_generation: u64,
    /// Canonical hash of the current configuration.
    pub current_hash: String,
    /// The generation being replicated right now, if any.
    pub in_flight: Option<u64>,
    /// The last completed round, `None` before the first one.
    pub last: Option<ReplicationRoundResponse>,
}

/// One completed replication round, as the API renders it.
#[derive(Debug, Serialize)]
pub struct ReplicationRoundResponse {
    /// The generation the round replicated.
    pub generation: u64,
    /// Canonical hash of that generation.
    pub hash: String,
    /// Node ids the round addressed.
    pub targets: Vec<String>,
    /// Nodes that staged the generation.
    pub prepared: Vec<String>,
    /// Nodes evicted on a transport failure, with the reason: the
    /// commit proceeded without them and they converge by pull (AC #5).
    pub evicted: Vec<NodeOutcome>,
    /// Nodes that refused the blob semantically; a single one aborts
    /// the round fleet-wide (AC #5).
    pub rejected: Vec<NodeOutcome>,
    /// Nodes that applied the generation.
    pub committed: Vec<String>,
    /// Nodes whose Commit failed after others committed: the fleet is
    /// split until the next heartbeat reconciles it (AC #6).
    pub commit_failed: Vec<NodeOutcome>,
    /// Nodes excluded because the coordinator quarantined them.
    pub skipped_quarantined: Vec<String>,
    /// Nodes excluded because they are in a break-glass window.
    pub skipped_break_glass: Vec<String>,
    /// Whether a semantic rejection aborted the round.
    pub aborted: bool,
    /// Whether some nodes committed and others did not (AC #6).
    pub split_fleet: bool,
}

/// A per-node failure with its reason.
#[derive(Debug, Serialize)]
pub struct NodeOutcome {
    /// The node id.
    pub node_id: String,
    /// Why it failed, for the operator's journal and the dashboard.
    pub reason: String,
}

impl From<lorica_cluster::ReplicationReport> for ReplicationRoundResponse {
    fn from(report: lorica_cluster::ReplicationReport) -> Self {
        let outcomes = |pairs: Vec<(String, String)>| -> Vec<NodeOutcome> {
            pairs
                .into_iter()
                .map(|(node_id, reason)| NodeOutcome { node_id, reason })
                .collect()
        };
        Self {
            split_fleet: !report.committed.is_empty() && !report.commit_failed.is_empty(),
            generation: report.generation,
            hash: report.hash,
            targets: report.targets,
            prepared: report.prepared,
            evicted: outcomes(report.evicted),
            rejected: outcomes(report.rejected),
            committed: report.committed,
            commit_failed: outcomes(report.commit_failed),
            skipped_quarantined: report.skipped_quarantined,
            skipped_break_glass: report.skipped_break_glass,
            aborted: report.aborted,
        }
    }
}

/// GET /api/v1/cluster/replication - the last replication round and
/// the generation in flight (Viewer+, control plane only).
pub async fn get_replication(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let version = control.config_version();
    Ok(json_data(ReplicationStatus {
        current_generation: version.generation,
        current_hash: version.hash,
        in_flight: control.replication.in_flight(),
        last: control.replication.last_report().map(Into::into),
    }))
}

/// GET /api/v1/cluster/drift - nodes whose applied configuration
/// differs from the current one, with the age of the divergence
/// (Viewer+, control plane only, AC #12).
pub async fn get_drift(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let runtime = control_plane_runtime(&state)?;
    let report = runtime::drift_report(&runtime, &state.store).await?;
    Ok(json_data(report))
}

/// Query string for the two fan-in endpoints (Story 9.6 AC #9).
#[derive(Debug, Deserialize, Default)]
pub struct FleetLogsQuery {
    /// Restrict to one node id.
    pub node: Option<String>,
    /// Substring match on the host (logs) or route hostname (WAF).
    pub route: Option<String>,
    /// Exact WAF rule category. Ignored by the access-log endpoint,
    /// which has no such column.
    pub category: Option<String>,
    /// Inclusive lower bound on the origin timestamp, RFC 3339.
    pub from: Option<String>,
    /// Inclusive upper bound on the origin timestamp, RFC 3339.
    pub to: Option<String>,
    /// Cursor: return rows with an id strictly below this one. Take
    /// it from `next_cursor` of the previous page.
    pub before_id: Option<i64>,
    /// Rows per page.
    pub limit: Option<u32>,
}

impl FleetLogsQuery {
    fn to_store_query(&self) -> FleetQuery {
        FleetQuery {
            node_id: self.node.clone(),
            route: self.route.clone(),
            category: self.category.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            before_id: self.before_id,
            limit: self.limit.unwrap_or(0),
        }
    }
}

/// One page of fanned-in rows.
///
/// There is no total, deliberately (AC #9): the single-node logs
/// query runs `SELECT COUNT(*)` on every page, and on an aggregated
/// table that is a full scan per page under the store lock, so the
/// dashboard would stall the ingest writer. `next_cursor` is `None`
/// on the last page.
#[derive(Debug, Serialize)]
pub struct FleetPage<T> {
    /// The rows, newest first.
    pub rows: Vec<T>,
    /// Pass as `before_id` to get the next page; `None` when this is
    /// the last one.
    pub next_cursor: Option<i64>,
}

/// GET /api/v1/cluster/logs - the fleet's access logs (Viewer+,
/// Story 9.6 AC #9).
///
/// Control plane only: a follower holds its own rows and serves them
/// through `/api/v1/logs`.
pub async fn fleet_logs(
    Extension(state): Extension<AppState>,
    Query(params): Query<FleetLogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let runtime = control_plane_runtime(&state)?;
    let telemetry = runtime.telemetry.clone().ok_or_else(|| {
        ApiError::Internal("the cluster telemetry database is not open".into())
    })?;
    let query = params.to_store_query();
    let rows = tokio::task::spawn_blocking(move || telemetry.query_access(&query))
        .await
        .map_err(|e| ApiError::Internal(format!("fleet log query task failed: {e}")))?
        .map_err(ApiError::Internal)?;
    let next_cursor = next_cursor(rows.len(), params.limit, rows.last().map(|r| r.id));
    Ok(json_data(FleetPage { rows, next_cursor }))
}

/// GET /api/v1/cluster/waf-events - the fleet's WAF events (Viewer+,
/// Story 9.6 AC #9).
pub async fn fleet_waf_events(
    Extension(state): Extension<AppState>,
    Query(params): Query<FleetLogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let runtime = control_plane_runtime(&state)?;
    let telemetry = runtime.telemetry.clone().ok_or_else(|| {
        ApiError::Internal("the cluster telemetry database is not open".into())
    })?;
    let query = params.to_store_query();
    let rows = tokio::task::spawn_blocking(move || telemetry.query_waf(&query))
        .await
        .map_err(|e| ApiError::Internal(format!("fleet WAF query task failed: {e}")))?
        .map_err(ApiError::Internal)?;
    let next_cursor = next_cursor(rows.len(), params.limit, rows.last().map(|r| r.id));
    Ok(json_data(FleetPage { rows, next_cursor }))
}

/// The cursor for the next page, or `None` when this page was short.
///
/// A short page means the table had nothing more to give, so there is
/// no need to spend a round trip discovering that.
fn next_cursor(returned: usize, requested: Option<u32>, last_id: Option<i64>) -> Option<i64> {
    let page = match requested {
        None | Some(0) => DEFAULT_PAGE,
        Some(n) => n.min(MAX_PAGE),
    };
    (returned as u32 >= page).then_some(last_id).flatten()
}

/// GET /api/v1/cluster/bans - every node's live bans (Viewer+,
/// control plane, Story 9.6 AC #10).
///
/// A snapshot of what each node last reported, not a history: bans
/// are in-memory state on each node, so this is lossy across a node
/// restart by construction (decision D3).
pub async fn fleet_bans(
    Extension(state): Extension<AppState>,
    Query(params): Query<FleetLogsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let runtime = control_plane_runtime(&state)?;
    let telemetry = runtime.telemetry.clone().ok_or_else(|| {
        ApiError::Internal("the cluster telemetry database is not open".into())
    })?;
    let node = params.node.clone();
    let rows = tokio::task::spawn_blocking(move || telemetry.query_bans(node.as_deref()))
        .await
        .map_err(|e| ApiError::Internal(format!("fleet ban query task failed: {e}")))?
        .map_err(ApiError::Internal)?;
    Ok(json_data(rows))
}

/// Body of `POST /api/v1/cluster/bans`.
#[derive(Debug, Deserialize)]
pub struct FleetBanRequest {
    /// The client address to ban across the fleet.
    pub client_ip: String,
    /// How long the ban lasts, in seconds.
    pub duration_s: u64,
}

/// Which nodes took a fleet-wide ban.
#[derive(Debug, Serialize)]
pub struct FleetBanResponse {
    /// Nodes now enforcing it.
    pub applied: Vec<String>,
    /// Nodes that did not answer. They do NOT receive it later: a ban
    /// has no convergence path, unlike configuration and keys.
    pub unreachable: Vec<String>,
}

/// Longest a fleet-wide ban may last: a day.
///
/// Past that it is a routing or firewall decision, not an incident
/// response, and an operator who wants it permanent should say so
/// somewhere that survives a restart. The data-plane ban map does
/// not.
pub const MAX_FLEET_BAN_DURATION_S: u64 = 24 * 3600;

/// POST /api/v1/cluster/bans - ban a client across the fleet
/// (SuperAdmin, Story 9.6 AC #10).
///
/// Fleet-wide by definition and NOT need-to-know: the operator
/// decided this client should reach nothing, so it goes to every
/// active node rather than to a resolved subset.
///
/// Automatic per-node auto-ban is deliberately not replicated. It is
/// a local reflex to local traffic, and replicating it would turn one
/// node's false positive into a fleet-wide outage for that client.
pub async fn fleet_ban(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<FleetBanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    // The address becomes a key in every node's data-plane ban map,
    // which the request path consults on every request. A ban on
    // something that is not an address could never match a client and
    // would sit there until it expired.
    if body.client_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ApiError::BadRequest(
            "client_ip must be an IP address".into(),
        ));
    }
    if body.duration_s == 0 || body.duration_s > MAX_FLEET_BAN_DURATION_S {
        return Err(ApiError::BadRequest(format!(
            "duration_s must be between 1 and {MAX_FLEET_BAN_DURATION_S}"
        )));
    }
    let (applied, unreachable) = control
        .push_ban(&body.client_ip, body.duration_s, "manual")
        .await;
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.ban.fleet",
        ("cluster_ban", &body.client_ip),
        None,
        Some(&serde_json::json!({
            "duration_s": body.duration_s,
            "applied": applied,
            "unreachable": unreachable,
        })),
    )
    .await;
    tracing::warn!(
        client_ip = %body.client_ip,
        duration_s = body.duration_s,
        applied = applied.len(),
        unreachable = unreachable.len(),
        "fleet-wide ban issued"
    );
    Ok(json_data(FleetBanResponse {
        applied,
        unreachable,
    }))
}

/// Body of `POST /api/v1/cluster/break-glass`.
#[derive(Debug, Deserialize)]
pub struct BreakGlassRequest {
    /// How long local mutations stay allowed, in seconds (max 24 h).
    pub duration_s: u64,
}

/// Payload of every break-glass endpoint (AC #11).
#[derive(Debug, Serialize)]
pub struct BreakGlassResponse {
    /// Whether a window is open right now.
    pub active: bool,
    /// When the window ends, RFC 3339; `None` when closed.
    pub until: Option<String>,
    /// Seconds remaining, `None` when closed.
    pub remaining_s: Option<i64>,
}

fn break_glass_response(follower: &FollowerRuntime) -> BreakGlassResponse {
    match follower.break_glass_until() {
        Some(until) => BreakGlassResponse {
            active: true,
            until: Some(until.to_rfc3339()),
            remaining_s: Some((until - Utc::now()).num_seconds().max(0)),
        },
        None => BreakGlassResponse {
            active: false,
            until: None,
            remaining_s: None,
        },
    }
}

/// GET /api/v1/cluster/break-glass - the current window (SuperAdmin,
/// follower only).
pub async fn get_break_glass(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let follower = follower_runtime(&state)?;
    Ok(json_data(break_glass_response(&follower)))
}

/// POST /api/v1/cluster/break-glass - re-enable local mutations for a
/// bounded window (SuperAdmin, follower only, AC #11). Loudly logged
/// and audited: this is the lever that lets an operator act on an edge
/// while the control plane is unreachable, and everything it changes
/// is reconciled away when the window ends.
pub async fn open_break_glass(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Json(body): Json<BreakGlassRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let follower = follower_runtime(&state)?;
    if body.duration_s == 0 || body.duration_s > runtime::MAX_BREAK_GLASS_SECS {
        return Err(ApiError::BadRequest(format!(
            "duration_s must be between 1 and {}",
            runtime::MAX_BREAK_GLASS_SECS
        )));
    }
    let until = Utc::now() + chrono::Duration::seconds(i64::try_from(body.duration_s).unwrap_or(0));
    // Opening the window INVALIDATES what this node reports as applied.
    //
    // Local edits made inside a window never touch the applied marker
    // (only a replica apply writes it), so without this the node would
    // still report the generation it last replicated, the control
    // plane's "is this node behind" check would say no, and the
    // divergent configuration would stand forever while the drift view
    // reported the node in sync. Clearing the hash makes the node
    // unconditionally behind, so the first heartbeat after the window
    // closes pulls the fleet's configuration and reconciles the edits
    // away, which is what AC #11 promises.
    db_blocking(&state.store, move |store| {
        store
            .set_cluster_break_glass_until(Some(until))
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        store
            .set_cluster_applied_config(0, "")
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    {
        let mut applied = follower
            .applied
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        applied.generation = 0;
        applied.hash = String::new();
    }
    follower.break_glass.send_replace(Some(until));
    tracing::warn!(
        node_id = %follower.node_id,
        control_plane = %follower.control_plane,
        until = %until.to_rfc3339(),
        operator = %session.username,
        "cluster break-glass OPEN: local configuration mutations are allowed on this follower \
         until the window ends; the control plane reconciles them away afterwards"
    );
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.break_glass.open",
        ("cluster_node", &follower.node_id),
        None,
        Some(&serde_json::json!({
            "until": until.to_rfc3339(),
            "duration_s": body.duration_s,
        })),
    )
    .await;
    Ok(json_data(break_glass_response(&follower)))
}

/// DELETE /api/v1/cluster/break-glass - close the window now
/// (SuperAdmin, follower only). The follower pulls the current
/// generation and applies it, so local edits are reconciled away.
pub async fn close_break_glass(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
) -> Result<impl IntoResponse, ApiError> {
    let follower = follower_runtime(&state)?;
    db_blocking(&state.store, |store| {
        store
            .set_cluster_break_glass_until(None)
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    follower.break_glass.send_replace(None);
    tracing::warn!(
        node_id = %follower.node_id,
        operator = %session.username,
        "cluster break-glass CLOSED; reconciling with the control plane"
    );
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "cluster.break_glass.close",
        ("cluster_node", &follower.node_id),
        None,
        None,
    )
    .await;
    Ok(json_data(break_glass_response(&follower)))
}
