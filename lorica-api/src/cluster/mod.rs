//! Cluster registry endpoints (Story 9.3 AC #5/#10/#13/#14, plus the
//! token-minting surface Story 9.7's dialog needs). The fleet runtime
//! rule (store first, serialized refresh, then the session registry)
//! lives in [`runtime`]; the handlers only call it and audit.
//!
//! Role floors live in the authorize middleware: token endpoints and
//! every node mutation are SuperAdmin, reads are Viewer+.

mod runtime;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_cluster::{display_field_is_valid, leaf_spki_sha256, token, ClusterRequest, ControlPlane};
use lorica_config::models::{ClusterNode, JoinToken, NodeStatus, TokenState};
use serde::{Deserialize, Serialize};

use crate::db::db_blocking;
use crate::error::{json_data, json_data_with_status, ApiError};
use crate::middleware::auth::Session;
use crate::server::AppState;

pub use runtime::{
    publish_token_liveness, refresh_control_plane, revoke_node as revoke_node_fully,
    roster_from_nodes, ClusterRuntime, FollowerRuntime, RevokeOutcome,
};

/// Default join-token lifetime.
pub const DEFAULT_TOKEN_TTL_S: u64 = 3600;
/// Longest join-token lifetime an operator may request (the TTL cap
/// the PRD relies on: past it a token is an identity, not a window).
pub const MAX_TOKEN_TTL_S: u64 = 24 * 3600;

/// How long `POST /api/v1/cluster/leave` waits for the control plane
/// to acknowledge before wiping locally anyway.
const LEAVE_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

fn control_plane(state: &AppState) -> Result<Arc<ControlPlane>, ApiError> {
    match &state.cluster {
        ClusterRuntime::ControlPlane(control) => Ok(Arc::clone(control)),
        _ => Err(ApiError::Conflict(
            "this node is not a cluster control plane".into(),
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
    if let Some(name) = &body.node_name {
        if name.is_empty() || !display_field_is_valid(name) {
            return Err(ApiError::BadRequest(
                "node_name must be 1-64 bytes without control characters".into(),
            ));
        }
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

    let live = publish_token_liveness(&control, &state.store)
        .await
        .map_err(ApiError::Internal)?;
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
    publish_token_liveness(&control, &state.store)
        .await
        .map_err(ApiError::Internal)?;
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
}

fn node_responses(control: &ControlPlane, nodes: Vec<ClusterNode>) -> Vec<NodeResponse> {
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
                node,
            }
        })
        .collect()
}

/// GET /api/v1/cluster/nodes - the fleet roster (Viewer+).
pub async fn list_nodes(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let nodes = db_blocking(&state.store, |store| {
        store
            .list_cluster_nodes()
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
    Ok(json_data(node_responses(&control, nodes)))
}

/// GET /api/v1/cluster/nodes/{id} - one node (Viewer+).
pub async fn get_node(
    Extension(state): Extension<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let node = db_blocking(&state.store, move |store| {
        store
            .get_cluster_node(&id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("node not found".into()))
    })
    .await?;
    let mut responses = node_responses(&control, vec![node]);
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
    let node = db_blocking(&state.store, move |store| {
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
        store
            .get_cluster_node(&node_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::NotFound("node not found".into()))
    })
    .await?;
    refresh_control_plane(&control, &state.store)
        .await
        .map_err(ApiError::Internal)?;
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
    let mut responses = node_responses(&control, vec![node]);
    Ok(json_data(responses.remove(0)))
}

/// DELETE /api/v1/cluster/nodes/{id} - revoke (SuperAdmin, AC #7):
/// the serials go on the CRL, the acceptor is rebuilt, the live
/// session is ended synchronously. Idempotent: revoking an already
/// revoked node re-runs the CRL rebuild and the session kill, so a
/// half-applied first attempt can be retried; only an absent node is
/// 404.
pub async fn revoke_node(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let control = control_plane(&state)?;
    let outcome = revoke_node_fully(&control, &state.store, &id, Utc::now())
        .await
        .map_err(ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound("node not found".into()))?;
    tracing::warn!(
        node_id = %id,
        name = %outcome.node.name,
        newly_revoked = outcome.newly_revoked,
        session_ended = outcome.session_ended,
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
        })),
    )
    .await;
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
    /// Applied configuration generation (Story 9.4; 0 until then).
    pub applied_config_generation: i64,
    /// The roster (control plane).
    pub fleet: Vec<FleetEntry>,
}

/// GET /api/v1/cluster/status (Viewer+).
pub async fn get_status(
    Extension(state): Extension<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    let build_version = env!("CARGO_PKG_VERSION").to_string();
    let applied_config_generation = db_blocking(&state.store, |store| {
        store
            .cluster_config_generation()
            .map(|g| i64::try_from(g).unwrap_or(i64::MAX))
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await?;
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
            fleet: Vec::new(),
        },
        ClusterRuntime::ControlPlane(control) => {
            let nodes = db_blocking(&state.store, |store| {
                store
                    .list_cluster_nodes()
                    .map_err(|e| ApiError::Internal(e.to_string()))
            })
            .await?;
            let fleet = node_responses(control, nodes)
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
            ClusterStatusResponse {
                role: "control_plane",
                build_version,
                node_id: None,
                node_name: None,
                control_plane: None,
                connection_state: None,
                session_generation: None,
                applied_config_generation,
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
    let _ = follower.left.send(true);
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
