//! The fleet runtime layer (Story 9.3): what this process is in the
//! fleet, and the rule "the store is the truth; the roster, the
//! fleet-size hint and the CRL-backed acceptor are derived from it".
//!
//! No HTTP here. The control-plane binary and the API handlers both
//! act through these functions, so a mutation always goes store
//! first, then one serialized refresh, then the session registry.
//! Failures are typed ([`ClusterRuntimeError`]) so a caller can tell
//! "the store is unavailable" from "the acceptor could not be
//! rebuilt" without parsing a message.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lorica_cluster::{
    ClusterConnection, ClusterTlsError, ControlPlane, NodeIdentity, NodeState, RevokedEntry,
};
use lorica_config::models::{ClusterNode, NodeStatus};
use lorica_config::{ConfigError, ConfigStore};
use tokio::sync::{watch, Mutex};

use crate::error::ApiError;

/// Why a fleet runtime operation failed.
#[derive(Debug, thiserror::Error)]
pub enum ClusterRuntimeError {
    /// The configuration store refused or failed the read or write.
    #[error("cluster registry: {0}")]
    Store(#[from] ConfigError),
    /// The store task could not be joined (the blocking pool is gone).
    #[error("cluster registry: {0}")]
    StoreTask(String),
    /// The CRL could not be minted or the operational TLS acceptor
    /// could not be rebuilt over it; the roster was still swapped.
    #[error("acceptor rebuild: {0}")]
    Acceptor(#[from] ClusterTlsError),
}

impl From<ClusterRuntimeError> for ApiError {
    fn from(err: ClusterRuntimeError) -> Self {
        match err {
            ClusterRuntimeError::Store(inner) => inner.into(),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

/// Run a pure-store closure and keep its error typed: `db_blocking`
/// collapses everything into `ApiError`, which this layer must not
/// name on its way out.
async fn store_op<T, F>(
    store: &Arc<Mutex<ConfigStore>>,
    f: F,
) -> Result<T, ClusterRuntimeError>
where
    F: FnOnce(&mut ConfigStore) -> Result<T, ConfigError> + Send + 'static,
    T: Send + 'static,
{
    let mut guard = Arc::clone(store).lock_owned().await;
    tokio::task::spawn_blocking(move || f(&mut guard))
        .await
        .map_err(|e| ClusterRuntimeError::StoreTask(format!("store task join failed: {e}")))?
        .map_err(ClusterRuntimeError::Store)
}

/// What this process is in the fleet, as the API sees it.
#[derive(Clone)]
pub enum ClusterRuntime {
    /// No cluster role (the default install).
    Standalone,
    /// This process serves the cluster plane.
    ControlPlane(Arc<ControlPlane>),
    /// This process dials a control plane.
    Follower(Arc<FollowerRuntime>),
}

/// The follower side's live handles.
pub struct FollowerRuntime {
    /// This node's server-assigned id.
    pub node_id: String,
    /// This node's display name.
    pub node_name: String,
    /// The control plane's `host:port`.
    pub control_plane: String,
    /// The dialer's connection slot.
    pub connection: ClusterConnection,
    /// Flipped to `true` by `POST /api/v1/cluster/leave`; the follower
    /// runtime stops dialing when it sees it.
    pub left: watch::Sender<bool>,
}

impl ClusterRuntime {
    /// `snake_case` role name for responses.
    pub fn role_name(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::ControlPlane(_) => "control_plane",
            Self::Follower(_) => "follower",
        }
    }
}

/// Build the roster the transport crate consults from the registry:
/// one entry per current fingerprint, plus one flagged
/// `via_previous_certificate` for every superseded certificate still
/// in its grace window.
pub fn roster_from_nodes(nodes: &[ClusterNode]) -> HashMap<String, NodeIdentity> {
    let mut map = HashMap::with_capacity(nodes.len() * 2);
    for node in nodes {
        let state = match node.status {
            NodeStatus::Pending => NodeState::Pending,
            NodeStatus::Active => NodeState::Active,
            NodeStatus::Revoked => NodeState::Revoked,
        };
        map.insert(
            node.cert_fingerprint.clone(),
            NodeIdentity {
                node_id: node.node_id.clone(),
                name: node.name.clone(),
                state,
                via_previous_certificate: false,
            },
        );
        if let Some(prev) = &node.prev_cert_fingerprint {
            map.insert(
                prev.clone(),
                NodeIdentity {
                    node_id: node.node_id.clone(),
                    name: node.name.clone(),
                    state,
                    via_previous_certificate: true,
                },
            );
        }
    }
    map
}

/// Reload the roster, the fleet-size hint and the CRL-backed acceptor
/// from the store. Called after every registry mutation and at boot.
///
/// Serialized on the control plane's refresh guard across the read AND
/// the swaps: two refreshes racing could otherwise land a pre-revocation
/// snapshot after the revocation and silently reopen the door. The
/// acceptor is rebuilt only when the revoked-serial set changed, and
/// BEFORE the roster swap, so a revoked node fails TLS before its
/// roster entry flips. When the rebuild fails the roster is swapped
/// anyway (the revoked node then fails identity resolution instead of
/// TLS) and the error is returned.
pub async fn refresh_control_plane(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<(), ClusterRuntimeError> {
    let guard = control.refresh_guard().await;
    let now = Utc::now();
    let (nodes, revoked) = store_op(store, move |store| {
        let nodes = store.list_cluster_nodes()?;
        let revoked = store.list_cluster_revoked_serials(now)?;
        Ok((nodes, revoked))
    })
    .await?;
    let entries: Vec<RevokedEntry> = revoked
        .into_iter()
        .map(|r| RevokedEntry {
            serial_hex: r.serial,
            revoked_at: r.revoked_at,
            superseded: r.reason == "superseded",
        })
        .collect();
    let rebuilt = control.rebuild_acceptor(&guard, &entries);
    control.replace_roster(&guard, roster_from_nodes(&nodes));
    if rebuilt? {
        tracing::info!(
            revoked_serials = entries.len(),
            "cluster operational acceptor rebuilt over the current CRL"
        );
    } else {
        tracing::debug!("cluster refresh: revoked-serial set unchanged, acceptor kept");
    }
    Ok(())
}

/// Recount live tokens and publish the count to the enrollment
/// listener (opens or closes the window).
pub async fn publish_token_liveness(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<u32, ClusterRuntimeError> {
    let live = store_op(store, |store| store.count_live_join_tokens(Utc::now())).await?;
    control.publish_token_liveness(live);
    Ok(live)
}

/// Outcome of [`revoke_node`]: what changed, and whether the refresh
/// that followed held. The row flip and the session kill are facts
/// the caller must audit even when `refresh_error` is set.
#[derive(Debug)]
pub struct RevokeOutcome {
    /// The node as it was before this call (already `Revoked` on a
    /// retry).
    pub node: ClusterNode,
    /// Whether this call flipped the registry row (false on a retry).
    pub newly_revoked: bool,
    /// Whether a live session was ended.
    pub session_ended: bool,
    /// The roster/CRL refresh failure, if any: the revocation is
    /// recorded and the session is gone, but the acceptor may still
    /// admit the certificate until a retry succeeds.
    pub refresh_error: Option<ClusterRuntimeError>,
}

/// Revoke a node end to end (AC #7): registry row, CRL-backed
/// acceptor, live session. Idempotent: on an already-revoked node the
/// refresh and the kill run again, so an operator whose first attempt
/// failed half-way (acceptor rebuild error) can retry until every
/// step held. The session is ended even when the refresh fails: a
/// revoked node must not keep a session because the CRL could not be
/// rebuilt. `Ok(None)` when the node does not exist; the refresh
/// failure travels in the outcome so the caller audits what happened
/// before surfacing it.
pub async fn revoke_node(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
    node_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<RevokeOutcome>, ClusterRuntimeError> {
    let id = node_id.to_string();
    let before = store_op(store, move |store| {
        let Some(existing) = store.get_cluster_node(&id)? else {
            return Ok(None);
        };
        let flipped = store.revoke_cluster_node(&id, now)?;
        Ok(Some((existing, flipped.is_some())))
    })
    .await?;
    let Some((node, newly_revoked)) = before else {
        return Ok(None);
    };
    let refresh_error = refresh_control_plane(control, store).await.err();
    let session_ended = control.sessions.kill(node_id);
    Ok(Some(RevokeOutcome {
        node,
        newly_revoked,
        session_ended,
        refresh_error,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, fp: &str, prev: Option<&str>, status: NodeStatus) -> ClusterNode {
        let now = Utc::now();
        ClusterNode {
            node_id: id.to_string(),
            name: id.to_string(),
            cert_fingerprint: fp.to_string(),
            cert_serial: "01".to_string(),
            prev_cert_fingerprint: prev.map(str::to_string),
            prev_cert_serial: prev.map(|_| "00".to_string()),
            address: String::new(),
            version: String::new(),
            schema_version: 0,
            status,
            enrolled_at: now,
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: now,
            revoked_at: None,
        }
    }

    #[test]
    fn roster_maps_current_and_superseded_fingerprints() {
        let roster = roster_from_nodes(&[
            node("a", "fp-a", None, NodeStatus::Active),
            node("b", "fp-b", Some("fp-b-old"), NodeStatus::Pending),
            node("c", "fp-c", None, NodeStatus::Revoked),
        ]);
        assert_eq!(roster.len(), 4);
        assert_eq!(roster["fp-a"].state, NodeState::Active);
        assert!(!roster["fp-b"].via_previous_certificate);
        assert!(roster["fp-b-old"].via_previous_certificate);
        assert_eq!(roster["fp-b-old"].node_id, "b");
        assert_eq!(roster["fp-c"].state, NodeState::Revoked);
    }

    #[test]
    fn store_errors_keep_their_http_identity_through_the_runtime_error() {
        use axum::response::IntoResponse;
        let absent: ApiError = ClusterRuntimeError::Store(ConfigError::NotFound("node".into())).into();
        assert_eq!(
            absent.into_response().status(),
            axum::http::StatusCode::NOT_FOUND
        );
        let acceptor: ApiError =
            ClusterRuntimeError::Acceptor(ClusterTlsError::Rustls("crl".into())).into();
        assert_eq!(
            acceptor.into_response().status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
