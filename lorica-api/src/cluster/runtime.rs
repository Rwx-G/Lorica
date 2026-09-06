//! The fleet runtime layer (Story 9.3): what this process is in the
//! fleet, and the rule "the store is the truth; the roster, the
//! fleet-size hint and the CRL-backed acceptor are derived from it".
//!
//! No HTTP here. The control-plane binary and the API handlers both
//! act through these functions, so a mutation always goes store
//! first, then one serialized refresh, then the session registry.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use lorica_cluster::{ClusterConnection, ControlPlane, NodeIdentity, NodeState, RevokedEntry};
use lorica_config::models::{ClusterNode, NodeStatus};
use lorica_config::ConfigStore;
use tokio::sync::{watch, Mutex};

use crate::db::db_blocking;
use crate::error::ApiError;

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
/// Serialized on the control plane's refresh lock across the read AND
/// the swaps: two refreshes racing could otherwise land a pre-revocation
/// snapshot after the revocation and silently reopen the door. The
/// acceptor is rebuilt only when the revoked-serial set changed.
pub async fn refresh_control_plane(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<(), String> {
    let _serialized = control.refresh_lock.lock().await;
    let now = Utc::now();
    let (nodes, revoked) = db_blocking(store, move |store| {
        let nodes = store
            .list_cluster_nodes()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let revoked = store
            .list_cluster_revoked_serials(now)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok::<_, ApiError>((nodes, revoked))
    })
    .await
    .map_err(|e| e.to_string())?;
    let entries: Vec<RevokedEntry> = revoked
        .into_iter()
        .map(|r| RevokedEntry {
            serial_hex: r.serial,
            revoked_at: r.revoked_at,
            superseded: r.reason == "superseded",
        })
        .collect();
    // Acceptor before roster: a revoked node must fail TLS before its
    // roster entry flips, never the reverse.
    control
        .rebuild_acceptor(&entries)
        .map_err(|e| format!("acceptor rebuild: {e}"))?;
    control.replace_roster(roster_from_nodes(&nodes));
    Ok(())
}

/// Recount live tokens and publish the count to the enrollment
/// listener (opens or closes the window).
pub async fn publish_token_liveness(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<u32, String> {
    let live = db_blocking(store, |store| {
        store
            .count_live_join_tokens(Utc::now())
            .map_err(|e| ApiError::Internal(e.to_string()))
    })
    .await
    .map_err(|e| e.to_string())?;
    control.publish_token_liveness(live);
    Ok(live)
}

/// Outcome of [`revoke_node`].
#[derive(Debug, Clone)]
pub struct RevokeOutcome {
    /// The node as it was before this call (already `Revoked` on a
    /// retry).
    pub node: ClusterNode,
    /// Whether this call flipped the registry row (false on a retry).
    pub newly_revoked: bool,
    /// Whether a live session was ended.
    pub session_ended: bool,
}

/// Revoke a node end to end (AC #7): registry row, CRL-backed
/// acceptor, live session. Idempotent: on an already-revoked node the
/// refresh and the kill run again, so an operator whose first attempt
/// failed half-way (acceptor rebuild error) can retry until every
/// step held. The session is ended even when the refresh fails: a
/// revoked node must not keep a session because the CRL could not be
/// rebuilt. `Ok(None)` when the node does not exist.
pub async fn revoke_node(
    control: &Arc<ControlPlane>,
    store: &Arc<Mutex<ConfigStore>>,
    node_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<RevokeOutcome>, String> {
    let id = node_id.to_string();
    let before = db_blocking(store, move |store| {
        let existing = store
            .get_cluster_node(&id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let Some(existing) = existing else {
            return Ok::<_, ApiError>(None);
        };
        let flipped = store
            .revoke_cluster_node(&id, now)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(Some((existing, flipped.is_some())))
    })
    .await
    .map_err(|e| e.to_string())?;
    let Some((node, newly_revoked)) = before else {
        return Ok(None);
    };
    let refreshed = refresh_control_plane(control, store).await;
    let session_ended = control.sessions.kill(node_id);
    refreshed?;
    Ok(Some(RevokeOutcome {
        node,
        newly_revoked,
        session_ended,
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
}
