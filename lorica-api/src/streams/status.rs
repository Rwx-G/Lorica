//! `GET /api/v1/streams/status` (Story 12.10 D-d, D-e): every stream's
//! bind state on this node, on a control plane its state on every
//! active node that binds it, and this node's live counters, in one
//! answer so the dashboard makes one call per refresh.
//!
//! Reads at Viewer, the GET default of `required_role`: a bind state is
//! what the stream reads and the fleet view already show a Viewer.
//!
//! The per-node states are read by `cluster::node_bind_state`, the rule
//! the fleet view's bindings follow, so the Streams page and the
//! Cluster drawer cannot disagree. The counters come from
//! [`StreamMetricsCollector::live_counters`], the aggregate `/metrics`
//! renders. They are this node's only: per-stream figures from the
//! other nodes would grow the heartbeat with the stream count, which
//! Story 12.2 D-i refused; the fleet-wide view is the stream SLA.

use axum::extract::Extension;
use axum::Json;
use lorica_config::models::StreamProtocol;
use serde::Serialize;

use crate::cluster::{fleet_stream_states, ClusterRuntime, StreamNodeState};
use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::server::AppState;
use crate::stream_metrics::{stream_metrics, StreamLiveCounters, StreamMetricsCollector};

/// One stream's status.
#[derive(Debug, Serialize)]
pub struct StreamStatus {
    /// The stream's id.
    pub id: String,
    /// The stream's name.
    pub name: String,
    /// `tcp` or `udp`.
    pub protocol: StreamProtocol,
    /// This node's bind state, the value the stream reads carry: `null`
    /// when this node does not bind the stream.
    pub bind: Option<lorica_stream::BindState>,
    /// On a control plane, the stream's state on every active node that
    /// binds it, by node name; `null` on any other role, where `bind`
    /// is the whole answer.
    pub nodes: Option<Vec<StreamNodeState>>,
    /// This node's live counters of the stream, `null` while nothing has
    /// counted it.
    pub counters: Option<StreamStatusCounters>,
}

/// The live counters of a stream, labelled with the node that counted
/// them.
#[derive(Debug, Serialize)]
pub struct StreamStatusCounters {
    /// The answering node's name on a follower; `null` on a standalone
    /// node and on a control plane, which have no roster name.
    pub node_name: Option<String>,
    /// The counters.
    #[serde(flatten)]
    pub live: StreamLiveCounters,
}

/// Every stored stream's status, by name, its counters read from
/// `collector`.
///
/// # Errors
///
/// The store's error.
pub(crate) async fn stream_statuses(
    state: &AppState,
    collector: &StreamMetricsCollector,
) -> Result<Vec<StreamStatus>, ApiError> {
    let on_control_plane = matches!(state.cluster, ClusterRuntime::ControlPlane(_));
    let (streams, roster) = db_blocking(&state.store, move |store| {
        let roster = if on_control_plane {
            store.list_cluster_nodes()?
        } else {
            Vec::new()
        };
        Ok::<_, ApiError>((store.list_streams()?, roster))
    })
    .await?;
    let (mut fleet, node_name) = match &state.cluster {
        ClusterRuntime::ControlPlane(runtime) => (
            Some(fleet_stream_states(&runtime.control, &roster, &streams)),
            None,
        ),
        ClusterRuntime::Follower(follower) => (None, Some(follower.node_name.clone())),
        ClusterRuntime::Standalone => (None, None),
    };
    let mut counted = collector.live_counters();
    Ok(streams
        .into_iter()
        .map(|stream| StreamStatus {
            bind: state.stream_plane.bind_state(&stream.id),
            nodes: fleet
                .as_mut()
                .map(|states| states.remove(&stream.id).unwrap_or_default()),
            counters: counted.remove(&stream.id).map(|live| StreamStatusCounters {
                node_name: node_name.clone(),
                live,
            }),
            id: stream.id,
            name: stream.name,
            protocol: stream.protocol,
        })
        .collect())
}

/// GET /api/v1/streams/status - every stream's bind state, per node on a
/// control plane, and this node's live counters (Viewer and above).
pub async fn get_stream_status(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let streams = stream_statuses(&state, stream_metrics()).await?;
    Ok(json_data(serde_json::json!({ "streams": streams })))
}
