//! The stream plane as the management API reads it (Story 12.2 D-e,
//! D-h): this node's bind states, the fd budget check every stream
//! create and update runs, and `GET /api/v1/streams/budget`.
//!
//! The figures come from the process that binds: the supervisor (or the
//! single process) reads its fd limit once at startup and hands it here
//! with its worker count and the registry its reconcile driver writes.
//! The arithmetic is `lorica_stream::budget`'s, so the API refuses
//! exactly what the node would refuse at bind with `fd_budget`.

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_config::listen_ports::NodeLabel;
use lorica_config::models::{binds_here, GlobalSettings, NodeRole, Stream};
use lorica_stream::budget::{BudgetView, NodeBudgetInputs, NodeBudgetView};
use lorica_stream::{
    BindState, BindStateKind, BudgetViolation, FdBudget, StreamBindStates, StreamDemand,
};

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::server::AppState;
use crate::streams::LocalRole;

/// The `error.code` of a stream write refused because the node that
/// would bind it cannot hold its sockets (D-e).
pub const STREAM_FD_BUDGET_CODE: &str = "stream_fd_budget";

/// What the API holds of this process's stream plane: the bind-state
/// registry the reconcile driver writes, and the inputs of its fd
/// budget. Cloning shares the registry.
#[derive(Debug, Clone)]
pub struct StreamPlaneState {
    states: StreamBindStates,
    fds: NodeFds,
}

impl StreamPlaneState {
    /// The stream plane of a process whose soft fd limit is `fd_limit`
    /// (0 when it could not be read, which leaves no stream budget) and
    /// which runs `worker_count` workers (1 in single-process mode),
    /// reading the bind states from `states`.
    pub fn new(states: StreamBindStates, fd_limit: u64, worker_count: u32) -> Self {
        StreamPlaneState {
            states,
            fds: NodeFds {
                fd_limit,
                worker_count,
            },
        }
    }

    /// This node's bind state of `stream_id`, `None` when this node does
    /// not bind it (disabled, not targeted, or not reconciled yet).
    pub fn bind_state(&self, stream_id: &str) -> Option<BindState> {
        self.states.get(stream_id)
    }

    /// This node's budget inputs.
    pub fn fds(&self) -> NodeFds {
        self.fds
    }
}

#[cfg(test)]
impl StreamPlaneState {
    /// A plane that binds nothing yet, at the packaged unit's
    /// `LimitNOFILE` with one worker: the test `AppState`s' default.
    pub(crate) fn unbound_at_packaged_limit() -> Self {
        StreamPlaneState::new(StreamBindStates::new(), 65_536, 1)
    }
}

/// A node's fd limit and worker count, what its budget is computed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeFds {
    /// The process's soft `RLIMIT_NOFILE`.
    pub fd_limit: u64,
    /// Workers on the node, the UDP slot count.
    pub worker_count: u32,
}

/// A node a stream write is checked on.
#[derive(Debug, Clone)]
pub(crate) struct BudgetNode<'a> {
    /// How a refusal or a warning names the node.
    pub(crate) label: NodeLabel,
    /// The node's role, which decides the streams it binds.
    pub(crate) role: NodeRole<'a>,
    /// Its budget inputs, `None` for a node that has not reported them.
    pub(crate) fds: Option<NodeFds>,
}

/// A stream write that would break a node's budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BudgetRefusal {
    /// The node.
    pub(crate) label: NodeLabel,
    /// The first constraint broken, with its numbers.
    pub(crate) violation: BudgetViolation,
}

impl BudgetRefusal {
    /// The `422` refusing `stream`.
    pub(crate) fn into_error(self, stream: &Stream) -> ApiError {
        ApiError::coded(
            StatusCode::UNPROCESSABLE_ENTITY,
            STREAM_FD_BUDGET_CODE,
            format!(
                "stream `{}` would break the fd budget on {} ({}): {}",
                stream.name,
                self.label,
                self.violation.constraint(),
                self.violation
            ),
        )
    }
}

/// Whether `candidate` adds nothing to what `stored` already asked of a
/// node in `role`: the same protocol, no more ports, already bound
/// there. Such a write (a rename, a backend change) is never refused for
/// the budget, so a node already over it after a cap was lowered can
/// still have its streams edited, disabled or narrowed.
fn adds_no_demand(stored: Option<&Stream>, candidate: &Stream, role: NodeRole<'_>) -> bool {
    stored.is_some_and(|s| {
        binds_here(s, role)
            && s.protocol == candidate.protocol
            && StreamDemand::of(s).listen_sockets >= StreamDemand::of(candidate).listen_sockets
    })
}

/// Check a stream write against the budget of every node in `nodes`
/// (D-e): `candidate` as it would be written, `stored` the row it
/// replaces (`None` on create), `others` every stored stream (the
/// candidate's own row is skipped).
///
/// A node that would not bind the candidate, or to which the write adds
/// nothing, is not checked. A node without figures cannot be checked
/// here: it is named in the returned warnings and refuses at bind.
///
/// # Errors
///
/// The first node whose budget the write breaks.
pub(crate) fn check_write(
    candidate: &Stream,
    stored: Option<&Stream>,
    others: &[Stream],
    nodes: &[BudgetNode<'_>],
    listen_socket_cap: u32,
) -> Result<Vec<String>, BudgetRefusal> {
    let mut warnings = Vec::new();
    for node in nodes {
        if !binds_here(candidate, node.role) || adds_no_demand(stored, candidate, node.role) {
            continue;
        }
        let Some(fds) = node.fds else {
            warnings.push(format!(
                "{} has not reported its fd budget yet: it checks the stream when it binds \
                 it, and refuses it there with `fd_budget` if it does not fit",
                node.label
            ));
            continue;
        };
        let demands: Vec<StreamDemand> = others
            .iter()
            .filter(|s| s.id != candidate.id && binds_here(s, node.role))
            .map(StreamDemand::of)
            .chain(std::iter::once(StreamDemand::of(candidate)))
            .collect();
        FdBudget::from_limit(fds.fd_limit)
            .check(&demands, fds.worker_count, listen_socket_cap)
            .map_err(|violation| BudgetRefusal {
                label: node.label.clone(),
                violation,
            })?;
    }
    Ok(warnings)
}

/// The budget view of the node answering: every stream it binds, by
/// name, with its bind state (`pending` until its first reconcile).
pub(crate) fn local_view(
    plane: &StreamPlaneState,
    identity: (Option<String>, Option<String>),
    role: NodeRole<'_>,
    streams: &[Stream],
    settings: &GlobalSettings,
    now: DateTime<Utc>,
) -> NodeBudgetView {
    let (node_id, node_name) = identity;
    let fds = plane.fds();
    let shares: Vec<(StreamDemand, BindStateKind)> = streams
        .iter()
        .filter(|s| binds_here(s, role))
        .map(|s| {
            let state = plane
                .bind_state(&s.id)
                .map_or(BindStateKind::Pending, |state| state.kind());
            (StreamDemand::of(s), state)
        })
        .collect();
    NodeBudgetView::build(
        NodeBudgetInputs {
            node_id,
            node_name,
            reported_at: now,
            fd_limit: fds.fd_limit,
            worker_count: fds.worker_count,
            listen_socket_cap: settings.stream_listen_socket_cap,
            worker_drain_timeout_s: settings.worker_drain_timeout_s,
        },
        &shares,
    )
}

/// GET /api/v1/streams/budget - the fd budget of the node answering:
/// its fd limit, the HTTP and base reserves, what its streams commit
/// and each stream's share. Operator and above (`required_role`).
pub async fn get_stream_budget(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (streams, settings) = db_blocking(&state.store, |store| {
        Ok::<_, ApiError>((store.list_streams()?, store.get_global_settings()?))
    })
    .await?;
    let identity = match &state.cluster {
        crate::cluster::ClusterRuntime::Follower(follower) => (
            Some(follower.node_id.clone()),
            Some(follower.node_name.clone()),
        ),
        // A standalone node and the control plane have no roster row.
        crate::cluster::ClusterRuntime::Standalone
        | crate::cluster::ClusterRuntime::ControlPlane(_) => (None, None),
    };
    let role = LocalRole::of(&state);
    let node = local_view(
        &state.stream_plane,
        identity,
        role.node_role(),
        &streams,
        &settings,
        Utc::now(),
    );
    Ok(json_data(BudgetView { nodes: vec![node] }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::StreamProtocol;

    const PACKAGED: NodeFds = NodeFds {
        fd_limit: 65_536,
        worker_count: 8,
    };

    fn stream(id: &str, protocol: StreamProtocol, first: u16, last: u16) -> Stream {
        Stream {
            id: id.into(),
            name: id.into(),
            group_name: String::new(),
            protocol,
            enabled: true,
            listen_address: "0.0.0.0".parse().expect("an address"),
            port_first: first,
            port_last: last,
            node_selector: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn this_node(fds: Option<NodeFds>) -> BudgetNode<'static> {
        BudgetNode {
            label: NodeLabel::ThisNode,
            role: NodeRole::Standalone,
            fds,
        }
    }

    #[test]
    fn a_write_within_the_budget_passes_without_warning() {
        let candidate = stream("a", StreamProtocol::Tcp, 5432, 5432);
        let others = [stream("b", StreamProtocol::Udp, 53, 53)];
        let outcome = check_write(
            &candidate,
            None,
            &others,
            &[this_node(Some(PACKAGED))],
            2048,
        );
        assert_eq!(outcome, Ok(Vec::new()));
    }

    #[test]
    fn the_refusal_names_the_node_the_constraint_and_its_numbers() {
        // 4,096 fds leave a stream budget of 1,024; a 1,000-port UDP
        // range on two workers needs 2,000 in the supervisor.
        let small = NodeFds {
            fd_limit: 4096,
            worker_count: 2,
        };
        let candidate = stream("dns", StreamProtocol::Udp, 20_000, 20_999);
        let refusal = check_write(&candidate, None, &[], &[this_node(Some(small))], 2048)
            .expect_err("over the supervisor budget");
        assert_eq!(refusal.label, NodeLabel::ThisNode);
        assert_eq!(
            refusal.violation,
            BudgetViolation::SupervisorFds {
                committed: 2000,
                budget: 1024,
                fd_limit: 4096,
                workers: 2
            }
        );
        let message = refusal.into_error(&candidate).to_string();
        assert!(message.contains("`dns`"), "{message}");
        assert!(message.contains("this node"), "{message}");
        assert!(message.contains("supervisor_fds"), "{message}");
        assert!(message.contains("2000"), "{message}");
    }

    #[test]
    fn the_listen_socket_cap_counts_every_stream_the_node_binds() {
        let others = [
            stream("a", StreamProtocol::Tcp, 1000, 1009),
            // Disabled: bound nowhere, so it counts nowhere.
            Stream {
                enabled: false,
                ..stream("off", StreamProtocol::Tcp, 2000, 2999)
            },
        ];
        let candidate = stream("b", StreamProtocol::Tcp, 3000, 3005);
        let nodes = [this_node(Some(PACKAGED))];
        assert!(check_write(&candidate, None, &others, &nodes, 16).is_ok());
        let refusal = check_write(&candidate, None, &others, &nodes, 15).expect_err("over the cap");
        assert_eq!(
            refusal.violation,
            BudgetViolation::ListenSocketCap { used: 16, cap: 15 }
        );
    }

    #[test]
    fn a_write_that_adds_no_demand_passes_on_a_node_already_over_its_budget() {
        let stored = stream("a", StreamProtocol::Tcp, 1000, 1009);
        let nodes = [this_node(Some(PACKAGED))];
        let renamed = Stream {
            name: "renamed".into(),
            ..stored.clone()
        };
        let narrowed = Stream {
            port_last: 1004,
            ..stored.clone()
        };
        for candidate in [&renamed, &narrowed] {
            assert!(
                check_write(
                    candidate,
                    Some(&stored),
                    std::slice::from_ref(&stored),
                    &nodes,
                    1
                )
                .is_ok(),
                "{candidate:?}"
            );
        }
        let widened = Stream {
            port_last: 1010,
            ..stored.clone()
        };
        assert!(check_write(
            &widened,
            Some(&stored),
            std::slice::from_ref(&stored),
            &nodes,
            1
        )
        .is_err());
        let to_udp = Stream {
            protocol: StreamProtocol::Udp,
            ..stored.clone()
        };
        assert!(
            check_write(
                &to_udp,
                Some(&stored),
                std::slice::from_ref(&stored),
                &nodes,
                1
            )
            .is_err(),
            "a protocol change is a new demand"
        );
        let disabled = Stream {
            enabled: false,
            ..widened
        };
        assert!(
            check_write(
                &disabled,
                Some(&stored),
                std::slice::from_ref(&stored),
                &nodes,
                1
            )
            .is_ok(),
            "disabling is always allowed"
        );
    }

    #[test]
    fn a_node_without_figures_is_named_in_a_warning_and_a_reporting_one_is_checked() {
        let candidate = Stream {
            node_selector: vec!["edge-1".into(), "edge-2".into()],
            ..stream("pinned", StreamProtocol::Tcp, 5000, 5009)
        };
        let reporting = BudgetNode {
            label: NodeLabel::Named("edge-1".into()),
            role: NodeRole::Follower {
                node_name: "edge-1",
            },
            fds: Some(PACKAGED),
        };
        let silent = BudgetNode {
            label: NodeLabel::Named("edge-2".into()),
            role: NodeRole::Follower {
                node_name: "edge-2",
            },
            fds: None,
        };
        let nodes = [reporting.clone(), silent.clone()];
        let warnings = check_write(&candidate, None, &[], &nodes, 2048).expect("fits on edge-1");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("node `edge-2`"), "{warnings:?}");

        let refusal = check_write(&candidate, None, &[], &nodes, 5).expect_err("edge-1 refuses");
        assert_eq!(refusal.label, NodeLabel::Named("edge-1".into()));
    }

    #[test]
    fn the_local_view_lists_the_streams_this_node_binds_with_their_state() {
        let states = StreamBindStates::new();
        states.set_bound("pg", 2, 2);
        let plane = StreamPlaneState::new(states, 65_536, 2);
        let streams = [
            stream("pg", StreamProtocol::Tcp, 5432, 5432),
            stream("dns", StreamProtocol::Udp, 53, 54),
            Stream {
                node_selector: vec!["edge-1".into()],
                ..stream("pinned", StreamProtocol::Tcp, 6000, 6000)
            },
        ];
        let settings = GlobalSettings::default();
        let view = local_view(
            &plane,
            (None, None),
            NodeRole::ControlPlane,
            &streams,
            &settings,
            Utc::now(),
        );
        assert_eq!(view.fd_limit, 65_536);
        assert_eq!(view.stream_budget, 31_744);
        assert_eq!(view.worker_count, 2);
        assert_eq!(view.listen_socket_cap, settings.stream_listen_socket_cap);
        assert_eq!(view.worker_drain_timeout_s, settings.worker_drain_timeout_s);
        assert_eq!(view.listen_sockets_used, 3);
        assert_eq!(view.supervisor_fds_committed, 1 + 2 * 2);
        let shares: Vec<(&str, BindStateKind)> = view
            .streams
            .iter()
            .map(|s| (s.name.as_str(), s.bind_state))
            .collect();
        assert_eq!(
            shares,
            vec![
                ("pg", BindStateKind::Bound),
                ("dns", BindStateKind::Pending)
            ],
            "the control plane binds no pinned stream"
        );
    }
}
