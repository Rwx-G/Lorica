//! The stream plane as the management API reads it (Story 12.2 D-e,
//! D-h, D-i): this node's bind states, the fd budget check every stream
//! create, update and import runs, `GET /api/v1/streams/budget`, and
//! the report a follower's heartbeat carries.
//!
//! The figures come from the process that binds: the supervisor (or the
//! single process) reads its fd limit once at startup and hands it here
//! with its worker count and the registry its reconcile driver writes.
//! A follower reports the same figures in its heartbeat
//! ([`heartbeat_report`]), which is how a control plane checks a stream
//! write against a node it does not run and shows that node's budget.
//! The arithmetic is `lorica_stream::budget`'s, so the API refuses
//! exactly what the node would refuse at bind with `fd_budget`.

use std::collections::HashMap;

use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use lorica_cluster::{
    StreamBindingReport, StreamBindingState, StreamPlaneReport, MAX_STREAM_BINDING_OS_ERROR_BYTES,
    MAX_STREAM_PLANE_BINDINGS,
};
use lorica_config::listen_ports::NodeLabel;
use lorica_config::models::{
    binds_here, ClusterNode, GlobalSettings, NodeRole, NodeStatus, Stream,
};
use lorica_stream::budget::{BudgetView, NodeBudgetInputs, NodeBudgetView};
use lorica_stream::{
    BindState, BindStateKind, BudgetUsage, BudgetViolation, FdBudget, StreamBindStates,
    StreamDemand,
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

impl NodeFds {
    /// The figures a follower reported in its heartbeat.
    pub fn reported(report: &StreamPlaneReport) -> Self {
        NodeFds {
            fd_limit: report.fd_limit,
            worker_count: report.worker_count,
        }
    }
}

/// What the streams a node in `role` binds commit against the budget of
/// `plane`: the half of the heartbeat report that needs the store, which
/// a follower computes off the heartbeat's task.
pub fn committed(plane: &StreamPlaneState, role: NodeRole<'_>, streams: &[Stream]) -> BudgetUsage {
    let demands: Vec<StreamDemand> = streams
        .iter()
        .filter(|s| binds_here(s, role))
        .map(StreamDemand::of)
        .collect();
    FdBudget::from_limit(plane.fds.fd_limit).usage(&demands, plane.fds.worker_count)
}

/// This node's stream plane as its heartbeat reports it (D-i): the
/// budget inputs, `usage` (from [`committed`]), how many bindings are
/// bound, and every binding that is not, failures first, at most
/// [`MAX_STREAM_PLANE_BINDINGS`] with `truncated` set past it.
///
/// Built so the control plane's decode-boundary check
/// (`lorica_cluster::stream_plane_report_defect`) passes: an OS error
/// loses its control characters and is cut to its bound here, on the
/// side that knows what it says.
pub fn heartbeat_report(plane: &StreamPlaneState, usage: BudgetUsage) -> StreamPlaneReport {
    let mut bound_count: u32 = 0;
    let mut failed = Vec::new();
    let mut pending = Vec::new();
    for (stream_id, state) in plane.states.snapshot() {
        match state {
            BindState::Bound { .. } => bound_count = bound_count.saturating_add(1),
            BindState::Pending => pending.push(StreamBindingReport {
                stream_id,
                state: StreamBindingState::Pending as i32,
                ..StreamBindingReport::default()
            }),
            BindState::Failed(failure) => failed.push(StreamBindingReport {
                stream_id,
                state: StreamBindingState::Failed as i32,
                kind: failure.kind.as_str().to_string(),
                os_error: wire_os_error(&failure.os_error),
                port: u32::from(failure.port),
                failed_since_ms: u64::try_from(failure.since.timestamp_millis()).unwrap_or(0),
            }),
        }
    }
    let not_bound = failed.len() + pending.len();
    let mut bindings = failed;
    bindings.extend(pending);
    bindings.truncate(MAX_STREAM_PLANE_BINDINGS);
    StreamPlaneReport {
        fd_limit: plane.fds.fd_limit,
        worker_count: plane.fds.worker_count,
        listen_sockets_used: usage.listen_sockets_used,
        worker_fds_committed: usage.worker_fds_committed,
        supervisor_fds_committed: usage.supervisor_fds_committed,
        bound_count,
        truncated: not_bound > bindings.len(),
        bindings,
    }
}

/// `text` as a binding may carry it: control characters become spaces
/// and it is cut, on a character boundary, to
/// [`MAX_STREAM_BINDING_OS_ERROR_BYTES`].
fn wire_os_error(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if out.len() + c.len_utf8() > MAX_STREAM_BINDING_OS_ERROR_BYTES {
            break;
        }
        out.push(c);
    }
    out
}

/// A node's bind states as the control plane reads them from its report
/// (D-i): a binding the node lists is in the state it lists; one it does
/// not list is bound, unless the node drifts from this control plane's
/// configuration (it may not hold that stream yet) or its list was cut
/// (the stream may be past the cut), where the state is `unknown`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReportedBindings<'a> {
    report: &'a StreamPlaneReport,
    drifted: bool,
}

impl<'a> ReportedBindings<'a> {
    /// Read `report`; `drifted` is the node's drift verdict.
    pub(crate) fn new(report: &'a StreamPlaneReport, drifted: bool) -> Self {
        ReportedBindings { report, drifted }
    }

    /// The binding of `stream_id` the node lists, if any.
    pub(crate) fn listed(&self, stream_id: &str) -> Option<&'a StreamBindingReport> {
        self.report
            .bindings
            .iter()
            .find(|b| b.stream_id == stream_id)
    }

    /// The state of a stream the control plane expects the node to bind.
    pub(crate) fn state_of(&self, stream_id: &str) -> BindStateKind {
        match self.listed(stream_id) {
            Some(binding) => listed_state(binding),
            None if self.drifted || self.report.truncated => BindStateKind::Unknown,
            None => BindStateKind::Bound,
        }
    }
}

/// The state of a binding a node lists; a state this build does not
/// know, which only a newer node sends, is `unknown`.
pub(crate) fn listed_state(binding: &StreamBindingReport) -> BindStateKind {
    match binding.binding_state() {
        StreamBindingState::Pending => BindStateKind::Pending,
        StreamBindingState::Failed => BindStateKind::Failed,
        StreamBindingState::Unspecified => BindStateKind::Unknown,
    }
}

/// The budget figures every node with an open session reported, by node
/// id, on a control plane; empty on any other role, where no node
/// reports to this one.
pub(crate) fn reported_fds(state: &AppState) -> HashMap<String, NodeFds> {
    let crate::cluster::ClusterRuntime::ControlPlane(runtime) = &state.cluster else {
        return HashMap::new();
    };
    runtime
        .control
        .sessions
        .snapshot()
        .into_iter()
        .filter_map(|s| {
            let fds = NodeFds::reported(s.stream_plane.as_ref()?);
            Some((s.node_id, fds))
        })
        .collect()
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

/// The budget view of an enrolled `node` from the report its heartbeat
/// carried at `reported_at` (D-i): each stream this control plane
/// expects it to bind, with its state as [`ReportedBindings`] reads it,
/// and the node's own figures.
///
/// The shares come from this control plane's configuration and the
/// committed totals from the node, which agree while the node is in
/// sync; while it drifts, the totals say what it holds now and the
/// shares what it will hold once it converges.
pub(crate) fn reported_view(
    node: &ClusterNode,
    report: &StreamPlaneReport,
    reported_at: DateTime<Utc>,
    drifted: bool,
    streams: &[Stream],
    settings: &GlobalSettings,
) -> NodeBudgetView {
    let role = NodeRole::Follower {
        node_name: &node.name,
    };
    let bindings = ReportedBindings::new(report, drifted);
    let shares: Vec<(StreamDemand, BindStateKind)> = streams
        .iter()
        .filter(|s| binds_here(s, role))
        .map(|s| (StreamDemand::of(s), bindings.state_of(&s.id)))
        .collect();
    let mut view = NodeBudgetView::build(
        NodeBudgetInputs {
            node_id: Some(node.node_id.clone()),
            node_name: Some(node.name.clone()),
            reported_at,
            fd_limit: report.fd_limit,
            worker_count: report.worker_count,
            listen_socket_cap: settings.stream_listen_socket_cap,
            worker_drain_timeout_s: settings.worker_drain_timeout_s,
        },
        &shares,
    );
    view.listen_sockets_used = report.listen_sockets_used;
    view.worker_fds_committed = report.worker_fds_committed;
    view.supervisor_fds_committed = report.supervisor_fds_committed;
    view
}

/// The budget views of the nodes reporting to a control plane: every
/// active roster row whose open session carried a report, by name.
fn fleet_views(
    runtime: &crate::cluster::ControlPlaneRuntime,
    roster: &[ClusterNode],
    streams: &[Stream],
    settings: &GlobalSettings,
) -> Vec<NodeBudgetView> {
    let sessions: HashMap<String, lorica_cluster::LiveSessionSnapshot> = runtime
        .control
        .sessions
        .snapshot()
        .into_iter()
        .map(|s| (s.node_id.clone(), s))
        .collect();
    let mut nodes: Vec<&ClusterNode> = roster
        .iter()
        .filter(|n| n.status == NodeStatus::Active)
        .collect();
    nodes.sort_by(|a, b| a.name.cmp(&b.name));
    nodes
        .into_iter()
        .filter_map(|node| {
            let session = sessions.get(&node.node_id)?;
            let report = session.stream_plane.as_ref()?;
            let drift = lorica_fleet::runtime::evaluate_drift(
                &runtime.control.expected_config_version(&node.node_id),
                node.applied_config_generation,
                &node.applied_config_hash,
                Some(&session.applied),
            );
            let reported_at = i64::try_from(session.last_seen_unix)
                .ok()
                .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0))
                .unwrap_or_else(Utc::now);
            Some(reported_view(
                node,
                report,
                reported_at,
                drift.drifted,
                streams,
                settings,
            ))
        })
        .collect()
}

/// GET /api/v1/streams/budget - the fd budget of the node answering:
/// its fd limit, the HTTP and base reserves, what its streams commit
/// and each stream's share; on a control plane, also every enrolled
/// node that reports its own. Operator and above (`required_role`).
pub async fn get_stream_budget(
    Extension(state): Extension<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let on_control_plane = matches!(
        state.cluster,
        crate::cluster::ClusterRuntime::ControlPlane(_)
    );
    let (streams, settings, roster) = db_blocking(&state.store, move |store| {
        let roster = if on_control_plane {
            store.list_cluster_nodes()?
        } else {
            Vec::new()
        };
        Ok::<_, ApiError>((store.list_streams()?, store.get_global_settings()?, roster))
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
    let mut nodes = vec![local_view(
        &state.stream_plane,
        identity,
        role.node_role(),
        &streams,
        &settings,
        Utc::now(),
    )];
    if let crate::cluster::ClusterRuntime::ControlPlane(runtime) = &state.cluster {
        nodes.extend(fleet_views(runtime, &roster, &streams, &settings));
    }
    Ok(json_data(BudgetView { nodes }))
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
        Stream::new(
            id.into(),
            id.into(),
            protocol,
            "0.0.0.0".parse().expect("an address"),
            first,
            last,
            Utc::now(),
        )
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

    fn uuid(n: u32) -> String {
        format!("00000000-0000-4000-8000-{n:012}")
    }

    #[test]
    fn the_heartbeat_report_lists_failures_first_and_passes_the_decode_check() {
        let states = StreamBindStates::new();
        states.set_bound(&uuid(1), 2, 2);
        states.set_pending(&uuid(2));
        states.set_failed(
            &uuid(3),
            lorica_stream::BindFailureKind::AddressInUse,
            "Address already in use\n(os error 98)".into(),
            6000,
            Utc::now(),
        );
        let plane = StreamPlaneState::new(states, 65_536, 2);
        let streams = [
            stream(&uuid(1), StreamProtocol::Tcp, 5432, 5432),
            stream(&uuid(3), StreamProtocol::Udp, 6000, 6001),
        ];
        let usage = committed(&plane, NodeRole::Standalone, &streams);
        let report = heartbeat_report(&plane, usage);
        assert_eq!(lorica_cluster::stream_plane_report_defect(&report), None);
        assert_eq!(report.fd_limit, 65_536);
        assert_eq!(report.worker_count, 2);
        assert_eq!(report.listen_sockets_used, 3);
        assert_eq!(report.worker_fds_committed, 3);
        assert_eq!(report.supervisor_fds_committed, 1 + 2 * 2);
        assert_eq!(report.bound_count, 1);
        assert!(!report.truncated);
        let listed: Vec<(&str, StreamBindingState)> = report
            .bindings
            .iter()
            .map(|b| (b.stream_id.as_str(), b.binding_state()))
            .collect();
        assert_eq!(
            listed,
            vec![
                (uuid(3).as_str(), StreamBindingState::Failed),
                (uuid(2).as_str(), StreamBindingState::Pending),
            ]
        );
        let failed = &report.bindings[0];
        assert_eq!(failed.kind, "address_in_use");
        assert_eq!(failed.port, 6000);
        assert_eq!(
            failed.os_error, "Address already in use (os error 98)",
            "a control character never reaches the wire"
        );
        assert!(failed.failed_since_ms > 0);
    }

    #[test]
    fn a_heartbeat_report_past_its_bound_is_cut_and_says_so() {
        let states = StreamBindStates::new();
        let past = u32::try_from(MAX_STREAM_PLANE_BINDINGS).expect("bound") + 2;
        for n in 0..past {
            states.set_pending(&uuid(n));
        }
        states.set_failed(
            &uuid(past),
            lorica_stream::BindFailureKind::Other,
            "x".repeat(MAX_STREAM_BINDING_OS_ERROR_BYTES + 40),
            1,
            Utc::now(),
        );
        let report = heartbeat_report(
            &StreamPlaneState::new(states, 65_536, 1),
            BudgetUsage::default(),
        );
        assert_eq!(report.bindings.len(), MAX_STREAM_PLANE_BINDINGS);
        assert!(report.truncated);
        assert_eq!(
            report.bindings[0].binding_state(),
            StreamBindingState::Failed,
            "the failure survives the cut"
        );
        assert_eq!(
            report.bindings[0].os_error.len(),
            MAX_STREAM_BINDING_OS_ERROR_BYTES
        );
        assert_eq!(lorica_cluster::stream_plane_report_defect(&report), None);
    }

    fn report_listing(bindings: Vec<StreamBindingReport>, truncated: bool) -> StreamPlaneReport {
        StreamPlaneReport {
            fd_limit: 4096,
            worker_count: 2,
            listen_sockets_used: 7,
            worker_fds_committed: 7,
            supervisor_fds_committed: 9,
            bound_count: 1,
            bindings,
            truncated,
        }
    }

    fn listed_failure(stream_id: &str) -> StreamBindingReport {
        StreamBindingReport {
            stream_id: stream_id.to_string(),
            state: StreamBindingState::Failed as i32,
            kind: "address_in_use".to_string(),
            os_error: "Address already in use (os error 98)".to_string(),
            port: 6000,
            failed_since_ms: 1,
        }
    }

    #[test]
    fn an_unlisted_stream_is_bound_only_while_the_node_is_in_sync_and_its_list_whole() {
        let report = report_listing(
            vec![
                listed_failure("failed"),
                StreamBindingReport {
                    stream_id: "newer".to_string(),
                    state: 9,
                    ..StreamBindingReport::default()
                },
            ],
            false,
        );
        let in_sync = ReportedBindings::new(&report, false);
        assert_eq!(in_sync.state_of("failed"), BindStateKind::Failed);
        assert_eq!(in_sync.state_of("newer"), BindStateKind::Unknown);
        assert_eq!(in_sync.state_of("unlisted"), BindStateKind::Bound);
        let drifting = ReportedBindings::new(&report, true);
        assert_eq!(drifting.state_of("unlisted"), BindStateKind::Unknown);
        assert_eq!(
            drifting.state_of("failed"),
            BindStateKind::Failed,
            "what the node lists stands, drift or not"
        );
        let cut = report_listing(vec![], true);
        assert_eq!(
            ReportedBindings::new(&cut, false).state_of("unlisted"),
            BindStateKind::Unknown
        );
    }

    fn enrolled(name: &str) -> ClusterNode {
        let now = Utc::now();
        ClusterNode {
            node_id: format!("id-{name}"),
            name: name.to_string(),
            cert_fingerprint: format!("fp-{name}"),
            cert_serial: "0a00".to_string(),
            prev_cert_fingerprint: None,
            prev_cert_serial: None,
            address: String::new(),
            version: String::new(),
            schema_version: 0,
            status: NodeStatus::Active,
            enrolled_at: now,
            last_seen_at: None,
            applied_config_generation: 0,
            applied_config_hash: String::new(),
            cert_not_after: now,
            revoked_at: None,
            reserved_ports: None,
        }
    }

    #[test]
    fn a_reported_view_shares_the_targeted_streams_and_keeps_the_nodes_totals() {
        let edge = enrolled("edge-1");
        let pinned = Stream {
            node_selector: vec!["edge-1".into()],
            ..stream("pinned", StreamProtocol::Tcp, 5000, 5004)
        };
        let elsewhere = Stream {
            node_selector: vec!["edge-2".into()],
            ..stream("elsewhere", StreamProtocol::Tcp, 7000, 7000)
        };
        let fleet = stream("fleet", StreamProtocol::Udp, 53, 54);
        let streams = [pinned, elsewhere, fleet];
        let report = report_listing(vec![listed_failure("fleet")], false);
        let settings = GlobalSettings::default();
        let at = Utc::now();
        let view = reported_view(&edge, &report, at, false, &streams, &settings);
        assert_eq!(view.node_id.as_deref(), Some("id-edge-1"));
        assert_eq!(view.node_name.as_deref(), Some("edge-1"));
        assert_eq!(view.reported_at, at);
        assert_eq!(view.fd_limit, 4096);
        assert_eq!(view.stream_budget, 4096 - 1024 - 2048);
        assert_eq!(view.worker_count, 2);
        assert_eq!(
            (
                view.listen_sockets_used,
                view.worker_fds_committed,
                view.supervisor_fds_committed
            ),
            (7, 7, 9),
            "the totals are what the node holds"
        );
        let shares: Vec<(&str, BindStateKind)> = view
            .streams
            .iter()
            .map(|s| (s.name.as_str(), s.bind_state))
            .collect();
        assert_eq!(
            shares,
            vec![
                ("pinned", BindStateKind::Bound),
                ("fleet", BindStateKind::Failed)
            ]
        );
        let drifting = reported_view(&edge, &report, at, true, &streams, &settings);
        assert_eq!(drifting.streams[0].bind_state, BindStateKind::Unknown);
    }

    #[test]
    fn a_control_plane_checks_a_node_on_the_figures_its_heartbeat_reported() {
        let candidate = Stream {
            node_selector: vec!["edge-1".into()],
            ..stream("dns", StreamProtocol::Udp, 20_000, 20_999)
        };
        let report = report_listing(vec![], false);
        let node = BudgetNode {
            label: NodeLabel::Named("edge-1".into()),
            role: NodeRole::Follower {
                node_name: "edge-1",
            },
            fds: Some(NodeFds::reported(&report)),
        };
        let refusal = check_write(&candidate, None, &[], &[node], 2048)
            .expect_err("4,096 fds on two workers cannot hold 1,000 UDP ports");
        assert_eq!(refusal.label, NodeLabel::Named("edge-1".into()));
        assert_eq!(refusal.violation.constraint(), "supervisor_fds");
    }
}
