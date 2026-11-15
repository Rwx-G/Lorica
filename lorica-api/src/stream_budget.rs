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
//! The arithmetic is `lorica_stream::budget`'s, every demand is
//! `StreamDemand::of`, the function the node's driver builds its own
//! demands with (the TCP engine's connections and the UDP engine's
//! sessions included, Stories 12.3 D-p and 12.5 D-e), and the rule is
//! `FdBudget::check_change`, the one the driver binds by, so the API
//! refuses exactly what the node would refuse at bind with `fd_budget`
//! or `source_ports`.

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
    fd_limit: u64,
    worker_count: u32,
    source_ports: SourcePorts,
}

/// Where a [`StreamPlaneState`] takes `U`, the usable UDP source ports
/// per source address (Story 12.5 D-e).
#[derive(Debug, Clone, Copy)]
enum SourcePorts {
    /// The host's port range, read at every use as the node's driver
    /// reads it at every pass, so a sysctl change is seen without a
    /// restart.
    Host,
    /// A fixed figure, `None` for a range that cannot be read.
    Fixed(Option<u64>),
}

impl StreamPlaneState {
    /// The stream plane of a process whose soft fd limit is `fd_limit`
    /// (0 when it could not be read, which leaves no stream budget) and
    /// which runs `worker_count` workers (1 in single-process mode),
    /// reading the bind states from `states` and its usable UDP source
    /// ports from the host.
    pub fn new(states: StreamBindStates, fd_limit: u64, worker_count: u32) -> Self {
        StreamPlaneState {
            states,
            fd_limit,
            worker_count,
            source_ports: SourcePorts::Host,
        }
    }

    /// The same plane with `U` fixed at `usable_source_ports` instead of
    /// read from the host; `None` stands for a range that cannot be read,
    /// which leaves the fd constraints alone to decide.
    pub fn with_usable_source_ports(mut self, usable_source_ports: Option<u64>) -> Self {
        self.source_ports = SourcePorts::Fixed(usable_source_ports);
        self
    }

    /// This node's bind state of `stream_id`, `None` when this node does
    /// not bind it (disabled, not targeted, or not reconciled yet).
    pub fn bind_state(&self, stream_id: &str) -> Option<BindState> {
        self.states.get(stream_id)
    }

    /// This node's budget inputs, `U` read now.
    pub fn fds(&self) -> NodeFds {
        NodeFds {
            fd_limit: self.fd_limit,
            worker_count: self.worker_count,
            usable_source_ports: match self.source_ports {
                SourcePorts::Fixed(usable) => usable,
                // The driver logs an unreadable range at every pass; a
                // second warning here would repeat it at every read.
                SourcePorts::Host => match lorica_stream::budget::usable_udp_source_ports() {
                    Ok(usable) => Some(u64::from(usable)),
                    Err(e) => {
                        tracing::debug!(error = %e, "usable UDP source ports unreadable");
                        None
                    }
                },
            },
        }
    }
}

#[cfg(test)]
impl StreamPlaneState {
    /// A plane that binds nothing yet, at the packaged unit's
    /// `LimitNOFILE` and the default port range's `U`, with one worker:
    /// the test `AppState`s' default.
    pub(crate) fn unbound_at_packaged_limit() -> Self {
        StreamPlaneState::new(StreamBindStates::new(), 65_536, 1)
            .with_usable_source_ports(Some(DEFAULT_RANGE_USABLE_PORTS))
    }
}

/// `U` at the kernel's default `ip_local_port_range` (32768 to 60999),
/// nothing reserved: what the tests' nodes report.
#[cfg(test)]
pub(crate) const DEFAULT_RANGE_USABLE_PORTS: u64 = 27_208;

/// A node's budget inputs: its fd limit and worker count, and its usable
/// UDP source ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeFds {
    /// The process's soft `RLIMIT_NOFILE`.
    pub fd_limit: u64,
    /// Workers on the node, the UDP slot count.
    pub worker_count: u32,
    /// `U`, the usable UDP source ports per source address; `None` when
    /// the node could not read its port range or has not reported it (a
    /// node from before Story 12.5), which leaves the fd constraints
    /// alone to decide.
    pub usable_source_ports: Option<u64>,
}

impl NodeFds {
    /// The figures a follower reported in its heartbeat.
    pub fn reported(report: &StreamPlaneReport) -> Self {
        NodeFds {
            fd_limit: report.fd_limit,
            worker_count: report.worker_count,
            usable_source_ports: report.usable_source_ports,
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
    FdBudget::from_limit(plane.fd_limit).usage(&demands, plane.worker_count)
}

/// This node's stream plane as its heartbeat reports it (D-i): the
/// budget inputs (`U` read now, Story 12.5 D-e), `usage` (from
/// [`committed`]), how many bindings are bound, and every binding that
/// is not, failures first, at most [`MAX_STREAM_PLANE_BINDINGS`] with
/// `truncated` set past it.
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
    let fds = plane.fds();
    StreamPlaneReport {
        fd_limit: fds.fd_limit,
        worker_count: fds.worker_count,
        listen_sockets_used: usage.listen_sockets_used,
        worker_fds_committed: usage.worker_fds_committed,
        supervisor_fds_committed: usage.supervisor_fds_committed,
        bound_count,
        truncated: not_bound > bindings.len(),
        bindings,
        usable_source_ports: fds.usable_source_ports,
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

/// Check a stream write against the budget of every node in `nodes`
/// (Story 12.2 D-e, Story 12.5 D-e): `candidate` as it would be
/// written, `stored` the row it replaces (`None` on create), `others`
/// every stored stream (the candidate's own row is skipped).
///
/// Each node applies [`FdBudget::check_change`], the rule the node's own
/// bind applies: the fd constraints and, where the node knows its `U`,
/// the source ports; a write that raises nothing over what the stored
/// row asks of a node already binding it (a rename, a backend change, a
/// lower share) is never refused, so a node past its ceiling can still
/// have its streams edited, disabled or narrowed. A node that would not
/// bind the candidate, or to which the write adds nothing, is not
/// checked. A node without figures cannot be checked here: it is named
/// in the returned warnings and refuses at bind.
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
    let demand = StreamDemand::of(candidate);
    let mut warnings = Vec::new();
    for node in nodes {
        if !binds_here(candidate, node.role) {
            continue;
        }
        let counted = stored
            .filter(|s| binds_here(s, node.role))
            .map(StreamDemand::of);
        if counted.as_ref().is_some_and(|was| !demand.raises(was)) {
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
            .collect();
        FdBudget::from_limit(fds.fd_limit)
            .check_change(
                &demand,
                counted.as_ref(),
                &demands,
                fds.worker_count,
                listen_socket_cap,
                fds.usable_source_ports,
            )
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
            usable_source_ports: fds.usable_source_ports,
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
            usable_source_ports: report.usable_source_ports,
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
        usable_source_ports: Some(DEFAULT_RANGE_USABLE_PORTS),
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
        // range of 16 sessions fits one worker, and on two workers needs
        // 2,000 slot sockets and its caps memfd in the supervisor.
        let small = NodeFds {
            fd_limit: 4096,
            worker_count: 2,
            usable_source_ports: Some(DEFAULT_RANGE_USABLE_PORTS),
        };
        let mut candidate = stream("dns", StreamProtocol::Udp, 20_000, 20_999);
        candidate
            .udp
            .as_mut()
            .expect("a UDP stream carries its settings")
            .max_sessions = 16;
        let refusal = check_write(&candidate, None, &[], &[this_node(Some(small))], 2048)
            .expect_err("over the supervisor budget");
        assert_eq!(refusal.label, NodeLabel::ThisNode);
        assert_eq!(
            refusal.violation,
            BudgetViolation::SupervisorFds {
                committed: 2001,
                budget: 1024,
                fd_limit: 4096,
                workers: 2
            }
        );
        let message = refusal.into_error(&candidate).to_string();
        assert!(message.contains("`dns`"), "{message}");
        assert!(message.contains("this node"), "{message}");
        assert!(message.contains("supervisor_fds"), "{message}");
        assert!(message.contains("2001"), "{message}");
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

    /// What the node's driver refuses at bind for `streams` on a node
    /// of `fds`, the last one new there: its rule over the demands it
    /// builds, which are [`StreamDemand::of`] each stream (pinned on the
    /// driver's side by `a_tcp_binding_declares_what_its_connections_hold`).
    fn node_verdict(streams: &[&Stream], fds: NodeFds, cap: u32) -> Result<(), BudgetViolation> {
        let mut demands: Vec<StreamDemand> = streams.iter().map(|s| StreamDemand::of(s)).collect();
        let new = demands.pop().expect("a stream to bind");
        FdBudget::from_limit(fds.fd_limit).check_change(
            &new,
            None,
            &demands,
            fds.worker_count,
            cap,
            fds.usable_source_ports,
        )
    }

    #[test]
    fn the_api_refuses_exactly_what_the_node_would_for_a_tcp_streams_connections() {
        // One port and `max_connections` connections of two fds each:
        // `1 + 2 x max` against the stream budget of the packaged limit.
        let budget = FdBudget::from_limit(PACKAGED.fd_limit).stream_budget;
        let per_connection = lorica_stream::tcp::TCP_FDS_PER_CONNECTION;
        let fitting = u32::try_from((budget - 1) / per_connection).expect("a cap");
        let nodes = [this_node(Some(PACKAGED))];
        for (max, fits) in [(fitting, true), (fitting + 1, false)] {
            let mut candidate = stream("pg", StreamProtocol::Tcp, 5432, 5432);
            candidate.max_connections = max;
            let api = check_write(&candidate, None, &[], &nodes, 2048);
            assert_eq!(api.is_ok(), fits, "max_connections {max}");
            assert_eq!(
                api.map(|_| ()).map_err(|refusal| refusal.violation),
                node_verdict(&[&candidate], PACKAGED, 2048),
                "max_connections {max}: the API and the node disagree"
            );
        }
    }

    #[test]
    fn the_default_cap_admits_fifteen_tcp_streams_at_the_packaged_limit() {
        // Story 12.3 D-p: "the default admits about fifteen TCP streams
        // per node before the budget refuses one".
        let others: Vec<Stream> = (0..15)
            .map(|n| stream(&format!("s{n}"), StreamProtocol::Tcp, 5000 + n, 5000 + n))
            .collect();
        let nodes = [this_node(Some(PACKAGED))];
        let sixteenth = stream("s15", StreamProtocol::Tcp, 6000, 6000);
        let refusal = check_write(&sixteenth, None, &others, &nodes, 2048)
            .expect_err("the sixteenth default TCP stream breaks the worker budget");
        assert_eq!(refusal.violation.constraint(), "worker_fds");
        let mut all: Vec<&Stream> = others.iter().collect();
        all.push(&sixteenth);
        assert_eq!(Err(refusal.violation), node_verdict(&all, PACKAGED, 2048));
        let fifteenth = &others[14];
        assert!(
            check_write(fifteenth, None, &others[..14], &nodes, 2048).is_ok(),
            "fifteen fit"
        );
    }

    #[test]
    fn raising_a_tcp_streams_cap_is_new_demand_and_lowering_it_is_not() {
        let stored = stream("pg", StreamProtocol::Tcp, 5432, 5432);
        let others = std::slice::from_ref(&stored);
        // A node already over its budget: one worker cannot hold even
        // the stored stream.
        let small = NodeFds {
            fd_limit: 2048,
            worker_count: 1,
            usable_source_ports: Some(DEFAULT_RANGE_USABLE_PORTS),
        };
        let nodes = [this_node(Some(small))];
        let mut lowered = stored.clone();
        lowered.max_connections = stored.max_connections - 1;
        assert!(check_write(&lowered, Some(&stored), others, &nodes, 2048).is_ok());
        let mut raised = stored.clone();
        raised.max_connections = stored.max_connections + 1;
        let refusal = check_write(&raised, Some(&stored), others, &nodes, 2048)
            .expect_err("more connections are more fds");
        assert_eq!(refusal.violation.constraint(), "worker_fds");
    }

    fn udp_on_private(id: &str, port: u16) -> Stream {
        Stream::new(
            id.into(),
            id.into(),
            StreamProtocol::Udp,
            "10.0.0.10".parse().expect("an address"),
            port,
            port,
            Utc::now(),
        )
    }

    #[test]
    fn the_api_refuses_exactly_what_the_node_would_for_udp_shares_of_the_source_ports() {
        // Six default UDP streams fill the default pool at the default
        // range; the seventh needs ports the node does not have.
        let six: Vec<Stream> = (0..6)
            .map(|n| udp_on_private(&format!("u{n}"), 5000 + n))
            .collect();
        let seventh = udp_on_private("u6", 6000);
        let nodes = [this_node(Some(PACKAGED))];
        assert!(check_write(&six[5], None, &six[..5], &nodes, 2048).is_ok());
        let refusal = check_write(&seventh, None, &six, &nodes, 2048)
            .expect_err("a seventh default UDP stream exceeds the source ports");
        assert_eq!(
            refusal.violation,
            BudgetViolation::SourcePorts {
                pool: lorica_stream::budget::SourcePool::Default,
                committed: 7 * 4096,
                usable: DEFAULT_RANGE_USABLE_PORTS
            }
        );
        let mut all: Vec<&Stream> = six.iter().collect();
        all.push(&seventh);
        assert_eq!(Err(refusal.violation), node_verdict(&all, PACKAGED, 2048));
        // A node that could not read its range checks its fds only.
        let unread = [this_node(Some(NodeFds {
            usable_source_ports: None,
            ..PACKAGED
        }))];
        assert!(check_write(&seventh, None, &six, &unread, 2048).is_ok());
    }

    #[test]
    fn a_node_past_its_source_port_ceiling_takes_writes_that_raise_nothing() {
        // Three default UDP streams on a range narrowed to 10,000 ports.
        let streams: Vec<Stream> = (0..3)
            .map(|n| udp_on_private(&format!("u{n}"), 5000 + n))
            .collect();
        let narrowed = [this_node(Some(NodeFds {
            usable_source_ports: Some(10_000),
            ..PACKAGED
        }))];
        let stored = &streams[0];
        let write =
            |candidate: &Stream| check_write(candidate, Some(stored), &streams, &narrowed, 2048);

        let mut moved = stored.clone();
        moved.port_first = 7000;
        moved.port_last = 7000;
        let mut lowered = stored.clone();
        lowered.udp.as_mut().expect("UDP settings").max_sessions = 1024;
        for candidate in [&moved, &lowered] {
            assert_eq!(write(candidate), Ok(Vec::new()), "{candidate:?}");
        }
        let mut raised = stored.clone();
        raised.udp.as_mut().expect("UDP settings").max_sessions = 4097;
        let refusal = write(&raised).expect_err("a raise is checked against the ports");
        assert_eq!(refusal.violation.constraint(), "source_ports");
        let message = refusal.into_error(&raised).to_string();
        assert!(
            message.contains("source_ports") && message.contains("10000"),
            "{message}"
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
        // The TCP port, the UDP ports per worker, the UDP caps memfd.
        assert_eq!(view.supervisor_fds_committed, 1 + 2 * 2 + 1);
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
        let plane = StreamPlaneState::new(states, 65_536, 2).with_usable_source_ports(Some(9_000));
        let streams = [
            stream(&uuid(1), StreamProtocol::Tcp, 5432, 5432),
            stream(&uuid(3), StreamProtocol::Udp, 6000, 6001),
        ];
        let usage = committed(&plane, NodeRole::Standalone, &streams);
        let report = heartbeat_report(&plane, usage);
        assert_eq!(lorica_cluster::stream_plane_report_defect(&report), None);
        assert_eq!(report.fd_limit, 65_536);
        assert_eq!(report.worker_count, 2);
        assert_eq!(report.usable_source_ports, Some(9_000));
        assert_eq!(
            heartbeat_report(&plane.clone().with_usable_source_ports(None), usage)
                .usable_source_ports,
            None,
            "a range the node cannot read is not reported, never guessed"
        );
        assert_eq!(report.listen_sockets_used, 3);
        let held = |s: &Stream| {
            lorica_stream::held_fds(s)
                .expect("each stream declares what it holds")
                .total()
        };
        assert_eq!(
            report.worker_fds_committed,
            3 + held(&streams[0]) + held(&streams[1])
        );
        assert_eq!(report.supervisor_fds_committed, 1 + 2 * 2 + 1);
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
            usable_source_ports: Some(10_000),
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
        let mut candidate = Stream {
            node_selector: vec!["edge-1".into()],
            ..stream("dns", StreamProtocol::Udp, 20_000, 20_999)
        };
        // Few enough sessions for one worker; the ports decide.
        candidate
            .udp
            .as_mut()
            .expect("a UDP stream carries its settings")
            .max_sessions = 16;
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
