// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The fd budget of Story 12.2 D-e, as pure arithmetic, and the view
//! types of `GET /api/v1/streams/budget`.
//!
//! From the process's soft `RLIMIT_NOFILE` `L`:
//!
//! - `B` = [`BASE_RESERVE`], the process's own plumbing;
//! - `H` = `L / 2`, the HTTP reserve, never usable by streams;
//! - `S` = `L - B - H`, the stream budget of one process.
//!
//! Three constraints hold for the streams a node binds:
//!
//! 1. their listening sockets (one per port) stay within the per-node
//!    `stream_listen_socket_cap` setting;
//! 2. in any one worker, listening sockets plus what the engines declare
//!    a stream may hold at its ceiling stay within `S`. Caps are per
//!    node, so the worst case puts every connection on one worker, and
//!    that is what is counted;
//! 3. in the supervisor, which keeps one socket per TCP port and one per
//!    worker slot per UDP port, `TCP ports + UDP ports x W` stays within
//!    `S`.
//!
//! What an engine holds per connection or session is a generic
//! [`HeldFds`] input (`ceiling x fds_per_unit`), declared by the
//! engine's own function and read by [`StreamDemand::of`]: Story 12.3
//! fills it for TCP; for UDP it stays absent and counts 0 until Story
//! 12.5 declares its own.

use chrono::{DateTime, Utc};
use lorica_config::models::{Stream, StreamProtocol};
use serde::{Deserialize, Serialize};

use crate::state::BindStateKind;

/// `B`: the fds held back for the process's own plumbing (databases, log
/// stores, channels, management and cluster sockets). A constant, not a
/// setting: an operator who wants more stream capacity raises
/// `LimitNOFILE`, which grows the stream budget and the HTTP reserve
/// together.
pub const BASE_RESERVE: u64 = 1024;

/// The budget figures of one process, derived from its fd limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdBudget {
    /// `L`: the process's soft `RLIMIT_NOFILE`.
    pub fd_limit: u64,
    /// `B`: [`BASE_RESERVE`].
    pub base_reserve: u64,
    /// `H`: `L / 2`, the HTTP reserve.
    pub http_reserve: u64,
    /// `S`: `L - B - H`, what the stream plane may use in one process;
    /// 0 when `L` is too small to leave anything.
    pub stream_budget: u64,
}

/// What an engine declares a stream may hold at its ceiling: a TCP
/// connection cap or a UDP session ceiling, times the fds each holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldFds {
    /// Connections (TCP) or sessions (UDP) the stream may hold on the node.
    pub ceiling: u64,
    /// Fds each connection or session holds.
    pub fds_per_unit: u64,
}

impl HeldFds {
    /// `ceiling x fds_per_unit`, saturating.
    pub fn total(&self) -> u64 {
        self.ceiling.saturating_mul(self.fds_per_unit)
    }
}

/// One stream's demand on the budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamDemand {
    /// The stream's id.
    pub stream_id: String,
    /// The stream's name.
    pub name: String,
    /// TCP or UDP.
    pub protocol: StreamProtocol,
    /// Listening sockets per process: one per port of the binding.
    pub listen_sockets: u64,
    /// What the engine declares, `None` until an engine declares it.
    pub held: Option<HeldFds>,
}

impl StreamDemand {
    /// The demand of `stream`: one listening socket per port, and what
    /// its engine declares it may hold at its cap
    /// ([`crate::tcp::held_fds`] for a TCP stream).
    ///
    /// The one demand function: the node's stream plane driver and the
    /// management API's write check both build their demands here, so
    /// the API never accepts a stream the node then refuses at bind with
    /// `fd_budget`.
    pub fn of(stream: &Stream) -> Self {
        StreamDemand {
            stream_id: stream.id.clone(),
            name: stream.name.clone(),
            protocol: stream.protocol,
            listen_sockets: u64::from(stream.port_last.saturating_sub(stream.port_first)) + 1,
            held: crate::tcp::held_fds(stream),
        }
    }

    /// The same demand with what its engine declares.
    pub fn with_held(mut self, held: HeldFds) -> Self {
        self.held = Some(held);
        self
    }

    /// What the stream costs one worker at its ceiling.
    pub fn worker_fds(&self) -> u64 {
        self.listen_sockets
            .saturating_add(self.held.map_or(0, |h| h.total()))
    }

    /// What the stream costs the supervisor with `workers` worker slots:
    /// one socket per TCP port, one per slot per UDP port.
    pub fn supervisor_fds(&self, workers: u32) -> u64 {
        match self.protocol {
            StreamProtocol::Tcp => self.listen_sockets,
            StreamProtocol::Udp => self.listen_sockets.saturating_mul(u64::from(workers)),
        }
    }
}

/// What a set of streams commits, against each constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetUsage {
    /// Listening sockets, one per port, against the per-node cap.
    pub listen_sockets_used: u64,
    /// Fds one worker holds at every stream's ceiling, against `S`.
    pub worker_fds_committed: u64,
    /// Fds the supervisor holds, against `S`.
    pub supervisor_fds_committed: u64,
}

/// The first constraint a set of streams breaks, with its numbers. The
/// caller names the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BudgetViolation {
    /// More listening sockets than `stream_listen_socket_cap`.
    #[error(
        "stream listening sockets: {used} exceed the node cap of {cap} (stream_listen_socket_cap)"
    )]
    ListenSocketCap {
        /// Listening sockets the streams would use.
        used: u64,
        /// The cap.
        cap: u64,
    },
    /// One worker would hold more than the stream budget.
    #[error(
        "worker fds: {committed} committed exceed the stream budget of {budget} \
         (fd limit {fd_limit}, HTTP reserve and base reserve excluded)"
    )]
    WorkerFds {
        /// Fds one worker would hold.
        committed: u64,
        /// `S`.
        budget: u64,
        /// `L`.
        fd_limit: u64,
    },
    /// The supervisor would hold more than the stream budget.
    #[error(
        "supervisor fds: {committed} committed (TCP ports + UDP ports x {workers} workers) \
         exceed the stream budget of {budget} (fd limit {fd_limit})"
    )]
    SupervisorFds {
        /// Fds the supervisor would hold.
        committed: u64,
        /// `S`.
        budget: u64,
        /// `L`.
        fd_limit: u64,
        /// Worker slots per UDP port.
        workers: u32,
    },
}

impl BudgetViolation {
    /// The constraint's machine name: `listen_socket_cap`, `worker_fds`
    /// or `supervisor_fds`.
    pub fn constraint(&self) -> &'static str {
        match self {
            BudgetViolation::ListenSocketCap { .. } => "listen_socket_cap",
            BudgetViolation::WorkerFds { .. } => "worker_fds",
            BudgetViolation::SupervisorFds { .. } => "supervisor_fds",
        }
    }
}

impl FdBudget {
    /// The budget of a process whose soft fd limit is `fd_limit`.
    pub fn from_limit(fd_limit: u64) -> Self {
        let http_reserve = fd_limit / 2;
        FdBudget {
            fd_limit,
            base_reserve: BASE_RESERVE,
            http_reserve,
            stream_budget: fd_limit
                .saturating_sub(BASE_RESERVE)
                .saturating_sub(http_reserve),
        }
    }

    /// What `streams` commit on a node of `workers` workers.
    pub fn usage(&self, streams: &[StreamDemand], workers: u32) -> BudgetUsage {
        streams
            .iter()
            .fold(BudgetUsage::default(), |acc, s| BudgetUsage {
                listen_sockets_used: acc.listen_sockets_used.saturating_add(s.listen_sockets),
                worker_fds_committed: acc.worker_fds_committed.saturating_add(s.worker_fds()),
                supervisor_fds_committed: acc
                    .supervisor_fds_committed
                    .saturating_add(s.supervisor_fds(workers)),
            })
    }

    /// Check `streams`, every stream the node would bind, against the
    /// three constraints, in the order of the module doc.
    ///
    /// # Errors
    ///
    /// The first [`BudgetViolation`].
    pub fn check(
        &self,
        streams: &[StreamDemand],
        workers: u32,
        listen_socket_cap: u32,
    ) -> Result<BudgetUsage, BudgetViolation> {
        let usage = self.usage(streams, workers);
        let cap = u64::from(listen_socket_cap);
        if usage.listen_sockets_used > cap {
            return Err(BudgetViolation::ListenSocketCap {
                used: usage.listen_sockets_used,
                cap,
            });
        }
        if usage.worker_fds_committed > self.stream_budget {
            return Err(BudgetViolation::WorkerFds {
                committed: usage.worker_fds_committed,
                budget: self.stream_budget,
                fd_limit: self.fd_limit,
            });
        }
        if usage.supervisor_fds_committed > self.stream_budget {
            return Err(BudgetViolation::SupervisorFds {
                committed: usage.supervisor_fds_committed,
                budget: self.stream_budget,
                fd_limit: self.fd_limit,
                workers,
            });
        }
        Ok(usage)
    }
}

/// The body of `GET /api/v1/streams/budget`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetView {
    /// One entry per node with a report: the local node standalone and
    /// on a follower, every reporting node on a control plane.
    pub nodes: Vec<NodeBudgetView>,
}

/// One node's budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeBudgetView {
    /// The node's cluster id, `None` on a standalone node.
    pub node_id: Option<String>,
    /// The node's roster name, `None` on a standalone node.
    pub node_name: Option<String>,
    /// When the figures were taken.
    pub reported_at: DateTime<Utc>,
    /// `L`.
    pub fd_limit: u64,
    /// `B`.
    pub base_reserve: u64,
    /// `H`.
    pub http_reserve: u64,
    /// `S`.
    pub stream_budget: u64,
    /// Workers on the node (1 in single-process mode).
    pub worker_count: u32,
    /// The `stream_listen_socket_cap` setting.
    pub listen_socket_cap: u32,
    /// See [`BudgetUsage::listen_sockets_used`].
    pub listen_sockets_used: u64,
    /// See [`BudgetUsage::worker_fds_committed`].
    pub worker_fds_committed: u64,
    /// See [`BudgetUsage::supervisor_fds_committed`].
    pub supervisor_fds_committed: u64,
    /// The `worker_drain_timeout_s` setting.
    pub worker_drain_timeout_s: u32,
    /// Each stream's share.
    pub streams: Vec<StreamBudgetView>,
}

/// One stream's share of a node's budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamBudgetView {
    /// The stream's id.
    pub id: String,
    /// The stream's name.
    pub name: String,
    /// TCP or UDP.
    pub protocol: StreamProtocol,
    /// See [`StreamDemand::listen_sockets`].
    pub listen_sockets: u64,
    /// The connection cap (TCP) or session ceiling (UDP), `null` until
    /// an engine declares it.
    pub ceiling: Option<u64>,
    /// Fds per connection or session, `null` until an engine declares it.
    pub fds_per_unit: Option<u64>,
    /// See [`StreamDemand::worker_fds`].
    pub fds_committed: u64,
    /// The stream's bind state on the node.
    pub bind_state: BindStateKind,
}

/// The node-level inputs of a [`NodeBudgetView`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeBudgetInputs {
    /// See [`NodeBudgetView::node_id`].
    pub node_id: Option<String>,
    /// See [`NodeBudgetView::node_name`].
    pub node_name: Option<String>,
    /// See [`NodeBudgetView::reported_at`].
    pub reported_at: DateTime<Utc>,
    /// The node's fd limit.
    pub fd_limit: u64,
    /// See [`NodeBudgetView::worker_count`].
    pub worker_count: u32,
    /// See [`NodeBudgetView::listen_socket_cap`].
    pub listen_socket_cap: u32,
    /// See [`NodeBudgetView::worker_drain_timeout_s`].
    pub worker_drain_timeout_s: u32,
}

impl NodeBudgetView {
    /// Build a node's view from its inputs and each stream it binds with
    /// its bind state.
    pub fn build(node: NodeBudgetInputs, streams: &[(StreamDemand, BindStateKind)]) -> Self {
        let budget = FdBudget::from_limit(node.fd_limit);
        let demands: Vec<StreamDemand> = streams.iter().map(|(d, _)| d.clone()).collect();
        let usage = budget.usage(&demands, node.worker_count);
        NodeBudgetView {
            node_id: node.node_id,
            node_name: node.node_name,
            reported_at: node.reported_at,
            fd_limit: budget.fd_limit,
            base_reserve: budget.base_reserve,
            http_reserve: budget.http_reserve,
            stream_budget: budget.stream_budget,
            worker_count: node.worker_count,
            listen_socket_cap: node.listen_socket_cap,
            listen_sockets_used: usage.listen_sockets_used,
            worker_fds_committed: usage.worker_fds_committed,
            supervisor_fds_committed: usage.supervisor_fds_committed,
            worker_drain_timeout_s: node.worker_drain_timeout_s,
            streams: streams
                .iter()
                .map(|(d, state)| StreamBudgetView {
                    id: d.stream_id.clone(),
                    name: d.name.clone(),
                    protocol: d.protocol,
                    listen_sockets: d.listen_sockets,
                    ceiling: d.held.map(|h| h.ceiling),
                    fds_per_unit: d.held.map(|h| h.fds_per_unit),
                    fds_committed: d.worker_fds(),
                    bind_state: *state,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The packaged unit's `LimitNOFILE`.
    const PACKAGED_LIMIT: u64 = 65_536;
    const DEFAULT_CAP: u32 = 2048;

    fn demand(id: &str, protocol: StreamProtocol, ports: u64) -> StreamDemand {
        StreamDemand {
            stream_id: id.into(),
            name: id.into(),
            protocol,
            listen_sockets: ports,
            held: None,
        }
    }

    #[test]
    fn packaged_limit_gives_the_documented_figures() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        assert_eq!(b.base_reserve, 1024);
        assert_eq!(b.http_reserve, 32_768);
        assert_eq!(b.stream_budget, 31_744);
        assert_eq!(
            b.stream_budget + b.http_reserve + b.base_reserve,
            PACKAGED_LIMIT
        );
    }

    #[test]
    fn a_limit_below_the_base_reserve_leaves_nothing() {
        let b = FdBudget::from_limit(1500);
        assert_eq!(b.stream_budget, 0);
        assert!(matches!(
            b.check(&[demand("s", StreamProtocol::Tcp, 1)], 1, DEFAULT_CAP),
            Err(BudgetViolation::WorkerFds { .. })
        ));
    }

    #[test]
    fn at_4096_a_wide_udp_range_breaks_the_supervisor_constraint_only_past_one_worker() {
        let b = FdBudget::from_limit(4096);
        assert_eq!(b.stream_budget, 1024);
        let range = [demand("udp", StreamProtocol::Udp, 1024)];
        let usage = b.check(&range, 1, DEFAULT_CAP).expect("one worker fits");
        assert_eq!(usage.supervisor_fds_committed, 1024);
        let err = b.check(&range, 2, DEFAULT_CAP).unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::SupervisorFds {
                committed: 2048,
                budget: 1024,
                fd_limit: 4096,
                workers: 2
            }
        );
        assert_eq!(err.constraint(), "supervisor_fds");
        assert!(err.to_string().contains("2 workers"), "{err}");
    }

    #[test]
    fn sixty_four_workers_hit_the_supervisor_constraint_at_the_packaged_limit() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let streams = [
            demand("tcp", StreamProtocol::Tcp, 100),
            demand("udp", StreamProtocol::Udp, 495),
        ];
        // 100 + 495 x 64 = 31,780 > 31,744; one worker holds 595.
        let err = b.check(&streams, 64, DEFAULT_CAP).unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::SupervisorFds {
                committed: 31_780,
                budget: 31_744,
                fd_limit: PACKAGED_LIMIT,
                workers: 64
            }
        );
        // One port fewer fits: 100 + 494 x 64 = 31,716.
        let fewer = [
            demand("tcp", StreamProtocol::Tcp, 100),
            demand("udp", StreamProtocol::Udp, 494),
        ];
        let usage = b.check(&fewer, 64, DEFAULT_CAP).expect("fits");
        assert_eq!(usage.supervisor_fds_committed, 31_716);
        assert_eq!(usage.worker_fds_committed, 594);
    }

    #[test]
    fn declared_fds_per_unit_count_against_one_worker() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let base = demand("tcp", StreamProtocol::Tcp, 1);
        for (fds_per_unit, committed, fits) in
            [(1, 12_001, true), (2, 24_001, true), (3, 36_001, false)]
        {
            let s = base.clone().with_held(HeldFds {
                ceiling: 12_000,
                fds_per_unit,
            });
            assert_eq!(s.worker_fds(), committed);
            let verdict = b.check(&[s], 8, DEFAULT_CAP);
            assert_eq!(verdict.is_ok(), fits, "fds_per_unit {fds_per_unit}");
            if !fits {
                assert_eq!(
                    verdict.unwrap_err(),
                    BudgetViolation::WorkerFds {
                        committed,
                        budget: 31_744,
                        fd_limit: PACKAGED_LIMIT
                    }
                );
            }
        }
        // Nothing declared counts nothing beyond the listening socket.
        assert_eq!(base.worker_fds(), 1);
    }

    #[test]
    fn the_listen_socket_cap_counts_ports() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let streams = [
            demand("a", StreamProtocol::Tcp, 1024),
            demand("b", StreamProtocol::Tcp, 1024),
        ];
        assert!(b.check(&streams, 1, 2048).is_ok());
        let err = b.check(&streams, 1, 2047).unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::ListenSocketCap {
                used: 2048,
                cap: 2047
            }
        );
        assert_eq!(err.constraint(), "listen_socket_cap");
    }

    #[test]
    fn saturating_inputs_never_overflow() {
        let b = FdBudget::from_limit(u64::MAX);
        let s = demand("udp", StreamProtocol::Udp, u64::MAX).with_held(HeldFds {
            ceiling: u64::MAX,
            fds_per_unit: u64::MAX,
        });
        assert_eq!(s.worker_fds(), u64::MAX);
        assert!(b.check(&[s.clone(), s], u32::MAX, u32::MAX).is_err());
    }

    #[test]
    fn node_view_matches_the_documented_shape() {
        let streams = [
            (demand("pg", StreamProtocol::Tcp, 1), BindStateKind::Bound),
            (
                demand("dns", StreamProtocol::Udp, 2).with_held(HeldFds {
                    ceiling: 100,
                    fds_per_unit: 1,
                }),
                BindStateKind::Failed,
            ),
        ];
        let view = NodeBudgetView::build(
            NodeBudgetInputs {
                node_id: Some("<UUID>".into()),
                node_name: Some("edge01".into()),
                reported_at: DateTime::parse_from_rfc3339("2026-11-14T10:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                fd_limit: PACKAGED_LIMIT,
                worker_count: 8,
                listen_socket_cap: DEFAULT_CAP,
                worker_drain_timeout_s: 30,
            },
            &streams,
        );
        assert_eq!(view.listen_sockets_used, 3);
        assert_eq!(view.worker_fds_committed, 103);
        assert_eq!(view.supervisor_fds_committed, 17);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["stream_budget"], 31_744);
        assert_eq!(json["streams"][0]["ceiling"], serde_json::Value::Null);
        assert_eq!(json["streams"][0]["fds_per_unit"], serde_json::Value::Null);
        assert_eq!(json["streams"][0]["bind_state"], "bound");
        assert_eq!(json["streams"][0]["protocol"], "tcp");
        assert_eq!(json["streams"][1]["ceiling"], 100);
        assert_eq!(json["streams"][1]["fds_committed"], 102);
        let back: NodeBudgetView = serde_json::from_value(json).unwrap();
        assert_eq!(back, view);
    }
}
