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

//! The fd budget of Story 12.2 D-e and the UDP session ceiling of Story
//! 12.5 D-e, as pure arithmetic, and the view types of
//! `GET /api/v1/streams/budget`.
//!
//! From the process's soft `RLIMIT_NOFILE` `L`:
//!
//! - `B` = [`BASE_RESERVE`], the process's own plumbing;
//! - `H` = `L / 2`, the HTTP reserve, never usable by streams;
//! - `S` = `L - B - H`, the stream budget of one process.
//!
//! Four constraints hold for the streams a node binds:
//!
//! 1. their listening sockets (one per port) stay within the per-node
//!    `stream_listen_socket_cap` setting;
//! 2. in any one worker, listening sockets plus what the engines declare
//!    a stream may hold at its ceiling stay within `S`. Caps are per
//!    node, so the worst case puts every connection or session on one
//!    worker, and that is what is counted;
//! 3. in the supervisor, which keeps one socket per TCP port, one per
//!    worker slot per UDP port and the caps memfd of each UDP stream,
//!    `TCP ports + UDP ports x W + UDP streams` stays within `S`;
//! 4. per source pool (each address of any UDP stream's
//!    `source_addresses`, and one `default` pool for the UDP streams
//!    without any), the UDP sessions that leave from it stay within `U`,
//!    the usable ephemeral ports per source address
//!    (`lorica_worker::stream_sockets::usable_udp_source_ports`): every
//!    session holds one connected upstream socket, hence one port. A
//!    stream with several source addresses spreads its sessions evenly,
//!    `ceil(max_sessions / addresses)` on each. TCP connections do not
//!    count here: TCP ports are a separate space.
//!
//! What an engine holds per connection or session is a generic
//! [`HeldFds`] input (`ceiling x fds_per_unit`), declared by [`held_fds`],
//! the one function [`StreamDemand::of`] reads: `max_connections` x 2 for
//! TCP (Story 12.3 D-p), `udp.max_sessions` x 1 for UDP.
//!
//! The node's UDP session ceiling is `min(S - other committed fds,
//! U x pools)`, reported with the limit that bound it. Each UDP stream's
//! share is its `max_sessions`; constraints 2 and 4 refuse shares that
//! add up past the ceiling.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use lorica_config::models::{Stream, StreamProtocol};
use serde::{Deserialize, Serialize};

use crate::state::BindStateKind;

/// `U` as the host reports it now. Re-exported so the management API,
/// which does not depend on `lorica-worker` directly, reads the very
/// figure the node's driver checks its binds against.
pub use lorica_worker::stream_sockets::usable_udp_source_ports;

/// `B`: the fds held back for the process's own plumbing (databases, log
/// stores, channels, management and cluster sockets). A constant, not a
/// setting: an operator who wants more stream capacity raises
/// `LimitNOFILE`, which grows the stream budget and the HTTP reserve
/// together.
pub const BASE_RESERVE: u64 = 1024;

/// Fds one UDP session holds: its connected upstream socket. No
/// client-side socket exists (Story 12.5 D-a).
pub const UDP_FDS_PER_SESSION: u64 = 1;

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

/// What `stream` may hold at its cap, for the fd budget: the one
/// definition for both protocols, dispatching to
/// [`crate::tcp::held_fds`] for TCP and declaring `udp.max_sessions`
/// sessions of [`UDP_FDS_PER_SESSION`] for UDP. `None` for a UDP stream
/// without its `udp` settings, which validation never stores.
pub fn held_fds(stream: &Stream) -> Option<HeldFds> {
    match stream.protocol {
        StreamProtocol::Tcp => crate::tcp::held_fds(stream),
        StreamProtocol::Udp => stream.udp.as_ref().map(|udp| HeldFds {
            ceiling: u64::from(udp.max_sessions),
            fds_per_unit: UDP_FDS_PER_SESSION,
        }),
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
    /// The source addresses a UDP stream's sessions leave from; empty
    /// for the `default` pool, and on TCP, whose connections take no
    /// UDP port.
    pub source_addresses: Vec<IpAddr>,
}

impl StreamDemand {
    /// The demand of `stream`: one listening socket per port, what
    /// [`held_fds`] declares it may hold at its cap, and for UDP the
    /// source pools its sessions take ports from.
    ///
    /// The one demand function: the node's stream plane driver and the
    /// management API's write check both build their demands here, so
    /// the API never accepts a stream the node then refuses at bind.
    pub fn of(stream: &Stream) -> Self {
        StreamDemand {
            stream_id: stream.id.clone(),
            name: stream.name.clone(),
            protocol: stream.protocol,
            listen_sockets: u64::from(stream.port_last.saturating_sub(stream.port_first)) + 1,
            held: held_fds(stream),
            source_addresses: match stream.protocol {
                StreamProtocol::Tcp => Vec::new(),
                StreamProtocol::Udp => stream.source_addresses.clone(),
            },
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
    /// one socket per TCP port; one per slot per UDP port, plus the
    /// stream's caps memfd.
    pub fn supervisor_fds(&self, workers: u32) -> u64 {
        match self.protocol {
            StreamProtocol::Tcp => self.listen_sockets,
            StreamProtocol::Udp => self
                .listen_sockets
                .saturating_mul(u64::from(workers))
                .saturating_add(1),
        }
    }

    /// The UDP sessions the stream may hold on the node, its share of
    /// the session ceiling; 0 on TCP.
    pub fn udp_sessions(&self) -> u64 {
        match self.protocol {
            StreamProtocol::Tcp => 0,
            StreamProtocol::Udp => self.held.map_or(0, |h| h.ceiling),
        }
    }

    /// The ports the stream's sessions take from each of its source
    /// pools: `ceil(sessions / pools)` on each, sessions spreading
    /// evenly over its addresses. Empty on TCP.
    pub fn pool_shares(&self) -> Vec<(SourcePool, u64)> {
        if self.protocol != StreamProtocol::Udp {
            return Vec::new();
        }
        let pools: BTreeSet<SourcePool> = if self.source_addresses.is_empty() {
            BTreeSet::from([SourcePool::Default])
        } else {
            self.source_addresses
                .iter()
                .copied()
                .map(SourcePool::Address)
                .collect()
        };
        let share = self.udp_sessions().div_ceil(pools.len() as u64);
        pools.into_iter().map(|pool| (pool, share)).collect()
    }

    /// Whether this demand asks more of a node than `stored` did: another
    /// protocol, more listening sockets, more fds at its ceiling, or more
    /// ports from any source pool. A write that raises nothing is never
    /// refused for the budget, so a node already over its ceiling (a
    /// narrowed port range, a lowered fd limit) can still have its
    /// streams edited, lowered or narrowed ([`FdBudget::check_change`]).
    pub fn raises(&self, stored: &StreamDemand) -> bool {
        if self.protocol != stored.protocol
            || self.listen_sockets > stored.listen_sockets
            || self.worker_fds() > stored.worker_fds()
        {
            return true;
        }
        let before: BTreeMap<SourcePool, u64> = stored.pool_shares().into_iter().collect();
        self.pool_shares()
            .into_iter()
            .any(|(pool, share)| share > before.get(&pool).copied().unwrap_or(0))
    }
}

/// Where a UDP session's upstream socket takes its ephemeral port from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourcePool {
    /// The kernel's choice of source address, for the streams without
    /// `source_addresses`.
    Default,
    /// One address of a stream's `source_addresses`.
    Address(IpAddr),
}

impl fmt::Display for SourcePool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SourcePool::Default => f.write_str("default"),
            SourcePool::Address(ip) => write!(f, "{ip}"),
        }
    }
}

/// The ports the UDP streams of a node commit in each source pool, in
/// pool order (`default` first, then by address).
pub fn source_pool_usage(streams: &[StreamDemand]) -> Vec<(SourcePool, u64)> {
    let mut pools: BTreeMap<SourcePool, u64> = BTreeMap::new();
    for (pool, share) in streams.iter().flat_map(StreamDemand::pool_shares) {
        let committed = pools.entry(pool).or_default();
        *committed = committed.saturating_add(share);
    }
    pools.into_iter().collect()
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
        "supervisor fds: {committed} committed (TCP ports + UDP ports x {workers} workers \
         + one caps memfd per UDP stream) exceed the stream budget of {budget} \
         (fd limit {fd_limit})"
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
    /// The UDP sessions leaving from one source pool would need more
    /// ephemeral ports than it has.
    #[error(
        "source ports: {committed} UDP sessions committed on source pool {pool} exceed its \
         {usable} usable ephemeral ports (lower udp.max_sessions, add source_addresses, \
         or widen net.ipv4.ip_local_port_range)"
    )]
    SourcePorts {
        /// The pool.
        pool: SourcePool,
        /// Sessions the streams would hold on it.
        committed: u64,
        /// `U`.
        usable: u64,
    },
}

impl BudgetViolation {
    /// The constraint's machine name: `listen_socket_cap`, `worker_fds`,
    /// `supervisor_fds` or `source_ports`.
    pub fn constraint(&self) -> &'static str {
        match self {
            BudgetViolation::ListenSocketCap { .. } => "listen_socket_cap",
            BudgetViolation::WorkerFds { .. } => "worker_fds",
            BudgetViolation::SupervisorFds { .. } => "supervisor_fds",
            BudgetViolation::SourcePorts { .. } => "source_ports",
        }
    }
}

/// What bound a node's UDP session ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeilingBound {
    /// The fds left in `S` after every other stream's commitment.
    FdBudget,
    /// The usable ephemeral ports times the source pools.
    SourcePorts,
}

/// A node's UDP session ceiling and the limit that bound it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionCeiling {
    /// Sessions the node can hold across its UDP streams.
    pub sessions: u64,
    /// The limit that set `sessions`.
    pub bound_by: CeilingBound,
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
    /// three fd constraints, in the order of the module doc.
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

    /// [`FdBudget::check`], then the source-port constraint against
    /// `usable_source_ports` (`U`), every pool in order. `None` when the
    /// node could not read its port range, which leaves the fd
    /// constraints only: the figure is never guessed.
    ///
    /// # Errors
    ///
    /// The first [`BudgetViolation`].
    pub fn check_node(
        &self,
        streams: &[StreamDemand],
        workers: u32,
        listen_socket_cap: u32,
        usable_source_ports: Option<u64>,
    ) -> Result<BudgetUsage, BudgetViolation> {
        let usage = self.check(streams, workers, listen_socket_cap)?;
        if let Some(usable) = usable_source_ports {
            if let Some((pool, committed)) = source_pool_usage(streams)
                .into_iter()
                .find(|(_, committed)| *committed > usable)
            {
                return Err(BudgetViolation::SourcePorts {
                    pool,
                    committed,
                    usable,
                });
            }
        }
        Ok(usage)
    }

    /// The check of one stream's change on a node, "refuse raises, allow
    /// lowers" (Story 12.5 D-e): the one rule the management API's write
    /// check and the node's bind both apply, so neither refuses what the
    /// other lets through for want of the other's exemption.
    ///
    /// `candidate` is the stream's demand as it will stand, `stored` what
    /// the node already counts for it (`None` for a stream the node does
    /// not hold), `others` every other stream the node binds. A change
    /// that raises nothing over `stored` ([`StreamDemand::raises`])
    /// passes unchecked, so a node already past its ceiling (a narrowed
    /// port range, a lowered fd limit) can still have its streams
    /// renamed, rebound, lowered or narrowed; any other change is
    /// [`FdBudget::check_node`] over `others` and `candidate`.
    ///
    /// # Errors
    ///
    /// The first [`BudgetViolation`] of a change that raises the demand.
    pub fn check_change(
        &self,
        candidate: &StreamDemand,
        stored: Option<&StreamDemand>,
        others: &[StreamDemand],
        workers: u32,
        listen_socket_cap: u32,
        usable_source_ports: Option<u64>,
    ) -> Result<(), BudgetViolation> {
        if stored.is_some_and(|stored| !candidate.raises(stored)) {
            return Ok(());
        }
        let demands: Vec<StreamDemand> = others
            .iter()
            .cloned()
            .chain(std::iter::once(candidate.clone()))
            .collect();
        self.check_node(&demands, workers, listen_socket_cap, usable_source_ports)
            .map(|_| ())
    }

    /// The node's UDP session ceiling for `streams`: what `S` leaves
    /// after every listening socket and every TCP stream's held fds, in
    /// sessions of [`UDP_FDS_PER_SESSION`], and at most `U` per source
    /// pool the UDP streams use (one, `default`, when they use none). On
    /// a tie the fd budget is named. Without `U` the fds alone bound it.
    pub fn session_ceiling(
        &self,
        streams: &[StreamDemand],
        usable_source_ports: Option<u64>,
    ) -> SessionCeiling {
        let other = streams.iter().fold(0u64, |acc, s| {
            let udp_fds = s.udp_sessions().saturating_mul(UDP_FDS_PER_SESSION);
            acc.saturating_add(s.worker_fds().saturating_sub(udp_fds))
        });
        let by_fds = self.stream_budget.saturating_sub(other) / UDP_FDS_PER_SESSION;
        let Some(usable) = usable_source_ports else {
            return SessionCeiling {
                sessions: by_fds,
                bound_by: CeilingBound::FdBudget,
            };
        };
        let pools = source_pool_usage(streams).len().max(1) as u64;
        let by_ports = usable.saturating_mul(pools);
        if by_ports < by_fds {
            SessionCeiling {
                sessions: by_ports,
                bound_by: CeilingBound::SourcePorts,
            }
        } else {
            SessionCeiling {
                sessions: by_fds,
                bound_by: CeilingBound::FdBudget,
            }
        }
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
    /// `U`, the usable UDP source ports per source address; `None` when
    /// the node could not read (or has not reported) its port range.
    pub usable_source_ports: Option<u64>,
    /// See [`SessionCeiling::sessions`].
    pub session_ceiling: u64,
    /// See [`SessionCeiling::bound_by`].
    pub session_ceiling_bound_by: CeilingBound,
    /// The UDP streams' shares added up: their `udp.max_sessions`.
    pub udp_sessions_committed: u64,
    /// Whether the committed UDP sessions pass the ceiling or a source
    /// pool's ports, as a narrowed port range or a lowered fd limit
    /// leaves a node: bound streams stay bound, and every change that
    /// raises the demand is refused until it fits again.
    pub over_ceiling: bool,
    /// The ports each source pool commits.
    pub source_pools: Vec<SourcePoolView>,
    /// Each stream's share.
    pub streams: Vec<StreamBudgetView>,
}

/// One source pool's ports on a node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePoolView {
    /// `default`, or the source address.
    pub pool: String,
    /// The sessions the UDP streams leaving from it may hold.
    pub committed: u64,
    /// `U`, `None` as [`NodeBudgetView::usable_source_ports`].
    pub usable: Option<u64>,
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
    /// The connection cap (TCP) or the stream's share of the session
    /// ceiling (UDP, `udp.max_sessions`), `null` until an engine
    /// declares it.
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
    /// See [`NodeBudgetView::usable_source_ports`].
    pub usable_source_ports: Option<u64>,
}

impl NodeBudgetView {
    /// Build a node's view from its inputs and each stream it binds with
    /// its bind state.
    pub fn build(node: NodeBudgetInputs, streams: &[(StreamDemand, BindStateKind)]) -> Self {
        let budget = FdBudget::from_limit(node.fd_limit);
        let demands: Vec<StreamDemand> = streams.iter().map(|(d, _)| d.clone()).collect();
        let usage = budget.usage(&demands, node.worker_count);
        let ceiling = budget.session_ceiling(&demands, node.usable_source_ports);
        let udp_sessions_committed = demands
            .iter()
            .fold(0u64, |acc, d| acc.saturating_add(d.udp_sessions()));
        let pools = source_pool_usage(&demands);
        let pool_over = node
            .usable_source_ports
            .is_some_and(|usable| pools.iter().any(|(_, committed)| *committed > usable));
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
            usable_source_ports: node.usable_source_ports,
            session_ceiling: ceiling.sessions,
            session_ceiling_bound_by: ceiling.bound_by,
            udp_sessions_committed,
            over_ceiling: udp_sessions_committed > ceiling.sessions || pool_over,
            source_pools: pools
                .into_iter()
                .map(|(pool, committed)| SourcePoolView {
                    pool: pool.to_string(),
                    committed,
                    usable: node.usable_source_ports,
                })
                .collect(),
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
    use lorica_config::models::UdpSettings;

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
            source_addresses: Vec::new(),
        }
    }

    /// `U` at the kernel's default `ip_local_port_range` (32768 to
    /// 60999) with nothing reserved, through Lot A's arithmetic.
    fn default_usable_ports() -> u64 {
        u64::from(
            lorica_worker::stream_sockets::usable_source_ports_from("32768\t60999\n", "\n")
                .expect("the default range parses"),
        )
    }

    fn udp_stream(id: &str, port: u16) -> Stream {
        Stream::new(
            id.into(),
            id.into(),
            StreamProtocol::Udp,
            "10.0.0.10".parse().unwrap(),
            port,
            port,
            Utc::now(),
        )
    }

    fn inputs(fd_limit: u64, usable_source_ports: Option<u64>) -> NodeBudgetInputs {
        NodeBudgetInputs {
            node_id: None,
            node_name: None,
            reported_at: Utc::now(),
            fd_limit,
            worker_count: 8,
            listen_socket_cap: DEFAULT_CAP,
            worker_drain_timeout_s: 30,
            usable_source_ports,
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
        // 1,023 ports and the stream's caps memfd.
        let range = [demand("udp", StreamProtocol::Udp, 1023)];
        let usage = b.check(&range, 1, DEFAULT_CAP).expect("one worker fits");
        assert_eq!(usage.supervisor_fds_committed, 1024);
        let err = b.check(&range, 2, DEFAULT_CAP).unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::SupervisorFds {
                committed: 2047,
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
        // 100 + 495 x 64 + 1 memfd = 31,781 > 31,744; one worker holds 595.
        let err = b.check(&streams, 64, DEFAULT_CAP).unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::SupervisorFds {
                committed: 31_781,
                budget: 31_744,
                fd_limit: PACKAGED_LIMIT,
                workers: 64
            }
        );
        // One port fewer fits: 100 + 494 x 64 + 1 = 31,717.
        let fewer = [
            demand("tcp", StreamProtocol::Tcp, 100),
            demand("udp", StreamProtocol::Udp, 494),
        ];
        let usage = b.check(&fewer, 64, DEFAULT_CAP).expect("fits");
        assert_eq!(usage.supervisor_fds_committed, 31_717);
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
        assert!(b
            .check(&[s.clone(), s.clone()], u32::MAX, u32::MAX)
            .is_err());
        assert!(b
            .check_node(&[s.clone(), s.clone()], 1, u32::MAX, Some(u64::MAX))
            .is_err());
        let ceiling = b.session_ceiling(&[s.clone(), s], Some(u64::MAX));
        assert_eq!(ceiling.bound_by, CeilingBound::FdBudget);
    }

    #[test]
    fn a_udp_stream_declares_one_fd_per_session_and_its_source_pools() {
        let mut s = udp_stream("dns", 53);
        s.source_addresses = vec!["10.0.0.11".parse().unwrap(), "10.0.0.12".parse().unwrap()];
        assert_eq!(
            held_fds(&s),
            Some(HeldFds {
                ceiling: u64::from(UdpSettings::DEFAULT_MAX_SESSIONS),
                fds_per_unit: UDP_FDS_PER_SESSION
            })
        );
        let d = StreamDemand::of(&s);
        assert_eq!(d.held, held_fds(&s));
        assert_eq!(d.worker_fds(), 1 + 4096);
        assert_eq!(d.supervisor_fds(8), 8 + 1, "the slots and the caps memfd");
        assert_eq!(
            d.pool_shares(),
            vec![
                (SourcePool::Address("10.0.0.11".parse().unwrap()), 2048),
                (SourcePool::Address("10.0.0.12".parse().unwrap()), 2048)
            ]
        );
        // Odd sessions round up on every address.
        s.udp.as_mut().unwrap().max_sessions = 4097;
        let odd = StreamDemand::of(&s);
        assert!(odd.pool_shares().iter().all(|(_, share)| *share == 2049));

        // A TCP stream keeps 12.3's declaration and takes no UDP port.
        let mut tcp = udp_stream("pg", 5432);
        tcp.protocol = StreamProtocol::Tcp;
        tcp.udp = None;
        tcp.source_addresses = vec!["10.0.0.11".parse().unwrap()];
        assert_eq!(held_fds(&tcp), crate::tcp::held_fds(&tcp));
        let tcp = StreamDemand::of(&tcp);
        assert!(tcp.pool_shares().is_empty());
        assert_eq!(tcp.udp_sessions(), 0);
        assert_eq!(tcp.supervisor_fds(8), 1);
    }

    #[test]
    fn six_default_udp_streams_fit_and_the_seventh_breaks_the_source_ports() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let usable = default_usable_ports();
        assert_eq!(usable, 27_208);
        let streams: Vec<StreamDemand> = (0..7)
            .map(|n| StreamDemand::of(&udp_stream(&format!("u{n}"), 5000 + n)))
            .collect();
        let six = &streams[..6];
        let usage = b
            .check_node(six, 8, DEFAULT_CAP, Some(usable))
            .expect("six default UDP streams fit");
        assert_eq!(usage.worker_fds_committed, 6 * 4097);
        assert_eq!(usage.supervisor_fds_committed, 6 * (8 + 1));
        // The fds alone would still admit the seventh: 7 x 4,097 = 28,679
        // fits in 31,744; the ports do not.
        assert!(b.check(&streams, 8, DEFAULT_CAP).is_ok());
        let err = b
            .check_node(&streams, 8, DEFAULT_CAP, Some(usable))
            .unwrap_err();
        assert_eq!(
            err,
            BudgetViolation::SourcePorts {
                pool: SourcePool::Default,
                committed: 7 * 4096,
                usable: 27_208
            }
        );
        assert_eq!(err.constraint(), "source_ports");
        let text = err.to_string();
        assert!(text.contains("default") && text.contains("28672"), "{text}");
        assert!(text.contains("source_addresses"), "{text}");
        // Without the port figure, only the fds are checked.
        assert!(b.check_node(&streams, 8, DEFAULT_CAP, None).is_ok());

        let ceiling = b.session_ceiling(six, Some(usable));
        assert_eq!(
            ceiling,
            SessionCeiling {
                sessions: 27_208,
                bound_by: CeilingBound::SourcePorts
            }
        );
    }

    #[test]
    fn a_seventh_stream_with_two_source_addresses_fits_in_their_pools() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let usable = default_usable_ports();
        let mut streams: Vec<StreamDemand> = (0..6)
            .map(|n| StreamDemand::of(&udp_stream(&format!("u{n}"), 5000 + n)))
            .collect();
        let mut spread = udp_stream("spread", 6000);
        spread.source_addresses = vec!["10.0.0.11".parse().unwrap(), "10.0.0.12".parse().unwrap()];
        streams.push(StreamDemand::of(&spread));
        assert!(b.check_node(&streams, 8, DEFAULT_CAP, Some(usable)).is_ok());
        assert_eq!(
            source_pool_usage(&streams),
            vec![
                (SourcePool::Default, 6 * 4096),
                (SourcePool::Address("10.0.0.11".parse().unwrap()), 2048),
                (SourcePool::Address("10.0.0.12".parse().unwrap()), 2048),
            ]
        );
        // Three pools: 3 x 27,208 ports, more than the 31,744 - 7 fds
        // left after the listening sockets.
        assert_eq!(
            b.session_ceiling(&streams, Some(usable)),
            SessionCeiling {
                sessions: 31_744 - 7,
                bound_by: CeilingBound::FdBudget
            }
        );
    }

    #[test]
    fn tcp_streams_lower_the_fd_ceiling_and_not_the_ports() {
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let tcp = demand("pg", StreamProtocol::Tcp, 1).with_held(HeldFds {
            ceiling: 10_000,
            fds_per_unit: 2,
        });
        let udp = StreamDemand::of(&udp_stream("dns", 53));
        let ceiling = b.session_ceiling(&[tcp, udp], Some(27_208));
        // 31,744 - (1 + 20,000) - 1 listening socket of the UDP stream.
        assert_eq!(
            ceiling,
            SessionCeiling {
                sessions: 11_742,
                bound_by: CeilingBound::FdBudget
            }
        );
    }

    #[test]
    fn a_narrowed_port_range_flags_the_node_and_only_raises_are_refused() {
        let streams: Vec<(StreamDemand, BindStateKind)> = (0..3)
            .map(|n| {
                (
                    StreamDemand::of(&udp_stream(&format!("u{n}"), 5000 + n)),
                    BindStateKind::Bound,
                )
            })
            .collect();
        let view = NodeBudgetView::build(inputs(PACKAGED_LIMIT, Some(10_000)), &streams);
        assert!(view.over_ceiling);
        assert_eq!(view.udp_sessions_committed, 3 * 4096);
        assert_eq!(view.session_ceiling, 10_000);
        assert_eq!(view.session_ceiling_bound_by, CeilingBound::SourcePorts);
        assert_eq!(
            view.source_pools,
            vec![SourcePoolView {
                pool: "default".into(),
                committed: 12_288,
                usable: Some(10_000)
            }]
        );
        let wide = NodeBudgetView::build(inputs(PACKAGED_LIMIT, Some(27_208)), &streams);
        assert!(!wide.over_ceiling);

        let stored = udp_stream("u0", 5000);
        let mut lowered = stored.clone();
        lowered.udp.as_mut().unwrap().max_sessions = 1024;
        let mut raised = stored.clone();
        raised.udp.as_mut().unwrap().max_sessions = 8192;
        let mut renamed = stored.clone();
        renamed.name = "renamed".into();
        let mut narrowed_pools = stored.clone();
        narrowed_pools.source_addresses = vec!["10.0.0.11".parse().unwrap()];
        let was = StreamDemand::of(&stored);
        assert!(!StreamDemand::of(&lowered).raises(&was));
        assert!(!StreamDemand::of(&renamed).raises(&was));
        assert!(StreamDemand::of(&raised).raises(&was));
        assert!(
            StreamDemand::of(&narrowed_pools).raises(&was),
            "a pool the stream did not use is new demand"
        );
        let mut to_tcp = stored.clone();
        to_tcp.protocol = StreamProtocol::Tcp;
        to_tcp.udp = None;
        assert!(StreamDemand::of(&to_tcp).raises(&was));
        let mut one_address = stored.clone();
        one_address.source_addresses = vec!["10.0.0.11".parse().unwrap()];
        let mut two_addresses = one_address.clone();
        two_addresses
            .source_addresses
            .push("10.0.0.12".parse().unwrap());
        let mut two_lowered = two_addresses.clone();
        two_lowered.udp.as_mut().unwrap().max_sessions = 2048;
        assert!(
            !StreamDemand::of(&two_lowered).raises(&StreamDemand::of(&two_addresses)),
            "a lower share on the same pools"
        );
        assert!(
            StreamDemand::of(&two_addresses).raises(&StreamDemand::of(&one_address)),
            "a pool the stream did not use is new demand, though its share elsewhere falls"
        );
        assert!(
            StreamDemand::of(&one_address).raises(&StreamDemand::of(&two_addresses)),
            "fewer addresses raise the share of each one left"
        );
    }

    #[test]
    fn a_change_is_checked_only_when_it_raises_what_the_node_counts() {
        // Three default streams on a range narrowed to 10,000 ports: the
        // node is past its ceiling, and each stream on its own fits.
        let b = FdBudget::from_limit(PACKAGED_LIMIT);
        let narrowed = Some(10_000);
        let others: Vec<StreamDemand> = (1..3)
            .map(|n| StreamDemand::of(&udp_stream(&format!("u{n}"), 5000 + n)))
            .collect();
        let stored = udp_stream("u0", 5000);
        let was = StreamDemand::of(&stored);
        let check = |candidate: &Stream, stored: Option<&StreamDemand>| {
            b.check_change(
                &StreamDemand::of(candidate),
                stored,
                &others,
                8,
                DEFAULT_CAP,
                narrowed,
            )
        };

        let mut rebound = stored.clone();
        rebound.listen_address = "10.0.0.20".parse().unwrap();
        let mut lowered = stored.clone();
        lowered.udp.as_mut().unwrap().max_sessions = 2048;
        for unchanged_or_lower in [&stored, &rebound, &lowered] {
            assert_eq!(check(unchanged_or_lower, Some(&was)), Ok(()));
        }

        let mut raised = stored.clone();
        raised.udp.as_mut().unwrap().max_sessions = 4097;
        let refusal = check(&raised, Some(&was)).expect_err("a raise is checked");
        assert_eq!(
            refusal,
            BudgetViolation::SourcePorts {
                pool: SourcePool::Default,
                committed: 2 * 4096 + 4097,
                usable: 10_000
            }
        );
        assert_eq!(
            check(&stored, None),
            Err(BudgetViolation::SourcePorts {
                pool: SourcePool::Default,
                committed: 3 * 4096,
                usable: 10_000
            }),
            "a stream the node does not hold yet is all new demand"
        );
        // The rule refuses what does not fit, not every raise: from 1,024
        // sessions, a raise to the 1,808 the narrowed range leaves fits,
        // one more does not.
        let mut small = stored.clone();
        small.udp.as_mut().unwrap().max_sessions = 1024;
        let small = StreamDemand::of(&small);
        raised.udp.as_mut().unwrap().max_sessions = 1808;
        assert_eq!(check(&raised, Some(&small)), Ok(()));
        raised.udp.as_mut().unwrap().max_sessions = 1809;
        assert!(check(&raised, Some(&small)).is_err());
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
                usable_source_ports: Some(27_208),
            },
            &streams,
        );
        assert_eq!(view.listen_sockets_used, 3);
        assert_eq!(view.worker_fds_committed, 103);
        assert_eq!(view.supervisor_fds_committed, 1 + 2 * 8 + 1);
        assert_eq!(view.udp_sessions_committed, 100);
        assert!(!view.over_ceiling);
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["stream_budget"], 31_744);
        assert_eq!(json["usable_source_ports"], 27_208);
        assert_eq!(json["session_ceiling"], 27_208);
        assert_eq!(json["session_ceiling_bound_by"], "source_ports");
        assert_eq!(json["over_ceiling"], false);
        assert_eq!(json["source_pools"][0]["pool"], "default");
        assert_eq!(json["source_pools"][0]["committed"], 100);
        assert_eq!(json["streams"][0]["ceiling"], serde_json::Value::Null);
        assert_eq!(json["streams"][0]["fds_per_unit"], serde_json::Value::Null);
        assert_eq!(json["streams"][0]["bind_state"], "bound");
        assert_eq!(json["streams"][0]["protocol"], "tcp");
        assert_eq!(json["streams"][1]["ceiling"], 100);
        assert_eq!(json["streams"][1]["fds_committed"], 102);
        let back: NodeBudgetView = serde_json::from_value(json).unwrap();
        assert_eq!(back, view);

        let unread = NodeBudgetView::build(inputs(PACKAGED_LIMIT, None), &streams);
        assert_eq!(unread.usable_source_ports, None);
        assert_eq!(unread.session_ceiling_bound_by, CeilingBound::FdBudget);
        assert_eq!(unread.source_pools[0].usable, None);
    }
}
