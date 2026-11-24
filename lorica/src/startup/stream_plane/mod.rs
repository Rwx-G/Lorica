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

//! The stream plane's driver (Story 12.2 D-a, D-c, D-d, D-h, D-j, D-k):
//! the process that binds every stream socket and hands it to the
//! workers.
//!
//! [`StreamPlane`] holds the bindings, the bind-state registry and one
//! [`WorkerLink`] per worker. The supervisor drives it over the
//! `SOCK_SEQPACKET` stream control channels ([`SeqpacketLink`]),
//! single-process mode over an in-process channel to its own stream
//! runtime ([`InProcessLink`], `W = 1`): one reconcile code for both.
//!
//! A configuration change runs in three steps around the workers'
//! commit ([`StreamPlaneHandle::before_commit`], the commit,
//! [`StreamPlaneHandle::after_commit`]): detach what is no longer
//! desired before the commit, so an accept never meets a stream the
//! committed config no longer has; bind and attach what is new after
//! it, then `refresh` every worker. Failed bindings whose error may
//! clear by itself are retried every [`STREAM_BIND_RETRY_INTERVAL`].
//!
//! Messages to one worker are stop-and-wait: the next goes out after the
//! previous one's answer or [`STREAM_CTL_ACK_TIMEOUT`], which bounds the
//! fds in flight to one `attach` per worker. An answer that arrives
//! after its timeout is still credited when it is read.
//!
//! A failure is a value in the registry, never an error returned up the
//! reconcile path: one stream's bind never blocks another's, and nothing
//! here can stop the process.
//!
//! **Caps regions** (Story 12.5 D-d, every protocol since Story 12.6
//! D-e): one [`NodeCapsRegions`] entry per stream on the node, sized from
//! its [`admitted_cap`] and its [`capped_links`], created at its first
//! bind, replaced when either moves its table sizes, retired once no
//! binding of the stream is
//! held or wanted. Its `caps` message goes to a worker ahead of every
//! `attach` of the stream, and again to every worker when the region is
//! replaced. A worker that dies has its connections and sessions
//! released from every live region before its respawn is sent anything
//! ([`WORKER_RELEASE`]).
//!
//! UDP streams (Story 12.5) add two more things the plane owns:
//!
//! - **Draining bindings** (D-m): a detached UDP binding keeps its
//!   workers' slot sockets open while its sessions drain, so the plane
//!   keeps it as draining until the drain ends plus
//!   [`UDP_DRAIN_RELEASE_MARGIN`], and binds nothing over its ports
//!   until then: the `address_in_use` retry binds it afterwards.
//! - **The source-port constraint** (D-e), read from the host's port
//!   range at every pass and checked with the fd constraints before
//!   every bind, by the API's rule: a rebind that raises nothing over
//!   what the node counted for the stream passes, so a node already past
//!   its ceiling (a narrowed port range) can still move a stream.
//!
//! **Hot upgrades** (Story 12.11): the outgoing plane hands its TCP
//! listeners and its UDP slot sockets to the next generation
//! ([`StreamPlaneHandle::handoff_fds`]), which adopts them in its first
//! pass, a UDP group whole or not at all, slot `k` to worker `k`, so the
//! group never changes size. Once the new generation is up the outgoing
//! plane quiesces its workers for the upgrade, waits for them to exit
//! and reads the drain reports they left on their channels
//! ([`StreamPlaneHandle::drain_for_upgrade`]). A quiesced plane binds,
//! detaches and refreshes nothing more.
//!
//! [`WORKER_RELEASE`]: StreamPlane::release_worker
//! [`admitted_cap`]: lorica_stream::caps::admitted_cap
//! [`capped_links`]: caps::capped_links

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{GlobalSettings, NodeRole};
use lorica_stream::{
    BindFailureKind, BindKey, BoundBinding, FdBudget, NodeCapsRegions, StreamBindStates,
    StreamDemand,
};
use lorica_worker::stream_sockets::{usable_udp_source_ports, BoundPort};
use tracing::warn;

use crate::startup::hot_upgrade::StreamUdpFd;

mod bind;
mod budget;
mod caps;
mod events;
mod exchange;
mod handle;
mod handoff;
mod link;
mod quiesce;
mod table;
#[cfg(test)]
mod test_support;
mod watch;

use caps::SharedCaps;
use exchange::WorkerSlot;

pub(crate) use events::PlaneEvent;
pub(crate) use handle::StreamPlaneHandle;
pub(crate) use link::{InProcessLink, LinkError, SeqpacketLink, WorkerLink};
pub(crate) use quiesce::UpgradeDrain;
pub(crate) use table::StoreStreamTable;
pub(crate) use watch::PlaneWatch;

/// How long the driver waits for a worker's answer before it moves on,
/// the two-phase reload's Prepare timeout.
pub(crate) const STREAM_CTL_ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a binding that failed on an error that may clear by itself
/// (`address_in_use`, `address_not_available`) is retried.
pub(crate) const STREAM_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// How often every caps region's settled rate cells are evicted and its
/// retired regions that count no session dropped (Story 12.5 D-d).
pub(crate) const STREAM_CAPS_TICK_INTERVAL: Duration = Duration::from_secs(1);

/// How long past its drain a detached UDP binding still holds its ports
/// in the plane (Story 12.5 D-m): the workers close their slot sockets
/// at the drain deadline at the latest, and this covers the time each
/// takes to notice it.
pub(crate) const UDP_DRAIN_RELEASE_MARGIN: Duration = Duration::from_secs(2);

/// Reads `U`, the usable UDP source ports per source address, or `None`
/// when the host's figures cannot be read (the source-port constraint is
/// then left out, never guessed).
pub(crate) type SourcePortsReader = Box<dyn Fn() -> Option<u64> + Send + Sync>;

/// [`usable_udp_source_ports`], with a failure logged.
fn read_usable_source_ports() -> Option<u64> {
    match usable_udp_source_ports() {
        Ok(usable) => Some(u64::from(usable)),
        Err(e) => {
            warn!(error = %e, "usable UDP source ports unreadable; the source-port constraint is not checked");
            None
        }
    }
}

/// The fleet role a stream plane binds for, owned: the supervisor reads
/// it once from its cluster runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaneRole {
    /// No cluster role.
    Standalone,
    /// The control plane: binds fleet-wide streams only.
    ControlPlane,
    /// An enrolled follower, by roster name.
    Follower(String),
}

impl PlaneRole {
    /// The role of a process running `runtime`.
    pub(crate) fn of(runtime: &lorica_fleet::ClusterRuntime) -> Self {
        match runtime {
            lorica_fleet::ClusterRuntime::Standalone => PlaneRole::Standalone,
            lorica_fleet::ClusterRuntime::ControlPlane(_) => PlaneRole::ControlPlane,
            lorica_fleet::ClusterRuntime::Follower(f) => PlaneRole::Follower(f.node_name.clone()),
        }
    }

    fn as_node_role(&self) -> NodeRole<'_> {
        match self {
            PlaneRole::Standalone => NodeRole::Standalone,
            PlaneRole::ControlPlane => NodeRole::ControlPlane,
            PlaneRole::Follower(name) => NodeRole::Follower { node_name: name },
        }
    }

    /// How audit rows and stream alerts name the node.
    pub(crate) fn label(&self) -> &str {
        match self {
            PlaneRole::Standalone => "standalone",
            PlaneRole::ControlPlane => "control_plane",
            PlaneRole::Follower(name) => name,
        }
    }
}

/// What the driver reads from the settings on every pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassSettings {
    /// `worker_drain_timeout_s`, sent as `drain_ms` in every message
    /// that starts a drain.
    pub(crate) drain: Duration,
    /// `stream_listen_socket_cap`.
    pub(crate) listen_socket_cap: u32,
}

impl PassSettings {
    /// The pass settings `settings` hold.
    pub(crate) fn of(settings: &GlobalSettings) -> Self {
        PassSettings {
            drain: crate::startup::drain::drain_timeout(settings),
            listen_socket_cap: settings.stream_listen_socket_cap,
        }
    }

    fn drain_ms(&self) -> u64 {
        u64::try_from(self.drain.as_millis()).unwrap_or(u64::MAX)
    }
}

/// What started a bind pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trigger {
    /// A configuration change, or the first reconcile: every desired
    /// binding is tried and every worker refreshed.
    Change,
    /// The retry tick: only failures that may clear by themselves.
    RetryTick,
}

struct HeldBinding {
    key: BindKey,
    bind_gen: u64,
    /// The supervisor's copies: one socket per TCP port, one per worker
    /// slot per UDP port, kept for the binding's whole life.
    ports: Vec<BoundPort>,
    /// `attach` messages each worker gets for this binding.
    chunks: usize,
    /// `attach` messages each worker acknowledged.
    acked: BTreeMap<u32, usize>,
    /// Workers whose last `caps` for this binding's stream was not
    /// acknowledged: they hold the sockets but admit no connection or
    /// session, so they do not count as serving (D-d).
    caps_refused: BTreeSet<u32>,
    /// What the budget check counted for the binding when it bound: the
    /// demand a rebind of its stream is compared with.
    demand: StreamDemand,
}

impl HeldBinding {
    fn serving(&self) -> u32 {
        let n = self
            .acked
            .iter()
            .filter(|(worker, acked)| {
                self.chunks > 0 && **acked >= self.chunks && !self.caps_refused.contains(worker)
            })
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    fn bound(&self) -> BoundBinding {
        BoundBinding {
            key: self.key.clone(),
            bind_gen: self.bind_gen,
        }
    }
}

/// A detached UDP binding whose workers still hold their slot sockets
/// while its sessions drain (D-m).
#[derive(Debug, Clone)]
struct DrainingBinding {
    key: BindKey,
    bind_gen: u64,
    /// The drain deadline plus [`UDP_DRAIN_RELEASE_MARGIN`]: from then
    /// on no worker holds its ports.
    until: Instant,
}

/// The stream plane of one process. See the module doc.
pub(crate) struct StreamPlane<L> {
    workers: BTreeMap<u32, WorkerSlot<L>>,
    worker_count: u32,
    held: BTreeMap<String, HeldBinding>,
    /// The demand of each binding detached for a rebind, by stream id,
    /// until the stream binds again or is no longer wanted: what its new
    /// binding is compared with (refuse raises, allow lowers), across the
    /// passes a drain or a retry may take.
    rebinding: BTreeMap<String, StreamDemand>,
    /// Detached UDP bindings still draining in the workers.
    draining: Vec<DrainingBinding>,
    /// See [`UDP_DRAIN_RELEASE_MARGIN`]; a field so tests can shorten it.
    drain_margin: Duration,
    /// One caps region per stream on the node.
    caps: SharedCaps,
    source_ports: SourcePortsReader,
    /// `U` as read at the start of the current pass.
    usable_source_ports: Option<u64>,
    /// TCP listeners inherited from the outgoing supervisor, adopted by
    /// the first pass that wants them and closed by it otherwise.
    inherited: Vec<(String, SocketAddr, OwnedFd)>,
    /// UDP slot sockets inherited from the outgoing supervisor, adopted
    /// group by group by the first pass that wants them (Story 12.11
    /// D-e) and closed by it otherwise.
    inherited_udp: Vec<(StreamUdpFd, OwnedFd)>,
    /// Set by a quiesce: the plane binds, detaches and refreshes nothing
    /// from then on, the process being on its way out.
    quiesced: bool,
    /// The seq of the `quiesce reason=upgrade` each worker was sent, which
    /// its drain report answers.
    upgrade_quiesce: BTreeMap<u32, u64>,
    states: StreamBindStates,
    failures: BTreeMap<String, BindFailureKind>,
    next_gen: u64,
    next_seq: u64,
    budget: FdBudget,
    reserved: ReservedPorts,
    ack_timeout: Duration,
}

impl<L: WorkerLink> StreamPlane<L> {
    /// A plane over `links`, one per worker id, for a node of
    /// `worker_count` workers (the UDP slot count): worker `i` gets slot
    /// `i`. `budget` is the process's, `reserved` the ports its own
    /// listeners hold, `states` the registry the API and the fleet view
    /// read.
    pub(crate) fn new(
        links: Vec<(u32, L)>,
        worker_count: u32,
        budget: FdBudget,
        reserved: ReservedPorts,
        states: StreamBindStates,
        ack_timeout: Duration,
    ) -> Self {
        StreamPlane {
            workers: links
                .into_iter()
                .map(|(id, link)| (id, WorkerSlot::new(link)))
                .collect(),
            worker_count,
            held: BTreeMap::new(),
            rebinding: BTreeMap::new(),
            draining: Vec::new(),
            drain_margin: UDP_DRAIN_RELEASE_MARGIN,
            caps: Arc::new(StdMutex::new(NodeCapsRegions::new(worker_count))),
            source_ports: Box::new(read_usable_source_ports),
            usable_source_ports: None,
            inherited: Vec::new(),
            inherited_udp: Vec::new(),
            quiesced: false,
            upgrade_quiesce: BTreeMap::new(),
            states,
            failures: BTreeMap::new(),
            next_gen: 1,
            next_seq: 1,
            budget,
            reserved,
            ack_timeout,
        }
    }

    /// Read `U` through `reader` instead of the host's `/proc` files.
    #[cfg(test)]
    fn with_source_ports(mut self, reader: SourcePortsReader) -> Self {
        self.source_ports = reader;
        self
    }

    fn seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }
}
