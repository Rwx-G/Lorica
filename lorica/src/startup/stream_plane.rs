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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{GlobalSettings, NodeRole, Stream, StreamProtocol};
use lorica_config::ConfigStore;
use lorica_stream::reconcile::desired_bindings;
use lorica_stream::{
    diff, BindFailureKind, BindKey, BindState, BoundBinding, Detach, FdBudget, InProcessPeer,
    ReleaseCause, StreamBindStates, StreamDemand,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{
    self, check_stream_id, chunk_sockets, NackReason, QuiesceReason, StreamCtlError, StreamCtlMsg,
    StreamSocket,
};
use lorica_worker::stream_sockets::{bind_range, BoundPort};
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::startup::hot_upgrade::StreamTcpFd;

/// How long the driver waits for a worker's answer before it moves on,
/// the two-phase reload's Prepare timeout.
pub(crate) const STREAM_CTL_ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How often a binding that failed on an error that may clear by itself
/// (`address_in_use`, `address_not_available`) is retried.
pub(crate) const STREAM_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(10);

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

    /// How audit rows name the node.
    fn label(&self) -> &str {
        match self {
            PlaneRole::Standalone => "standalone",
            PlaneRole::ControlPlane => "control_plane",
            PlaneRole::Follower(name) => name,
        }
    }
}

/// Why a message could not be exchanged with a worker.
#[derive(Debug, thiserror::Error)]
pub(crate) enum LinkError {
    /// The channel is unusable: the worker is gone.
    #[error("stream control channel lost: {0}")]
    Lost(String),
    /// One message was refused or garbled; the channel still works.
    #[error("stream control message refused: {0}")]
    Refused(String),
}

/// The driver's end of one worker's stream control channel. The futures
/// are `Send` so the driver runs from spawned tasks.
pub(crate) trait WorkerLink: Send {
    /// Send one message.
    fn send(
        &mut self,
        msg: StreamCtlMsg,
    ) -> impl std::future::Future<Output = Result<(), LinkError>> + Send;
    /// Receive the next answer.
    fn recv(&mut self)
        -> impl std::future::Future<Output = Result<StreamCtlMsg, LinkError>> + Send;
}

/// The supervisor's end of a worker's `SOCK_SEQPACKET` channel.
pub(crate) struct SeqpacketLink {
    fd: AsyncFd<OwnedFd>,
}

fn would_block(e: &StreamCtlError) -> bool {
    match e {
        StreamCtlError::Send(errno) | StreamCtlError::Recv(errno) => {
            io::Error::from(*errno).kind() == io::ErrorKind::WouldBlock
        }
        _ => false,
    }
}

impl SeqpacketLink {
    /// Register `fd`, the supervisor end a [`WorkerHandle`] hands over.
    /// Must run inside the runtime that will poll it.
    ///
    /// [`WorkerHandle`]: lorica_worker::manager::WorkerHandle
    pub(crate) fn new(fd: OwnedFd) -> io::Result<Self> {
        // `set_nonblocking` is a plain `fcntl(O_NONBLOCK)` whatever the
        // socket type; the std wrapper only borrows the descriptor for it.
        let socket = std::os::unix::net::UnixDatagram::from(fd);
        socket.set_nonblocking(true)?;
        let fd = OwnedFd::from(socket);
        // SAFETY: an `OwnedFd` is a valid open descriptor that it alone
        // closes, and `as_raw_fd` returns the same number for its whole
        // life; the `AsyncFd` owns it from here, so it stays open for as
        // long as it is registered.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(SeqpacketLink { fd })
    }
}

impl WorkerLink for SeqpacketLink {
    async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
        loop {
            let mut guard = self
                .fd
                .writable()
                .await
                .map_err(|e| LinkError::Lost(e.to_string()))?;
            match stream_ctl::send_msg(guard.get_inner(), &msg) {
                Ok(()) => return Ok(()),
                Err(e) if would_block(&e) => guard.clear_ready(),
                Err(e @ StreamCtlError::Send(_)) => return Err(LinkError::Lost(e.to_string())),
                Err(e) => return Err(LinkError::Refused(e.to_string())),
            }
        }
    }

    async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
        loop {
            let mut guard = self
                .fd
                .readable()
                .await
                .map_err(|e| LinkError::Lost(e.to_string()))?;
            match stream_ctl::recv_msg(guard.get_inner()) {
                Ok(msg) => return Ok(msg),
                Err(e) if would_block(&e) => guard.clear_ready(),
                Err(e @ (StreamCtlError::Closed | StreamCtlError::Recv(_))) => {
                    return Err(LinkError::Lost(e.to_string()))
                }
                Err(e) => return Err(LinkError::Refused(e.to_string())),
            }
        }
    }
}

/// Single-process mode's end of the in-process channel to its own stream
/// runtime (D-k): the same messages, with owned fds instead of
/// `SCM_RIGHTS`.
pub(crate) struct InProcessLink(pub(crate) InProcessPeer);

impl WorkerLink for InProcessLink {
    async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
        self.0
            .to_runtime
            .send(msg)
            .await
            .map_err(|_| LinkError::Lost("the stream runtime is gone".into()))
    }

    async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
        self.0
            .from_runtime
            .recv()
            .await
            .ok_or_else(|| LinkError::Lost("the stream runtime is gone".into()))
    }
}

/// The stream table a stream runtime accepts against, read from the
/// configuration store.
///
/// It holds a connection of its own: the runtime loads the table
/// synchronously from inside its tokio runtime, where the blocking lock
/// of the process's shared `tokio::sync::Mutex` store would panic.
///
/// The table holds every stream, not only the ones this node binds:
/// which bindings a worker serves is the driver's decision, made with
/// `binds_here` over the node's role and carried by `attach` and
/// `detach`, so a stream this node stops binding is drained by its
/// `detach`. A worker cannot make that decision itself, since it does
/// not know whether it runs on the control plane (`--cluster-listen`).
/// What the table answers is whether an attached binding still has its
/// stream, enabled, with the backend a connection uses, which a
/// `refresh` drains on, and the linked backend rows the engines select
/// from, with their health as stored (Story 12.3 D-i).
pub(crate) struct StoreStreamTable {
    store: Arc<std::sync::Mutex<ConfigStore>>,
}

impl StoreStreamTable {
    /// Open a connection of its own to the database at `db_path`.
    pub(crate) fn open(
        db_path: &std::path::Path,
        key: Option<lorica_config::crypto::EncryptionKey>,
    ) -> lorica_config::Result<Self> {
        Ok(StoreStreamTable {
            store: Arc::new(std::sync::Mutex::new(ConfigStore::open(db_path, key)?)),
        })
    }

    /// The stored drain setting, for a stop that arrives without a
    /// `quiesce` message.
    pub(crate) fn drain_timeout(&self) -> Duration {
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::startup::drain::stored_drain_timeout(&store)
    }
}

impl lorica_stream::StreamTableSource for StoreStreamTable {
    fn load(&self) -> Result<lorica_stream::StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        // A panic while holding the lock leaves nothing half-written: the
        // connection only reads here.
        let store = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let streams = store.list_streams()?;
        let links = store.list_stream_backends()?;
        let backends = store.list_backends()?;
        Ok(lorica_stream::StreamTable::with_backends(
            streams, &links, backends,
        ))
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

/// What a pass did, for the audit chain and the log (D-h).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaneEvent {
    /// A binding is held and attached (`stream.bind`).
    Bound {
        /// The binding.
        key: BindKey,
        /// Its generation.
        bind_gen: u64,
        /// Workers that acknowledged it.
        workers_serving: u32,
        /// Workers on the node.
        workers: u32,
    },
    /// A binding was released (`stream.release`).
    Released {
        /// The binding.
        key: BindKey,
        /// Its generation.
        bind_gen: u64,
        /// Why.
        cause: ReleaseCause,
    },
    /// A binding entered the failed state (`stream.bind_failed` and the
    /// `stream_bind_failed` alert), once per entry, never per retry.
    BindFailed {
        /// The binding.
        key: BindKey,
        /// The stream's name, which the alert carries and the key does
        /// not.
        name: String,
        /// The classification.
        kind: BindFailureKind,
        /// The OS error, or the node-side check's own sentence.
        os_error: String,
        /// The port that failed.
        port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    Attach { stream_id: String, bind_gen: u64 },
    Other,
}

impl Pending {
    fn of(msg: &StreamCtlMsg) -> Self {
        match msg {
            StreamCtlMsg::Attach {
                stream_id,
                bind_gen,
                ..
            } => Pending::Attach {
                stream_id: stream_id.clone(),
                bind_gen: *bind_gen,
            },
            _ => Pending::Other,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    Ack,
    Nack(NackReason),
    Timeout,
    Lost,
    Refused(String),
    NoLink,
}

#[derive(Debug)]
struct Sent {
    seq: u64,
    pending: Pending,
    answer: Answer,
}

#[derive(Debug, Default)]
struct SlotRun {
    sent: Vec<Sent>,
    stale: Vec<StreamCtlMsg>,
}

struct WorkerSlot<L> {
    link: Option<L>,
    /// Attaches that timed out, by sequence number, credited if their
    /// answer arrives later.
    outstanding: HashMap<u64, Pending>,
}

impl<L: WorkerLink> WorkerSlot<L> {
    fn new(link: L) -> Self {
        WorkerSlot {
            link: Some(link),
            outstanding: HashMap::new(),
        }
    }

    async fn run(&mut self, worker: u32, msgs: Vec<StreamCtlMsg>, timeout: Duration) -> SlotRun {
        let mut run = SlotRun::default();
        for msg in msgs {
            let seq = msg.seq();
            let pending = Pending::of(&msg);
            let answer = self.exchange(worker, msg, timeout, &mut run.stale).await;
            run.sent.push(Sent {
                seq,
                pending,
                answer,
            });
        }
        run
    }

    async fn exchange(
        &mut self,
        worker: u32,
        msg: StreamCtlMsg,
        timeout: Duration,
        stale: &mut Vec<StreamCtlMsg>,
    ) -> Answer {
        let seq = msg.seq();
        let Some(link) = self.link.as_mut() else {
            return Answer::NoLink;
        };
        match link.send(msg).await {
            Ok(()) => {}
            Err(LinkError::Refused(reason)) => return Answer::Refused(reason),
            Err(e @ LinkError::Lost(_)) => {
                warn!(worker_id = worker, error = %e, "stream control channel lost");
                self.link = None;
                return Answer::Lost;
            }
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let Some(link) = self.link.as_mut() else {
                return Answer::Lost;
            };
            let received = tokio::time::timeout_at(deadline, link.recv()).await;
            match received {
                Err(_) => return Answer::Timeout,
                Ok(Ok(StreamCtlMsg::Ack { seq: s, .. })) if s == seq => return Answer::Ack,
                Ok(Ok(StreamCtlMsg::Nack { seq: s, reason })) if s == seq => {
                    return Answer::Nack(reason)
                }
                Ok(Ok(other)) => stale.push(other),
                Ok(Err(e @ LinkError::Lost(_))) => {
                    warn!(worker_id = worker, error = %e, "stream control channel lost");
                    self.link = None;
                    return Answer::Lost;
                }
                Ok(Err(e @ LinkError::Refused(_))) => {
                    warn!(worker_id = worker, error = %e, "garbled stream control answer dropped");
                }
            }
        }
    }
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
}

impl HeldBinding {
    fn serving(&self) -> u32 {
        let n = self
            .acked
            .values()
            .filter(|acked| self.chunks > 0 && **acked >= self.chunks)
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

/// Whether a failure may clear without a configuration change.
fn retryable(kind: BindFailureKind) -> bool {
    matches!(
        kind,
        BindFailureKind::AddressInUse | BindFailureKind::AddressNotAvailable
    )
}

fn proto_of(protocol: StreamProtocol) -> StreamProto {
    match protocol {
        StreamProtocol::Tcp => StreamProto::Tcp,
        StreamProtocol::Udp => StreamProto::Udp,
    }
}

/// The budget demand of binding `key`, with what its engine holds at the
/// stream's cap (Story 12.3 D-p) when `stream` is known: the same
/// [`lorica_stream::tcp::held_fds`] the API's budget check reads.
fn demand_of(key: &BindKey, stream: Option<&Stream>) -> StreamDemand {
    let demand = StreamDemand {
        stream_id: key.stream_id.clone(),
        name: stream.map(|s| s.name.clone()).unwrap_or_default(),
        protocol: key.protocol,
        listen_sockets: u64::from(key.port_last.saturating_sub(key.port_first)) + 1,
        held: None,
    };
    match stream.and_then(lorica_stream::tcp::held_fds) {
        Some(held) => demand.with_held(held),
        None => demand,
    }
}

/// The stream plane of one process. See the module doc.
pub(crate) struct StreamPlane<L> {
    workers: BTreeMap<u32, WorkerSlot<L>>,
    worker_count: u32,
    held: BTreeMap<String, HeldBinding>,
    /// TCP listeners inherited from the outgoing supervisor, adopted by
    /// the first pass that wants them and closed by it otherwise.
    inherited: Vec<(String, SocketAddr, OwnedFd)>,
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
            inherited: Vec::new(),
            states,
            failures: BTreeMap::new(),
            next_gen: 1,
            next_seq: 1,
            budget,
            reserved,
            ack_timeout,
        }
    }

    /// Adopt the TCP stream listeners a hot upgrade handed over (D-j).
    /// The next pass takes each one a desired binding matches instead of
    /// binding its port, and closes the rest.
    pub(crate) fn adopt_inherited(&mut self, listeners: Vec<(StreamTcpFd, OwnedFd)>) {
        for (entry, fd) in listeners {
            // The old generation's numbers name its own bindings; this
            // supervisor never reuses one.
            self.next_gen = self.next_gen.max(entry.bind_gen.saturating_add(1));
            self.inherited.push((entry.stream_id, entry.addr, fd));
        }
    }

    fn seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    fn bound_list(&self) -> Vec<BoundBinding> {
        self.held.values().map(HeldBinding::bound).collect()
    }

    /// Whether a failure the retry tick would retry is held.
    pub(crate) fn has_retryable_failure(&self) -> bool {
        self.failures.values().any(|kind| retryable(*kind))
    }

    /// The TCP listeners a hot upgrade hands to the next supervisor
    /// (D-j). The descriptors stay owned here.
    pub(crate) fn tcp_handoff_fds(&self) -> Vec<StreamTcpFd> {
        self.held
            .values()
            .filter(|b| b.key.protocol == StreamProtocol::Tcp)
            .flat_map(|b| {
                b.ports.iter().filter_map(move |port| {
                    port.sockets.first().map(|fd| StreamTcpFd {
                        stream_id: b.key.stream_id.clone(),
                        bind_gen: b.bind_gen,
                        addr: port.addr,
                        fd: fd.as_raw_fd(),
                    })
                })
            })
            .collect()
    }

    /// D-d step 1, before the workers commit: detach every binding no
    /// longer desired or whose bind key changed.
    pub(crate) async fn release_stale(
        &mut self,
        streams: &[Stream],
        role: NodeRole<'_>,
        pass: PassSettings,
    ) -> Vec<PlaneEvent> {
        let actions = diff(streams, role, &self.bound_list());
        self.detach(actions.detach, pass).await
    }

    /// D-d step 3, after the workers commit: detach what step 1 could
    /// not see, bind and attach every desired binding not held yet, and
    /// on a [`Trigger::Change`] refresh every worker.
    pub(crate) async fn bind_desired(
        &mut self,
        streams: &[Stream],
        role: NodeRole<'_>,
        pass: PassSettings,
        trigger: Trigger,
    ) -> Vec<PlaneEvent> {
        let actions = diff(streams, role, &self.bound_list());
        let mut events = self.detach(actions.detach, pass).await;

        let desired: BTreeSet<String> = desired_bindings(streams, role)
            .into_iter()
            .map(|k| k.stream_id)
            .collect();
        for id in self.states.snapshot().into_keys() {
            if !desired.contains(&id) && !self.held.contains_key(&id) {
                self.states.remove(&id);
                self.failures.remove(&id);
            }
        }

        let names: BTreeMap<&str, &str> = streams
            .iter()
            .map(|s| (s.id.as_str(), s.name.as_str()))
            .collect();
        for refused in actions.refused {
            let name = names
                .get(refused.key.stream_id.as_str())
                .copied()
                .unwrap_or("");
            self.fail(
                &refused.key,
                name,
                refused.kind(),
                refused.to_string(),
                refused.port,
                &mut events,
            );
        }

        for key in actions.bind {
            let skip = trigger == Trigger::RetryTick
                && self
                    .failures
                    .get(&key.stream_id)
                    .is_some_and(|kind| !retryable(*kind));
            if skip {
                continue;
            }
            let name = names.get(key.stream_id.as_str()).copied().unwrap_or("");
            self.bind_one(key, name, streams, pass, &mut events).await;
        }

        // Inherited listeners serve the first pass only: whatever it did
        // not adopt belongs to no desired binding.
        for (stream_id, addr, _fd) in self.inherited.drain(..) {
            info!(%stream_id, %addr, "inherited stream listener not adopted; closed");
        }

        if trigger == Trigger::Change {
            self.refresh_all(pass).await;
        }
        events
    }

    /// Send `refresh` to every worker: each reloads its stream table and
    /// drains what the new one no longer holds. Binds and detaches
    /// nothing.
    pub(crate) async fn refresh_all(&mut self, pass: PassSettings) {
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for id in self.workers.keys().copied().collect::<Vec<_>>() {
            let seq = self.seq();
            per_worker.insert(
                id,
                vec![StreamCtlMsg::Refresh {
                    seq,
                    drain_ms: pass.drain_ms(),
                }],
            );
        }
        self.send_all(per_worker).await;
    }

    /// A worker came back after a crash: take its new channel and replay
    /// every live binding, then a `refresh` (D-a).
    pub(crate) async fn replay_worker(&mut self, worker: u32, link: L, pass: PassSettings) {
        self.workers.insert(worker, WorkerSlot::new(link));
        let mut msgs = Vec::new();
        let ids: Vec<String> = self.held.keys().cloned().collect();
        for id in ids {
            let attaches = self.attach_messages(&id, worker);
            if let Some(b) = self.held.get_mut(&id) {
                b.acked.remove(&worker);
            }
            msgs.extend(attaches);
        }
        let seq = self.seq();
        msgs.push(StreamCtlMsg::Refresh {
            seq,
            drain_ms: pass.drain_ms(),
        });
        self.send_all(BTreeMap::from([(worker, msgs)])).await;
        for b in self.held.values() {
            self.states
                .set_bound(&b.key.stream_id, b.serving(), self.worker_count);
        }
    }

    /// The stop path (D-f): quiesce every worker for `drain` and release
    /// every binding with cause `shutdown`.
    pub(crate) async fn quiesce(&mut self, drain: Duration) -> Vec<PlaneEvent> {
        let drain_ms = u64::try_from(drain.as_millis()).unwrap_or(u64::MAX);
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for id in self.workers.keys().copied().collect::<Vec<_>>() {
            let seq = self.seq();
            per_worker.insert(
                id,
                vec![StreamCtlMsg::Quiesce {
                    seq,
                    reason: QuiesceReason::Shutdown,
                    drain_ms,
                }],
            );
        }
        self.send_all(per_worker).await;
        let mut events = Vec::new();
        for (id, b) in std::mem::take(&mut self.held) {
            self.states.remove(&id);
            events.push(PlaneEvent::Released {
                key: b.key,
                bind_gen: b.bind_gen,
                cause: ReleaseCause::Shutdown,
            });
        }
        events
    }

    async fn detach(&mut self, detaches: Vec<Detach>, pass: PassSettings) -> Vec<PlaneEvent> {
        let mut events = Vec::new();
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        let workers: Vec<u32> = self.workers.keys().copied().collect();
        for d in detaches {
            let id = d.binding.key.stream_id.clone();
            let held_here = self
                .held
                .get(&id)
                .is_some_and(|b| b.bind_gen == d.binding.bind_gen);
            if !held_here {
                continue;
            }
            // The supervisor's copies close first; the port is free once
            // the last worker closes its copy on `detach`.
            drop(self.held.remove(&id));
            for slot in self.workers.values_mut() {
                slot.outstanding.retain(|_, p| {
                    *p != Pending::Attach {
                        stream_id: id.clone(),
                        bind_gen: d.binding.bind_gen,
                    }
                });
            }
            for worker in &workers {
                let seq = self.seq();
                per_worker
                    .entry(*worker)
                    .or_default()
                    .push(StreamCtlMsg::Detach {
                        seq,
                        stream_id: id.clone(),
                        bind_gen: d.binding.bind_gen,
                        drain_ms: pass.drain_ms(),
                    });
            }
            if d.cause == ReleaseCause::Rebind {
                self.states.set_pending(&id);
            } else {
                self.states.remove(&id);
            }
            events.push(PlaneEvent::Released {
                key: d.binding.key,
                bind_gen: d.binding.bind_gen,
                cause: d.cause,
            });
        }
        self.send_all(per_worker).await;
        events
    }

    fn fail(
        &mut self,
        key: &BindKey,
        name: &str,
        kind: BindFailureKind,
        os_error: String,
        port: u16,
        events: &mut Vec<PlaneEvent>,
    ) {
        let entered = self.states.set_failed(
            &key.stream_id,
            kind,
            os_error.clone(),
            port,
            chrono::Utc::now(),
        );
        self.failures.insert(key.stream_id.clone(), kind);
        if entered {
            events.push(PlaneEvent::BindFailed {
                key: key.clone(),
                name: name.to_string(),
                kind,
                os_error,
                port,
            });
        }
    }

    /// The inherited listeners that cover exactly the ports of `key`, if
    /// every port has one.
    fn take_inherited(&mut self, key: &BindKey) -> Option<Vec<BoundPort>> {
        if key.protocol != StreamProtocol::Tcp {
            return None;
        }
        let matches = |(stream_id, addr, _): &(String, SocketAddr, OwnedFd)| {
            *stream_id == key.stream_id
                && addr.ip() == key.listen_address
                && key.ports().contains(&addr.port())
        };
        let ports: BTreeSet<u16> = self
            .inherited
            .iter()
            .filter(|e| matches(e))
            .map(|(_, addr, _)| addr.port())
            .collect();
        let covered = ports.len() == key.ports().len()
            && self.inherited.iter().filter(|e| matches(e)).count() == ports.len();
        if !covered {
            return None;
        }
        let (taken, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.inherited)
            .into_iter()
            .partition(matches);
        self.inherited = kept;
        let mut bound: Vec<BoundPort> = taken
            .into_iter()
            .map(|(_, addr, fd)| BoundPort {
                addr,
                sockets: vec![fd],
            })
            .collect();
        bound.sort_by_key(|p| p.addr.port());
        Some(bound)
    }

    async fn bind_one(
        &mut self,
        key: BindKey,
        name: &str,
        streams: &[Stream],
        pass: PassSettings,
        events: &mut Vec<PlaneEvent>,
    ) {
        let id = key.stream_id.clone();
        if self.states.get(&id).is_none() {
            self.states.set_pending(&id);
        }
        // An id the channel cannot carry could never be attached: say so
        // on the stream rather than drop it.
        if let Err(reason) = check_stream_id(&id) {
            self.fail(
                &key,
                name,
                BindFailureKind::Other,
                format!("the stream id cannot be sent to the workers: {reason}"),
                key.port_first,
                events,
            );
            return;
        }
        if let Some((port, listener)) = self.reserved.clash_in(key.port_first, key.port_last) {
            self.fail(
                &key,
                name,
                BindFailureKind::ReservedPort,
                format!("port {port} is {}", listener.phrase()),
                port,
                events,
            );
            return;
        }
        let stream_of = |id: &str| streams.iter().find(|s| s.id == id);
        let mut demands: Vec<StreamDemand> = self
            .held
            .values()
            .map(|b| demand_of(&b.key, stream_of(&b.key.stream_id)))
            .collect();
        demands.push(demand_of(&key, stream_of(&key.stream_id)));
        if let Err(violation) =
            self.budget
                .check(&demands, self.worker_count, pass.listen_socket_cap)
        {
            self.fail(
                &key,
                name,
                BindFailureKind::FdBudget,
                violation.to_string(),
                key.port_first,
                events,
            );
            return;
        }
        let ports = match self.take_inherited(&key) {
            Some(ports) => ports,
            None => match bind_range(
                proto_of(key.protocol),
                key.listen_address,
                key.ports(),
                self.worker_count as usize,
            ) {
                Ok(ports) => ports,
                Err(e) => {
                    self.fail(
                        &key,
                        name,
                        e.kind,
                        e.source.to_string(),
                        e.addr.port(),
                        events,
                    );
                    return;
                }
            },
        };

        let bind_gen = self.next_gen;
        self.next_gen += 1;
        self.held.insert(
            id.clone(),
            HeldBinding {
                key: key.clone(),
                bind_gen,
                ports,
                chunks: 0,
                acked: BTreeMap::new(),
            },
        );
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for worker in self.workers.keys().copied().collect::<Vec<_>>() {
            let msgs = self.attach_messages(&id, worker);
            per_worker.insert(worker, msgs);
        }
        self.send_all(per_worker).await;

        self.failures.remove(&id);
        let (serving, bind_gen) = match self.held.get(&id) {
            Some(b) => (b.serving(), b.bind_gen),
            None => return,
        };
        self.states.set_bound(&id, serving, self.worker_count);
        events.push(PlaneEvent::Bound {
            key,
            bind_gen,
            workers_serving: serving,
            workers: self.worker_count,
        });
    }

    /// The `attach` messages of binding `stream_id` for `worker`: a dup
    /// of each TCP listener, or the worker's own slot socket of each UDP
    /// port, chunked by [`chunk_sockets`].
    fn attach_messages(&mut self, stream_id: &str, worker: u32) -> Vec<StreamCtlMsg> {
        let Some(b) = self.held.get(stream_id) else {
            return Vec::new();
        };
        let slot = match b.key.protocol {
            StreamProtocol::Tcp => 0,
            StreamProtocol::Udp => worker as usize,
        };
        let mut sockets = Vec::with_capacity(b.ports.len());
        for port in &b.ports {
            let dup = port.sockets.get(slot).map(OwnedFd::try_clone);
            match dup {
                Some(Ok(fd)) => sockets.push(StreamSocket {
                    proto: proto_of(b.key.protocol),
                    addr: port.addr,
                    fd,
                }),
                Some(Err(e)) => {
                    warn!(%stream_id, worker_id = worker, addr = %port.addr, error = %e,
                          "stream socket not duplicated; this worker will not serve the binding");
                    return Vec::new();
                }
                None => {
                    warn!(%stream_id, worker_id = worker, slot,
                          "no UDP slot socket for this worker; it will not serve the binding");
                    return Vec::new();
                }
            }
        }
        let bind_gen = b.bind_gen;
        let chunks = chunk_sockets(sockets);
        if let Some(b) = self.held.get_mut(stream_id) {
            b.chunks = chunks.len();
        }
        chunks
            .into_iter()
            .map(|sockets| StreamCtlMsg::Attach {
                seq: self.seq(),
                stream_id: stream_id.to_string(),
                bind_gen,
                sockets,
            })
            .collect()
    }

    /// Run each worker's messages, stop-and-wait per worker and every
    /// worker at once, then credit the acknowledged attaches, the late
    /// ones included.
    async fn send_all(&mut self, mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>>) {
        let timeout = self.ack_timeout;
        let runs: Vec<(u32, SlotRun)> =
            join_all(self.workers.iter_mut().filter_map(|(id, slot)| {
                let msgs = per_worker.remove(id)?;
                Some(async move { (*id, slot.run(*id, msgs, timeout).await) })
            }))
            .await;
        for (worker, run) in runs {
            if let Some(slot) = self.workers.get_mut(&worker) {
                for sent in &run.sent {
                    if sent.answer == Answer::Timeout {
                        slot.outstanding.insert(sent.seq, sent.pending.clone());
                    }
                }
            }
            for sent in run.sent {
                match sent.answer {
                    Answer::Ack => self.credit(worker, &sent.pending),
                    Answer::Nack(reason) => {
                        debug!(
                            worker_id = worker,
                            seq = sent.seq,
                            reason = reason.as_str(),
                            "stream control message refused by the worker"
                        );
                    }
                    Answer::Timeout => {
                        warn!(
                            worker_id = worker,
                            seq = sent.seq,
                            "stream control message not answered in time"
                        );
                    }
                    Answer::Refused(reason) => {
                        warn!(worker_id = worker, seq = sent.seq, %reason,
                              "stream control message could not be sent");
                    }
                    Answer::Lost | Answer::NoLink => {}
                }
            }
            for msg in run.stale {
                self.late_answer(worker, msg);
            }
        }
    }

    fn credit(&mut self, worker: u32, pending: &Pending) {
        let Pending::Attach {
            stream_id,
            bind_gen,
        } = pending
        else {
            return;
        };
        if let Some(b) = self.held.get_mut(stream_id) {
            if b.bind_gen == *bind_gen {
                *b.acked.entry(worker).or_default() += 1;
            }
        }
    }

    fn late_answer(&mut self, worker: u32, msg: StreamCtlMsg) {
        let (seq, acked) = match msg {
            StreamCtlMsg::Ack { seq, .. } => (seq, true),
            StreamCtlMsg::Nack { seq, .. } => (seq, false),
            other => {
                warn!(
                    worker_id = worker,
                    seq = other.seq(),
                    "unexpected message from a worker on the stream control channel"
                );
                return;
            }
        };
        let Some(pending) = self
            .workers
            .get_mut(&worker)
            .and_then(|slot| slot.outstanding.remove(&seq))
        else {
            return;
        };
        if !acked {
            return;
        }
        self.credit(worker, &pending);
        if let Pending::Attach { stream_id, .. } = &pending {
            if let Some(b) = self.held.get(stream_id) {
                if matches!(self.states.get(stream_id), Some(BindState::Bound { .. })) {
                    self.states
                        .set_bound(stream_id, b.serving(), self.worker_count);
                }
            }
        }
    }
}

/// A [`StreamPlane`] shared by the reload path, the retry tick, the
/// worker monitor and the stop path, with what each pass reads (the
/// store, the node's role) and where its events go (the audit chain and
/// the alert channel).
pub(crate) struct StreamPlaneHandle<L> {
    plane: Arc<Mutex<StreamPlane<L>>>,
    store: Arc<Mutex<ConfigStore>>,
    role: Arc<PlaneRole>,
    audit: Option<lorica_api::server::LogStoreSlot>,
    alerts: lorica_notify::AlertSender,
}

impl<L> Clone for StreamPlaneHandle<L> {
    fn clone(&self) -> Self {
        StreamPlaneHandle {
            plane: Arc::clone(&self.plane),
            store: Arc::clone(&self.store),
            role: Arc::clone(&self.role),
            audit: self.audit.clone(),
            alerts: self.alerts.clone(),
        }
    }
}

impl<L: WorkerLink + 'static> StreamPlaneHandle<L> {
    /// Share `plane`, reading `store` and binding for `role`; `audit` is
    /// where `stream.bind`, `stream.release` and `stream.bind_failed`
    /// rows go, `alerts` where the `stream_bind_failed` alert goes.
    pub(crate) fn new(
        plane: StreamPlane<L>,
        store: Arc<Mutex<ConfigStore>>,
        role: PlaneRole,
        audit: Option<lorica_api::server::LogStoreSlot>,
        alerts: lorica_notify::AlertSender,
    ) -> Self {
        StreamPlaneHandle {
            plane: Arc::new(Mutex::new(plane)),
            store,
            role: Arc::new(role),
            audit,
            alerts,
        }
    }

    async fn inputs(&self) -> Option<(Vec<Stream>, PassSettings)> {
        let store = self.store.lock().await;
        let streams = store.list_streams();
        let settings = store.get_global_settings();
        match (streams, settings) {
            (Ok(streams), Ok(settings)) => Some((streams, PassSettings::of(&settings))),
            (Err(e), _) | (_, Err(e)) => {
                warn!(error = %e, "stream plane: configuration unreadable; bindings left as they are");
                None
            }
        }
    }

    /// D-d step 1: before the workers commit a change.
    pub(crate) async fn before_commit(&self) {
        let Some((streams, pass)) = self.inputs().await else {
            return;
        };
        let events = self
            .plane
            .lock()
            .await
            .release_stale(&streams, self.role.as_node_role(), pass)
            .await;
        self.record(events).await;
    }

    /// D-d step 3: after the workers commit a change, and the first
    /// reconcile at startup.
    pub(crate) async fn after_commit(&self) {
        self.bind_pass(Trigger::Change).await;
    }

    async fn bind_pass(&self, trigger: Trigger) {
        let Some((streams, pass)) = self.inputs().await else {
            return;
        };
        let events = self
            .plane
            .lock()
            .await
            .bind_desired(&streams, self.role.as_node_role(), pass, trigger)
            .await;
        self.record(events).await;
    }

    /// Retry the failures that may have cleared, every
    /// [`STREAM_BIND_RETRY_INTERVAL`], for the life of the process.
    pub(crate) fn spawn_retry_loop(&self) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(STREAM_BIND_RETRY_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                if handle.plane.lock().await.has_retryable_failure() {
                    handle.bind_pass(Trigger::RetryTick).await;
                }
            }
        })
    }

    /// A worker came back: replay the live bindings to it.
    pub(crate) async fn replay(&self, worker: u32, link: L) {
        let Some((_, pass)) = self.inputs().await else {
            return;
        };
        self.plane
            .lock()
            .await
            .replay_worker(worker, link, pass)
            .await;
    }

    /// The stop path: quiesce every worker for `drain`.
    pub(crate) async fn quiesce(&self, drain: Duration) {
        let events = self.plane.lock().await.quiesce(drain).await;
        self.record(events).await;
    }

    /// The TCP listeners to hand over on a hot upgrade.
    pub(crate) async fn tcp_handoff_fds(&self) -> Vec<StreamTcpFd> {
        self.plane.lock().await.tcp_handoff_fds()
    }

    async fn record(&self, events: Vec<PlaneEvent>) {
        let node = self.role.label();
        for event in events {
            let (action, key, payload) = audit_row(node, &event);
            match &event {
                PlaneEvent::BindFailed {
                    name,
                    kind,
                    os_error,
                    port,
                    ..
                } => {
                    warn!(stream_id = %key.stream_id, kind = kind.as_str(), %os_error,
                          "stream bind failed");
                    self.alerts.send(bind_failed_alert(
                        node,
                        &key.stream_id,
                        name,
                        *kind,
                        os_error,
                        *port,
                    ));
                }
                _ => info!(stream_id = %key.stream_id, action, "stream plane"),
            }
            if let Some(slot) = &self.audit {
                lorica_api::audit::record_with_store(
                    slot.store(),
                    &lorica_api::audit::AuditContext::node("stream-plane"),
                    action,
                    ("stream", &key.stream_id),
                    None,
                    Some(&payload),
                )
                .await;
            }
        }
    }
}

/// The `stream_bind_failed` alert of one entry into the failed state
/// (D-h), raised where its `stream.bind_failed` audit row is written.
fn bind_failed_alert(
    node: &str,
    stream_id: &str,
    name: &str,
    kind: BindFailureKind,
    os_error: &str,
    port: u16,
) -> lorica_notify::AlertEvent {
    lorica_notify::AlertEvent::new(
        lorica_notify::events::AlertType::StreamBindFailed,
        format!("stream `{name}` failed to bind port {port} on {node}: {os_error}"),
    )
    .with_detail("stream_id", stream_id)
    .with_detail("stream_name", name)
    .with_detail("node", node)
    .with_detail("kind", kind.as_str())
    .with_detail("os_error", os_error)
    .with_detail("port", port.to_string())
}

/// The audit action, binding and hashed payload of `event` (D-h).
fn audit_row<'a>(
    node: &str,
    event: &'a PlaneEvent,
) -> (&'static str, &'a BindKey, serde_json::Value) {
    let base = |key: &BindKey| {
        serde_json::json!({
            "node": node,
            "address": key.listen_address.to_string(),
            "port_first": key.port_first,
            "port_last": key.port_last,
            "protocol": key.protocol.as_str(),
        })
    };
    match event {
        PlaneEvent::Bound {
            key,
            bind_gen,
            workers_serving,
            workers,
        } => {
            let mut payload = base(key);
            payload["bind_gen"] = (*bind_gen).into();
            payload["workers_serving"] = (*workers_serving).into();
            payload["workers"] = (*workers).into();
            ("stream.bind", key, payload)
        }
        PlaneEvent::Released {
            key,
            bind_gen,
            cause,
        } => {
            let mut payload = base(key);
            payload["bind_gen"] = (*bind_gen).into();
            payload["cause"] = cause.as_str().into();
            ("stream.release", key, payload)
        }
        // The name is for the alert: the row names the stream by its
        // target id, like every other `stream.*` row.
        PlaneEvent::BindFailed {
            key,
            name: _,
            kind,
            os_error,
            port,
        } => {
            let mut payload = base(key);
            payload["kind"] = kind.as_str().into();
            payload["os_error"] = os_error.as_str().into();
            payload["port"] = (*port).into();
            ("stream.bind_failed", key, payload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Mutex as StdMutex;

    use chrono::Utc;

    const TEST_ACK_TIMEOUT: Duration = Duration::from_millis(200);
    const PASS: PassSettings = PassSettings {
        drain: Duration::from_secs(30),
        listen_socket_cap: 2048,
    };
    const STANDALONE: NodeRole<'static> = NodeRole::Standalone;

    /// What a fake worker saw, fds left out.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Seen {
        Attach {
            stream_id: String,
            bind_gen: u64,
            addrs: Vec<SocketAddr>,
        },
        Detach {
            stream_id: String,
            drain_ms: u64,
        },
        Refresh {
            drain_ms: u64,
        },
        Quiesce {
            drain_ms: u64,
        },
    }

    #[derive(Debug, Clone, Copy)]
    enum Reply {
        Ack,
        /// Never answers.
        Silent,
        /// Answers when the next message arrives.
        Late,
    }

    /// A worker that answers from a script (acks once it runs out), and
    /// holds the sockets it was attached until they are detached, as a
    /// worker does.
    #[derive(Default)]
    struct FakeLink {
        script: VecDeque<Reply>,
        seen: Arc<StdMutex<Vec<Seen>>>,
        outbox: VecDeque<StreamCtlMsg>,
        late: Vec<StreamCtlMsg>,
        holding: HashMap<(String, u64), Vec<OwnedFd>>,
    }

    impl FakeLink {
        fn new(script: &[Reply]) -> (Self, Arc<StdMutex<Vec<Seen>>>) {
            let link = FakeLink {
                script: script.iter().copied().collect(),
                ..FakeLink::default()
            };
            let seen = Arc::clone(&link.seen);
            (link, seen)
        }
    }

    impl WorkerLink for FakeLink {
        async fn send(&mut self, msg: StreamCtlMsg) -> Result<(), LinkError> {
            self.outbox.extend(self.late.drain(..));
            let seq = msg.seq();
            let seen = match msg {
                StreamCtlMsg::Attach {
                    stream_id,
                    bind_gen,
                    sockets,
                    ..
                } => {
                    let addrs = sockets.iter().map(|s| s.addr).collect();
                    self.holding
                        .entry((stream_id.clone(), bind_gen))
                        .or_default()
                        .extend(sockets.into_iter().map(|s| s.fd));
                    Seen::Attach {
                        stream_id,
                        bind_gen,
                        addrs,
                    }
                }
                StreamCtlMsg::Detach {
                    stream_id,
                    bind_gen,
                    drain_ms,
                    ..
                } => {
                    self.holding.remove(&(stream_id.clone(), bind_gen));
                    Seen::Detach {
                        stream_id,
                        drain_ms,
                    }
                }
                StreamCtlMsg::Refresh { drain_ms, .. } => Seen::Refresh { drain_ms },
                StreamCtlMsg::Quiesce { drain_ms, .. } => {
                    self.holding.clear();
                    Seen::Quiesce { drain_ms }
                }
                other => panic!("a driver never sends {other:?}"),
            };
            self.seen.lock().unwrap().push(seen);
            let answer = StreamCtlMsg::Ack { seq, count: 1 };
            match self.script.pop_front().unwrap_or(Reply::Ack) {
                Reply::Ack => self.outbox.push_back(answer),
                Reply::Silent => {}
                Reply::Late => self.late.push(answer),
            }
            Ok(())
        }

        async fn recv(&mut self) -> Result<StreamCtlMsg, LinkError> {
            match self.outbox.pop_front() {
                Some(msg) => Ok(msg),
                None => std::future::pending().await,
            }
        }
    }

    fn reserved() -> ReservedPorts {
        // Ports a test never draws: the ephemeral range starts above.
        ReservedPorts {
            management: 9443,
            http: 8080,
            https: 8443,
            cluster: None,
            enrollment: None,
            automation: None,
        }
    }

    fn plane(links: Vec<FakeLink>) -> (StreamPlane<FakeLink>, StreamBindStates) {
        let states = StreamBindStates::new();
        let count = u32::try_from(links.len()).unwrap();
        let plane = StreamPlane::new(
            links
                .into_iter()
                .enumerate()
                .map(|(i, l)| (u32::try_from(i).unwrap(), l))
                .collect(),
            count,
            FdBudget::from_limit(65536),
            reserved(),
            states.clone(),
            TEST_ACK_TIMEOUT,
        );
        (plane, states)
    }

    fn stream(id: &str, protocol: StreamProtocol, first: u16, last: u16) -> Stream {
        Stream::new(
            id.into(),
            id.into(),
            protocol,
            "127.0.0.1".parse().unwrap(),
            first,
            last,
            Utc::now(),
        )
    }

    fn tcp(id: &str, port: u16) -> Stream {
        stream(id, StreamProtocol::Tcp, port, port)
    }

    /// `n` consecutive TCP ports free on 127.0.0.1 right now.
    fn free_ports(n: u16) -> u16 {
        loop {
            let probe = TcpListener::bind("127.0.0.1:0").unwrap();
            let first = probe.local_addr().unwrap().port();
            drop(probe);
            if first.checked_add(n).is_none() {
                continue;
            }
            let all_free = (first..first + n).all(|p| TcpListener::bind(("127.0.0.1", p)).is_ok());
            if all_free {
                return first;
            }
        }
    }

    fn bindable(port: u16) -> bool {
        TcpListener::bind(("127.0.0.1", port)).is_ok()
    }

    fn seen(log: &Arc<StdMutex<Vec<Seen>>>) -> Vec<Seen> {
        log.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn a_new_stream_is_bound_attached_to_every_worker_then_refreshed() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let port = free_ports(1);
        let s = tcp("s1", port);

        let events = plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        assert_eq!(
            events,
            vec![PlaneEvent::Bound {
                key: BindKey::of(&s),
                bind_gen: 1,
                workers_serving: 2,
                workers: 2,
            }]
        );
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        for log in [&seen0, &seen1] {
            assert_eq!(
                seen(log),
                vec![
                    Seen::Attach {
                        stream_id: "s1".into(),
                        bind_gen: 1,
                        addrs: vec![addr],
                    },
                    Seen::Refresh { drain_ms: 30_000 },
                ]
            );
        }
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 2,
                workers: 2
            })
        );
        assert!(TcpStream::connect(addr).is_ok(), "the port listens");
        assert_eq!(plane.tcp_handoff_fds().len(), 1);
    }

    #[tokio::test]
    async fn deleting_a_stream_detaches_it_everywhere_and_frees_the_port() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let port = free_ports(1);
        let s = tcp("s1", port);
        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;
        assert!(!bindable(port));

        let events = plane.release_stale(&[], STANDALONE, PASS).await;

        assert_eq!(
            events,
            vec![PlaneEvent::Released {
                key: BindKey::of(&s),
                bind_gen: 1,
                cause: ReleaseCause::Deleted,
            }]
        );
        assert_eq!(
            seen(&seen0).last(),
            Some(&Seen::Detach {
                stream_id: "s1".into(),
                drain_ms: 30_000
            })
        );
        assert!(bindable(port), "the port is free once every holder let go");
        assert!(states.get("s1").is_none());
    }

    #[tokio::test]
    async fn a_port_change_rebinds_under_a_new_generation() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(2);
        let before = tcp("s1", first);
        plane
            .bind_desired(
                std::slice::from_ref(&before),
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        let after = tcp("s1", first + 1);

        let mut events = plane
            .release_stale(std::slice::from_ref(&after), STANDALONE, PASS)
            .await;
        assert_eq!(states.get("s1"), Some(BindState::Pending));
        events.extend(
            plane
                .bind_desired(
                    std::slice::from_ref(&after),
                    STANDALONE,
                    PASS,
                    Trigger::Change,
                )
                .await,
        );

        assert!(matches!(
            events.as_slice(),
            [
                PlaneEvent::Released {
                    cause: ReleaseCause::Rebind,
                    bind_gen: 1,
                    ..
                },
                PlaneEvent::Bound { bind_gen: 2, .. },
            ]
        ));
        assert!(bindable(first));
        assert!(!bindable(first + 1));
        assert!(seen(&seen0).contains(&Seen::Detach {
            stream_id: "s1".into(),
            drain_ms: 30_000
        }));
    }

    #[tokio::test]
    async fn a_silent_worker_times_out_and_the_binding_counts_the_others() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[Reply::Silent, Reply::Silent]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = tcp("s1", free_ports(1));

        let start = std::time::Instant::now();
        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        // One ack timeout for the attach and one for the refresh, the
        // workers waited on together.
        assert!(start.elapsed() < TEST_ACK_TIMEOUT * 4);
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 2
            })
        );
    }

    #[tokio::test]
    async fn an_attach_acknowledged_after_its_timeout_is_credited_when_read() {
        let (w0, _) = FakeLink::new(&[Reply::Late]);
        let (mut plane, states) = plane(vec![w0]);
        let s = tcp("s1", free_ports(1));

        // The attach times out; its answer reaches the driver while it
        // waits for the refresh's.
        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 1
            })
        );
    }

    #[tokio::test]
    async fn a_range_with_a_taken_port_binds_nothing_reports_that_port_then_recovers() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(3);
        let squatter = TcpListener::bind(("127.0.0.1", first + 1)).unwrap();
        let s = stream("s1", StreamProtocol::Tcp, first, first + 2);

        let events = plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::AddressInUse,
                port,
                os_error,
                ..
            }] => {
                assert_eq!(*port, first + 1);
                assert!(os_error.contains("os error"), "{os_error}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            bindable(first),
            "the ports bound before the failure are closed"
        );
        assert!(!seen(&seen0)
            .iter()
            .any(|s| matches!(s, Seen::Attach { .. })));
        assert!(plane.has_retryable_failure());

        // Failing again is not a new entry: no second event.
        let again = plane
            .bind_desired(
                std::slice::from_ref(&s),
                STANDALONE,
                PASS,
                Trigger::RetryTick,
            )
            .await;
        assert!(again.is_empty());
        assert!(matches!(states.get("s1"), Some(BindState::Failed(_))));

        drop(squatter);
        let recovered = plane
            .bind_desired(
                std::slice::from_ref(&s),
                STANDALONE,
                PASS,
                Trigger::RetryTick,
            )
            .await;
        assert!(matches!(recovered.as_slice(), [PlaneEvent::Bound { .. }]));
        assert!(!plane.has_retryable_failure());
    }

    #[tokio::test]
    async fn a_failed_bind_raises_one_alert_per_entry_never_per_retry() {
        let first = free_ports(1);
        let squatter = TcpListener::bind(("127.0.0.1", first)).unwrap();
        let mut s = tcp("6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d", first);
        s.name = "pg".into();
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        store.create_stream(&s).expect("test setup: stream");
        let alerts = lorica_notify::AlertSender::new(16);
        let mut received = alerts.subscribe();
        let (w0, _) = FakeLink::new(&[]);
        let (plane, states) = plane(vec![w0]);
        // A follower binds a fleet-wide stream, and the alert names the
        // node by its roster name.
        let handle = StreamPlaneHandle::new(
            plane,
            Arc::new(Mutex::new(store)),
            PlaneRole::Follower("edge01".into()),
            None,
            alerts,
        );

        handle.after_commit().await;
        handle.bind_pass(Trigger::RetryTick).await;
        handle.after_commit().await;

        let alert = received.try_recv().expect("one alert");
        assert_eq!(
            alert.alert_type,
            lorica_notify::events::AlertType::StreamBindFailed
        );
        let detail = |key: &str| alert.details.get(key).map(String::as_str);
        assert_eq!(detail("stream_id"), Some(s.id.as_str()));
        assert_eq!(detail("stream_name"), Some("pg"));
        assert_eq!(detail("node"), Some("edge01"));
        assert_eq!(detail("kind"), Some("address_in_use"));
        assert_eq!(detail("port"), Some(first.to_string().as_str()));
        let os_error = detail("os_error").expect("the OS error");
        assert!(os_error.contains("os error"), "{os_error}");
        assert!(alert.summary.contains("`pg`"), "{}", alert.summary);
        assert!(
            received.try_recv().is_err(),
            "a retry or a change that fails again raises nothing"
        );

        // A recovery then a new failure is a new entry.
        drop(squatter);
        handle.bind_pass(Trigger::RetryTick).await;
        assert!(matches!(states.get(&s.id), Some(BindState::Bound { .. })));
        handle
            .store
            .lock()
            .await
            .update_stream(&Stream {
                port_first: reserved().http,
                port_last: reserved().http,
                ..s.clone()
            })
            .expect("test setup: move onto a reserved port");
        handle.before_commit().await;
        handle.after_commit().await;
        let again = received.try_recv().expect("a second entry alerts again");
        assert_eq!(
            again.details.get("kind").map(String::as_str),
            Some("reserved_port")
        );
    }

    #[tokio::test]
    async fn a_stream_id_the_channel_cannot_carry_is_a_failed_bind() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let port = free_ports(1);
        let id = "x".repeat(stream_ctl::MAX_STREAM_ID_LEN + 1);
        let s = tcp(&id, port);

        let events = plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::Other,
                os_error,
                ..
            }] => assert!(os_error.contains("stream id"), "{os_error}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(states.get(&id), Some(BindState::Failed(_))));
        assert!(bindable(port), "nothing was bound for it");
        assert!(!seen(&seen0)
            .iter()
            .any(|s| matches!(s, Seen::Attach { .. })));
    }

    #[tokio::test]
    async fn a_reserved_port_is_refused_and_left_to_the_next_change() {
        let (w0, _) = FakeLink::new(&[]);
        let (mut plane, _) = plane(vec![w0]);
        let s = tcp("s1", reserved().http);

        let events = plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::ReservedPort,
                os_error,
                port: 8080,
                ..
            }] => assert_eq!(os_error, "port 8080 is a proxy listener port"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!plane.has_retryable_failure());
    }

    #[tokio::test]
    async fn the_listen_socket_cap_refuses_the_binding_past_it() {
        let (w0, _) = FakeLink::new(&[]);
        let (mut plane, _) = plane(vec![w0]);
        let first = free_ports(2);
        let streams = vec![tcp("a", first), tcp("b", first + 1)];
        let pass = PassSettings {
            listen_socket_cap: 1,
            ..PASS
        };

        let events = plane
            .bind_desired(&streams, STANDALONE, pass, Trigger::Change)
            .await;

        assert!(matches!(events[0], PlaneEvent::Bound { .. }));
        match &events[1] {
            PlaneEvent::BindFailed {
                kind: BindFailureKind::FdBudget,
                os_error,
                ..
            } => assert!(os_error.contains("stream_listen_socket_cap"), "{os_error}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(bindable(first + 1));
    }

    #[tokio::test]
    async fn a_respawned_worker_gets_every_live_binding_replayed() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let port = free_ports(1);
        let s = tcp("s1", port);
        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        let (respawned, seen1) = FakeLink::new(&[]);
        plane.replay_worker(1, respawned, PASS).await;

        assert_eq!(
            seen(&seen1),
            vec![
                Seen::Attach {
                    stream_id: "s1".into(),
                    bind_gen: 1,
                    addrs: vec![([127, 0, 0, 1], port).into()],
                },
                Seen::Refresh { drain_ms: 30_000 },
            ]
        );
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 2,
                workers: 2
            })
        );
    }

    #[tokio::test]
    async fn udp_gives_each_worker_one_slot_socket_per_port() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let s = stream("u1", StreamProtocol::Udp, port, port);

        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        for log in [&seen0, &seen1] {
            assert!(matches!(
                &seen(log)[0],
                Seen::Attach { addrs, .. } if addrs.len() == 1
            ));
        }
        assert!(matches!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                ..
            })
        ));
        assert!(plane.tcp_handoff_fds().is_empty(), "UDP is not handed over");
    }

    #[tokio::test]
    async fn quiesce_reaches_every_worker_and_releases_with_shutdown() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = tcp("s1", free_ports(1));
        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        let events = plane.quiesce(Duration::from_secs(20)).await;

        for log in [&seen0, &seen1] {
            assert_eq!(seen(log).last(), Some(&Seen::Quiesce { drain_ms: 20_000 }));
        }
        assert!(matches!(
            events.as_slice(),
            [PlaneEvent::Released {
                cause: ReleaseCause::Shutdown,
                ..
            }]
        ));
        assert!(states.snapshot().is_empty());
    }

    #[tokio::test]
    async fn an_inherited_listener_is_adopted_and_an_unwanted_one_closed() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(2);
        let (wanted, unwanted) = (first, first + 1);
        // No SO_REUSEPORT: binding the port again would fail, so a bound
        // state proves the inherited socket was taken.
        let inherited = |id: &str, port: u16| {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();
            let fd = lorica_worker::stream_sockets::bind_tcp_stream_listener(addr).unwrap();
            (
                StreamTcpFd {
                    stream_id: id.into(),
                    bind_gen: 41,
                    addr,
                    fd: fd.as_raw_fd(),
                },
                fd,
            )
        };
        plane.adopt_inherited(vec![inherited("s1", wanted), inherited("gone", unwanted)]);
        let s = tcp("s1", wanted);

        let events = plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        assert!(
            matches!(events.as_slice(), [PlaneEvent::Bound { bind_gen: 42, .. }]),
            "{events:?}"
        );
        assert!(matches!(states.get("s1"), Some(BindState::Bound { .. })));
        assert!(matches!(&seen(&seen0)[0], Seen::Attach { .. }));
        assert!(!bindable(wanted));
        assert!(
            bindable(unwanted),
            "an inherited socket no stream wants is closed"
        );
    }

    #[tokio::test]
    async fn the_in_process_link_drives_a_real_stream_runtime() {
        let port = free_ports(1);
        let s = tcp("s1", port);
        let (peer, transport) = lorica_stream::ControlTransport::in_process_pair(8);
        let runtime = lorica_stream::StreamRuntime::spawn(
            transport,
            lorica_stream::Engines::default(),
            Arc::new(FixedTable(vec![s.clone()])),
        )
        .unwrap();
        let states = StreamBindStates::new();
        let mut plane = StreamPlane::new(
            vec![(0, InProcessLink(peer))],
            1,
            FdBudget::from_limit(65536),
            reserved(),
            states.clone(),
            STREAM_CTL_ACK_TIMEOUT,
        );

        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;

        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 1
            })
        );
        plane.quiesce(Duration::from_secs(1)).await;
        assert_eq!(*runtime.quiesced().borrow(), Some(Duration::from_secs(1)));
        runtime.stop();
    }

    #[tokio::test]
    async fn the_seqpacket_link_drives_a_real_stream_runtime() {
        let port = free_ports(1);
        let s = tcp("s1", port);
        let (supervisor_end, worker_end) = stream_ctl::create_seqpacket_pair().unwrap();
        let runtime = lorica_stream::StreamRuntime::spawn(
            lorica_stream::ControlTransport::Seqpacket(worker_end),
            lorica_stream::Engines::default(),
            Arc::new(FixedTable(vec![s.clone()])),
        )
        .unwrap();
        let states = StreamBindStates::new();
        let mut plane = StreamPlane::new(
            vec![(0, SeqpacketLink::new(supervisor_end).unwrap())],
            1,
            FdBudget::from_limit(65536),
            reserved(),
            states.clone(),
            STREAM_CTL_ACK_TIMEOUT,
        );

        plane
            .bind_desired(std::slice::from_ref(&s), STANDALONE, PASS, Trigger::Change)
            .await;
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 1
            })
        );

        plane.release_stale(&[], STANDALONE, PASS).await;
        assert!(bindable(port), "the worker closed its copy before acking");
        runtime.stop();
    }

    #[test]
    fn the_store_table_reads_what_another_connection_wrote() {
        use lorica_stream::StreamTableSource;
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let db = dir.path().join("lorica.db");
        // The store holds stream ids to the canonical UUID form.
        let id = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d";
        let writer = ConfigStore::open(&db, None).expect("test setup: store");
        writer
            .create_stream(&tcp(id, 5432))
            .expect("test setup: stream");

        let source = StoreStreamTable::open(&db, None).expect("a second connection opens");
        let table = source.load().expect("the table loads");

        assert!(table.stream(id).is_some());
        assert!(table.holds(id, None));
        assert_eq!(
            source.drain_timeout(),
            Duration::from_secs(u64::from(GlobalSettings::DEFAULT_WORKER_DRAIN_TIMEOUT_S))
        );
    }

    #[test]
    fn a_tcp_binding_declares_what_its_connections_hold() {
        let mut s = tcp("s1", 5432);
        s.max_connections = 100;
        let key = desired_bindings(std::slice::from_ref(&s), STANDALONE)
            .into_iter()
            .next()
            .expect("a desired binding");
        let held = demand_of(&key, Some(&s))
            .held
            .expect("a TCP stream declares its fds");
        assert_eq!(Some(held), lorica_stream::tcp::held_fds(&s));
        assert_eq!(
            demand_of(&key, None).held,
            None,
            "a binding whose stream is gone declares nothing"
        );
    }

    struct FixedTable(Vec<Stream>);

    impl lorica_stream::StreamTableSource for FixedTable {
        fn load(
            &self,
        ) -> Result<lorica_stream::StreamTable, Box<dyn std::error::Error + Send + Sync>> {
            Ok(lorica_stream::StreamTable::new(self.0.clone(), &[]))
        }
    }
}
