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

//! The worker-side stream runtime (Story 12.2 D-b).
//!
//! [`StreamRuntime::spawn`] starts a dedicated OS thread named
//! `lorica-stream` driving its own tokio multi-thread runtime of one
//! worker thread, the share Pingora's service gets in a worker. It shares
//! nothing with Pingora but the process: no listener in Pingora's set, no
//! task on Pingora's runtimes.
//!
//! The runtime applies the five control messages and answers each:
//!
//! | Message | Effect | `ack` count |
//! |---|---|---|
//! | `attach` | adopt the sockets, start one loop per socket | sockets adopted |
//! | `detach` | TCP: stop the binding's loops, close its sockets; UDP: put its loops in drain mode; then drain its connections or sessions with `config_removed` | TCP: sockets closed; UDP: sockets put in drain |
//! | `refresh` | reload the table, drain what it no longer holds with `config_removed` | connections newly draining |
//! | `quiesce` | stop every loop and drain everything with the reason's end reason (below) | bindings stopped or draining |
//! | `caps` | map the stream's caps region and make it the stream's current one in the [`CapsRegistry`] the engines read | 1 |
//!
//! A refused message is answered with a `nack`: `unknown_binding` for a
//! `detach` of a binding it does not hold, `shutting_down` for an
//! `attach` after a quiesce, `adopt_failed` when a socket cannot be
//! adopted (the whole `attach` is then dropped and its sockets closed)
//! or a caps region cannot be used (not mappable, another layout
//! version, another `caps_gen` than the message's, no such slot: the
//! stream's sessions then have no region in this worker),
//! `table_unavailable` for a `refresh` whose table load failed (the
//! previous table is kept and nothing is drained).
//!
//! A TCP `detach` is acknowledged only once its sockets are closed, so
//! the port is free in this worker when the supervisor reads the `ack`.
//! A UDP binding drains with its sockets open (Story 12.5 D-m): a session
//! is only reachable through the slot socket its client hashes to, so
//! its loops keep serving existing sessions, open none, and close their
//! sockets when the binding's last session ends or at the drain
//! deadline, whichever comes first.
//!
//! A `quiesce` carries its reason (Story 12.11 D-a), which
//! [`quiesce_end_reason`] maps to the end reason of what it closes:
//!
//! - `shutdown`, the node stopping: every TCP loop stops and closes its
//!   listener, every UDP binding drains open as on a `detach`, everything
//!   drains with `node_shutdown`;
//! - `upgrade`, a new generation holding the same sockets: every loop
//!   stops and closes this worker's own descriptor, never `shutdown(2)`,
//!   which would stop the new generation's accepts too (D-c). A UDP
//!   session keeps its slot socket to answer from the address its client
//!   wrote to, and reads nothing more from it: the new generation does
//!   (D-e). Each connection or session then follows its stream's
//!   [`Stream::upgrade_policy`]: `close` ends at once, `drain` and
//!   `relay_in_flight` at their deadline at the latest, with
//!   `drained_by_upgrade`. The worker's drain report, sent by
//!   [`StreamRuntimeHandle::send_drain_report`], answers this quiesce.
//!
//! Only the first quiesce counts: a later one, or a
//! [`StreamRuntimeHandle::terminate`], changes neither the reason nor the
//! deadline.
//!
//! After every table load (start, `refresh`, the `attach` of an unknown
//! stream) both engines are told
//! ([`crate::StreamHandler::table_changed`],
//! [`crate::DatagramHandler::table_changed`]), the caps regions of
//! streams the table no longer holds are forgotten, and every connection
//! or session whose accepted snapshot sets `close_on_backend_down` and
//! whose backend is `Down` in the new table is closed at once with
//! `backend_down` (Story 12.3 D-i).
//!
//! Every drain duration is capped at
//! [`GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S`], the setting's hard
//! maximum, whatever the message says.
//!
//! Nothing restarts a part of the runtime that dies (Story 12.2 D-b, as
//! amended on 2026-11-21): when the control thread panics, or a TCP
//! accept loop or UDP receive loop panics or ends without being told to
//! stop, [`StreamRuntimeHandle::died`] says why, and the process is
//! expected to exit so that a fresh one serves the streams again. A
//! panic inside one connection's or session's own task ends that task
//! only.

use std::any::Any;
use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[cfg(doc)]
use lorica_config::models::Stream;
use lorica_config::models::{GlobalSettings, HealthStatus, StreamEndReason, UpgradePolicy};
use lorica_shmem::StreamCapsRegion;
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{
    DrainEnd, DrainReport, DrainedEntry, NackReason, QuiesceReason, ReportSent, StreamCtlError,
    StreamCtlMsg, StreamSocket,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::caps::CapsRegistry;
use crate::counters::{CountersSnapshot, StreamCounters};
use crate::handler::Engines;
use crate::listener::{self, AdoptedSocket, LoopContext, LoopMode};
use crate::local::BoundPorts;
use crate::table::{SharedTable, StreamTable, StreamTableSource};
use crate::tracker::ConnectionTracker;
use crate::transport::{ActiveTransport, ControlTransport, TransportError};

/// Name of the runtime's OS thread, and prefix of its tokio thread.
pub const STREAM_THREAD_NAME: &str = "lorica-stream";

/// Why a runtime could not start.
#[derive(Debug, thiserror::Error)]
pub enum StreamRuntimeError {
    /// The tokio runtime could not be built.
    #[error("cannot build the stream runtime: {0}")]
    Runtime(io::Error),
    /// The control channel could not be registered.
    #[error("cannot register the stream control channel: {0}")]
    Transport(io::Error),
    /// The OS thread could not be spawned.
    #[error("cannot spawn the stream thread: {0}")]
    Thread(io::Error),
}

/// How long [`StreamRuntimeHandle::send_drain_report`] waits for the
/// runtime thread to hand the report to the channel. The sends never
/// wait; this bounds a runtime thread busy elsewhere.
pub const DRAIN_REPORT_TIMEOUT: Duration = Duration::from_secs(1);

/// The end reason of what a quiesce for `reason` closes (Story 12.11
/// D-a).
pub fn quiesce_end_reason(reason: QuiesceReason) -> StreamEndReason {
    match reason {
        QuiesceReason::Shutdown => StreamEndReason::NodeShutdown,
        QuiesceReason::Upgrade => StreamEndReason::DrainedByUpgrade,
    }
}

/// How the runtime was quiesced: the drain it applied and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quiesced {
    /// The drain, capped at the setting's hard maximum.
    pub drain: Duration,
    /// Why; what the drain watcher closes the leftovers with.
    pub reason: QuiesceReason,
}

/// Why a drain report did not reach the channel.
#[derive(Debug, thiserror::Error)]
pub enum DrainReportError {
    /// No `quiesce reason=upgrade` reached the runtime: there is no
    /// upgrade to report on.
    #[error("the stream runtime was not quiesced for an upgrade")]
    NotUpgrading,
    /// The runtime thread is gone.
    #[error("the stream runtime is gone")]
    RuntimeGone,
    /// The runtime thread did not take the report in time.
    #[error("the stream runtime did not send the report in time")]
    Timeout,
    /// The channel refused the end marker.
    #[error(transparent)]
    Channel(StreamCtlError),
}

/// What stopped part of a stream runtime without it being asked to:
/// the process should exit on it (Story 12.2 D-b).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StreamDeath {
    /// The control thread panicked: no control message is applied any
    /// more, and every loop of the runtime is gone with it.
    #[error("the stream control thread panicked: {cause}")]
    Control {
        /// The panic message.
        cause: String,
    },
    /// A TCP accept loop or a UDP receive loop panicked, or ended while
    /// its binding was still serving or draining: its socket is read by
    /// nothing in this process.
    #[error("the {proto} loop of stream {stream_id} (bind_gen {bind_gen}) ended: {cause}")]
    Loop {
        /// The loop's stream.
        stream_id: String,
        /// The loop's binding generation.
        bind_gen: u64,
        /// The loop's socket protocol.
        proto: StreamProto,
        /// Why it ended: the panic message, or what made it return.
        cause: String,
    },
}

/// The sending side of [`StreamRuntimeHandle::died`], shared by the
/// control thread and every loop. The first death raised stands.
#[derive(Debug, Clone)]
pub(crate) struct DeathSignal(Arc<watch::Sender<Option<StreamDeath>>>);

impl DeathSignal {
    fn new() -> (Self, watch::Receiver<Option<StreamDeath>>) {
        let (tx, rx) = watch::channel(None);
        (DeathSignal(Arc::new(tx)), rx)
    }

    pub(crate) fn raise(&self, death: StreamDeath) {
        self.0.send_if_modified(|slot| {
            if slot.is_some() {
                return false;
            }
            *slot = Some(death);
            true
        });
    }
}

/// The message of a caught panic.
pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_else(|| "a panic without a message".to_string())
}

enum Command {
    Terminate(Duration),
    Report {
        report: DrainReport,
        reply: std::sync::mpsc::SyncSender<Result<ReportSent, DrainReportError>>,
    },
}

/// The handle the worker keeps on its running stream runtime. Dropping
/// it stops the runtime, so the worker holds it for its whole life.
#[derive(Debug)]
pub struct StreamRuntimeHandle {
    tracker: ConnectionTracker,
    counters: Arc<StreamCounters>,
    quiesced: watch::Receiver<Option<Quiesced>>,
    died: watch::Receiver<Option<StreamDeath>>,
    commands: mpsc::UnboundedSender<Command>,
    thread: Option<thread::JoinHandle<()>>,
}

impl StreamRuntimeHandle {
    /// Turns `Some` when part of the runtime stops without being asked
    /// to (see [`StreamDeath`]): nothing restarts it, so the process
    /// exits on it. Its sender goes away with the value still `None`
    /// once the runtime has stopped on its own terms ([`Self::stop`], or
    /// dropping the handle).
    pub fn died(&self) -> watch::Receiver<Option<StreamDeath>> {
        self.died.clone()
    }

    /// The runtime's connection tracker; the drain watcher waits for it
    /// to be empty.
    pub fn tracker(&self) -> &ConnectionTracker {
        &self.tracker
    }

    /// The engines' counters as they stand (Story 12.3 D-r).
    pub fn counters(&self) -> CountersSnapshot {
        self.counters.snapshot()
    }

    /// Turns `Some` once the runtime is quiesced, by a `quiesce` message
    /// or by [`Self::terminate`]: the signal that arms the drain watcher,
    /// with the drain the runtime applied and its reason.
    pub fn quiesced(&self) -> watch::Receiver<Option<Quiesced>> {
        self.quiesced.clone()
    }

    /// Quiesce without a `quiesce` message: stop every loop and drain
    /// everything for `drain` with `node_shutdown`. The path of a SIGTERM
    /// that arrives without one (Pingora's `GracefulTerminate`), which a
    /// worker cannot tell from a stop: an upgrade always quiesces first,
    /// and a runtime already quiesced ignores it.
    pub fn terminate(&self, drain: Duration) {
        // A send error means the runtime is already gone, which leaves
        // nothing to quiesce.
        let _ = self.commands.send(Command::Terminate(drain));
    }

    /// Send this worker's upgrade drain report (Story 12.11 D-g) to the
    /// supervisor, answering the `quiesce reason=upgrade` it got: the
    /// tracker's per-stream counts, how the drain ended and the HTTP
    /// requests it cut. Never waits on the channel, and waits at most
    /// [`DRAIN_REPORT_TIMEOUT`] for the runtime thread.
    ///
    /// # Errors
    ///
    /// [`DrainReportError`]: no upgrade quiesce, the runtime gone or
    /// late, or the end marker refused (a full socket buffer).
    pub fn send_drain_report(
        &self,
        end: DrainEnd,
        http_cut: u64,
    ) -> Result<ReportSent, DrainReportError> {
        let entries = self
            .tracker
            .upgrade_drain_counts()
            .into_iter()
            .map(|(stream_id, counts)| DrainedEntry {
                stream_id,
                closed: counts.closed,
                finished: counts.finished,
            })
            .collect();
        let (reply, answer) = std::sync::mpsc::sync_channel(1);
        self.commands
            .send(Command::Report {
                report: DrainReport {
                    end,
                    http_cut,
                    entries,
                },
                reply,
            })
            .map_err(|_| DrainReportError::RuntimeGone)?;
        match answer.recv_timeout(DRAIN_REPORT_TIMEOUT) {
            Ok(sent) => sent,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(DrainReportError::Timeout),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                Err(DrainReportError::RuntimeGone)
            }
        }
    }

    /// Stop the runtime and wait for its thread. Live connections are
    /// cut without an end reason, so the stop path quiesces and drains
    /// first; this is for the process's last moment and for tests.
    pub fn stop(mut self) {
        self.join();
    }

    fn join(&mut self) {
        let (closed, _) = mpsc::unbounded_channel();
        drop(std::mem::replace(&mut self.commands, closed));
        if let Some(thread) = self.thread.take() {
            if thread.join().is_err() {
                error!("the stream runtime thread panicked");
            }
        }
    }
}

impl Drop for StreamRuntimeHandle {
    fn drop(&mut self) {
        self.join();
    }
}

/// The worker-side stream runtime.
pub struct StreamRuntime {
    transport: ActiveTransport,
    engines: Engines,
    source: Arc<dyn StreamTableSource>,
    table: SharedTable,
    tracker: ConnectionTracker,
    bindings: HashMap<(String, u64), Binding>,
    bound_ports: BoundPorts,
    caps: CapsRegistry,
    /// The tasks closing draining UDP bindings (D-m).
    draining: Vec<JoinHandle<()>>,
    /// Turns true when the runtime ends, closing every draining binding
    /// at once.
    ending: watch::Sender<bool>,
    quiesced: watch::Sender<Option<Quiesced>>,
    /// The seq of the `quiesce reason=upgrade` this runtime applied: the
    /// drain report answers it.
    upgrade_seq: Option<u64>,
    death: DeathSignal,
}

struct Binding {
    mode: watch::Sender<LoopMode>,
    loops: Vec<JoinHandle<()>>,
    ports: Vec<u16>,
    /// Whether its sockets are UDP ones, which drain open (D-m).
    udp: bool,
}

fn drain_duration(drain_ms: u64) -> Duration {
    let max_ms = u64::from(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S) * 1000;
    Duration::from_millis(drain_ms.min(max_ms))
}

impl StreamRuntime {
    /// Start the runtime on its own thread, reading control messages from
    /// `transport`, serving with `engines`, loading the stream table from
    /// `source` (once at start, then on every `refresh` and on an
    /// `attach` for a stream the table does not hold yet).
    ///
    /// # Errors
    ///
    /// [`StreamRuntimeError`] when the runtime, the channel registration
    /// or the thread cannot be created. Nothing is left running then.
    pub fn spawn(
        transport: ControlTransport,
        engines: Engines,
        source: Arc<dyn StreamTableSource>,
    ) -> Result<StreamRuntimeHandle, StreamRuntimeError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name(STREAM_THREAD_NAME)
            .enable_all()
            .build()
            .map_err(StreamRuntimeError::Runtime)?;
        let transport = {
            let _entered = rt.enter();
            ActiveTransport::activate(transport).map_err(StreamRuntimeError::Transport)?
        };
        let tracker = ConnectionTracker::new();
        let (quiesced_tx, quiesced_rx) = watch::channel(None);
        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let (death, died) = DeathSignal::new();
        let counters = Arc::clone(&engines.counters);
        let runtime = StreamRuntime {
            transport,
            engines,
            source,
            table: SharedTable::default(),
            tracker: tracker.clone(),
            bindings: HashMap::new(),
            bound_ports: BoundPorts::new(),
            caps: CapsRegistry::new(),
            draining: Vec::new(),
            ending: watch::channel(false).0,
            quiesced: quiesced_tx,
            upgrade_seq: None,
            death: death.clone(),
        };
        let thread = thread::Builder::new()
            .name(STREAM_THREAD_NAME.into())
            .spawn(move || {
                let served =
                    panic::catch_unwind(AssertUnwindSafe(|| rt.block_on(runtime.run(commands_rx))));
                if let Err(payload) = served {
                    death.raise(StreamDeath::Control {
                        cause: panic_message(&*payload),
                    });
                }
            })
            .map_err(StreamRuntimeError::Thread)?;
        Ok(StreamRuntimeHandle {
            tracker,
            counters,
            quiesced: quiesced_rx,
            died,
            commands: commands_tx,
            thread: Some(thread),
        })
    }

    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        self.reload_table();
        let reaper = tokio::spawn(reap(self.tracker.clone()));
        let mut channel_open = true;
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(Command::Terminate(drain)) => {
                        if self.quiesced.borrow().is_none() {
                            info!(drain_ms = drain.as_millis() as u64,
                                  "stream runtime terminated without a quiesce message");
                        }
                        self.quiesce(drain, QuiesceReason::Shutdown, None).await;
                    }
                    Some(Command::Report { report, reply }) => {
                        let sent = match self.upgrade_seq {
                            Some(seq) => self
                                .transport
                                .try_send_report(seq, report)
                                .map_err(DrainReportError::Channel),
                            None => Err(DrainReportError::NotUpgrading),
                        };
                        // The watcher may have given up waiting; nothing
                        // is left to tell it then.
                        let _ = reply.send(sent);
                    }
                    None => break,
                },
                received = self.transport.recv(), if channel_open => match received {
                    Ok(msg) => {
                        if let Some(answer) = self.apply(msg).await {
                            if let Err(e) = self.transport.send(answer).await {
                                warn!(error = %e, "stream control answer not sent");
                            }
                        }
                    }
                    Err(TransportError::Message(e)) => {
                        warn!(error = %e, "stream control message dropped");
                    }
                    Err(TransportError::Lost(e)) => {
                        warn!(error = %e,
                              "stream control channel lost; the loops keep serving");
                        channel_open = false;
                    }
                },
            }
        }
        reaper.abort();
        let bindings: Vec<Binding> = self.bindings.drain().map(|(_, b)| b).collect();
        for binding in bindings {
            stop_binding(binding, &self.bound_ports).await;
        }
        self.ending.send_replace(true);
        for task in self.draining.drain(..) {
            if let Err(e) = task.await {
                error!(error = %e, "draining UDP binding ended abnormally");
            }
        }
    }

    fn reload_table(&self) -> bool {
        match self.source.load() {
            Ok(table) => {
                self.table.replace(table);
                self.table_changed(&self.table.current());
                true
            }
            Err(e) => {
                error!(error = %e, "stream table not loaded; keeping the previous one");
                false
            }
        }
    }

    /// Tell the engine, then close the connections whose accepted
    /// snapshot asks to follow their backend down (D-i). Lifecycle
    /// `closing` and `closed` do not count: they are an operator's
    /// drain, which keeps established connections.
    fn table_changed(&self, table: &StreamTable) {
        if let Some(tcp) = &self.engines.tcp {
            tcp.table_changed(table);
        }
        if let Some(udp) = &self.engines.udp {
            udp.table_changed(table);
        }
        // A `caps` precedes the `attach` of a new stream, whose table
        // load reads the store the supervisor wrote it to first, so a
        // stream the table lacks is one that left.
        self.caps
            .retain(|stream_id| table.stream(stream_id).is_some());
        let now = Instant::now();
        let down = self.tracker.drain_where(
            |e| {
                e.snapshot.close_on_backend_down
                    && e.backend_id
                        .and_then(|b| table.backend(b))
                        .is_some_and(|b| b.health_status == HealthStatus::Down)
            },
            now,
            StreamEndReason::BackendDown,
        );
        if down > 0 {
            self.tracker.close_expired(now);
            info!(
                connections = down,
                "stream connections closed: their backend is down"
            );
        }
    }

    async fn apply(&mut self, msg: StreamCtlMsg) -> Option<StreamCtlMsg> {
        match msg {
            StreamCtlMsg::Attach {
                seq,
                stream_id,
                bind_gen,
                sockets,
            } => Some(self.attach(seq, stream_id, bind_gen, sockets)),
            StreamCtlMsg::Detach {
                seq,
                stream_id,
                bind_gen,
                drain_ms,
            } => Some(self.detach(seq, stream_id, bind_gen, drain_ms).await),
            StreamCtlMsg::Refresh { seq, drain_ms } => Some(self.refresh(seq, drain_ms)),
            StreamCtlMsg::Quiesce {
                seq,
                reason,
                drain_ms,
            } => {
                let stopped = self
                    .quiesce(drain_duration(drain_ms), reason, Some(seq))
                    .await;
                Some(StreamCtlMsg::Ack {
                    seq,
                    count: count(stopped),
                })
            }
            StreamCtlMsg::Caps {
                seq,
                stream_id,
                caps_gen,
                slot,
                region,
            } => Some(self.adopt_caps(seq, &stream_id, caps_gen, slot, region)),
            StreamCtlMsg::Ack { seq, .. }
            | StreamCtlMsg::Nack { seq, .. }
            | StreamCtlMsg::Drained { seq, .. }
            | StreamCtlMsg::DrainedEnd { seq, .. } => {
                warn!(
                    seq,
                    "unexpected worker-to-supervisor message on the stream control channel ignored"
                );
                None
            }
        }
    }

    fn attach(
        &mut self,
        seq: u64,
        stream_id: String,
        bind_gen: u64,
        sockets: Vec<StreamSocket>,
    ) -> StreamCtlMsg {
        if self.quiesced.borrow().is_some() {
            return StreamCtlMsg::Nack {
                seq,
                reason: NackReason::ShuttingDown,
            };
        }
        let mut adopted: Vec<AdoptedSocket> = Vec::with_capacity(sockets.len());
        let mut ports: Vec<u16> = Vec::with_capacity(sockets.len());
        let udp = sockets.iter().any(|s| s.proto == StreamProto::Udp);
        for socket in sockets {
            match listener::adopt(socket.proto, socket.fd) {
                Ok(a) => {
                    ports.push(a.port().unwrap_or(socket.addr.port()));
                    adopted.push(a);
                }
                Err(e) => {
                    warn!(%stream_id, bind_gen, addr = %socket.addr, error = %e,
                          "stream socket not adopted; attach refused");
                    return StreamCtlMsg::Nack {
                        seq,
                        reason: NackReason::AdoptFailed,
                    };
                }
            }
        }
        if self.table.current().stream(&stream_id).is_none() {
            // The attach of a new stream comes before the `refresh` that
            // would bring it into the table.
            self.reload_table();
        }
        let n = adopted.len();
        let binding = self
            .bindings
            .entry((stream_id.clone(), bind_gen))
            .or_insert_with(|| Binding {
                mode: watch::channel(LoopMode::Serving).0,
                loops: Vec::new(),
                ports: Vec::new(),
                udp: false,
            });
        binding.udp |= udp;
        for port in ports {
            self.bound_ports.add(port);
            binding.ports.push(port);
        }
        let ctx = LoopContext {
            stream_id: stream_id.clone(),
            bind_gen,
            table: self.table.clone(),
            tracker: self.tracker.clone(),
            engines: self.engines.clone(),
            bound_ports: self.bound_ports.clone(),
            caps: self.caps.clone(),
            death: self.death.clone(),
        };
        for socket in adopted {
            binding.loops.push(tokio::spawn(listener::run(
                socket,
                ctx.clone(),
                binding.mode.subscribe(),
            )));
        }
        debug!(%stream_id, bind_gen, sockets = n, "stream sockets attached");
        StreamCtlMsg::Ack {
            seq,
            count: count(n),
        }
    }

    async fn detach(
        &mut self,
        seq: u64,
        stream_id: String,
        bind_gen: u64,
        drain_ms: u64,
    ) -> StreamCtlMsg {
        let Some(binding) = self.bindings.remove(&(stream_id.clone(), bind_gen)) else {
            return StreamCtlMsg::Nack {
                seq,
                reason: NackReason::UnknownBinding,
            };
        };
        let deadline = Instant::now() + drain_duration(drain_ms);
        let sockets = if binding.udp {
            let sockets = binding.loops.len();
            self.drain_open(
                stream_id.clone(),
                bind_gen,
                binding,
                deadline,
                StreamEndReason::ConfigRemoved,
            );
            sockets
        } else {
            stop_binding(binding, &self.bound_ports).await
        };
        let draining = self.tracker.drain_binding(
            &stream_id,
            bind_gen,
            deadline,
            StreamEndReason::ConfigRemoved,
        );
        self.tracker.close_expired(Instant::now());
        debug!(%stream_id, bind_gen, sockets, draining, "stream binding detached");
        StreamCtlMsg::Ack {
            seq,
            count: count(sockets),
        }
    }

    /// Put a UDP binding's loops in drain mode and hand it to a task
    /// that closes its sockets when its last session ends, at
    /// `deadline`, or when the runtime ends, whichever comes first
    /// (D-m). Its sessions are drained by the caller, with `reason`.
    fn drain_open(
        &mut self,
        stream_id: String,
        bind_gen: u64,
        binding: Binding,
        deadline: Instant,
        reason: StreamEndReason,
    ) {
        binding.mode.send_replace(LoopMode::Draining);
        self.draining.retain(|task| !task.is_finished());
        let tracker = self.tracker.clone();
        let bound_ports = self.bound_ports.clone();
        let mut ending = self.ending.subscribe();
        self.draining.push(tokio::spawn(async move {
            tokio::select! {
                _ = tracker.binding_ended(&stream_id, bind_gen) => {}
                _ = tokio::time::sleep_until(deadline) => {}
                _ = ending.wait_for(|e| *e) => {}
            }
            // A loop that read `serving` just before the switch may have
            // opened a session after its binding was drained: it ends now
            // with the binding's reason rather than outliving its socket.
            let now = Instant::now();
            tracker.drain_binding(&stream_id, bind_gen, now, reason);
            tracker.close_expired(now);
            let closed = stop_binding(binding, &bound_ports).await;
            debug!(%stream_id, bind_gen, sockets = closed, "draining UDP binding closed");
        }));
    }

    fn refresh(&mut self, seq: u64, drain_ms: u64) -> StreamCtlMsg {
        if !self.reload_table() {
            // Nothing to drain against: the previous table is kept and
            // the next `refresh` retries the load.
            return StreamCtlMsg::Nack {
                seq,
                reason: NackReason::TableUnavailable,
            };
        }
        let table = self.table.current();
        let deadline = Instant::now() + drain_duration(drain_ms);
        let draining = self.tracker.drain_where(
            |e| !table.holds(e.stream_id, e.backend_id),
            deadline,
            StreamEndReason::ConfigRemoved,
        );
        self.tracker.close_expired(Instant::now());
        StreamCtlMsg::Ack {
            seq,
            count: count(draining),
        }
    }

    /// Stop every binding and drain everything for `drain` with the end
    /// reason of `reason`, as the module doc describes; `seq` is the
    /// message's, which the drain report answers. Returns the bindings
    /// stopped or draining: 0 when already quiesced, which changes
    /// nothing.
    async fn quiesce(&mut self, drain: Duration, reason: QuiesceReason, seq: Option<u64>) -> usize {
        let already = *self.quiesced.borrow();
        if let Some(first) = already {
            if seq.is_some() {
                info!(
                    first = first.reason.as_str(),
                    again = reason.as_str(),
                    "stream runtime already quiesced; the first quiesce stands"
                );
            }
            return 0;
        }
        let now = Instant::now();
        let deadline = now + drain;
        let end = quiesce_end_reason(reason);
        let bindings: Vec<((String, u64), Binding)> = self.bindings.drain().collect();
        let stopped = bindings.len();
        for ((stream_id, bind_gen), binding) in bindings {
            if binding.udp && reason == QuiesceReason::Shutdown {
                self.drain_open(stream_id, bind_gen, binding, deadline, end);
            } else {
                // TCP: the loops drop their listeners, a `close` of this
                // worker's descriptors. UDP on an upgrade: the loops stop
                // reading; each session keeps its own handle on its slot
                // socket to answer from.
                stop_binding(binding, &self.bound_ports).await;
            }
        }
        if reason == QuiesceReason::Upgrade {
            self.upgrade_seq = seq;
            self.tracker.drain_where(
                |e| e.snapshot.upgrade_policy() == UpgradePolicy::Close,
                now,
                end,
            );
        }
        self.tracker.drain_all(deadline, end);
        self.tracker.close_expired(Instant::now());
        self.quiesced.send_replace(Some(Quiesced { drain, reason }));
        stopped
    }

    /// Map the caps region of stream `stream_id` and make it the
    /// stream's current one under worker slot `slot` (D-d).
    fn adopt_caps(
        &self,
        seq: u64,
        stream_id: &str,
        caps_gen: u64,
        slot: u32,
        region: OwnedFd,
    ) -> StreamCtlMsg {
        let refused = |why: &dyn std::fmt::Display| {
            warn!(seq, %stream_id, caps_gen, slot, reason = %why,
                  "stream caps region refused");
            StreamCtlMsg::Nack {
                seq,
                reason: NackReason::AdoptFailed,
            }
        };
        let region = match StreamCapsRegion::open(region) {
            Ok(region) => Arc::new(region),
            Err(e) => return refused(&e),
        };
        if region.caps_gen() != caps_gen {
            return refused(&format_args!(
                "the region is caps_gen {}, the message {caps_gen}",
                region.caps_gen()
            ));
        }
        let Some(worker) = region.worker(slot) else {
            return refused(&format_args!(
                "the region has {} worker slots",
                region.layout().workers
            ));
        };
        self.caps.adopt(stream_id, worker);
        debug!(%stream_id, caps_gen, slot, "stream caps region adopted");
        StreamCtlMsg::Ack { seq, count: 1 }
    }
}

/// Stop a binding's loops, wait until each has closed its socket, and
/// forget its ports. Returns the sockets closed.
async fn stop_binding(binding: Binding, bound_ports: &BoundPorts) -> usize {
    binding.mode.send_replace(LoopMode::Stopped);
    let mut closed = 0;
    for task in binding.loops {
        if let Err(e) = task.await {
            error!(error = %e, "stream loop ended abnormally");
        }
        closed += 1;
    }
    for port in binding.ports {
        bound_ports.remove(port);
    }
    closed
}

/// Close each draining connection at its deadline.
async fn reap(tracker: ConnectionTracker) {
    loop {
        match tracker.next_deadline() {
            Some(deadline) => {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {}
                    _ = tracker.drains_changed() => {}
                }
            }
            None => tracker.drains_changed().await,
        }
        tracker.close_expired(Instant::now());
    }
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_is_capped_at_the_setting_maximum() {
        assert_eq!(drain_duration(250), Duration::from_millis(250));
        assert_eq!(
            drain_duration(u64::MAX),
            Duration::from_secs(u64::from(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S))
        );
    }
}
