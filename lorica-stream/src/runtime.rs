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
//! The runtime applies the four control messages and answers each:
//!
//! | Message | Effect | `ack` count |
//! |---|---|---|
//! | `attach` | adopt the sockets, start one loop per socket | sockets adopted |
//! | `detach` | stop the binding's loops, close its sockets, drain its connections with `config_removed` | sockets closed |
//! | `refresh` | reload the table, drain what it no longer holds with `config_removed` | connections newly draining |
//! | `quiesce` | stop every loop, drain everything with `node_shutdown` | bindings stopped |
//!
//! A refused message is answered with a `nack`: `unknown_binding` for a
//! `detach` of a binding it does not hold, `shutting_down` for an
//! `attach` after a quiesce, `adopt_failed` when a socket cannot be
//! adopted (the whole `attach` is then dropped and its sockets closed),
//! `table_unavailable` for a `refresh` whose table load failed (the
//! previous table is kept and nothing is drained).
//!
//! A `detach` is acknowledged only once its sockets are closed, so the
//! port is free in this worker when the supervisor reads the `ack`.
//!
//! After every table load (start, `refresh`, the `attach` of an unknown
//! stream) the TCP engine is told ([`crate::StreamHandler::table_changed`]),
//! and every connection whose accepted snapshot sets
//! `close_on_backend_down` and whose backend is `Down` in the new table
//! is closed at once with `backend_down` (Story 12.3 D-i).
//!
//! Every drain duration is capped at
//! [`GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S`], the setting's hard
//! maximum, whatever the message says.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lorica_config::models::{GlobalSettings, HealthStatus, StreamEndReason};
use lorica_worker::stream_ctl::{NackReason, StreamCtlMsg, StreamSocket};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use crate::counters::{CountersSnapshot, StreamCounters};
use crate::handler::Engines;
use crate::listener::{self, AdoptedSocket, LoopContext};
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

enum Command {
    Terminate(Duration),
}

/// The handle the worker keeps on its running stream runtime. Dropping
/// it stops the runtime, so the worker holds it for its whole life.
#[derive(Debug)]
pub struct StreamRuntimeHandle {
    tracker: ConnectionTracker,
    counters: Arc<StreamCounters>,
    quiesced: watch::Receiver<Option<Duration>>,
    commands: mpsc::UnboundedSender<Command>,
    thread: Option<thread::JoinHandle<()>>,
}

impl StreamRuntimeHandle {
    /// The runtime's connection tracker; the drain watcher waits for it
    /// to be empty.
    pub fn tracker(&self) -> &ConnectionTracker {
        &self.tracker
    }

    /// The engines' counters as they stand (Story 12.3 D-r).
    pub fn counters(&self) -> CountersSnapshot {
        self.counters.snapshot()
    }

    /// Turns `Some(drain)` once the runtime is quiesced, by a `quiesce`
    /// message or by [`Self::terminate`]: the signal that arms the drain
    /// watcher, with the drain the runtime applied.
    pub fn quiesced(&self) -> watch::Receiver<Option<Duration>> {
        self.quiesced.clone()
    }

    /// Quiesce without a `quiesce` message: stop every loop and drain
    /// everything for `drain` with `node_shutdown`. The path of a SIGTERM
    /// that arrives without one (Pingora's `GracefulTerminate`, the
    /// upgrade path until Story 12.11).
    pub fn terminate(&self, drain: Duration) {
        // A send error means the runtime is already gone, which leaves
        // nothing to quiesce.
        let _ = self.commands.send(Command::Terminate(drain));
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
    quiesced: watch::Sender<Option<Duration>>,
}

struct Binding {
    stop: watch::Sender<bool>,
    loops: Vec<JoinHandle<()>>,
    ports: Vec<u16>,
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
        let counters = Arc::clone(&engines.counters);
        let runtime = StreamRuntime {
            transport,
            engines,
            source,
            table: SharedTable::default(),
            tracker: tracker.clone(),
            bindings: HashMap::new(),
            bound_ports: BoundPorts::new(),
            quiesced: quiesced_tx,
        };
        let thread = thread::Builder::new()
            .name(STREAM_THREAD_NAME.into())
            .spawn(move || rt.block_on(runtime.run(commands_rx)))
            .map_err(StreamRuntimeError::Thread)?;
        Ok(StreamRuntimeHandle {
            tracker,
            counters,
            quiesced: quiesced_rx,
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
                        info!(drain_ms = drain.as_millis() as u64,
                              "stream runtime terminated without a quiesce message");
                        self.quiesce(drain).await;
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
            self.stop_binding(binding).await;
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
            StreamCtlMsg::Quiesce { seq, drain_ms, .. } => {
                let stopped = self.quiesce(drain_duration(drain_ms)).await;
                Some(StreamCtlMsg::Ack {
                    seq,
                    count: count(stopped),
                })
            }
            StreamCtlMsg::Caps {
                seq,
                stream_id,
                caps_gen,
                ..
            } => {
                // No engine here counts sessions on a caps region yet: the
                // region's fd closes with the message and the binding
                // reports the worker as not serving, as a bad attach does.
                warn!(
                    seq,
                    %stream_id,
                    caps_gen,
                    "stream caps region refused: this runtime maps none"
                );
                Some(StreamCtlMsg::Nack {
                    seq,
                    reason: NackReason::AdoptFailed,
                })
            }
            StreamCtlMsg::Ack { seq, .. } | StreamCtlMsg::Nack { seq, .. } => {
                warn!(
                    seq,
                    "unexpected answer on the stream control channel ignored"
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
                stop: watch::channel(false).0,
                loops: Vec::new(),
                ports: Vec::new(),
            });
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
        };
        for socket in adopted {
            binding.loops.push(tokio::spawn(listener::run(
                socket,
                ctx.clone(),
                binding.stop.subscribe(),
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
        let closed = self.stop_binding(binding).await;
        let deadline = Instant::now() + drain_duration(drain_ms);
        let draining = self.tracker.drain_binding(
            &stream_id,
            bind_gen,
            deadline,
            StreamEndReason::ConfigRemoved,
        );
        self.tracker.close_expired(Instant::now());
        debug!(%stream_id, bind_gen, sockets = closed, draining, "stream binding detached");
        StreamCtlMsg::Ack {
            seq,
            count: count(closed),
        }
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

    /// Stop every binding and drain everything for `drain`. Returns the
    /// bindings stopped.
    async fn quiesce(&mut self, drain: Duration) -> usize {
        let bindings: Vec<Binding> = self.bindings.drain().map(|(_, b)| b).collect();
        let stopped = bindings.len();
        for binding in bindings {
            self.stop_binding(binding).await;
        }
        self.tracker
            .drain_all(Instant::now() + drain, StreamEndReason::NodeShutdown);
        self.tracker.close_expired(Instant::now());
        self.quiesced.send_replace(Some(drain));
        stopped
    }

    /// Stop a binding's loops, wait until each has closed its socket, and
    /// forget its ports. Returns the sockets closed.
    async fn stop_binding(&self, binding: Binding) -> usize {
        binding.stop.send_replace(true);
        let mut closed = 0;
        for task in binding.loops {
            if let Err(e) = task.await {
                error!(error = %e, "stream loop ended abnormally");
            }
            closed += 1;
        }
        for port in binding.ports {
            self.bound_ports.remove(port);
        }
        closed
    }
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
