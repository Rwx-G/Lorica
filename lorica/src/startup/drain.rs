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

//! How a stop drains (Story 12.2 D-f).
//!
//! - [`pingora_server_conf`]: Pingora's own shutdown waits, from the
//!   drain setting's hard maximum instead of its 300 s `EXIT_TIMEOUT`.
//! - The drain watcher ([`wait_for_drain`], [`arm_worker_drain`]): once
//!   a stop starts, it ends the process as soon as no HTTP request and
//!   no stream connection is in flight, or at the drain deadline, having
//!   first let the stream tracker close what is left with
//!   `node_shutdown`. This is what makes a stop take as long as the
//!   traffic needs and no longer.
//! - The stop keepalive ([`start_stop_keepalive`]): while a stop drains
//!   under systemd, `EXTEND_TIMEOUT_USEC` keeps the unit's
//!   `TimeoutStopSec` from cutting it short.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use lorica_config::models::{GlobalSettings, StreamEndReason};
use lorica_config::ConfigStore;
use lorica_core::server::configuration::ServerConf;
use lorica_core::server::ExecutionPhase;
use lorica_stream::{ConnectionTracker, StreamRuntimeHandle};
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::startup::hot_upgrade;

/// How long Pingora gives its runtimes to stop once its grace period
/// ends. Upstream's default, set explicitly so no wait is left implicit.
pub(crate) const PINGORA_RUNTIME_SHUTDOWN_TIMEOUT_S: u64 = 5;

/// How often the drain watcher checks for traffic.
pub(crate) const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// How long the watcher lets the stream engines end what the tracker
/// closed at the deadline, so each writes its own end reason.
pub(crate) const DEADLINE_CLOSE_GRACE: Duration = Duration::from_secs(1);

/// Margin the supervisor adds to the drain before it SIGKILLs a worker:
/// a worker's watcher exits by itself at the drain deadline, so the kill
/// only meets one whose watcher failed.
pub(crate) const WORKER_KILL_MARGIN: Duration = Duration::from_secs(10);

/// How often the stop keepalive renews its extension.
pub(crate) const STOP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// What each keepalive message asks systemd for. Three renewals fit in
/// one extension, so two lost or late messages never let the stop
/// timeout fire on a drain in progress.
pub(crate) const STOP_KEEPALIVE_EXTENSION: Duration = Duration::from_secs(30);

const _: () = assert!(
    STOP_KEEPALIVE_EXTENSION.as_secs() >= 3 * STOP_KEEPALIVE_INTERVAL.as_secs(),
    "the keepalive must renew at least three times per extension"
);

/// Lorica's `ServerConf` for a Pingora `Server`: `base` with the grace
/// period set to the drain setting's hard maximum and the runtime
/// shutdown timeout set explicitly.
///
/// The grace is the bound, not the current value, because a
/// `ServerConf` is frozen into the `Server` for the process's life while
/// the setting changes at runtime: the drain watcher applies the current
/// value and ends the process as soon as traffic is gone, so Pingora's
/// grace is a backstop it always beats.
pub(crate) fn pingora_server_conf(base: ServerConf) -> ServerConf {
    ServerConf {
        grace_period_seconds: Some(u64::from(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S)),
        graceful_shutdown_timeout_seconds: Some(PINGORA_RUNTIME_SHUTDOWN_TIMEOUT_S),
        ..base
    }
}

/// The drain `settings` ask for, capped at the setting's hard maximum.
pub(crate) fn drain_timeout(settings: &GlobalSettings) -> Duration {
    Duration::from_secs(u64::from(
        settings
            .worker_drain_timeout_s
            .min(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S),
    ))
}

/// The stored drain setting, or its default when the store cannot be
/// read: a stop must never fail for want of a setting.
pub(crate) fn stored_drain_timeout(store: &ConfigStore) -> Duration {
    match store.get_global_settings() {
        Ok(settings) => drain_timeout(&settings),
        Err(e) => {
            warn!(error = %e, "drain setting unreadable; draining for the default");
            Duration::from_secs(u64::from(GlobalSettings::DEFAULT_WORKER_DRAIN_TIMEOUT_S))
        }
    }
}

/// What the drain watcher looks at: the HTTP requests in flight and the
/// stream connections and sessions the tracker holds.
#[derive(Debug, Clone)]
pub(crate) struct DrainProbe {
    /// `LoricaProxy::active_connections`, which counts in-flight
    /// requests, not idle keepalive connections.
    pub(crate) http_in_flight: Arc<AtomicU64>,
    /// The stream runtime's tracker.
    pub(crate) streams: ConnectionTracker,
}

impl DrainProbe {
    fn idle(&self) -> bool {
        self.http_in_flight.load(Ordering::Acquire) == 0 && self.streams.is_empty()
    }

    /// Close every stream connection still open, with `node_shutdown`
    /// unless it was already draining for another reason.
    fn close_remaining(&self) {
        let now = tokio::time::Instant::now();
        self.streams.drain_all(now, StreamEndReason::NodeShutdown);
        self.streams.close_expired(now);
    }
}

/// How a drain ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainEnd {
    /// No traffic was left before the deadline.
    Idle,
    /// The deadline passed with traffic still in flight.
    Deadline,
}

/// Wait, blocking, until `probe` is idle or `drain` has elapsed,
/// checking every `poll`. At the deadline the stream connections left
/// are closed with `node_shutdown` and given [`DEADLINE_CLOSE_GRACE`] to
/// end, so their end reason is written here and never left to the exit.
pub(crate) fn wait_for_drain(probe: &DrainProbe, drain: Duration, poll: Duration) -> DrainEnd {
    let deadline = Instant::now() + drain;
    loop {
        if probe.idle() {
            return DrainEnd::Idle;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    }
    probe.close_remaining();
    let grace_end = Instant::now() + DEADLINE_CLOSE_GRACE;
    while !probe.streams.is_empty() && Instant::now() < grace_end {
        thread::sleep(poll.min(DEADLINE_CLOSE_GRACE));
    }
    DrainEnd::Deadline
}

/// Arm a worker's drain watcher on its own thread.
///
/// The watcher waits for the stream runtime to be quiesced, either by a
/// `quiesce` message (a stop driven by the supervisor) or because
/// Pingora reached its graceful-terminate phase (a SIGTERM without one,
/// the upgrade path until Story 12.11), in which case the runtime is
/// terminated with `fallback_drain()`, the stored setting. It then waits
/// for the drain and calls `exit` with how it ended.
///
/// The worker keeps `runtime` alive for its whole life: dropping the
/// last handle stops the runtime.
pub(crate) fn arm_worker_drain(
    runtime: Arc<StreamRuntimeHandle>,
    mut phases: broadcast::Receiver<ExecutionPhase>,
    http_in_flight: Arc<AtomicU64>,
    fallback_drain: impl Fn() -> Duration + Send + 'static,
    exit: impl FnOnce(DrainEnd) + Send + 'static,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("lorica-drain".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    warn!(error = %e, "drain watcher runtime not built; Pingora's grace bounds the stop");
                    return;
                }
            };
            let mut quiesced = runtime.quiesced();
            let armed: Option<Duration> = rt.block_on(async {
                let mut phases_open = true;
                loop {
                    tokio::select! {
                        changed = quiesced.wait_for(Option::is_some) => {
                            return changed.ok().and_then(|drain| *drain);
                        }
                        phase = phases.recv(), if phases_open => match phase {
                            Ok(ExecutionPhase::GracefulTerminate)
                            | Ok(ExecutionPhase::ShutdownStarted)
                            | Ok(ExecutionPhase::ShutdownGracePeriod) => {
                                runtime.terminate(fallback_drain());
                            }
                            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                            Err(broadcast::error::RecvError::Closed) => phases_open = false,
                        },
                    }
                }
            });
            let Some(drain) = armed else {
                return;
            };
            info!(drain_s = drain.as_secs(), "stop started; draining");
            let probe = DrainProbe {
                http_in_flight,
                streams: runtime.tracker().clone(),
            };
            let end = wait_for_drain(&probe, drain, DRAIN_POLL_INTERVAL);
            exit(end);
        })
}

/// Start the stop keepalive towards `target`, systemd's notify socket
/// ([`hot_upgrade::notify_socket`]): `EXTEND_TIMEOUT_USEC` for
/// [`STOP_KEEPALIVE_EXTENSION`] every [`STOP_KEEPALIVE_INTERVAL`], until
/// the process exits, so a drain in progress is never cut by
/// `TimeoutStopSec`, while a process that hangs stops renewing and is
/// killed after its last extension.
///
/// Called from the stop path only: outside a stop job the message would
/// extend another timeout. A dedicated thread rather than a task, so a
/// blocked runtime cannot starve it. `None` without a target (no
/// systemd), in which case nothing is sent.
pub(crate) fn start_stop_keepalive(target: Option<PathBuf>) -> Option<thread::JoinHandle<()>> {
    let target = target?;
    let payload = hot_upgrade::extend_timeout_payload(
        u64::try_from(STOP_KEEPALIVE_EXTENSION.as_micros()).unwrap_or(u64::MAX),
    );
    let spawned = thread::Builder::new()
        .name("lorica-stop-keepalive".into())
        .spawn(move || {
            let mut reported = false;
            loop {
                if let Err(e) = hot_upgrade::sd_notify_to(&target, &payload) {
                    // A datagram gets no reply, so a mistake is silent
                    // unless it is said once here.
                    if !reported {
                        warn!(error = %e, socket = %target.display(),
                              "stop keepalive not delivered; systemd may cut the drain short");
                        reported = true;
                    }
                }
                thread::sleep(STOP_KEEPALIVE_INTERVAL);
            }
        });
    match spawned {
        Ok(thread) => Some(thread),
        Err(e) => {
            warn!(error = %e, "stop keepalive thread not spawned; TimeoutStopSec bounds the drain");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::{Stream, StreamProtocol};
    use std::os::unix::net::UnixDatagram;

    fn probe() -> DrainProbe {
        DrainProbe {
            http_in_flight: Arc::new(AtomicU64::new(0)),
            streams: ConnectionTracker::new(),
        }
    }

    fn stream() -> Arc<Stream> {
        let now = chrono::Utc::now();
        Arc::new(Stream {
            id: "s1".into(),
            name: "s1".into(),
            group_name: String::new(),
            protocol: StreamProtocol::Tcp,
            enabled: true,
            listen_address: "127.0.0.1".parse().unwrap(),
            port_first: 5432,
            port_last: 5432,
            node_selector: Vec::new(),
            created_at: now,
            updated_at: now,
        })
    }

    #[test]
    fn pingora_conf_takes_the_drain_bound_and_an_explicit_runtime_timeout() {
        let conf = pingora_server_conf(ServerConf {
            upstream_keepalive_pool_size: 7,
            ..ServerConf::new()
        });
        assert_eq!(
            conf.grace_period_seconds,
            Some(u64::from(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S))
        );
        assert_eq!(
            conf.graceful_shutdown_timeout_seconds,
            Some(PINGORA_RUNTIME_SHUTDOWN_TIMEOUT_S)
        );
        assert_eq!(conf.upstream_keepalive_pool_size, 7, "the base is kept");
    }

    #[test]
    fn no_pingora_server_is_built_without_lorica_conf() {
        // `Server::new` builds its own `ServerConf`, whose grace period is
        // Pingora's 300 s: every stop waited on it until Story 12.2.
        let needle = concat!("Server::", "new(");
        let mut offenders = Vec::new();
        let mut dirs = vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = dirs.pop() {
            for entry in std::fs::read_dir(&dir).expect("test setup: read lorica/src") {
                let path = entry.expect("test setup: dir entry").path();
                if path.is_dir() {
                    dirs.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("test setup: read source");
                    if text.contains(needle) {
                        offenders.push(path.display().to_string());
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "build the Server with new_with_opt_and_conf(None, pingora_server_conf(..)): {offenders:?}"
        );
    }

    #[test]
    fn drain_timeout_is_capped_at_the_maximum() {
        let mut settings = GlobalSettings {
            worker_drain_timeout_s: 20,
            ..GlobalSettings::default()
        };
        assert_eq!(drain_timeout(&settings), Duration::from_secs(20));
        settings.worker_drain_timeout_s = u32::MAX;
        assert_eq!(
            drain_timeout(&settings),
            Duration::from_secs(u64::from(GlobalSettings::WORKER_DRAIN_TIMEOUT_MAX_S))
        );
    }

    #[test]
    fn the_watcher_ends_at_once_when_nothing_is_in_flight() {
        let start = Instant::now();
        let end = wait_for_drain(&probe(), Duration::from_secs(30), DRAIN_POLL_INTERVAL);
        assert_eq!(end, DrainEnd::Idle);
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn the_watcher_waits_for_an_http_request_in_flight() {
        let probe = probe();
        probe.http_in_flight.store(1, Ordering::Release);
        let counter = Arc::clone(&probe.http_in_flight);
        let finisher = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            counter.store(0, Ordering::Release);
        });
        let start = Instant::now();
        let end = wait_for_drain(&probe, Duration::from_secs(30), Duration::from_millis(20));
        finisher.join().unwrap();
        assert_eq!(end, DrainEnd::Idle);
        assert!(start.elapsed() >= Duration::from_millis(400));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn the_watcher_waits_for_a_tracked_stream_connection() {
        let probe = probe();
        let tracked = probe.streams.register(1, stream());
        let finisher = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            drop(tracked);
        });
        let start = Instant::now();
        let end = wait_for_drain(&probe, Duration::from_secs(30), Duration::from_millis(20));
        finisher.join().unwrap();
        assert_eq!(end, DrainEnd::Idle);
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[test]
    fn at_the_deadline_the_watcher_closes_what_is_left_with_node_shutdown() {
        let probe = probe();
        probe.http_in_flight.store(1, Ordering::Release);
        let tracked = probe.streams.register(1, stream());
        let start = Instant::now();
        let end = wait_for_drain(
            &probe,
            Duration::from_millis(300),
            Duration::from_millis(20),
        );
        assert_eq!(end, DrainEnd::Deadline);
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(tracked.close_reason(), Some(StreamEndReason::NodeShutdown));
    }

    #[test]
    fn a_connection_already_draining_keeps_its_reason_at_the_deadline() {
        let probe = probe();
        let tracked = probe.streams.register(1, stream());
        probe.streams.drain_all(
            tokio::time::Instant::now() + Duration::from_secs(60),
            StreamEndReason::ConfigRemoved,
        );
        wait_for_drain(
            &probe,
            Duration::from_millis(100),
            Duration::from_millis(20),
        );
        assert_eq!(tracked.close_reason(), Some(StreamEndReason::ConfigRemoved));
    }

    #[test]
    fn a_terminate_without_quiesce_arms_the_watcher_with_the_stored_drain() {
        let (_peer, transport) = lorica_stream::ControlTransport::in_process_pair(4);
        let runtime = Arc::new(
            lorica_stream::StreamRuntime::spawn(
                transport,
                lorica_stream::Engines::default(),
                Arc::new(EmptyTable),
            )
            .expect("test setup: stream runtime"),
        );
        let (phase_tx, phases) = broadcast::channel(8);
        let (exit_tx, exit_rx) = std::sync::mpsc::channel();
        let watcher = arm_worker_drain(
            Arc::clone(&runtime),
            phases,
            Arc::new(AtomicU64::new(0)),
            || Duration::from_secs(7),
            move |end| exit_tx.send(end).unwrap(),
        )
        .unwrap();
        phase_tx.send(ExecutionPhase::Running).unwrap();
        assert!(exit_rx.recv_timeout(Duration::from_millis(300)).is_err());
        phase_tx.send(ExecutionPhase::GracefulTerminate).unwrap();
        assert_eq!(
            exit_rx.recv_timeout(Duration::from_secs(5)),
            Ok(DrainEnd::Idle)
        );
        assert_eq!(*runtime.quiesced().borrow(), Some(Duration::from_secs(7)));
        watcher.join().unwrap();
    }

    struct EmptyTable;

    impl lorica_stream::StreamTableSource for EmptyTable {
        fn load(
            &self,
        ) -> Result<lorica_stream::StreamTable, Box<dyn std::error::Error + Send + Sync>> {
            Ok(lorica_stream::StreamTable::default())
        }
    }

    #[test]
    fn the_keepalive_extends_the_stop_three_times_in_twenty_five_seconds() {
        let dir = tempfile::tempdir().expect("test setup: tempdir");
        let path = dir.path().join("notify.sock");
        let socket = UnixDatagram::bind(&path).expect("test setup: notify socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        // The thread runs until the test process exits, as it runs until
        // Lorica exits; the socket going away only makes it log once.
        let _keepalive = start_stop_keepalive(Some(path)).expect("a target starts it");
        let window = Instant::now() + Duration::from_secs(25);
        let mut received = Vec::new();
        let mut buf = [0u8; 128];
        while received.len() < 3 && Instant::now() < window {
            if let Ok(n) = socket.recv(&mut buf) {
                received.push(String::from_utf8(buf[..n].to_vec()).unwrap());
            }
        }
        assert!(
            received.len() >= 3,
            "only {} extensions sent",
            received.len()
        );
        for message in received {
            assert_eq!(message, "EXTEND_TIMEOUT_USEC=30000000\n");
        }
    }

    #[test]
    fn the_keepalive_sends_nothing_without_a_target() {
        assert!(start_stop_keepalive(None).is_none());
    }
}
