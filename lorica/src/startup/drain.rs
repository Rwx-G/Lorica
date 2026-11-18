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

//! How a stop or a hot upgrade drains (Story 12.2 D-f, Story 12.11).
//!
//! - [`pingora_server_conf`]: Pingora's own shutdown waits, from the
//!   drain setting's hard maximum instead of its 300 s `EXIT_TIMEOUT`.
//! - The drain watcher ([`wait_for_drain`], [`arm_worker_drain`]): once
//!   a stop or an upgrade starts, it ends the process as soon as no HTTP
//!   request and no stream connection is in flight, or at the drain
//!   deadline, having first let the stream tracker close what is left
//!   with the quiesce's end reason: `node_shutdown` for a stop,
//!   `drained_by_upgrade` for an upgrade. This is what makes a drain take
//!   as long as the traffic needs and no longer. At the end of an upgrade
//!   drain a worker sends its drain report to its supervisor first.
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
use lorica_stream::{quiesce_end_reason, ConnectionTracker, Quiesced, StreamRuntimeHandle};
pub(crate) use lorica_worker::stream_ctl::DrainEnd;
use lorica_worker::stream_ctl::QuiesceReason;
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
/// stream connections and sessions the tracker holds, and the end reason
/// it closes the leftovers with.
#[derive(Debug, Clone)]
pub(crate) struct DrainProbe {
    /// `LoricaProxy::active_connections`, which counts in-flight
    /// requests, not idle keepalive connections.
    http_in_flight: Arc<AtomicU64>,
    /// The stream runtime's tracker.
    streams: ConnectionTracker,
    /// What a connection still open at the deadline closes with.
    end_reason: StreamEndReason,
}

impl DrainProbe {
    /// A probe for a drain quiesced for `reason`.
    pub(crate) fn new(
        http_in_flight: Arc<AtomicU64>,
        streams: ConnectionTracker,
        reason: QuiesceReason,
    ) -> Self {
        DrainProbe {
            http_in_flight,
            streams,
            end_reason: quiesce_end_reason(reason),
        }
    }

    fn idle(&self) -> bool {
        self.http_in_flight.load(Ordering::Acquire) == 0 && self.streams.is_empty()
    }

    /// Close every stream connection still open with the drain's end
    /// reason, unless it was already draining for another one.
    fn close_remaining(&self) {
        let now = tokio::time::Instant::now();
        self.streams.drain_all(now, self.end_reason);
        self.streams.close_expired(now);
    }
}

/// How a drain ended, and what the exit cuts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainOutcome {
    /// Idle before the deadline, or not.
    pub(crate) end: DrainEnd,
    /// HTTP requests still in flight at the deadline, which the exit
    /// cuts; 0 when the drain ended idle.
    pub(crate) http_cut: u64,
}

/// Wait, blocking, until `probe` is idle or `drain` has elapsed,
/// checking every `poll`. At the deadline the stream connections left
/// are closed with the probe's end reason and given
/// [`DEADLINE_CLOSE_GRACE`] to end, so their end reason is written here
/// and never left to the exit.
pub(crate) fn wait_for_drain(probe: &DrainProbe, drain: Duration, poll: Duration) -> DrainOutcome {
    let deadline = Instant::now() + drain;
    loop {
        if probe.idle() {
            return DrainOutcome {
                end: DrainEnd::Idle,
                http_cut: 0,
            };
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(poll.min(deadline.saturating_duration_since(Instant::now())));
    }
    let http_cut = probe.http_in_flight.load(Ordering::Acquire);
    probe.close_remaining();
    let grace_end = Instant::now() + DEADLINE_CLOSE_GRACE;
    while !probe.streams.is_empty() && Instant::now() < grace_end {
        thread::sleep(poll.min(DEADLINE_CLOSE_GRACE));
    }
    DrainOutcome {
        end: DrainEnd::Deadline,
        http_cut,
    }
}

/// End an upgrade drain's bookkeeping before the exit (Story 12.11 D-g):
/// at the deadline, one `warn` per stream the upgrade closed connections
/// of and one for the HTTP requests cut; then the drain report to the
/// supervisor, which never waits on the channel.
fn report_upgrade_drain(runtime: &StreamRuntimeHandle, outcome: DrainOutcome) {
    if outcome.end == DrainEnd::Deadline {
        for (stream_id, counts) in runtime.tracker().upgrade_drain_counts() {
            if counts.closed > 0 {
                warn!(%stream_id, closed = counts.closed,
                      "upgrade drain deadline reached; stream connections closed with drained_by_upgrade");
            }
        }
        if outcome.http_cut > 0 {
            warn!(
                http_cut = outcome.http_cut,
                "upgrade drain deadline reached; HTTP requests in flight are cut by the exit"
            );
        }
    }
    match runtime.send_drain_report(outcome.end, outcome.http_cut) {
        Ok(sent) if sent.truncated => {
            warn!(
                entries = sent.entries,
                "upgrade drain report truncated: the control channel was full"
            )
        }
        Ok(sent) => info!(entries = sent.entries, "upgrade drain report sent"),
        Err(e) => {
            warn!(error = %e,
                  "upgrade drain report not sent; the supervisor counts this worker as unreported")
        }
    }
}

/// Arm a worker's drain watcher on its own thread.
///
/// The watcher waits for the stream runtime to be quiesced, either by a
/// `quiesce` message (a stop or a hot upgrade driven by the supervisor,
/// which says which) or because Pingora reached its graceful-terminate
/// phase (a SIGTERM without one, a degraded stop path), in which case
/// the runtime is terminated with `fallback_drain()`, the stored setting,
/// and drains as for a stop. A SIGTERM after a `quiesce` changes nothing:
/// the first quiesce stands. The watcher then waits for the drain,
/// closing the leftovers with the quiesce's end reason, sends the drain
/// report when the quiesce was an upgrade, and calls `exit` with how the
/// drain ended.
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
            let armed: Option<Quiesced> = rt.block_on(async {
                let mut phases_open = true;
                loop {
                    tokio::select! {
                        changed = quiesced.wait_for(Option::is_some) => {
                            return changed.ok().and_then(|q| *q);
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
            let Some(Quiesced { drain, reason }) = armed else {
                return;
            };
            info!(
                drain_s = drain.as_secs(),
                reason = reason.as_str(),
                "drain started"
            );
            let probe = DrainProbe::new(http_in_flight, runtime.tracker().clone(), reason);
            let outcome = wait_for_drain(&probe, drain, DRAIN_POLL_INTERVAL);
            if reason == QuiesceReason::Upgrade {
                report_upgrade_drain(&runtime, outcome);
            }
            exit(outcome.end);
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
    use lorica_worker::stream_ctl::{self, DrainedEntry, StreamCtlMsg};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    fn probe() -> DrainProbe {
        probe_for(QuiesceReason::Shutdown)
    }

    fn probe_for(reason: QuiesceReason) -> DrainProbe {
        DrainProbe::new(
            Arc::new(AtomicU64::new(0)),
            ConnectionTracker::new(),
            reason,
        )
    }

    fn stream() -> Arc<Stream> {
        let now = chrono::Utc::now();
        Arc::new(Stream::new(
            "s1".into(),
            "s1".into(),
            StreamProtocol::Tcp,
            "127.0.0.1".parse().unwrap(),
            5432,
            5432,
            now,
        ))
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
        let outcome = wait_for_drain(&probe(), Duration::from_secs(30), DRAIN_POLL_INTERVAL);
        assert_eq!(
            outcome,
            DrainOutcome {
                end: DrainEnd::Idle,
                http_cut: 0
            }
        );
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
        let outcome = wait_for_drain(&probe, Duration::from_secs(30), Duration::from_millis(20));
        finisher.join().unwrap();
        assert_eq!(outcome.end, DrainEnd::Idle);
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
        let outcome = wait_for_drain(&probe, Duration::from_secs(30), Duration::from_millis(20));
        finisher.join().unwrap();
        assert_eq!(outcome.end, DrainEnd::Idle);
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[test]
    fn at_the_deadline_the_watcher_closes_what_is_left_with_the_quiesce_end_reason() {
        for (reason, expected) in [
            (QuiesceReason::Shutdown, StreamEndReason::NodeShutdown),
            (QuiesceReason::Upgrade, StreamEndReason::DrainedByUpgrade),
        ] {
            let probe = probe_for(reason);
            probe.http_in_flight.store(2, Ordering::Release);
            let tracked = probe.streams.register(1, stream());
            let start = Instant::now();
            let outcome = wait_for_drain(
                &probe,
                Duration::from_millis(300),
                Duration::from_millis(20),
            );
            assert_eq!(
                outcome,
                DrainOutcome {
                    end: DrainEnd::Deadline,
                    http_cut: 2
                }
            );
            assert!(start.elapsed() >= Duration::from_millis(300));
            assert_eq!(tracked.close_reason(), Some(expected), "{reason:?}");
        }
    }

    #[test]
    fn a_connection_already_draining_keeps_its_reason_at_the_deadline() {
        let probe = probe_for(QuiesceReason::Upgrade);
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
        assert_eq!(
            *runtime.quiesced().borrow(),
            Some(Quiesced {
                drain: Duration::from_secs(7),
                reason: QuiesceReason::Shutdown
            })
        );
        watcher.join().unwrap();
    }

    /// A worker runtime on a real stream control socketpair, and the
    /// supervisor's end, reading with a timeout.
    fn seqpacket_runtime() -> (OwnedFd, Arc<StreamRuntimeHandle>) {
        let (supervisor, worker) = stream_ctl::create_seqpacket_pair().unwrap();
        // `SO_RCVTIMEO` through std's setter, which applies to any socket
        // type: a lost message fails the test instead of hanging it.
        let supervisor = {
            let socket = std::os::unix::net::UnixStream::from(supervisor);
            socket
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            OwnedFd::from(socket)
        };
        let runtime = lorica_stream::StreamRuntime::spawn(
            lorica_stream::ControlTransport::Seqpacket(worker),
            lorica_stream::Engines::default(),
            Arc::new(EmptyTable),
        )
        .expect("test setup: stream runtime");
        (supervisor, Arc::new(runtime))
    }

    fn quiesce_for_upgrade(supervisor: &OwnedFd, seq: u64, drain_ms: u64) {
        stream_ctl::send_msg(
            supervisor,
            &StreamCtlMsg::Quiesce {
                seq,
                reason: QuiesceReason::Upgrade,
                drain_ms,
            },
        )
        .unwrap();
        assert!(matches!(
            stream_ctl::recv_msg(supervisor),
            Ok(StreamCtlMsg::Ack { seq: s, .. }) if s == seq
        ));
    }

    /// Arm the watcher on `runtime` with no SIGTERM path; `exit` sends
    /// how the drain ended.
    fn arm(
        runtime: &Arc<StreamRuntimeHandle>,
        http_in_flight: Arc<AtomicU64>,
    ) -> (thread::JoinHandle<()>, std::sync::mpsc::Receiver<DrainEnd>) {
        let (_phase_tx, phases) = broadcast::channel(1);
        let (exit_tx, exit_rx) = std::sync::mpsc::channel();
        let watcher = arm_worker_drain(
            Arc::clone(runtime),
            phases,
            http_in_flight,
            || Duration::from_secs(1),
            move |end| exit_tx.send(end).unwrap(),
        )
        .unwrap();
        (watcher, exit_rx)
    }

    #[test]
    fn an_upgrade_drain_that_ends_idle_reports_before_the_exit() {
        let (supervisor, runtime) = seqpacket_runtime();
        let (watcher, exit_rx) = arm(&runtime, Arc::new(AtomicU64::new(0)));
        quiesce_for_upgrade(&supervisor, 5, 60_000);
        assert_eq!(
            exit_rx.recv_timeout(Duration::from_secs(30)),
            Ok(DrainEnd::Idle)
        );
        assert!(matches!(
            stream_ctl::recv_msg(&supervisor),
            Ok(StreamCtlMsg::DrainedEnd {
                seq: 5,
                end: DrainEnd::Idle,
                http_cut: 0,
                entries: 0,
                truncated: false
            })
        ));
        watcher.join().unwrap();
    }

    #[test]
    fn an_upgrade_drain_that_reaches_its_deadline_reports_what_it_closed_and_cut() {
        let (supervisor, runtime) = seqpacket_runtime();
        let http_in_flight = Arc::new(AtomicU64::new(1));
        // A stream connection whose engine ends it when told to.
        let mut tracked = runtime.tracker().register(1, stream());
        let engine = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let reason = rt.block_on(tracked.closed());
            tracked.finish(reason, |r| r)
        });
        let (watcher, exit_rx) = arm(&runtime, Arc::clone(&http_in_flight));
        quiesce_for_upgrade(&supervisor, 9, 300);
        assert_eq!(
            exit_rx.recv_timeout(Duration::from_secs(30)),
            Ok(DrainEnd::Deadline)
        );
        assert_eq!(engine.join().unwrap(), StreamEndReason::DrainedByUpgrade);
        match stream_ctl::recv_msg(&supervisor) {
            Ok(StreamCtlMsg::Drained { seq: 9, entries }) => assert_eq!(
                entries,
                vec![DrainedEntry {
                    stream_id: "s1".into(),
                    closed: 1,
                    finished: 0
                }]
            ),
            other => panic!("expected the report's entries, got {other:?}"),
        }
        assert!(matches!(
            stream_ctl::recv_msg(&supervisor),
            Ok(StreamCtlMsg::DrainedEnd {
                seq: 9,
                end: DrainEnd::Deadline,
                http_cut: 1,
                entries: 1,
                truncated: false
            })
        ));
        watcher.join().unwrap();
    }

    /// Nobody reads the supervisor's end: the runtime blocks on its acks
    /// once the channel is full, so the report can be neither handed over
    /// nor sent. The exit still comes, bounded by the report timeout.
    #[test]
    fn a_full_control_channel_does_not_hold_the_exit() {
        let (supervisor, runtime) = seqpacket_runtime();
        let (watcher, exit_rx) = arm(&runtime, Arc::new(AtomicU64::new(1)));
        let drain = Duration::from_secs(2);
        quiesce_for_upgrade(&supervisor, 1, drain.as_millis() as u64);
        let filler = StreamCtlMsg::Refresh {
            seq: 2,
            drain_ms: 0,
        };
        let flood_until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < flood_until {
            match stream_ctl::try_send_msg(&supervisor, &filler) {
                Ok(()) => {}
                Err(e) if stream_ctl::would_block(&e) => break,
                Err(e) => panic!("flood: {e}"),
            }
        }
        let bound = drain + DEADLINE_CLOSE_GRACE + lorica_stream::runtime::DRAIN_REPORT_TIMEOUT;
        assert_eq!(
            exit_rx.recv_timeout(bound + Duration::from_secs(20)),
            Ok(DrainEnd::Deadline)
        );
        watcher.join().unwrap();
        // The runtime's pending ack fails once the peer is gone, which
        // lets it stop.
        drop(supervisor);
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
