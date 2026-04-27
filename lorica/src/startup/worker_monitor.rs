// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Supervisor worker-monitor task : crash detection + respawn with
//! exponential backoff.
//!
//! Story 8.1 AC #1+#3 - moved out of `run_supervisor` (was ~260 LOC
//! inline + 14 captures) so the supervisor boot path reads as a flat
//! sequence of helper calls. The monitor :
//!
//! - Polls `WorkerManager::check_workers()` every 500 ms for `Exited`
//!   / `Crashed` events.
//! - Computes the per-id exponential-backoff delay (audit M-26 :
//!   `restart_backoff` is a pure computation ; the actual sleep
//!   happens here on the tokio runtime so a `std::thread::sleep`
//!   never blocks the supervisor reactor).
//! - Aborts the dead worker's stale heartbeat task, calls
//!   `restart_worker(id)`, and on success re-spawns BOTH the
//!   pipelined RPC handler (audit C-1 closure ; same helper as the
//!   initial-spawn site) AND the legacy `CommandChannel` loop (ban /
//!   reload / heartbeat / metrics-pull). The latter remains an inline
//!   `tokio::spawn` because its shape mirrors the initial-spawn
//!   channel-loop in `run_supervisor` ; a future refactor that
//!   factors both call sites into one shared helper is tracked in
//!   the v1.6.0 backlog.
//! - Short-circuits on `monitor_shutting_down` so a SIGTERM-driven
//!   `manager.shutdown_all()` does not race a respawn and leak a
//!   worker past the systemd `TimeoutStopSec`.

use std::collections::HashMap;
use std::os::fd::IntoRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{broadcast, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use lorica_command::{Command, CommandChannel, CommandType, Response, RpcEndpoint};
use lorica_config::ConfigStore;
use lorica_worker::manager::{WorkerEvent, WorkerManager};

use crate::{spawn_supervisor_rpc_handler, SupervisorBreakerRegistry, SupervisorVerdictCache};

type GenericCounterRow = (String, Vec<(String, String)>, u64);

/// Bundle of supervisor-owned handles the worker monitor needs.
///
/// Centralising the captures in one struct keeps the public function
/// signature readable (one parameter instead of fourteen) and makes
/// the `monitor_handle` extraction a mechanical move - the original
/// inline closure already grouped these into a `monitor_*` prefix
/// at the assignment level. The fields are individually Arc-cheap to
/// clone, so the supervisor's local clones stay independent of the
/// monitor task's set.
pub struct WorkerMonitorDeps {
    /// `WorkerManager` lives behind a `std::sync::Mutex` (not tokio)
    /// because `WorkerEvent` polling is sync ; the monitor briefly
    /// re-acquires the lock around each `restart_backoff` /
    /// `restart_worker` / `worker_pids` read so the lock is never held
    /// across `.await`.
    pub manager: Arc<std::sync::Mutex<WorkerManager>>,
    /// Broadcast sender for `ConfigReload` ; the monitor's restart
    /// branch subscribes a fresh receiver per restarted worker.
    pub reload_tx: broadcast::Sender<u64>,
    /// Broadcast sender for `BanIp` ; same subscription pattern.
    pub ban_tx: broadcast::Sender<(String, u64)>,
    /// Monotonic command-sequence counter shared with peer worker
    /// channel-loops.
    pub sequence: Arc<AtomicU64>,
    /// Heartbeat metrics accumulator.
    pub hb_metrics: Arc<lorica_api::workers::WorkerMetrics>,
    /// Aggregated cross-worker metrics surfaced via `/metrics`.
    pub agg_metrics: Arc<lorica_api::workers::AggregatedMetrics>,
    /// Per-worker channel-loop `JoinHandle` map. The monitor aborts
    /// the stale handle on crash and inserts the new one after a
    /// successful respawn.
    pub task_handles: Arc<parking_lot::Mutex<HashMap<u32, JoinHandle<()>>>>,
    /// RPC endpoint table consulted by the two-phase config-reload
    /// coordinator. The monitor's restart branch re-registers the
    /// new endpoint here (audit C-1 fix) so the respawned worker
    /// receives subsequent Prepare / Commit fan-outs.
    pub rpc_endpoints: Arc<dashmap::DashMap<u32, RpcEndpoint>>,
    /// Cross-worker token-bucket registry used by the supervisor RPC
    /// handler. Re-registered for the respawned worker.
    pub rl_registry: Arc<
        dashmap::DashMap<String, Arc<lorica_limits::token_bucket::AuthoritativeBucket>>,
    >,
    /// Per-route rate-limit policy cache (audit M-4) ; same.
    pub rl_policy: Arc<
        dashmap::DashMap<String, Option<lorica_config::models::RateLimit>>,
    >,
    /// SQLite-backed config store ; the supervisor RPC handler reads
    /// route policies from here on first-seen `RateLimitDelta` keys.
    pub store: Arc<Mutex<ConfigStore>>,
    /// Cross-worker forward-auth verdict cache.
    pub verdict_cache: Arc<SupervisorVerdictCache>,
    /// Cross-worker circuit-breaker registry.
    pub breaker_registry: Arc<SupervisorBreakerRegistry>,
    /// Shutdown flag set by the SIGTERM handler before
    /// `manager.shutdown_all()`. The monitor's loop short-circuits on
    /// this flag at three points (loop top, post-mutex, mid-backoff)
    /// so a shutdown-driven SIGKILL never triggers a respawn that
    /// races shutdown.
    pub shutting_down: Arc<AtomicBool>,
}

/// Spawn the worker-monitor loop. Returns the `JoinHandle` so the
/// supervisor's shutdown path can `abort()` the monitor before the
/// worker drain begins.
///
/// The handle holds no payload - the monitor returns `()` on
/// shutdown-flag observation.
pub fn spawn_worker_monitor(deps: WorkerMonitorDeps) -> JoinHandle<()> {
    let WorkerMonitorDeps {
        manager: monitor_mgr,
        reload_tx: monitor_reload_tx,
        ban_tx: monitor_ban_tx,
        sequence: monitor_seq,
        hb_metrics: monitor_hb_metrics,
        agg_metrics: monitor_agg_metrics,
        task_handles: monitor_task_handles,
        rpc_endpoints: monitor_rpc_endpoints,
        rl_registry: monitor_rl_registry,
        rl_policy: monitor_rl_policy,
        store: monitor_store,
        verdict_cache: monitor_verdict_cache,
        breaker_registry: monitor_breaker_registry,
        shutting_down: monitor_shutting_down,
    } = deps;

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;

            if monitor_shutting_down.load(Ordering::Acquire) {
                return;
            }

            let events = {
                let mgr = monitor_mgr.lock().unwrap_or_else(|e| {
                    warn!("worker monitor mutex poisoned, recovering");
                    e.into_inner()
                });
                // Re-check after acquiring the mutex: shutdown may have
                // grabbed the mutex while we waited (the supervisor
                // shutdown path holds it for the full ~30 s drain). If
                // we observe the flag now, the workers we are about to
                // see as "crashed" were actually SIGKILL'd by us and
                // must not be respawned.
                if monitor_shutting_down.load(Ordering::Acquire) {
                    return;
                }
                mgr.check_workers()
            };
            // The std::sync::Mutex guard is dropped here on
            // purpose. Audit M-26 closure : the per-event restart
            // path below uses `tokio::time::sleep` for the
            // exponential backoff, which is illegal across an
            // .await while holding a !Send sync-Mutex guard.
            // Re-acquire the lock briefly inside the loop for
            // each `restart_backoff` / `restart_worker` /
            // `worker_pids` read.
            for event in events {
                let (id, log_msg) = match event {
                    WorkerEvent::Exited { id, pid, status } => {
                        warn!(worker_id = id, pid = pid.as_raw(), status, "worker exited");
                        (id, "exited")
                    }
                    WorkerEvent::Crashed { id, pid, signal } => {
                        error!(worker_id = id, pid = pid.as_raw(), signal = %signal, "worker crashed");
                        (id, "crashed")
                    }
                };

                // Abort the old heartbeat/reload task for this worker
                if let Some(old_handle) = monitor_task_handles.lock().remove(&id) {
                    old_handle.abort();
                    info!(worker_id = id, "aborted stale worker task");
                }

                // Re-check shutdown flag before respawning - a
                // crash detected just before SIGTERM should not
                // trigger a respawn that races shutdown.
                if monitor_shutting_down.load(Ordering::Acquire) {
                    info!(worker_id = id, "shutdown in progress, skipping respawn");
                    break;
                }

                // Audit M-26 closure : compute the exponential-
                // backoff delay, drop the mgr lock, sleep async
                // (was `std::thread::sleep` inside `restart_worker`
                // - blocked the supervisor tokio thread for up to
                // 30 s, starving heartbeats from peer workers and
                // every other tokio task on the same runtime).
                let backoff = {
                    let mgr = monitor_mgr.lock().unwrap_or_else(|e| {
                        warn!("worker monitor mutex poisoned, recovering");
                        e.into_inner()
                    });
                    mgr.restart_backoff(id)
                };
                if !backoff.is_zero() {
                    tokio::time::sleep(backoff).await;
                    if monitor_shutting_down.load(Ordering::Acquire) {
                        info!(worker_id = id, "shutdown raced backoff sleep, skipping respawn");
                        break;
                    }
                }

                let (restart_result, new_pid) = {
                    let mut mgr = monitor_mgr.lock().unwrap_or_else(|e| {
                        warn!("worker monitor mutex poisoned, recovering");
                        e.into_inner()
                    });
                    let result = mgr.restart_worker(id);
                    let pid = mgr
                        .worker_pids()
                        .iter()
                        .find(|(wid, _)| *wid == id)
                        .map(|(_, pid)| pid.as_raw())
                        .unwrap_or(0);
                    (result, pid)
                };

                match restart_result {
                    Ok(Some((new_cmd_fd, new_rpc_fd))) => {
                        info!(worker_id = id, new_pid, reason = log_msg, "worker restarted, reconnecting channel");

                        // Audit C-1 closure : re-spawn the
                        // pipelined RPC handler so the supervisor's
                        // two-phase config-reload coordinator finds
                        // the restarted worker. Without this, the
                        // worker silently sits outside
                        // `worker_rpc_endpoints` and every
                        // subsequent ConfigReloadPrepare / Commit
                        // fan-out skips it (proxy config /
                        // CertResolver / OTel / GeoIP / ASN /
                        // bot-secret state stay frozen at boot
                        // until full process restart). Same helper
                        // the initial-spawn path uses, so a new
                        // RPC variant added to the match arm is
                        // wired uniformly across both paths.
                        spawn_supervisor_rpc_handler(
                            id,
                            new_rpc_fd.into_raw_fd(),
                            Arc::clone(&monitor_rl_registry),
                            Arc::clone(&monitor_rl_policy),
                            Arc::clone(&monitor_store),
                            Arc::clone(&monitor_verdict_cache),
                            Arc::clone(&monitor_breaker_registry),
                            Arc::clone(&monitor_rpc_endpoints),
                        );

                        // SAFETY: new_cmd_fd is a fresh socketpair fd
                        // from WorkerManager::restart_worker(),
                        // exclusively owned here.
                        match unsafe { CommandChannel::from_raw_fd(new_cmd_fd.into_raw_fd()) } {
                            Ok(mut channel) => {
                                let mut rx = monitor_reload_tx.subscribe();
                                let mut ban_rx = monitor_ban_tx.subscribe();
                                let seq = Arc::clone(&monitor_seq);
                                let hb_metrics = Arc::clone(&monitor_hb_metrics);
                                let agg_metrics = Arc::clone(&monitor_agg_metrics);
                                let new_handle = tokio::spawn(async move {
                                    info!(worker_id = id, "restarted worker channel task started");
                                    let mut timer = tokio::time::interval(Duration::from_secs(5));
                                    timer.tick().await;
                                    loop {
                                        tokio::select! {
                                            // BanIp command from supervisor
                                            Ok((ip, duration_s)) = ban_rx.recv() => {
                                                let s = seq.fetch_add(1, Ordering::Relaxed);
                                                let cmd = Command::ban_ip(s, &ip, duration_s);
                                                if channel.send(&cmd).await.is_ok() {
                                                    let _ = channel.recv::<Response>().await;
                                                }
                                            }
                                            // Same lagged-aware shape as the
                                            // initial-spawn branch (audit C-2).
                                            reload_result = rx.recv() => {
                                                let s = match reload_result {
                                                    Ok(s) => s,
                                                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                                        warn!(
                                                            worker_id = id,
                                                            dropped = n,
                                                            "ConfigReload broadcast lagged on restarted worker ; issuing catch-up reload"
                                                        );
                                                        lorica_api::metrics::inc_reload_broadcast_lagged(
                                                            &id.to_string(),
                                                            n,
                                                        );
                                                        seq.fetch_add(1, Ordering::Relaxed)
                                                    }
                                                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                                };
                                                let cmd = Command::new(CommandType::ConfigReload, s);
                                                if channel.send(&cmd).await.is_ok() {
                                                    if let Ok(r) = channel.recv::<Response>().await {
                                                        match r.typed_status() {
                                                            lorica_command::ResponseStatus::Ok => info!(worker_id = id, "restarted worker applied config reload"),
                                                            lorica_command::ResponseStatus::Error => error!(worker_id = id, message = %r.message, "restarted worker config reload failed"),
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                            }
                                            _ = timer.tick() => {
                                                let hb_s = seq.fetch_add(1, Ordering::Relaxed);
                                                let cmd = Command::new(CommandType::Heartbeat, hb_s);
                                                let start = Instant::now();
                                                if let Err(e) = channel.send(&cmd).await {
                                                    warn!(worker_id = id, error = %e, "restarted worker heartbeat send failed");
                                                    continue;
                                                }
                                                match channel.recv::<Response>().await {
                                                    Ok(_) => {
                                                        let latency_ms = start.elapsed().as_millis() as u64;
                                                        hb_metrics.record_heartbeat(id, new_pid, latency_ms).await;

                                                        // Request metrics
                                                        let m_seq = seq.fetch_add(1, Ordering::Relaxed);
                                                        let m_cmd = Command::new(CommandType::MetricsRequest, m_seq);
                                                        if let Err(e) = channel.send(&m_cmd).await {
                                                            warn!(worker_id = id, error = %e, "metrics request send failed");
                                                        } else if let Ok(report) = channel.recv::<lorica_command::MetricsReport>().await {
                                                            let _ = channel.recv::<Response>().await;
                                                            let ewma: std::collections::HashMap<String, f64> = report
                                                                .ewma_entries.iter()
                                                                .map(|e| (e.backend_address.clone(), e.score_us))
                                                                .collect();
                                                            let bans: Vec<(String, u64, u64)> = report
                                                                .ban_entries.iter()
                                                                .map(|b| (b.ip.clone(), b.remaining_seconds, b.ban_duration_seconds))
                                                                .collect();
                                                            let backend_conns: std::collections::HashMap<String, u64> = report
                                                                .backend_conn_entries.iter()
                                                                .map(|e| (e.backend_address.clone(), e.connections))
                                                                .collect();
                                                            let req_counts: Vec<(String, u32, u64)> = report
                                                                .request_entries.iter()
                                                                .map(|e| (e.route_id.clone(), e.status_code, e.count))
                                                                .collect();
                                                            let waf_counts: Vec<(String, String, u64)> = report
                                                                .waf_entries.iter()
                                                                .map(|e| (e.category.clone(), e.action.clone(), e.count))
                                                                .collect();
                                                            agg_metrics
                                                                .update_worker(id, report.cache_hits, report.cache_misses, report.active_connections, bans, ewma, backend_conns, req_counts, waf_counts)
                                                                .await;
                                                            let gc: Vec<GenericCounterRow> =
                                                                report
                                                                    .generic_counters
                                                                    .iter()
                                                                    .map(|e| {
                                                                        let pairs: Vec<(String, String)> = e
                                                                            .labels
                                                                            .chunks_exact(2)
                                                                            .map(|c| (c[0].clone(), c[1].clone()))
                                                                            .collect();
                                                                        (e.name.clone(), pairs, e.value)
                                                                    })
                                                                    .collect();
                                                            lorica_api::metrics::apply_worker_generic_counters(
                                                                id,
                                                                &gc,
                                                            );
                                                        }
                                                    }
                                                    Err(e) => warn!(worker_id = id, error = %e, "restarted worker heartbeat recv failed"),
                                                }
                                            }
                                        }
                                    }
                                });
                                monitor_task_handles.lock().insert(id, new_handle);
                            }
                            Err(e) => error!(worker_id = id, error = %e, "failed to create channel for restarted worker"),
                        }
                    }
                    Ok(None) => {
                        warn!(worker_id = id, "restarted worker has no command channel");
                    }
                    Err(e) => {
                        error!(worker_id = id, error = %e, "failed to restart worker");
                    }
                }
            }
        }
    })
}
