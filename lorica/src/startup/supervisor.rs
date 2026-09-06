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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use lorica_api::logs::LogBuffer;
use lorica_api::server::AppState;
use lorica_api::system::SystemCache;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use lorica::proxy_wiring::ProxyConfig;
use lorica::reload::reload_proxy_config;

use crate::cli::Cli;
use crate::startup;
use crate::startup::{
    persist_initial_password, restrict_key_permissions, shutdown_signal,
    try_init_otel_from_settings,
};

/// Wire shape a worker sends for each generic counter slot:
/// `(counter_name, [(label_key, label_value), ...], value)`.
type GenericCounterRow = (String, Vec<(String, String)>, u64);

/// Decode a worker's [`lorica_command::BanReportEntry`] wire row into the
/// supervisor-side ban tuple
/// `(ip, remaining_seconds, ban_duration_seconds, reason)`.
///
/// `reason` is an i32 on the wire; an unrecognized value (a legacy `0`,
/// or a future reason emitted by a newer worker) falls back to
/// [`lorica_api::ban::BanReason::WafCriticalRule`] rather than dropping
/// the row or mislabeling it, matching the worker-side decode in
/// `startup::worker`. Single source of truth for the three metrics-report
/// ingestion sites that previously inlined this map closure verbatim.
fn decode_ban_report_entry(
    b: &lorica_command::BanReportEntry,
) -> (String, u64, u64, lorica_api::ban::BanReason) {
    (
        b.ip.clone(),
        b.remaining_seconds,
        b.ban_duration_seconds,
        lorica_api::ban::BanReason::from_i32(b.reason)
            .unwrap_or(lorica_api::ban::BanReason::WafCriticalRule),
    )
}

// ---------------------------------------------------------------------------
// Supervisor mode (Unix only): forks workers, runs API server, monitors workers
// ---------------------------------------------------------------------------

pub(crate) fn run_supervisor(cli: Cli) {
    use lorica_command::CommandChannel;
    use lorica_worker::manager::{WorkerConfig, WorkerEvent, WorkerManager};
    use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::sync::broadcast;

    use crate::startup::hot_upgrade;

    let data_dir_path = PathBuf::from(&cli.data_dir);

    // Hot upgrade (Story 8.4), NEW supervisor side: pull the inherited
    // listening sockets from the outgoing supervisor's transfer socket
    // BEFORE any other startup work, so we bind/adopt the transfer socket
    // well within the old side's connect-retry budget. The pulled FDs are
    // the SAME kernel listening sockets the old workers accept on, so the
    // overlap never drops a connection.
    let inherited: Option<hot_upgrade::InheritedListeners> = if cli.hot_upgrade {
        match hot_upgrade::pull_inherited_listeners(&data_dir_path, cli.management_port) {
            Ok(i) => {
                info!(
                    proxy_listeners = i.proxy.len(),
                    has_management = i.management.is_some(),
                    // The operational cluster listener is handed off
                    // (Story 9.2); the enrollment one is not (its
                    // socket is only bound while a join token is
                    // live, and it rebinds on the next liveness edge).
                    cluster_listeners = i.cluster.len(),
                    "hot upgrade: pulled inherited listeners from outgoing supervisor"
                );
                Some(i)
            }
            Err(e) => {
                error!(error = %e, "hot upgrade: failed to pull inherited listeners; aborting");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let worker_count = cli.workers.resolved();

    let config = WorkerConfig {
        worker_count,
        data_dir: cli.data_dir.clone(),
        log_level: cli.log_level.clone(),
        log_format: cli.log_format.clone(),
        log_file: cli.log_file.clone(),
        http_addr: format!("0.0.0.0:{}", cli.http_port),
        https_addr: Some(format!("0.0.0.0:{}", cli.https_port)),
        https_port: cli.https_port,
        upstream_crl_file: cli.upstream_crl_file.clone(),
    };

    // Run DB migrations BEFORE forking workers to avoid SQLite lock contention.
    // Workers will open the DB after migrations are complete.
    {
        let data_dir = PathBuf::from(&cli.data_dir);
        let _ = std::fs::create_dir_all(&data_dir);
        let key_path = data_dir.join("encryption.key");
        let encryption_key = match lorica_config::crypto::EncryptionKey::load_or_create(&key_path) {
            Ok(key) => Some(key),
            Err(e) => {
                error!(
                    error = %e,
                    path = %key_path.display(),
                    "failed to load encryption key - database will open WITHOUT encryption. \
                     Certificate private keys and notification credentials will be stored in cleartext. \
                     Fix the key file permissions or path and restart."
                );
                None
            }
        };
        let db_path = data_dir.join("lorica.db");
        match ConfigStore::open(&db_path, encryption_key) {
            Ok(store) => {
                // Story 9.1 AC #7 interlock: a NEW supervisor taking
                // over via --hot-upgrade bumps the takeover epoch
                // BEFORE it serves anything. Cluster sessions (Story
                // 9.2) tag themselves with the epoch they were
                // accepted under and the registry fences older
                // epochs, so a follower never holds two live sessions
                // for one node_id during the old/new overlap.
                if cli.hot_upgrade {
                    match store.increment_cluster_takeover_epoch() {
                        Ok(epoch) => info!(epoch, "hot upgrade: took cluster takeover epoch"),
                        Err(e) => {
                            error!(error = %e, "hot upgrade: failed to take cluster takeover epoch");
                            std::process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "failed to run database migrations before forking workers");
                std::process::exit(1);
            }
        }
        info!("database migrations completed, forking workers");
    }

    // Create the shared-memory region BEFORE forking so every worker
    // inherits a mapping to the same pages. See
    // docs/architecture/worker-shared-state.md § 5.
    // The returned &'static reference outlives the fork; the OwnedFd is
    // passed to every worker via SCM_RIGHTS and is closed in the
    // supervisor once all workers have received it (workers then keep
    // the pages alive via their own OwnedFd inside `open_worker`).
    let (shmem_region, shmem_fd) = match lorica_shmem::SharedRegion::create_supervisor() {
        Ok(pair) => pair,
        Err(e) => {
            error!(error = %e, "failed to create shared-memory region");
            std::process::exit(1);
        }
    };
    info!(
        bytes = lorica_shmem::REGION_SIZE,
        "shared-memory region created; forking workers"
    );

    // Fork workers BEFORE creating any threads/runtime
    let mut manager = WorkerManager::new(config);
    // Hand the memfd to the manager so every forked worker receives it
    // alongside the listener FDs.
    {
        use std::os::fd::AsRawFd;
        manager.set_shmem_fd(Some(shmem_fd.as_raw_fd()));
    }
    // On a hot upgrade, build workers from the inherited listening
    // sockets (same kernel sockets the old workers accept on); otherwise
    // bind fresh ones. Either path captures long-lived handoff dups so
    // THIS supervisor can itself be upgraded later.
    let manager_start = match inherited {
        Some(ref inh) => manager.start_with_inherited_listeners(inh.proxy.clone()),
        None => manager.start(),
    };
    if let Err(e) = manager_start {
        error!(error = %e, "failed to start worker processes");
        std::process::exit(1);
    }
    // The supervisor keeps the fd alive (via `shmem_fd`) for the
    // eviction task and any later supervisor-side reads/writes.

    // Capture the proxy listening sockets to hand over on a future hot
    // upgrade. These raw FDs stay owned by the manager for its lifetime.
    let handoff_proxy_fds: Vec<(String, RawFd)> = manager.handoff_listen_fds();

    info!(
        worker_count = manager.worker_count(),
        "all workers spawned, starting supervisor services"
    );

    // Pre-bind (or adopt) the management-API listening socket in the
    // supervisor itself so it can be handed over on a hot upgrade with no
    // rebind gap. On the new side we adopt the inherited management FD; on
    // a fresh start we bind 127.0.0.1:<port>. We keep a long-lived dup
    // (`mgmt_handoff_listener`) for the next upgrade and pass the original
    // to the API task.
    let mgmt_listener: std::net::TcpListener = match inherited.as_ref().and_then(|i| i.management) {
        Some(fd) => {
            // SAFETY: `fd` was just received via SCM_RIGHTS in
            // `pull_inherited_listeners` and is owned exclusively here; it
            // refers to the same kernel listening socket the old API served
            // on, so adopting it avoids a rebind gap on the management port.
            unsafe { std::net::TcpListener::from_raw_fd(fd) }
        }
        None => match std::net::TcpListener::bind(("127.0.0.1", cli.management_port)) {
            Ok(l) => l,
            Err(e) => {
                error!(error = %e, port = cli.management_port, "failed to bind management listener");
                std::process::exit(1);
            }
        },
    };
    if let Err(e) = mgmt_listener.set_nonblocking(true) {
        error!(error = %e, "failed to set management listener non-blocking");
        std::process::exit(1);
    }
    let mgmt_handoff_listener: std::net::TcpListener = match mgmt_listener.try_clone() {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, "failed to duplicate management listener for handoff");
            std::process::exit(1);
        }
    };
    let mgmt_handoff_fd: RawFd = mgmt_handoff_listener.as_raw_fd();

    // Extract raw FDs from worker handles before entering the tokio runtime.
    // CommandChannel::from_raw_fd requires a tokio runtime, so we take the raw FDs
    // here and create channels inside block_on. Each worker has two channels:
    // the legacy `cmd` socketpair (for Heartbeat/ConfigReload/BanIp/Shutdown)
    // and the pipelined `rpc` socketpair (for WPAR-1 token-bucket sync and
    // future WPAR RPCs).
    let worker_fds: Vec<(u32, i32, RawFd, RawFd)> = manager
        .workers_mut()
        .iter_mut()
        .filter_map(|w| {
            let cmd = w.take_cmd_fd()?;
            let rpc = w.take_rpc_fd()?;
            Some((
                w.id(),
                w.pid().as_raw(),
                cmd.into_raw_fd(),
                rpc.into_raw_fd(),
            ))
        })
        .collect();

    // Now start the async runtime for API server + worker monitoring
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async move {
        let data_dir = PathBuf::from(&cli.data_dir);
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            error!(error = %e, path = %data_dir.display(), "failed to create data directory");
            std::process::exit(1);
        }

        // Load or create encryption key for certificate private keys at rest
        let key_path = data_dir.join("encryption.key");
        let encryption_key = match lorica_config::crypto::EncryptionKey::load_or_create(&key_path) {
            Ok(k) => k,
            Err(e) => {
                error!(error = %e, "failed to load/create encryption key");
                std::process::exit(1);
            }
        };
        restrict_key_permissions(&key_path);

        let db_path = data_dir.join("lorica.db");
        let store = match ConfigStore::open(&db_path, Some(encryption_key)) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to open configuration database");
                std::process::exit(1);
            }
        };
        // Restrict database file permissions (contains encrypted private keys)
        restrict_key_permissions(&db_path);

        match lorica_api::auth::ensure_admin_user(&store) {
            Ok(Some(password)) => match persist_initial_password(&data_dir, &password) {
                Ok(path) => {
                    println!();
                    println!("  ===================================================");
                    println!("  Initial admin password written to (mode 0600):");
                    println!("    {}", path.display());
                    println!("  Read it with:  sudo cat {}", path.display());
                    println!(
                        "  Login at https://localhost:{}/ (self-signed cert - accept the browser warning)",
                        cli.management_port
                    );
                    println!("  You will be asked to change it on first login,");
                    println!("  after which you can delete that file.");
                    println!("  ===================================================");
                    println!();
                    info!(path = %path.display(), "admin user created (first run); password written to 0600 file");
                }
                Err(e) => {
                    // Last resort: never lose the only copy of the
                    // bootstrap credential. Fall back to stdout (journal)
                    // with a warning so the operator can still log in.
                    warn!(error = %e, "failed to write initial password file; printing to stdout as fallback");
                    println!();
                    println!("  ===================================================");
                    println!("  Initial admin password: {password}");
                    println!(
                        "  Login at https://localhost:{}/ (self-signed cert - accept the browser warning)",
                        cli.management_port
                    );
                    println!("  You will be asked to change it on first login.");
                    println!("  ===================================================");
                    println!();
                }
            },
            Ok(None) => {}
            Err(e) => {
                error!(error = %e, "failed to ensure admin user");
                std::process::exit(1);
            }
        }

        let log_store = match lorica_api::log_store::LogStore::open(&data_dir) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                warn!(error = %e, "failed to open access log database, persistence disabled");
                None
            }
        };

        let store = Arc::new(Mutex::new(store));
        let log_buffer = Arc::new(LogBuffer::new(10_000));
        let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let worker_metrics = Arc::new(lorica_api::workers::WorkerMetrics::new());

        try_init_otel_from_settings(&store, "supervisor").await;

        // Supervisor-side GeoIP / ASN state. Workers load the `.mmdb`
        // files from disk at fork and keep their own copy (see the
        // corresponding block in `run_worker`), so the supervisor's
        // job here is to keep the on-disk files fresh via the auto-
        // update task AND to expose a registered resolver handle so
        // the config-reload hook can spawn / abort the updater on
        // `*_auto_update_enabled` toggles from the dashboard.
        //
        // The actual spawn happens inside `apply_geoip_settings_from_store`
        // / `apply_asn_settings_from_store` (called from the first
        // `reload_proxy_config` below), which reads the persisted
        // flag and starts the updater when it is true. This unifies
        // the boot-time path with the runtime hot-reload path so the
        // two can never drift.
        let supervisor_geoip = std::sync::Arc::new(lorica_geoip::GeoIpResolver::empty());
        let supervisor_asn = std::sync::Arc::new(lorica_geoip::AsnResolver::empty());
        // Handle registration shared with worker / single-process
        // modes (audit H-9, see `startup::init_geo_resolver_handles`).
        // No rDNS in the supervisor: it never evaluates
        // bot-protection bypasses.
        startup::init_geo_resolver_handles(&supervisor_geoip, &supervisor_asn, None);
        // `apply_supervisor_settings_from_store` boot call happens
        // below, AFTER `register_supervisor_reload_trigger`, so the
        // "is_supervisor" guard in `apply_auto_update_flip` sees the
        // trigger in place and allows the spawn.

        // UDS log stream: workers send access logs in real-time to the supervisor
        let log_sock_path = data_dir.join("log.sock");
        let _ = std::fs::remove_file(&log_sock_path); // clean stale socket
        let log_listener = tokio::net::UnixListener::bind(&log_sock_path)
            .expect("failed to bind log socket");
        // Make socket writable by the lorica user (workers run as same user)
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&log_sock_path, std::fs::Permissions::from_mode(0o660));
        }
        let log_sink = Arc::clone(&log_buffer);
        tokio::spawn(async move {
            loop {
                match log_listener.accept().await {
                    Ok((stream, _)) => {
                        let sink = Arc::clone(&log_sink);
                        tokio::spawn(async move {
                            let mut reader = tokio::io::BufReader::new(stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                    Ok(0) => break, // EOF - worker disconnected
                                    Ok(_) => {
                                        if let Ok(entry) = serde_json::from_str::<lorica_api::logs::LogEntry>(&line) {
                                            // Workers persist access logs directly via their own
                                            // LogStore, so we only push to the in-memory buffer
                                            // here (for WebSocket streaming to the dashboard).
                                            sink.push(entry);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "log socket accept failed");
                    }
                }
            }
        });

        // Shared-memory region eviction task. The supervisor is the sole
        // evictor; workers only read and increment. See
        // docs/architecture/worker-shared-state.md § 5.4. Cadence and
        // staleness come from `lorica_shmem::DEFAULT_SCAN_INTERVAL` (60s)
        // and `DEFAULT_STALE_AFTER` (5 min) respectively.
        {
            let region = shmem_region;
            tokio::spawn(async move {
                let mut tick =
                    tokio::time::interval(lorica_shmem::DEFAULT_SCAN_INTERVAL);
                tick.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Delay,
                );
                tick.tick().await; // skip the immediate tick
                let stale_ns = lorica_shmem::DEFAULT_STALE_AFTER.as_nanos() as u64;
                loop {
                    tick.tick().await;
                    let now = lorica_shmem::now_ns();
                    let stats = lorica_shmem::evict_once(region, now, stale_ns);
                    lorica_shmem::eviction::log_pass(stats);
                }
            });
        }

        // Broadcast channel: API config changes fan out to all per-worker tasks
        let (reload_bc_tx, _) = broadcast::channel::<u64>(16);
        // Broadcast channel: supervisor sends BanIp commands to all
        // per-worker tasks. Capacity 1024: large enough to absorb a
        // sweep-like burst from `/api/v1/bans/bulk` or a WAF flood
        // without tripping `RecvError::Lagged` under normal load. If
        // a worker still lags, the drop count is exported via the
        // `lorica_ban_broadcast_lagged_total{worker_id}` Prometheus
        // counter and the ban is still persisted to SQLite, so the
        // next `ConfigReload` picks it up.
        let (ban_bc_tx, _) = broadcast::channel::<(String, u64)>(1024);
        // Clone for the API's watch-based reload signal
        let reload_bc_tx_clone = reload_bc_tx.clone();
        let (config_reload_tx, mut config_reload_rx) = tokio::sync::watch::channel(0u64);

        // Register the watch sender with the reload module so the
        // GeoIP / ASN auto-update task can bump it after every
        // successful download. That triggers the worker reload
        // coordinator below, which makes the freshly-downloaded
        // .mmdb visible to the data plane without a manual save.
        lorica::reload::register_supervisor_reload_trigger(config_reload_tx.clone());

        // Fire the hot-reload path once at boot so the updater
        // tasks spawn if `*_auto_update_enabled` is persisted true.
        // Must run AFTER `register_supervisor_reload_trigger` above
        // so the supervisor-guard in `apply_auto_update_flip` lets
        // the spawn through.
        lorica::reload::apply_supervisor_settings_from_store(&store).await;

        // Per-worker RPC endpoint table. Used by the config-reload
        // coordinator (§ 7 WPAR-8) to fan out `ConfigReloadPrepare`
        // and `ConfigReloadCommit` in two phases. Each worker's spawn
        // block inserts here; on worker crash + respawn the table is
        // updated with the new endpoint.
        let worker_rpc_endpoints: Arc<
            dashmap::DashMap<u32, lorica_command::RpcEndpoint>,
        > = Arc::new(dashmap::DashMap::new());
        // Monotonic generation counter owned by the supervisor. Every
        // coordinated Prepare+Commit round bumps it so late/reordered
        // workers detect stale Prepares via `GenerationGate::observe`.
        let reload_generation: Arc<std::sync::atomic::AtomicU64> =
            Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Per-route rate-limit policy cache (audit M-4). Without this
        // cache, N concurrent `RateLimitDelta` RPCs on a first-seen
        // `{route|scope}` key serialise on the single `store`
        // tokio::Mutex for N SQLite reads. Cache populated on miss,
        // invalidated on every successful two-phase Commit (see the
        // reload coordinator below).
        let rl_policy_cache: Arc<
            dashmap::DashMap<String, Option<lorica_config::models::RateLimit>>,
        > = Arc::new(dashmap::DashMap::new());

        // Bridge: watch channel (from API) -> broadcast (to per-worker tasks)
        //
        // In worker mode we also drive the pipelined-RPC two-phase
        // coordinator off the same signal (see `coordinate_config_reload`
        // below). The coordinator and the legacy broadcast both end up
        // reloading the same config; when both succeed the later one is
        // a no-op (new_config == current_config). We keep the legacy
        // path for the rare case where a worker's RPC channel is not
        // yet registered (race at worker spawn).
        let sequence = Arc::new(AtomicU64::new(1));
        let bridge_seq = Arc::clone(&sequence);
        let endpoints_for_reload = Arc::clone(&worker_rpc_endpoints);
        let reload_generation_clone = Arc::clone(&reload_generation);
        let rl_policy_for_reload = Arc::clone(&rl_policy_cache);
        let supervisor_reload_store = Arc::clone(&store);
        tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                // Apply the per-process hot-reload hooks (GeoIP / ASN
                // updater task lifecycle, OTel exporter, bot HMAC
                // secret) on the SUPERVISOR side. Worker reload runs
                // independently via the RPC two-phase coordinator
                // below. Without this call, supervisor-side state
                // (auto-update task spawn / abort, OTel exporter)
                // would only refresh at boot time.
                lorica::reload::apply_supervisor_settings_from_store(
                    &supervisor_reload_store,
                )
                .await;
                let seq = bridge_seq.fetch_add(1, Ordering::Relaxed);
                // Two-phase RPC reload (WPAR-8) when any worker has a
                // registered endpoint.
                if !endpoints_for_reload.is_empty() {
                    let gen = reload_generation_clone
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    let report = coordinate_config_reload(&endpoints_for_reload, gen).await;
                    if !report.prepare_failed.is_empty() || !report.commit_failed.is_empty() {
                        // Audit M-17 : when commit_failed is non-empty
                        // AND committed is non-empty, the fleet is
                        // transiently split (some workers serve the
                        // new config, others still on the old) until
                        // the legacy fallback below brings the
                        // stragglers in line. Surface as a Prometheus
                        // counter so operators can alert on
                        // fleet-coherence gaps even though the system
                        // self-heals on the next reload.
                        if !report.commit_failed.is_empty() && !report.committed.is_empty() {
                            warn!(
                                seq,
                                generation = report.generation,
                                committed = report.committed.len(),
                                commit_failed = report.commit_failed.len(),
                                "two-phase config reload split fleet : some workers committed, others did not - legacy broadcast fallback will reconcile"
                            );
                            lorica_api::metrics::inc_config_reload_split_fleet();
                        }
                        warn!(
                            seq,
                            generation = report.generation,
                            prepare_failed = report.prepare_failed.len(),
                            commit_failed = report.commit_failed.len(),
                            "two-phase config reload had failures; falling back to legacy broadcast"
                        );
                        let _ = reload_bc_tx_clone.send(seq);
                    }
                    // Whether the two-phase path fully committed or fell
                    // back to the legacy broadcast, the route policies
                    // may have changed - drop the supervisor-side
                    // rate-limit policy cache so the next RateLimitDelta
                    // re-reads them from the store (audit M-4).
                    rl_policy_for_reload.clear();
                } else {
                    // No workers with RPC (e.g. --workers 0 or before
                    // any worker registered). Fall back to legacy
                    // per-worker broadcast which also fires the SIGHUP
                    // path for single-process mode.
                    let _ = reload_bc_tx_clone.send(seq);
                    rl_policy_for_reload.clear();
                }
            }
        });

        // Aggregated metrics from all workers (shared with API)
        let aggregated_metrics = Arc::new(lorica_api::workers::AggregatedMetrics::new());

        // Track per-worker task handles so we can abort stale tasks on restart
        let worker_task_handles: Arc<parking_lot::Mutex<std::collections::HashMap<u32, tokio::task::JoinHandle<()>>>> =
            Arc::new(parking_lot::Mutex::new(std::collections::HashMap::new()));

        // Cross-worker authoritative token-bucket registry. Every
        // `RateLimitDelta` RPC from a worker drains its consumption into
        // the `AuthoritativeBucket` keyed here, then replies with the
        // current token count for each key so the worker can refresh its
        // local cache. See docs/architecture/worker-shared-state.md § 6.
        let rl_registry: Arc<
            dashmap::DashMap<String, Arc<lorica_limits::token_bucket::AuthoritativeBucket>>,
        > = Arc::new(dashmap::DashMap::new());

        // Cross-worker forward-auth verdict cache. Workers issue
        // `VerdictLookup` before calling the auth upstream and
        // `VerdictPush` after a successful Allow. A single shared cache
        // means every worker sees Allow verdicts populated by any peer
        // and a session revocation invalidates them uniformly. See
        // design § 7 WPAR-2.
        let verdict_cache: Arc<SupervisorVerdictCache> =
            Arc::new(SupervisorVerdictCache::new());

        // Cross-worker circuit breaker state. Workers ask the
        // supervisor whether a request to `(route, backend)` should be
        // admitted and report back the outcome; the supervisor owns
        // the Closed/Open/HalfOpen state machine so probe admission
        // never races across workers. See design § 7 WPAR-3.
        let breaker_registry: Arc<SupervisorBreakerRegistry> =
            Arc::new(SupervisorBreakerRegistry::new(5, Duration::from_secs(10)));

        // Shared shutdown flag. Set by the SIGTERM handler before
        // `manager.shutdown_all()` so the worker monitor short-circuits
        // crash-event respawns and the per-worker heartbeat tasks stop
        // probing workers that were just SIGTERM'd (avoids a burst of
        // "heartbeat send failed: Broken pipe" warnings at every
        // shutdown).
        let shutting_down = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Spawn a per-worker task that handles both config reload and heartbeat
        // No shared Mutex - each worker has its own channel and task
        for (worker_id, worker_pid, raw_fd, rpc_raw_fd) in worker_fds {
            // SAFETY: raw_fd is a valid file descriptor from the socketpair
            // created by WorkerManager::spawn_workers(), passed to this task
            // immediately after fork. The fd is exclusively owned by this task.
            let channel = match unsafe { CommandChannel::from_raw_fd(raw_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(worker_id, error = %e, "failed to create command channel");
                    continue;
                }
            };
            let reload_rx = reload_bc_tx.subscribe();
            let ban_rx = ban_bc_tx.subscribe();
            let hb_seq = Arc::clone(&sequence);
            let hb_metrics = Arc::clone(&worker_metrics);
            let agg_metrics = Arc::clone(&aggregated_metrics);
            let hb_shutting_down = Arc::clone(&shutting_down);

            // Pipelined RPC channel task: consumes the per-worker
            // RpcEndpoint stream and handles RateLimitDelta /
            // VerdictLookup / VerdictPush / BreakerQuery /
            // BreakerReport. Spawned alongside the legacy channel
            // task ; dies with the worker. Same wiring is re-issued
            // by the crash branch in `monitor_workers` (audit C-1
            // closure) - both call sites go through one helper so a
            // new RPC variant is wired uniformly.
            spawn_supervisor_rpc_handler(
                worker_id,
                rpc_raw_fd,
                Arc::clone(&rl_registry),
                Arc::clone(&rl_policy_cache),
                Arc::clone(&store),
                Arc::clone(&verdict_cache),
                Arc::clone(&breaker_registry),
                Arc::clone(&worker_rpc_endpoints),
            );

            let handle = spawn_worker_channel_task(
                worker_id,
                worker_pid,
                channel,
                ban_rx,
                reload_rx,
                hb_seq,
                hb_shutting_down,
                hb_metrics,
                agg_metrics,
            );
            worker_task_handles.lock().insert(worker_id, handle);
        }

        // Bug 1 fix: Create a ProxyConfig for health checks in supervisor mode.
        // The supervisor does not route traffic, but it needs a ProxyConfig to
        // resolve backend topologies for health check decisions. It also triggers
        // reload_proxy_config so the health loop sees updated backends.
        let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
        if let Err(e) = reload_proxy_config(&store, &proxy_config, None).await {
            warn!(error = %e, "supervisor: failed to load initial proxy config for health checks");
        }

        // Create non-blocking alert sender (broadcast channel for proxy/health/acme -> dispatcher)
        let alert_sender = lorica_notify::AlertSender::new(256);

        // Start health check background task (runs in supervisor, not
        // workers). No backend_connections in supervisor - drain
        // monitoring is per-worker. Spawn shared with single-process
        // mode (audit H-9, see `startup::spawn_health_check_loop`).
        let health_handle = startup::spawn_health_check_loop(
            &store,
            &proxy_config,
            None,
            alert_sender.clone(),
            Some(reload_bc_tx.clone()),
        )
        .await;

        // Create WAF engine in supervisor for API access (rules listing,
        // blocklist toggle, events). Workers have their own engines for
        // real-time evaluation in the proxy pipeline.
        let waf_engine = Arc::new(lorica_waf::WafEngine::new());
        let waf_event_buffer = waf_engine.event_buffer();
        let waf_rule_count = waf_engine.rule_count();

        // UDS WAF event stream: workers forward WAF events to the supervisor
        let waf_sock_path = data_dir.join("waf.sock");
        let _ = std::fs::remove_file(&waf_sock_path);
        let waf_listener = tokio::net::UnixListener::bind(&waf_sock_path)
            .expect("failed to bind WAF socket");
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&waf_sock_path, std::fs::Permissions::from_mode(0o660));
        }
        let waf_event_sink = Arc::clone(&waf_event_buffer);
        let waf_alert_sender = alert_sender.clone();
        // Cross-worker WAF auto-ban counter lives in the shmem region
        // (see lorica-shmem::SharedRegion::waf_auto_ban). The supervisor
        // is the sole ban-issuer: it increments on each UDS event,
        // compares to the configured threshold, and on crossing
        // broadcasts BanIp then resets the slot so the next round of
        // violations starts at zero.
        let waf_shmem = shmem_region;
        let waf_ban_tx = ban_bc_tx.clone();
        let waf_ban_store = Arc::clone(&store);
        tokio::spawn(async move {
            loop {
                match waf_listener.accept().await {
                    Ok((stream, _)) => {
                        let sink = Arc::clone(&waf_event_sink);
                        let alert_tx = waf_alert_sender.clone();
                        let ban_tx = waf_ban_tx.clone();
                        let ban_store = Arc::clone(&waf_ban_store);
                        let shmem = waf_shmem;
                        tokio::spawn(async move {
                            let mut reader = tokio::io::BufReader::new(stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        if let Ok(event) = serde_json::from_str::<lorica_waf::WafEvent>(&line) {
                                            // Workers insert WAF events into the DB directly
                                            // (with route_hostname and action stamped), so we
                                            // skip the insert here to avoid duplicates.

                                            // Dispatch WAF alert notification
                                            alert_tx.send(
                                                lorica_notify::AlertEvent::new(
                                                    lorica_notify::events::AlertType::WafAlert,
                                                    format!("WAF {}: {} (rule {})", event.category.as_str(), event.description, event.rule_id),
                                                )
                                                .with_detail("rule_id", event.rule_id.to_string())
                                                .with_detail("category", event.category.as_str().to_string())
                                                .with_detail("severity", event.severity.to_string()),
                                            );

                                            // Global WAF auto-ban: read the cross-worker shmem
                                            // counter. Workers have already bumped it in their
                                            // hot path (see proxy_wiring.rs). The supervisor
                                            // compares against the configured threshold and,
                                            // on the first crossing, broadcasts BanIp and
                                            // resets the slot so the next round starts at zero.
                                            //
                                            // Concurrent UDS events for the same IP can race:
                                            // task A reads shmem >= threshold, decides to ban,
                                            // resets; task B reads (post-A's read, pre-A's
                                            // reset) ALSO sees >= threshold and broadcasts a
                                            // duplicate BanIp. The race is bounded by the
                                            // burst size of WAF events for one IP within a few
                                            // microseconds, and the duplicate broadcast is
                                            // idempotent (DashMap insert + same duration). The
                                            // ban_list arrives at every worker exactly the
                                            // same way; the only effect is one extra notify
                                            // alert dispatch. Acceptable.
                                            if !event.client_ip.is_empty() && event.client_ip != "-" {
                                                let s = ban_store.lock().await;
                                                let (threshold, duration_s) = s.get_global_settings()
                                                    .map(|gs| (gs.waf_ban_threshold as u64, gs.waf_ban_duration_s as u64))
                                                    .unwrap_or((0, 600));
                                                drop(s);

                                                if threshold > 0 {
                                                    let key = lorica::proxy_wiring::ip_to_shmem_key(
                                                        &event.client_ip,
                                                    );
                                                    let tagged = shmem.tagged(key);
                                                    let count = shmem
                                                        .waf_auto_ban
                                                        .read(tagged)
                                                        .unwrap_or(0);
                                                    if count >= threshold {
                                                        // Reset slot so concurrent/future
                                                        // violations after broadcast start
                                                        // fresh. CAS failure is benign (another
                                                        // event raced and we already broadcast).
                                                        let _ = shmem
                                                            .waf_auto_ban
                                                            .reset(tagged);
                                                        warn!(
                                                            ip = %event.client_ip,
                                                            violations = %count,
                                                            ban_duration_s = %duration_s,
                                                            "global WAF auto-ban: IP banned for repeated violations"
                                                        );
                                                        // Broadcast BanIp to all workers
                                                        let _ = ban_tx.send((event.client_ip.clone(), duration_s));
                                                        // Dispatch ip_banned alert
                                                        alert_tx.send(
                                                            lorica_notify::AlertEvent::new(
                                                                lorica_notify::events::AlertType::IpBanned,
                                                                format!(
                                                                    "IP {} auto-banned for repeated WAF violations",
                                                                    event.client_ip
                                                                ),
                                                            )
                                                            .with_detail("ip", event.client_ip.clone())
                                                            .with_detail("violations", count.to_string())
                                                            .with_detail("ban_duration_s", duration_s.to_string()),
                                                        );
                                                    }
                                                }
                                            }

                                            let mut buf = sink.lock();
                                            if buf.len() >= 500 {
                                                buf.pop_front();
                                            }
                                            buf.push_back(event);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "WAF socket accept failed");
                    }
                }
            }
        });

        // Restore WAF state (IP blocklist + initial fetch, disabled + custom rules)
        supervisor_restore_waf_state(&store, &waf_engine).await;

        // Tracker shared by every background task that must drain on
        // shutdown (blocklist refresh, ACME polling, session GC,
        // backend drain, loadtest driver). The shutdown path below
        // calls `close(); wait().await` on its clone.
        let task_tracker = tokio_util::task::TaskTracker::new();

        // Spawn IP blocklist auto-refresh in supervisor
        let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
            Arc::clone(&waf_engine),
            std::time::Duration::from_secs(6 * 3600),
            &task_tracker,
        );

        // Notification dispatcher + alert bridge + probe scheduler +
        // SLA collector cluster, shared with single-process mode
        // (audit H-9, see `startup::start_alerting_stack`). The
        // notification history is re-read from the dispatcher at
        // AppState build below, so the handle is discarded here.
        let startup::AlertingStack {
            notify_dispatcher,
            notification_history: _,
            probe_scheduler,
            sla_collector,
        } = startup::start_alerting_stack(&store, &alert_sender, log_store.clone()).await;

        // Reload proxy config, probe scheduler, SLA configs, and notification dispatcher on config changes
        let reload_store = Arc::clone(&store);
        let reload_config = Arc::clone(&proxy_config);
        let reload_probe_scheduler = Arc::clone(&probe_scheduler);
        let reload_sla_collector = Arc::clone(&sla_collector);
        let reload_notify_dispatcher = Arc::clone(&notify_dispatcher);
        let mut reload_rx = reload_bc_tx.subscribe();
        tokio::spawn(async move {
            while reload_rx.recv().await.is_ok() {
                if let Err(e) = reload_proxy_config(&reload_store, &reload_config, None).await {
                    tracing::error!(error = %e, "supervisor: failed to reload proxy config");
                }
                reload_probe_scheduler.reload().await;
                {
                    let s = reload_store.lock().await;
                    reload_sla_collector.load_configs(&s);
                    // Rebuild notification dispatcher with updated channel configs
                    let new_dispatcher = startup::build_notify_dispatcher(&s);
                    let mut d = reload_notify_dispatcher.lock().await;
                    *d = new_dispatcher;
                }
            }
        });

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let api_log_store = log_store.clone();
        let api_worker_metrics = Arc::clone(&worker_metrics);
        let api_aggregated_metrics = Arc::clone(&aggregated_metrics);
        // Pipelined metrics refresher (WPAR-7 pull-on-scrape). Captures
        // the per-worker RPC endpoint map, the AggregatedMetrics
        // handle, and a dedup lock so concurrent /metrics scrapes
        // collapse into a single supervisor fan-out. Lives for the
        // lifetime of the API task.
        let refresher_endpoints = Arc::clone(&worker_rpc_endpoints);
        let refresher_aggregated = Arc::clone(&aggregated_metrics);
        let refresher_dedup: Arc<tokio::sync::Mutex<Option<Instant>>> =
            Arc::new(tokio::sync::Mutex::new(None));
        let api_metrics_refresher: lorica_api::server::MetricsRefresher = Arc::new(move || {
            let endpoints = Arc::clone(&refresher_endpoints);
            let aggregated = Arc::clone(&refresher_aggregated);
            let dedup = Arc::clone(&refresher_dedup);
            Box::pin(pull_all_metrics_via_rpc(
                endpoints,
                aggregated,
                dedup,
                METRICS_PULL_PER_WORKER_TIMEOUT,
                METRICS_PULL_DEDUP_TTL,
            ))
        });
        let management_port = cli.management_port;
        let api_db_path = db_path.clone();
        // `task_tracker` is already defined above (before the WAF
        // blocklist refresh spawn). Re-use its clones for the API
        // task's AppState and the shutdown drain path.
        let api_task_tracker = task_tracker.clone();
        let shutdown_task_tracker = task_tracker.clone();
        // Clone the alert sender so the ACME renewal + cert-expiry
        // background tasks spawned inside the API tail can surface
        // alerts through the same dispatcher the health / WAF paths
        // already use. The tail itself is shared with single-process
        // mode (audit H-9, see `startup::run_api_server`; v1.5.2 fix:
        // worker mode was missing auto-renewal entirely).
        let api_alert_sender = alert_sender.clone();
        // Load-test engine + cron scheduler (shared helper, see
        // `startup::start_load_test_engine`). Story 8.1 asymmetry,
        // fixed in v1.5.11: supervisor mode used to create the engine
        // for AppState without ever starting the scheduler, so
        // cron-scheduled load tests silently never ran in worker mode.
        let load_test_engine = startup::start_load_test_engine(&store);
        // Snapshot the whole CLI for the hot-upgrade control loop, as the
        // API task's `async move` below moves `cli` into itself. Cloning
        // the live `Cli` (rather than a hand-picked subset of scalars) is
        // what lets the handoff derive the child argv from it without the
        // two drifting apart (audit M2).
        let hu_cli = cli.clone();
        // Hot-upgrade trigger channel (Story 8.4). The API's
        // `POST /api/v1/system/upgrade` handler sends the staged binary
        // path here after a successful verify+stage; the supervisor's
        // control loop (below) receives it and drives the handoff.
        // Capacity 1: a second upgrade while one is in flight is shed.
        let (upgrade_tx, mut upgrade_rx) =
            tokio::sync::mpsc::channel::<lorica_api::upgrade::StagedBinary>(1);
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store,
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                data_dir: PathBuf::from(&cli.data_dir),
                http_port: cli.http_port,
                https_port: cli.https_port,
                config_reload_tx: Some(config_reload_tx),
                // Supervisor: cache/ban are per-worker process, surfaced
                // to the API as metrics aggregated over the command channel.
                mode: lorica_api::server::Mode::Supervisor {
                    worker_metrics: api_worker_metrics,
                    aggregated_metrics: api_aggregated_metrics,
                    metrics_refresher: Some(api_metrics_refresher),
                    upgrade_trigger: upgrade_tx,
                },
                waf_event_buffer: Some(waf_event_buffer),
                waf_engine: Some(waf_engine),
                waf_rule_count: Some(waf_rule_count),
                acme_challenge_store: Some(lorica_api::acme::AcmeChallengeStore::with_db_path(api_db_path)),
                pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
                sla_collector: Some(Arc::clone(&sla_collector)),
                load_test_engine: Some(load_test_engine),
                notification_history: {
                    let d = notify_dispatcher.lock().await;
                    Some(d.history())
                },
                log_store: api_log_store,
                log_writer: None,
                task_tracker: api_task_tracker,
            };
            // Session store + ACME auto-renewal + cert-expiry notifier
            // + server loop, shared with single-process mode (audit
            // H-9, see `startup::run_api_server`). The management listener
            // is pre-bound (or adopted from the outgoing supervisor) so it
            // can be handed over on the next hot upgrade without a gap.
            startup::run_api_server(management_port, state, api_alert_sender, Some(mgmt_listener))
                .await;
        });

        // Hourly retention loop (access logs, probe results, WAF
        // events, SLA buckets), shared across modes (audit H-9, see
        // `startup::spawn_retention_loop`). No-op when the access-log
        // store failed to open.
        startup::spawn_retention_loop(log_store.clone(), Arc::clone(&store));

        // Cluster plane (Story 9.2): control-plane listeners, opt-in
        // via --cluster-listen. A bad bind or a missing CA is fatal -
        // the operator asked for the plane, running without it is
        // the wrong failure mode. Handles stay alive for the process
        // lifetime; the stats feed the Prometheus bridge.
        // On a hot upgrade the operational cluster socket is adopted
        // from the outgoing supervisor (Story 9.1's FD slot), so
        // established follower sessions survive the handoff exactly
        // like proxy connections do. The enrollment socket is not
        // handed off: it only exists while a join token is live and
        // rebinds on the next liveness edge.
        let inherited_operational_fd: Option<RawFd> = inherited.as_ref().and_then(|i| {
            i.cluster
                .iter()
                .find(|(role, _, _)| *role == hot_upgrade::ClusterListenerRole::Operational)
                .map(|(_, _, fd)| *fd)
        });
        let mut cluster_plane = match startup::cluster_plane::spawn_cluster_plane(
            startup::cluster_plane::ClusterPlaneOptions {
                cluster_listen: hu_cli.cluster_listen.clone(),
                enrollment_listen: hu_cli.cluster_enrollment_listen.clone(),
                advertise: hu_cli.cluster_advertise.clone(),
                listen_any: hu_cli.cluster_listen_any,
                reserved: crate::cli::ReservedPorts {
                    management: management_port,
                    http: hu_cli.http_port,
                    https: hu_cli.https_port,
                },
                inherited_operational_fd,
            },
            &store,
        )
        .await
        {
            Ok(Some(plane)) => {
                lorica_api::metrics::install_cluster_plane_stats(
                    Arc::clone(&plane.operational_stats),
                    Arc::clone(&plane.enrollment_stats),
                );
                Some(plane)
            }
            Ok(None) => None,
            Err(e) => {
                error!(error = %e, "cluster plane failed to start");
                std::process::exit(1);
            }
        };

        // Worker monitoring loop (crash detection and restart with backoff)
        let manager = Arc::new(std::sync::Mutex::new(manager));
        let monitor_mgr = Arc::clone(&manager);
        let monitor_reload_tx = reload_bc_tx.clone();
        let monitor_ban_tx = ban_bc_tx.clone();
        let monitor_seq = Arc::clone(&sequence);
        let monitor_hb_metrics = Arc::clone(&worker_metrics);
        let monitor_agg_metrics = Arc::clone(&aggregated_metrics);
        let monitor_task_handles = Arc::clone(&worker_task_handles);
        // Audit C-1 fix : the worker-respawn path now re-wires the
        // RPC endpoint as well as the legacy command channel, so the
        // supervisor's two-phase config-reload coordinator finds the
        // restarted worker and stops silently skipping it. Cloning
        // the deps the helper needs once at monitor scope so the
        // crash branch can move them into `spawn_supervisor_rpc_handler`.
        let monitor_rpc_endpoints = Arc::clone(&worker_rpc_endpoints);
        let monitor_rl_registry = Arc::clone(&rl_registry);
        let monitor_rl_policy = Arc::clone(&rl_policy_cache);
        let monitor_store = Arc::clone(&store);
        let monitor_verdict_cache = Arc::clone(&verdict_cache);
        let monitor_breaker_registry = Arc::clone(&breaker_registry);
        // `shutting_down` is declared above, shared with the per-worker
        // heartbeat tasks. The monitor short-circuits on the same flag
        // so shutdown-driven worker SIGKILLs don't trigger a respawn:
        // `monitor_handle.abort()` alone is not enough because the
        // monitor's loop blocks on `monitor_mgr.lock()` (a
        // `std::sync::Mutex`, not a tokio one), so abort cannot fire
        // while the supervisor is holding that mutex inside
        // `manager.shutdown_all()`. The monitor would then unblock
        // 30 s later, see the SIGKILL'd workers as crashed, and
        // respawn them - the exact race that drove systemd to SIGKILL
        // the whole service group past `TimeoutStopSec`.
        let monitor_shutting_down = Arc::clone(&shutting_down);
        let monitor_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;

                if monitor_shutting_down.load(std::sync::atomic::Ordering::Acquire) {
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
                    if monitor_shutting_down.load(std::sync::atomic::Ordering::Acquire) {
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

                    // Drop the dead worker's generic-counter baseline before
                    // it respawns with the SAME worker_id. The aggregator
                    // keeps a per-worker last-value baseline and applies
                    // positive deltas only; a respawned worker restarts its
                    // counters at 0, so without this forget the supervisor
                    // would hold the pre-crash high-water mark and freeze the
                    // worker's contribution until it climbed back over it.
                    // Typed metrics (cache/bans/EWMA/...) self-heal because
                    // `AggregatedMetrics::update_worker` stores absolute
                    // values keyed by worker_id; only the delta-based generic
                    // counters need this reset.
                    lorica_api::metrics::forget_worker_generic_counters(id);

                    // Re-check shutdown flag before respawning - a
                    // crash detected just before SIGTERM should not
                    // trigger a respawn that races shutdown.
                    if monitor_shutting_down.load(std::sync::atomic::Ordering::Acquire) {
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
                        if monitor_shutting_down.load(std::sync::atomic::Ordering::Acquire) {
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
                                Ok(channel) => {
                                    let rx = monitor_reload_tx.subscribe();
                                    let ban_rx = monitor_ban_tx.subscribe();
                                    let seq = Arc::clone(&monitor_seq);
                                    let hb_metrics = Arc::clone(&monitor_hb_metrics);
                                    let agg_metrics = Arc::clone(&monitor_agg_metrics);
                                    let new_handle = spawn_worker_channel_task(
                                        id,
                                        new_pid,
                                        channel,
                                        ban_rx,
                                        rx,
                                        seq,
                                        Arc::clone(&monitor_shutting_down),
                                        hb_metrics,
                                        agg_metrics,
                                    );
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
        });

        // Hot upgrade (Story 8.4), NEW supervisor side: now that workers
        // are forked from the inherited sockets and the API task is
        // running on the inherited management socket, confirm we are up to
        // the outgoing supervisor so it can drain. The shared listening
        // sockets mean the old process is still accepting until it drains,
        // so an early "ready" here is safe.
        let self_pid: i32 = std::process::id() as i32;
        if hu_cli.hot_upgrade {
            // Robust readiness handshake (audit H3): resend "ready" until
            // the old acks, and ONLY THEN reassign the systemd MAINPID. A
            // dropped datagram must never leave the old rolling back (and
            // SIGKILLing us) after we have claimed MAINPID (split-brain).
            match hot_upgrade::handshake_ready_with_old(
                &data_dir_path,
                hot_upgrade::READY_ACK_DEADLINE,
            )
            .await
            {
                Ok(true) => {
                    info!("hot upgrade: outgoing supervisor acked readiness");
                    match hot_upgrade::sd_notify_ready(self_pid) {
                        Ok(true) => info!(pid = self_pid, "sent sd_notify READY + MAINPID"),
                        Ok(false) => info!("NOTIFY_SOCKET unset, skipping sd_notify"),
                        Err(e) => warn!(error = %e, "sd_notify failed"),
                    }
                    // Terminal success recorded HERE, in the surviving new
                    // process's registry (the old's dies on exit), so an
                    // operator can see the completed upgrade on /metrics
                    // (audit M4).
                    lorica_api::metrics::record_hot_upgrade("completed");
                }
                Ok(false) => {
                    // No ack within the deadline: the old never saw us (or
                    // the ack path is broken). Exit so it rolls back
                    // cleanly; we never claimed MAINPID, so systemd still
                    // tracks the (live) old supervisor.
                    error!(
                        "hot upgrade: no ack from outgoing supervisor within the deadline; \
                         exiting so it resumes serving"
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    error!(error = %e, "hot upgrade: readiness handshake failed; exiting so the outgoing supervisor resumes");
                    std::process::exit(1);
                }
            }
        } else {
            // Cold boot: tell systemd we are accepting. REQUIRED for
            // `Type=notify` on every start or systemd times the unit out.
            // `MAINPID=self` is a no-op (self is already the tracked main
            // PID). No-op when `$NOTIFY_SOCKET` is unset (Docker, manual run).
            match hot_upgrade::sd_notify_ready(self_pid) {
                Ok(true) => info!(pid = self_pid, "sent sd_notify READY + MAINPID"),
                Ok(false) => info!("NOTIFY_SOCKET unset, skipping sd_notify"),
                Err(e) => warn!(error = %e, "sd_notify failed"),
            }
        }

        // Main control loop: serve until either a shutdown signal or a
        // hot-upgrade trigger arrives. A rollback resumes the loop
        // (keeps serving); a successful handoff or a shutdown breaks out.
        loop {
            tokio::select! {
                _ = shutdown_signal() => {
                    info!("supervisor shutting down");
                    // Stop accepting cluster sessions and tear down the
                    // established ones before the workers drain.
                    if let Some(plane) = cluster_plane.take() {
                        plane.shutdown();
                    }
                    // CRITICAL ordering: stop the worker monitor BEFORE
                    // telling workers to drain. The monitor respawns
                    // crashed workers; during shutdown the SIGKILL we
                    // send to stragglers shows up as a crash and would
                    // trigger a respawn-into-shutdown race. The atomic
                    // flag is the primary defence (the monitor checks it
                    // around its std::sync::Mutex acquire); abort is the
                    // backstop.
                    shutting_down.store(true, std::sync::atomic::Ordering::Release);
                    monitor_handle.abort();
                    manager
                        .lock()
                        .unwrap_or_else(|e| {
                            warn!("worker manager mutex poisoned during shutdown, recovering");
                            e.into_inner()
                        })
                        .shutdown_all();
                    // Drain tracked background tasks, bounded to 10 s.
                    shutdown_task_tracker.close();
                    if tokio::time::timeout(Duration::from_secs(10), shutdown_task_tracker.wait())
                        .await
                        .is_err()
                    {
                        warn!("some background tasks did not finish within drain timeout; aborting");
                    }
                    api_handle.abort();
                    health_handle.abort();
                    lorica::otel::shutdown();
                    break;
                }
                staged = upgrade_rx.recv() => {
                    let Some(staged) = staged else {
                        // All senders dropped (API task gone): nothing
                        // more can trigger an upgrade. Keep serving until
                        // a shutdown signal arrives.
                        continue;
                    };
                    let staged_path = staged.path.clone();
                    info!(
                        staged = %staged_path.display(),
                        "hot upgrade triggered; beginning handoff to new supervisor"
                    );

                    // Re-verify the staged binary against the SHA-256
                    // computed at verify+stage time, immediately before we
                    // fork/exec it. Closes the TOCTOU where the on-disk
                    // binary is swapped between staging and exec (audit M7).
                    if let Err(e) =
                        lorica_api::upgrade::verify_staged_digest(&staged_path, &staged.sha256)
                    {
                        error!(
                            error = %e,
                            staged = %staged_path.display(),
                            "hot upgrade: staged binary failed re-verification; refusing to exec it"
                        );
                        lorica_api::metrics::record_hot_upgrade(
                            hot_upgrade::RollbackReason::ExecFailed.metric_outcome(),
                        );
                        let unix_ts: u64 = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        if let Ok(dest) =
                            hot_upgrade::quarantine_failed_binary(&data_dir_path, &staged_path, unix_ts)
                        {
                            info!(quarantined = %dest.display(), "hot upgrade: quarantined the mismatched staged binary");
                        }
                        continue;
                    }

                    // Build the new binary's argv from this process's live
                    // CLI (audit M2), resolving the concrete worker count so
                    // the child does not re-resolve `auto`.
                    let child_argv: Vec<String> =
                        hu_cli.hot_upgrade_argv(&staged_path.to_string_lossy(), worker_count);

                    let run = hot_upgrade::run_old_side_handoff(hot_upgrade::HandoffArgs {
                        data_dir: data_dir_path.clone(),
                        staged_binary: staged_path.clone(),
                        proxy_fds: handoff_proxy_fds.clone(),
                        management_fd: mgmt_handoff_fd,
                        management_port,
                        // The operational cluster listener rides the
                        // same FD handoff as the proxy sockets; the
                        // enrollment one is rebound by the new side.
                        cluster_fds: cluster_plane
                            .as_ref()
                            .map(|plane| plane.handoff_fds())
                            .unwrap_or_default(),
                        child_argv,
                    })
                    .await;

                    match run.decision {
                        hot_upgrade::HandoffDecision::Drain => {
                            info!("hot upgrade: new supervisor is up; draining old workers");
                            // Stop the monitor so a drained worker is not
                            // seen as a crash and respawned.
                            shutting_down.store(true, std::sync::atomic::Ordering::Release);
                            monitor_handle.abort();
                            // Drain in-flight connections, timing it for
                            // the histogram. Only after this completes do
                            // the old listening sockets close (the manager
                            // drops at process exit); until then both old
                            // and new accept from the shared queue, so no
                            // connection is dropped.
                            let drain_start = Instant::now();
                            let clean = manager
                                .lock()
                                .unwrap_or_else(|e| {
                                    warn!("worker manager mutex poisoned during handoff, recovering");
                                    e.into_inner()
                                })
                                .drain_for_handoff();
                            let drain_secs = drain_start.elapsed().as_secs_f64();
                            lorica_api::metrics::observe_hot_upgrade_drain(drain_secs);
                            if !clean {
                                lorica_api::metrics::record_hot_upgrade(
                                    hot_upgrade::RollbackReason::DrainTimeout.metric_outcome(),
                                );
                                warn!(
                                    drain_secs,
                                    "hot upgrade: drain exceeded the window, stragglers were force-killed"
                                );
                            }
                            shutdown_task_tracker.close();
                            let _ = tokio::time::timeout(
                                Duration::from_secs(10),
                                shutdown_task_tracker.wait(),
                            )
                            .await;
                            api_handle.abort();
                            health_handle.abort();
                            lorica::otel::shutdown();
                            info!(
                                drain_secs,
                                "hot upgrade complete; exiting so the new supervisor takes over"
                            );
                            std::process::exit(0);
                        }
                        hot_upgrade::HandoffDecision::Rollback(reason) => {
                            // The new process never came up. The old one
                            // never stopped accepting, so this is seamless.
                            if let Some(child) = run.child {
                                lorica_worker::hot_upgrade::kill_and_reap(child);
                            }
                            // Abort the FD-transfer task and surface its
                            // outcome rather than silently dropping it: an
                            // error here (e.g. the socket serve failed)
                            // explains WHY the new side never connected
                            // (audit L6).
                            run.serve_task.abort();
                            match run.serve_task.await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => warn!(
                                    error = %e,
                                    "hot upgrade: FD-transfer task errored during rollback"
                                ),
                                Err(join_err) if join_err.is_cancelled() => {}
                                Err(join_err) => warn!(
                                    error = %join_err,
                                    "hot upgrade: FD-transfer task panicked during rollback"
                                ),
                            }
                            let unix_ts: u64 = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            match hot_upgrade::quarantine_failed_binary(
                                &data_dir_path,
                                &staged_path,
                                unix_ts,
                            ) {
                                Ok(dest) => info!(
                                    quarantined = %dest.display(),
                                    "hot upgrade: staged binary quarantined after failed handoff"
                                ),
                                Err(e) => warn!(
                                    error = %e,
                                    "hot upgrade: failed to quarantine staged binary"
                                ),
                            }
                            let _ = std::fs::remove_file(hot_upgrade::transfer_sock_path(&data_dir_path));
                            let _ = std::fs::remove_file(hot_upgrade::ready_sock_path(&data_dir_path));
                            let _ = std::fs::remove_file(hot_upgrade::ack_sock_path(&data_dir_path));
                            // The failed NEW supervisor already bumped the
                            // persisted takeover epoch during its boot, so
                            // under Story 9.2's "fence sessions from older
                            // epochs" rule the SURVIVING supervisor's
                            // sessions would be the ones fenced - the
                            // interlock inverting on exactly the path it
                            // exists to protect. Re-take the epoch so the
                            // survivor is newest again ("newest writer
                            // wins" is preserved: we still own the DB).
                            match store.lock().await.increment_cluster_takeover_epoch() {
                                Ok(epoch) => info!(
                                    epoch,
                                    "hot upgrade: re-took cluster takeover epoch after rollback"
                                ),
                                Err(e) => warn!(
                                    error = %e,
                                    "hot upgrade: failed to re-take cluster takeover epoch after rollback"
                                ),
                            }
                            lorica_api::metrics::record_hot_upgrade(reason.metric_outcome());
                            error!(
                                reason = reason.metric_outcome(),
                                "hot upgrade rolled back; resuming normal operation"
                            );
                            continue;
                        }
                    }
                }
            }
        }
    });
}

/// Restore WAF runtime state for the supervisor from persisted settings:
/// the IP blocklist (enable flag plus an initial Data-Shield fetch when
/// on), the disabled-rule set, and custom rules. The supervisor owns the
/// blocklist fetch; workers inherit the enable flag only.
async fn supervisor_restore_waf_state(
    store: &Arc<Mutex<ConfigStore>>,
    waf_engine: &Arc<lorica_waf::WafEngine>,
) {
    let s = store.lock().await;
    if let Ok(settings) = s.get_global_settings() {
        if settings.ip_blocklist_enabled {
            waf_engine.ip_blocklist().set_enabled(true);
            match lorica_api::waf::fetch_and_load_blocklist(waf_engine.ip_blocklist()).await {
                Ok(count) => info!(count, "supervisor: IP blocklist loaded at startup"),
                Err(e) => warn!(error = %e, "supervisor: IP blocklist initial load failed"),
            }
        }
    }
    if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
        if !disabled_ids.is_empty() {
            waf_engine.set_disabled_rules(&disabled_ids);
            info!(count = disabled_ids.len(), "supervisor: WAF disabled rules restored");
        }
    }
    if let Ok(custom_rules) = s.load_waf_custom_rules() {
        for (id, desc, cat, pattern, severity, _enabled) in &custom_rules {
            let category = cat
                .parse()
                .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
            let _ = waf_engine.add_custom_rule(*id, desc.clone(), category, pattern, *severity);
        }
        if !custom_rules.is_empty() {
            info!(count = custom_rules.len(), "supervisor: WAF custom rules restored");
        }
    }
}

/// Drive one worker's command channel: BanIp fan-out, ConfigReload,
/// heartbeat + metrics pull. One source of truth shared by the
/// initial-spawn and crash-respawn paths so the two cannot drift
/// (the respawn path previously ran a simplified copy that lacked the
/// BanIp broadcast-lag handling and the shutdown heartbeat guard).
#[allow(clippy::too_many_arguments)]
fn spawn_worker_channel_task(
    worker_id: u32,
    worker_pid: i32,
    mut channel: lorica_command::CommandChannel,
    mut ban_rx: tokio::sync::broadcast::Receiver<(String, u64)>,
    mut reload_rx: tokio::sync::broadcast::Receiver<u64>,
    hb_seq: Arc<std::sync::atomic::AtomicU64>,
    hb_shutting_down: Arc<std::sync::atomic::AtomicBool>,
    hb_metrics: Arc<lorica_api::workers::WorkerMetrics>,
    agg_metrics: Arc<lorica_api::workers::AggregatedMetrics>,
) -> tokio::task::JoinHandle<()> {
    use lorica_command::{Command, CommandType, Response};
    use std::sync::atomic::Ordering;
    tokio::spawn(async move {
                let heartbeat_interval = Duration::from_secs(5);
                let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
                heartbeat_timer.tick().await; // skip first immediate tick


                loop {
                    tokio::select! {
                        // BanIp command from supervisor's global WAF counter
                        ban_result = ban_rx.recv() => {
                            match ban_result {
                                Ok((ip, duration_s)) => {
                                    let seq = hb_seq.fetch_add(1, Ordering::Relaxed);
                                    let cmd = Command::ban_ip(
                                        seq,
                                        &ip,
                                        duration_s,
                                        lorica_api::ban::BanReason::WafCriticalRule.as_i32(),
                                    );
                                    if let Err(e) = channel.send(&cmd).await {
                                        warn!(worker_id, error = %e, "BanIp send failed");
                                        continue;
                                    }
                                    match channel.recv::<Response>().await {
                                        Ok(resp) => match resp.typed_status() {
                                            lorica_command::ResponseStatus::Ok => {
                                                info!(worker_id, ip = %ip, "worker applied BanIp");
                                            }
                                            lorica_command::ResponseStatus::Error => {
                                                error!(worker_id, message = %resp.message, "worker BanIp failed");
                                            }
                                            _ => {}
                                        },
                                        Err(e) => warn!(worker_id, error = %e, "BanIp response failed"),
                                    }
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    // Subscriber fell behind the bounded channel.
                                    // The missed bans are still in SQLite (auto-
                                    // ban logic persists before broadcasting),
                                    // and the next ConfigReload rehydrates them.
                                    warn!(
                                        worker_id,
                                        dropped = n,
                                        "BanIp broadcast lagged; missed bans will be applied via next ConfigReload"
                                    );
                                    lorica_api::metrics::inc_ban_broadcast_lagged(
                                        &worker_id.to_string(),
                                        n,
                                    );
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    break;
                                }
                            }
                        }
                        // Config reload triggered by API.
                        //
                        // Use an explicit `match` on `reload_rx.recv()` instead
                        // of the convenience `Ok(seq) = ...` pattern so that a
                        // `RecvError::Lagged(n)` is surfaced (counter + warn +
                        // catch-up reload) instead of silently disabling the
                        // branch for this select iteration. Without this, a
                        // burst > the broadcast capacity (16 today) leaves the
                        // worker on a stale config with zero log, zero metric,
                        // zero notification (audit C-2 ; mirrors the BanIp
                        // arm above).
                        reload_result = reload_rx.recv() => {
                            let seq = match reload_result {
                                Ok(s) => s,
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                    warn!(
                                        worker_id,
                                        dropped = n,
                                        "ConfigReload broadcast lagged ; issuing catch-up reload to bring worker to latest DB state"
                                    );
                                    lorica_api::metrics::inc_reload_broadcast_lagged(
                                        &worker_id.to_string(),
                                        n,
                                    );
                                    // Synthesize a single catch-up reload with
                                    // a fresh sequence number from the per-
                                    // worker counter so the seq stays unique
                                    // on this command channel.
                                    hb_seq.fetch_add(1, Ordering::Relaxed)
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                    break;
                                }
                            };
                            let cmd = Command::new(CommandType::ConfigReload, seq);
                            if let Err(e) = channel.send(&cmd).await {
                                warn!(worker_id, error = %e, "config reload send failed");
                                continue;
                            }
                            match channel.recv::<Response>().await {
                                Ok(resp) => match resp.typed_status() {
                                    lorica_command::ResponseStatus::Ok => {
                                        info!(worker_id, seq, "worker applied config reload");
                                    }
                                    lorica_command::ResponseStatus::Error => {
                                        error!(worker_id, message = %resp.message, "worker config reload failed");
                                    }
                                    lorica_command::ResponseStatus::Processing => {
                                        info!(worker_id, message = %resp.message, "worker processing config reload");
                                    }
                                    _ => {}
                                },
                                Err(e) => warn!(worker_id, error = %e, "config reload response failed"),
                            }
                        }
                        // Periodic heartbeat
                        _ = heartbeat_timer.tick() => {
                            // Skip the probe entirely once the supervisor is
                            // tearing down: workers are SIGTERM'd in the same
                            // instant, so any send would race the worker's
                            // exit and log a spurious "Broken pipe" warning.
                            if hb_shutting_down.load(std::sync::atomic::Ordering::Acquire) {
                                continue;
                            }
                            let seq = hb_seq.fetch_add(1, Ordering::Relaxed);
                            let cmd = Command::new(CommandType::Heartbeat, seq);
                            let start = Instant::now();
                            if let Err(e) = channel.send(&cmd).await {
                                warn!(worker_id, error = %e, "heartbeat send failed");
                                continue;
                            }
                            match channel.recv::<Response>().await {
                                Ok(_) => {
                                    let latency_ms = start.elapsed().as_millis() as u64;
                                    hb_metrics.record_heartbeat(worker_id, worker_pid, latency_ms).await;

                                    // Request metrics from this worker
                                    let m_seq = hb_seq.fetch_add(1, Ordering::Relaxed);
                                    let m_cmd = Command::new(CommandType::MetricsRequest, m_seq);
                                    if let Err(e) = channel.send(&m_cmd).await {
                                        warn!(worker_id, error = %e, "metrics request send failed");
                                    } else if let Ok(report) = channel.recv::<lorica_command::MetricsReport>().await {
                                        // Consume the Response::ok that follows the report
                                        let _ = channel.recv::<Response>().await;
                                        let ewma: std::collections::HashMap<String, f64> = report
                                            .ewma_entries
                                            .iter()
                                            .map(|e| (e.backend_address.clone(), e.score_us))
                                            .collect();
                                        let bans: Vec<(String, u64, u64, lorica_api::ban::BanReason)> = report
                                            .ban_entries
                                            .iter()
                                            .map(decode_ban_report_entry)
                                            .collect();
                                        let backend_conns: std::collections::HashMap<String, u64> = report
                                            .backend_conn_entries
                                            .iter()
                                            .map(|e| (e.backend_address.clone(), e.connections))
                                            .collect();
                                        let req_counts: Vec<(String, u32, u64)> = report
                                            .request_entries
                                            .iter()
                                            .map(|e| (e.route_id.clone(), e.status_code, e.count))
                                            .collect();
                                        let waf_counts: Vec<(String, String, u64)> = report
                                            .waf_entries
                                            .iter()
                                            .map(|e| (e.category.clone(), e.action.clone(), e.count))
                                            .collect();
                                        agg_metrics
                                            .update_worker(
                                                worker_id,
                                                report.cache_hits,
                                                report.cache_misses,
                                                report.active_connections,
                                                bans,
                                                ewma,
                                                backend_conns,
                                                req_counts,
                                                waf_counts,
                                            )
                                            .await;
                                        // Cross-worker generic-counter
                                        // aggregation (v1.4.0
                                        // follow-up).
                                        // Pair up the flat ["k","v","k","v",...]
                                        // list back into (String, String) label
                                        // pairs. Odd trailing entries are
                                        // silently dropped — safe default
                                        // since a truncated wire payload
                                        // just skips the affected metric.
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
                                            worker_id,
                                            &gc,
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(worker_id, error = %e, "heartbeat response failed - worker may be unresponsive");
                                }
                            }
                        }
                    }
                }
    })
}

/// Supervisor-side handler for `CommandType::RateLimitDelta`. Walks the
/// Spawn the supervisor-side RPC handler for one worker. Owns the
/// `RpcEndpoint`'s incoming half and dispatches each command type to
/// the matching `handle_*` function. On EOF (worker died), removes
/// the worker's entry from `worker_rpc_endpoints` so the config-
/// reload coordinator stops fanning out to a dead channel.
///
/// Extracted from the inline initial-spawn block (was duplicated when
/// audit C-1 added the same wiring to the worker-respawn crash branch
/// in `monitor_workers`). One source of truth for "supervisor RPC
/// loop for worker N" means the next RPC variant added to the match
/// arm is wired uniformly across initial-spawn AND respawn paths.
#[allow(clippy::too_many_arguments)]
fn spawn_supervisor_rpc_handler(
    worker_id: u32,
    rpc_fd: std::os::fd::RawFd,
    rl_registry: Arc<
        dashmap::DashMap<String, Arc<lorica_limits::token_bucket::AuthoritativeBucket>>,
    >,
    rl_policy_cache: Arc<dashmap::DashMap<String, Option<lorica_config::models::RateLimit>>>,
    store: Arc<Mutex<lorica_config::ConfigStore>>,
    verdict_cache: Arc<SupervisorVerdictCache>,
    breaker_registry: Arc<SupervisorBreakerRegistry>,
    worker_rpc_endpoints: Arc<dashmap::DashMap<u32, lorica_command::RpcEndpoint>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // SAFETY: rpc_fd is a fresh socketpair end from
        // WorkerManager::spawn_worker / restart_worker, exclusively
        // owned by this task.
        let (endpoint, mut incoming) =
            match unsafe { lorica_command::RpcEndpoint::from_raw_fd(rpc_fd) } {
                Ok(pair) => pair,
                Err(e) => {
                    error!(
                        worker_id,
                        error = %e,
                        "failed to create supervisor RpcEndpoint"
                    );
                    return;
                }
            };
        // Register for supervisor-initiated RPCs (config reload
        // coordinator, metrics pull, breaker queries).
        worker_rpc_endpoints.insert(worker_id, endpoint);
        while let Some(inc) = incoming.recv().await {
            match inc.command_type() {
                lorica_command::CommandType::RateLimitDelta => {
                    handle_rate_limit_delta(inc, &rl_registry, &rl_policy_cache, &store, worker_id)
                        .await;
                }
                lorica_command::CommandType::VerdictLookup => {
                    handle_verdict_lookup(inc, &verdict_cache).await;
                }
                lorica_command::CommandType::VerdictPush => {
                    handle_verdict_push(inc, &verdict_cache).await;
                }
                lorica_command::CommandType::BreakerQuery => {
                    handle_breaker_query(inc, &breaker_registry).await;
                }
                lorica_command::CommandType::BreakerReport => {
                    handle_breaker_report(inc, &breaker_registry).await;
                }
                other => {
                    tracing::debug!(
                        worker_id,
                        command_type = ?other,
                        "supervisor RPC: ignoring command (no handler)"
                    );
                    let _ = inc
                        .reply_error("no handler registered for this command")
                        .await;
                }
            }
        }
        // Worker died or channel EOF: drop the registered endpoint so
        // the config-reload coordinator does not try to fan out
        // commands to a dead worker.
        worker_rpc_endpoints.remove(&worker_id);
        tracing::debug!(worker_id, "supervisor RPC loop exiting");
    })
}

/// batched entries, applies each consumption to the authoritative
/// bucket for `{route_id}|{scope_key}`, and replies with a
/// `RateLimitDeltaResult` carrying the current token count per key
/// so the worker can refresh its local cache.
///
/// The `{route_id}|{scope_key}` key format is assembled by the worker
/// in `proxy_wiring.rs`; the supervisor only splits it to look up the
/// route config once per first-seen key (for capacity + refill rate).
async fn handle_rate_limit_delta(
    inc: lorica_command::IncomingCommand,
    registry: &dashmap::DashMap<String, Arc<lorica_limits::token_bucket::AuthoritativeBucket>>,
    rl_policy_cache: &dashmap::DashMap<String, Option<lorica_config::models::RateLimit>>,
    store: &Arc<Mutex<lorica_config::ConfigStore>>,
    worker_id: u32,
) {
    use lorica_command::{command, response, RateLimitDeltaResult, RateLimitSnapshot};

    let delta = match inc.command().payload.clone() {
        Some(command::Payload::RateLimitDelta(d)) => d,
        _ => {
            let _ = inc.reply_error("malformed RateLimitDelta payload").await;
            return;
        }
    };
    if delta.entries.is_empty() {
        let _ = inc
            .reply(lorica_command::Response::ok_with(
                0,
                response::Payload::RateLimitDeltaResult(RateLimitDeltaResult {
                    snapshots: Vec::new(),
                }),
            ))
            .await;
        return;
    }
    let now_ns = lorica_shmem::now_ns();
    let mut snapshots = Vec::with_capacity(delta.entries.len());
    for entry in &delta.entries {
        // Key shape: "{route_id}|{scope_key}". Peel off the route id to
        // fetch capacity/refill for a first-seen key.
        let route_id = entry.key.split('|').next().unwrap_or("");
        let bucket = match registry.get(&entry.key) {
            Some(b) => Arc::clone(b.value()),
            None => {
                // Lookup route config to seed the authoritative bucket.
                // A missing or unlimited route means any contribution
                // the worker sent is a no-op (the worker's own
                // LocalBucket should not have existed in the first
                // place, but we handle it defensively).
                //
                // Hit the per-route policy cache first so concurrent
                // RateLimitDeltas from N workers don't all serialise on
                // the `store` tokio::Mutex at first-seen time (audit
                // M-4). The cache is invalidated on every successful
                // config reload (see `invalidate_rl_policy_cache`).
                let rl_cfg = if let Some(cached) =
                    rl_policy_cache.get(route_id).map(|e| e.value().clone())
                {
                    cached
                } else {
                    let fetched = {
                        let s = store.lock().await;
                        s.get_route(route_id)
                            .ok()
                            .flatten()
                            .and_then(|r| r.rate_limit.clone())
                    };
                    rl_policy_cache.insert(route_id.to_string(), fetched.clone());
                    fetched
                };
                let Some(rl) = rl_cfg else {
                    tracing::debug!(
                        worker_id,
                        key = %entry.key,
                        "RateLimitDelta for route with no rate_limit; ignoring"
                    );
                    snapshots.push(RateLimitSnapshot {
                        key: entry.key.clone(),
                        remaining: 0,
                    });
                    continue;
                };
                let new = Arc::new(lorica_limits::token_bucket::AuthoritativeBucket::new(
                    rl.capacity,
                    rl.refill_per_sec,
                    now_ns,
                ));
                let entry_ref = registry
                    .entry(entry.key.clone())
                    .or_insert_with(|| new.clone());
                Arc::clone(entry_ref.value())
            }
        };
        let remaining = bucket.apply_delta(entry.consumed, now_ns);
        snapshots.push(RateLimitSnapshot {
            key: entry.key.clone(),
            remaining,
        });
    }
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            response::Payload::RateLimitDeltaResult(RateLimitDeltaResult { snapshots }),
        ))
        .await;
}

// ---------------------------------------------------------------------------
// Supervisor-side forward-auth verdict cache (WPAR-2).
//
// Mirrors the per-process FIFO cache that `proxy_wiring.rs` keeps for
// single-process deployments, but as an instance rather than a static.
// Worker-mode deployments route lookup/push through the pipelined RPC
// channel so every worker sees the same Allow verdicts and session
// revocation invalidates them uniformly.
// ---------------------------------------------------------------------------

const SUPERVISOR_VERDICT_CACHE_MAX_ENTRIES: usize = 16_384;

/// Triple returned by [`SupervisorVerdictCache::lookup`]: encoded
/// `Verdict`, response-header pairs, and remaining TTL in ms.
type VerdictLookupResult = (i32, Vec<(String, String)>, u64);

struct SupervisorVerdictCacheEntry {
    verdict: i32,
    response_headers: Vec<(String, String)>,
    expires_at: Instant,
}

struct SupervisorVerdictCache {
    entries: dashmap::DashMap<String, SupervisorVerdictCacheEntry>,
    order: parking_lot::Mutex<std::collections::VecDeque<String>>,
}

impl SupervisorVerdictCache {
    fn new() -> Self {
        Self {
            entries: dashmap::DashMap::with_capacity(SUPERVISOR_VERDICT_CACHE_MAX_ENTRIES),
            order: parking_lot::Mutex::new(std::collections::VecDeque::with_capacity(
                SUPERVISOR_VERDICT_CACHE_MAX_ENTRIES,
            )),
        }
    }

    fn key(route_id: &str, cookie: &str) -> String {
        let mut k = String::with_capacity(route_id.len() + 1 + cookie.len());
        k.push_str(route_id);
        k.push('\0');
        k.push_str(cookie);
        k
    }

    fn lookup(&self, route_id: &str, cookie: &str) -> Option<VerdictLookupResult> {
        let key = Self::key(route_id, cookie);
        // Fast path: clone out under the read guard, then drop the ref.
        let (verdict, response_headers, expires_at) = {
            let entry = self.entries.get(&key)?;
            (
                entry.verdict,
                entry.response_headers.clone(),
                entry.expires_at,
            )
        };
        let now = Instant::now();
        if now >= expires_at {
            // Expired: evict atomically only if the entry at `key` is
            // still the one we read. `remove_if` closes the TOCTOU noted
            // in audit M-2 - a fresh `insert` racing with this lookup
            // can no longer be evicted by a stale expiry observation.
            self.entries
                .remove_if(&key, |_, e| e.expires_at == expires_at);
            return None;
        }
        let ttl_ms = expires_at.saturating_duration_since(now).as_millis() as u64;
        Some((verdict, response_headers, ttl_ms))
    }

    fn insert(
        &self,
        route_id: &str,
        cookie: &str,
        verdict: i32,
        response_headers: Vec<(String, String)>,
        ttl_ms: u64,
    ) {
        let key = Self::key(route_id, cookie);
        let expires_at = Instant::now() + Duration::from_millis(ttl_ms);
        let prior = self.entries.insert(
            key.clone(),
            SupervisorVerdictCacheEntry {
                verdict,
                response_headers,
                expires_at,
            },
        );
        // Only push to the FIFO `order` when this insert actually
        // grew the entries map. Audit L-13 closure : a duplicate
        // verdict refresh used to push twice into `order` ; on
        // overflow `pop_front` removed the entries row even though a
        // logically-still-present duplicate sat further back in the
        // queue, the next pop became a no-op, and the effective FIFO
        // cap shrunk per duplicate. DashMap's `insert` returns the
        // previous value on overwrite ; gate the push on `is_none()`.
        if prior.is_none() {
            // FIFO bound: pop oldest keys until strictly under the cap.
            // Matches `verdict_cache_insert` in proxy_wiring.rs so
            // worker mode and single-process mode agree on memory
            // ceiling.
            let mut order = self.order.lock();
            while order.len() >= SUPERVISOR_VERDICT_CACHE_MAX_ENTRIES {
                if let Some(old) = order.pop_front() {
                    self.entries.remove(&old);
                } else {
                    break;
                }
            }
            order.push_back(key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

async fn handle_verdict_lookup(
    inc: lorica_command::IncomingCommand,
    cache: &SupervisorVerdictCache,
) {
    use lorica_command::{command, response, ForwardAuthHeader, VerdictResult};

    let lookup = match inc.command().payload.clone() {
        Some(command::Payload::VerdictLookup(l)) => l,
        _ => {
            let _ = inc.reply_error("malformed VerdictLookup payload").await;
            return;
        }
    };
    let result = match cache.lookup(&lookup.route_id, &lookup.cookie) {
        Some((verdict, headers, ttl_ms)) => VerdictResult {
            found: true,
            verdict,
            ttl_ms,
            response_headers: headers
                .into_iter()
                .map(|(n, v)| ForwardAuthHeader { name: n, value: v })
                .collect(),
        },
        None => VerdictResult {
            found: false,
            verdict: 0,
            ttl_ms: 0,
            response_headers: Vec::new(),
        },
    };
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            response::Payload::VerdictResult(result),
        ))
        .await;
}

async fn handle_verdict_push(inc: lorica_command::IncomingCommand, cache: &SupervisorVerdictCache) {
    use lorica_command::command;

    let push = match inc.command().payload.clone() {
        Some(command::Payload::VerdictPush(p)) => p,
        _ => {
            let _ = inc.reply_error("malformed VerdictPush payload").await;
            return;
        }
    };
    // Only Allow verdicts with a positive TTL are cached, matching the
    // single-process semantics. A Deny or zero-TTL push is treated as a
    // silent no-op so a worker that miscomputes the cache predicate
    // cannot poison the supervisor's cache.
    if push.ttl_ms > 0
        && lorica_command::Verdict::from_i32(push.verdict) == lorica_command::Verdict::Allow
    {
        let headers = push
            .response_headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect();
        cache.insert(
            &push.route_id,
            &push.cookie,
            push.verdict,
            headers,
            push.ttl_ms,
        );
    }
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

// ---------------------------------------------------------------------------
// Supervisor-side circuit breaker (WPAR-3).
//
// Mirrors the per-process `CircuitBreaker` kept in `proxy_wiring.rs` but
// elevated to the supervisor so admission decisions and probe slots are
// consistent across workers. Reuses the same `threshold` / `cooldown`
// shape so operator-visible behaviour is unchanged.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupervisorBreakerState {
    Closed,
    Open {
        opened_at: Instant,
    },
    /// HalfOpen grants a single probe slot. `probe_started_at` is set to
    /// `Some(Instant)` on admission and back to `None` on report. The
    /// deadlock-avoidance guarantee (audit H-1) lives here: if the
    /// probe-admitted worker crashes between admit and report, every
    /// subsequent query observes `probe_started_at.elapsed() > cooldown`
    /// and synthesises a failed-probe transition back to Open with a
    /// fresh cooldown, so the backend is never locked out forever.
    HalfOpen {
        probe_started_at: Option<Instant>,
    },
}

struct SupervisorBreakerEntry {
    state: SupervisorBreakerState,
    consecutive_failures: u32,
}

struct SupervisorBreakerRegistry {
    /// Key: `{route_id}|{backend}`
    entries: dashmap::DashMap<String, parking_lot::Mutex<SupervisorBreakerEntry>>,
    failure_threshold: u32,
    cooldown: Duration,
}

impl SupervisorBreakerRegistry {
    fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            failure_threshold,
            cooldown,
        }
    }

    fn key(route_id: &str, backend: &str) -> String {
        let mut k = String::with_capacity(route_id.len() + 1 + backend.len());
        k.push_str(route_id);
        k.push('|');
        k.push_str(backend);
        k
    }

    /// Decide admission for a `(route, backend)`. Closed = Allow; Open
    /// past cooldown = promote to HalfOpen and grant the sole probe
    /// (`AllowProbe`); HalfOpen with probe already in flight = Deny
    /// (unless the probe is stale past `cooldown`, in which case we
    /// synthesise a failed-probe transition to Open and grant a fresh
    /// probe to the caller).
    ///
    /// The stale-probe path closes audit H-1: a worker that crashes
    /// between admit and report no longer pins the breaker in
    /// HalfOpen forever.
    fn query(&self, route_id: &str, backend: &str) -> lorica_command::BreakerDecision {
        let key = Self::key(route_id, backend);
        let entry = self.entries.entry(key).or_insert_with(|| {
            parking_lot::Mutex::new(SupervisorBreakerEntry {
                state: SupervisorBreakerState::Closed,
                consecutive_failures: 0,
            })
        });
        let mut guard = entry.value().lock();
        match guard.state {
            SupervisorBreakerState::Closed => lorica_command::BreakerDecision::Allow,
            SupervisorBreakerState::Open { opened_at } => {
                if opened_at.elapsed() >= self.cooldown {
                    guard.state = SupervisorBreakerState::HalfOpen {
                        probe_started_at: Some(Instant::now()),
                    };
                    lorica_command::BreakerDecision::AllowProbe
                } else {
                    lorica_command::BreakerDecision::Deny
                }
            }
            SupervisorBreakerState::HalfOpen { probe_started_at } => {
                match probe_started_at {
                    None => {
                        // Slot is free (prior probe reported). Grant.
                        guard.state = SupervisorBreakerState::HalfOpen {
                            probe_started_at: Some(Instant::now()),
                        };
                        lorica_command::BreakerDecision::AllowProbe
                    }
                    Some(started) if started.elapsed() >= self.cooldown => {
                        // Stale probe: the admitted worker never reported
                        // back within cooldown. Treat as a failed probe
                        // so the backend isn't locked out forever (H-1).
                        // Bounce to Open with a fresh cooldown; account
                        // the miss as a failure for consistency with the
                        // HalfOpen -> Open transition path in `report`.
                        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
                        guard.state = SupervisorBreakerState::Open {
                            opened_at: Instant::now(),
                        };
                        tracing::warn!(
                            route_id,
                            backend,
                            probe_age_s = started.elapsed().as_secs(),
                            "breaker probe stale past cooldown; synthesising failed probe (audit H-1)"
                        );
                        lorica_command::BreakerDecision::Deny
                    }
                    Some(_) => lorica_command::BreakerDecision::Deny,
                }
            }
        }
    }

    /// Update breaker state after a worker reports the outcome.
    fn report(&self, route_id: &str, backend: &str, success: bool, was_probe: bool) {
        let key = Self::key(route_id, backend);
        let entry = self.entries.entry(key).or_insert_with(|| {
            parking_lot::Mutex::new(SupervisorBreakerEntry {
                state: SupervisorBreakerState::Closed,
                consecutive_failures: 0,
            })
        });
        let mut guard = entry.value().lock();
        if success {
            guard.consecutive_failures = 0;
            if was_probe
                || matches!(
                    guard.state,
                    SupervisorBreakerState::HalfOpen { .. } | SupervisorBreakerState::Open { .. }
                )
            {
                guard.state = SupervisorBreakerState::Closed;
            }
        } else {
            guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
            if guard.consecutive_failures >= self.failure_threshold {
                guard.state = SupervisorBreakerState::Open {
                    opened_at: Instant::now(),
                };
            } else if was_probe {
                // Probe failed: bounce back to Open with fresh cooldown.
                guard.state = SupervisorBreakerState::Open {
                    opened_at: Instant::now(),
                };
            }
        }
    }
}

async fn handle_breaker_query(
    inc: lorica_command::IncomingCommand,
    registry: &SupervisorBreakerRegistry,
) {
    use lorica_command::{command, response, BreakerResult};

    let q = match inc.command().payload.clone() {
        Some(command::Payload::BreakerQuery(q)) => q,
        _ => {
            let _ = inc.reply_error("malformed BreakerQuery payload").await;
            return;
        }
    };
    let decision = registry.query(&q.route_id, &q.backend);
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            response::Payload::BreakerResult(BreakerResult {
                decision: decision as i32,
            }),
        ))
        .await;
}

async fn handle_breaker_report(
    inc: lorica_command::IncomingCommand,
    registry: &SupervisorBreakerRegistry,
) {
    use lorica_command::command;

    let r = match inc.command().payload.clone() {
        Some(command::Payload::BreakerReport(r)) => r,
        _ => {
            let _ = inc.reply_error("malformed BreakerReport payload").await;
            return;
        }
    };
    registry.report(&r.route_id, &r.backend, r.success, r.was_probe);
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

// ---------------------------------------------------------------------------
// Supervisor-side two-phase config reload coordinator (WPAR-8).
//
// Replaces the legacy one-shot `CommandType::ConfigReload` with a
// Prepare (2 s timeout per worker, slow path: SQLite read + config
// build) + Commit (500 ms timeout, fast path: single ArcSwap). The
// result is that the divergence window between workers collapses
// from ~10-50 ms down to the UDS RTT between workers (microseconds).
//
// A failed Prepare aborts the whole reload — workers that did reply
// Ok to Prepare are asked to drop their pending slot via a best-effort
// Commit of the *same* generation so they don't leak a stale pending
// entry across a subsequent reload.
// ---------------------------------------------------------------------------

const CONFIG_RELOAD_PREPARE_TIMEOUT: Duration = Duration::from_secs(2);
const CONFIG_RELOAD_COMMIT_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug)]
#[allow(dead_code)] // Lists are exported via the Debug derive for ops diagnostics.
struct ConfigReloadReport {
    generation: u64,
    prepared: Vec<u32>,
    prepare_failed: Vec<(u32, String)>,
    committed: Vec<u32>,
    commit_failed: Vec<(u32, String)>,
}

async fn coordinate_config_reload(
    endpoints: &dashmap::DashMap<u32, lorica_command::RpcEndpoint>,
    generation: u64,
) -> ConfigReloadReport {
    // Snapshot the endpoint list so a worker re-registering or dying
    // mid-coordination doesn't change the set we're operating on.
    let targets: Vec<(u32, lorica_command::RpcEndpoint)> = endpoints
        .iter()
        .map(|e| (*e.key(), e.value().clone()))
        .collect();
    let mut prepared = Vec::new();
    let mut prepare_failed = Vec::new();
    let mut committed = Vec::new();
    let mut commit_failed = Vec::new();

    // Phase 1: Prepare. Per-worker timeout; concurrent dispatch.
    let prepare_futures = targets.iter().map(|(wid, ep)| {
        let payload = lorica_command::command::Payload::ConfigReloadPrepare(
            lorica_command::ConfigReloadPrepare { generation },
        );
        let ep = ep.clone();
        let wid = *wid;
        async move {
            let res = ep
                .request_rpc(
                    lorica_command::CommandType::ConfigReloadPrepare,
                    payload,
                    CONFIG_RELOAD_PREPARE_TIMEOUT,
                )
                .await;
            (wid, res)
        }
    });
    let prepare_results = futures_util::future::join_all(prepare_futures).await;
    for (wid, result) in prepare_results {
        match result {
            Ok(resp) if resp.typed_status() == lorica_command::ResponseStatus::Ok => {
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_prepare", "ok");
                prepared.push(wid);
            }
            Ok(resp) => {
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_prepare", "error");
                prepare_failed.push((wid, resp.message));
            }
            Err(e) => {
                let outcome = if matches!(e, lorica_command::ChannelError::Timeout) {
                    "timeout"
                } else {
                    "error"
                };
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_prepare", outcome);
                prepare_failed.push((wid, format!("rpc error: {e}")));
            }
        }
    }
    if !prepare_failed.is_empty() {
        warn!(
            generation,
            failed = prepare_failed.len(),
            succeeded = prepared.len(),
            "ConfigReloadPrepare failed on some workers; aborting reload"
        );
        // Best-effort drop of the pending slot on workers that did
        // Prepare successfully via the `ConfigReloadAbort` RPC (audit
        // M-7). Without this, a partial-Prepare failure leaves one
        // orphan `Arc<ProxyConfig>` per successful-Prepare worker
        // until the next reload overwrites it. Abort is advisory so
        // we ignore reply errors - the worst case (RPC timeout) is
        // exactly what we already guarded against.
        let abort_futures = prepared.iter().filter_map(|wid| {
            let ep = endpoints.get(wid).map(|e| e.value().clone())?;
            let payload = lorica_command::command::Payload::ConfigReloadAbort(
                lorica_command::ConfigReloadAbort { generation },
            );
            let wid = *wid;
            Some(async move {
                let res = ep
                    .request_rpc(
                        lorica_command::CommandType::ConfigReloadAbort,
                        payload,
                        CONFIG_RELOAD_COMMIT_TIMEOUT,
                    )
                    .await;
                let outcome = match res {
                    Ok(r) if r.typed_status() == lorica_command::ResponseStatus::Ok => "ok",
                    Ok(_) => "error",
                    Err(lorica_command::ChannelError::Timeout) => "timeout",
                    Err(_) => "error",
                };
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_abort", outcome);
                wid
            })
        });
        let _ = futures_util::future::join_all(abort_futures).await;
        return ConfigReloadReport {
            generation,
            prepared,
            prepare_failed,
            committed,
            commit_failed,
        };
    }

    // Phase 2: Commit. Smaller timeout; still concurrent.
    let commit_futures = targets.iter().map(|(wid, ep)| {
        let payload = lorica_command::command::Payload::ConfigReloadCommit(
            lorica_command::ConfigReloadCommit { generation },
        );
        let ep = ep.clone();
        let wid = *wid;
        async move {
            let res = ep
                .request_rpc(
                    lorica_command::CommandType::ConfigReloadCommit,
                    payload,
                    CONFIG_RELOAD_COMMIT_TIMEOUT,
                )
                .await;
            (wid, res)
        }
    });
    let commit_results = futures_util::future::join_all(commit_futures).await;
    for (wid, result) in commit_results {
        match result {
            Ok(resp) if resp.typed_status() == lorica_command::ResponseStatus::Ok => {
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_commit", "ok");
                committed.push(wid);
            }
            Ok(resp) => {
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_commit", "error");
                commit_failed.push((wid, resp.message));
            }
            Err(e) => {
                let outcome = if matches!(e, lorica_command::ChannelError::Timeout) {
                    "timeout"
                } else {
                    "error"
                };
                lorica_api::metrics::inc_supervisor_rpc_outcome("config_reload_commit", outcome);
                commit_failed.push((wid, format!("rpc error: {e}")));
            }
        }
    }
    info!(
        generation,
        prepared = prepared.len(),
        committed = committed.len(),
        commit_failed = commit_failed.len(),
        "config reload coordinated via pipelined RPC"
    );
    ConfigReloadReport {
        generation,
        prepared,
        prepare_failed,
        committed,
        commit_failed,
    }
}

// ---------------------------------------------------------------------------
// Supervisor-side metrics pull-on-scrape coordinator (WPAR-7).
//
// The /metrics HTTP handler invokes the refresher closure (see
// `lorica_api::server::MetricsRefresher`) before reading
// `AggregatedMetrics`. Internally, the refresher dedups concurrent
// calls and, at most once per `METRICS_PULL_DEDUP_TTL`, fans out a
// `CommandType::MetricsRequest` RPC to every registered worker with
// a per-worker timeout of `METRICS_PULL_PER_WORKER_TIMEOUT`. Non-
// responders fall back silently to the cached AggregatedMetrics
// (populated by the periodic-pull task that still runs on the
// legacy channel), so a stuck worker never blocks the scrape.
// ---------------------------------------------------------------------------

const METRICS_PULL_PER_WORKER_TIMEOUT: Duration = Duration::from_millis(500);
const METRICS_PULL_DEDUP_TTL: Duration = Duration::from_millis(250);

async fn pull_all_metrics_via_rpc(
    endpoints: Arc<dashmap::DashMap<u32, lorica_command::RpcEndpoint>>,
    aggregated: Arc<lorica_api::workers::AggregatedMetrics>,
    dedup: Arc<tokio::sync::Mutex<Option<Instant>>>,
    per_worker_timeout: Duration,
    dedup_ttl: Duration,
) {
    // Dedup: if a refresh started within `dedup_ttl`, this call is a
    // no-op. The caller will read the existing cached state which is
    // at most `dedup_ttl` old.
    {
        let mut guard = dedup.lock().await;
        if let Some(last) = *guard {
            if last.elapsed() < dedup_ttl {
                return;
            }
        }
        *guard = Some(Instant::now());
    }

    if endpoints.is_empty() {
        return;
    }

    // Snapshot endpoints so a concurrent worker insert/remove doesn't
    // skew the fan-out set.
    let targets: Vec<(u32, lorica_command::RpcEndpoint)> = endpoints
        .iter()
        .map(|e| (*e.key(), e.value().clone()))
        .collect();

    let futures = targets.into_iter().map(|(wid, ep)| {
        let cmd = lorica_command::Command::new(lorica_command::CommandType::MetricsRequest, 0);
        async move {
            let res = ep.request(cmd, per_worker_timeout).await;
            (wid, res)
        }
    });
    let results = futures_util::future::join_all(futures).await;

    for (wid, result) in results {
        match result {
            Ok(resp) => match resp.payload {
                Some(lorica_command::response::Payload::MetricsReport(report)) => {
                    lorica_api::metrics::inc_supervisor_rpc_outcome("metrics_pull", "ok");
                    let ewma: std::collections::HashMap<String, f64> = report
                        .ewma_entries
                        .iter()
                        .map(|e| (e.backend_address.clone(), e.score_us))
                        .collect();
                    let bans: Vec<(String, u64, u64, lorica_api::ban::BanReason)> = report
                        .ban_entries
                        .iter()
                        .map(|b| (b.ip.clone(), b.remaining_seconds, b.ban_duration_seconds, lorica_api::ban::BanReason::from_i32(b.reason).unwrap_or(lorica_api::ban::BanReason::WafCriticalRule)))
                        .collect();
                    let backend_conns: std::collections::HashMap<String, u64> = report
                        .backend_conn_entries
                        .iter()
                        .map(|e| (e.backend_address.clone(), e.connections))
                        .collect();
                    let req_counts: Vec<(String, u32, u64)> = report
                        .request_entries
                        .iter()
                        .map(|e| (e.route_id.clone(), e.status_code, e.count))
                        .collect();
                    let waf_counts: Vec<(String, String, u64)> = report
                        .waf_entries
                        .iter()
                        .map(|e| (e.category.clone(), e.action.clone(), e.count))
                        .collect();
                    aggregated
                        .update_worker(
                            wid,
                            report.cache_hits,
                            report.cache_misses,
                            report.active_connections,
                            bans,
                            ewma,
                            backend_conns,
                            req_counts,
                            waf_counts,
                        )
                        .await;
                    // Cross-worker counter aggregation (v1.4.0
                    // follow-up). Apply the per-worker snapshot
                    // to the supervisor's own prometheus registry
                    // so the supervisor's `/metrics` sees the
                    // union of every worker's counters for
                    // bot_challenge / geoip_block / forward_auth
                    // cache / header rule match / canary split /
                    // mirror outcome / cache predictor bypass.
                    let gc: Vec<GenericCounterRow> = report
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
                    lorica_api::metrics::apply_worker_generic_counters(wid, &gc);
                }
                _ => {
                    lorica_api::metrics::inc_supervisor_rpc_outcome("metrics_pull", "error");
                    tracing::debug!(
                        worker_id = wid,
                        "MetricsRequest RPC: response missing MetricsReport payload; keeping cached state"
                    );
                }
            },
            Err(e) => {
                let outcome = if matches!(e, lorica_command::ChannelError::Timeout) {
                    "timeout"
                } else {
                    "error"
                };
                lorica_api::metrics::inc_supervisor_rpc_outcome("metrics_pull", outcome);
                tracing::debug!(
                    worker_id = wid,
                    error = %e,
                    "MetricsRequest RPC failed; keeping cached state for this worker"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for supervisor-side RPC registries (WPAR-2 + WPAR-3).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod supervisor_tests {
    use super::*;

    #[test]
    fn decode_ban_report_entry_round_trips_reason_and_falls_back() {
        use lorica_api::ban::BanReason;
        use lorica_command::BanReportEntry;

        // Every known wire reason decodes back to its variant, with the
        // ip / remaining / duration fields carried through verbatim.
        for reason in [
            BanReason::RateLimit,
            BanReason::WafFlood,
            BanReason::WafCriticalRule,
            BanReason::Manual,
        ] {
            let entry = BanReportEntry {
                ip: "192.0.2.7".to_string(),
                remaining_seconds: 12,
                ban_duration_seconds: 60,
                reason: reason.as_i32(),
            };
            let (ip, remaining, duration, decoded) = decode_ban_report_entry(&entry);
            assert_eq!(ip, "192.0.2.7");
            assert_eq!(remaining, 12);
            assert_eq!(duration, 60);
            assert_eq!(decoded, reason);
        }

        // An unknown wire value (legacy 0 or a future reason) falls back
        // to WafCriticalRule rather than dropping the row.
        for unknown in [0, 99] {
            let entry = BanReportEntry {
                ip: "192.0.2.8".to_string(),
                remaining_seconds: 1,
                ban_duration_seconds: 2,
                reason: unknown,
            };
            let (_, _, _, decoded) = decode_ban_report_entry(&entry);
            assert_eq!(decoded, BanReason::WafCriticalRule);
        }
    }

    #[test]
    fn verdict_cache_lookup_miss_on_empty() {
        let c = SupervisorVerdictCache::new();
        assert!(c.lookup("r1", "cookie-a").is_none());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn verdict_cache_hit_round_trip() {
        let c = SupervisorVerdictCache::new();
        c.insert(
            "r1",
            "session=abc",
            lorica_command::Verdict::Allow as i32,
            vec![("Remote-User".into(), "alice".into())],
            30_000,
        );
        let (verdict, headers, ttl_ms) = c.lookup("r1", "session=abc").expect("hit");
        assert_eq!(verdict, lorica_command::Verdict::Allow as i32);
        assert_eq!(headers, vec![("Remote-User".into(), "alice".into())]);
        assert!(ttl_ms > 29_000 && ttl_ms <= 30_000);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn verdict_cache_miss_on_expired_entry() {
        let c = SupervisorVerdictCache::new();
        c.insert(
            "r1",
            "cookie",
            lorica_command::Verdict::Allow as i32,
            Vec::new(),
            1,
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(c.lookup("r1", "cookie").is_none());
        // Lazy eviction on lookup: expired entry removed.
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn verdict_cache_partitions_by_route() {
        let c = SupervisorVerdictCache::new();
        c.insert(
            "route-a",
            "c",
            lorica_command::Verdict::Allow as i32,
            Vec::new(),
            30_000,
        );
        assert!(c.lookup("route-a", "c").is_some());
        assert!(c.lookup("route-b", "c").is_none());
    }

    #[test]
    fn breaker_registry_defaults_to_allow() {
        let r = SupervisorBreakerRegistry::new(5, Duration::from_secs(10));
        assert_eq!(
            r.query("r", "10.0.0.1:80"),
            lorica_command::BreakerDecision::Allow
        );
    }

    #[test]
    fn breaker_registry_opens_after_threshold() {
        let r = SupervisorBreakerRegistry::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            r.report("r", "b", false, false);
        }
        assert_eq!(r.query("r", "b"), lorica_command::BreakerDecision::Deny);
    }

    #[test]
    fn breaker_registry_success_resets_failures() {
        let r = SupervisorBreakerRegistry::new(3, Duration::from_secs(60));
        r.report("r", "b", false, false);
        r.report("r", "b", false, false);
        r.report("r", "b", true, false);
        r.report("r", "b", false, false);
        r.report("r", "b", false, false);
        assert_eq!(r.query("r", "b"), lorica_command::BreakerDecision::Allow);
    }

    #[test]
    fn breaker_registry_half_open_probe_single_slot() {
        let r = SupervisorBreakerRegistry::new(1, Duration::from_millis(0));
        r.report("r", "b", false, false);
        // First query after cooldown moves to HalfOpen and grants probe.
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::AllowProbe
        );
        // Second concurrent query is denied (slot already held).
        assert_eq!(r.query("r", "b"), lorica_command::BreakerDecision::Deny);
    }

    #[test]
    fn breaker_registry_probe_success_closes() {
        let r = SupervisorBreakerRegistry::new(1, Duration::from_millis(0));
        r.report("r", "b", false, false);
        let d = r.query("r", "b");
        assert_eq!(d, lorica_command::BreakerDecision::AllowProbe);
        r.report("r", "b", true, true);
        assert_eq!(r.query("r", "b"), lorica_command::BreakerDecision::Allow);
    }

    #[test]
    fn breaker_registry_probe_failure_reopens() {
        let r = SupervisorBreakerRegistry::new(5, Duration::from_millis(0));
        // Hit the threshold to open.
        for _ in 0..5 {
            r.report("r", "b", false, false);
        }
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::AllowProbe
        );
        // Probe fails: breaker re-opens.
        r.report("r", "b", false, true);
        // Still Open immediately (cooldown=0 means next query admits a fresh probe).
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::AllowProbe
        );
    }

    #[test]
    fn breaker_registry_stale_probe_recovers_after_cooldown() {
        // Audit H-1: if the probe-admitted worker crashes between admit
        // and report, the breaker must not lock the backend out forever.
        // After `cooldown` elapses past probe_started_at, the next query
        // synthesises a failed probe and transitions back to Open.
        let cooldown = Duration::from_millis(40);
        let r = SupervisorBreakerRegistry::new(1, cooldown);
        r.report("r", "b", false, false); // state: Open at t0

        // Wait past the initial cooldown so Open promotes to HalfOpen.
        std::thread::sleep(cooldown + Duration::from_millis(10));
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::AllowProbe,
            "first admission past cooldown grants probe"
        );
        // Worker "crashes" - no report arrives.

        // Concurrent query within cooldown of the probe: denied.
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::Deny,
            "second query within probe cooldown is denied"
        );

        // Wait past cooldown from probe_started_at. Next query
        // synthesises the failed probe: state -> Open with a fresh
        // opened_at, returns Deny (fresh cooldown starts now).
        std::thread::sleep(cooldown + Duration::from_millis(10));
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::Deny,
            "stale-probe detection path: synthesises failed probe and returns Deny"
        );

        // Wait past the fresh cooldown.
        std::thread::sleep(cooldown + Duration::from_millis(10));
        assert_eq!(
            r.query("r", "b"),
            lorica_command::BreakerDecision::AllowProbe,
            "backend admits a fresh probe; if this fails the breaker has stuck (audit H-1)"
        );
    }

    #[test]
    fn breaker_registry_isolates_routes_sharing_backend() {
        let r = SupervisorBreakerRegistry::new(1, Duration::from_secs(60));
        r.report("route-a", "b", false, false);
        assert_eq!(
            r.query("route-a", "b"),
            lorica_command::BreakerDecision::Deny
        );
        assert_eq!(
            r.query("route-b", "b"),
            lorica_command::BreakerDecision::Allow
        );
    }
}
