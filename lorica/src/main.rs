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

mod health;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use chrono::Datelike;
use clap::{Parser, Subcommand};
use lorica_api::logs::LogBuffer;
use lorica_api::middleware::auth::SessionStore;
use lorica_api::middleware::rate_limit::RateLimiter;
use lorica_api::server::AppState;
use lorica_api::system::SystemCache;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use lorica::proxy_wiring::{LoricaProxy, ProxyConfig};
use lorica::reload::reload_proxy_config;

const DEFAULT_DATA_DIR: &str = "/var/lib/lorica";

const DEFAULT_MANAGEMENT_PORT: u16 = 9443;
const DEFAULT_HTTP_PORT: u16 = 8080;
const DEFAULT_HTTPS_PORT: u16 = 8443;

#[derive(Parser, Debug)]
#[command(
    name = "lorica",
    version,
    about = "A modern, secure, dashboard-first reverse proxy built in Rust."
)]
struct Cli {
    /// Data directory for configuration state and database
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log format: "json" (default) or "text"
    #[arg(long, default_value = "json", value_parser = clap::builder::PossibleValuesParser::new(["json", "text"]))]
    log_format: String,

    /// Path to a log file. When set, logs are written to this file in
    /// addition to stdout. The file is appended to (not truncated).
    #[arg(long)]
    log_file: Option<String>,

    /// Management port (localhost only)
    #[arg(long, default_value_t = DEFAULT_MANAGEMENT_PORT)]
    management_port: u16,

    /// HTTP proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTP_PORT)]
    http_port: u16,

    /// HTTPS proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTPS_PORT)]
    https_port: u16,

    /// Path to a CRL (Certificate Revocation List) file in PEM or DER format.
    /// When set, upstream server certificates are checked against this CRL.
    /// Requires a service restart after updating the CRL file.
    #[arg(long)]
    upstream_crl_file: Option<String>,

    /// Number of worker processes (default: number of CPU cores, 0 = single-process mode)
    #[arg(long, default_value_t = 0)]
    workers: usize,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as a worker process (internal - launched by supervisor)
    Worker {
        /// Worker ID assigned by the supervisor
        #[arg(long)]
        id: u32,

        /// File descriptor for the command socketpair (receives listen FDs)
        #[arg(long)]
        cmd_fd: i32,

        /// Data directory path
        #[arg(long)]
        data_dir: String,

        /// HTTPS port (0 = no TLS)
        #[arg(long, default_value = "0")]
        https_port: u16,

        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Log format (json or text)
        #[arg(long, default_value = "json", value_parser = clap::builder::PossibleValuesParser::new(["json", "text"]))]
        log_format: String,

        /// Log file path
        #[arg(long)]
        log_file: Option<String>,

        /// Path to upstream CRL file (passed from supervisor)
        #[arg(long)]
        upstream_crl_file: Option<String>,
    },
    /// Rotate the encryption key (re-encrypts all secrets in the database)
    RotateKey {
        /// Path to the new encryption key file (32 bytes, generated if missing)
        #[arg(long)]
        new_key_file: String,
    },
    /// Remove an IP from the auto-ban list
    Unban {
        /// IP address to unban
        ip: String,

        /// Admin username
        #[arg(long, default_value = "admin")]
        user: String,

        /// Admin password
        #[arg(long)]
        password: String,
    },
}

/// Guard that must be held alive for the non-blocking file appender to flush.
/// Stored in main() to keep it alive for the process lifetime.
#[allow(dead_code)]
static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    std::sync::OnceLock::new();

fn init_logging(log_level: &str, log_format: &str, log_file: Option<&str>) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Build the writer: file (non-blocking, thread-safe) or stdout.
    macro_rules! build_subscriber {
        ($writer:expr, $ansi:expr) => {
            if log_format == "text" {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime)
                    .with_ansi($ansi)
                    .with_writer($writer)
                    .init();
            } else {
                tracing_subscriber::fmt()
                    .json()
                    .with_env_filter(filter)
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_timer(tracing_subscriber::fmt::time::SystemTime)
                    .with_writer($writer)
                    .init();
            }
        };
    }

    if let Some(path) = log_file {
        let dir = std::path::Path::new(path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("lorica.log");
        let file_appender = tracing_appender::rolling::never(dir, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        let _ = LOG_GUARD.set(guard);
        build_subscriber!(non_blocking, false);
    } else {
        build_subscriber!(std::io::stdout, true);
    }
}

fn startup_banner(cli: &Cli) {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        data_dir = %cli.data_dir,
        management_port = cli.management_port,
        http_port = cli.http_port,
        https_port = cli.https_port,
        workers = cli.workers,
        "Lorica reverse proxy starting"
    );
}

fn main() {
    // Explicitly set ring as the default TLS crypto provider. Ignore the
    // error if a provider was already installed (e.g. by a linked library),
    // since that is also valid.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Worker {
            id,
            cmd_fd,
            data_dir,
            https_port,
            log_level,
            log_format,
            log_file,
            upstream_crl_file,
        }) => {
            init_logging(&log_level, &log_format, log_file.as_deref());
            run_worker(
                id,
                cmd_fd,
                &data_dir,
                https_port,
                upstream_crl_file.as_deref(),
            );
        }
        Some(Commands::RotateKey { new_key_file }) => {
            use lorica_config::crypto::EncryptionKey;
            use lorica_config::store::ConfigStore;

            let data_dir = PathBuf::from(&cli.data_dir);
            let key_path = data_dir.join("encryption.key");
            let old_key = EncryptionKey::load_or_create(&key_path)
                .expect("failed to load current encryption key");

            let new_key_path = PathBuf::from(&new_key_file);
            let new_key = EncryptionKey::load_or_create(&new_key_path)
                .expect("failed to load/create new encryption key");

            let db_path = data_dir.join("lorica.db");
            let store =
                ConfigStore::open(&db_path, Some(old_key)).expect("failed to open database");

            let count = store
                .rotate_encryption_key(&new_key)
                .expect("key rotation failed");

            println!("Key rotation complete: {count} secrets re-encrypted");
            println!(
                "IMPORTANT: Replace {} with {}",
                key_path.display(),
                new_key_path.display()
            );
            println!("  mv {} {}.backup", key_path.display(), key_path.display());
            println!("  mv {} {}", new_key_path.display(), key_path.display());
        }
        Some(Commands::Unban { ip, user, password }) => {
            let port = cli.management_port;
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async {
                let client = reqwest::Client::builder()
                    .danger_accept_invalid_certs(true)
                    .cookie_store(true)
                    .build()
                    .expect("HTTP client");

                // Login
                let login_url = format!("https://127.0.0.1:{port}/api/v1/auth/login");
                let login_res = client
                    .post(&login_url)
                    .json(&serde_json::json!({ "username": user, "password": password }))
                    .send()
                    .await;
                match login_res {
                    Ok(r) if r.status().is_success() => {}
                    Ok(r) => {
                        eprintln!("Login failed ({}). Check credentials.", r.status());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Cannot connect to management API on port {port}: {e}");
                        std::process::exit(1);
                    }
                }

                // Unban
                let unban_url = format!("https://127.0.0.1:{port}/api/v1/bans/{ip}");
                match client.delete(&unban_url).send().await {
                    Ok(r) if r.status().is_success() => {
                        println!("IP {ip} unbanned successfully.");
                    }
                    Ok(r) => {
                        let body = r.text().await.unwrap_or_default();
                        eprintln!("Unban failed: {body}");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Unban request failed: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }
        None => {
            init_logging(&cli.log_level, &cli.log_format, cli.log_file.as_deref());
            startup_banner(&cli);

            if cli.workers > 0 {
                run_supervisor(cli);
                return;
            }

            // Single-process mode (workers=0 or non-Unix)
            run_single_process(cli);
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor mode (Unix only): forks workers, runs API server, monitors workers
// ---------------------------------------------------------------------------

fn run_supervisor(cli: Cli) {
    use lorica_command::{Command, CommandChannel, CommandType, Response};
    use lorica_worker::manager::{WorkerConfig, WorkerEvent, WorkerManager};
    use std::os::fd::{IntoRawFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use tokio::sync::broadcast;

    let worker_count = if cli.workers == 0 {
        WorkerConfig::default_worker_count()
    } else {
        cli.workers
    };

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
        if let Err(e) = ConfigStore::open(&db_path, encryption_key) {
            error!(error = %e, "failed to run database migrations before forking workers");
            std::process::exit(1);
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
    if let Err(e) = manager.start() {
        error!(error = %e, "failed to start worker processes");
        std::process::exit(1);
    }
    // The supervisor keeps the fd alive (via `shmem_fd`) for the
    // eviction task and any later supervisor-side reads/writes.

    info!(
        worker_count = manager.worker_count(),
        "all workers spawned, starting supervisor services"
    );

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
            Ok(Some(password)) => {
                println!();
                println!("  ===================================================");
                println!("  Initial admin password: {password}");
                println!("  Login at http://localhost:{}/", cli.management_port);
                println!("  You will be asked to change it on first login.");
                println!("  ===================================================");
                println!();
                info!("admin user created (first run)");
            }
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
                                            sink.push(entry).await;
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
        tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                let seq = bridge_seq.fetch_add(1, Ordering::Relaxed);
                // Two-phase RPC reload (WPAR-8) when any worker has a
                // registered endpoint.
                if !endpoints_for_reload.is_empty() {
                    let gen = reload_generation_clone
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    let report = coordinate_config_reload(&endpoints_for_reload, gen).await;
                    if !report.prepare_failed.is_empty() || !report.commit_failed.is_empty() {
                        warn!(
                            seq,
                            generation = report.generation,
                            prepare_failed = report.prepare_failed.len(),
                            commit_failed = report.commit_failed.len(),
                            "two-phase config reload had failures; falling back to legacy broadcast"
                        );
                        let _ = reload_bc_tx_clone.send(seq);
                    }
                } else {
                    // No workers with RPC (e.g. --workers 0 or before
                    // any worker registered). Fall back to legacy
                    // per-worker broadcast which also fires the SIGHUP
                    // path for single-process mode.
                    let _ = reload_bc_tx_clone.send(seq);
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

        // Spawn a per-worker task that handles both config reload and heartbeat
        // No shared Mutex - each worker has its own channel and task
        for (worker_id, worker_pid, raw_fd, rpc_raw_fd) in worker_fds {
            // SAFETY: raw_fd is a valid file descriptor from the socketpair
            // created by WorkerManager::spawn_workers(), passed to this task
            // immediately after fork. The fd is exclusively owned by this task.
            let mut channel = match unsafe { CommandChannel::from_raw_fd(raw_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(worker_id, error = %e, "failed to create command channel");
                    continue;
                }
            };
            let mut reload_rx = reload_bc_tx.subscribe();
            let mut ban_rx = ban_bc_tx.subscribe();
            let hb_seq = Arc::clone(&sequence);
            let hb_metrics = Arc::clone(&worker_metrics);
            let agg_metrics = Arc::clone(&aggregated_metrics);

            // Pipelined RPC channel task: consumes the per-worker
            // RpcEndpoint stream and handles `RateLimitDelta` by applying
            // each entry to the authoritative bucket registry. Spawned
            // alongside the legacy channel task; dies with the worker.
            {
                let rpc_fd = rpc_raw_fd;
                let registry = Arc::clone(&rl_registry);
                let store_for_rpc = Arc::clone(&store);
                let vcache = Arc::clone(&verdict_cache);
                let breakers = Arc::clone(&breaker_registry);
                let endpoints = Arc::clone(&worker_rpc_endpoints);
                tokio::spawn(async move {
                    // SAFETY: rpc_fd is a valid socketpair end from
                    // WorkerManager::spawn_worker, exclusively owned by
                    // this task.
                    let (endpoint, mut incoming) = match unsafe {
                        lorica_command::RpcEndpoint::from_raw_fd(rpc_fd)
                    } {
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
                    // Register for supervisor-initiated RPCs (config
                    // reload coordinator, future metrics pull).
                    endpoints.insert(worker_id, endpoint);
                    while let Some(inc) = incoming.recv().await {
                        match inc.command_type() {
                            lorica_command::CommandType::RateLimitDelta => {
                                handle_rate_limit_delta(
                                    inc,
                                    &registry,
                                    &store_for_rpc,
                                    worker_id,
                                )
                                .await;
                            }
                            lorica_command::CommandType::VerdictLookup => {
                                handle_verdict_lookup(inc, &vcache).await;
                            }
                            lorica_command::CommandType::VerdictPush => {
                                handle_verdict_push(inc, &vcache).await;
                            }
                            lorica_command::CommandType::BreakerQuery => {
                                handle_breaker_query(inc, &breakers).await;
                            }
                            lorica_command::CommandType::BreakerReport => {
                                handle_breaker_report(inc, &breakers).await;
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
                    // Worker died or channel EOF: drop the registered
                    // endpoint so the config-reload coordinator does
                    // not try to fan out commands to a dead worker.
                    endpoints.remove(&worker_id);
                    tracing::debug!(worker_id, "supervisor RPC loop exiting");
                });
            }

            let handle = tokio::spawn(async move {
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
                                    let cmd = Command::ban_ip(seq, &ip, duration_s);
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
                        // Config reload triggered by API
                        Ok(seq) = reload_rx.recv() => {
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
                                        let bans: Vec<(String, u64, u64)> = report
                                            .ban_entries
                                            .iter()
                                            .map(|b| (b.ip.clone(), b.remaining_seconds, b.ban_duration_seconds))
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
                                    }
                                }
                                Err(e) => {
                                    warn!(worker_id, error = %e, "heartbeat response failed - worker may be unresponsive");
                                }
                            }
                        }
                    }
                }
            });
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

        // Start health check background task (runs in supervisor, not workers)
        let health_alert_sender = alert_sender.clone();
        let health_store = Arc::clone(&store);
        let health_config = Arc::clone(&proxy_config);
        let health_reload_tx = reload_bc_tx.clone();
        let health_interval = {
            let s = store.lock().await;
            s.get_global_settings()
                .map(|gs| gs.default_health_check_interval_s as u64)
                .unwrap_or(10)
        };
        let health_handle = tokio::spawn(async move {
            // No backend_connections in supervisor - drain monitoring is per-worker
            health::health_check_loop(health_store, health_config, health_interval, None, Some(health_alert_sender), Some(health_reload_tx)).await;
        });

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

        // Restore WAF state from persisted settings
        {
            let s = store.lock().await;
            if let Ok(settings) = s.get_global_settings() {
                if settings.ip_blocklist_enabled {
                    waf_engine.ip_blocklist().set_enabled(true);
                    // Fetch blocklist immediately at startup
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
                    let category = cat.parse().unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
                    let _ = waf_engine.add_custom_rule(*id, desc.clone(), category, pattern, *severity);
                }
                if !custom_rules.is_empty() {
                    info!(count = custom_rules.len(), "supervisor: WAF custom rules restored");
                }
            }
        }

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

        // Create notification dispatcher from DB configs
        let notify_dispatcher = {
            let s = store.lock().await;
            build_notify_dispatcher(&s)
        };
        let notify_dispatcher = Arc::new(tokio::sync::Mutex::new(notify_dispatcher));

        // Bridge: alert_sender (broadcast) -> NotifyDispatcher (async dispatch) + DB persistence
        let _alert_dispatcher = spawn_persisted_alert_dispatcher(
            &alert_sender,
            Arc::clone(&notify_dispatcher),
            log_store.clone(),
        );

        // Bug 2 fix: Start probe scheduler in supervisor mode
        let probe_store = Arc::clone(&store);
        let probe_scheduler = Arc::new(lorica_bench::ProbeScheduler::new(
            probe_store,
            Some(Arc::clone(&notify_dispatcher)),
        ));
        probe_scheduler.reload().await;

        // Bug 4 fix: Create SLA collector in supervisor and start flush task
        let sla_collector = Arc::new(lorica_bench::SlaCollector::new());
        {
            let s = store.lock().await;
            sla_collector.load_configs(&s);
        }
        sla_collector.start_flush_task(Arc::clone(&store), Some(Arc::clone(&notify_dispatcher)));

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
                    let new_dispatcher = build_notify_dispatcher(&s);
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
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store,
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                http_port: cli.http_port,
                https_port: cli.https_port,
                config_reload_tx: Some(config_reload_tx),
                worker_metrics: Some(api_worker_metrics),
                waf_event_buffer: Some(waf_event_buffer),
                waf_engine: Some(waf_engine),
                waf_rule_count: Some(waf_rule_count),
                acme_challenge_store: Some(lorica_api::acme::AcmeChallengeStore::with_db_path(api_db_path)),
                pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
                sla_collector: Some(Arc::clone(&sla_collector)),
                load_test_engine: Some(Arc::new(lorica_bench::LoadTestEngine::new())),
                // cache/ban are per-worker process; aggregated via command channel
                cache_hits: None,
                cache_misses: None,
                ban_list: None,
                cache_backend: None,
                ewma_scores: None,
                backend_connections: None,
                aggregated_metrics: Some(api_aggregated_metrics),
                metrics_refresher: Some(api_metrics_refresher),
                notification_history: {
                    let d = notify_dispatcher.lock().await;
                    Some(d.history())
                },
                log_store: api_log_store,
                task_tracker: api_task_tracker,
            };
            let session_store = SessionStore::new(Arc::clone(&state.store))
                .await
                .with_task_tracker(state.task_tracker.clone());
            let rate_limiter = RateLimiter::new();

            if let Err(e) =
                lorica_api::server::start_server(management_port, state, session_store, rate_limiter)
                    .await
            {
                error!(error = %e, "API server exited with error");
            }
        });

        if let Some(ref retention_store) = log_store {
            let retention_log_store = Arc::clone(retention_store);
            let retention_config_store = Arc::clone(&store);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                let mut last_sla_purge_day: u32 = 0;
                loop {
                    interval.tick().await;
                    let retention = {
                        let s = retention_config_store.lock().await;
                        s.get_global_settings()
                            .map(|gs| gs.access_log_retention)
                            .unwrap_or(100_000)
                    };
                    if retention > 0 {
                        if let Err(e) = retention_log_store.enforce_retention(retention as u64) {
                            tracing::warn!(error = %e, "access log retention cleanup failed");
                        }
                    }
                    {
                        let s = retention_config_store.lock().await;
                        if let Err(e) = s.purge_probe_results(1000) {
                            tracing::warn!(error = %e, "probe result retention cleanup failed");
                        }
                    }
                    if let Err(e) = retention_log_store.enforce_waf_retention(100_000) {
                        tracing::warn!(error = %e, "WAF event retention cleanup failed");
                    }
                    last_sla_purge_day =
                        run_sla_purge(&retention_config_store, last_sla_purge_day).await;
                }
            });
        }

        // Worker monitoring loop (crash detection and restart with backoff)
        let manager = Arc::new(std::sync::Mutex::new(manager));
        let monitor_mgr = Arc::clone(&manager);
        let monitor_reload_tx = reload_bc_tx.clone();
        let monitor_ban_tx = ban_bc_tx.clone();
        let monitor_seq = Arc::clone(&sequence);
        let monitor_hb_metrics = Arc::clone(&worker_metrics);
        let monitor_agg_metrics = Arc::clone(&aggregated_metrics);
        let monitor_task_handles = Arc::clone(&worker_task_handles);
        let monitor_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;

                let mut mgr = monitor_mgr.lock().unwrap_or_else(|e| {
                    warn!("worker monitor mutex poisoned, recovering");
                    e.into_inner()
                });
                let events = mgr.check_workers();
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

                    match mgr.restart_worker(id) {
                        Ok(Some(new_fd)) => {
                            // Get the new PID for metrics reporting
                            let new_pid = mgr
                                .worker_pids()
                                .iter()
                                .find(|(wid, _)| *wid == id)
                                .map(|(_, pid)| pid.as_raw())
                                .unwrap_or(0);
                            info!(worker_id = id, new_pid, reason = log_msg, "worker restarted, reconnecting channel");
                            // SAFETY: new_fd is a fresh socketpair fd from
                            // WorkerManager::restart_worker(), exclusively owned here.
                            match unsafe { CommandChannel::from_raw_fd(new_fd.into_raw_fd()) } {
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
                                                Ok(s) = rx.recv() => {
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
        });

        // Wait for shutdown signal
        shutdown_signal().await;

        info!("supervisor shutting down");
        // Explicit SIGTERM to all workers before exiting
        manager
            .lock()
            .unwrap_or_else(|e| {
                warn!("worker manager mutex poisoned during shutdown, recovering");
                e.into_inner()
            })
            .shutdown_all();
        // Drain tracked background tasks (ACME polling, session-store
        // writes, WAF refresh, backend drain watchdog). Bounded to 10 s
        // so a hung task cannot delay shutdown indefinitely; systemd
        // TimeoutStopSec will SIGKILL us past that anyway.
        shutdown_task_tracker.close();
        if tokio::time::timeout(Duration::from_secs(10), shutdown_task_tracker.wait())
            .await
            .is_err()
        {
            warn!("some background tasks did not finish within drain timeout; aborting");
        }
        api_handle.abort();
        health_handle.abort();
        monitor_handle.abort();
    });
}

/// Supervisor-side handler for `CommandType::RateLimitDelta`. Walks the
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
                let rl_cfg = {
                    let s = store.lock().await;
                    s.get_route(route_id)
                        .ok()
                        .flatten()
                        .and_then(|r| r.rate_limit.clone())
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
        let result = {
            let entry = self.entries.get(&key)?;
            let now = Instant::now();
            if now >= entry.expires_at {
                None
            } else {
                let ttl_ms = entry.expires_at.saturating_duration_since(now).as_millis() as u64;
                Some((entry.verdict, entry.response_headers.clone(), ttl_ms))
            }
        };
        if result.is_none() {
            self.entries.remove(&key);
        }
        result
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
        // FIFO bound: pop oldest keys until strictly under the cap.
        // Matches `verdict_cache_insert` in proxy_wiring.rs so worker
        // mode and single-process mode agree on memory ceiling.
        let mut order = self.order.lock();
        while order.len() >= SUPERVISOR_VERDICT_CACHE_MAX_ENTRIES {
            if let Some(old) = order.pop_front() {
                self.entries.remove(&old);
            } else {
                break;
            }
        }
        order.push_back(key.clone());
        drop(order);
        let expires_at = Instant::now() + Duration::from_millis(ttl_ms);
        self.entries.insert(
            key,
            SupervisorVerdictCacheEntry {
                verdict,
                response_headers,
                expires_at,
            },
        );
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

async fn handle_verdict_push(
    inc: lorica_command::IncomingCommand,
    cache: &SupervisorVerdictCache,
) {
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
    if push.ttl_ms > 0 && lorica_command::Verdict::from_i32(push.verdict) == lorica_command::Verdict::Allow {
        let headers = push
            .response_headers
            .into_iter()
            .map(|h| (h.name, h.value))
            .collect();
        cache.insert(&push.route_id, &push.cookie, push.verdict, headers, push.ttl_ms);
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
    Open { opened_at: Instant },
    HalfOpen { probe_in_flight: bool },
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
    /// (`AllowProbe`); HalfOpen with probe already in flight = Deny;
    /// Open within cooldown = Deny.
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
                        probe_in_flight: true,
                    };
                    lorica_command::BreakerDecision::AllowProbe
                } else {
                    lorica_command::BreakerDecision::Deny
                }
            }
            SupervisorBreakerState::HalfOpen { probe_in_flight } => {
                if probe_in_flight {
                    lorica_command::BreakerDecision::Deny
                } else {
                    guard.state = SupervisorBreakerState::HalfOpen {
                        probe_in_flight: true,
                    };
                    lorica_command::BreakerDecision::AllowProbe
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
                prepared.push(wid);
            }
            Ok(resp) => {
                prepare_failed.push((wid, resp.message));
            }
            Err(e) => {
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
        // Prepare successfully: issue a Commit for `generation` so the
        // slot gets swapped-in on those workers. This keeps the
        // workers consistent with the partial failure semantics the
        // operator expects: either every worker picks up the new
        // config or the reload fails loudly. We *could* instead send
        // a dedicated Abort RPC, but there's no meaningful difference
        // to operators between "some workers are running the new
        // config" and "none are" - both require a retry anyway, and
        // the simpler wire format is a single command type.
        //
        // For now we leave the pending entries in place on the
        // successful workers; a follow-up reload will overwrite them
        // with a fresher generation, and the GenerationGate rejects
        // commits for older generations so stale pending cannot be
        // committed by accident.
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
                committed.push(wid);
            }
            Ok(resp) => {
                commit_failed.push((wid, resp.message));
            }
            Err(e) => {
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
        let cmd =
            lorica_command::Command::new(lorica_command::CommandType::MetricsRequest, 0);
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
                    let ewma: std::collections::HashMap<String, f64> = report
                        .ewma_entries
                        .iter()
                        .map(|e| (e.backend_address.clone(), e.score_us))
                        .collect();
                    let bans: Vec<(String, u64, u64)> = report
                        .ban_entries
                        .iter()
                        .map(|b| (b.ip.clone(), b.remaining_seconds, b.ban_duration_seconds))
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
                }
                _ => {
                    tracing::debug!(
                        worker_id = wid,
                        "MetricsRequest RPC: response missing MetricsReport payload; keeping cached state"
                    );
                }
            },
            Err(e) => {
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
// Worker mode (Unix only): receives FDs from supervisor, runs proxy engine
// ---------------------------------------------------------------------------

fn run_worker(
    id: u32,
    cmd_fd: i32,
    data_dir: &str,
    https_port: u16,
    upstream_crl_file: Option<&str>,
) {
    use lorica_command::{Command, CommandChannel, CommandType, Response};
    use lorica_core::server::Fds;
    use lorica_worker::fd_passing;

    info!(worker_id = id, cmd_fd = cmd_fd, "worker starting");

    // Receive typed FDs from supervisor via SCM_RIGHTS. Listener entries
    // register with the Fds table; a `Shmem` entry (if present) is
    // adopted via `lorica_shmem::SharedRegion::open_worker`.
    let entries = match fd_passing::recv_worker_fds(cmd_fd) {
        Ok(entries) => entries,
        Err(e) => {
            error!(error = %e, "worker failed to receive FDs");
            std::process::exit(1);
        }
    };

    let mut fds = Fds::new();
    let mut listener_addrs: Vec<String> = Vec::new();
    let mut shmem_region: Option<&'static lorica_shmem::SharedRegion> = None;
    let mut rpc_fd: Option<i32> = None;
    let mut listener_count = 0usize;
    for entry in entries {
        match entry.kind {
            fd_passing::FdKind::Listener { addr } => {
                fds.add(addr.clone(), entry.fd);
                listener_addrs.push(addr.clone());
                listener_count += 1;
                info!(worker_id = id, addr = %addr, fd = entry.fd, "registered listener FD");
            }
            fd_passing::FdKind::Shmem => {
                match unsafe { lorica_shmem::SharedRegion::open_worker(entry.fd) } {
                    Ok(region) => {
                        shmem_region = Some(region);
                        info!(worker_id = id, fd = entry.fd, "adopted shmem region");
                    }
                    Err(e) => {
                        error!(worker_id = id, error = %e, "worker failed to open shmem region");
                        std::process::exit(1);
                    }
                }
            }
            fd_passing::FdKind::Rpc => {
                rpc_fd = Some(entry.fd);
                info!(worker_id = id, fd = entry.fd, "adopted RPC channel FD");
            }
        }
    }

    info!(
        worker_id = id,
        listener_count,
        shmem = shmem_region.is_some(),
        rpc = rpc_fd.is_some(),
        "received worker FDs"
    );

    // Open the configuration database with encryption key
    let data_dir = PathBuf::from(data_dir);
    let key_path = data_dir.join("encryption.key");
    let encryption_key = match lorica_config::crypto::EncryptionKey::load_or_create(&key_path) {
        Ok(key) => Some(key),
        Err(e) => {
            error!(
                error = %e,
                path = %key_path.display(),
                "worker: failed to load encryption key - database opens WITHOUT encryption"
            );
            None
        }
    };
    let db_path = data_dir.join("lorica.db");
    let store = match ConfigStore::open(&db_path, encryption_key) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "worker failed to open database");
            std::process::exit(1);
        }
    };

    let store = Arc::new(Mutex::new(store));
    let log_buffer = Arc::new(LogBuffer::new(10_000));
    let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
    // Listener-level connection filter with hot-reloadable CIDR policy.
    // The supervisor broadcasts settings changes via the command channel; the
    // filter is refreshed inline with ProxyConfig so listener state never
    // drifts from the rest of the configuration.
    let connection_filter = Arc::new(lorica::connection_filter::GlobalConnectionFilter::empty());

    // Load initial proxy configuration
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = reload_proxy_config(&store, &proxy_config, Some(&connection_filter)).await {
            error!(error = %e, "worker failed to load proxy configuration");
            std::process::exit(1);
        }
    });

    // Build CertResolver for TLS termination in worker
    let cert_resolver = Arc::new(lorica_tls::cert_resolver::CertResolver::new());
    rt.block_on(async {
        let db_certs = store.lock().await;
        let certs = db_certs.list_certificates().unwrap_or_default();
        if !certs.is_empty() {
            let cert_data: Vec<lorica_tls::cert_resolver::CertData> = certs
                .iter()
                .map(|c| lorica_tls::cert_resolver::CertData {
                    domain: c.domain.clone(),
                    san_domains: c.san_domains.clone(),
                    cert_pem: c.cert_pem.clone(),
                    key_pem: c.key_pem.clone(),
                    not_after_epoch: c.not_after.timestamp(),
                    ocsp_response: None, // OCSP fetched asynchronously on reload_cert_resolver
                })
                .collect();
            if let Err(e) = cert_resolver.reload(cert_data) {
                warn!(error = %e, "worker failed to load certificates into resolver");
            } else {
                info!(
                    worker_id = id,
                    domains = cert_resolver.domain_count(),
                    "worker loaded TLS certificates"
                );
            }
        }
    });

    // Pre-create metric Arcs so the command thread can read them
    let worker_cache_hits = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let worker_cache_misses = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let worker_ban_list: Arc<dashmap::DashMap<String, (std::time::Instant, u64)>> =
        Arc::new(dashmap::DashMap::new());
    let worker_ewma = Arc::new(lorica::proxy_wiring::EwmaTracker::new());
    let worker_backend_conns = Arc::new(lorica::proxy_wiring::BackendConnections::new());
    let worker_request_counts: Arc<dashmap::DashMap<(String, u16), std::sync::atomic::AtomicU64>> =
        Arc::new(dashmap::DashMap::new());
    let worker_waf_counts: Arc<dashmap::DashMap<(String, String), std::sync::atomic::AtomicU64>> =
        Arc::new(dashmap::DashMap::new());

    // Create shared WAF engine for worker (must be before command channel setup)
    let waf_engine = Arc::new(lorica_waf::WafEngine::new());
    {
        let s = store.blocking_lock();
        if let Ok(settings) = s.get_global_settings() {
            if settings.ip_blocklist_enabled {
                waf_engine.ip_blocklist().set_enabled(true);
                info!("worker: IP blocklist restored as enabled");
            }
        }
        if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
            if !disabled_ids.is_empty() {
                waf_engine.set_disabled_rules(&disabled_ids);
                info!(
                    count = disabled_ids.len(),
                    "worker: WAF disabled rules restored"
                );
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
                info!(
                    count = custom_rules.len(),
                    "worker: WAF custom rules restored"
                );
            }
        }
    }

    // Start the command channel listener in a background thread
    // (the proxy server's run_forever blocks the main thread)
    let cmd_store = Arc::clone(&store);
    let cmd_config = Arc::clone(&proxy_config);
    let cmd_cert_resolver = Arc::clone(&cert_resolver);
    let cmd_waf_engine = Arc::clone(&waf_engine);
    let cmd_cache_hits = Arc::clone(&worker_cache_hits);
    let cmd_cache_misses = Arc::clone(&worker_cache_misses);
    let cmd_active_conns = Arc::clone(&active_connections);
    let cmd_ban_list = Arc::clone(&worker_ban_list);
    let cmd_ewma = worker_ewma.scores_ref();
    let cmd_backend_conns = Arc::clone(&worker_backend_conns);
    let cmd_request_counts = Arc::clone(&worker_request_counts);
    let cmd_waf_counts = Arc::clone(&worker_waf_counts);
    let cmd_connection_filter = Arc::clone(&connection_filter);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to create command channel runtime");
        rt.block_on(async move {
            // SAFETY: cmd_fd is the socketpair file descriptor passed by the
            // supervisor via --cmd-fd CLI arg. It is exclusively owned by this
            // worker process after fork/exec.
            let mut channel = match unsafe { CommandChannel::from_raw_fd(cmd_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(error = %e, "worker failed to create command channel");
                    return;
                }
            };
            // Worker recv timeout must be longer than supervisor heartbeat interval
            channel.set_timeout(std::time::Duration::from_secs(30));

            info!(worker_id = id, "command channel listener started");

            loop {
                let cmd: Command = match channel.recv().await {
                    Ok(cmd) => cmd,
                    Err(e) => {
                        warn!(worker_id = id, error = %e, "command channel recv error");
                        // Channel closed - supervisor probably shut down
                        break;
                    }
                };

                match cmd.typed_command() {
                    CommandType::ConfigReload => {
                        info!(worker_id = id, seq = cmd.sequence, "applying config reload");
                        // Sync WAF state from persisted settings/DB
                        {
                            let s = cmd_store.lock().await;
                            if let Ok(settings) = s.get_global_settings() {
                                cmd_waf_engine
                                    .ip_blocklist()
                                    .set_enabled(settings.ip_blocklist_enabled);
                            }
                            // Reload disabled rules
                            if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
                                cmd_waf_engine.set_disabled_rules(&disabled_ids);
                            }
                            // Reload custom rules
                            cmd_waf_engine.clear_custom_rules();
                            if let Ok(custom_rules) = s.load_waf_custom_rules() {
                                for (rule_id, desc, cat, pattern, severity, _enabled) in
                                    &custom_rules
                                {
                                    let category = cat
                                        .parse()
                                        .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
                                    let _ = cmd_waf_engine.add_custom_rule(
                                        *rule_id,
                                        desc.clone(),
                                        category,
                                        pattern,
                                        *severity,
                                    );
                                }
                            }
                        }
                        match reload_proxy_config(
                            &cmd_store,
                            &cmd_config,
                            Some(&cmd_connection_filter),
                        )
                        .await
                        {
                            Ok(()) => {
                                // Rebuild the cert resolver AFTER the
                                // proxy config is committed so any new
                                // routes referencing a cert are
                                // resolvable on the first subsequent
                                // handshake, and so any TLS-settings
                                // change lands on the same snapshot
                                // the proxy just adopted.
                                lorica::reload::reload_cert_resolver(
                                    &cmd_store,
                                    &cmd_cert_resolver,
                                )
                                .await;
                                let resp = Response::ok(cmd.sequence);
                                if let Err(e) = channel.send(&resp).await {
                                    warn!(error = %e, "failed to send response");
                                }
                            }
                            Err(e) => {
                                error!(
                                    worker_id = id,
                                    error = %e,
                                    "config reload failed"
                                );
                                let resp = Response::error(cmd.sequence, e.to_string());
                                if let Err(e) = channel.send(&resp).await {
                                    warn!(error = %e, "failed to send error response");
                                }
                            }
                        }
                    }
                    CommandType::Heartbeat => {
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send heartbeat response");
                        }
                    }
                    CommandType::Shutdown => {
                        info!(worker_id = id, "received shutdown command");
                        let resp = Response::ok(cmd.sequence);
                        let _ = channel.send(&resp).await;
                        std::process::exit(0);
                    }
                    CommandType::MetricsRequest => {
                        use lorica_command::{BanReportEntry, EwmaReportEntry, MetricsReport};

                        // Collect ban list entries (skip expired)
                        let ban_entries: Vec<BanReportEntry> = cmd_ban_list
                            .iter()
                            .filter_map(|entry| {
                                let (ip, (banned_at, duration_s)) = (entry.key(), entry.value());
                                let elapsed = banned_at.elapsed().as_secs();
                                if elapsed >= *duration_s {
                                    return None; // expired
                                }
                                Some(BanReportEntry {
                                    ip: ip.clone(),
                                    remaining_seconds: duration_s - elapsed,
                                    ban_duration_seconds: *duration_s,
                                })
                            })
                            .collect();

                        // Collect EWMA scores
                        let ewma_entries: Vec<EwmaReportEntry> = cmd_ewma
                            .read()
                            .iter()
                            .map(|(addr, score): (&String, &f64)| EwmaReportEntry {
                                backend_address: addr.clone(),
                                score_us: *score,
                            })
                            .collect();

                        let mut report = MetricsReport::new(
                            id,
                            0, // total_requests not tracked yet
                            cmd_active_conns.load(std::sync::atomic::Ordering::Relaxed),
                        );
                        report.cache_hits =
                            cmd_cache_hits.load(std::sync::atomic::Ordering::Relaxed);
                        report.cache_misses =
                            cmd_cache_misses.load(std::sync::atomic::Ordering::Relaxed);
                        report.ban_entries = ban_entries;
                        report.ewma_entries = ewma_entries;
                        report.backend_conn_entries = cmd_backend_conns
                            .snapshot()
                            .into_iter()
                            .map(|(addr, conns)| lorica_command::BackendConnEntry {
                                backend_address: addr,
                                connections: conns,
                            })
                            .collect();
                        report.request_entries = cmd_request_counts
                            .iter()
                            .map(|entry| {
                                let ((route_id, status_code), counter) =
                                    (entry.key(), entry.value());
                                lorica_command::RequestCountEntry {
                                    route_id: route_id.clone(),
                                    status_code: *status_code as u32,
                                    count: counter.load(std::sync::atomic::Ordering::Relaxed),
                                }
                            })
                            .collect();
                        report.waf_entries = cmd_waf_counts
                            .iter()
                            .map(|entry| {
                                let ((category, action), counter) = (entry.key(), entry.value());
                                lorica_command::WafCountEntry {
                                    category: category.clone(),
                                    action: action.clone(),
                                    count: counter.load(std::sync::atomic::Ordering::Relaxed),
                                }
                            })
                            .collect();

                        if let Err(e) = channel.send(&report).await {
                            warn!(error = %e, "failed to send metrics report");
                        }
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send metrics response");
                        }
                    }
                    CommandType::BanIp => {
                        let ip = cmd.ban_ip.clone();
                        let duration_s = cmd.ban_duration_s;
                        if !ip.is_empty() {
                            cmd_ban_list.insert(ip.clone(), (Instant::now(), duration_s));
                            info!(
                                worker_id = id,
                                ip = %ip,
                                ban_duration_s = %duration_s,
                                "applied BanIp from supervisor"
                            );
                        }
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send BanIp response");
                        }
                    }
                    CommandType::Unspecified => {
                        warn!(worker_id = id, "received unspecified command");
                    }
                    // Pipelined RPC command variants (Phase 1 framework,
                    // see docs/architecture/worker-shared-state.md § 4).
                    // The legacy CommandChannel used here is request/reply
                    // inline; the pipelined RPC uses RpcEndpoint on a
                    // separate (future) socketpair. Any RPC-typed Command
                    // arriving on this channel is a protocol misuse; reply
                    // with a clear error so the supervisor can log it.
                    CommandType::RateLimitQuery
                    | CommandType::RateLimitDelta
                    | CommandType::VerdictLookup
                    | CommandType::VerdictPush
                    | CommandType::BreakerQuery
                    | CommandType::BreakerReport
                    | CommandType::ConfigReloadPrepare
                    | CommandType::ConfigReloadCommit => {
                        warn!(
                            worker_id = id,
                            command_type = ?cmd.typed_command(),
                            "RPC-typed command delivered on legacy channel; expected the pipelined RpcEndpoint"
                        );
                        let resp = Response::error(
                            cmd.sequence,
                            "pipelined RPC command on legacy channel",
                        );
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send RPC protocol-error response");
                        }
                    }
                }
            }
        });
    });

    // Create SLA collector and load configs
    let sla_collector = Arc::new(lorica_bench::SlaCollector::new());
    rt.block_on(async {
        let s = store.lock().await;
        sla_collector.load_configs(&s);
    });

    // Worker background tasks: log forwarding + WAF event forwarding via UDS + SLA flush to DB
    let log_fwd_buffer = Arc::clone(&log_buffer);
    let sla_flush_collector = Arc::clone(&sla_collector);
    let sla_flush_store = Arc::clone(&store);
    let log_sock_path = PathBuf::from(&data_dir).join("log.sock");
    let waf_fwd_engine = Arc::clone(&waf_engine);
    let waf_sock_path_worker = PathBuf::from(&data_dir).join("waf.sock");
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("worker background runtime");
        rt.block_on(async move {
            sla_flush_collector.start_flush_task(sla_flush_store, None);

            // IP blocklist: initial load + periodic refresh (every 6h)
            if waf_fwd_engine.ip_blocklist().is_enabled() {
                match lorica_api::waf::fetch_and_load_blocklist(waf_fwd_engine.ip_blocklist()).await
                {
                    Ok(count) => tracing::info!(count, "worker: IP blocklist loaded at startup"),
                    Err(e) => {
                        tracing::warn!(error = %e, "worker: IP blocklist initial load failed")
                    }
                }
            }
            let blocklist_engine = Arc::clone(&waf_fwd_engine);
            // Worker mode has no supervisor drain; a local tracker
            // is fine (worker shutdown is orchestrated by the
            // supervisor via SIGTERM + drain-timeout anyway).
            let worker_blocklist_tracker = tokio_util::task::TaskTracker::new();
            lorica_api::waf::spawn_blocklist_refresh(
                blocklist_engine,
                std::time::Duration::from_secs(6 * 3600),
                &worker_blocklist_tracker,
            );

            // Forward WAF events to supervisor
            tokio::spawn(async move {
                let stream = loop {
                    match tokio::net::UnixStream::connect(&waf_sock_path_worker).await {
                        Ok(s) => break s,
                        Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                    }
                };
                let mut writer = tokio::io::BufWriter::new(stream);
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                let mut last_count = 0usize;
                let event_buf = waf_fwd_engine.event_buffer();
                loop {
                    interval.tick().await;
                    let events: Vec<lorica_waf::WafEvent> = {
                        let buf = event_buf.lock();
                        if buf.len() == last_count {
                            continue;
                        }
                        let new_events: Vec<_> = buf.iter().skip(last_count).cloned().collect();
                        last_count = buf.len();
                        new_events
                    };
                    for event in &events {
                        if let Ok(json) = serde_json::to_string(event) {
                            let line = format!("{json}\n");
                            if tokio::io::AsyncWriteExt::write_all(&mut writer, line.as_bytes())
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                    }
                    let _ = tokio::io::AsyncWriteExt::flush(&mut writer).await;
                }
            });

            // Connect to supervisor's log socket (retry until available)
            let stream = loop {
                match tokio::net::UnixStream::connect(&log_sock_path).await {
                    Ok(s) => break s,
                    Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                }
            };
            let mut writer = tokio::io::BufWriter::new(stream);
            let mut rx = log_fwd_buffer.subscribe();
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            let line = format!("{json}\n");
                            if tokio::io::AsyncWriteExt::write_all(&mut writer, line.as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                            let _ = tokio::io::AsyncWriteExt::flush(&mut writer).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    });

    // Build the proxy service with pre-created metric Arcs
    let mut lorica_proxy = LoricaProxy::new(
        Arc::clone(&proxy_config),
        Arc::clone(&log_buffer),
        Arc::clone(&active_connections),
        Arc::clone(&sla_collector),
    );
    // Replace the default Arcs with our pre-created ones (shared with command thread)
    lorica_proxy.cache_hits = worker_cache_hits;
    lorica_proxy.cache_misses = worker_cache_misses;
    lorica_proxy.ban_list = worker_ban_list;
    lorica_proxy.ewma_tracker = worker_ewma;
    lorica_proxy.backend_connections = worker_backend_conns;
    lorica_proxy.request_counts = worker_request_counts;
    lorica_proxy.waf_counts = worker_waf_counts;
    lorica_proxy.waf_engine = waf_engine;
    lorica_proxy.shmem = shmem_region;
    // Worker mode: rate-limit engine runs as a local cache synced with
    // the supervisor via the pipelined RPC channel every 100 ms. See
    // `spawn_rate_limit_sync` below and design doc § 6.
    lorica_proxy.rate_limit_buckets = lorica::proxy_wiring::RateLimitEngine::local();
    // Periodic basic-auth cache prune (PERF-8). Worker mode has no
    // supervisor TaskTracker available here; a local tracker is fine
    // because worker shutdown is orchestrated by the supervisor via
    // SIGTERM and the prune task exits with the runtime.
    let worker_auth_prune_tracker = tokio_util::task::TaskTracker::new();
    // All four of the following `spawn_*` helpers call into
    // `tokio::spawn`, which requires a current runtime. We are
    // between two `rt.block_on(...)` blocks here, so use `rt.enter()`
    // to establish a runtime context for the duration of the setup.
    // The spawned tasks outlive the guard (tokio keeps them attached
    // to the runtime itself).
    let _rt_guard = rt.enter();
    let _basic_auth_prune = lorica_proxy
        .spawn_basic_auth_cache_prune(&worker_auth_prune_tracker, Duration::from_secs(30));
    // Per-IP rate-limit buckets need the same lazy-prune treatment:
    // a scan or high-cardinality traffic pattern would otherwise
    // accumulate one bucket per distinct IP forever. 5 min idle TTL
    // matches the shmem WAF eviction cadence.
    let _rate_limit_prune = lorica_proxy.spawn_rate_limit_prune(
        &worker_auth_prune_tracker,
        Duration::from_secs(60),
        Duration::from_secs(5 * 60),
    );
    // Spawn the cross-worker sync task when the supervisor provided
    // an RPC socketpair (production worker mode). The task drains
    // `LocalBucket::take_delta` every 100 ms, pushes the batch via
    // `RateLimitDelta`, and refreshes each bucket with the
    // authoritative snapshot from the reply.
    if let Some(fd) = rpc_fd {
        // SAFETY: fd is a valid socketpair end received via SCM_RIGHTS
        // from the supervisor and exclusively owned by this worker.
        match unsafe { lorica_command::RpcEndpoint::from_raw_fd(fd) } {
            Ok((endpoint, incoming)) => {
                // The endpoint is cloned across five use sites:
                // rate-limit sync loop, verdict cache lookup/push,
                // breaker query/report, config-reload prepare/commit
                // listener, and the incoming stream that receives
                // supervisor-initiated commands. `RpcEndpoint` is
                // `Clone` via `Arc<Inner>` so all five share the
                // same underlying stream and pipelined dispatcher.
                // See design § 4.3.
                lorica_proxy.verdict_cache =
                    lorica::proxy_wiring::VerdictCacheEngine::rpc(
                        endpoint.clone(),
                        Duration::from_millis(500),
                    );
                lorica_proxy.circuit_breaker_engine =
                    lorica::proxy_wiring::BreakerEngine::rpc(
                        endpoint.clone(),
                        Duration::from_millis(500),
                    );
                let _rpc_listener = lorica_proxy.spawn_worker_rpc_listener(
                    &worker_auth_prune_tracker,
                    incoming,
                    Arc::clone(&store),
                    None,
                    id,
                );
                let _sync_handle = lorica_proxy.spawn_rate_limit_sync(
                    &worker_auth_prune_tracker,
                    endpoint,
                    Duration::from_millis(100),
                );
                info!(
                    worker_id = id,
                    "rate-limit sync + RPC listener spawned; verdict cache + breaker engines bound to RPC"
                );
            }
            Err(e) => {
                error!(
                    worker_id = id,
                    error = %e,
                    "failed to create worker RpcEndpoint; rate-limit sync disabled"
                );
            }
        }
    } else if shmem_region.is_some() {
        // Worker mode without RPC FD: should not happen in current
        // `WorkerManager::spawn_worker` which always sends one. Log
        // loudly so the misconfiguration surfaces.
        warn!(
            worker_id = id,
            "worker started with shmem but no RPC FD; rate-limit sync disabled"
        );
    }
    drop(_rt_guard);
    // Open a LogStore so the worker can persist WAF events directly (with
    // route_hostname and action stamped). SQLite WAL mode allows concurrent
    // writes from multiple worker processes.
    lorica_proxy.log_store = match lorica_api::log_store::LogStore::open(&data_dir) {
        Ok(s) => Some(Arc::new(s)),
        Err(e) => {
            warn!(error = %e, "worker: failed to open log store, WAF event persistence disabled");
            None
        }
    };
    // ACME challenge store backed by SQLite - workers can read challenges set by supervisor
    lorica_proxy.acme_challenge_store = Some(lorica_api::acme::AcmeChallengeStore::with_db_path(
        db_path.clone(),
    ));

    let pool_size = {
        let backend_count = store
            .blocking_lock()
            .list_backends()
            .map(|b| b.len())
            .unwrap_or(0);
        lorica::proxy_wiring::compute_pool_size(backend_count)
    };
    info!(pool_size, "upstream keepalive pool size");
    let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
        upstream_crl_file: upstream_crl_file.map(|s| s.to_string()),
        upstream_keepalive_pool_size: pool_size,
        ..Default::default()
    });
    let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
    // Install the TCP-level pre-filter. Held by Arc inside the listener, so
    // subsequent reloads take effect without rebuilding endpoints.
    proxy_service.set_connection_filter(
        connection_filter.clone() as Arc<dyn lorica_core::listeners::ConnectionFilter>
    );

    // Build the optional mTLS client-cert verifier from the union of
    // per-route CA bundles. This is done once here; rustls
    // ServerConfig is immutable so reloading a CA requires a restart.
    // We also snapshot the CA fingerprint so `reload_proxy_config`
    // can warn if an operator edits `mtls.ca_cert_pem` at runtime.
    let (mtls_verifier, mtls_installed_fingerprint) = {
        let routes = store.blocking_lock().list_routes().unwrap_or_default();
        let fp = lorica::mtls::compute_ca_fingerprint(&routes);
        (lorica::mtls::build_from_routes(&routes), fp)
    };
    if let Some(ref fp) = mtls_installed_fingerprint {
        info!(worker_id = id, fingerprint = %fp, "mTLS enabled at listener: per-route enforcement applies");
    }
    // Note: the worker process doesn't drive reload_proxy_config
    // directly (supervisor does via command channel), so no
    // fingerprint slot is wired here - the supervisor side carries
    // the drift-detection responsibility for the entire worker pool.

    // Register listeners - TCP for HTTP, TLS for HTTPS
    let https_suffix = format!(":{https_port}");
    for addr in &listener_addrs {
        if https_port > 0 && addr.ends_with(&https_suffix) {
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
            if let Some(ref v) = mtls_verifier {
                tls_settings.set_client_cert_verifier(v.clone());
            }
            proxy_service.add_tls_with_settings(addr, None, tls_settings);
            info!(worker_id = id, addr = %addr, "registered TLS listener");
        } else {
            proxy_service.add_tcp(addr);
            info!(worker_id = id, addr = %addr, "registered TCP listener");
        }
    }

    info!(worker_id = id, "starting proxy engine");

    let mut server = lorica_core::server::Server::new(None).expect("failed to create proxy server");
    server.set_listen_fds(fds);
    server.add_service(proxy_service);
    server.run_forever();
}

// ---------------------------------------------------------------------------
// Single-process mode (original behavior, no workers)
// ---------------------------------------------------------------------------

fn run_single_process(cli: Cli) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async move {
        // Ensure data directory exists
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

        // Open the configuration database
        let db_path = data_dir.join("lorica.db");
        let store = match ConfigStore::open(&db_path, Some(encryption_key)) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to open configuration database");
                std::process::exit(1);
            }
        };
        restrict_key_permissions(&db_path);

        // Ensure an admin user exists (first-run password generation)
        match lorica_api::auth::ensure_admin_user(&store) {
            Ok(Some(password)) => {
                println!();
                println!("  ===================================================");
                println!("  Initial admin password: {password}");
                println!("  Login at http://localhost:{}/", cli.management_port);
                println!("  You will be asked to change it on first login.");
                println!("  ===================================================");
                println!();
                info!("admin user created (first run)");
            }
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
        let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
        let connection_filter =
            Arc::new(lorica::connection_filter::GlobalConnectionFilter::empty());

        if let Err(e) = reload_proxy_config(&store, &proxy_config, Some(&connection_filter)).await {
            error!(error = %e, "failed to load initial proxy configuration");
            std::process::exit(1);
        }

        // Build the CertResolver for SNI-based certificate selection
        let cert_resolver = Arc::new(lorica_tls::cert_resolver::CertResolver::new());
        {
            let s = store.lock().await;
            let db_certs = s.list_certificates().unwrap_or_default();
            if !db_certs.is_empty() {
                let cert_data: Vec<lorica_tls::cert_resolver::CertData> = db_certs
                    .iter()
                    .map(|c| lorica_tls::cert_resolver::CertData {
                        domain: c.domain.clone(),
                        san_domains: c.san_domains.clone(),
                        cert_pem: c.cert_pem.clone(),
                        key_pem: c.key_pem.clone(),
                        not_after_epoch: c.not_after.timestamp(),
                        ocsp_response: None, // OCSP fetched asynchronously on reload_cert_resolver
                    })
                    .collect();
                if let Err(e) = cert_resolver.reload(cert_data) {
                    warn!(error = %e, "failed to load certificates into resolver");
                } else {
                    info!(
                        domains = cert_resolver.domain_count(),
                        "loaded certificates into SNI resolver"
                    );
                }
            }
        }

        // Create shared WAF engine
        let waf_engine = Arc::new(lorica_waf::WafEngine::new());
        let waf_event_buffer = waf_engine.event_buffer();
        let waf_rule_count = waf_engine.rule_count();

        // Restore WAF state from persisted settings
        {
            let s = store.lock().await;
            if let Ok(settings) = s.get_global_settings() {
                if settings.ip_blocklist_enabled {
                    waf_engine.ip_blocklist().set_enabled(true);
                    match lorica_api::waf::fetch_and_load_blocklist(waf_engine.ip_blocklist()).await
                    {
                        Ok(count) => info!(count, "IP blocklist loaded at startup"),
                        Err(e) => warn!(error = %e, "IP blocklist initial load failed"),
                    }
                }
            }
            // Restore disabled WAF rules
            if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
                if !disabled_ids.is_empty() {
                    waf_engine.set_disabled_rules(&disabled_ids);
                    info!(count = disabled_ids.len(), "WAF disabled rules restored");
                }
            }
            // Restore custom WAF rules
            if let Ok(custom_rules) = s.load_waf_custom_rules() {
                for (id, desc, cat, pattern, severity, _enabled) in &custom_rules {
                    let category = cat
                        .parse()
                        .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
                    let _ =
                        waf_engine.add_custom_rule(*id, desc.clone(), category, pattern, *severity);
                }
                if !custom_rules.is_empty() {
                    info!(count = custom_rules.len(), "WAF custom rules restored");
                }
            }
        }

        // Tracker shared by every background task that must drain on
        // shutdown. The shutdown path below calls `close(); wait().
        // await` on its clone, giving in-flight work a bounded time
        // to complete.
        let single_task_tracker = tokio_util::task::TaskTracker::new();

        // Spawn IP blocklist auto-refresh (every 6 hours, matching Data-Shield update frequency)
        let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
            Arc::clone(&waf_engine),
            std::time::Duration::from_secs(6 * 3600),
            &single_task_tracker,
        );

        // Create non-blocking alert sender and notification dispatcher
        let alert_sender = lorica_notify::AlertSender::new(256);
        let notify_dispatcher = {
            let s = store.lock().await;
            build_notify_dispatcher(&s)
        };
        let notification_history = notify_dispatcher.history();
        let notify_dispatcher = Arc::new(tokio::sync::Mutex::new(notify_dispatcher));
        let _alert_dispatcher = spawn_persisted_alert_dispatcher(
            &alert_sender,
            Arc::clone(&notify_dispatcher),
            log_store.clone(),
        );

        // Create SLA collector and start background flush task
        let sla_collector = Arc::new(lorica_bench::SlaCollector::new());
        {
            let s = store.lock().await;
            sla_collector.load_configs(&s);
        }
        sla_collector.start_flush_task(Arc::clone(&store), Some(Arc::clone(&notify_dispatcher)));

        // Start active probe scheduler
        let probe_store = Arc::clone(&store);
        let probe_scheduler = Arc::new(lorica_bench::ProbeScheduler::new(
            probe_store,
            Some(Arc::clone(&notify_dispatcher)),
        ));
        probe_scheduler.reload().await;

        // Create load test engine (shared between API and scheduler)
        let load_test_engine = Arc::new(lorica_bench::LoadTestEngine::new());

        // Start load test cron scheduler
        let lt_scheduler_store = Arc::clone(&store);
        let lt_scheduler_engine = Arc::clone(&load_test_engine);
        lorica_bench::scheduler::start_scheduler(lt_scheduler_store, lt_scheduler_engine);

        // Create shared ACME challenge store backed by SQLite for cross-process access
        let acme_challenge_store =
            lorica_api::acme::AcmeChallengeStore::with_db_path(db_path.clone());

        // Start the HTTP proxy service
        let mut lorica_proxy = LoricaProxy::new(
            Arc::clone(&proxy_config),
            Arc::clone(&log_buffer),
            Arc::clone(&active_connections),
            Arc::clone(&sla_collector),
        );
        lorica_proxy.waf_engine = Arc::clone(&waf_engine);
        lorica_proxy.acme_challenge_store = Some(acme_challenge_store.clone());
        lorica_proxy.alert_sender = Some(alert_sender.clone());
        lorica_proxy.log_store = log_store.clone();
        // Periodic prune of expired basic-auth cache entries so a
        // password-spray with no successful logins cannot grow the
        // cache unboundedly until next restart (PERF-8).
        let _basic_auth_prune = lorica_proxy
            .spawn_basic_auth_cache_prune(&single_task_tracker, Duration::from_secs(30));
        // Same lazy-prune for per-IP rate-limit buckets; see worker
        // path comment for rationale.
        let _rate_limit_prune = lorica_proxy.spawn_rate_limit_prune(
            &single_task_tracker,
            Duration::from_secs(60),
            Duration::from_secs(5 * 60),
        );
        let backend_conns = Arc::clone(&lorica_proxy.backend_connections);
        let health_backend_conns = Arc::clone(&backend_conns);
        let proxy_cache_hits = Arc::clone(&lorica_proxy.cache_hits);
        let proxy_cache_misses = Arc::clone(&lorica_proxy.cache_misses);
        let proxy_ban_list = Arc::clone(&lorica_proxy.ban_list);
        let proxy_ewma_scores = lorica_proxy.ewma_tracker.scores_ref();
        let pool_size = {
            let s = store.lock().await;
            let backend_count = s.list_backends().map(|b| b.len()).unwrap_or(0);
            lorica::proxy_wiring::compute_pool_size(backend_count)
        };
        info!(pool_size, "upstream keepalive pool size");
        let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
            upstream_crl_file: cli.upstream_crl_file.clone(),
            upstream_keepalive_pool_size: pool_size,
            ..Default::default()
        });
        let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
        proxy_service.set_connection_filter(
            connection_filter.clone() as Arc<dyn lorica_core::listeners::ConnectionFilter>
        );
        let mut tcp_opts = lorica_core::listeners::TcpSocketOptions::default();
        tcp_opts.so_reuseport = Some(true);
        proxy_service.add_tcp_with_settings(&format!("0.0.0.0:{}", cli.http_port), tcp_opts);

        info!(port = cli.http_port, "HTTP proxy listener configured");

        // Add TLS listener with SNI-based cert resolver (always, even with no certs yet).
        // Connections to unknown domains fail TLS handshake; when the first cert is uploaded
        // and the resolver is reloaded, TLS starts working without restart.
        let https_port = cli.https_port;
        // Snapshot the CA fingerprint once at startup and pass the slot
        // to the reload loop further down so it can warn the operator
        // if an `mtls.ca_cert_pem` edit happens at runtime (rustls
        // ServerConfig is immutable; an edit needs a restart).
        let mtls_installed_fingerprint: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));
        {
            // Build the optional mTLS verifier from the union of per-route
            // CA bundles. `store` is a `tokio::sync::Mutex`, and we are
            // inside the `rt.block_on(async move { ... })` runtime
            // context — so we must `await` the lock instead of using
            // the blocking_lock which panics from within a runtime.
            let (mtls_verifier, startup_fp) = {
                let routes = store.lock().await.list_routes().unwrap_or_default();
                (
                    lorica::mtls::build_from_routes(&routes),
                    lorica::mtls::compute_ca_fingerprint(&routes),
                )
            };
            *mtls_installed_fingerprint.lock() = startup_fp.clone();
            if let Some(ref fp) = startup_fp {
                info!(fingerprint = %fp, "mTLS enabled at listener: per-route enforcement applies");
            }
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
            if let Some(ref v) = mtls_verifier {
                tls_settings.set_client_cert_verifier(v.clone());
            }
            let mut tls_tcp_opts = lorica_core::listeners::TcpSocketOptions::default();
            tls_tcp_opts.so_reuseport = Some(true);
            proxy_service.add_tls_with_settings(
                &format!("0.0.0.0:{https_port}"),
                Some(tls_tcp_opts),
                tls_settings,
            );
            info!(
                port = https_port,
                domains = cert_resolver.domain_count(),
                "HTTPS proxy listener configured with SNI resolver"
            );
        }

        // Create config reload channel so API mutations can trigger proxy reload
        let (config_reload_tx, mut config_reload_rx) = tokio::sync::watch::channel(0u64);

        // Clone sla_collector before the async move closure captures it
        let reload_sla_collector = Arc::clone(&sla_collector);

        // Clone alert_sender before it's moved into the API spawn block
        let health_alert_sender2 = alert_sender.clone();

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let api_log_store = log_store.clone();
        let management_port = cli.management_port;
        // `single_task_tracker` is already defined above (before the
        // WAF blocklist refresh spawn). Clone it for AppState and the
        // shutdown drain path.
        let api_task_tracker = single_task_tracker.clone();
        let shutdown_task_tracker = single_task_tracker.clone();
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store.clone(),
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                http_port: cli.http_port,
                https_port: cli.https_port,
                config_reload_tx: Some(config_reload_tx),
                worker_metrics: None,
                waf_event_buffer: Some(waf_event_buffer),
                waf_engine: Some(waf_engine),
                waf_rule_count: Some(waf_rule_count),
                acme_challenge_store: Some(acme_challenge_store),
                pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
                sla_collector: Some(Arc::clone(&sla_collector)),
                load_test_engine: Some(Arc::clone(&load_test_engine)),
                cache_hits: Some(proxy_cache_hits),
                cache_misses: Some(proxy_cache_misses),
                ban_list: Some(proxy_ban_list),
                cache_backend: Some(&*lorica::proxy_wiring::CACHE_BACKEND),
                ewma_scores: Some(proxy_ewma_scores),
                backend_connections: Some(backend_conns.clone()),
                notification_history: Some(notification_history),
                log_store: api_log_store,
                aggregated_metrics: None, // single-process uses direct Arc references
                metrics_refresher: None,  // pull-on-scrape only meaningful in worker mode
                task_tracker: api_task_tracker,
            };

            // Spawn ACME certificate auto-renewal (check every 12h, renew at 30 days before expiry)
            let _acme_renewal = lorica_api::acme::spawn_renewal_task(
                state.clone(),
                std::time::Duration::from_secs(12 * 3600),
                30,
                Some(alert_sender.clone()),
            );

            // Spawn certificate expiry check for ALL certs (ACME + manual), every 12h
            let _cert_expiry_check = lorica_api::acme::spawn_cert_expiry_check_task(
                state.clone(),
                std::time::Duration::from_secs(12 * 3600),
                alert_sender.clone(),
            );

            let session_store = SessionStore::new(api_store.clone())
                .await
                .with_task_tracker(state.task_tracker.clone());
            let rate_limiter = RateLimiter::new();

            if let Err(e) = lorica_api::server::start_server(
                management_port,
                state,
                session_store,
                rate_limiter,
            )
            .await
            {
                error!(error = %e, "API server exited with error");
            }
        });

        if let Some(ref retention_store) = log_store {
            let retention_log_store = Arc::clone(retention_store);
            let retention_config_store = Arc::clone(&store);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                let mut last_sla_purge_day: u32 = 0;
                loop {
                    interval.tick().await;
                    let retention = {
                        let s = retention_config_store.lock().await;
                        s.get_global_settings()
                            .map(|gs| gs.access_log_retention)
                            .unwrap_or(100_000)
                    };
                    if retention > 0 {
                        if let Err(e) = retention_log_store.enforce_retention(retention as u64) {
                            tracing::warn!(error = %e, "access log retention cleanup failed");
                        }
                    }
                    {
                        let s = retention_config_store.lock().await;
                        if let Err(e) = s.purge_probe_results(1000) {
                            tracing::warn!(error = %e, "probe result retention cleanup failed");
                        }
                    }
                    if let Err(e) = retention_log_store.enforce_waf_retention(100_000) {
                        tracing::warn!(error = %e, "WAF event retention cleanup failed");
                    }
                    last_sla_purge_day =
                        run_sla_purge(&retention_config_store, last_sla_purge_day).await;
                }
            });
        }

        // Background task: reload proxy config, cert resolver, and probe scheduler when API signals a change
        let reload_store = Arc::clone(&store);
        let reload_config = Arc::clone(&proxy_config);
        let reload_cert_resolver = Arc::clone(&cert_resolver);
        let reload_probe_scheduler = Arc::clone(&probe_scheduler);
        let reload_connection_filter = Arc::clone(&connection_filter);
        let reload_mtls_fp = Arc::clone(&mtls_installed_fingerprint);
        let _reload_handle = tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                if let Err(e) = lorica::reload::reload_proxy_config_with_mtls(
                    &reload_store,
                    &reload_config,
                    Some(&reload_connection_filter),
                    Some(&*reload_mtls_fp),
                )
                .await
                {
                    tracing::error!(error = %e, "failed to reload proxy configuration");
                }
                lorica::reload::reload_cert_resolver(&reload_store, &reload_cert_resolver).await;
                reload_probe_scheduler.reload().await;
                {
                    let s = reload_store.lock().await;
                    reload_sla_collector.load_configs(&s);
                }
            }
        });

        // Start health check background task
        let health_store = Arc::clone(&store);
        let health_config = Arc::clone(&proxy_config);
        let health_interval = {
            let s = store.lock().await;
            s.get_global_settings()
                .map(|gs| gs.default_health_check_interval_s as u64)
                .unwrap_or(10)
        };
        let health_handle = tokio::spawn(async move {
            health::health_check_loop(
                health_store,
                health_config,
                health_interval,
                Some(health_backend_conns),
                Some(health_alert_sender2),
                None, // single-process mode, no workers to notify
            )
            .await;
        });

        // Run the proxy engine in a dedicated thread
        let _proxy_thread = std::thread::spawn(move || {
            let mut server =
                lorica_core::server::Server::new(None).expect("failed to create proxy server");
            server.bootstrap();
            server.add_service(proxy_service);
            server.run_forever();
        });

        // Wait for shutdown signal
        shutdown_signal().await;

        info!("Lorica shutting down gracefully");

        // Drain tracked background tasks before tearing down the API
        // server. Bounded at 10 s so a hung task does not delay exit.
        shutdown_task_tracker.close();
        if tokio::time::timeout(Duration::from_secs(10), shutdown_task_tracker.wait())
            .await
            .is_err()
        {
            warn!("some background tasks did not finish within drain timeout; aborting");
        }
        api_handle.abort();
        health_handle.abort();
    });
}

/// Build a NotifyDispatcher from database notification configs.
/// Run the SLA data purge if enabled and the schedule matches today.
/// Returns the day-of-month on which the last purge ran (used as guard to run once per day).
async fn run_sla_purge(store: &Arc<Mutex<lorica_config::ConfigStore>>, last_purge_day: u32) -> u32 {
    let today = chrono::Utc::now().day();
    if today == last_purge_day {
        return last_purge_day;
    }
    let s = store.lock().await;
    let gs = match s.get_global_settings() {
        Ok(gs) => gs,
        Err(_) => return last_purge_day,
    };
    if !gs.sla_purge_enabled {
        return last_purge_day;
    }
    let should_run = match gs.sla_purge_schedule.as_str() {
        "daily" => true,
        "first_of_month" => today == 1,
        other => other.parse::<u32>().is_ok_and(|d| d == today),
    };
    if !should_run {
        return last_purge_day;
    }
    let cutoff = chrono::Utc::now() - chrono::Duration::days(gs.sla_purge_retention_days as i64);
    match s.prune_sla_buckets(&cutoff) {
        Ok(n) if n > 0 => {
            tracing::info!(
                count = n,
                retention_days = gs.sla_purge_retention_days,
                "purged old SLA buckets"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "SLA purge failed");
        }
        _ => {}
    }
    today
}

/// Spawn alert dispatcher that also persists events to the log store (SQLite).
fn spawn_persisted_alert_dispatcher(
    alert_sender: &lorica_notify::AlertSender,
    dispatcher: Arc<Mutex<lorica_notify::NotifyDispatcher>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = alert_sender.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Dispatch via channels (email, webhook, etc.)
                    let d = dispatcher.lock().await;
                    d.dispatch(&event).await;
                    drop(d);

                    // Persist to log store
                    if let Some(ref store) = log_store {
                        if let Err(e) = store.insert_notification_event(&event) {
                            tracing::warn!(error = %e, "failed to persist notification event");
                        }
                        let _ = store.enforce_notification_retention(500);
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        dropped = n,
                        "alert dispatcher lagged, some notifications were dropped"
                    );
                    lorica_api::metrics::inc_notifier_events_dropped("lag", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    lorica_api::metrics::inc_notifier_events_dropped("closed", 1);
                    break;
                }
            }
        }
    })
}

fn build_notify_dispatcher(store: &lorica_config::ConfigStore) -> lorica_notify::NotifyDispatcher {
    let mut dispatcher = lorica_notify::NotifyDispatcher::new();
    if let Ok(configs) = store.list_notification_configs() {
        for nc in configs {
            let config_json = &nc.config;
            match nc.channel {
                lorica_config::models::NotificationChannel::Email => {
                    if let Ok(email_cfg) =
                        serde_json::from_str::<lorica_notify::channels::EmailConfig>(config_json)
                    {
                        dispatcher.add_email_channel(nc.id, email_cfg, nc.alert_types, nc.enabled);
                    }
                }
                lorica_config::models::NotificationChannel::Webhook => {
                    if let Ok(webhook_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_webhook_channel(
                            nc.id,
                            webhook_cfg,
                            nc.alert_types,
                            nc.enabled,
                        );
                    }
                }
                lorica_config::models::NotificationChannel::Slack => {
                    if let Ok(slack_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_slack_channel(nc.id, slack_cfg, nc.alert_types, nc.enabled);
                    }
                }
            }
        }
    }
    dispatcher
}

/// Restrict private key file permissions to owner-only read.
fn restrict_key_permissions(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(error = %e, path = %path.display(), "failed to restrict key file permissions");
        return false;
    }
    true
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            warn!("Received SIGTERM");
        }
        _ = sigint.recv() => {
            warn!("Received SIGINT");
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
        c.insert("r1", "cookie", lorica_command::Verdict::Allow as i32, Vec::new(), 1);
        std::thread::sleep(Duration::from_millis(10));
        assert!(c.lookup("r1", "cookie").is_none());
        // Lazy eviction on lookup: expired entry removed.
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn verdict_cache_partitions_by_route() {
        let c = SupervisorVerdictCache::new();
        c.insert("route-a", "c", lorica_command::Verdict::Allow as i32, Vec::new(), 30_000);
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
