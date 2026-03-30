// Copyright 2026 Romain G. (Lorica)
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
use std::time::Instant;

use arc_swap::ArcSwap;
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

const DEFAULT_DATA_DIR: &str = if cfg!(unix) {
    "/var/lib/lorica"
} else {
    "./data"
};

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

    /// Management port (localhost only)
    #[arg(long, default_value_t = DEFAULT_MANAGEMENT_PORT)]
    management_port: u16,

    /// HTTP proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTP_PORT)]
    http_port: u16,

    /// HTTPS proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTPS_PORT)]
    https_port: u16,

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

        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

fn init_logging(log_level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .init();
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
    let cli = Cli::parse();

    match cli.command {
        #[cfg(unix)]
        Some(Commands::Worker {
            id,
            cmd_fd,
            data_dir,
            log_level,
        }) => {
            init_logging(&log_level);
            run_worker(id, cmd_fd, &data_dir);
        }
        #[cfg(not(unix))]
        Some(Commands::Worker { .. }) => {
            eprintln!("Worker mode is only supported on Unix");
            std::process::exit(1);
        }
        None => {
            init_logging(&cli.log_level);
            startup_banner(&cli);

            #[cfg(unix)]
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

#[cfg(unix)]
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
        http_addr: format!("0.0.0.0:{}", cli.http_port),
        https_addr: Some(format!("0.0.0.0:{}", cli.https_port)),
    };

    // Fork workers BEFORE creating any threads/runtime
    let mut manager = WorkerManager::new(config);
    if let Err(e) = manager.start() {
        error!(error = %e, "failed to start worker processes");
        std::process::exit(1);
    }

    info!(
        worker_count = manager.worker_count(),
        "all workers spawned, starting supervisor services"
    );

    // Extract raw FDs from worker handles before entering the tokio runtime.
    // CommandChannel::from_raw_fd requires a tokio runtime, so we take the raw FDs
    // here and create channels inside block_on.
    let worker_fds: Vec<(u32, RawFd)> = manager
        .workers_mut()
        .iter_mut()
        .filter_map(|w| {
            let fd = w.take_cmd_fd()?;
            Some((w.id(), fd.into_raw_fd()))
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

        let db_path = data_dir.join("lorica.db");
        let store = match ConfigStore::open(&db_path, None) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to open configuration database");
                std::process::exit(1);
            }
        };

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

        let store = Arc::new(Mutex::new(store));
        let log_buffer = Arc::new(LogBuffer::new(10_000));
        let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Broadcast channel: API config changes fan out to all per-worker tasks
        let (reload_bc_tx, _) = broadcast::channel::<u64>(16);
        // Clone for the API's watch-based reload signal
        let reload_bc_tx_clone = reload_bc_tx.clone();
        let (config_reload_tx, mut config_reload_rx) = tokio::sync::watch::channel(0u64);

        // Bridge: watch channel (from API) -> broadcast (to per-worker tasks)
        let sequence = Arc::new(AtomicU64::new(1));
        let bridge_seq = Arc::clone(&sequence);
        tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                let seq = bridge_seq.fetch_add(1, Ordering::Relaxed);
                let _ = reload_bc_tx_clone.send(seq);
            }
        });

        // Spawn a per-worker task that handles both config reload and heartbeat
        // No shared Mutex - each worker has its own channel and task
        for (worker_id, raw_fd) in worker_fds {
            let mut channel = match unsafe { CommandChannel::from_raw_fd(raw_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(worker_id, error = %e, "failed to create command channel");
                    continue;
                }
            };
            let mut reload_rx = reload_bc_tx.subscribe();
            let hb_seq = Arc::clone(&sequence);

            tokio::spawn(async move {
                let heartbeat_interval = Duration::from_secs(5);
                let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
                heartbeat_timer.tick().await; // skip first immediate tick

                loop {
                    tokio::select! {
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
                                    info!(worker_id, latency_ms, "heartbeat ok");
                                }
                                Err(e) => {
                                    warn!(worker_id, error = %e, "heartbeat response failed - worker may be unresponsive");
                                }
                            }
                        }
                    }
                }
            });
        }

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let management_port = cli.management_port;
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store,
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                config_reload_tx: Some(config_reload_tx),
            };
            let session_store = SessionStore::new();
            let rate_limiter = RateLimiter::new();

            if let Err(e) =
                lorica_api::server::start_server(management_port, state, session_store, rate_limiter)
                    .await
            {
                error!(error = %e, "API server exited with error");
            }
        });

        // Worker monitoring loop (crash detection and restart with backoff)
        let manager = Arc::new(std::sync::Mutex::new(manager));
        let monitor_mgr = Arc::clone(&manager);
        let monitor_reload_tx = reload_bc_tx.clone();
        let monitor_seq = Arc::clone(&sequence);
        let monitor_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;

                let mut mgr = monitor_mgr.lock().unwrap();
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

                    match mgr.restart_worker(id) {
                        Ok(Some(new_fd)) => {
                            // Spawn a new per-worker channel task for the restarted worker
                            info!(worker_id = id, reason = log_msg, "worker restarted, reconnecting channel");
                            match unsafe { CommandChannel::from_raw_fd(new_fd.into_raw_fd()) } {
                                Ok(mut channel) => {
                                    let mut rx = monitor_reload_tx.subscribe();
                                    let seq = Arc::clone(&monitor_seq);
                                    tokio::spawn(async move {
                                        let mut timer = tokio::time::interval(Duration::from_secs(5));
                                        timer.tick().await;
                                        loop {
                                            tokio::select! {
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
                                                    let s = seq.fetch_add(1, Ordering::Relaxed);
                                                    let cmd = Command::new(CommandType::Heartbeat, s);
                                                    let start = Instant::now();
                                                    if channel.send(&cmd).await.is_ok() {
                                                        match channel.recv::<Response>().await {
                                                            Ok(_) => info!(worker_id = id, latency_ms = start.elapsed().as_millis() as u64, "heartbeat ok"),
                                                            Err(e) => warn!(worker_id = id, error = %e, "heartbeat failed"),
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    });
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
        manager.lock().unwrap().shutdown_all();
        api_handle.abort();
        monitor_handle.abort();
    });
}

// ---------------------------------------------------------------------------
// Worker mode (Unix only): receives FDs from supervisor, runs proxy engine
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn run_worker(id: u32, cmd_fd: i32, data_dir: &str) {
    use lorica_command::{Command, CommandChannel, CommandType, Response};
    use lorica_core::server::Fds;
    use lorica_worker::fd_passing;

    info!(worker_id = id, cmd_fd = cmd_fd, "worker starting");

    // Receive listening FDs from supervisor via SCM_RIGHTS
    let fd_pairs = match fd_passing::recv_listener_fds(cmd_fd) {
        Ok(pairs) => pairs,
        Err(e) => {
            error!(error = %e, "worker failed to receive listener FDs");
            std::process::exit(1);
        }
    };

    info!(
        worker_id = id,
        listener_count = fd_pairs.len(),
        "received listener FDs"
    );

    // Build the Fds table for lorica-core
    let mut fds = Fds::new();
    let mut listener_addrs: Vec<String> = Vec::new();
    for (fd, addr) in &fd_pairs {
        fds.add(addr.clone(), *fd);
        listener_addrs.push(addr.clone());
        info!(worker_id = id, addr = %addr, fd = fd, "registered listener FD");
    }

    // Open the configuration database (read-only access via WAL mode)
    let data_dir = PathBuf::from(data_dir);
    let db_path = data_dir.join("lorica.db");
    let store = match ConfigStore::open(&db_path, None) {
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

    // Load initial proxy configuration
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
            error!(error = %e, "worker failed to load proxy configuration");
            std::process::exit(1);
        }
    });

    // Start the command channel listener in a background thread
    // (the proxy server's run_forever blocks the main thread)
    let cmd_store = Arc::clone(&store);
    let cmd_config = Arc::clone(&proxy_config);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to create command channel runtime");
        rt.block_on(async move {
            // Create the command channel from the socketpair FD
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
                        match reload_proxy_config(&cmd_store, &cmd_config).await {
                            Ok(()) => {
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
                    CommandType::Unspecified => {
                        warn!(worker_id = id, "received unspecified command");
                    }
                }
            }
        });
    });

    // Build the proxy service
    let lorica_proxy = LoricaProxy::new(
        Arc::clone(&proxy_config),
        Arc::clone(&log_buffer),
        Arc::clone(&active_connections),
    );

    let server_conf = Arc::new(lorica_core::server::configuration::ServerConf::default());
    let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);

    for addr in &listener_addrs {
        proxy_service.add_tcp(addr);
    }

    info!(worker_id = id, "starting proxy engine");

    let mut server =
        lorica_core::server::Server::new(None).expect("failed to create proxy server");
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

        // Open the configuration database
        let db_path = data_dir.join("lorica.db");
        let store = match ConfigStore::open(&db_path, None) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to open configuration database");
                std::process::exit(1);
            }
        };

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

        let store = Arc::new(Mutex::new(store));
        let log_buffer = Arc::new(LogBuffer::new(10_000));
        let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));

        if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
            error!(error = %e, "failed to load initial proxy configuration");
            std::process::exit(1);
        }

        // Start the HTTP proxy service
        let lorica_proxy = LoricaProxy::new(
            Arc::clone(&proxy_config),
            Arc::clone(&log_buffer),
            Arc::clone(&active_connections),
        );
        let server_conf = Arc::new(lorica_core::server::configuration::ServerConf::default());
        let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
        proxy_service.add_tcp(&format!("0.0.0.0:{}", cli.http_port));

        info!(port = cli.http_port, "HTTP proxy listener configured");

        // Add TLS listener if any certificates are available
        let tls_dir = data_dir.join("tls");
        let https_port = cli.https_port;
        {
            let s = store.lock().await;
            let certs = s.list_certificates().unwrap_or_default();
            if let Some(cert) = certs.first() {
                if let Err(e) = std::fs::create_dir_all(&tls_dir) {
                    warn!(error = %e, "failed to create TLS directory");
                } else {
                    let cert_path = tls_dir.join("server.crt");
                    let key_path = tls_dir.join("server.key");
                    if std::fs::write(&cert_path, &cert.cert_pem).is_ok()
                        && std::fs::write(&key_path, &cert.key_pem).is_ok()
                        && restrict_key_permissions(&key_path)
                    {
                        match lorica_core::listeners::tls::TlsSettings::intermediate(
                            cert_path.to_str().unwrap(),
                            key_path.to_str().unwrap(),
                        ) {
                            Ok(mut tls_settings) => {
                                tls_settings.enable_h2();
                                proxy_service.add_tls_with_settings(
                                    &format!("0.0.0.0:{https_port}"),
                                    None,
                                    tls_settings,
                                );
                                info!(port = https_port, domain = %cert.domain, "HTTPS proxy listener configured");
                            }
                            Err(e) => {
                                warn!(error = %e, "failed to create TLS settings");
                            }
                        }
                    }
                }
            }
        }

        // Create config reload channel so API mutations can trigger proxy reload
        let (config_reload_tx, mut config_reload_rx) = tokio::sync::watch::channel(0u64);

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let management_port = cli.management_port;
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store.clone(),
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                config_reload_tx: Some(config_reload_tx),
            };
            let session_store = SessionStore::new();
            let rate_limiter = RateLimiter::new();

            if let Err(e) =
                lorica_api::server::start_server(management_port, state, session_store, rate_limiter)
                    .await
            {
                error!(error = %e, "API server exited with error");
            }
        });

        // Background task: reload proxy config when API signals a change
        let reload_store = Arc::clone(&store);
        let reload_config = Arc::clone(&proxy_config);
        let _reload_handle = tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                if let Err(e) = reload_proxy_config(&reload_store, &reload_config).await {
                    tracing::error!(error = %e, "failed to reload proxy configuration");
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
            health::health_check_loop(health_store, health_config, health_interval).await;
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

        api_handle.abort();
        health_handle.abort();

        // Clean up TLS key material from disk
        cleanup_tls_files(&tls_dir);
    });
}

/// Remove TLS key material from disk on shutdown.
fn cleanup_tls_files(tls_dir: &std::path::Path) {
    for name in &["server.key", "server.crt"] {
        let path = tls_dir.join(name);
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                warn!(error = %e, path = %path.display(), "failed to remove TLS file on shutdown");
            } else {
                info!(path = %path.display(), "removed TLS file on shutdown");
            }
        }
    }
}

/// Restrict private key file permissions (owner-only read on Unix).
fn restrict_key_permissions(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!(error = %e, path = %path.display(), "failed to restrict key file permissions");
            return false;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    true
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
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

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        warn!("Received Ctrl+C");
    }
}
