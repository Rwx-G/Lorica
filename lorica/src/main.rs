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
use clap::{Parser, Subcommand};
use lorica_api::logs::LogBuffer;
use lorica_api::middleware::auth::SessionStore;
use lorica_api::middleware::rate_limit::RateLimiter;
use lorica_api::server::AppState;
use lorica_api::system::SystemCache;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use chrono::Datelike;
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

        /// Path to upstream CRL file (passed from supervisor)
        #[arg(long)]
        upstream_crl_file: Option<String>,
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
    // Explicitly set ring as the default TLS crypto provider to avoid
    // ambiguity when both ring and aws-lc-rs are in the dependency tree
    // (pulled by bollard/kube). Ignore the error if a provider was already
    // installed (e.g. by a linked library), since that is also valid.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Worker {
            id,
            cmd_fd,
            data_dir,
            https_port,
            log_level,
            upstream_crl_file,
        }) => {
            init_logging(&log_level);
            run_worker(
                id,
                cmd_fd,
                &data_dir,
                https_port,
                upstream_crl_file.as_deref(),
            );
        }
        None => {
            init_logging(&cli.log_level);
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
        let encryption_key = lorica_config::crypto::EncryptionKey::load_or_create(&key_path).ok();
        let db_path = data_dir.join("lorica.db");
        if let Err(e) = ConfigStore::open(&db_path, encryption_key) {
            error!(error = %e, "failed to run database migrations before forking workers");
            std::process::exit(1);
        }
        info!("database migrations completed, forking workers");
    }

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
    let worker_fds: Vec<(u32, i32, RawFd)> = manager
        .workers_mut()
        .iter_mut()
        .filter_map(|w| {
            let fd = w.take_cmd_fd()?;
            Some((w.id(), w.pid().as_raw(), fd.into_raw_fd()))
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
        let log_store_sink = log_store.clone();
        tokio::spawn(async move {
            loop {
                match log_listener.accept().await {
                    Ok((stream, _)) => {
                        let sink = Arc::clone(&log_sink);
                        let store_sink = log_store_sink.clone();
                        tokio::spawn(async move {
                            let mut reader = tokio::io::BufReader::new(stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                    Ok(0) => break, // EOF - worker disconnected
                                    Ok(_) => {
                                        if let Ok(entry) = serde_json::from_str::<lorica_api::logs::LogEntry>(&line) {
                                            if let Some(ref s) = store_sink {
                                                if let Err(e) = s.insert(&entry) {
                                                    tracing::warn!(error = %e, "failed to persist access log entry");
                                                }
                                            }
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

        // Aggregated metrics from all workers (shared with API)
        let aggregated_metrics = Arc::new(lorica_api::workers::AggregatedMetrics::new());

        // Spawn a per-worker task that handles both config reload and heartbeat
        // No shared Mutex - each worker has its own channel and task
        for (worker_id, worker_pid, raw_fd) in worker_fds {
            let mut channel = match unsafe { CommandChannel::from_raw_fd(raw_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(worker_id, error = %e, "failed to create command channel");
                    continue;
                }
            };
            let mut reload_rx = reload_bc_tx.subscribe();
            let hb_seq = Arc::clone(&sequence);
            let hb_metrics = Arc::clone(&worker_metrics);
            let agg_metrics = Arc::clone(&aggregated_metrics);

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
                                        agg_metrics
                                            .update_worker(
                                                worker_id,
                                                report.cache_hits,
                                                report.cache_misses,
                                                report.active_connections,
                                                bans,
                                                ewma,
                                                backend_conns,
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
        }

        // Bug 1 fix: Create a ProxyConfig for health checks in supervisor mode.
        // The supervisor does not route traffic, but it needs a ProxyConfig to
        // resolve backend topologies for health check decisions. It also triggers
        // reload_proxy_config so the health loop sees updated backends.
        let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
        if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
            warn!(error = %e, "supervisor: failed to load initial proxy config for health checks");
        }

        // Create non-blocking alert sender (broadcast channel for proxy/health/acme -> dispatcher)
        let alert_sender = lorica_notify::AlertSender::new(256);

        // Start health check background task (runs in supervisor, not workers)
        let health_alert_sender = alert_sender.clone();
        let health_store = Arc::clone(&store);
        let health_config = Arc::clone(&proxy_config);
        let health_interval = {
            let s = store.lock().await;
            s.get_global_settings()
                .map(|gs| gs.default_health_check_interval_s as u64)
                .unwrap_or(10)
        };
        let health_handle = tokio::spawn(async move {
            // No backend_connections in supervisor - drain monitoring is per-worker
            health::health_check_loop(health_store, health_config, health_interval, None, Some(health_alert_sender)).await;
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
        let waf_log_store = log_store.clone();
        tokio::spawn(async move {
            loop {
                match waf_listener.accept().await {
                    Ok((stream, _)) => {
                        let sink = Arc::clone(&waf_event_sink);
                        let store = waf_log_store.clone();
                        tokio::spawn(async move {
                            let mut reader = tokio::io::BufReader::new(stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                                    Ok(0) => break,
                                    Ok(_) => {
                                        if let Ok(event) = serde_json::from_str::<lorica_waf::WafEvent>(&line) {
                                            if let Some(ref s) = store {
                                                let _ = s.insert_waf_event(&event);
                                            }
                                            let mut buf = sink.lock().unwrap();
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
                    info!("supervisor: IP blocklist restored as enabled");
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

        // Spawn IP blocklist auto-refresh in supervisor
        let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
            Arc::clone(&waf_engine),
            std::time::Duration::from_secs(6 * 3600),
        );

        // Create notification dispatcher from DB configs
        let notify_dispatcher = {
            let s = store.lock().await;
            build_notify_dispatcher(&s)
        };
        let notify_dispatcher = Arc::new(tokio::sync::Mutex::new(notify_dispatcher));

        // Bridge: alert_sender (broadcast) -> NotifyDispatcher (async dispatch)
        let _alert_dispatcher = lorica_notify::spawn_alert_dispatcher(
            &alert_sender,
            Arc::clone(&notify_dispatcher),
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

        // Reload proxy config, probe scheduler, and SLA configs on config changes
        let reload_store = Arc::clone(&store);
        let reload_config = Arc::clone(&proxy_config);
        let reload_probe_scheduler = Arc::clone(&probe_scheduler);
        let reload_sla_collector = Arc::clone(&sla_collector);
        let mut reload_rx = reload_bc_tx.subscribe();
        tokio::spawn(async move {
            while reload_rx.recv().await.is_ok() {
                if let Err(e) = reload_proxy_config(&reload_store, &reload_config).await {
                    tracing::error!(error = %e, "supervisor: failed to reload proxy config");
                }
                reload_probe_scheduler.reload().await;
                {
                    let s = reload_store.lock().await;
                    reload_sla_collector.load_configs(&s);
                }
            }
        });

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let api_log_store = log_store.clone();
        let management_port = cli.management_port;
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store,
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                config_reload_tx: Some(config_reload_tx),
                worker_metrics: Some(Arc::clone(&worker_metrics)),
                waf_event_buffer: Some(waf_event_buffer),
                waf_engine: Some(waf_engine),
                waf_rule_count: Some(waf_rule_count),
                acme_challenge_store: None,
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
                aggregated_metrics: Some(Arc::clone(&aggregated_metrics)),
                notification_history: {
                    let d = notify_dispatcher.lock().await;
                    Some(d.history())
                },
                log_store: api_log_store,
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
        health_handle.abort();
        monitor_handle.abort();
    });
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

    // Open the configuration database with encryption key
    let data_dir = PathBuf::from(data_dir);
    let key_path = data_dir.join("encryption.key");
    let encryption_key = lorica_config::crypto::EncryptionKey::load_or_create(&key_path).ok();
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

    // Load initial proxy configuration
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
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
                info!(count = disabled_ids.len(), "worker: WAF disabled rules restored");
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
                info!(count = custom_rules.len(), "worker: WAF custom rules restored");
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
                        lorica::reload::reload_cert_resolver(&cmd_store, &cmd_cert_resolver).await;
                        // Sync WAF blocklist state from persisted settings
                        {
                            let s = cmd_store.lock().await;
                            if let Ok(settings) = s.get_global_settings() {
                                cmd_waf_engine
                                    .ip_blocklist()
                                    .set_enabled(settings.ip_blocklist_enabled);
                            }
                        }
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
                            .unwrap()
                            .iter()
                            .map(|(addr, score)| EwmaReportEntry {
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

                        if let Err(e) = channel.send(&report).await {
                            warn!(error = %e, "failed to send metrics report");
                        }
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send metrics response");
                        }
                    }
                    CommandType::Unspecified => {
                        warn!(worker_id = id, "received unspecified command");
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
            let blocklist_engine = Arc::clone(&waf_fwd_engine);
            lorica_api::waf::spawn_blocklist_refresh(
                blocklist_engine,
                std::time::Duration::from_secs(6 * 3600),
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
                        let buf = event_buf.lock().unwrap();
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
    lorica_proxy.waf_engine = waf_engine;

    let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
        upstream_crl_file: upstream_crl_file.map(|s| s.to_string()),
        ..Default::default()
    });
    let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);

    // Register listeners - TCP for HTTP, TLS for HTTPS
    let https_suffix = format!(":{https_port}");
    for addr in &listener_addrs {
        if https_port > 0 && addr.ends_with(&https_suffix) {
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
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

        if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
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
                    info!("IP blocklist restored as enabled from settings");
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

        // Spawn IP blocklist auto-refresh (every 6 hours, matching Data-Shield update frequency)
        let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
            Arc::clone(&waf_engine),
            std::time::Duration::from_secs(6 * 3600),
        );

        // Create non-blocking alert sender and notification dispatcher
        let alert_sender = lorica_notify::AlertSender::new(256);
        let notify_dispatcher = {
            let s = store.lock().await;
            build_notify_dispatcher(&s)
        };
        let notification_history = notify_dispatcher.history();
        let notify_dispatcher = Arc::new(tokio::sync::Mutex::new(notify_dispatcher));
        let _alert_dispatcher =
            lorica_notify::spawn_alert_dispatcher(&alert_sender, Arc::clone(&notify_dispatcher));

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

        // Create shared ACME challenge store for proxy + API (internally Arc'd)
        let acme_challenge_store = lorica_api::acme::AcmeChallengeStore::new();

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
        let backend_conns = Arc::clone(&lorica_proxy.backend_connections);
        let health_backend_conns = Arc::clone(&backend_conns);
        let proxy_cache_hits = Arc::clone(&lorica_proxy.cache_hits);
        let proxy_cache_misses = Arc::clone(&lorica_proxy.cache_misses);
        let proxy_ban_list = Arc::clone(&lorica_proxy.ban_list);
        let proxy_ewma_scores = lorica_proxy.ewma_tracker.scores_ref();
        let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
            upstream_crl_file: cli.upstream_crl_file.clone(),
            ..Default::default()
        });
        let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
        let mut tcp_opts = lorica_core::listeners::TcpSocketOptions::default();
        tcp_opts.so_reuseport = Some(true);
        proxy_service.add_tcp_with_settings(&format!("0.0.0.0:{}", cli.http_port), tcp_opts);

        info!(port = cli.http_port, "HTTP proxy listener configured");

        // Add TLS listener with SNI-based cert resolver (always, even with no certs yet).
        // Connections to unknown domains fail TLS handshake; when the first cert is uploaded
        // and the resolver is reloaded, TLS starts working without restart.
        let https_port = cli.https_port;
        {
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
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
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store.clone(),
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
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
            };

            // Spawn ACME certificate auto-renewal (check every 12h, renew at 30 days before expiry)
            let _acme_renewal = lorica_api::acme::spawn_renewal_task(
                state.clone(),
                std::time::Duration::from_secs(12 * 3600),
                30,
                Some(alert_sender.clone()),
            );

            let session_store = SessionStore::new();
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
        let _reload_handle = tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                if let Err(e) = reload_proxy_config(&reload_store, &reload_config).await {
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

        api_handle.abort();
        health_handle.abort();
    });
}

/// Build a NotifyDispatcher from database notification configs.
/// Run the SLA data purge if enabled and the schedule matches today.
/// Returns the day-of-month on which the last purge ran (used as guard to run once per day).
async fn run_sla_purge(
    store: &Arc<Mutex<lorica_config::ConfigStore>>,
    last_purge_day: u32,
) -> u32 {
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
