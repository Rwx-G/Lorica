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
use clap::Parser;
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
        "Lorica reverse proxy starting"
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(&cli.log_level);
    startup_banner(&cli);

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

    let store = Arc::new(Mutex::new(store));

    // Create shared log buffer for access log capture (10,000 entries)
    let log_buffer = Arc::new(LogBuffer::new(10_000));

    // Build initial proxy config from database
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
    if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
        error!(error = %e, "failed to load initial proxy configuration");
        std::process::exit(1);
    }

    // Start the HTTP proxy service using the lorica-core server framework
    let lorica_proxy = LoricaProxy::new(
        Arc::clone(&proxy_config),
        Arc::clone(&log_buffer),
        tokio::runtime::Handle::current(),
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

    // Start API server (management plane)
    let api_store = Arc::clone(&store);
    let api_log_buffer = Arc::clone(&log_buffer);
    let management_port = cli.management_port;
    let api_handle = tokio::spawn(async move {
        let state = AppState {
            store: api_store.clone(),
            log_buffer: api_log_buffer,
            system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
            started_at: Instant::now(),
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

    // Run the proxy engine in a dedicated thread (it blocks via run_forever)
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

    // Abort background tasks
    api_handle.abort();
    health_handle.abort();

    // Clean up TLS key material from disk
    cleanup_tls_files(&tls_dir);

    // The proxy thread runs in its own process lifecycle via run_forever;
    // it handles signals internally. We just exit.
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

/// Restrict private key file permissions (owner-only read on Unix, best-effort on Windows).
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
