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
mod proxy;
mod reload;

use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use clap::Parser;
use lorica_api::middleware::auth::SessionStore;
use lorica_api::middleware::rate_limit::RateLimiter;
use lorica_api::server::AppState;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use proxy::{LoricaProxy, ProxyConfig};
use reload::reload_proxy_config;

const DEFAULT_DATA_DIR: &str = if cfg!(unix) {
    "/var/lib/lorica"
} else {
    "./data"
};

const DEFAULT_MANAGEMENT_PORT: u16 = 9443;
const DEFAULT_HTTP_PORT: u16 = 8080;

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
}

fn init_logging(log_level: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level));

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

    // Build initial proxy config from database
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
    if let Err(e) = reload_proxy_config(&store, &proxy_config).await {
        error!(error = %e, "failed to load initial proxy configuration");
        std::process::exit(1);
    }

    // Start the HTTP proxy service using the lorica-core server framework
    let lorica_proxy = LoricaProxy::new(Arc::clone(&proxy_config));
    let server_conf = Arc::new(lorica_core::server::configuration::ServerConf::default());
    let mut proxy_service =
        lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
    proxy_service.add_tcp(&format!("0.0.0.0:{}", cli.http_port));

    info!(port = cli.http_port, "HTTP proxy listener configured");

    // Start API server (management plane)
    let api_store = Arc::clone(&store);
    let management_port = cli.management_port;
    let api_handle = tokio::spawn(async move {
        let state = AppState {
            store: api_store.clone(),
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

    // The proxy thread runs in its own process lifecycle via run_forever;
    // it handles signals internally. We just exit.
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt())
            .expect("failed to install SIGINT handler");

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
