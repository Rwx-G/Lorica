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

use clap::Parser;
use tracing::{info, warn};

const DEFAULT_DATA_DIR: &str = if cfg!(unix) {
    "/var/lib/lorica"
} else {
    "./data"
};

const DEFAULT_MANAGEMENT_PORT: u16 = 9443;

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
        "Lorica reverse proxy starting"
    );
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(&cli.log_level);
    startup_banner(&cli);

    // Wait for shutdown signal
    shutdown_signal().await;

    info!("Lorica shutting down gracefully");
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
