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

use clap::{Parser, Subcommand};
use tracing::info;

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
pub(crate) struct Cli {
    /// Data directory for configuration state and database
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    pub(crate) data_dir: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    pub(crate) log_level: String,

    /// Log format: "json" (default) or "text"
    #[arg(long, default_value = "json", value_parser = clap::builder::PossibleValuesParser::new(["json", "text"]))]
    pub(crate) log_format: String,

    /// Path to a log file. When set, logs are written to this file in
    /// addition to stdout. The file is appended to (not truncated).
    #[arg(long)]
    pub(crate) log_file: Option<String>,

    /// Management port (localhost only)
    #[arg(long, default_value_t = DEFAULT_MANAGEMENT_PORT)]
    pub(crate) management_port: u16,

    /// HTTP proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTP_PORT)]
    pub(crate) http_port: u16,

    /// HTTPS proxy listen port
    #[arg(long, default_value_t = DEFAULT_HTTPS_PORT)]
    pub(crate) https_port: u16,

    /// Path to a CRL (Certificate Revocation List) file in PEM or DER format.
    /// When set, upstream server certificates are checked against this CRL.
    /// Requires a service restart after updating the CRL file.
    #[arg(long)]
    pub(crate) upstream_crl_file: Option<String>,

    /// Number of worker processes (default: number of CPU cores, 0 = single-process mode)
    #[arg(long, default_value_t = 0)]
    pub(crate) workers: usize,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
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

pub(crate) fn init_logging(log_level: &str, log_format: &str, log_file: Option<&str>) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Resolve the writer + ANSI combo once here so the subscriber
    // composition below has a single source of truth. The non-blocking
    // file path keeps its `WorkerGuard` alive in a process-wide
    // static so flushes continue until shutdown; the stdout path
    // uses ANSI colours. Daily rotation with 14-file retention
    // bounds disk usage on unattended installs.
    let (writer, ansi): (tracing_subscriber::fmt::writer::BoxMakeWriter, bool) = if let Some(path) =
        log_file
    {
        let dir = std::path::Path::new(path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("lorica.log");
        let appender = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix(filename)
            .max_log_files(14)
            .build(dir);
        let appender = match appender {
            Ok(a) => a,
            Err(e) => {
                eprintln!(
                        "warning: rolling log appender failed for {path}: {e}; falling back to non-rotating append"
                    );
                tracing_appender::rolling::never(dir, filename)
            }
        };
        let (non_blocking, guard) = tracing_appender::non_blocking(appender);
        let _ = LOG_GUARD.set(guard);
        (
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(non_blocking),
            false,
        )
    } else {
        (
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stdout),
            true,
        )
    };

    // JSON and text fmt layers have different concrete types, so
    // the whole subscriber must be built separately in each branch
    // (`Box<dyn Layer<S>>` does not satisfy the
    // `Layer<Layered<_, S>>` bound needed when the boxed layer is
    // then layered on top of another, which is the shape we would
    // need to lift the OTel bridge out of both branches). The
    // duplication is the price we pay for leaning on concrete
    // monomorphic types; each branch composes cleanly and
    // `init()` accepts the resulting `Layered` stack.
    //
    // Inside each branch, when the `otel` feature is on, we add a
    // `tracing_opentelemetry::layer` wrapped in a `reload::Layer`
    // so `otel::init` can swap the embedded `BoxedTracer` from its
    // startup-noop placeholder to a real tracer bound to the
    // freshly-installed global provider. The reload callback is
    // stored in `OTEL_RELOAD_HOOK` with its subscriber-chain type
    // parameters erased behind a `Box<dyn Fn(...)>` so the public
    // OTel API stays free of subscriber-generic plumbing.
    if log_format == "text" {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .with_ansi(ansi)
            .with_writer(writer);
        let subscriber = tracing_subscriber::Registry::default()
            .with(filter)
            .with(fmt_layer);
        #[cfg(feature = "otel")]
        {
            let noop_tracer = opentelemetry::global::tracer("lorica");
            let initial = tracing_opentelemetry::layer().with_tracer(noop_tracer);
            let (otel_bridge, handle) = tracing_subscriber::reload::Layer::new(initial);
            let hook: Box<dyn Fn(opentelemetry::global::BoxedTracer) + Send + Sync> =
                Box::new(move |tracer| {
                    let _ =
                        handle.modify(|l| *l = tracing_opentelemetry::layer().with_tracer(tracer));
                });
            let _ = lorica::otel::OTEL_RELOAD_HOOK.set(hook);
            subscriber.with(otel_bridge).init();
        }
        #[cfg(not(feature = "otel"))]
        subscriber.init();
    } else {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_target(true)
            .with_thread_ids(true)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .with_writer(writer);
        let subscriber = tracing_subscriber::Registry::default()
            .with(filter)
            .with(fmt_layer);
        #[cfg(feature = "otel")]
        {
            let noop_tracer = opentelemetry::global::tracer("lorica");
            let initial = tracing_opentelemetry::layer().with_tracer(noop_tracer);
            let (otel_bridge, handle) = tracing_subscriber::reload::Layer::new(initial);
            let hook: Box<dyn Fn(opentelemetry::global::BoxedTracer) + Send + Sync> =
                Box::new(move |tracer| {
                    let _ =
                        handle.modify(|l| *l = tracing_opentelemetry::layer().with_tracer(tracer));
                });
            let _ = lorica::otel::OTEL_RELOAD_HOOK.set(hook);
            subscriber.with(otel_bridge).init();
        }
        #[cfg(not(feature = "otel"))]
        subscriber.init();
    }
}

pub(crate) fn startup_banner(cli: &Cli) {
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

/// Implementation of the `rotate-key` subcommand: re-encrypts every
/// secret in the database under the new key file.
pub(crate) fn run_rotate_key(data_dir: &str, new_key_file: &str) {
    use lorica_config::crypto::EncryptionKey;
    use lorica_config::store::ConfigStore;

    let data_dir = PathBuf::from(data_dir);
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

/// Implementation of the `unban` subcommand: logs into the management
/// API on `port` and removes `ip` from the auto-ban list.
pub(crate) fn run_unban(port: u16, ip: String, user: String, password: String) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        // The management API is served over plaintext HTTP (see
        // lorica-api `server.rs`: `axum::serve` over a plain
        // `TcpListener`). When TLS on the management port lands
        // (backlog #20), switch the scheme below back to https and
        // restore `danger_accept_invalid_certs(true)` for the
        // self-signed startup cert.
        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("HTTP client");

        // Login
        let login_url = format!("http://127.0.0.1:{port}/api/v1/auth/login");
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
        let unban_url = format!("http://127.0.0.1:{port}/api/v1/bans/{ip}");
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
