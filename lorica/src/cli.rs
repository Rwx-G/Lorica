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

/// How many worker processes to run.
///
/// Parsed from `--workers`: `0` (the dev default) keeps single-process
/// mode; `auto` (the packaged default, so the hot-upgrade handoff is a
/// real multi-process swap - audit H1) runs one worker per CPU core; a
/// positive integer runs exactly that many.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Workers {
    /// Single-process mode (`--workers 0`).
    Single,
    /// One worker per CPU core (`--workers auto`).
    Auto,
    /// A fixed worker count (`--workers N`, N >= 1).
    Fixed(usize),
}

impl Workers {
    /// True when Lorica runs as a supervisor with separate worker
    /// processes (the only mode where a hot binary upgrade can hand off
    /// listening sockets to a new supervisor).
    pub(crate) fn is_multi_process(self) -> bool {
        !matches!(self, Workers::Single)
    }

    /// Concrete worker count: `0` for single-process, the CPU-core count
    /// for `auto`, or the fixed value.
    pub(crate) fn resolved(self) -> usize {
        match self {
            Workers::Single => 0,
            Workers::Auto => lorica_worker::manager::WorkerConfig::default_worker_count(),
            Workers::Fixed(n) => n,
        }
    }
}

/// `--workers` value parser: `auto`, `0`, or a positive integer.
fn parse_workers(s: &str) -> Result<Workers, String> {
    if s.eq_ignore_ascii_case("auto") {
        return Ok(Workers::Auto);
    }
    match s.parse::<usize>() {
        Ok(0) => Ok(Workers::Single),
        Ok(n) => Ok(Workers::Fixed(n)),
        Err(_) => Err(format!("expected `auto`, `0`, or a positive integer, got `{s}`")),
    }
}

#[derive(Parser, Debug, Clone)]
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

    /// Number of worker processes: `auto` (one per CPU core), `0`
    /// (single-process mode, the default), or a positive integer.
    #[arg(long, default_value = "0", value_parser = parse_workers)]
    pub(crate) workers: Workers,

    /// Internal: set only when an outgoing supervisor exec's this process
    /// during a hot upgrade (Story 8.4). Adopts the inherited listening
    /// sockets from the upgrade transfer socket instead of binding fresh
    /// ones. Operators never pass this directly; it is hidden from help.
    #[arg(long, hide = true)]
    pub(crate) hot_upgrade: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
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
    /// Upload a new signed `lorica` binary to the running instance and
    /// trigger a zero-downtime hot upgrade (Story 8.4).
    Upgrade {
        /// Path to the new `lorica` executable to install.
        #[arg(long)]
        binary: String,

        /// Path to the detached Ed25519 signature (128 hex chars).
        /// Defaults to `<binary>.sig`.
        #[arg(long)]
        signature: Option<String>,

        /// Admin username
        #[arg(long, default_value = "admin")]
        user: String,

        /// Admin password
        #[arg(long)]
        password: String,
    },
}

impl Cli {
    /// Reconstruct the argv for a hot-upgrade child supervisor from this
    /// process's live CLI (audit M2). Deriving it from `self` rather than
    /// a hand-copied subset of scalar fields means a new runtime-affecting
    /// flag is inherited by the child by editing this one method (co-located
    /// with the struct), not by remembering to touch a snapshot block in
    /// `supervisor.rs`. `staged_binary` becomes `argv[0]`; `resolved_workers`
    /// is the concrete worker count the parent already resolved (so the
    /// child does not re-resolve `auto` to a possibly different core count);
    /// `--hot-upgrade` is always set so the child adopts the inherited
    /// listening sockets.
    pub(crate) fn hot_upgrade_argv(&self, staged_binary: &str, resolved_workers: usize) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            staged_binary.to_string(),
            "--data-dir".to_string(),
            self.data_dir.clone(),
            "--log-level".to_string(),
            self.log_level.clone(),
            "--log-format".to_string(),
            self.log_format.clone(),
            "--management-port".to_string(),
            self.management_port.to_string(),
            "--http-port".to_string(),
            self.http_port.to_string(),
            "--https-port".to_string(),
            self.https_port.to_string(),
            "--workers".to_string(),
            resolved_workers.to_string(),
            "--hot-upgrade".to_string(),
        ];
        if let Some(ref log_file) = self.log_file {
            argv.push("--log-file".to_string());
            argv.push(log_file.clone());
        }
        if let Some(ref crl) = self.upstream_crl_file {
            argv.push("--upstream-crl-file".to_string());
            argv.push(crl.clone());
        }
        argv
    }
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
        workers = ?cli.workers,
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

/// Implementation of the `upgrade` subcommand: uploads a new signed
/// `lorica` binary plus its detached Ed25519 signature to the running
/// instance's management API, which verifies, stages, and (in supervisor
/// mode) triggers the zero-downtime hot upgrade (Story 8.4).
///
/// The multipart body is assembled by hand rather than via reqwest's
/// `multipart` feature so no extra cargo feature (and its transitive
/// deps) is pulled in just for one upload. Mirrors `run_unban`'s
/// login-then-call flow against the localhost management API.
pub(crate) fn run_upgrade(
    port: u16,
    binary: String,
    signature: Option<String>,
    user: String,
    password: String,
) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    rt.block_on(async {
        let signature_path: String = signature.unwrap_or_else(|| format!("{binary}.sig"));

        let binary_bytes: Vec<u8> = match std::fs::read(&binary) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Cannot read binary {binary}: {e}");
                std::process::exit(1);
            }
        };
        let signature_hex: String = match std::fs::read_to_string(&signature_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                eprintln!("Cannot read signature {signature_path}: {e}");
                std::process::exit(1);
            }
        };

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build()
            .expect("HTTP client");

        // Login (the upgrade endpoint is behind require_auth).
        let login_url = format!("http://127.0.0.1:{port}/api/v1/auth/login");
        match client
            .post(&login_url)
            .json(&serde_json::json!({ "username": user, "password": password }))
            .send()
            .await
        {
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

        // Hand-rolled multipart/form-data body: `binary` (raw bytes) +
        // `signature` (hex text), matching the axum Multipart extractor.
        let boundary = "----loricahotupgradeboundary7f3a";
        let mut body: Vec<u8> = Vec::with_capacity(binary_bytes.len() + 512);
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"binary\"; \
                 filename=\"lorica\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&binary_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(signature_hex.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());

        println!("Uploading {} ({} bytes) for hot upgrade...", binary, binary_bytes.len());
        let upgrade_url = format!("http://127.0.0.1:{port}/api/v1/system/upgrade");
        match client
            .post(&upgrade_url)
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body)
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                println!("Upgrade accepted: {body}");
                // Report honestly whether a live handoff actually started
                // or the binary was only staged (audit H1). The server
                // returns `data.handoff` = triggered | staged_only |
                // trigger_unavailable.
                let handoff = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| {
                        v.get("data")
                            .and_then(|d| d.get("handoff"))
                            .and_then(|h| h.as_str())
                            .map(str::to_string)
                    });
                match handoff.as_deref() {
                    Some("triggered") => println!(
                        "The binary is verified and staged; the supervisor is performing the \
                         zero-downtime handoff. Watch the journal for the drain/rollback result."
                    ),
                    Some("staged_only") => println!(
                        "NOTE: this instance runs in single-process mode, so no live handoff was \
                         performed. The binary is staged and will take effect on the next restart. \
                         Start Lorica with `--workers auto` (the packaged systemd unit does) to \
                         get a true zero-downtime upgrade."
                    ),
                    Some("trigger_unavailable") => println!(
                        "NOTE: the binary is staged but the handoff signal could not be delivered \
                         (an upgrade may already be in progress). Retry once it settles; the staged \
                         binary is in place."
                    ),
                    _ => println!(
                        "The binary is verified and staged. Watch the journal for the handoff result."
                    ),
                }
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                eprintln!("Upgrade rejected ({status}): {body}");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Upgrade request failed: {e}");
                std::process::exit(1);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_workers_accepts_auto_zero_and_positive() {
        assert_eq!(parse_workers("auto"), Ok(Workers::Auto));
        assert_eq!(parse_workers("AUTO"), Ok(Workers::Auto));
        assert_eq!(parse_workers("0"), Ok(Workers::Single));
        assert_eq!(parse_workers("4"), Ok(Workers::Fixed(4)));
        assert!(parse_workers("-1").is_err());
        assert!(parse_workers("many").is_err());
    }

    #[test]
    fn workers_multi_process_and_resolution() {
        assert!(!Workers::Single.is_multi_process());
        assert!(Workers::Auto.is_multi_process());
        assert!(Workers::Fixed(2).is_multi_process());
        assert_eq!(Workers::Single.resolved(), 0);
        assert_eq!(Workers::Fixed(3).resolved(), 3);
        assert!(Workers::Auto.resolved() >= 1);
    }

    #[test]
    fn hot_upgrade_argv_round_trips_through_clap() {
        // The reconstructed argv must parse back into an equivalent Cli
        // (the invariant that keeps the child config from drifting, M2).
        let original = Cli::parse_from([
            "lorica",
            "--data-dir",
            "/var/lib/lorica",
            "--log-level",
            "debug",
            "--log-format",
            "text",
            "--management-port",
            "9443",
            "--http-port",
            "8080",
            "--https-port",
            "8443",
            "--workers",
            "auto",
            "--log-file",
            "/var/log/lorica.log",
            "--upstream-crl-file",
            "/etc/lorica/crl.pem",
        ]);
        let argv = original.hot_upgrade_argv("/var/lib/lorica/upgrade/lorica.new", 8);
        assert_eq!(argv[0], "/var/lib/lorica/upgrade/lorica.new");
        assert!(argv.iter().any(|a| a == "--hot-upgrade"));

        let child = Cli::parse_from(argv);
        assert!(child.hot_upgrade);
        assert_eq!(child.data_dir, original.data_dir);
        assert_eq!(child.log_level, original.log_level);
        assert_eq!(child.log_format, original.log_format);
        assert_eq!(child.management_port, original.management_port);
        assert_eq!(child.http_port, original.http_port);
        assert_eq!(child.https_port, original.https_port);
        assert_eq!(child.log_file, original.log_file);
        assert_eq!(child.upstream_crl_file, original.upstream_crl_file);
        // `auto` is resolved to the concrete count for the child.
        assert_eq!(child.workers, Workers::Fixed(8));
    }
}
