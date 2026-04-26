// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `tracing` subscriber initialisation for the `lorica` binary.
//!
//! Wires the chosen log level + format (JSON or text) + optional rolling
//! file output, and (when the `otel` feature is on) layers a reloadable
//! `tracing_opentelemetry` bridge whose backing tracer is swapped at
//! runtime once `try_init_otel_from_settings` installs the global OTel
//! provider. Called from every entry point (`run_supervisor`,
//! `run_worker`, `run_single_process`) and the per-subcommand
//! dispatchers.

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Guard that must be held alive for the non-blocking file appender to
/// flush. Process-wide static so it lives for the whole program.
#[allow(dead_code)]
static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
    std::sync::OnceLock::new();

/// Install the global tracing subscriber.
///
/// `log_level` is the EnvFilter spec (e.g. `info`, `debug,
/// hyper=warn`). `log_format` is one of `"json"` or `"text"`.
/// `log_file` is an optional file path ; when set, the writer becomes
/// a 14-day rolling file appender + non-blocking writer (`stdout` is
/// disabled in that branch). `RUST_LOG` overrides `log_level` when
/// set, matching the standard EnvFilter convention.
pub fn init(log_level: &str, log_format: &str, log_file: Option<&str>) {
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
