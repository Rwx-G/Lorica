//! OpenTelemetry tracing integration (feature-gated).
//!
//! Compiled only when `--features otel` is enabled. Without the feature,
//! every function here is a no-op so call sites do not need their own
//! `#[cfg(feature = "otel")]` gates.
//!
//! The transport, endpoint, service name and sampling ratio are wired
//! from `GlobalSettings` (story 1.2) and consumed by `init()` below
//! before the worker pool boots. `shutdown()` is called from the
//! supervisor drain hook (story 1.6) so in-flight spans flush before
//! the process exits.

/// OTLP transport protocol selector.
///
/// Mirrors the three wire formats the OpenTelemetry collector accepts.
/// `HttpProto` is the interop default (Tempo, Jaeger v2, Datadog agent
/// all accept it). `Grpc` is preferred for high-volume deployments.
/// `HttpJson` is useful for quick debugging with tools like `curl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    Grpc,
    HttpProto,
    HttpJson,
}

impl OtlpProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            OtlpProtocol::Grpc => "grpc",
            OtlpProtocol::HttpProto => "http-proto",
            OtlpProtocol::HttpJson => "http-json",
        }
    }
}

/// Runtime configuration for the OTLP exporter, derived from
/// `GlobalSettings` at startup and frozen for the life of the process.
///
/// A config change (endpoint, protocol, service name, sampling ratio)
/// triggers a full OTel shutdown + re-init on the next reload.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    pub endpoint: String,
    pub protocol: OtlpProtocol,
    pub service_name: String,
    pub sampling_ratio: f64,
}

#[cfg(feature = "otel")]
mod imp {
    //! Real implementation; compiled only when `otel` is enabled.

    use super::{OtelConfig, OtlpProtocol};

    /// Initialise the global OpenTelemetry tracer provider with an
    /// OTLP exporter. Returns `Ok(())` on success; on failure the
    /// caller should log and continue without tracing rather than
    /// abort startup (tracing is observability, not a critical path).
    pub fn init(_cfg: &OtelConfig) -> Result<(), String> {
        // Wired in story 1.2 once GlobalSettings carries the fields.
        Ok(())
    }

    /// Flush and shut down the global tracer provider. Called from
    /// the supervisor drain hook before the 10 s worker drain so
    /// in-flight spans reach the collector.
    pub fn shutdown() {
        // Wired in story 1.6.
    }

    // Silence unused-variant warnings on the enum before stories 1.2+
    // wire the config. Removed once `init` consumes `_cfg.protocol`.
    fn _keep_variants_alive() {
        let _ = OtlpProtocol::Grpc;
        let _ = OtlpProtocol::HttpProto;
        let _ = OtlpProtocol::HttpJson;
    }
}

#[cfg(not(feature = "otel"))]
mod imp {
    //! No-op stubs; compiled when `otel` is disabled.

    use super::OtelConfig;

    pub fn init(_cfg: &OtelConfig) -> Result<(), String> {
        Ok(())
    }

    pub fn shutdown() {}
}

pub use imp::{init, shutdown};
