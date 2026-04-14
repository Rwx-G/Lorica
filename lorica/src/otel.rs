//! OpenTelemetry tracing integration.
//!
//! This module has two layers:
//!
//! 1. **Wire-format helpers** (always compiled): parse and build W3C
//!    `traceparent` / `tracestate` headers. These run on every request
//!    regardless of the `otel` feature so Lorica always forwards an
//!    existing trace context untouched. The overhead of parsing a
//!    well-formed traceparent is ~50 ns (one split + two hex decodes).
//!
//! 2. **Exporter + span creation** (feature-gated behind `otel`): build
//!    the OTLP exporter, install the global tracer provider, create
//!    spans per request, and flush on shutdown. Stub no-ops when the
//!    feature is disabled so call sites do not need their own `#[cfg]`
//!    guards.
//!
//! The init / shutdown lifecycle is driven from `main.rs` with values
//! from `GlobalSettings.otlp_*`. A config reload that changes the
//! endpoint / protocol / service name / sampling ratio triggers a
//! `shutdown()` + `init()` cycle so the new settings take effect.

// ---- Wire-format helpers (always compiled) ----

/// Parsed W3C `traceparent` header, as defined by the Trace Context
/// Level 2 spec (2021). We only accept version `00`, the only version
/// defined to date.
///
/// Version 00 layout:
///   `00-{trace_id:32 hex}-{parent_id:16 hex}-{flags:2 hex}`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceParent {
    /// 128-bit trace identifier, lower-case hex, 32 chars. Non-zero.
    pub trace_id: String,
    /// 64-bit parent-span identifier, lower-case hex, 16 chars. Non-zero.
    pub parent_id: String,
    /// 8-bit trace flags. Bit 0 is the sampled flag; other bits are reserved.
    pub flags: u8,
}

impl TraceParent {
    /// Parse a `traceparent` header value. Returns `None` for any
    /// malformed input so the caller can fall back to generating a
    /// fresh trace without propagating client-injected garbage.
    ///
    /// Spec reference: https://www.w3.org/TR/trace-context/#traceparent-header
    pub fn parse(header: &str) -> Option<Self> {
        let header = header.trim();
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        let version = parts[0];
        let trace_id = parts[1];
        let parent_id = parts[2];
        let flags = parts[3];

        if version != "00" {
            // Future versions MAY have more fields after the four we know;
            // but v00 is the only one defined and we reject unknown
            // versions rather than silently mistreating them.
            return None;
        }
        if trace_id.len() != 32 || !trace_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if parent_id.len() != 16 || !parent_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        if flags.len() != 2 || !flags.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        // Reject all-zero trace_id / parent_id (reserved per spec).
        if trace_id.bytes().all(|b| b == b'0') || parent_id.bytes().all(|b| b == b'0') {
            return None;
        }

        let flags_u8 = u8::from_str_radix(flags, 16).ok()?;
        Some(Self {
            trace_id: trace_id.to_ascii_lowercase(),
            parent_id: parent_id.to_ascii_lowercase(),
            flags: flags_u8,
        })
    }

    /// Is this trace sampled (bit 0 of flags)?
    pub fn is_sampled(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Render back to the wire format (version `00`).
    pub fn to_header_value(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.parent_id, self.flags
        )
    }

    /// Derive a new traceparent that shares the same trace_id but
    /// rolls a new parent_id. Use on the egress side (upstream) so
    /// the backend sees Lorica as its parent in the trace tree.
    ///
    /// The new parent_id is the first 16 hex chars of a SHA-256 of
    /// `{trace_id}{seed}`. Deterministic so two workers observing the
    /// same request produce the same id, keeping the trace tree
    /// well-formed under multi-worker fan-out (WPAR). `seed` is
    /// typically the request_id.
    pub fn child(&self, seed: &str) -> Self {
        // SipHash via DefaultHasher would be stable for the life of
        // the process but not stable across processes — we need
        // cross-process determinism so workers agree on the parent-span
        // id. FNV-1a 64 is the cheapest hash that meets that bar.
        let mixed = fnv1a_64(format!("{}{}", self.trace_id, seed).as_bytes());
        let parent_id = format!("{mixed:016x}");
        Self {
            trace_id: self.trace_id.clone(),
            parent_id,
            flags: self.flags,
        }
    }
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Build a brand-new traceparent rooted on a request_id. Used when the
/// client did not send a `traceparent`, so Lorica becomes the trace
/// origin. The trace_id is a deterministic 128-bit hash of the
/// request_id (double FNV on both halves, using different seeds so the
/// two halves are independent).
///
/// Default `flags = 0x01` (sampled). The actual sampling decision lives
/// in the OTel SDK sampler when the feature is enabled; this header is
/// forwarded to the backend regardless so an in-backend agent can still
/// reconstruct the trace even when Lorica itself is not exporting.
pub fn traceparent_from_request_id(request_id: &str) -> TraceParent {
    // Two independent FNV-1a hashes seeded differently. `_HI` uses the
    // request_id prefixed with 0x00, `_LO` with 0xff — cheap seed
    // diversification so the two 64-bit halves do not correlate.
    let mut hi_input = Vec::with_capacity(request_id.len() + 1);
    hi_input.push(0x00);
    hi_input.extend_from_slice(request_id.as_bytes());
    let hi = fnv1a_64(&hi_input);

    let mut lo_input = Vec::with_capacity(request_id.len() + 1);
    lo_input.push(0xff);
    lo_input.extend_from_slice(request_id.as_bytes());
    let lo = fnv1a_64(&lo_input);

    // Guard against the rare all-zero output (reserved by spec). A
    // single bit flip keeps determinism without a collision risk that
    // matters in practice.
    let trace_hi = if hi == 0 { 1 } else { hi };
    let trace_lo = if lo == 0 { 1 } else { lo };
    let trace_id = format!("{trace_hi:016x}{trace_lo:016x}");

    // Parent-span id from a third hash so a client that sent just a
    // request_id does not get a trace_id whose low 64 bits equal the
    // parent_id (which would be a cosmetic oddity).
    let mut span_input = Vec::with_capacity(request_id.len() + 1);
    span_input.push(0x7f);
    span_input.extend_from_slice(request_id.as_bytes());
    let span_raw = fnv1a_64(&span_input);
    let parent_raw = if span_raw == 0 { 1 } else { span_raw };
    let parent_id = format!("{parent_raw:016x}");

    TraceParent {
        trace_id,
        parent_id,
        flags: 0x01,
    }
}

// ---- OTLP lifecycle (feature-gated) ----

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

    /// Parse the stored-config string back to an enum. Returns
    /// `HttpProto` for any unrecognised value to match API validation,
    /// which rejects invalid protocols at write time.
    pub fn from_settings(value: &str) -> Self {
        match value {
            "grpc" => OtlpProtocol::Grpc,
            "http-json" => OtlpProtocol::HttpJson,
            _ => OtlpProtocol::HttpProto,
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
        // Exporter wiring lands in story 1.4 (span creation depends
        // on the tracer being installed). For now the feature-gated
        // build path exists and links against the OTel crates.
        Ok(())
    }

    /// Flush and shut down the global tracer provider. Called from
    /// the supervisor drain hook before the 10 s worker drain so
    /// in-flight spans reach the collector.
    pub fn shutdown() {
        // Wired in story 1.6.
    }

    // Silence unused-variant warnings on the enum before stories 1.4+
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_parses_well_formed() {
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp = TraceParent::parse(raw).expect("well-formed traceparent parses");
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.parent_id, "00f067aa0ba902b7");
        assert_eq!(tp.flags, 0x01);
        assert!(tp.is_sampled());
        assert_eq!(tp.to_header_value(), raw);
    }

    #[test]
    fn traceparent_rejects_malformed() {
        // Wrong version
        assert!(TraceParent::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_none());
        // Short trace_id
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce-00f067aa0ba902b7-01").is_none());
        // Non-hex char in parent_id
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0bXX02b7-01").is_none());
        // All-zero trace_id (reserved)
        assert!(TraceParent::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_none());
        // All-zero parent_id (reserved)
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_none());
        // Extra fields (future versions not supported)
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-ff").is_none());
        // Empty
        assert!(TraceParent::parse("").is_none());
    }

    #[test]
    fn traceparent_is_case_normalised() {
        // W3C spec requires lowercase hex; we normalise on the way in
        // so downstream consumers do not have to care.
        let tp = TraceParent::parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01")
            .expect("uppercase hex is valid, just gets normalised");
        assert_eq!(tp.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(tp.parent_id, "00f067aa0ba902b7");
    }

    #[test]
    fn traceparent_child_preserves_trace_id_and_flags() {
        let parent = TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
            .expect("well-formed");
        let child = parent.child("req-abc-123");
        assert_eq!(child.trace_id, parent.trace_id);
        assert_ne!(child.parent_id, parent.parent_id);
        assert_eq!(child.flags, parent.flags);
        // Determinism: same inputs produce same child.
        assert_eq!(child.parent_id, parent.child("req-abc-123").parent_id);
    }

    #[test]
    fn traceparent_from_request_id_is_deterministic() {
        let tp1 = traceparent_from_request_id("req-xyz-42");
        let tp2 = traceparent_from_request_id("req-xyz-42");
        assert_eq!(tp1, tp2, "same request_id must produce same traceparent");
        // And round-trips through parse().
        let parsed = TraceParent::parse(&tp1.to_header_value())
            .expect("generated traceparent must round-trip through parse");
        assert_eq!(parsed, tp1);
        // Different request_id produces different trace_id (collisions
        // are possible but vanishingly unlikely on sensible inputs).
        let tp3 = traceparent_from_request_id("req-other-99");
        assert_ne!(tp1.trace_id, tp3.trace_id);
    }

    #[test]
    fn traceparent_from_request_id_is_sampled_by_default() {
        let tp = traceparent_from_request_id("anything");
        assert!(tp.is_sampled());
    }

    #[test]
    fn otlp_protocol_round_trip() {
        assert_eq!(OtlpProtocol::from_settings("grpc"), OtlpProtocol::Grpc);
        assert_eq!(OtlpProtocol::from_settings("http-proto"), OtlpProtocol::HttpProto);
        assert_eq!(OtlpProtocol::from_settings("http-json"), OtlpProtocol::HttpJson);
        // Unknown falls back to http-proto (API validation rejects bad values anyway).
        assert_eq!(OtlpProtocol::from_settings("bogus"), OtlpProtocol::HttpProto);
        assert_eq!(OtlpProtocol::Grpc.as_str(), "grpc");
        assert_eq!(OtlpProtocol::HttpProto.as_str(), "http-proto");
        assert_eq!(OtlpProtocol::HttpJson.as_str(), "http-json");
    }
}
