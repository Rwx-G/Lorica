// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! OpenTelemetry hot-path microbenchmarks (v1.4.0 stories 1.7 / 1.4c).
//!
//! Measures the per-request overhead of the always-on W3C trace
//! context machinery on the proxy hot path. The OTel-bridge code
//! (story 1.4c) is exercised through the regular `#[instrument]`
//! attributes on the proxy hooks; benchmarking it in isolation here
//! would require standing up a tracing subscriber + the bridge layer
//! per iteration, which is not representative of steady-state
//! behaviour. The TESTING-GUIDE Jaeger walk-through is the right
//! venue for end-to-end OTel overhead measurements.
//!
//! ## Running
//!
//! ```bash
//! # Baseline: no OTel feature, just the W3C wire-format helpers.
//! cargo bench --bench otel_overhead
//!
//! # With the feature (no behaviour change for these primitives —
//! # they are always on regardless of the feature):
//! cargo bench --bench otel_overhead --features otel
//! ```
//!
//! ## Budget
//!
//! W3C traceparent capture + outgoing serialisation runs on every
//! request regardless of the `otel` feature. Total budget per
//! request: < 500 ns for the wire-format steps. Numbers reported in
//! the v1.4.0 release notes (CHANGELOG) come from this bench.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lorica::otel::{traceparent_from_request_id, TraceParent};

fn bench_traceparent_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("otel_traceparent");
    group.throughput(Throughput::Elements(1));

    // Well-formed header: the common case when the client is part of
    // an already-instrumented service mesh.
    let well_formed = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    group.bench_function("parse_valid", |b| {
        b.iter(|| {
            black_box(TraceParent::parse(black_box(well_formed)));
        });
    });

    // Malformed header: rejected by the length / hex-char guards. The
    // reject path is what a misbehaving client forces on us so it
    // must stay cheap.
    let malformed = "00-4bf92f3577b34da6a3ce-invalid-01";
    group.bench_function("parse_malformed", |b| {
        b.iter(|| {
            black_box(TraceParent::parse(black_box(malformed)));
        });
    });

    // Fresh-trace synthesis from request_id: the path taken when the
    // client did not send a traceparent. Hits FNV-1a 64 three times
    // (trace_id high, trace_id low, parent_id) plus hex formatting.
    group.bench_function("synthesise_from_request_id", |b| {
        b.iter(|| {
            black_box(traceparent_from_request_id(black_box("req-1f4a2b3c")));
        });
    });

    // Deriving a child traceparent (preserving trace_id, rolling
    // parent_id) via FNV-1a 64 of the combined string. Runs on every
    // request that arrives with a valid client traceparent.
    let parent = TraceParent::parse(well_formed).expect("valid traceparent");
    group.bench_function("child_from_parent", |b| {
        b.iter(|| {
            black_box(parent.child(black_box("req-1f4a2b3c")));
        });
    });

    // Wire-format serialisation on egress. Runs once per request when
    // injecting the outgoing traceparent into the upstream request.
    group.bench_function("to_header_value", |b| {
        b.iter(|| {
            black_box(parent.to_header_value());
        });
    });

    group.finish();
}

fn bench_full_request_traceparent(c: &mut Criterion) {
    // Aggregate cost of the W3C touch-points a single request
    // incurs end-to-end: parse incoming, derive outgoing (or
    // synthesise from request_id), serialise for upstream injection.
    // Spans (#[instrument] + bridge export) are a separate cost
    // measured via the Jaeger E2E harness; we benchmark only the
    // wire-format work here because it is the only part that runs
    // on every request unconditionally.
    let mut group = c.benchmark_group("otel_per_request");
    group.throughput(Throughput::Elements(1));

    let incoming_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let request_id = "req-1f4a2b3c";

    group.bench_function("with_client_traceparent", |b| {
        b.iter(|| {
            let incoming = TraceParent::parse(black_box(incoming_header));
            let outgoing = incoming
                .as_ref()
                .map(|p| p.child(black_box(request_id)))
                .unwrap_or_else(|| traceparent_from_request_id(black_box(request_id)));
            let _ = black_box(outgoing.to_header_value());
        });
    });

    group.bench_function("synthesised_trace", |b| {
        b.iter(|| {
            let outgoing = traceparent_from_request_id(black_box(request_id));
            let _ = black_box(outgoing.to_header_value());
        });
    });

    group.finish();
}

criterion_group!(benches, bench_traceparent_parse, bench_full_request_traceparent);
criterion_main!(benches);
