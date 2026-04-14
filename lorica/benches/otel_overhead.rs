// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! OpenTelemetry hot-path microbenchmarks (v1.4.0 story 1.7).
//!
//! Measures the per-request overhead of the OTel instrumentation on the
//! proxy hot path. Run both with and without the `otel` Cargo feature
//! to compare the two profiles; the no-feature numbers are the cost of
//! the always-on W3C header pass-through (story 1.3) plus the
//! `ActiveSpan` ZST no-ops, the feature-on numbers add real span
//! creation + attribute recording.
//!
//! ## Running
//!
//! ```bash
//! # Baseline: no OTel, no endpoint configured.
//! cargo bench --bench otel_overhead
//!
//! # With the feature built in (BoxedTracer still returns NoopSpan
//! # since no global provider is installed in the bench process):
//! cargo bench --bench otel_overhead --features otel
//! ```
//!
//! The bench deliberately does NOT install a real OTel provider — the
//! interesting question is "what is the per-request cost baked into
//! the proxy pipeline when tracing is compiled in but idle or
//! sampled-out". Real-endpoint overhead is collector-bound (BatchSpanProcessor
//! buffers + exports async) and is better measured via the
//! `tests-e2e-docker/` harness with a Jaeger collector.
//!
//! ## Budget
//!
//! Default sampling ratio is 0.1 so in steady state ~90 % of requests
//! get a `NoopSpan`. The budget for that path is "< 500 ns of
//! overhead per request". The sampled path (10 %) adds the real
//! span_builder + batch-processor enqueue, typically ~2-5 µs.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lorica::otel::{traceparent_from_request_id, ActiveSpan, TraceParent};

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

fn bench_active_span(c: &mut Criterion) {
    let mut group = c.benchmark_group("otel_active_span");
    group.throughput(Throughput::Elements(1));

    // Empty-span creation: the hot path when OTel is compiled out or
    // the global provider is not installed. Should be essentially
    // free (ZST construction when the feature is off).
    group.bench_function("empty_construction", |b| {
        b.iter(|| {
            black_box(ActiveSpan::empty());
        });
    });

    // is_recording(): called in logging() before setting the final
    // attributes. Must stay cheap on the no-op path so the guard is
    // a net win.
    let empty_span = ActiveSpan::empty();
    group.bench_function("is_recording_empty", |b| {
        b.iter(|| {
            black_box(empty_span.is_recording());
        });
    });

    // end() on an empty span: called in the final logging() hook via
    // mem::take. Path exercised on every request regardless of
    // whether OTel is active.
    group.bench_function("end_empty", |b| {
        b.iter(|| {
            let s = ActiveSpan::empty();
            s.end();
        });
    });

    // set_str / set_i64 / set_status on an empty span — the no-op
    // dispatch path. Called per-attribute in logging() so any cost
    // multiplies by ~6 attributes per request.
    group.bench_function("set_str_empty", |b| {
        b.iter(|| {
            let mut s = ActiveSpan::empty();
            s.set_str("http.request.method", "GET");
            black_box(s);
        });
    });

    group.bench_function("set_i64_empty", |b| {
        b.iter(|| {
            let mut s = ActiveSpan::empty();
            s.set_i64("http.response.status_code", 200);
            black_box(s);
        });
    });

    group.bench_function("set_status_empty", |b| {
        b.iter(|| {
            let mut s = ActiveSpan::empty();
            s.set_status(200);
            black_box(s);
        });
    });

    group.finish();
}

fn bench_full_request_overhead(c: &mut Criterion) {
    // Simulates the full OTel touch-points a single request goes
    // through: parse incoming traceparent, synthesise outgoing
    // (always), render to wire, create span, record typical
    // attributes, set status, end. This is the aggregate hot-path
    // cost that `lorica-bench` would measure at the HTTP layer minus
    // the network + TLS overhead.
    let mut group = c.benchmark_group("otel_per_request");
    group.throughput(Throughput::Elements(1));

    let incoming_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    let request_id = "req-1f4a2b3c";

    group.bench_function("end_to_end_with_client_traceparent", |b| {
        b.iter(|| {
            // 1. Parse incoming
            let incoming = TraceParent::parse(black_box(incoming_header));
            // 2. Derive outgoing
            let outgoing = incoming
                .as_ref()
                .map(|p| p.child(black_box(request_id)))
                .unwrap_or_else(|| traceparent_from_request_id(black_box(request_id)));
            // 3. Serialise for injection
            let _ = black_box(outgoing.to_header_value());
            // 4. Create span (no-op when feature off or provider not installed)
            let mut span = ActiveSpan::empty();
            // 5. Record request + response attributes
            span.set_str("http.request.method", "GET");
            span.set_str("url.path", "/api/v1/health");
            span.set_i64("http.response.status_code", 200);
            span.set_str("server.address", "example.com");
            span.set_str("network.peer.address", "10.0.0.1:8080");
            span.set_str("lorica.route_id", "route-prod-api");
            span.set_i64("lorica.latency_ms", 12);
            span.set_status(200);
            // 6. End
            span.end();
        });
    });

    group.bench_function("end_to_end_synthesised_trace", |b| {
        b.iter(|| {
            // No incoming header: synthesise from request_id.
            let outgoing = traceparent_from_request_id(black_box(request_id));
            let _ = black_box(outgoing.to_header_value());
            let mut span = ActiveSpan::empty();
            span.set_str("http.request.method", "POST");
            span.set_str("url.path", "/api/v1/submit");
            span.set_i64("http.response.status_code", 500);
            span.set_str("lorica.route_id", "route-prod-api");
            span.set_i64("lorica.latency_ms", 47);
            span.set_status(500);
            span.end();
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_traceparent_parse,
    bench_active_span,
    bench_full_request_overhead,
);
criterion_main!(benches);
