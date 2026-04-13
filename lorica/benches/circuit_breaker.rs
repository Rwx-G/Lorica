// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Circuit breaker microbenchmarks (PERF-12 regression coverage).
//!
//! Exercises `CircuitBreaker::is_available` (read-mostly hot-path
//! filter on every healthy-backend selection) and `record_failure` /
//! `record_success` (write-on-each-response) under both single-thread
//! and multi-thread contention.
//!
//! Baselines:
//!  - is_available (closed): ~10-30 ns per call (DashMap get + read)
//!  - record_success (no state change): similar
//!  - record_failure (state change): DashMap entry + atomic update
//!  - 4-thread mix: contention should stay sub-microsecond per op
//!
//! A regression that pushes any of these into the microsecond range
//! signals a fundamental change in the breaker's data structures.

use std::sync::Arc;
use std::thread;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lorica::proxy_wiring::CircuitBreaker;

fn bench_is_available_closed(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(5, 10);
    // Pre-populate with a closed-state entry so the lookup hits.
    breaker.record_success("route-1", "10.0.0.1:80");

    c.bench_function("breaker/is_available/closed_hit", |b| {
        b.iter(|| {
            black_box(breaker.is_available(black_box("route-1"), black_box("10.0.0.1:80")));
        });
    });
}

fn bench_is_available_unknown(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(5, 10);

    c.bench_function("breaker/is_available/unknown_key", |b| {
        b.iter(|| {
            black_box(breaker.is_available(black_box("never-seen"), black_box("10.0.0.1:80")));
        });
    });
}

fn bench_record_success(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(5, 10);
    breaker.record_failure("route-1", "10.0.0.1:80"); // seed an entry

    c.bench_function("breaker/record_success/known_key", |b| {
        b.iter(|| {
            breaker.record_success(black_box("route-1"), black_box("10.0.0.1:80"));
        });
    });
}

fn bench_record_failure(c: &mut Criterion) {
    let breaker = CircuitBreaker::new(u32::MAX, 10); // never trip
    breaker.record_failure("route-1", "10.0.0.1:80"); // seed

    c.bench_function("breaker/record_failure/known_key", |b| {
        b.iter(|| {
            breaker.record_failure(black_box("route-1"), black_box("10.0.0.1:80"));
        });
    });
}

fn bench_mixed_contention_4_threads(c: &mut Criterion) {
    let mut group = c.benchmark_group("breaker/mixed_4_threads");
    group.throughput(Throughput::Elements(4));

    group.bench_function("is_available_x_record_success", |b| {
        b.iter_custom(|iters| {
            let breaker = Arc::new(CircuitBreaker::new(u32::MAX, 10));
            breaker.record_success("route-1", "10.0.0.1:80");

            let start = std::time::Instant::now();
            let handles: Vec<_> = (0..4)
                .map(|tid| {
                    let breaker = Arc::clone(&breaker);
                    thread::spawn(move || {
                        let route = "route-1";
                        let backend = "10.0.0.1:80";
                        for _ in 0..iters {
                            if tid % 2 == 0 {
                                black_box(breaker.is_available(route, backend));
                            } else {
                                breaker.record_success(route, backend);
                            }
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().expect("thread joins");
            }
            start.elapsed()
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_is_available_closed,
    bench_is_available_unknown,
    bench_record_success,
    bench_record_failure,
    bench_mixed_contention_4_threads,
);
criterion_main!(benches);
