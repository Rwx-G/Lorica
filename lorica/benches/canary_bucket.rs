// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `canary_bucket` microbenchmarks (PERF-12 regression coverage).
//!
//! Asserts that the FNV-1a-with-NUL-separator hashing introduced in
//! v1.3.0 stays in the tens-of-nanoseconds range. The function is
//! called once per request when a route has any traffic_splits
//! configured, so any regression is multiplied by RPS.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lorica::proxy_wiring::canary_bucket;

fn bench_canary_short(c: &mut Criterion) {
    let mut group = c.benchmark_group("canary_bucket");
    group.throughput(Throughput::Elements(1));
    group.bench_function("short_route_ipv4", |b| {
        b.iter(|| {
            black_box(canary_bucket(black_box("r1"), black_box("10.0.0.1")));
        });
    });
    group.bench_function("realistic_route_ipv4", |b| {
        b.iter(|| {
            black_box(canary_bucket(
                black_box("api-gateway-prod-eu-west-1"),
                black_box("203.0.113.42"),
            ));
        });
    });
    group.bench_function("realistic_route_ipv6", |b| {
        b.iter(|| {
            black_box(canary_bucket(
                black_box("api-gateway-prod-eu-west-1"),
                black_box("2001:db8:abcd:0012::1"),
            ));
        });
    });
    group.finish();
}

fn bench_canary_distribution(c: &mut Criterion) {
    // Throughput proxy for "1 hash per request". 256 distinct IPs per
    // iteration so we don't accidentally measure CPU branch
    // prediction on a single hot key.
    let ips: Vec<String> = (0..256).map(|i| format!("10.0.0.{i}")).collect();
    c.bench_function("canary_bucket/256_ips", |b| {
        b.iter(|| {
            for ip in &ips {
                black_box(canary_bucket(black_box("route-fixed"), black_box(ip)));
            }
        });
    });
}

criterion_group!(benches, bench_canary_short, bench_canary_distribution);
criterion_main!(benches);
