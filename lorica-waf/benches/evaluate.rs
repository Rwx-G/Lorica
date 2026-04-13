// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `WafEngine::evaluate` microbenchmarks (PERF-12 regression coverage).
//!
//! Exercises the full default CRS ruleset against three representative
//! request shapes:
//!  - "clean": short path + few headers, nothing matches (best case)
//!  - "noisy": realistic API request with many headers, still clean
//!  - "matches": payload that hits a SQLi rule (worst case path)
//!
//! Baselines (rough, wall-clock varies by host):
//!  - clean: ~5-15 us
//!  - noisy: ~30-80 us
//!  - matches: ~50-150 us (event allocation dominates)
//!
//! A regression that pushes the noisy case past 200 us at modest QPS
//! starts impacting tail latency.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use lorica_waf::{WafEngine, WafMode};

fn build_engine() -> WafEngine {
    WafEngine::new()
}

fn clean_short_request() -> (&'static str, Vec<(&'static str, &'static str)>) {
    let path = "/api/v1/health";
    let headers = vec![
        ("user-agent", "curl/8.0.0"),
        ("accept", "*/*"),
        ("host", "api.example.com"),
    ];
    (path, headers)
}

fn noisy_realistic_request() -> (&'static str, Vec<(&'static str, &'static str)>) {
    let path = "/api/v1/users/12345/profile";
    let headers = vec![
        ("user-agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
        ("accept", "application/json, text/plain, */*"),
        ("accept-encoding", "gzip, deflate, br"),
        ("accept-language", "en-US,en;q=0.9,fr;q=0.8"),
        ("authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
        ("cookie", "session=abc123; csrf=xyz789; theme=dark"),
        ("host", "api.example.com"),
        ("origin", "https://app.example.com"),
        ("referer", "https://app.example.com/dashboard"),
        ("sec-ch-ua", "\"Chromium\";v=\"118\", \"Google Chrome\";v=\"118\""),
        ("sec-ch-ua-mobile", "?0"),
        ("sec-ch-ua-platform", "\"Linux\""),
        ("sec-fetch-dest", "empty"),
        ("sec-fetch-mode", "cors"),
        ("sec-fetch-site", "same-origin"),
        ("x-request-id", "550e8400-e29b-41d4-a716-446655440000"),
        ("x-forwarded-for", "203.0.113.42, 198.51.100.7"),
    ];
    (path, headers)
}

fn matching_sqli_request() -> (&'static str, Vec<(&'static str, &'static str)>) {
    let path = "/api/v1/products";
    let headers = vec![
        ("user-agent", "sqlmap/1.7"),
        ("accept", "*/*"),
        ("host", "shop.example.com"),
    ];
    (path, headers)
}

fn bench_evaluate(c: &mut Criterion) {
    let engine = build_engine();
    let mut group = c.benchmark_group("waf_evaluate");
    group.throughput(Throughput::Elements(1));

    let (clean_path, clean_headers) = clean_short_request();
    group.bench_function("clean_short", |b| {
        b.iter(|| {
            black_box(engine.evaluate(
                black_box(WafMode::Detection),
                black_box(clean_path),
                black_box(None),
                black_box(&clean_headers),
                black_box("api.example.com"),
                black_box("10.0.0.1"),
            ));
        });
    });

    let (noisy_path, noisy_headers) = noisy_realistic_request();
    group.bench_function("noisy_realistic", |b| {
        b.iter(|| {
            black_box(engine.evaluate(
                black_box(WafMode::Detection),
                black_box(noisy_path),
                black_box(Some("page=1&size=20&sort=-updated")),
                black_box(&noisy_headers),
                black_box("api.example.com"),
                black_box("10.0.0.1"),
            ));
        });
    });

    let (sqli_path, sqli_headers) = matching_sqli_request();
    group.bench_function("matches_sqli", |b| {
        b.iter(|| {
            black_box(engine.evaluate(
                black_box(WafMode::Detection),
                black_box(sqli_path),
                black_box(Some("id=1' OR '1'='1")),
                black_box(&sqli_headers),
                black_box("shop.example.com"),
                black_box("10.0.0.1"),
            ));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
