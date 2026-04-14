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

//! Phase 6 end-to-end coverage for the pipelined `MetricsRequest`
//! round-trip (WPAR-7). Exercises the worker-side handler (building
//! `MetricsReport` and replying with a `Response::MetricsReport`
//! payload) over a real `RpcEndpoint` socketpair.
//!
//! The supervisor-side dedup + aggregated-metrics update is tested
//! separately in main.rs; this file focuses on the wire contract so
//! protocol regressions surface before the integration layer.

#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use lorica_command::{
    response, BackendConnEntry, BanReportEntry, Command, CommandType, EwmaReportEntry,
    MetricsReport, RequestCountEntry, Response, RpcEndpoint, WafCountEntry,
};

fn socketpair() -> (RpcEndpoint, lorica_command::IncomingCommands, RpcEndpoint, lorica_command::IncomingCommands) {
    let (a, b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
    let (ep1, inc1) = RpcEndpoint::new(a);
    let (ep2, inc2) = RpcEndpoint::new(b);
    (ep1, inc1, ep2, inc2)
}

fn fixture_report(worker_id: u32) -> MetricsReport {
    let mut r = MetricsReport::new(worker_id, 0, 42);
    r.cache_hits = 100;
    r.cache_misses = 25;
    r.ban_entries = vec![BanReportEntry {
        ip: "10.0.0.1".into(),
        remaining_seconds: 120,
        ban_duration_seconds: 600,
    }];
    r.ewma_entries = vec![EwmaReportEntry {
        backend_address: "10.0.0.2:8080".into(),
        score_us: 1234.5,
    }];
    r.backend_conn_entries = vec![BackendConnEntry {
        backend_address: "10.0.0.2:8080".into(),
        connections: 7,
    }];
    r.request_entries = vec![RequestCountEntry {
        route_id: "r1".into(),
        status_code: 200,
        count: 500,
    }];
    r.waf_entries = vec![WafCountEntry {
        category: "SqlInjection".into(),
        action: "Block".into(),
        count: 2,
    }];
    r
}

fn spawn_mock_worker(
    endpoint: RpcEndpoint,
    mut incoming: lorica_command::IncomingCommands,
    worker_id: u32,
    delay: Option<Duration>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = &endpoint;
        while let Some(inc) = incoming.recv().await {
            match inc.command_type() {
                CommandType::MetricsRequest => {
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    let report = fixture_report(worker_id);
                    let _ = inc
                        .reply(Response::ok_with(
                            0,
                            response::Payload::MetricsReport(report),
                        ))
                        .await;
                }
                _ => {
                    let _ = inc.reply_error("unsupported").await;
                }
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_pull_rpc_roundtrip_carries_full_report() {
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let _h = spawn_mock_worker(wk_ep, wk_inc, 7, None);

    let cmd = Command::new(CommandType::MetricsRequest, 0);
    let resp = sup_ep
        .request(cmd, Duration::from_millis(500))
        .await
        .expect("rpc");

    match resp.payload {
        Some(response::Payload::MetricsReport(r)) => {
            assert_eq!(r.worker_id, 7);
            assert_eq!(r.cache_hits, 100);
            assert_eq!(r.cache_misses, 25);
            assert_eq!(r.active_connections, 42);
            assert_eq!(r.ban_entries.len(), 1);
            assert_eq!(r.ban_entries[0].ip, "10.0.0.1");
            assert_eq!(r.ewma_entries.len(), 1);
            assert_eq!(r.ewma_entries[0].backend_address, "10.0.0.2:8080");
            assert_eq!(r.backend_conn_entries.len(), 1);
            assert_eq!(r.request_entries.len(), 1);
            assert_eq!(r.request_entries[0].status_code, 200);
            assert_eq!(r.waf_entries.len(), 1);
            assert_eq!(r.waf_entries[0].category, "SqlInjection");
        }
        other => panic!("expected MetricsReport, got: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_pull_rpc_timeout_on_stuck_worker_does_not_block_others() {
    // Worker A replies promptly; worker B stalls past the timeout. A
    // scrape fanning out across both should return within ~timeout,
    // keeping A's report and losing B's. This is the key WPAR-7
    // guarantee: one stuck worker cannot stall a Prometheus scrape.
    let (sup_a, _s_inc_a, wk_a, wk_inc_a) = socketpair();
    let (sup_b, _s_inc_b, wk_b, wk_inc_b) = socketpair();
    let _ha = spawn_mock_worker(wk_a, wk_inc_a, 1, None);
    let _hb = spawn_mock_worker(wk_b, wk_inc_b, 2, Some(Duration::from_millis(2_000)));

    let per_timeout = Duration::from_millis(150);
    let start = std::time::Instant::now();
    let futures = vec![
        sup_a.request(
            Command::new(CommandType::MetricsRequest, 0),
            per_timeout,
        ),
        sup_b.request(
            Command::new(CommandType::MetricsRequest, 0),
            per_timeout,
        ),
    ];
    let results = futures_util::future::join_all(futures).await;
    let elapsed = start.elapsed();

    let mut ok = 0usize;
    let mut timed_out = 0usize;
    for r in results {
        match r {
            Ok(_) => ok += 1,
            Err(lorica_command::ChannelError::Timeout) => timed_out += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
    assert_eq!(ok, 1, "one worker should respond");
    assert_eq!(timed_out, 1, "one worker should time out");
    // Join_all is concurrent; total should be ~per_timeout, not 2x.
    assert!(
        elapsed < Duration::from_millis(400),
        "parallel dispatch must bound total runtime at roughly per-worker timeout, got {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_pull_rpc_concurrent_scrapes_can_pipeline() {
    // Same endpoint, two concurrent requests. The pipelined RPC
    // dispatches both via distinct sequence numbers; neither
    // should block the other.
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let _h = spawn_mock_worker(wk_ep, wk_inc, 3, None);

    let sup_ep = Arc::new(sup_ep);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let ep = Arc::clone(&sup_ep);
        handles.push(tokio::spawn(async move {
            let cmd = Command::new(CommandType::MetricsRequest, 0);
            ep.request(cmd, Duration::from_millis(500)).await
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 8, "all pipelined scrapes must succeed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_pull_rpc_dropped_peer_surfaces_via_per_request_timeout() {
    // Worker half closes immediately. The RPC framework does not have
    // a separate "peer closed" signal on the request path - the
    // oneshot for an in-flight request simply never resolves, so
    // callers rely on the per-request timeout to bound the wait.
    // This test documents the contract: a dead worker stalls a
    // scrape for at most `per_worker_timeout`. At the /metrics
    // handler layer the overall 1 s watchdog bounds the total.
    let (sup_ep, _sup_inc, wk_ep, _wk_inc) = socketpair();
    drop(wk_ep);

    let per_timeout = Duration::from_millis(200);
    let start = std::time::Instant::now();
    let res = sup_ep
        .request(Command::new(CommandType::MetricsRequest, 0), per_timeout)
        .await;
    let elapsed = start.elapsed();
    assert!(matches!(res, Err(lorica_command::ChannelError::Timeout) | Err(lorica_command::ChannelError::Closed)));
    assert!(
        elapsed < Duration::from_millis(800),
        "per-request timeout must bound the stall on a dead peer, got {elapsed:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_pull_rpc_dedup_on_repeated_calls_is_caller_responsibility() {
    // The protocol itself does not dedup: two successive MetricsRequest
    // RPCs issue two independent fan-outs. Dedup lives in the
    // supervisor-side coordinator closure. This test documents the
    // contract so future maintainers don't accidentally push dedup
    // into the RPC layer (which would coalesce unrelated callers too).
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let counter_in_worker = Arc::clone(&counter);
    tokio::spawn(async move {
        let _ = &wk_ep;
        let mut incoming = wk_inc;
        while let Some(inc) = incoming.recv().await {
            if inc.command_type() == CommandType::MetricsRequest {
                counter_in_worker.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let report = fixture_report(9);
                let _ = inc
                    .reply(Response::ok_with(
                        0,
                        response::Payload::MetricsReport(report),
                    ))
                    .await;
            }
        }
    });

    for _ in 0..3 {
        let _ = sup_ep
            .request(
                Command::new(CommandType::MetricsRequest, 0),
                Duration::from_millis(500),
            )
            .await
            .expect("rpc");
    }
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "protocol layer does not dedup; 3 sends -> 3 received"
    );
}
