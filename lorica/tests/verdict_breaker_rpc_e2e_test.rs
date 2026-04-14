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

//! Phase 4 + Phase 5 end-to-end coverage over a real `RpcEndpoint`
//! socketpair (no lorica binary fork): verifies the WPAR-2 verdict
//! cache and WPAR-3 breaker admission / reporting round-trip.
//!
//! The supervisor-side handlers in these tests mirror the ones in
//! `main.rs` (`handle_verdict_lookup`, `handle_verdict_push`,
//! `handle_breaker_query`, `handle_breaker_report`) but operate on a
//! small inline registry so the test is self-contained.

#![cfg(unix)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lorica_command::{
    command, response, BreakerDecision, BreakerResult, CommandType, ForwardAuthHeader,
    IncomingCommand, RpcEndpoint, Verdict, VerdictResult,
};

// ---------------------------------------------------------------------------
// Minimal supervisor-side caches
// ---------------------------------------------------------------------------

struct VerdictEntry {
    verdict: i32,
    headers: Vec<(String, String)>,
    expires_at: Instant,
}

struct VerdictCache {
    inner: DashMap<String, VerdictEntry>,
}

impl VerdictCache {
    fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }
    fn key(route: &str, cookie: &str) -> String {
        format!("{route}\0{cookie}")
    }
    fn lookup(&self, route: &str, cookie: &str) -> Option<(i32, Vec<(String, String)>, u64)> {
        let k = Self::key(route, cookie);
        let entry = self.inner.get(&k)?;
        if Instant::now() >= entry.expires_at {
            drop(entry);
            self.inner.remove(&k);
            return None;
        }
        let ttl = entry
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        Some((entry.verdict, entry.headers.clone(), ttl))
    }
    fn insert(
        &self,
        route: &str,
        cookie: &str,
        verdict: i32,
        headers: Vec<(String, String)>,
        ttl_ms: u64,
    ) {
        self.inner.insert(
            Self::key(route, cookie),
            VerdictEntry {
                verdict,
                headers,
                expires_at: Instant::now() + Duration::from_millis(ttl_ms),
            },
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BState {
    Closed,
    Open { opened_at: Instant },
    HalfOpen { in_flight: bool },
}

struct BEntry {
    state: BState,
    fails: u32,
}

struct BreakerRegistry {
    inner: DashMap<String, parking_lot::Mutex<BEntry>>,
    threshold: u32,
    cooldown: Duration,
}

impl BreakerRegistry {
    fn new(threshold: u32, cooldown: Duration) -> Self {
        Self {
            inner: DashMap::new(),
            threshold,
            cooldown,
        }
    }
    fn key(r: &str, b: &str) -> String {
        format!("{r}|{b}")
    }
    fn query(&self, r: &str, b: &str) -> BreakerDecision {
        let entry = self.inner.entry(Self::key(r, b)).or_insert_with(|| {
            parking_lot::Mutex::new(BEntry {
                state: BState::Closed,
                fails: 0,
            })
        });
        let mut g = entry.value().lock();
        match g.state {
            BState::Closed => BreakerDecision::Allow,
            BState::Open { opened_at } => {
                if opened_at.elapsed() >= self.cooldown {
                    g.state = BState::HalfOpen { in_flight: true };
                    BreakerDecision::AllowProbe
                } else {
                    BreakerDecision::Deny
                }
            }
            BState::HalfOpen { in_flight } => {
                if in_flight {
                    BreakerDecision::Deny
                } else {
                    g.state = BState::HalfOpen { in_flight: true };
                    BreakerDecision::AllowProbe
                }
            }
        }
    }
    fn report(&self, r: &str, b: &str, success: bool, was_probe: bool) {
        let entry = self.inner.entry(Self::key(r, b)).or_insert_with(|| {
            parking_lot::Mutex::new(BEntry {
                state: BState::Closed,
                fails: 0,
            })
        });
        let mut g = entry.value().lock();
        if success {
            g.fails = 0;
            if was_probe || matches!(g.state, BState::HalfOpen { .. } | BState::Open { .. }) {
                g.state = BState::Closed;
            }
        } else {
            g.fails = g.fails.saturating_add(1);
            if g.fails >= self.threshold || was_probe {
                g.state = BState::Open {
                    opened_at: Instant::now(),
                };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Supervisor loop
// ---------------------------------------------------------------------------

fn spawn_supervisor(
    endpoint: RpcEndpoint,
    mut incoming: lorica_command::IncomingCommands,
    vc: Arc<VerdictCache>,
    br: Arc<BreakerRegistry>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = &endpoint;
        while let Some(inc) = incoming.recv().await {
            match inc.command_type() {
                CommandType::VerdictLookup => handle_verdict_lookup(inc, &vc).await,
                CommandType::VerdictPush => handle_verdict_push(inc, &vc).await,
                CommandType::BreakerQuery => handle_breaker_query(inc, &br).await,
                CommandType::BreakerReport => handle_breaker_report(inc, &br).await,
                _ => {
                    let _ = inc.reply_error("unsupported").await;
                }
            }
        }
    })
}

async fn handle_verdict_lookup(inc: IncomingCommand, vc: &VerdictCache) {
    let lookup = match inc.command().payload.clone() {
        Some(command::Payload::VerdictLookup(l)) => l,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    let res = match vc.lookup(&lookup.route_id, &lookup.cookie) {
        Some((v, headers, ttl)) => VerdictResult {
            found: true,
            verdict: v,
            ttl_ms: ttl,
            response_headers: headers
                .into_iter()
                .map(|(n, v)| ForwardAuthHeader { name: n, value: v })
                .collect(),
        },
        None => VerdictResult {
            found: false,
            verdict: 0,
            ttl_ms: 0,
            response_headers: Vec::new(),
        },
    };
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            response::Payload::VerdictResult(res),
        ))
        .await;
}

async fn handle_verdict_push(inc: IncomingCommand, vc: &VerdictCache) {
    let push = match inc.command().payload.clone() {
        Some(command::Payload::VerdictPush(p)) => p,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    if push.ttl_ms > 0 && Verdict::from_i32(push.verdict) == Verdict::Allow {
        vc.insert(
            &push.route_id,
            &push.cookie,
            push.verdict,
            push.response_headers
                .into_iter()
                .map(|h| (h.name, h.value))
                .collect(),
            push.ttl_ms,
        );
    }
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

async fn handle_breaker_query(inc: IncomingCommand, br: &BreakerRegistry) {
    let q = match inc.command().payload.clone() {
        Some(command::Payload::BreakerQuery(q)) => q,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    let d = br.query(&q.route_id, &q.backend);
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            response::Payload::BreakerResult(BreakerResult {
                decision: d as i32,
            }),
        ))
        .await;
}

async fn handle_breaker_report(inc: IncomingCommand, br: &BreakerRegistry) {
    let r = match inc.command().payload.clone() {
        Some(command::Payload::BreakerReport(r)) => r,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    br.report(&r.route_id, &r.backend, r.success, r.was_probe);
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn socketpair() -> (RpcEndpoint, lorica_command::IncomingCommands, RpcEndpoint, lorica_command::IncomingCommands) {
    let (a, b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
    let (ep1, inc1) = RpcEndpoint::new(a);
    let (ep2, inc2) = RpcEndpoint::new(b);
    (ep1, inc1, ep2, inc2)
}

// ---------------------------------------------------------------------------
// Verdict cache E2E tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verdict_rpc_miss_then_hit_roundtrip() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::new());
    let br = Arc::new(BreakerRegistry::new(5, Duration::from_secs(10)));
    let _sup_handle = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc), Arc::clone(&br));

    // Miss.
    let resp = wk_ep
        .request_rpc(
            CommandType::VerdictLookup,
            command::Payload::VerdictLookup(lorica_command::VerdictLookup {
                route_id: "r".into(),
                cookie: "c".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .expect("rpc");
    match resp.payload {
        Some(response::Payload::VerdictResult(v)) => assert!(!v.found, "empty cache must miss"),
        other => panic!("unexpected payload: {:?}", other),
    }

    // Push.
    let _ = wk_ep
        .request_rpc(
            CommandType::VerdictPush,
            command::Payload::VerdictPush(lorica_command::VerdictPush {
                route_id: "r".into(),
                cookie: "c".into(),
                verdict: Verdict::Allow as i32,
                ttl_ms: 30_000,
                response_headers: vec![ForwardAuthHeader {
                    name: "Remote-User".into(),
                    value: "alice".into(),
                }],
            }),
            Duration::from_millis(500),
        )
        .await
        .expect("push rpc");

    // Hit.
    let resp = wk_ep
        .request_rpc(
            CommandType::VerdictLookup,
            command::Payload::VerdictLookup(lorica_command::VerdictLookup {
                route_id: "r".into(),
                cookie: "c".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .expect("rpc");
    match resp.payload {
        Some(response::Payload::VerdictResult(v)) => {
            assert!(v.found, "must hit after push");
            assert_eq!(Verdict::from_i32(v.verdict), Verdict::Allow);
            assert_eq!(v.response_headers.len(), 1);
            assert_eq!(v.response_headers[0].name, "Remote-User");
            assert_eq!(v.response_headers[0].value, "alice");
        }
        other => panic!("unexpected payload: {:?}", other),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verdict_rpc_partitions_by_route() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::new());
    let br = Arc::new(BreakerRegistry::new(5, Duration::from_secs(10)));
    let _sup_handle = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc), Arc::clone(&br));

    let _ = wk_ep
        .request_rpc(
            CommandType::VerdictPush,
            command::Payload::VerdictPush(lorica_command::VerdictPush {
                route_id: "route-a".into(),
                cookie: "c".into(),
                verdict: Verdict::Allow as i32,
                ttl_ms: 30_000,
                response_headers: Vec::new(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

    // Lookup same cookie on a different route must miss.
    let resp = wk_ep
        .request_rpc(
            CommandType::VerdictLookup,
            command::Payload::VerdictLookup(lorica_command::VerdictLookup {
                route_id: "route-b".into(),
                cookie: "c".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    match resp.payload {
        Some(response::Payload::VerdictResult(v)) => assert!(
            !v.found,
            "route partitioning must isolate route-a's verdict from route-b"
        ),
        other => panic!("unexpected payload: {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Breaker E2E tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_rpc_opens_after_threshold() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::new());
    let br = Arc::new(BreakerRegistry::new(3, Duration::from_secs(60)));
    let _sup_handle = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc), Arc::clone(&br));

    // Initial query: Allow.
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "r".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    match resp.payload {
        Some(response::Payload::BreakerResult(r)) => {
            assert_eq!(BreakerDecision::from_i32(r.decision), BreakerDecision::Allow);
        }
        _ => panic!("unexpected payload"),
    }

    // Three failures -> Open.
    for _ in 0..3 {
        let _ = wk_ep
            .request_rpc(
                CommandType::BreakerReport,
                command::Payload::BreakerReport(lorica_command::BreakerReport {
                    route_id: "r".into(),
                    backend: "b".into(),
                    success: false,
                    was_probe: false,
                }),
                Duration::from_millis(500),
            )
            .await
            .unwrap();
    }

    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "r".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    match resp.payload {
        Some(response::Payload::BreakerResult(r)) => {
            assert_eq!(BreakerDecision::from_i32(r.decision), BreakerDecision::Deny);
        }
        _ => panic!("unexpected payload"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_rpc_probe_success_closes() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::new());
    let br = Arc::new(BreakerRegistry::new(1, Duration::from_millis(0)));
    let _sup_handle = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc), Arc::clone(&br));

    // Trip the breaker.
    let _ = wk_ep
        .request_rpc(
            CommandType::BreakerReport,
            command::Payload::BreakerReport(lorica_command::BreakerReport {
                route_id: "r".into(),
                backend: "b".into(),
                success: false,
                was_probe: false,
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

    // Next query: AllowProbe.
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "r".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    let decision = match resp.payload {
        Some(response::Payload::BreakerResult(r)) => BreakerDecision::from_i32(r.decision),
        _ => panic!("unexpected payload"),
    };
    assert_eq!(decision, BreakerDecision::AllowProbe);

    // Concurrent query: second probe is denied (single slot).
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "r".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    let decision = match resp.payload {
        Some(response::Payload::BreakerResult(r)) => BreakerDecision::from_i32(r.decision),
        _ => panic!("unexpected payload"),
    };
    assert_eq!(decision, BreakerDecision::Deny);

    // Report probe success.
    let _ = wk_ep
        .request_rpc(
            CommandType::BreakerReport,
            command::Payload::BreakerReport(lorica_command::BreakerReport {
                route_id: "r".into(),
                backend: "b".into(),
                success: true,
                was_probe: true,
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

    // Next query: Closed -> Allow.
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "r".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    let decision = match resp.payload {
        Some(response::Payload::BreakerResult(r)) => BreakerDecision::from_i32(r.decision),
        _ => panic!("unexpected payload"),
    };
    assert_eq!(decision, BreakerDecision::Allow);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn breaker_rpc_isolates_routes() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::new());
    let br = Arc::new(BreakerRegistry::new(1, Duration::from_secs(60)));
    let _sup_handle = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc), Arc::clone(&br));

    let _ = wk_ep
        .request_rpc(
            CommandType::BreakerReport,
            command::Payload::BreakerReport(lorica_command::BreakerReport {
                route_id: "route-a".into(),
                backend: "b".into(),
                success: false,
                was_probe: false,
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

    // route-a is Open.
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "route-a".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    let d = match resp.payload {
        Some(response::Payload::BreakerResult(r)) => BreakerDecision::from_i32(r.decision),
        _ => panic!(),
    };
    assert_eq!(d, BreakerDecision::Deny);

    // route-b with same backend is Closed.
    let resp = wk_ep
        .request_rpc(
            CommandType::BreakerQuery,
            command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                route_id: "route-b".into(),
                backend: "b".into(),
            }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    let d = match resp.payload {
        Some(response::Payload::BreakerResult(r)) => BreakerDecision::from_i32(r.decision),
        _ => panic!(),
    };
    assert_eq!(d, BreakerDecision::Allow);
}
