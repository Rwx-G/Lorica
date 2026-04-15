// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! End-to-end coverage for `lorica::bot::rpc_cache_check` and
//! `lorica::bot::rpc_cache_push` over a real `RpcEndpoint`
//! socketpair. These wrappers prefix the route_id with `bot\0<ip_prefix>`
//! before calling the shared VerdictLookup/VerdictPush RPC protocol,
//! so a regression in the prefix format would silently make every
//! RPC call miss, degrading bot-protection to "challenge every
//! request" under worker mode. The tests verify:
//!   - push -> lookup round-trip hits
//!   - lookup returns None when the cache is empty (graceful miss)
//!   - a Deny verdict on the supervisor side is returned as None
//!     (the bot wrapper treats anything other than Allow as a miss)
//!   - IP-prefix partitioning: same cookie + route but different
//!     /24 (v4) or /64 (v6) prefixes do not collide
//!   - an unresponsive supervisor (timeout) fails open (returns None)

#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use lorica::bot::{rpc_cache_check, rpc_cache_push};
use lorica::proxy_wiring::VerdictCacheEngine;
use lorica_challenge::IpPrefix;
use lorica_command::{
    command, response, CommandType, ForwardAuthHeader, IncomingCommand, RpcEndpoint, Verdict,
    VerdictResult,
};

// ---------------------------------------------------------------------------
// Minimal supervisor-side cache (mirrors main.rs's handler shape).
// ---------------------------------------------------------------------------

struct VerdictEntry {
    verdict: i32,
    expires_at: Instant,
}

#[derive(Default)]
struct VerdictCache {
    inner: DashMap<String, VerdictEntry>,
}

impl VerdictCache {
    fn key(route: &str, cookie: &str) -> String {
        format!("{route}\0{cookie}")
    }
    fn lookup(&self, route: &str, cookie: &str) -> Option<(i32, u64)> {
        let k = Self::key(route, cookie);
        let e = self.inner.get(&k)?;
        if Instant::now() >= e.expires_at {
            drop(e);
            self.inner.remove(&k);
            return None;
        }
        let ttl = e
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        Some((e.verdict, ttl))
    }
    fn insert(&self, route: &str, cookie: &str, verdict: i32, ttl_ms: u64) {
        self.inner.insert(
            Self::key(route, cookie),
            VerdictEntry {
                verdict,
                expires_at: Instant::now() + Duration::from_millis(ttl_ms),
            },
        );
    }
}

async fn handle_lookup(inc: IncomingCommand, vc: &VerdictCache) {
    let l = match inc.command().payload.clone() {
        Some(command::Payload::VerdictLookup(l)) => l,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    let res = match vc.lookup(&l.route_id, &l.cookie) {
        Some((v, ttl)) => VerdictResult {
            found: true,
            verdict: v,
            ttl_ms: ttl,
            response_headers: Vec::<ForwardAuthHeader>::new(),
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

async fn handle_push(inc: IncomingCommand, vc: &VerdictCache) {
    let p = match inc.command().payload.clone() {
        Some(command::Payload::VerdictPush(p)) => p,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    if p.ttl_ms > 0 && Verdict::from_i32(p.verdict) == Verdict::Allow {
        vc.insert(&p.route_id, &p.cookie, p.verdict, p.ttl_ms);
    }
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

fn spawn_supervisor(
    endpoint: RpcEndpoint,
    mut inc: lorica_command::IncomingCommands,
    vc: Arc<VerdictCache>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Keep the supervisor-side endpoint alive for the lifetime
        // of the task; dropping it closes the socketpair and the
        // worker's RPC calls start timing out. Same trick as
        // `verdict_breaker_rpc_e2e_test::spawn_supervisor`.
        let _ = &endpoint;
        while let Some(cmd) = inc.recv().await {
            match cmd.command_type() {
                CommandType::VerdictLookup => handle_lookup(cmd, &vc).await,
                CommandType::VerdictPush => handle_push(cmd, &vc).await,
                _ => {
                    let _ = cmd.reply_error("unsupported").await;
                }
            }
        }
    })
}

fn socketpair() -> (
    RpcEndpoint,
    lorica_command::IncomingCommands,
    RpcEndpoint,
    lorica_command::IncomingCommands,
) {
    let (a, b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
    let (e1, i1) = RpcEndpoint::new(a);
    let (e2, i2) = RpcEndpoint::new(b);
    (e1, i1, e2, i2)
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_push_then_check_roundtrip() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::default());
    let _h = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc));

    let engine = VerdictCacheEngine::rpc(wk_ep, Duration::from_millis(500));
    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let prefix = IpPrefix::from_ip(ip);
    let route = "bot-route";
    let cookie = "cookie-abc";
    let now = 1_700_000_000_i64;
    let expires = now + 60;

    // Push: supervisor cache must hold the entry after this returns.
    rpc_cache_push(&engine, route, &prefix, cookie, expires, now).await;

    // Cache check: expect Some(absolute expires_at) close to `expires`.
    let hit = rpc_cache_check(&engine, route, &prefix, cookie, now)
        .await
        .expect("push must be visible to subsequent check");
    // `rpc_cache_check` recomputes expires_at from the supervisor's
    // remaining TTL: on fast loopback the reported expires_at should
    // land in [now, expires] (never exceed `expires`, since time only
    // moves forward), but we allow ±2s for test jitter on loaded CI.
    assert!(
        hit >= now - 2 && hit <= expires + 2,
        "expected {now}..={expires} (±2s), got {hit}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_check_empty_returns_none() {
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::default());
    let _h = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc));

    let engine = VerdictCacheEngine::rpc(wk_ep, Duration::from_millis(500));
    let prefix = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    let hit = rpc_cache_check(&engine, "r", &prefix, "c", 1_700_000_000).await;
    assert!(hit.is_none(), "empty cache must return None");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_check_ignores_non_allow_verdict() {
    // Supervisor seeded with a Deny verdict. The bot wrapper only
    // treats `Allow` as "cached cookie valid" — any other variant
    // must surface as None so the data-plane falls through to full
    // HMAC verify. A Deny cached as a hit would incorrectly short-
    // circuit the evaluator and block a request that might now pass.
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::default());

    // Seed the cache with a Deny entry under the EXACT wire key that
    // `rpc_cache_check` will query: `bot\0<route>\0<prefix_hex>` and
    // the plain cookie value.
    let route = "bot-deny-route";
    let cookie = "denied-cookie";
    let prefix = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let wire_route = {
        let mut s = String::from("bot\0");
        s.push_str(route);
        s.push('\0');
        for b in prefix.as_bytes() {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };
    vc.insert(&wire_route, cookie, Verdict::Deny as i32, 60_000);

    let _h = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc));
    let engine = VerdictCacheEngine::rpc(wk_ep, Duration::from_millis(500));

    let hit = rpc_cache_check(&engine, route, &prefix, cookie, 1_700_000_000).await;
    assert!(hit.is_none(), "Deny verdict must surface as None");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_partitions_by_ip_prefix() {
    // Two clients behind different /24 prefixes with the SAME cookie
    // and route must NOT share a verdict. This is why the wrapper
    // folds the IP prefix into the wire route_id — a collision here
    // would mean one NAT tenant's verdict bleeds to another.
    let (sup_ep, sup_inc, wk_ep, _wk_inc) = socketpair();
    let vc = Arc::new(VerdictCache::default());
    let _h = spawn_supervisor(sup_ep, sup_inc, Arc::clone(&vc));

    let engine = VerdictCacheEngine::rpc(wk_ep, Duration::from_millis(500));
    let prefix_a = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
    let prefix_b = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)));
    let route = "shared";
    let cookie = "same-cookie";
    let now = 1_700_000_000;

    rpc_cache_push(&engine, route, &prefix_a, cookie, now + 60, now).await;

    // Same cookie/route on a DIFFERENT client prefix must miss.
    let hit_b = rpc_cache_check(&engine, route, &prefix_b, cookie, now).await;
    assert!(
        hit_b.is_none(),
        "prefix partitioning breach: B saw A's entry"
    );

    // Same cookie/route on the original prefix still hits.
    let hit_a = rpc_cache_check(&engine, route, &prefix_a, cookie, now).await;
    assert!(hit_a.is_some(), "original prefix must still hit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_check_returns_none_on_rpc_timeout() {
    // The supervisor task is intentionally NOT spawned: any RPC call
    // will block waiting for a reply that never comes and time out.
    // The wrapper must fail open (return None) so the data plane
    // falls through to local verify — never DoS a request on transport
    // errors.
    let (_sup_ep, _sup_inc, wk_ep, _wk_inc) = socketpair();
    let engine = VerdictCacheEngine::rpc(wk_ep, Duration::from_millis(100));

    let prefix = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
    let hit = rpc_cache_check(&engine, "r", &prefix, "c", 1_700_000_000).await;
    assert!(hit.is_none(), "timeout must fail open (None)");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rpc_cache_local_engine_passes_through_to_sync_cache() {
    // The wrapper's `Local` branch must delegate to the in-process
    // synchronous cache. Push then check on Local round-trips without
    // touching any RPC socket.
    use lorica::bot::cache_check;

    let engine = VerdictCacheEngine::Local;
    let prefix = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)));
    let now = 1_700_000_000;
    rpc_cache_push(&engine, "r-local", &prefix, "c-local", now + 30, now).await;

    // Using the sync helper shows the write went to the process-wide
    // cache (same static that single-process mode reads from).
    assert!(cache_check("r-local", &prefix, "c-local", now).is_some());
}
