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
// See the License for the specific language governing permissions and
// limitations under the License.

//! Backlog #75 measurement: what the audit fan-in costs the other users
//! of `access-log.db`'s single connection.
//!
//! The control plane's own access-log writer, the dashboard audit page
//! and `verify` all take the same `Mutex<Connection>` that every
//! follower's audit push takes for one transaction of up to
//! `MAX_TELEMETRY_AUDIT` rows. This runs that mix with zero, two and
//! five followers whose pushes land on the same tick boundary, with
//! time compressed (a 1 s tick instead of the 10 s drain tick), and
//! prints the latencies. It asserts nothing: it exists to inform a
//! design decision, and the numbers depend on the machine.
//!
//! Run in release mode:
//! `cargo test --release -p lorica-api --test audit_fan_in_contention -- --ignored --nocapture`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lorica_api::audit::{
    compute_chain_hash, AuditQuery, ChainInput, FannedInAuditRow, NewAuditEntry, GENESIS_HASH,
};
use lorica_api::log_store::LogStore;
use lorica_api::logs::LogEntry;
use lorica_cluster::MAX_TELEMETRY_AUDIT;

/// Followers whose chains exist in the store before the run, whether
/// or not they push during it, so every phase verifies the same data.
const SEEDED_FOLLOWERS: usize = 5;
/// Rows each follower chain holds before the run starts.
const FOLLOWER_HISTORY: usize = 20_000;
/// Rows the control plane's own chain holds before the run starts.
const LOCAL_HISTORY: usize = 10_000;
/// Compressed drain tick: production pushes every 10 s.
const TICK: Duration = Duration::from_secs(1);
const TICKS: u32 = 30;
/// Local access-log writer: one batch every 10 ms, 20 rows each, so
/// 2 000 rows per second through `insert_batch`.
const WRITER_PERIOD: Duration = Duration::from_millis(10);
const WRITER_BATCH: usize = 20;
/// A dashboard audit page every 500 ms.
const READER_PERIOD: Duration = Duration::from_millis(500);
/// A full verify sweep (every chain) every 3 s.
const VERIFY_PERIOD: Duration = Duration::from_secs(3);

fn follower_name(n: usize) -> String {
    format!("node-{n}")
}

/// One follower's whole chain, history and live rows, hashed exactly
/// as the origin would have so verify walks it to the end.
fn follower_chain(rows: usize) -> Vec<FannedInAuditRow> {
    let mut prev = GENESIS_HASH.to_string();
    (1..=rows)
        .map(|origin_id| {
            let timestamp = format!("2026-10-14T10:00:00.{origin_id:06}Z");
            let target_id = format!("route-{origin_id}");
            let input = ChainInput {
                timestamp: &timestamp,
                operator_username: "automation",
                operator_role: "admin",
                action: "route.update",
                target_type: "route",
                target_id: &target_id,
                before_payload_hash: "",
                after_payload_hash: "",
                ip: "192.0.2.10",
                user_agent: "ci-pipeline",
            };
            let chain_hash = compute_chain_hash(&prev, &input);
            let row = FannedInAuditRow {
                origin_id: origin_id as i64,
                timestamp: timestamp.clone(),
                operator_username: "automation".into(),
                operator_role: "admin".into(),
                action: "route.update".into(),
                target_type: "route".into(),
                target_id,
                before_payload_hash: String::new(),
                after_payload_hash: String::new(),
                ip: "192.0.2.10".into(),
                user_agent: "ci-pipeline".into(),
                prev_chain_hash: prev.clone(),
                chain_hash: chain_hash.clone(),
            };
            prev = chain_hash;
            row
        })
        .collect()
}

fn access_entry(i: u64) -> LogEntry {
    LogEntry {
        id: i,
        timestamp: "2026-10-14T10:00:00Z".into(),
        method: "GET".into(),
        path: "/api/items".into(),
        host: "shop.example.com".into(),
        status: 200,
        latency_ms: 3,
        backend: "10.0.0.10:8080".into(),
        error: None,
        client_ip: "192.0.2.10".into(),
        is_xff: false,
        xff_proxy_ip: String::new(),
        source: String::new(),
        request_id: format!("req-{i}"),
    }
}

/// `(p50, p99, max)` in milliseconds.
fn summary(samples: &mut [Duration]) -> (f64, f64, f64) {
    if samples.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    samples.sort();
    let at = |q: f64| {
        let idx = ((samples.len() as f64 - 1.0) * q).round() as usize;
        samples[idx].as_secs_f64() * 1000.0
    };
    (at(0.50), at(0.99), at(1.0))
}

struct PhaseResult {
    followers: usize,
    writer: Vec<Duration>,
    /// Writer calls that started within 100 ms after a tick boundary,
    /// where the pushes land.
    writer_on_tick: Vec<Duration>,
    push: Vec<Duration>,
    reader: Vec<Duration>,
    verify_sweep: Vec<Duration>,
    verify_chain: Vec<Duration>,
    /// Longest the writer fell behind its own schedule.
    writer_max_lag: Duration,
}

/// Seed a fresh store: the local chain and every follower's history.
/// Returns the store and, per follower, the rows still to be pushed.
fn seeded_store(dir: &std::path::Path) -> (Arc<LogStore>, Vec<Vec<FannedInAuditRow>>) {
    let store = Arc::new(LogStore::open(dir).expect("test setup: open the log store"));
    for i in 0..LOCAL_HISTORY {
        store
            .insert_audit(&NewAuditEntry {
                timestamp: "2026-10-14T09:00:00Z".into(),
                operator_username: "admin".into(),
                operator_role: "admin".into(),
                action: "route.update".into(),
                target_type: "route".into(),
                target_id: format!("route-{i}"),
                before_payload_hash: String::new(),
                after_payload_hash: String::new(),
                ip: "192.0.2.20".into(),
                user_agent: "dashboard".into(),
            })
            .expect("test setup: local audit row");
    }
    let live_rows = TICKS as usize * MAX_TELEMETRY_AUDIT;
    let mut pending = Vec::new();
    for n in 0..SEEDED_FOLLOWERS {
        let mut chain = follower_chain(FOLLOWER_HISTORY + live_rows);
        let live = chain.split_off(FOLLOWER_HISTORY);
        for batch in chain.chunks(MAX_TELEMETRY_AUDIT) {
            store
                .insert_fanned_in_audit(&follower_name(n), batch)
                .expect("test setup: follower history");
        }
        pending.push(live);
    }
    (store, pending)
}

fn run_phase(followers: usize) -> PhaseResult {
    let dir = tempfile::tempdir().expect("test setup: temp dir");
    let (store, pending) = seeded_store(dir.path());
    let start = Instant::now() + Duration::from_millis(200);
    let end = start + TICK * TICKS;
    let stop = Arc::new(AtomicBool::new(false));

    let writer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let mut all = Vec::new();
            let mut on_tick = Vec::new();
            let mut max_lag = Duration::ZERO;
            let mut next = start;
            let mut seq = 0u64;
            while next < end {
                let now = Instant::now();
                if now < next {
                    std::thread::sleep(next - now);
                }
                let began = Instant::now();
                max_lag = max_lag.max(began.saturating_duration_since(next));
                let batch: Vec<LogEntry> = (0..WRITER_BATCH)
                    .map(|_| {
                        seq += 1;
                        access_entry(seq)
                    })
                    .collect();
                store.insert_batch(&batch).expect("access batch");
                let took = began.elapsed();
                all.push(took);
                let into_tick = began.saturating_duration_since(start).as_nanos() % TICK.as_nanos();
                if into_tick < Duration::from_millis(100).as_nanos() {
                    on_tick.push(took);
                }
                next += WRITER_PERIOD;
            }
            (all, on_tick, max_lag)
        })
    };

    let pushers: Vec<_> = pending
        .into_iter()
        .take(followers)
        .enumerate()
        .map(|(n, live)| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                let node = follower_name(n);
                let mut took = Vec::new();
                for (tick, batch) in live.chunks(MAX_TELEMETRY_AUDIT).enumerate() {
                    let at = start + TICK * tick as u32;
                    let now = Instant::now();
                    if now < at {
                        std::thread::sleep(at - now);
                    }
                    let began = Instant::now();
                    store
                        .insert_fanned_in_audit(&node, batch)
                        .expect("follower push");
                    took.push(began.elapsed());
                }
                took
            })
        })
        .collect();

    let reader = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut took = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let began = Instant::now();
                store
                    .query_audit(&AuditQuery {
                        limit: 50,
                        ..Default::default()
                    })
                    .expect("audit page");
                took.push(began.elapsed());
                std::thread::sleep(READER_PERIOD);
            }
            took
        })
    };

    let verifier = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut sweeps = Vec::new();
            let mut chains = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let began = Instant::now();
                for node in store.audit_node_ids().expect("audit nodes") {
                    let chain_began = Instant::now();
                    let result = store.verify_audit_chain_for(&node).expect("verify");
                    chains.push(chain_began.elapsed());
                    assert!(result.verified, "chain {node:?} must verify: {result:?}");
                }
                sweeps.push(began.elapsed());
                std::thread::sleep(VERIFY_PERIOD);
            }
            (sweeps, chains)
        })
    };

    let (writer, writer_on_tick, writer_max_lag) = writer.join().expect("writer thread");
    let push: Vec<Duration> = pushers
        .into_iter()
        .flat_map(|p| p.join().expect("pusher thread"))
        .collect();
    stop.store(true, Ordering::Relaxed);
    let reader = reader.join().expect("reader thread");
    let (verify_sweep, verify_chain) = verifier.join().expect("verify thread");
    PhaseResult {
        followers,
        writer,
        writer_on_tick,
        push,
        reader,
        verify_sweep,
        verify_chain,
        writer_max_lag,
    }
}

/// An uncontended push of one full batch: the lock hold a push costs
/// everyone else, against which a contended push's wait is read.
fn uncontended_push() -> Vec<Duration> {
    let dir = tempfile::tempdir().expect("test setup: temp dir");
    let (store, pending) = seeded_store(dir.path());
    pending[0]
        .chunks(MAX_TELEMETRY_AUDIT)
        .take(10)
        .map(|batch| {
            let began = Instant::now();
            store
                .insert_fanned_in_audit(&follower_name(0), batch)
                .expect("push");
            began.elapsed()
        })
        .collect()
}

/// Rows in the one follower chain of the long-chain scenario: well
/// inside `FANNED_IN_AUDIT_ROWS_PER_NODE`, so a chain an honest node can
/// legitimately leave on the control plane.
const LONG_CHAIN: usize = 200_000;
/// How long the long-chain scenario runs the writer against back-to-back
/// verifies.
const LONG_CHAIN_RUN: Duration = Duration::from_secs(10);

/// The access-log writer against `verify` walking one long follower
/// chain over and over, with nothing else on the connection: the lag
/// a single chain walk can put on the writer, which a mutex held for
/// the whole walk grows linearly with the chain.
///
/// Returns `(writer samples, writer max lag, verify samples)`.
fn run_long_chain_phase() -> (Vec<Duration>, Duration, Vec<Duration>) {
    let dir = tempfile::tempdir().expect("test setup: temp dir");
    let store = Arc::new(LogStore::open(dir.path()).expect("test setup: open the log store"));
    for batch in follower_chain(LONG_CHAIN).chunks(MAX_TELEMETRY_AUDIT) {
        store
            .insert_fanned_in_audit(&follower_name(0), batch)
            .expect("test setup: long follower chain");
    }
    let start = Instant::now() + Duration::from_millis(200);
    let end = start + LONG_CHAIN_RUN;
    let stop = Arc::new(AtomicBool::new(false));

    let writer = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            let mut all = Vec::new();
            let mut max_lag = Duration::ZERO;
            let mut next = start;
            let mut seq = 0u64;
            while next < end {
                let now = Instant::now();
                if now < next {
                    std::thread::sleep(next - now);
                }
                let began = Instant::now();
                max_lag = max_lag.max(began.saturating_duration_since(next));
                let batch: Vec<LogEntry> = (0..WRITER_BATCH)
                    .map(|_| {
                        seq += 1;
                        access_entry(seq)
                    })
                    .collect();
                store.insert_batch(&batch).expect("access batch");
                all.push(began.elapsed());
                next += WRITER_PERIOD;
            }
            (all, max_lag)
        })
    };

    let verifier = {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut took = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                let began = Instant::now();
                let result = store
                    .verify_audit_chain_for(&follower_name(0))
                    .expect("verify");
                took.push(began.elapsed());
                assert!(result.verified, "the long chain must verify: {result:?}");
                assert_eq!(result.total_rows, LONG_CHAIN as u64);
            }
            took
        })
    };

    let (writer, max_lag) = writer.join().expect("writer thread");
    stop.store(true, Ordering::Relaxed);
    let verify = verifier.join().expect("verify thread");
    (writer, max_lag, verify)
}

#[test]
#[ignore = "measurement (backlog #75): one long follower chain verified back to back"]
fn measure_writer_lag_behind_a_long_chain_verify() {
    let (mut writer, max_lag, mut verify) = run_long_chain_phase();
    let w = summary(&mut writer);
    let v = summary(&mut verify);
    eprintln!(
        "[#75] long chain {LONG_CHAIN} rows, {} verifies over {LONG_CHAIN_RUN:?}: \
         writer p50/p99/max {:.2}/{:.2}/{:.2} ms, writer max lag {:.2} ms, verify p50/max {:.2}/{:.2} ms",
        verify.len(),
        w.0,
        w.1,
        w.2,
        max_lag.as_secs_f64() * 1000.0,
        v.0,
        v.2
    );
}

#[test]
#[ignore = "measurement (backlog #75): about two minutes of synthetic load"]
fn measure_audit_fan_in_contention_on_the_access_log_connection() {
    let (p50, p99, max) = summary(&mut uncontended_push());
    eprintln!(
        "[#75] uncontended push of {MAX_TELEMETRY_AUDIT} rows: p50={p50:.2} ms p99={p99:.2} ms max={max:.2} ms"
    );
    eprintln!(
        "[#75] seeded: local chain {LOCAL_HISTORY} rows, {SEEDED_FOLLOWERS} follower chains of {FOLLOWER_HISTORY}; \
         writer {WRITER_BATCH} rows every {WRITER_PERIOD:?}; tick {TICK:?} x {TICKS}"
    );
    eprintln!(
        "[#75] {:<9} | {:<26} | {:<26} | {:<26} | {:<20} | {:<20} | {:<20} | writer max lag ms",
        "followers",
        "writer p50/p99/max ms",
        "writer on-tick p50/p99/max",
        "push p50/p99/max ms",
        "page p50/p99/max",
        "verify chain p50/max",
        "verify sweep p50/max"
    );
    for followers in [0, 2, 5] {
        let mut r = run_phase(followers);
        let w = summary(&mut r.writer);
        let wt = summary(&mut r.writer_on_tick);
        let p = summary(&mut r.push);
        let page = summary(&mut r.reader);
        let vc = summary(&mut r.verify_chain);
        let vs = summary(&mut r.verify_sweep);
        eprintln!(
            "[#75] {:<9} | {:>7.2} {:>8.2} {:>8.2} | {:>7.2} {:>8.2} {:>8.2} | {:>7.2} {:>8.2} {:>8.2} | {:>6.2} {:>6.2} {:>6.2} | {:>9.2} {:>9.2} | {:>9.2} {:>9.2} | {:.2}",
            r.followers,
            w.0, w.1, w.2,
            wt.0, wt.1, wt.2,
            p.0, p.1, p.2,
            page.0, page.1, page.2,
            vc.0, vc.2,
            vs.0, vs.2,
            r.writer_max_lag.as_secs_f64() * 1000.0
        );
    }
}
