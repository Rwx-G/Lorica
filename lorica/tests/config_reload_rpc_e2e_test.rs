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

//! Phase 7 end-to-end coverage for the two-phase config reload
//! (WPAR-8) over a real `RpcEndpoint` socketpair. Verifies:
//!
//! 1. Prepare/Commit round-trip transitions a worker's pending slot
//!    and then swaps it in (generation matches).
//! 2. Commit with a mismatched generation is rejected, pending slot
//!    preserved.
//! 3. Prepare with a non-monotonic generation is rejected by the
//!    GenerationGate.

#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use lorica_command::{
    command, CommandType, ConfigReloadCommit, ConfigReloadPrepare, GenerationGate, IncomingCommand,
    ResponseStatus, RpcEndpoint,
};

struct WorkerState {
    gate: Arc<GenerationGate>,
    pending_gen: parking_lot::Mutex<Option<u64>>,
    committed_gen: parking_lot::Mutex<Option<u64>>,
    prepare_should_fail: AtomicBool,
}

impl WorkerState {
    fn new() -> Self {
        Self {
            gate: Arc::new(GenerationGate::new()),
            pending_gen: parking_lot::Mutex::new(None),
            committed_gen: parking_lot::Mutex::new(None),
            prepare_should_fail: AtomicBool::new(false),
        }
    }
}

fn spawn_worker(
    endpoint: RpcEndpoint,
    mut incoming: lorica_command::IncomingCommands,
    state: Arc<WorkerState>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = &endpoint;
        while let Some(inc) = incoming.recv().await {
            match inc.command_type() {
                CommandType::ConfigReloadPrepare => handle_prepare(inc, &state).await,
                CommandType::ConfigReloadCommit => handle_commit(inc, &state).await,
                _ => {
                    let _ = inc.reply_error("unsupported").await;
                }
            }
        }
    })
}

async fn handle_prepare(inc: IncomingCommand, state: &WorkerState) {
    let p: ConfigReloadPrepare = match inc.command().payload.clone() {
        Some(command::Payload::ConfigReloadPrepare(p)) => p,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    if state.prepare_should_fail.load(Ordering::Acquire) {
        let _ = inc.reply_error("injected Prepare failure").await;
        return;
    }
    if let Err(e) = state.gate.observe(p.generation) {
        let _ = inc.reply_error(format!("stale: {e}")).await;
        return;
    }
    *state.pending_gen.lock() = Some(p.generation);
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

async fn handle_commit(inc: IncomingCommand, state: &WorkerState) {
    let c: ConfigReloadCommit = match inc.command().payload.clone() {
        Some(command::Payload::ConfigReloadCommit(c)) => c,
        _ => {
            let _ = inc.reply_error("malformed").await;
            return;
        }
    };
    if let Err(e) = state.gate.observe_commit(c.generation) {
        let _ = inc.reply_error(format!("stale commit: {e}")).await;
        return;
    }
    let result = {
        let mut pending = state.pending_gen.lock();
        match *pending {
            Some(g) if g == c.generation => {
                *pending = None;
                Ok(())
            }
            Some(g) => Err(format!("pending={g} commit={}", c.generation)),
            None => Err("no pending config".into()),
        }
    };
    match result {
        Ok(()) => {
            *state.committed_gen.lock() = Some(c.generation);
            let _ = inc.reply(lorica_command::Response::ok(0)).await;
        }
        Err(msg) => {
            let _ = inc.reply_error(msg).await;
        }
    }
}

fn socketpair() -> (
    RpcEndpoint,
    lorica_command::IncomingCommands,
    RpcEndpoint,
    lorica_command::IncomingCommands,
) {
    let (a, b) = tokio::net::UnixStream::pair().expect("UnixStream::pair");
    let (ep1, inc1) = RpcEndpoint::new(a);
    let (ep2, inc2) = RpcEndpoint::new(b);
    (ep1, inc1, ep2, inc2)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_prepare_commit_happy_path() {
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let state = Arc::new(WorkerState::new());
    let _h = spawn_worker(wk_ep, wk_inc, Arc::clone(&state));

    // Prepare generation 1.
    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 1 }),
            Duration::from_secs(2),
        )
        .await
        .expect("rpc");
    assert_eq!(resp.typed_status(), ResponseStatus::Ok);
    assert_eq!(*state.pending_gen.lock(), Some(1));
    assert_eq!(*state.committed_gen.lock(), None);

    // Commit generation 1.
    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadCommit,
            command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 1 }),
            Duration::from_millis(500),
        )
        .await
        .expect("rpc");
    assert_eq!(resp.typed_status(), ResponseStatus::Ok);
    assert_eq!(*state.pending_gen.lock(), None);
    assert_eq!(*state.committed_gen.lock(), Some(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_prepare_rejects_non_monotonic_generation() {
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let state = Arc::new(WorkerState::new());
    let _h = spawn_worker(wk_ep, wk_inc, Arc::clone(&state));

    // Prepare + Commit generation 5.
    let _ = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 5 }),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let _ = sup_ep
        .request_rpc(
            CommandType::ConfigReloadCommit,
            command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 5 }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();

    // Re-Prepare generation 3: rejected as stale.
    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 3 }),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.typed_status(),
        ResponseStatus::Error,
        "generation regression must be rejected"
    );
    assert!(
        resp.message.contains("stale"),
        "error message should mention staleness, got: {:?}",
        resp.message
    );
    // Pending slot should be clear (Commit cleared it, no new Prepare stashed).
    assert_eq!(*state.pending_gen.lock(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_commit_rejects_mismatched_generation() {
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let state = Arc::new(WorkerState::new());
    let _h = spawn_worker(wk_ep, wk_inc, Arc::clone(&state));

    // Prepare generation 7.
    let _ = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 7 }),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    // Commit with a different generation: rejected.
    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadCommit,
            command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 6 }),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
    assert_eq!(resp.typed_status(), ResponseStatus::Error);
    // Pending slot must still hold generation 7 — a mismatched commit
    // must not clobber a prepared entry.
    assert_eq!(*state.pending_gen.lock(), Some(7));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_listener_drains_on_supervisor_eof() {
    // Audit gap coverage: verify a worker's RPC listener task exits
    // cleanly when the supervisor drops BOTH its endpoint and its
    // incoming receiver (process exit, SIGTERM, crash). Without this
    // guarantee, worker shutdown would hang on the TaskTracker drain
    // past its 10 s deadline.
    let (sup_ep, sup_inc, wk_ep, wk_inc) = socketpair();
    let state = Arc::new(WorkerState::new());
    let handle = spawn_worker(wk_ep, wk_inc, Arc::clone(&state));

    // Round-trip one Prepare to confirm the listener is alive.
    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 1 }),
            Duration::from_secs(1),
        )
        .await
        .expect("rpc");
    assert_eq!(resp.typed_status(), ResponseStatus::Ok);

    // Drop both supervisor-side halves. The worker's
    // `IncomingCommands` receiver must observe EOF (peer closed its
    // end of the socketpair) and its `while let Some = recv().await`
    // loop must exit.
    drop(sup_ep);
    drop(sup_inc);

    // The listener task should complete within a few seconds; 5 s is a
    // generous ceiling that catches "truly hung" while tolerating
    // tokio scheduler hiccups.
    let join_result = tokio::time::timeout(Duration::from_secs(5), handle).await;
    assert!(
        join_result.is_ok(),
        "worker RPC listener must exit within 5s of supervisor EOF; hung shutdown is a blocker"
    );
    assert!(
        join_result.unwrap().is_ok(),
        "listener task completed but panicked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reload_prepare_failure_propagates() {
    let (sup_ep, _sup_inc, wk_ep, wk_inc) = socketpair();
    let state = Arc::new(WorkerState::new());
    state.prepare_should_fail.store(true, Ordering::Release);
    let _h = spawn_worker(wk_ep, wk_inc, Arc::clone(&state));

    let resp = sup_ep
        .request_rpc(
            CommandType::ConfigReloadPrepare,
            command::Payload::ConfigReloadPrepare(ConfigReloadPrepare { generation: 1 }),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(resp.typed_status(), ResponseStatus::Error);
    assert!(resp.message.contains("injected"));
}
