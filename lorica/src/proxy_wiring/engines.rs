// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Worker-mode RPC engines (audit M-8).
//!
//! Three enums that route an admission / cache / rate-limit decision
//! either to a local in-process state machine (single-process mode)
//! or to the supervisor via the pipelined RPC channel (worker mode).
//! Extracted from the parent `proxy_wiring` module at the end of
//! v1.3.0 to shrink that 8 Ki-LOC file below the refactor threshold.
//! The previous import path `lorica::proxy_wiring::BreakerEngine`
//! still works via the `pub use` re-export at the top of
//! `proxy_wiring.rs`.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use super::CircuitBreaker;

/// Circuit-breaker admission result. The worker uses this to know
/// whether to proceed (`Allow` / `Probe`) and, on completion, whether
/// the subsequent outcome report must be flagged as `was_probe=true`
/// so the supervisor can transition HalfOpen -> Closed / Open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerAdmission {
    /// Admission granted by a Closed breaker. Report outcome without
    /// `was_probe` flag.
    Allow,
    /// HalfOpen probe admitted: the caller holds the sole probe slot
    /// for this (route, backend) until it reports. Must set
    /// `was_probe=true` when reporting.
    Probe,
    /// Breaker is Open; backend must not be contacted.
    Deny,
}

/// Circuit-breaker engine dispatch. Single-process mode uses the
/// in-process `CircuitBreaker`; worker mode delegates admission and
/// outcome reporting to the supervisor via the pipelined RPC channel so
/// probe slots and state transitions are consistent across workers.
/// See design § 7 WPAR-3.
#[derive(Clone)]
pub enum BreakerEngine {
    Local(Arc<CircuitBreaker>),
    Rpc {
        endpoint: lorica_command::RpcEndpoint,
        timeout: Duration,
    },
}

impl BreakerEngine {
    pub fn local(failure_threshold: u32, cooldown_s: u64) -> Self {
        Self::Local(Arc::new(CircuitBreaker::new(failure_threshold, cooldown_s)))
    }

    pub fn rpc(endpoint: lorica_command::RpcEndpoint, timeout: Duration) -> Self {
        Self::Rpc { endpoint, timeout }
    }

    /// Query admission for `(route, backend)`. Fails open on transport
    /// error so a flaky supervisor UDS channel never DoS's the data
    /// plane - matches the design doc § 9 failure-matrix entry for
    /// "channel goes silent".
    pub async fn admit(&self, route_id: &str, backend: &str) -> BreakerAdmission {
        match self {
            BreakerEngine::Local(b) => {
                if b.is_available(route_id, backend) {
                    // The local breaker collapses Closed and HalfOpen
                    // into a single boolean; it tracks its own probe
                    // slot internally. So we always report `Allow` and
                    // never flag `was_probe`; record_{success,failure}
                    // on the inner CircuitBreaker handle the state
                    // transition uniformly.
                    BreakerAdmission::Allow
                } else {
                    BreakerAdmission::Deny
                }
            }
            BreakerEngine::Rpc { endpoint, timeout } => {
                let payload =
                    lorica_command::command::Payload::BreakerQuery(lorica_command::BreakerQuery {
                        route_id: route_id.to_string(),
                        backend: backend.to_string(),
                    });
                match endpoint
                    .request_rpc(lorica_command::CommandType::BreakerQuery, payload, *timeout)
                    .await
                {
                    Ok(resp) => match resp.payload {
                        Some(lorica_command::response::Payload::BreakerResult(r)) => {
                            match lorica_command::BreakerDecision::from_i32(r.decision) {
                                lorica_command::BreakerDecision::Allow => BreakerAdmission::Allow,
                                lorica_command::BreakerDecision::Deny => BreakerAdmission::Deny,
                                lorica_command::BreakerDecision::AllowProbe => {
                                    BreakerAdmission::Probe
                                }
                                lorica_command::BreakerDecision::Unspecified => {
                                    BreakerAdmission::Allow
                                }
                            }
                        }
                        _ => BreakerAdmission::Allow,
                    },
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            route_id,
                            backend,
                            "breaker RPC admission failed; failing open"
                        );
                        BreakerAdmission::Allow
                    }
                }
            }
        }
    }

    /// Report request outcome. `was_probe` must be `true` if the
    /// prior `admit()` returned `BreakerAdmission::Probe`; the Local
    /// variant ignores the flag (its state machine handles probe
    /// transitions internally).
    pub async fn record(&self, route_id: &str, backend: &str, success: bool, was_probe: bool) {
        match self {
            BreakerEngine::Local(b) => {
                if success {
                    b.record_success(route_id, backend);
                } else {
                    b.record_failure(route_id, backend);
                }
            }
            BreakerEngine::Rpc { endpoint, timeout } => {
                let payload = lorica_command::command::Payload::BreakerReport(
                    lorica_command::BreakerReport {
                        route_id: route_id.to_string(),
                        backend: backend.to_string(),
                        success,
                        was_probe,
                    },
                );
                if let Err(e) = endpoint
                    .request_rpc(
                        lorica_command::CommandType::BreakerReport,
                        payload,
                        *timeout,
                    )
                    .await
                {
                    tracing::debug!(
                        error = %e,
                        route_id,
                        backend,
                        success,
                        was_probe,
                        "breaker RPC outcome report failed; state may drift until next report"
                    );
                }
            }
        }
    }
}

/// Forward-auth verdict cache dispatch. Single-process deployments use
/// the per-process `FORWARD_AUTH_VERDICT_CACHE` static (same behaviour
/// as pre-WPAR); worker-mode deployments delegate to the supervisor via
/// the pipelined RPC channel so every worker sees a consistent cache
/// and session revocation propagates uniformly.
///
/// `Clone` is cheap: the `Rpc` variant holds a cloneable `RpcEndpoint`
/// (internal `Arc<Inner>`), and `Local` is a unit variant.
#[derive(Clone)]
pub enum VerdictCacheEngine {
    /// Single-process: read/write the process-global static cache.
    /// There is at most one `LoricaProxy` per process, so no partitioning
    /// by proxy instance is needed.
    Local,
    /// Worker mode: issue `VerdictLookup` / `VerdictPush` RPC calls to
    /// the supervisor. A lookup miss or RPC failure degrades gracefully
    /// to an upstream auth call - the worker never denies on transport
    /// errors.
    Rpc {
        endpoint: lorica_command::RpcEndpoint,
        timeout: Duration,
    },
}

impl VerdictCacheEngine {
    pub fn local() -> Self {
        Self::Local
    }

    pub fn rpc(endpoint: lorica_command::RpcEndpoint, timeout: Duration) -> Self {
        Self::Rpc { endpoint, timeout }
    }
}

/// Per-route rate-limit engine: either the local authoritative state
/// (single-process) or a CAS-based local cache synced with the
/// supervisor (worker mode). `Clone` is cheap — the inner `DashMap` is
/// wrapped in `Arc`.
#[derive(Clone)]
pub enum RateLimitEngine {
    /// Owner of the bucket state lives in-process. Time-based refill
    /// happens lazily inside each `try_consume` call.
    Authoritative(Arc<DashMap<String, Arc<lorica_limits::token_bucket::AuthoritativeBucket>>>),
    /// Cache of buckets; supervisor holds the authoritative state. The
    /// 100 ms sync task (see `spawn_rate_limit_sync`) drains delta
    /// counters and refreshes token counts from the supervisor's reply.
    Local(Arc<DashMap<String, Arc<lorica_limits::token_bucket::LocalBucket>>>),
}

impl RateLimitEngine {
    /// Fresh single-process engine.
    pub fn authoritative() -> Self {
        Self::Authoritative(Arc::new(DashMap::new()))
    }

    /// Fresh worker-mode engine; caller is expected to spawn the
    /// supervisor sync task.
    pub fn local() -> Self {
        Self::Local(Arc::new(DashMap::new()))
    }

    /// Attempt to consume `cost` tokens for the bucket keyed by `key`,
    /// creating a fresh bucket on first-seen (seeded from `rl`). The
    /// hot path is lock-free for the `Local` variant (CAS loop on a
    /// single atomic); `Authoritative` takes the per-bucket mutex for
    /// refill + drain.
    pub fn try_consume(
        &self,
        key: &str,
        rl: &lorica_config::models::RateLimit,
        cost: u32,
        now_ns: u64,
    ) -> bool {
        match self {
            RateLimitEngine::Authoritative(map) => {
                let bucket = map
                    .entry(key.to_string())
                    .or_insert_with(|| {
                        Arc::new(lorica_limits::token_bucket::AuthoritativeBucket::new(
                            rl.capacity,
                            rl.refill_per_sec,
                            now_ns,
                        ))
                    })
                    .clone();
                bucket.try_consume(cost, now_ns)
            }
            RateLimitEngine::Local(map) => {
                let bucket = map
                    .entry(key.to_string())
                    .or_insert_with(|| {
                        Arc::new(lorica_limits::token_bucket::LocalBucket::new(rl.capacity))
                    })
                    .clone();
                bucket.try_consume(cost)
            }
        }
    }
}
