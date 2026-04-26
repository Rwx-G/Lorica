// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Load-balancing primitives extracted from `proxy_wiring.rs`.
//!
//! Three independent state machines share the data plane :
//! - [`SmoothWrrState`] : smooth weighted round-robin selector with a
//!   per-worker offset to avoid all workers picking the same backend
//!   on cold start.
//! - [`EwmaTracker`] : exponentially-weighted moving average of
//!   per-backend latency, used by Peak-EWMA load balancing.
//! - [`CircuitBreaker`] : per-(route, backend) failure counter with
//!   `Closed` / `Open` / `HalfOpen` state machine.
//!
//! All three are constructed at proxy boot and live for the process
//! lifetime ; nothing in here touches the request / response pipeline
//! directly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lorica_config::models::Backend;

/// Smooth weighted round-robin LB state.
///
/// Implements the classic Nginx-style smooth WRR algorithm where
/// each backend's effective weight increases each round and the
/// selected backend's weight is decreased by the total weight.
///
/// State is keyed by backend address (not position) so it works correctly when
/// unhealthy backends are filtered out between calls.
#[derive(Debug)]
pub struct SmoothWrrState {
    /// Per-backend-address current weights.
    current_weights: parking_lot::Mutex<HashMap<String, i64>>,
    /// Worker offset to avoid all workers selecting the same backend at startup.
    worker_offset: usize,
}

impl Clone for SmoothWrrState {
    fn clone(&self) -> Self {
        Self {
            current_weights: parking_lot::Mutex::new(self.current_weights.lock().clone()),
            worker_offset: self.worker_offset,
        }
    }
}

impl SmoothWrrState {
    pub fn new(worker_offset: usize) -> Self {
        Self {
            current_weights: parking_lot::Mutex::new(HashMap::new()),
            worker_offset,
        }
    }

    /// Select the next backend using smooth weighted round-robin.
    /// `backends` is a slice of (address, weight) for healthy backends only.
    /// Returns the index into the `backends` slice.
    pub fn next(&self, backends: &[(&str, i64)]) -> usize {
        if backends.is_empty() {
            return 0;
        }
        let total: i64 = backends.iter().map(|(_, w)| *w).sum();
        if total == 0 {
            return 0;
        }

        let mut cw = self.current_weights.lock();

        // Initialize new backends with offset-based head start.
        // The head start is just +1 so the offset backend wins the first
        // tie-break without skewing the overall distribution.
        for (i, (addr, _)) in backends.iter().enumerate() {
            cw.entry(addr.to_string()).or_insert_with(|| {
                if i == self.worker_offset % backends.len() {
                    1 // tiny head start to win first tie-break
                } else {
                    0
                }
            });
        }

        // Increase all current_weights by their effective weight
        for (addr, weight) in backends {
            *cw.entry(addr.to_string()).or_insert(0) += weight;
        }

        // Find the backend with the highest current_weight
        let mut best_idx = 0;
        let mut best_weight = i64::MIN;
        for (i, (addr, _)) in backends.iter().enumerate() {
            let w = cw.get(*addr).copied().unwrap_or(0);
            if w > best_weight {
                best_weight = w;
                best_idx = i;
            }
        }

        // Decrease the selected backend's current_weight by total_weight
        let best_addr = backends[best_idx].0;
        if let Some(w) = cw.get_mut(best_addr) {
            *w -= total;
        }

        best_idx
    }
}

/// Peak EWMA latency tracker for load balancing.
///
/// Tracks exponentially weighted moving average of latency per backend.
/// The decay factor ensures recent measurements count more than old ones.
#[derive(Debug, Default)]
pub struct EwmaTracker {
    /// EWMA score per backend address (microseconds).
    pub(crate) scores: Arc<parking_lot::RwLock<HashMap<String, f64>>>,
}

impl EwmaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the EWMA score for a backend with a new latency sample.
    ///
    /// Hot path: we try `get_mut` first with a write lock already held
    /// so the common case (backend already known) avoids the
    /// `addr.to_string()` allocation that `insert` would incur. Only
    /// the first-seen backend per process pays for the `String`
    /// (audit M-1).
    pub fn record(&self, addr: &str, latency_us: f64) {
        let alpha = 0.3;
        let mut scores = self.scores.write();
        if let Some(current) = scores.get_mut(addr) {
            *current = alpha * latency_us + (1.0 - alpha) * *current;
        } else {
            // First-seen: seed the decay with the sample itself.
            scores.insert(addr.to_string(), latency_us);
        }
    }

    /// Select the backend with the lowest EWMA score.
    /// Returns the index into the provided backends slice.
    pub fn select_best(&self, backends: &[&Backend]) -> usize {
        if backends.is_empty() {
            return 0;
        }
        let scores = self.scores.read();
        let mut best_idx = 0;
        let mut best_score = f64::MAX;
        for (i, b) in backends.iter().enumerate() {
            let score = scores.get(&b.address).copied().unwrap_or(0.0);
            // Tie-break: unscored backends get priority (explore)
            if score < best_score {
                best_score = score;
                best_idx = i;
            }
        }
        best_idx
    }

    /// Get the EWMA score for a backend (for dashboard display).
    pub fn get_score(&self, addr: &str) -> f64 {
        self.scores.read().get(addr).copied().unwrap_or(0.0)
    }

    /// Return a shared reference to the scores map (for passing to API state).
    pub fn scores_ref(&self) -> Arc<parking_lot::RwLock<HashMap<String, f64>>> {
        Arc::clone(&self.scores)
    }
}

/// Per-(route, backend) circuit breaker.
///
/// Tracks consecutive failures per (route, backend) pair rather than per
/// backend alone. This matters when several routes share the same upstream
/// IP:port but exercise different paths on it - for example two virtual
/// hosts both pointing at `10.0.0.1:3080` where one path always succeeds
/// and the other structurally fails. Keying on the route prevents failures
/// on one route from tripping the breaker for siblings that are actually
/// healthy against the same physical backend.
///
/// When the failure count reaches the threshold, the circuit opens for that
/// (route, backend) pair and traffic on that route is redirected to other
/// backends for a cooldown period. After the cooldown, one probe request is
/// allowed through (half-open). If it succeeds the circuit closes; if it
/// fails the circuit re-opens.
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Per-(route_id, backend) state: (consecutive_failures, state, last_state_change)
    states: dashmap::DashMap<(String, String), CircuitBreakerState>,
    /// Number of consecutive errors before opening the circuit.
    threshold: u32,
    /// How long the circuit stays open before moving to half-open (seconds).
    cooldown_s: u64,
}

#[derive(Debug, Clone)]
struct CircuitBreakerState {
    failures: u32,
    state: CircuitStatus,
    changed_at: Instant,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitStatus {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, cooldown_s: u64) -> Self {
        Self {
            states: dashmap::DashMap::new(),
            threshold,
            cooldown_s,
        }
    }

    /// Check if a backend is available for the given route (not in Open state).
    /// Open circuits that have exceeded the cooldown move to HalfOpen.
    pub fn is_available(&self, route_id: &str, addr: &str) -> bool {
        let key = (route_id.to_string(), addr.to_string());
        let mut entry = match self.states.get_mut(&key) {
            Some(e) => e,
            None => return true, // no state = closed = available
        };
        match entry.state {
            CircuitStatus::Closed | CircuitStatus::HalfOpen => true,
            CircuitStatus::Open => {
                if entry.changed_at.elapsed() >= Duration::from_secs(self.cooldown_s) {
                    entry.state = CircuitStatus::HalfOpen;
                    entry.changed_at = Instant::now();
                    true // allow one probe request
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful response. Resets the failure count and closes the circuit.
    pub fn record_success(&self, route_id: &str, addr: &str) {
        let key = (route_id.to_string(), addr.to_string());
        if let Some(mut entry) = self.states.get_mut(&key) {
            if entry.failures > 0 || entry.state != CircuitStatus::Closed {
                entry.failures = 0;
                entry.state = CircuitStatus::Closed;
                entry.changed_at = Instant::now();
            }
        }
    }

    /// Record a failure. Increments the counter and opens the circuit if threshold is reached.
    pub fn record_failure(&self, route_id: &str, addr: &str) {
        let key = (route_id.to_string(), addr.to_string());
        let mut entry = self.states.entry(key).or_insert(CircuitBreakerState {
            failures: 0,
            state: CircuitStatus::Closed,
            changed_at: Instant::now(),
        });
        entry.failures += 1;
        if entry.failures >= self.threshold && entry.state != CircuitStatus::Open {
            entry.state = CircuitStatus::Open;
            entry.changed_at = Instant::now();
            tracing::warn!(
                route_id = %route_id,
                backend = %addr,
                failures = entry.failures,
                cooldown_s = self.cooldown_s,
                "circuit breaker opened - backend removed from rotation for this route"
            );
        }
    }
}
