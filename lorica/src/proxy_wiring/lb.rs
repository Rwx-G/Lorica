// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Load-balancing primitives (backlog #7 step 3).
//!
//! Peak-EWMA latency tracker (bounded explore/exploit selection),
//! the per-(route, backend) circuit breaker state machine, and the
//! `BackendConnections` re-export.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lorica_config::models::Backend;

/// Per-backend active connection counter.
///
pub use lorica_api::connections::BackendConnections;

/// One call in `EXPLORE_EVERY` to [`EwmaTracker::select_best`] explores a
/// not-yet-scored backend instead of exploiting the lowest score, so a cold
/// backend acquires its first latency sample without being stampeded.
const EXPLORE_EVERY: usize = 10;

/// Peak EWMA latency tracker for load balancing.
///
/// Tracks exponentially weighted moving average of latency per backend.
/// The decay factor ensures recent measurements count more than old ones.
#[derive(Debug, Default)]
pub struct EwmaTracker {
    /// EWMA score per backend address (microseconds). Sharded map so
    /// concurrent `record` calls (one per upstream response, plus the
    /// health-prober's samples) contend per shard instead of
    /// serialising on a single global write lock (audit L-17).
    pub(crate) scores: Arc<dashmap::DashMap<String, f64>>,
    /// Monotonic selection ticket. Drives the bounded explore/exploit split
    /// and round-robin tie-breaking, and (via `fetch_add`) hands each
    /// concurrent caller a distinct value so they spread instead of stampeding.
    next: AtomicUsize,
}

impl EwmaTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the EWMA score for a backend with a new latency sample.
    ///
    /// Hot path: we try `get_mut` first so the common case (backend
    /// already known) avoids the `addr.to_string()` allocation that
    /// `insert` would incur; only the first-seen backend per process
    /// pays for the `String` (audit M-1). The guard must be dropped
    /// before the `insert` fallback: holding a DashMap shard ref while
    /// inserting into the same shard deadlocks.
    pub fn record(&self, addr: &str, latency_us: f64) {
        let alpha = 0.3;
        if let Some(mut current) = self.scores.get_mut(addr) {
            *current = alpha * latency_us + (1.0 - alpha) * *current;
            return;
        }
        // First-seen: seed the decay with the sample itself. Two racing
        // first samples both land here; last write wins, which is an
        // acceptable seed either way.
        self.scores.insert(addr.to_string(), latency_us);
    }

    /// Select a backend index, balancing exploit (lowest EWMA score) against
    /// bounded exploration of not-yet-scored backends.
    ///
    /// This is a plain latency EWMA: a backend's score does not rise under
    /// load, so treating an unscored backend as the minimum (the previous
    /// `unwrap_or(0.0)`) made it the best by default - every concurrent request
    /// then stampeded the same cold backend (a thundering herd). Instead:
    ///
    /// - roughly one call in [`EXPLORE_EVERY`] picks an unscored backend
    ///   (round-robin, so warm-up traffic is bounded and spread across
    ///   concurrent callers);
    /// - the rest exploit the lowest finite score, treating unscored backends
    ///   as `+inf` so they are never stampeded;
    /// - at a cold start (nothing scored yet) selection round-robins across all
    ///   backends rather than always returning index 0.
    ///
    /// A backend leaves the unscored set as soon as [`Self::record`] lands its
    /// first sample, after which it competes on real latency.
    pub fn select_best(&self, backends: &[&Backend]) -> usize {
        if backends.is_empty() {
            return 0;
        }
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);

        // Explore: bounded, round-robin over not-yet-scored backends.
        if ticket.is_multiple_of(EXPLORE_EVERY) {
            let unscored: Vec<usize> = backends
                .iter()
                .enumerate()
                .filter(|(_, b)| !self.scores.contains_key(&b.address))
                .map(|(i, _)| i)
                .collect();
            if !unscored.is_empty() {
                return unscored[(ticket / EXPLORE_EVERY) % unscored.len()];
            }
        }

        // Exploit: lowest scored backend. Unscored backends are ignored here
        // (treated as +inf); they receive traffic only via the explore path.
        // Per-key shard reads instead of one map-wide read lock: a sample
        // landing between two lookups can shift the winner by one sample,
        // which is within EWMA noise.
        let mut best_idx = 0;
        let mut best_score = f64::INFINITY;
        let mut any_scored = false;
        for (i, b) in backends.iter().enumerate() {
            if let Some(score) = self.scores.get(&b.address) {
                any_scored = true;
                if *score < best_score {
                    best_score = *score;
                    best_idx = i;
                }
            }
        }
        if !any_scored {
            // Cold start: nothing scored yet, spread round-robin.
            return ticket % backends.len();
        }
        best_idx
    }

    /// Get the EWMA score for a backend (for dashboard display).
    pub fn get_score(&self, addr: &str) -> f64 {
        self.scores.get(addr).map(|s| *s).unwrap_or(0.0)
    }

    /// Return a shared reference to the scores map (for passing to API state).
    pub fn scores_ref(&self) -> Arc<dashmap::DashMap<String, f64>> {
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
    /// Per-route map of per-backend state. Nested maps instead of a
    /// composite `(String, String)` key so the hot-path lookups
    /// (`is_available` per candidate backend, `record_*` per finished
    /// request) run on `&str` borrows with zero allocations; only the
    /// first request of a (route, backend) pair pays for the owned
    /// keys (audit #41b). The inner map is a different `DashMap`, so
    /// holding an outer shard ref while touching the inner one cannot
    /// self-deadlock.
    states: dashmap::DashMap<String, dashmap::DashMap<String, CircuitBreakerState>>,
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

impl CircuitBreakerState {
    fn closed() -> Self {
        Self {
            failures: 0,
            state: CircuitStatus::Closed,
            changed_at: Instant::now(),
        }
    }
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
        let route_states = match self.states.get(route_id) {
            Some(r) => r,
            None => return true, // no state = closed = available
        };
        let mut entry = match route_states.get_mut(addr) {
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
        if let Some(route_states) = self.states.get(route_id) {
            if let Some(mut entry) = route_states.get_mut(addr) {
                if entry.failures > 0 || entry.state != CircuitStatus::Closed {
                    entry.failures = 0;
                    entry.state = CircuitStatus::Closed;
                    entry.changed_at = Instant::now();
                }
            }
        }
    }

    /// Record a failure. Increments the counter and opens the circuit if threshold is reached.
    pub fn record_failure(&self, route_id: &str, addr: &str) {
        // Fast path: known (route, backend) pair, `&str` lookups only.
        // The `get_mut` guard must not outlive the early return: an
        // `entry()` insert on the same inner map while its shard ref
        // is alive would deadlock, hence the staged shape below.
        if let Some(route_states) = self.states.get(route_id) {
            if let Some(mut entry) = route_states.get_mut(addr) {
                self.bump_failure(&mut entry, route_id, addr);
                return;
            }
            // Known route, first-seen backend: the inner guard from the
            // miss above is dropped, only the outer shard ref is held.
            let mut entry = route_states
                .entry(addr.to_string())
                .or_insert_with(CircuitBreakerState::closed);
            self.bump_failure(&mut entry, route_id, addr);
            return;
        }
        // First-seen route: the outer `get` miss guard is dropped at the
        // end of the `if let` above, so the upsert cannot self-deadlock.
        let route_states = self.states.entry(route_id.to_string()).or_default();
        let mut entry = route_states
            .entry(addr.to_string())
            .or_insert_with(CircuitBreakerState::closed);
        self.bump_failure(&mut entry, route_id, addr);
    }

    /// Shared tail of [`Self::record_failure`]: bump the consecutive
    /// counter and open the circuit at the threshold.
    fn bump_failure(&self, entry: &mut CircuitBreakerState, route_id: &str, addr: &str) {
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
