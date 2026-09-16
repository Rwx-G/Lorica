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

//! Per-rule capture budgets: the total a rule stops at, and the rate it
//! samples at until then.
//!
//! [`CompiledCaptureRules`] answers whether a rule considers a request
//! and whether the finished exchange is worth writing out. This module
//! answers the question that comes after those two: the rule wants this
//! exchange, is it still allowed to have it.
//!
//! # Process-local by design
//!
//! Every counter here, and the rate window with them, lives in this
//! process. In worker mode that means PER WORKER: a node running four
//! workers admits up to four times `rate_per_minute` and stops at up to
//! four times `max_captures`. That is the documented semantics, not an
//! oversight. Making either bound fleet-consistent would put a shared
//! counter (a cross-process lock, or an RPC) on the path that decides
//! whether to record one exchange, on a node whose main job is
//! terminating production TLS, and the precision is not worth that.
//!
//! It is also why [`CaptureRule::expires_at`] is an absolute instant
//! rather than a duration: the clock is the one bound every node in the
//! fleet agrees on without talking to any other. Expiry is not checked
//! here at all, because a rule past it is already gone from the
//! candidate set ([`CompiledCaptureRules::candidates_for_request`]) and
//! never reaches this module to ask.
//!
//! # Series count
//!
//! Each tracked rule contributes at most one `lorica_captures_total`
//! series per outcome. A rule the tracking map refuses (see
//! [`CAPTURE_MAX_TRACKED_RULES`]) records nothing and reports no
//! metric, so the family stays bounded by the same constant that bounds
//! the map rather than by the stored rule count.
//!
//! [`CaptureRule::expires_at`]: lorica_config::models::CaptureRule::expires_at

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use lorica_config::models::CaptureLimits;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use tracing::warn;

use super::rules::CompiledCaptureRule;

/// Rules this process keeps a budget for at once.
///
/// Nothing caps how many rows `capture_rules` may hold, so the map
/// keyed by rule id needs a ceiling of its own or an operator (or a
/// buggy automation token) can grow it without limit. The number is far
/// above any plausible diagnostic deployment: a node carrying a
/// thousand simultaneous capture rules has a configuration problem that
/// this map is not the right place to notice.
pub const CAPTURE_MAX_TRACKED_RULES: usize = 1024;

/// Buckets in the rate window, one per second of the minute it covers.
const RATE_WINDOW_BUCKETS: usize = 60;

/// A one-minute sliding window, counted in per-second buckets.
///
/// Deliberately NOT a list of emission timestamps. `rate_per_minute`
/// goes up to `CAPTURE_RATE_PER_MINUTE_CAP` (10 000), so one instant
/// per emission would be ten thousand `Instant`s per rule per minute,
/// allocated, pushed and scanned on the path that decides whether to
/// record at all. The bucket array costs the same 60 words whether the
/// rule emits once a minute or ten thousand times, and the decision is
/// one comparison against a running total. What is given up is
/// sub-second precision: an emission is counted in the second it
/// happened, and the window forgets a whole second at a time instead of
/// one emission at a time.
#[derive(Debug)]
struct RateWindow {
    /// Emissions per second, indexed by `second % RATE_WINDOW_BUCKETS`.
    buckets: [u32; RATE_WINDOW_BUCKETS],
    /// Sum of `buckets`, maintained on every mutation so the admission
    /// check does not walk the array.
    total: u32,
    /// Seconds since `base` that the newest bucket stands for.
    head_secs: u64,
    /// Where this window counts seconds from.
    base: Instant,
}

impl RateWindow {
    fn new(now: Instant) -> Self {
        Self {
            buckets: [0; RATE_WINDOW_BUCKETS],
            total: 0,
            head_secs: 0,
            base: now,
        }
    }

    /// Move the window up to `now`, clearing the seconds it left behind.
    fn advance(&mut self, now: Instant) {
        let secs = now.saturating_duration_since(self.base).as_secs();
        // `<=` rather than `<`: a reading that did not move keeps the
        // current bucket instead of rewinding the head, which would
        // clear seconds whose emissions are already counted.
        if secs <= self.head_secs {
            return;
        }
        let steps = secs - self.head_secs;
        if steps >= RATE_WINDOW_BUCKETS as u64 {
            self.buckets = [0; RATE_WINDOW_BUCKETS];
            self.total = 0;
        } else {
            for step in 1..=steps {
                let index = ((self.head_secs + step) % RATE_WINDOW_BUCKETS as u64) as usize;
                self.total -= self.buckets[index];
                self.buckets[index] = 0;
            }
        }
        self.head_secs = secs;
    }

    /// Count one emission when the window still has room for it.
    fn try_admit(&mut self, limit: u32, now: Instant) -> bool {
        self.advance(now);
        if self.total >= limit {
            return false;
        }
        let index = (self.head_secs % RATE_WINDOW_BUCKETS as u64) as usize;
        self.buckets[index] += 1;
        self.total += 1;
        true
    }
}

/// One rule's accounting on this process.
#[derive(Debug)]
struct RuleBudget {
    /// Captures admitted since this process started tracking the rule.
    emitted: u32,
    /// The rolling minute the rate limit is measured over.
    window: RateWindow,
    /// Whether the self-disable for this rule has already been queued.
    disable_signalled: bool,
}

impl RuleBudget {
    fn new(now: Instant) -> Self {
        Self {
            emitted: 0,
            window: RateWindow::new(now),
            disable_signalled: false,
        }
    }
}

/// What a rule is told when it asks to record one exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureAdmission {
    /// Record it. The rule's total and rate window are already advanced.
    Emit,
    /// The rolling minute is full. The rule recovers on its own as the
    /// window slides; nothing is disabled.
    DroppedRate,
    /// The rule's `max_captures` total is spent, or this process is
    /// tracking as many rules as it will. A spent total also queues the
    /// rule for a self-disable.
    DroppedBudget,
}

impl CaptureAdmission {
    /// The `outcome` label this decision reports under.
    ///
    /// ```
    /// use lorica::capture::CaptureAdmission;
    /// assert_eq!(CaptureAdmission::Emit.metric_outcome(), "emitted");
    /// assert_eq!(CaptureAdmission::DroppedRate.metric_outcome(), "dropped_rate");
    /// ```
    pub fn metric_outcome(self) -> &'static str {
        match self {
            Self::Emit => "emitted",
            Self::DroppedRate => "dropped_rate",
            Self::DroppedBudget => "dropped_budget",
        }
    }

    /// Whether the exchange may be recorded.
    pub fn emitted(self) -> bool {
        matches!(self, Self::Emit)
    }
}

/// One rule that spent its total and must be disabled in the store.
///
/// The rule is never deleted, only disarmed, so an operator opening the
/// dashboard sees a rule that stopped and why rather than a rule that
/// vanished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingDisable {
    /// The rule to disable.
    pub rule_id: String,
    /// The route it was recording, for the audit line.
    pub route_id: String,
    /// Which limit was spent. `max_captures` is the only one that
    /// disarms a rule: the rate window throttles and recovers by
    /// itself, and expiry is the clock's business.
    pub budget: &'static str,
    /// The value that limit stood at, so the audit says what was
    /// reached and not merely that something was.
    pub limit: u32,
}

/// The `budget` value on every [`PendingDisable`] this module queues.
const BUDGET_MAX_CAPTURES: &str = "max_captures";

/// One rule's admissions since the counters were last flushed to the
/// store, as the deltas `ConfigStore::bump_capture_counters` takes.
///
/// Accumulated here, under the admission lock, rather than written per
/// capture: the store is a SQLite file every worker shares, and one
/// `UPDATE` per admitted exchange would put a disk write on the path
/// that decides whether to record. The flush task drains the map on
/// its tick, so a rule costs one write per tick however many exchanges
/// it admitted or refused in between.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCounters {
    /// The rule the deltas belong to.
    pub rule_id: String,
    /// Exchanges admitted since the last flush.
    pub emitted: i64,
    /// Exchanges refused since the last flush, by rate or by total.
    pub dropped: i64,
}

#[derive(Debug, Default)]
struct BudgetState {
    per_rule: HashMap<String, RuleBudget>,
    /// Rules waiting for the store write that disarms them. Bounded by
    /// the map above, since `disable_signalled` queues each rule once.
    pending_disable: Vec<PendingDisable>,
    /// Deltas waiting for the store write that publishes them, keyed
    /// by rule id. Only a tracked rule gets an entry, so the map is
    /// bounded by [`CAPTURE_MAX_TRACKED_RULES`] plus the rules retired
    /// since the last flush; `retain_rules` deliberately leaves those
    /// in place, because the exchanges a rule admitted before it was
    /// disabled or evicted are still its exchanges and the flush is
    /// what publishes them.
    pending_counters: HashMap<String, PendingCounters>,
    /// Whether the tracking cap has already been reported. One line per
    /// process, not one per refused request.
    cap_reported: bool,
}

/// Every capture rule's total and rate, for this process.
#[derive(Debug)]
pub struct CaptureBudgets {
    state: Mutex<BudgetState>,
}

/// The process-wide budgets every request is measured against.
static NODE_BUDGETS: Lazy<Arc<CaptureBudgets>> = Lazy::new(CaptureBudgets::new);

/// The budgets the proxy pipeline uses.
///
/// A static for the same reason [`super::node_budget`] is one: the
/// counters outlive the configuration snapshot they were advanced
/// under. A reload swaps the snapshot several times an hour on a fleet
/// under change, and budgets that died with it would hand every rule
/// its `max_captures` back on each swap, which is a standing recorder
/// wearing a diagnostic's limits.
///
/// Tests build their own [`CaptureBudgets`] instead, so they neither
/// observe nor disturb a concurrently running test.
pub fn node_budgets() -> &'static Arc<CaptureBudgets> {
    &NODE_BUDGETS
}

impl CaptureBudgets {
    /// A fresh set of budgets, tracking nothing.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(BudgetState::default()),
        })
    }

    /// Ask whether `rule` may record one more exchange, and account for
    /// the answer.
    ///
    /// `now` is a parameter rather than an `Instant::now()` inside, for
    /// the same reason
    /// [`CompiledCaptureRules::candidates_for_request`] takes one: the
    /// whole exchange is judged against a single reading, and the tests
    /// are arithmetic instead of a race with the clock.
    pub fn admit(&self, rule: &CompiledCaptureRule, now: Instant) -> CaptureAdmission {
        self.admit_rule(&rule.rule.id, &rule.rule.route_id, &rule.rule.limits, now)
    }

    /// The decision, without a compiled rule to carry it.
    ///
    /// Reading the counters, comparing them against the limits and
    /// advancing them all happen under ONE lock. Split into a check and
    /// a separate bump, two requests arriving together on a rule with
    /// one capture left would both see room and both record, which is
    /// precisely the overrun `max_captures` exists to prevent.
    ///
    /// The lock is not on the request path: it is taken once per
    /// would-be emission, which is per request that matched a rule AND
    /// satisfied its `emit` block, and what it guards is a comparison
    /// and two increments.
    fn admit_rule(
        &self,
        rule_id: &str,
        route_id: &str,
        limits: &CaptureLimits,
        now: Instant,
    ) -> CaptureAdmission {
        let mut guard = self.state.lock();
        let state = &mut *guard;

        // `contains_key` runs only once the map is full, so the common
        // path pays one hash lookup in total, in the `entry` below.
        if state.per_rule.len() >= CAPTURE_MAX_TRACKED_RULES
            && !state.per_rule.contains_key(rule_id)
        {
            if !state.cap_reported {
                state.cap_reported = true;
                warn!(
                    tracked = CAPTURE_MAX_TRACKED_RULES,
                    capture_rule_id = %rule_id,
                    "capture budget tracking is at its cap; further rules record nothing"
                );
            }
            return CaptureAdmission::DroppedBudget;
        }

        let budget = state
            .per_rule
            .entry(rule_id.to_string())
            .or_insert_with(|| RuleBudget::new(now));

        let admission = if budget.emitted >= limits.max_captures {
            CaptureAdmission::DroppedBudget
        } else if budget.window.try_admit(limits.rate_per_minute, now) {
            budget.emitted += 1;
            CaptureAdmission::Emit
        } else {
            CaptureAdmission::DroppedRate
        };

        // The total is spent the moment the last capture is taken, so
        // the request that took it queues the disable rather than the
        // next one to be refused. The flag is flipped under the same
        // lock that decided the admission, so however many requests
        // observe a spent total, exactly one of them queues the write.
        let signal = budget.emitted >= limits.max_captures && !budget.disable_signalled;
        if signal {
            budget.disable_signalled = true;
        }
        if signal {
            state.pending_disable.push(PendingDisable {
                rule_id: rule_id.to_string(),
                route_id: route_id.to_string(),
                budget: BUDGET_MAX_CAPTURES,
                limit: limits.max_captures,
            });
        }
        let counters = state
            .pending_counters
            .entry(rule_id.to_string())
            .or_insert_with(|| PendingCounters {
                rule_id: rule_id.to_string(),
                emitted: 0,
                dropped: 0,
            });
        match admission {
            CaptureAdmission::Emit => counters.emitted += 1,
            CaptureAdmission::DroppedRate | CaptureAdmission::DroppedBudget => {
                counters.dropped += 1
            }
        }
        drop(guard);

        lorica_api::metrics::inc_capture_outcome(rule_id, admission.metric_outcome());
        admission
    }

    /// Forget every rule whose id is not in `live`.
    ///
    /// Called when a configuration snapshot is rebuilt, which is the
    /// only moment the set of rules changes. Without it the map keyed by
    /// rule id only ever grows, and a fleet that creates and deletes
    /// capture rules for a living leaks one entry per rule it retires.
    ///
    /// A rule that comes back after being evicted starts from zero. That
    /// is the intent: re-enabling a rule that spent its total is an
    /// operator re-arming it, and an operator who re-arms a rule expects
    /// it to record again.
    pub fn retain_rules<'a>(&self, live: impl IntoIterator<Item = &'a str>) {
        let live: HashSet<&str> = live.into_iter().collect();
        let mut state = self.state.lock();
        state.per_rule.retain(|id, _| live.contains(id.as_str()));
    }

    /// Take the rules queued for a self-disable, leaving the queue
    /// empty. Called by the task that performs the store write.
    pub fn take_pending_disables(&self) -> Vec<PendingDisable> {
        std::mem::take(&mut self.state.lock().pending_disable)
    }

    /// Take every rule's unflushed counter deltas, leaving none behind.
    /// Called by the task that performs the store writes; the order is
    /// unspecified because each entry is an independent `UPDATE`.
    pub fn take_pending_counters(&self) -> Vec<PendingCounters> {
        std::mem::take(&mut self.state.lock().pending_counters)
            .into_values()
            .collect()
    }

    /// How many rules this process currently tracks a budget for.
    pub fn tracked_rules(&self) -> usize {
        self.state.lock().per_rule.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn limits(max_captures: u32, rate_per_minute: u32) -> CaptureLimits {
        CaptureLimits {
            max_captures,
            rate_per_minute,
            ttl_seconds: 3600,
        }
    }

    #[test]
    fn two_requests_racing_for_the_last_capture_produce_one_emit_and_one_drop() {
        // Repeated, because a check-then-bump split does not fail on
        // every interleaving: one round could pass by luck.
        for _ in 0..200 {
            let budgets = CaptureBudgets::new();
            let limits = limits(1, 10_000);
            let now = Instant::now();
            let emits = AtomicUsize::new(0);
            let drops = AtomicUsize::new(0);
            std::thread::scope(|scope| {
                for _ in 0..2 {
                    scope.spawn(|| {
                        match budgets.admit_rule("cap-1", "route-1", &limits, now) {
                            CaptureAdmission::Emit => emits.fetch_add(1, Ordering::Relaxed),
                            CaptureAdmission::DroppedBudget => {
                                drops.fetch_add(1, Ordering::Relaxed)
                            }
                            CaptureAdmission::DroppedRate => {
                                panic!("the rate window has room for both")
                            }
                        };
                    });
                }
            });
            assert_eq!(emits.load(Ordering::Relaxed), 1);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn the_rate_window_admits_its_minute_and_refuses_the_next_request() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10_000, 5);
        let now = Instant::now();
        for i in 0..5 {
            assert_eq!(
                budgets.admit_rule("cap-1", "route-1", &limits, now + Duration::from_secs(i)),
                CaptureAdmission::Emit,
                "emission {i} is inside the minute"
            );
        }
        assert_eq!(
            budgets.admit_rule("cap-1", "route-1", &limits, now + Duration::from_secs(5)),
            CaptureAdmission::DroppedRate
        );
    }

    #[test]
    fn the_rate_window_admits_again_once_the_minute_rolls() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10_000, 2);
        let now = Instant::now();
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now)
            .emitted());
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now)
            .emitted());
        assert_eq!(
            budgets.admit_rule("cap-1", "route-1", &limits, now + Duration::from_secs(59)),
            CaptureAdmission::DroppedRate,
            "still inside the same minute"
        );
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now + Duration::from_secs(60))
            .emitted());
    }

    #[test]
    fn the_rate_window_costs_the_same_memory_after_ten_thousand_emissions() {
        let base = Instant::now();
        let mut window = RateWindow::new(base);
        let before = std::mem::size_of_val(&window);
        // One emission per second for nearly three hours, so the ring
        // wraps well over a hundred times.
        for i in 0..10_000u64 {
            assert!(window.try_admit(u32::MAX, base + Duration::from_secs(i)));
        }
        assert_eq!(std::mem::size_of_val(&window), before);
        assert_eq!(before, std::mem::size_of::<RateWindow>());
        assert_eq!(window.buckets.len(), RATE_WINDOW_BUCKETS);
        // A timestamp list would hold all ten thousand. The window holds
        // the last minute and nothing else, whatever came before it.
        assert_eq!(window.total, RATE_WINDOW_BUCKETS as u32);
    }

    #[test]
    fn a_spent_total_signals_the_self_disable_exactly_once_under_concurrency() {
        let budgets = CaptureBudgets::new();
        let limits = limits(1, 10_000);
        let now = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    budgets.admit_rule("cap-1", "route-1", &limits, now);
                });
            }
        });
        let pending = budgets.take_pending_disables();
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0],
            PendingDisable {
                rule_id: "cap-1".to_string(),
                route_id: "route-1".to_string(),
                budget: BUDGET_MAX_CAPTURES,
                limit: 1,
            }
        );
        // Requests after the total is spent do not queue it again.
        budgets.admit_rule("cap-1", "route-1", &limits, now);
        assert!(budgets.take_pending_disables().is_empty());
    }

    #[test]
    fn a_spent_total_reports_the_total_and_not_the_rate() {
        let budgets = CaptureBudgets::new();
        let limits = limits(1, 10_000);
        let now = Instant::now();
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now)
            .emitted());
        assert_eq!(
            budgets.admit_rule("cap-1", "route-1", &limits, now),
            CaptureAdmission::DroppedBudget
        );
    }

    #[test]
    fn every_admission_lands_in_the_pending_counters_and_taking_them_empties_the_map() {
        let budgets = CaptureBudgets::new();
        let limits = limits(2, 10_000);
        let now = Instant::now();
        for _ in 0..5 {
            budgets.admit_rule("cap-1", "route-1", &limits, now);
        }
        budgets.admit_rule("cap-2", "route-1", &limits, now);

        let mut pending = budgets.take_pending_counters();
        pending.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
        assert_eq!(
            pending,
            vec![
                PendingCounters {
                    rule_id: "cap-1".to_string(),
                    emitted: 2,
                    dropped: 3,
                },
                PendingCounters {
                    rule_id: "cap-2".to_string(),
                    emitted: 1,
                    dropped: 0,
                },
            ]
        );
        assert!(budgets.take_pending_counters().is_empty());
    }

    #[test]
    fn a_retired_rule_keeps_its_unflushed_counters_until_they_are_taken() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10, 10_000);
        let now = Instant::now();
        budgets.admit_rule("cap-1", "route-1", &limits, now);
        budgets.retain_rules(std::iter::empty());
        assert_eq!(budgets.tracked_rules(), 0);
        let pending = budgets.take_pending_counters();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].emitted, 1);
    }

    #[test]
    fn a_rule_past_the_tracking_cap_records_no_counters() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10_000, 10_000);
        let now = Instant::now();
        for i in 0..CAPTURE_MAX_TRACKED_RULES {
            budgets.admit_rule(&format!("cap-{i}"), "route-1", &limits, now);
        }
        budgets.admit_rule("over", "route-1", &limits, now);
        let pending = budgets.take_pending_counters();
        assert_eq!(pending.len(), CAPTURE_MAX_TRACKED_RULES);
        assert!(pending.iter().all(|p| p.rule_id != "over"));
    }

    #[test]
    fn a_rule_that_left_the_configuration_loses_its_budget_entry() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10, 10);
        let now = Instant::now();
        for id in ["cap-1", "cap-2", "cap-3"] {
            budgets.admit_rule(id, "route-1", &limits, now);
        }
        assert_eq!(budgets.tracked_rules(), 3);

        budgets.retain_rules(["cap-1", "cap-3"]);
        assert_eq!(budgets.tracked_rules(), 2);

        budgets.retain_rules(std::iter::empty());
        assert_eq!(budgets.tracked_rules(), 0);
    }

    #[test]
    fn a_rule_that_comes_back_after_eviction_starts_from_zero() {
        let budgets = CaptureBudgets::new();
        let limits = limits(1, 10_000);
        let now = Instant::now();
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now)
            .emitted());
        assert_eq!(
            budgets.admit_rule("cap-1", "route-1", &limits, now),
            CaptureAdmission::DroppedBudget
        );
        budgets.retain_rules(std::iter::empty());
        assert!(budgets
            .admit_rule("cap-1", "route-1", &limits, now)
            .emitted());
    }

    #[test]
    fn the_tracked_rule_map_cannot_grow_past_its_cap() {
        let budgets = CaptureBudgets::new();
        let limits = limits(10_000, 10_000);
        let now = Instant::now();
        for i in 0..CAPTURE_MAX_TRACKED_RULES {
            assert!(budgets
                .admit_rule(&format!("cap-{i}"), "route-1", &limits, now)
                .emitted());
        }
        assert_eq!(budgets.tracked_rules(), CAPTURE_MAX_TRACKED_RULES);

        for i in 0..5 {
            assert_eq!(
                budgets.admit_rule(&format!("over-{i}"), "route-1", &limits, now),
                CaptureAdmission::DroppedBudget,
                "a rule past the cap records nothing"
            );
        }
        assert_eq!(budgets.tracked_rules(), CAPTURE_MAX_TRACKED_RULES);

        // A rule already tracked is unaffected by the cap.
        assert!(budgets
            .admit_rule("cap-0", "route-1", &limits, now)
            .emitted());
    }
}
