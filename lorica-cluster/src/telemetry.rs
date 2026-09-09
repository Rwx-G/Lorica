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

//! Telemetry ingest policy (Story 9.6 AC #8): what the control plane
//! will accept from one node, and when it stops accepting anything at
//! all.
//!
//! # Why this exists
//!
//! The follower-side bound protects the FOLLOWER. Nothing else today
//! protects the control plane: an enrolled node that is compromised,
//! misconfigured or simply broken can stream rows at line rate, fill
//! the disk, and make SQLite fail writes for every other node AND for
//! the configuration and audit paths that share that disk. Day-based
//! retention does not help within the day.
//!
//! So the control plane budgets each node independently and sheds
//! everything when storage runs short. Two separate mechanisms,
//! because they answer different questions: the per-node quota
//! answers "is this node taking more than its share", the watermark
//! answers "is there room for telemetry at all".
//!
//! # Shedding order is not negotiable
//!
//! Telemetry is the FIRST thing dropped and the configuration and
//! audit writes are the last, because a fleet that cannot record what
//! happened is inconvenient while a fleet that cannot be configured
//! or audited is broken. The watermark is deliberately set with
//! headroom for that reason: by the time telemetry is being shed
//! there is still room for the writes that matter.
//!
//! # No policy here touches identity
//!
//! Every method takes the `node_id` the session proved. Nothing in
//! this module reads a node name out of a payload (decision D2).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding window the per-node rate is measured over.
pub const QUOTA_WINDOW: Duration = Duration::from_secs(60);

/// Rows one node may deliver per [`QUOTA_WINDOW`] by default.
///
/// A node pushing its own traffic at the documented ceiling stays
/// well inside this; a node above it is either misconfigured or
/// fabricating, and either way the control plane is not the place to
/// absorb it.
pub const DEFAULT_ROWS_PER_WINDOW: u64 = 120_000;

/// Bytes one node may deliver per [`QUOTA_WINDOW`] by default.
///
/// The row cap alone is not enough: rows are variable-length, and a
/// node sending maximum-length paths and matched values in every row
/// costs far more disk than the same count of ordinary rows.
pub const DEFAULT_BYTES_PER_WINDOW: u64 = 64 * 1024 * 1024;

/// What a node over its quota is told to wait, in seconds.
pub const QUOTA_RETRY_AFTER_S: u32 = 30;

/// How large the fan-in database may grow before telemetry is shed
/// entirely.
///
/// A cap on the telemetry database's OWN size rather than a free-disk
/// floor, and that is the deliberate choice. The thing this protects
/// against is the one thing fan-in can grow without bound; free disk
/// moves for reasons that have nothing to do with the fleet, so a
/// floor on it would shed telemetry because something else filled the
/// volume, and would keep accepting telemetry on a huge volume long
/// after the database had become unmanageable.
///
/// Bounding the database directly leaves the rest of the volume for
/// the configuration store and the audit chain, which is what AC #8
/// actually asks for, and it needs no syscall beyond a file stat.
pub const DEFAULT_STORAGE_CAP_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// How much of one batch a node may store right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestVerdict {
    /// Store the whole batch.
    Accept,
    /// Store this many access rows and this many WAF events, and tell
    /// the node to back off. Either number may be zero.
    Partial {
        /// Access rows that fit in what is left of the budget.
        access: usize,
        /// WAF events that fit in what is left of the budget.
        waf: usize,
        /// What the node is told to wait.
        retry_after_s: u32,
    },
    /// Store nothing and tell the node to back off. Used both for a
    /// node that has spent its budget and for the storage watermark,
    /// which sheds every node at once.
    Shed {
        /// What the node is told to wait.
        retry_after_s: u32,
    },
}

impl IngestVerdict {
    /// How many access rows this verdict allows out of `offered`.
    pub fn access_allowance(&self, offered: usize) -> usize {
        match self {
            Self::Accept => offered,
            Self::Partial { access, .. } => (*access).min(offered),
            Self::Shed { .. } => 0,
        }
    }

    /// How many WAF events this verdict allows out of `offered`.
    pub fn waf_allowance(&self, offered: usize) -> usize {
        match self {
            Self::Accept => offered,
            Self::Partial { waf, .. } => (*waf).min(offered),
            Self::Shed { .. } => 0,
        }
    }

    /// What to put in the ack's `retry_after_s`.
    pub fn retry_after_s(&self) -> u32 {
        match self {
            Self::Accept => 0,
            Self::Partial { retry_after_s, .. } | Self::Shed { retry_after_s } => *retry_after_s,
        }
    }
}

/// One node's spend inside the current window.
#[derive(Debug)]
struct NodeSpend {
    window_started: Instant,
    rows: u64,
    bytes: u64,
}

impl NodeSpend {
    fn new(now: Instant) -> Self {
        Self {
            window_started: now,
            rows: 0,
            bytes: 0,
        }
    }

    /// Reset when the window has rolled over. A plain reset rather
    /// than a decaying average on purpose: an operator reading the
    /// counters should be able to reason about "rows in the last
    /// minute", not about a half-life.
    fn roll(&mut self, now: Instant, window: Duration) {
        if now.duration_since(self.window_started) >= window {
            self.window_started = now;
            self.rows = 0;
            self.bytes = 0;
        }
    }
}

/// Per-node ingest budgets and the global storage watermark.
///
/// Cheap to consult and safe to share: one mutex around a small map
/// keyed by node id, touched once per batch rather than once per row.
#[derive(Debug)]
pub struct IngestQuota {
    window: Duration,
    rows_per_window: u64,
    bytes_per_window: u64,
    retry_after_s: u32,
    spend: Mutex<HashMap<String, NodeSpend>>,
}

impl Default for IngestQuota {
    fn default() -> Self {
        Self::new()
    }
}

impl IngestQuota {
    /// A quota with the documented defaults.
    pub fn new() -> Self {
        Self {
            window: QUOTA_WINDOW,
            rows_per_window: DEFAULT_ROWS_PER_WINDOW,
            bytes_per_window: DEFAULT_BYTES_PER_WINDOW,
            retry_after_s: QUOTA_RETRY_AFTER_S,
            spend: Mutex::new(HashMap::new()),
        }
    }

    /// A quota with explicit budgets, for tests and for an operator
    /// setting that reaches here later.
    pub fn with_budget(rows_per_window: u64, bytes_per_window: u64, window: Duration) -> Self {
        Self {
            window,
            rows_per_window,
            bytes_per_window,
            retry_after_s: QUOTA_RETRY_AFTER_S,
            spend: Mutex::new(HashMap::new()),
        }
    }

    /// Decide what `node_id` may store of a batch of `rows` rows and
    /// `bytes` bytes, and CHARGE what is allowed against its budget.
    ///
    /// `access` and `waf` are the two row counts, so a partial verdict
    /// can be split between them proportionally rather than the caller
    /// having to guess.
    ///
    /// Charging happens here, in the same lock as the decision, so two
    /// concurrent batches from one node cannot both be told there is
    /// room for the same remaining budget.
    pub fn admit(&self, node_id: &str, access: usize, waf: usize, bytes: u64) -> IngestVerdict {
        let now = Instant::now();
        let offered = (access + waf) as u64;
        let mut spend = self.spend.lock().unwrap_or_else(|p| p.into_inner());
        // An entry whose window has rolled over is indistinguishable
        // from no entry: `roll` would zero it on its next use. Dropping
        // those here bounds the map by the nodes that pushed within
        // the last window, whatever removed the others (leave, which
        // calls `forget`, but also revocation, re-enrolment under a
        // fresh id, or a node that simply died), without threading a
        // hook through every removal path. O(nodes) per batch, on a
        // map that is small by construction.
        let window = self.window;
        spend.retain(|_, s| now.duration_since(s.window_started) < window);
        let entry = spend
            .entry(node_id.to_string())
            .or_insert_with(|| NodeSpend::new(now));
        entry.roll(now, self.window);

        let rows_left = self.rows_per_window.saturating_sub(entry.rows);
        let bytes_left = self.bytes_per_window.saturating_sub(entry.bytes);
        if rows_left == 0 || bytes_left == 0 {
            return IngestVerdict::Shed {
                retry_after_s: self.retry_after_s,
            };
        }
        if offered <= rows_left && bytes <= bytes_left {
            entry.rows += offered;
            entry.bytes += bytes;
            return IngestVerdict::Accept;
        }

        // Over budget on at least one axis. Take the tighter of the
        // two allowances, split proportionally between the kinds so
        // neither starves the other, and charge exactly what is taken.
        let by_rows = rows_left;
        let by_bytes = if bytes == 0 || offered == 0 {
            offered
        } else {
            // Average bytes per row in THIS batch, so a batch of large
            // rows is charged what it actually costs.
            let per_row = bytes.div_ceil(offered).max(1);
            bytes_left / per_row
        };
        let allowed = by_rows.min(by_bytes).min(offered);
        if allowed == 0 {
            return IngestVerdict::Shed {
                retry_after_s: self.retry_after_s,
            };
        }
        let allowed_access = if offered == 0 {
            0
        } else {
            // Proportional split, rounding the remainder to access
            // rows: they are the higher-volume kind, so rounding the
            // other way would systematically starve them.
            let share = (allowed as u128 * access as u128) / offered as u128;
            (share as u64).min(access as u64)
        };
        let allowed_waf = (allowed - allowed_access).min(waf as u64);
        let taken = allowed_access + allowed_waf;
        entry.rows += taken;
        // `offered` cannot be zero here (`allowed > 0` implies it),
        // but charging is not the place to rely on that.
        entry.bytes += bytes
            .saturating_mul(taken)
            .checked_div(offered)
            .unwrap_or(0);
        IngestVerdict::Partial {
            access: allowed_access as usize,
            waf: allowed_waf as usize,
            retry_after_s: self.retry_after_s,
        }
    }

    /// Forget a node's spend at once, for a node that has left the
    /// fleet. A node removed any other way is swept by the next
    /// [`IngestQuota::admit`] once its window has rolled over.
    pub fn forget(&self, node_id: &str) {
        self.spend
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
    }

    /// How many nodes currently hold a budget entry, for the gauge.
    pub fn tracked_nodes(&self) -> usize {
        self.spend.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// Whether there is room to store telemetry at all.
///
/// Separate from [`IngestQuota`] because it is a different question
/// with a different answer: the quota is about fairness between
/// nodes, this is about whether there is room for anything. When this
/// says no, EVERY node is shed, including one well inside its quota.
///
/// `used_bytes` is the size of the fan-in database itself. Retention
/// is what normally keeps it under the cap; reaching the cap means
/// retention is not keeping up, and shedding is what stops the
/// database from growing while an operator finds out why.
pub fn storage_verdict(used_bytes: u64, cap_bytes: u64) -> IngestVerdict {
    if used_bytes >= cap_bytes {
        IngestVerdict::Shed {
            retry_after_s: QUOTA_RETRY_AFTER_S,
        }
    } else {
        IngestVerdict::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_inside_the_budget_is_taken_whole() {
        let quota = IngestQuota::new();
        assert_eq!(
            quota.admit("node-a", 100, 10, 30_000),
            IngestVerdict::Accept
        );
        assert_eq!(quota.tracked_nodes(), 1);
    }

    #[test]
    fn one_node_spending_its_budget_does_not_touch_another() {
        // The property that makes this a per-node quota rather than a
        // global one, and the reason a compromised node cannot deny
        // the fleet its telemetry.
        let quota = IngestQuota::with_budget(100, u64::MAX, QUOTA_WINDOW);
        assert_eq!(quota.admit("node-noisy", 100, 0, 1), IngestVerdict::Accept);
        assert!(matches!(
            quota.admit("node-noisy", 10, 0, 1),
            IngestVerdict::Shed { .. }
        ));
        assert_eq!(
            quota.admit("node-quiet", 50, 0, 1),
            IngestVerdict::Accept,
            "a quiet node is unaffected by a noisy one"
        );
    }

    #[test]
    fn a_batch_that_only_partly_fits_is_split_between_the_kinds() {
        let quota = IngestQuota::with_budget(100, u64::MAX, QUOTA_WINDOW);
        quota.admit("node-a", 60, 0, 1);
        // 40 rows of budget left, 80 offered: both kinds get a share.
        let verdict = quota.admit("node-a", 40, 40, 1);
        match verdict {
            IngestVerdict::Partial {
                access,
                waf,
                retry_after_s,
            } => {
                assert_eq!(access + waf, 40, "exactly the remaining budget is taken");
                assert!(access > 0 && waf > 0, "neither kind is starved");
                assert_eq!(retry_after_s, QUOTA_RETRY_AFTER_S);
            }
            other => panic!("expected a partial verdict, got {other:?}"),
        }
    }

    #[test]
    fn the_byte_budget_binds_independently_of_the_row_budget() {
        // Rows are variable-length: a node sending few but enormous
        // rows must still be bounded.
        let quota = IngestQuota::with_budget(u64::MAX, 1_000, QUOTA_WINDOW);
        let verdict = quota.admit("node-a", 100, 0, 10_000);
        match verdict {
            IngestVerdict::Partial { access, .. } => {
                assert!(access < 100, "the byte budget cut the batch down");
            }
            other => panic!("expected a partial verdict, got {other:?}"),
        }
    }

    #[test]
    fn the_window_rolls_and_the_budget_comes_back() {
        let quota = IngestQuota::with_budget(10, u64::MAX, Duration::from_millis(1));
        assert_eq!(quota.admit("node-a", 10, 0, 1), IngestVerdict::Accept);
        assert!(matches!(
            quota.admit("node-a", 1, 0, 1),
            IngestVerdict::Shed { .. }
        ));
        std::thread::sleep(Duration::from_millis(3));
        assert_eq!(
            quota.admit("node-a", 5, 0, 1),
            IngestVerdict::Accept,
            "the next window starts clean"
        );
    }

    #[test]
    fn the_allowance_helpers_never_exceed_what_was_offered() {
        let partial = IngestVerdict::Partial {
            access: 50,
            waf: 50,
            retry_after_s: 30,
        };
        assert_eq!(partial.access_allowance(10), 10);
        assert_eq!(partial.access_allowance(500), 50);
        assert_eq!(IngestVerdict::Accept.waf_allowance(7), 7);
        assert_eq!(
            IngestVerdict::Shed { retry_after_s: 30 }.access_allowance(7),
            0
        );
        assert_eq!(IngestVerdict::Accept.retry_after_s(), 0);
        assert_eq!(partial.retry_after_s(), 30);
    }

    #[test]
    fn the_watermark_sheds_every_node_at_once() {
        // Not a per-node decision: at the cap, a node well inside its
        // quota is shed too, because the question is whether there is
        // room for anything rather than whose turn it is.
        assert!(matches!(
            storage_verdict(DEFAULT_STORAGE_CAP_BYTES, DEFAULT_STORAGE_CAP_BYTES),
            IngestVerdict::Shed { .. }
        ));
        assert!(matches!(
            storage_verdict(DEFAULT_STORAGE_CAP_BYTES + 1, DEFAULT_STORAGE_CAP_BYTES),
            IngestVerdict::Shed { .. }
        ));
        assert_eq!(
            storage_verdict(DEFAULT_STORAGE_CAP_BYTES - 1, DEFAULT_STORAGE_CAP_BYTES),
            IngestVerdict::Accept
        );
    }

    #[test]
    fn a_departed_node_is_forgotten() {
        let quota = IngestQuota::new();
        quota.admit("node-a", 1, 0, 1);
        assert_eq!(quota.tracked_nodes(), 1);
        quota.forget("node-a");
        assert_eq!(quota.tracked_nodes(), 0);
    }

    #[test]
    fn a_node_nobody_forgot_is_swept_once_its_window_rolled() {
        // Revocation, re-enrolment and a plain crash never call
        // `forget`; the sweep is what keeps the map from holding one
        // entry per node that ever existed for the life of the
        // process.
        let quota = IngestQuota::with_budget(100, u64::MAX, Duration::from_millis(20));
        quota.admit("node-gone", 1, 0, 1);
        assert_eq!(quota.tracked_nodes(), 1);
        std::thread::sleep(Duration::from_millis(30));
        quota.admit("node-here", 1, 0, 1);
        assert_eq!(quota.tracked_nodes(), 1, "only the node that pushed inside the window");
        // The sweep is lossless: a swept entry had a rolled window,
        // which `roll` would have zeroed anyway, so the node's budget
        // is the full one either way.
        assert_eq!(quota.admit("node-gone", 100, 0, 1), IngestVerdict::Accept);
    }
}
