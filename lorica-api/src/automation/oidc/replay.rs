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

//! The bounded replay set (Story 10.5 AC #4): every accepted `jti` is
//! remembered until its `exp`, and a second presentation is refused.
//!
//! # Why the bound is the point
//!
//! Remembering every `jti` until it expires is correct until someone
//! sends a million tokens. An ID token lives for minutes, so the set
//! is small under honest use; what the cap defends is the node that
//! also terminates production TLS, which must not have a memory
//! primitive on its control plane. When the cap is reached the
//! entries with the EARLIEST `exp` are evicted, because they are the
//! ones whose replay window is shortest, and every eviction is counted
//! in `lorica_automation_oidc_replay_evictions_total`: a silent
//! eviction would turn a full set into a replay window, and a counter
//! that moves is the alert.

use std::collections::{BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;

/// Most `jti` entries the replay set holds at once.
///
/// Sized for the memory it may cost, not the traffic it may see: a key
/// is the issuer URL plus a UUID, around 100 bytes, held twice (once
/// per index) with map overhead, so the cap bounds the set near
/// 15 MiB. GitLab tokens live for the job timeout or five minutes, so
/// reaching it at all means several hundred accepted tokens per second
/// sustained, which is not a CI pipeline.
pub const OIDC_REPLAY_SET_CAP: usize = 50_000;

/// The two indexes the set keeps: by key for the membership test, by
/// expiry for the purge and the eviction.
#[derive(Debug, Default)]
struct Inner {
    by_key: HashMap<String, DateTime<Utc>>,
    by_exp: BTreeSet<(DateTime<Utc>, String)>,
}

/// A bounded set of accepted token ids, each kept until its expiry.
#[derive(Debug)]
pub struct ReplaySet {
    inner: Mutex<Inner>,
    cap: usize,
}

impl Default for ReplaySet {
    fn default() -> Self {
        Self::with_cap(OIDC_REPLAY_SET_CAP)
    }
}

impl ReplaySet {
    /// A set holding at most `cap` entries. Production uses
    /// [`OIDC_REPLAY_SET_CAP`]; tests use a small cap to exercise the
    /// eviction without a million tokens.
    pub fn with_cap(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap: cap.max(1),
        }
    }

    /// Remember `key` until `exp`.
    ///
    /// Returns `true` when the key was not in the set, `false` when it
    /// was, which is a replay. Entries whose `exp` is at or before
    /// `now` are purged first, so an expired entry never blocks a key
    /// (an expired token is refused on `exp` anyway, before this set
    /// is consulted). When the insert takes the set past its cap, the
    /// entries with the earliest `exp` are evicted and counted.
    pub fn remember(&self, key: &str, exp: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let mut inner = self.inner.lock();
        purge_expired(&mut inner, now);
        if inner.by_key.contains_key(key) {
            return false;
        }
        inner.by_key.insert(key.to_string(), exp);
        inner.by_exp.insert((exp, key.to_string()));

        let mut evicted: u64 = 0;
        while inner.by_key.len() > self.cap {
            let Some(oldest) = inner.by_exp.pop_first() else {
                break;
            };
            inner.by_key.remove(&oldest.1);
            evicted += 1;
        }
        if evicted > 0 {
            crate::metrics::inc_automation_oidc_replay_evictions(evicted);
            tracing::warn!(
                evicted,
                cap = self.cap,
                "OIDC replay set full; evicted unexpired token ids, which opens a replay window \
                 until their expiry"
            );
        }
        true
    }

    /// How many ids the set currently holds, expired ones included
    /// until the next insert purges them.
    pub fn len(&self) -> usize {
        self.inner.lock().by_key.len()
    }

    /// Whether the set holds no id at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Drop every entry whose expiry is at or before `now`.
fn purge_expired(inner: &mut Inner, now: DateTime<Utc>) {
    while let Some(first) = inner.by_exp.first() {
        if first.0 > now {
            break;
        }
        let Some((_, key)) = inner.by_exp.pop_first() else {
            break;
        };
        inner.by_key.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn at(offset_seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test setup: valid timestamp")
            .with_timezone(&Utc)
            + Duration::seconds(offset_seconds)
    }

    #[test]
    fn a_second_presentation_before_expiry_is_a_replay() {
        let set = ReplaySet::default();
        assert!(set.remember("iss|a", at(300), at(0)));
        assert!(!set.remember("iss|a", at(300), at(1)));
        assert!(set.remember("iss|b", at(300), at(1)));
    }

    #[test]
    fn an_expired_entry_no_longer_blocks_its_key() {
        let set = ReplaySet::default();
        assert!(set.remember("iss|a", at(300), at(0)));
        assert!(!set.remember("iss|a", at(300), at(299)));
        assert!(
            set.remember("iss|a", at(600), at(300)),
            "at exactly exp the entry is purged"
        );
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn reaching_the_cap_evicts_the_earliest_expiry_and_counts_it() {
        let before =
            crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[]);
        let set = ReplaySet::with_cap(3);
        assert!(set.remember("iss|late", at(900), at(0)));
        assert!(set.remember("iss|early", at(100), at(0)));
        assert!(set.remember("iss|middle", at(500), at(0)));
        assert_eq!(set.len(), 3);

        assert!(set.remember("iss|fourth", at(700), at(0)));
        assert_eq!(set.len(), 3, "the cap holds");
        // The evicted id is the one expiring first, and its replay is
        // now possible: that is the window the counter reports.
        assert!(set.remember("iss|early", at(100), at(0)));
        assert!(!set.remember("iss|late", at(900), at(0)));
        assert_eq!(
            crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[])
                - before,
            2
        );
    }

    #[test]
    fn purging_runs_before_the_cap_is_measured() {
        let set = ReplaySet::with_cap(2);
        assert!(set.remember("iss|a", at(10), at(0)));
        assert!(set.remember("iss|b", at(20), at(0)));
        // Both have expired by now: the insert purges them instead of
        // evicting anything, and the counter does not move.
        let before =
            crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[]);
        assert!(set.remember("iss|c", at(100), at(30)));
        assert_eq!(set.len(), 1);
        assert_eq!(
            crate::metrics::gathered_counter("lorica_automation_oidc_replay_evictions_total", &[]),
            before
        );
    }
}
