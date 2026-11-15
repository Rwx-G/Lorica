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

//! The refusal log limiter (Story 12.8 D-j, generalised by Story 12.6
//! D-j): at most one row per key per [`REFUSAL_LOG_WINDOW`], then one row
//! counting what the window held back.
//!
//! Refusals are chosen by whoever connects, so a row per refusal would
//! let anyone choose the write rate of the log sinks; the counters still
//! count every refusal. The key is the caller's: the HTTP listeners key
//! it by listener and PROXY outcome, the stream engines by stream and
//! refusal. Each process has its own windows, so a node writes at most
//! one row per key per window per process.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// How long one refusal row per key holds back the next ones.
pub const REFUSAL_LOG_WINDOW: Duration = Duration::from_secs(10);

/// What the refusal log does with one refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalLogDecision {
    /// Write the refusal row, after a row reporting `suppressed` refusals
    /// of the same key that the window just closed held back and nobody
    /// has reported yet.
    Write {
        /// Refusals held back and not yet reported, 0 for none.
        suppressed: u64,
    },
    /// Hold the row back. `first` is true for the first refusal held back
    /// in this window: its caller arranges the report due at `window_ends`.
    Suppress {
        /// Whether this is the window's first held-back refusal.
        first: bool,
        /// When the window closes.
        window_ends: Instant,
    },
}

#[derive(Debug, Clone, Copy)]
struct RefusalWindow {
    opened: Instant,
    suppressed: u64,
}

/// At most one refusal row per key per [`REFUSAL_LOG_WINDOW`], then one
/// row counting what the window held back.
#[derive(Debug)]
pub struct RefusalLogLimiter<K> {
    windows: Mutex<HashMap<K, RefusalWindow>>,
}

impl<K> Default for RefusalLogLimiter<K> {
    fn default() -> Self {
        RefusalLogLimiter {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl<K: Hash + Eq + Copy> RefusalLogLimiter<K> {
    /// Decides on one refusal of `key` at `now`.
    pub fn admit(&self, key: K, now: Instant) -> RefusalLogDecision {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let fresh = RefusalWindow {
            opened: now,
            suppressed: 0,
        };
        match windows.get_mut(&key) {
            Some(window) if now < window.opened + REFUSAL_LOG_WINDOW => {
                window.suppressed += 1;
                RefusalLogDecision::Suppress {
                    first: window.suppressed == 1,
                    window_ends: window.opened + REFUSAL_LOG_WINDOW,
                }
            }
            Some(window) => {
                let suppressed = window.suppressed;
                *window = fresh;
                RefusalLogDecision::Write { suppressed }
            }
            None => {
                windows.insert(key, fresh);
                RefusalLogDecision::Write { suppressed: 0 }
            }
        }
    }

    /// Takes the count the window of `key` ending at `window_ends` held
    /// back, once: 0 when it was already taken, or when a later refusal
    /// opened a new window and reported it with its own row.
    pub fn close(&self, key: K, window_ends: Instant) -> u64 {
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        match windows.get_mut(&key) {
            Some(window) if window.opened + REFUSAL_LOG_WINDOW == window_ends => {
                std::mem::take(&mut window.suppressed)
            }
            _ => 0,
        }
    }

    /// Forget the windows of the keys `keep` refuses. A count they held
    /// back is dropped unreported: their subject is gone.
    pub fn retain(&self, mut keep: impl FnMut(&K) -> bool) {
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|key, _| keep(key));
    }

    /// Keys with a window.
    pub fn len(&self) -> usize {
        self.windows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether no key has a window.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Listener {
        Http,
        Https,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    enum Reason {
        UntrustedPeer,
        Timeout,
    }

    #[test]
    fn the_refusal_log_writes_one_row_per_window_and_reports_what_it_held_back_once() {
        let log = RefusalLogLimiter::default();
        let (http, https) = (Listener::Http, Listener::Https);
        let untrusted = Reason::UntrustedPeer;
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let first_window_ends = t0 + REFUSAL_LOG_WINDOW;

        assert_eq!(
            log.admit((http, untrusted), t0),
            RefusalLogDecision::Write { suppressed: 0 }
        );
        assert_eq!(
            log.admit((http, untrusted), at(1)),
            RefusalLogDecision::Suppress {
                first: true,
                window_ends: first_window_ends
            }
        );
        assert_eq!(
            log.admit((http, untrusted), at(2)),
            RefusalLogDecision::Suppress {
                first: false,
                window_ends: first_window_ends
            }
        );
        // Each part of the key has its own window.
        assert_eq!(
            log.admit((https, untrusted), at(2)),
            RefusalLogDecision::Write { suppressed: 0 }
        );
        assert_eq!(
            log.admit((http, Reason::Timeout), at(2)),
            RefusalLogDecision::Write { suppressed: 0 }
        );

        // The window's end reports its two held-back refusals, once.
        assert_eq!(log.close((http, untrusted), first_window_ends), 2);
        assert_eq!(log.close((http, untrusted), first_window_ends), 0);
        // Already reported: the next window opens with nothing owed.
        assert_eq!(
            log.admit((http, untrusted), first_window_ends),
            RefusalLogDecision::Write { suppressed: 0 }
        );

        // A refusal after the window, before its report ran, carries the
        // count itself, and the late report then finds nothing to say.
        let second_window_ends = first_window_ends + REFUSAL_LOG_WINDOW;
        assert!(matches!(
            log.admit(
                (http, untrusted),
                first_window_ends + Duration::from_secs(1)
            ),
            RefusalLogDecision::Suppress { first: true, .. }
        ));
        assert_eq!(
            log.admit(
                (http, untrusted),
                second_window_ends + Duration::from_secs(1)
            ),
            RefusalLogDecision::Write { suppressed: 1 }
        );
        assert_eq!(log.close((http, untrusted), second_window_ends), 0);
    }

    #[test]
    fn a_retained_key_keeps_its_window_and_a_dropped_one_starts_afresh() {
        let log = RefusalLogLimiter::default();
        let t0 = Instant::now();
        assert!(log.is_empty());
        for key in [1u32, 2] {
            log.admit(key, t0);
            log.admit(key, t0);
        }
        assert_eq!(log.len(), 2);
        log.retain(|key| *key == 1);
        assert_eq!(log.len(), 1);
        assert!(matches!(
            log.admit(1, t0),
            RefusalLogDecision::Suppress { first: false, .. }
        ));
        assert_eq!(
            log.admit(2, t0),
            RefusalLogDecision::Write { suppressed: 0 }
        );
    }
}
