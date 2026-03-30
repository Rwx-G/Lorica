// Copyright 2026 Cloudflare, Inc.
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

//! Implementation of algorithms for weighted selection
//!
//! All [std::hash::Hasher] + [Default] can be used directly as a selection algorithm.

use super::*;
use std::hash::Hasher;
use std::sync::atomic::{AtomicUsize, Ordering};

impl<H> SelectionAlgorithm for H
where
    H: Default + Hasher,
{
    fn new() -> Self {
        H::default()
    }
    fn next(&self, key: &[u8]) -> u64 {
        let mut hasher = H::default();
        hasher.write(key);
        hasher.finish()
    }
}

/// Round Robin selection
pub struct RoundRobin(AtomicUsize);

impl SelectionAlgorithm for RoundRobin {
    fn new() -> Self {
        Self(AtomicUsize::new(0))
    }
    fn next(&self, _key: &[u8]) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed) as u64
    }
}

/// Random selection
pub struct Random;

impl SelectionAlgorithm for Random {
    fn new() -> Self {
        Self
    }
    fn next(&self, _key: &[u8]) -> u64 {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        rng.gen()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    #[test]
    fn test_round_robin_increments() {
        let rr = RoundRobin::new();
        assert_eq!(rr.next(b""), 0);
        assert_eq!(rr.next(b""), 1);
        assert_eq!(rr.next(b""), 2);
    }

    #[test]
    fn test_round_robin_ignores_key() {
        let rr = RoundRobin::new();
        assert_eq!(rr.next(b"a"), 0);
        assert_eq!(rr.next(b"b"), 1);
        assert_eq!(rr.next(b"c"), 2);
    }

    #[test]
    fn test_hasher_deterministic() {
        let h = <DefaultHasher as SelectionAlgorithm>::new();
        let v1 = h.next(b"test-key");
        let v2 = h.next(b"test-key");
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_hasher_different_keys_differ() {
        let h = <DefaultHasher as SelectionAlgorithm>::new();
        let v1 = h.next(b"key-a");
        let v2 = h.next(b"key-b");
        assert_ne!(v1, v2);
    }

    #[test]
    fn test_random_produces_values() {
        let r = Random::new();
        let v1 = r.next(b"");
        let v2 = r.next(b"");
        // Very unlikely to be equal, but we just check they don't panic
        let _ = (v1, v2);
    }

    #[test]
    fn test_round_robin_high_count() {
        let rr = RoundRobin::new();
        for i in 0..1000u64 {
            assert_eq!(rr.next(b""), i);
        }
    }
}
