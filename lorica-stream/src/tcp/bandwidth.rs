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

//! Per-connection bandwidth limits (Story 12.3 D-o): one token bucket per
//! direction, refilled at the rate, holding at most one second's worth
//! and at most one forwarding buffer. A direction waits for a token
//! before it reads, reads at most what the bucket holds, and spends what
//! it read: the limit throttles reads and never queues a write, so it
//! composes with the backpressure of the forwarding loop and holds no
//! memory of its own.

use std::time::Duration;

use tokio::time::Instant;

use super::FORWARD_BUFFER_SIZE;

/// The fewest bytes a throttled read waits for, unless the bucket holds
/// fewer: waking per byte would cost a task wake-up per byte forwarded
/// at low rates. The smallest accepted rate is this many bytes per
/// second, so the wait is at most one second.
const READ_QUANTUM: u64 = 1_024;

/// A token bucket counting bytes.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: u64,
    capacity: u64,
    tokens: f64,
    refilled_at: Instant,
}

impl TokenBucket {
    /// A full bucket for `rate` bytes per second (at least 1).
    pub fn new(rate: u64) -> Self {
        let rate = rate.max(1);
        let capacity = rate.min(FORWARD_BUFFER_SIZE as u64);
        TokenBucket {
            rate,
            capacity,
            tokens: capacity as f64,
            refilled_at: Instant::now(),
        }
    }

    /// The bucket's capacity in bytes.
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.refilled_at);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * self.rate as f64).min(self.capacity as f64);
        self.refilled_at = now;
    }

    /// Whole bytes that may be read now.
    pub fn available(&mut self) -> usize {
        self.refill(Instant::now());
        // Truncation is the point: a fraction of a byte cannot be read.
        self.tokens.floor() as usize
    }

    /// Wait until a read is worth making: the bucket holds
    /// [`READ_QUANTUM`] bytes, or is full when it holds fewer.
    /// Cancel-safe: it changes nothing a later call would miss.
    pub async fn ready(&mut self) {
        let wanted = READ_QUANTUM.min(self.capacity) as f64;
        loop {
            self.refill(Instant::now());
            if self.tokens >= wanted {
                return;
            }
            let missing = wanted - self.tokens;
            tokio::time::sleep(Duration::from_secs_f64(missing / self.rate as f64)).await;
        }
    }

    /// Spend `bytes` just read.
    pub fn spend(&mut self, bytes: usize) {
        self.tokens -= bytes as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_burst_is_one_second_and_one_buffer_at_most() {
        assert_eq!(TokenBucket::new(1_024).capacity(), 1_024);
        assert_eq!(
            TokenBucket::new(10_000_000_000).capacity(),
            FORWARD_BUFFER_SIZE as u64
        );
    }

    #[tokio::test(start_paused = true)]
    async fn sixty_four_kib_at_sixteen_kib_per_second_take_three_seconds() {
        let mut bucket = TokenBucket::new(16 * 1024);
        let start = Instant::now();
        let mut moved = 0usize;
        while moved < 64 * 1024 {
            bucket.ready().await;
            let n = bucket.available().min(64 * 1024 - moved);
            bucket.spend(n);
            moved += n;
        }
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(2_990) && took <= Duration::from_millis(3_100),
            "{took:?}"
        );
    }
}
