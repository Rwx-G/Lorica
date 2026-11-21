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
//! direction, refilled at the rate, holding at most one second's worth:
//! one forwarding buffer, or [`TIMER_ALLOWANCE`] of the rate when that is
//! more. A direction waits for a token before it reads, reads at most
//! what the bucket holds and its buffer takes, and spends what it read:
//! the limit throttles reads and never queues a write, so it composes
//! with the backpressure of the forwarding loop and holds no memory of
//! its own.

use std::time::Duration;

use tokio::time::Instant;

use super::FORWARD_BUFFER_SIZE;

/// The fewest bytes a throttled read waits for, unless the bucket holds
/// fewer: waking per byte would cost a task wake-up per byte forwarded
/// at low rates. The smallest accepted rate is this many bytes per
/// second, so the wait is at most one second.
const READ_QUANTUM: u64 = 1_024;

/// The rate's worth the bucket can hold beyond one buffer. tokio's timer
/// fires on millisecond ticks and rounds a wait up to the next one, so a
/// wait of a few microseconds lasts up to two ticks: a bucket capped at
/// one buffer would then throw away what those ticks refilled past it,
/// and every rate above one buffer per tick (about 16 MB/s) would run at
/// that ceiling. Below eight MB/s one buffer is the larger of the two.
const TIMER_ALLOWANCE: Duration = Duration::from_millis(2);

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
        let over_the_timer = u64::try_from(
            u128::from(rate) * TIMER_ALLOWANCE.as_nanos() / Duration::from_secs(1).as_nanos(),
        )
        .unwrap_or(u64::MAX);
        let capacity = rate.min(FORWARD_BUFFER_SIZE as u64).max(over_the_timer);
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

    /// When a read is worth making: `None` if it is at `now`, otherwise
    /// the instant the bucket holds [`READ_QUANTUM`] bytes, or is full
    /// when it holds fewer. Nothing is spent until a read, so the instant
    /// stays right until then.
    pub fn ready_at(&mut self, now: Instant) -> Option<Instant> {
        let wanted = READ_QUANTUM.min(self.capacity) as f64;
        self.refill(now);
        if self.tokens >= wanted {
            return None;
        }
        let missing = wanted - self.tokens;
        Some(now + Duration::from_secs_f64(missing / self.rate as f64))
    }

    /// Wait until a read is worth making ([`TokenBucket::ready_at`]).
    /// Cancel-safe: it changes nothing a later call would miss.
    pub async fn ready(&mut self) {
        while let Some(at) = self.ready_at(Instant::now()) {
            tokio::time::sleep_until(at).await;
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
    fn the_burst_is_one_second_and_one_buffer_or_two_timer_ticks_at_most() {
        assert_eq!(TokenBucket::new(1_024).capacity(), 1_024);
        assert_eq!(
            TokenBucket::new(8_000_000).capacity(),
            FORWARD_BUFFER_SIZE as u64
        );
        assert_eq!(TokenBucket::new(64_000_000).capacity(), 128_000);
        assert_eq!(TokenBucket::new(10_000_000_000).capacity(), 20_000_000);
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

    /// On a real clock, whose timer fires on millisecond ticks: a rate
    /// above one buffer per tick must keep what a tick refills past one
    /// buffer, or every such rate tops out near one buffer per
    /// millisecond, about 16 MB/s. 8 MiB at 64 MiB/s is an eighth of a
    /// second.
    #[tokio::test]
    async fn eight_mib_at_sixty_four_mib_per_second_take_an_eighth_of_a_second() {
        const SIZE: usize = 8 * 1024 * 1024;
        let mut bucket = TokenBucket::new(64 * 1024 * 1024);
        let start = Instant::now();
        let mut moved = 0usize;
        while moved < SIZE {
            bucket.ready().await;
            let n = bucket
                .available()
                .min(FORWARD_BUFFER_SIZE)
                .min(SIZE - moved);
            bucket.spend(n);
            moved += n;
        }
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(100) && took < Duration::from_millis(250),
            "{took:?}"
        );
    }
}
