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

//! Control-plane admission control on convergence (Story 9.2 AC #10).
//!
//! After a control-plane restart every follower reconnects within the
//! backoff cap and each pulls its full state: a synchronised burst
//! against a node that just started cold. The gate bounds how many
//! sessions converge CONCURRENTLY (`max_concurrent`), lets a bounded
//! number wait their turn (`queue_depth`), and answers everyone past
//! that with [`ClusterStatus::RetryLater`] plus a `retry_after_s` the
//! dialer honours as its next delay.
//!
//! [`ClusterStatus::RetryLater`]: crate::messages::ClusterStatus::RetryLater

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// RAII permit for one converging session. Dropping it releases both
/// the queue slot and the active slot.
pub struct AdmissionPermit {
    _active: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}

/// Outcome of [`AdmissionGate::admit`].
pub enum AdmissionDecision {
    /// The session may proceed with its handshake / initial sync. The
    /// permit must be held until convergence completes.
    Admitted(AdmissionPermit),
    /// Both the active set and the wait queue are full; the peer must
    /// come back after `retry_after_s` seconds.
    RetryLater {
        /// Seconds the peer should wait before its next attempt.
        retry_after_s: u32,
    },
}

/// Default bound on a queued wait: shorter than the dialer's default
/// request timeout (10 s) so the SERVER answers RetryLater before the
/// CLIENT gives up, reconnects, and takes a second queue slot for a
/// permit it no longer wants.
pub const DEFAULT_QUEUE_WAIT: Duration = Duration::from_secs(5);

/// Concurrent-session limit with a bounded wait queue (AC #10).
pub struct AdmissionGate {
    /// Total occupancy bound: active + queued. `try_acquire` failing
    /// here means the queue itself is full.
    slots: Arc<Semaphore>,
    /// Concurrency bound: holders of one of these are actively
    /// converging; the rest of the slot holders are queued.
    active: Arc<Semaphore>,
    retry_after_s: u32,
    queue_wait: Duration,
    /// `(max_concurrent, max_concurrent + queue_depth)`: semaphores
    /// never grow, so the created capacities are the occupancy
    /// denominators for the gauges.
    capacity: (usize, usize),
}

impl AdmissionGate {
    /// A gate admitting `max_concurrent` sessions at once, queueing up
    /// to `queue_depth` more, and telling everyone else to retry after
    /// `retry_after_s` seconds. Queued sessions wait at most
    /// [`DEFAULT_QUEUE_WAIT`]; see [`AdmissionGate::with_queue_wait`].
    pub fn new(max_concurrent: usize, queue_depth: usize, retry_after_s: u32) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(max_concurrent + queue_depth)),
            active: Arc::new(Semaphore::new(max_concurrent)),
            retry_after_s,
            queue_wait: DEFAULT_QUEUE_WAIT,
            capacity: (max_concurrent, max_concurrent + queue_depth),
        }
    }

    /// Override the bound on a queued wait (keep it below the peers'
    /// request timeout, see [`DEFAULT_QUEUE_WAIT`]).
    pub fn with_queue_wait(mut self, queue_wait: Duration) -> Self {
        self.queue_wait = queue_wait;
        self
    }

    /// The bound on a queued wait this gate applies in
    /// [`AdmissionGate::admit`].
    pub fn queue_wait(&self) -> Duration {
        self.queue_wait
    }

    /// The `retry_after_s` this gate tells refused peers to wait, so
    /// other refusal paths (the session cap) advertise the same delay.
    pub fn retry_after_s_hint(&self) -> u32 {
        self.retry_after_s
    }

    /// Currently converging sessions (active permits held).
    pub fn active_count(&self) -> usize {
        self.active_capacity() - self.active.available_permits()
    }

    /// Sessions waiting in the queue for an active slot.
    pub fn queued_count(&self) -> usize {
        let occupied = self.slots_capacity() - self.slots.available_permits();
        occupied.saturating_sub(self.active_count())
    }

    fn active_capacity(&self) -> usize {
        // Semaphores never grow; capacity is what was created.
        self.capacity.0
    }

    fn slots_capacity(&self) -> usize {
        self.capacity.1
    }

    /// Try to admit one converging session: immediate `RetryLater`
    /// when the queue is full, otherwise waits in the bounded queue for
    /// an active slot for at most the gate's queue wait, answering
    /// `RetryLater` on expiry.
    pub async fn admit(&self) -> AdmissionDecision {
        self.admit_within(self.queue_wait).await
    }

    /// [`AdmissionGate::admit`] with an explicit bound on the queued
    /// wait.
    pub async fn admit_within(&self, wait: Duration) -> AdmissionDecision {
        let retry_later = AdmissionDecision::RetryLater {
            retry_after_s: self.retry_after_s,
        };
        let slot = match Arc::clone(&self.slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return retry_later,
        };
        // The semaphores are never closed, so acquire can only fail if
        // the gate itself were torn down mid-await; answer RetryLater
        // rather than panicking in library code. The timeout is the
        // queued-wait bound.
        match tokio::time::timeout(wait, Arc::clone(&self.active).acquire_owned()).await {
            Ok(Ok(active)) => AdmissionDecision::Admitted(AdmissionPermit {
                _active: active,
                _slot: slot,
            }),
            Ok(Err(_)) | Err(_) => retry_later,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_queued_session_is_told_to_retry_when_the_wait_expires() {
        let gate = Arc::new(AdmissionGate::new(1, 1, 9));
        let _active = admitted(gate.admit().await);
        // Queue slot free, active slot held: the wait bound decides.
        match gate.admit_within(Duration::from_millis(100)).await {
            AdmissionDecision::RetryLater { retry_after_s } => assert_eq!(retry_after_s, 9),
            AdmissionDecision::Admitted(_) => panic!("must not be admitted past the wait"),
        }
        // And the queue slot was released with the refusal.
        assert_eq!(gate.queued_count(), 0);
        assert_eq!(gate.active_count(), 1);
    }

    fn admitted(d: AdmissionDecision) -> AdmissionPermit {
        match d {
            AdmissionDecision::Admitted(p) => p,
            AdmissionDecision::RetryLater { .. } => panic!("expected admission"),
        }
    }

    #[tokio::test]
    async fn concurrent_sessions_up_to_the_limit_are_admitted() {
        let gate = AdmissionGate::new(2, 1, 30);
        let _a = admitted(gate.admit().await);
        let _b = admitted(gate.admit().await);
    }

    #[tokio::test]
    async fn a_session_past_the_limit_waits_in_the_queue() {
        let gate = Arc::new(AdmissionGate::new(1, 1, 30));
        let first = admitted(gate.admit().await);

        // Second admit occupies the queue slot and blocks...
        let gate_c = Arc::clone(&gate);
        let waiter = tokio::spawn(async move { gate_c.admit().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiter.is_finished(), "queued session must wait");

        // ...until the active session releases its permit.
        drop(first);
        let second = tokio::time::timeout(Duration::from_secs(10), waiter)
            .await
            .expect("queued session must be admitted after a release")
            .expect("task");
        let _second = admitted(second);
    }

    #[tokio::test]
    async fn a_session_past_the_queue_gets_retry_later() {
        let gate = AdmissionGate::new(1, 1, 45);
        let _active = admitted(gate.admit().await);
        // Occupy the single queue slot with a pending admit.
        let gate = Arc::new(gate);
        let gate_c = Arc::clone(&gate);
        let _queued = tokio::spawn(async move { gate_c.admit().await });
        tokio::time::sleep(Duration::from_millis(50)).await;

        match gate.admit().await {
            AdmissionDecision::RetryLater { retry_after_s } => assert_eq!(retry_after_s, 45),
            AdmissionDecision::Admitted(_) => panic!("expected RetryLater past the queue"),
        }
    }
}
