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

//! Request coalescing primitive.
//!
//! Implements the dedup pattern from
//! `docs/architecture/worker-shared-state.md` § 4.5: concurrent callers
//! that need the same expensive result (e.g. a fan-out `MetricsRequest`
//! across N workers) coalesce into one in-flight computation; all
//! callers observe the same published value.
//!
//! A result is cached for `ttl` after publication; a new call after the
//! TTL re-issues the computation.

use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{watch, Mutex};

/// Coalesces concurrent computations keyed by `K`, caching the result
/// for a bounded TTL.
///
/// `get_or_issue(key, compute)` either:
/// - awaits the already-in-flight computation for `key` and returns a
///   clone of its result, or
/// - if no computation is in flight and no fresh cached result exists,
///   runs `compute`, publishes the result to all waiters, and caches
///   it for `ttl`.
///
/// The cached value is invalidated after `ttl`; subsequent callers
/// re-issue `compute`. Errors are not cached — a failing `compute` is
/// propagated to all current waiters, and the next caller re-issues.
///
/// `V` must be `Clone` because multiple waiters receive copies.
pub struct Coalescer<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + Sync + 'static,
{
    ttl: Duration,
    inner: Arc<Mutex<Inner<K, V>>>,
}

struct Inner<K, V> {
    slots: std::collections::HashMap<K, Slot<V>>,
}

enum Slot<V> {
    /// A computation is in flight. All waiters subscribe to `rx` and
    /// observe `Some(value)` once the first caller finishes.
    InFlight(watch::Receiver<Option<V>>),
    /// Last published value + when it was published. Served to callers
    /// while `now - published_at <= ttl`.
    Cached { value: V, published_at: Instant },
}

impl<K, V> Coalescer<K, V>
where
    K: Eq + Hash + Clone + Send + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(Mutex::new(Inner {
                slots: std::collections::HashMap::new(),
            })),
        }
    }

    /// Returns a cached value if fresh, joins an in-flight computation
    /// if one is running for `key`, or runs `compute` exactly once and
    /// publishes the result to all current waiters.
    pub async fn get_or_issue<F, Fut, E>(&self, key: K, compute: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        // Phase 1: decide under the lock whether we're the initiator, a
        // subscriber to in-flight, or a hit on the cache.
        enum Plan<V> {
            Initiate(watch::Sender<Option<V>>),
            Subscribe(watch::Receiver<Option<V>>),
            Cached(V),
        }

        let plan = {
            let mut guard = self.inner.lock().await;
            match guard.slots.get(&key) {
                Some(Slot::Cached {
                    value,
                    published_at,
                }) if published_at.elapsed() <= self.ttl => Plan::Cached(value.clone()),
                Some(Slot::InFlight(rx)) => Plan::Subscribe(rx.clone()),
                _ => {
                    let (tx, rx) = watch::channel::<Option<V>>(None);
                    guard.slots.insert(key.clone(), Slot::InFlight(rx));
                    Plan::Initiate(tx)
                }
            }
        };

        match plan {
            Plan::Cached(v) => Ok(v),
            Plan::Subscribe(mut rx) => {
                // Wait for publication. If the initiator failed, the slot
                // is removed and the watch sender dropped — recursively
                // retry once so callers still get an answer.
                loop {
                    if let Some(v) = rx.borrow().clone() {
                        return Ok(v);
                    }
                    if rx.changed().await.is_err() {
                        // Initiator dropped without publishing (error path).
                        // Recurse to either find a cached value or re-issue.
                        return Box::pin(self.get_or_issue(key, compute)).await;
                    }
                }
            }
            Plan::Initiate(tx) => {
                let compute_res = compute().await;
                let mut guard = self.inner.lock().await;
                match compute_res {
                    Ok(v) => {
                        // Publish, then replace InFlight with Cached.
                        let _ = tx.send(Some(v.clone()));
                        guard.slots.insert(
                            key,
                            Slot::Cached {
                                value: v.clone(),
                                published_at: Instant::now(),
                            },
                        );
                        Ok(v)
                    }
                    Err(e) => {
                        // Drop the slot so the next caller re-issues.
                        // Dropping tx signals rx.changed() -> Err to subs.
                        guard.slots.remove(&key);
                        drop(tx);
                        Err(e)
                    }
                }
            }
        }
    }

    /// Manually invalidate the cached entry for `key` (if any). Does not
    /// affect in-flight computations.
    pub async fn invalidate(&self, key: &K) {
        let mut guard = self.inner.lock().await;
        if let Some(Slot::Cached { .. }) = guard.slots.get(key) {
            guard.slots.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn concurrent_calls_coalesce_to_one_computation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let coal: Coalescer<&'static str, u32> = Coalescer::new(Duration::from_millis(200));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let coal = Coalescer {
                ttl: coal.ttl,
                inner: coal.inner.clone(),
            };
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                coal.get_or_issue::<_, _, ()>("k", || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok(42u32)
                })
                .await
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), Ok(42));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ttl_expiry_triggers_recompute() {
        let calls = Arc::new(AtomicUsize::new(0));
        let coal: Coalescer<&'static str, u32> = Coalescer::new(Duration::from_millis(30));

        for _ in 0..3 {
            let c = calls.clone();
            let v = coal
                .get_or_issue::<_, _, ()>("k", || async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(1)
                })
                .await
                .unwrap();
            assert_eq!(v, 1);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn error_is_not_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let coal: Coalescer<&'static str, u32> = Coalescer::new(Duration::from_secs(60));

        let c = calls.clone();
        let r: Result<u32, &'static str> = coal
            .get_or_issue("k", || async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err("boom")
            })
            .await;
        assert_eq!(r, Err("boom"));

        let c = calls.clone();
        let r: Result<u32, &'static str> = coal
            .get_or_issue("k", || async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
            .await;
        assert_eq!(r, Ok(7));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn manual_invalidation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let coal: Coalescer<&'static str, u32> = Coalescer::new(Duration::from_secs(60));

        for _ in 0..3 {
            let c = calls.clone();
            let _ = coal
                .get_or_issue::<_, _, ()>("k", || async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(1)
                })
                .await;
            coal.invalidate(&"k").await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
