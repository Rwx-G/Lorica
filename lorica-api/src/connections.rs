//! Per-backend active connection counters shared with the proxy engine.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

/// Thread-safe per-backend active connection counter, indexed by `host:port`.
#[derive(Default)]
pub struct BackendConnections {
    counts: RwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl BackendConnections {
    /// Create an empty registry with no tracked backends.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the counter for `addr`, inserting a new entry if absent. Returns the shared counter.
    pub fn increment(&self, addr: &str) -> Arc<AtomicU64> {
        let counts = self.counts.read();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(counter);
        }
        drop(counts);

        let mut counts = self.counts.write();
        let counter = counts
            .entry(addr.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
        Arc::clone(counter)
    }

    /// Decrement the counter for `addr`. No-op if the backend was never tracked.
    pub fn decrement(&self, addr: &str) {
        let counts = self.counts.read();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Read the current connection count for `addr`, or 0 if untracked.
    pub fn get(&self, addr: &str) -> u64 {
        let counts = self.counts.read();
        counts
            .get(addr)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Atomic snapshot of every tracked backend's current connection count.
    pub fn snapshot(&self) -> HashMap<String, u64> {
        let counts = self.counts.read();
        counts
            .iter()
            .map(|(addr, c)| (addr.clone(), c.load(Ordering::Relaxed)))
            .collect()
    }
}
