use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Thread-safe per-backend active connection counter.
#[derive(Default)]
pub struct BackendConnections {
    counts: RwLock<HashMap<String, Arc<AtomicU64>>>,
}

impl BackendConnections {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&self, addr: &str) -> Arc<AtomicU64> {
        let counts = self.counts.read().unwrap();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_add(1, Ordering::Relaxed);
            return Arc::clone(counter);
        }
        drop(counts);

        let mut counts = self.counts.write().unwrap();
        let counter = counts
            .entry(addr.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)));
        counter.fetch_add(1, Ordering::Relaxed);
        Arc::clone(counter)
    }

    pub fn decrement(&self, addr: &str) {
        let counts = self.counts.read().unwrap();
        if let Some(counter) = counts.get(addr) {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn get(&self, addr: &str) -> u64 {
        let counts = self.counts.read().unwrap();
        counts
            .get(addr)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn snapshot(&self) -> HashMap<String, u64> {
        let counts = self.counts.read().unwrap();
        counts
            .iter()
            .map(|(addr, c)| (addr.clone(), c.load(Ordering::Relaxed)))
            .collect()
    }
}
