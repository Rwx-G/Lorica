// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Supervisor-side shmem eviction task.
//!
//! The supervisor is the sole evictor of stale entries from the
//! cross-worker shared memory region (per-IP WAF flood / auto-ban
//! counters). Workers only read + increment ; the eviction walker
//! periodically removes entries whose `last_activity_ns` is older
//! than `DEFAULT_STALE_AFTER`. See
//! `docs/architecture/worker-shared-state.md` § 5.4.

use lorica_shmem::SharedRegion;

/// Spawn the supervisor's shared-memory eviction walker. Runs every
/// `lorica_shmem::DEFAULT_SCAN_INTERVAL` (60 s) and evicts entries
/// older than `DEFAULT_STALE_AFTER` (5 min). The first tick is
/// skipped so the eviction does not run during the supervisor's
/// boot-stabilisation phase.
pub fn spawn_shmem_eviction_task(region: &'static SharedRegion) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(lorica_shmem::DEFAULT_SCAN_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // skip the immediate tick
        let stale_ns = lorica_shmem::DEFAULT_STALE_AFTER.as_nanos() as u64;
        loop {
            tick.tick().await;
            let now = lorica_shmem::now_ns();
            let stats = lorica_shmem::evict_once(region, now, stale_ns);
            lorica_shmem::eviction::log_pass(stats);
        }
    });
}
