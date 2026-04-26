// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Data-plane handle setup + prune spawns shared by the worker and
//! single-process boot paths.
//!
//! Both modes carry a live `LoricaProxy` instance, so they need the same
//! per-process resolver handles registered (GeoIP / ASN, the rDNS
//! resolver), and the same three lazy-prune background tasks running
//! against the proxy's caches (basic-auth verification cache, per-IP
//! rate-limit buckets, bot challenge stash). Supervisor mode does NOT
//! call these helpers - it has no `LoricaProxy` of its own.
//!
//! Both helpers must be called from inside an active tokio runtime
//! context : `init_data_plane_handles` constructs `RdnsResolver` which
//! latches onto the current runtime (hickory-resolver internals), and
//! `spawn_data_plane_pruners` calls `tokio::spawn` through the proxy's
//! prune helpers. Worker mode wraps the calls in a `rt.enter()` guard
//! because it sits between two `rt.block_on(...)` blocks at the call
//! site ; single-process is already inside the outer `rt.block_on`.
//!
//! **Why this exists** : the v1.5.2 worker-mode cert hot-reload bug had
//! the same shape - the worker boot path was missing a step that single
//! and supervisor had wired. Folding both data-plane setup blocks
//! through one helper here makes that class of asymmetry harder to
//! introduce in the future. The `cargo expand` diff before / after this
//! extraction is empty.

use std::sync::Arc;
use std::time::Duration;

use tokio_util::task::TaskTracker;
use tracing::{info, warn};

use lorica::proxy_wiring::LoricaProxy;

/// Initialise the per-process data-plane resolver handles : the GeoIP
/// resolver + ASN resolver are registered in the `lorica::geoip`
/// statics so the config-reload path can hot-swap their backing files,
/// and the rDNS resolver is built from the system `resolv.conf` and
/// stashed in the `lorica::bot_rdns` static for bot-protection's rdns
/// bypass category.
///
/// `role` is folded into log messages ("worker:" / "single:") so the
/// per-role logs stay distinguishable post-extraction.
///
/// Caller MUST be inside an active tokio runtime context : the rDNS
/// resolver constructor latches onto the current runtime.
pub fn init_data_plane_handles(proxy: &LoricaProxy, role: &str) {
    lorica::geoip::set_handle(Arc::clone(&proxy.geoip_resolver));
    lorica::geoip::set_asn_handle(Arc::clone(&proxy.asn_resolver));
    init_rdns_resolver(role);
}

/// Build and register the rDNS resolver from the system `resolv.conf`.
/// A missing or broken file is not fatal - it just disables the rDNS
/// bypass category for this process (the other bot-protection
/// categories keep working).
fn init_rdns_resolver(role: &str) {
    match lorica::bot_rdns::RdnsResolver::from_system_conf() {
        Ok(r) => {
            lorica::bot_rdns::set_handle(Arc::new(r));
            info!(role = %role, "rDNS resolver initialised from system resolv.conf");
        }
        Err(e) => warn!(
            role = %role,
            error = %e,
            "rDNS resolver init failed; bot_protection.bypass.rdns will be a silent no-op"
        ),
    }
}

/// Spawn the three lazy-prune background tasks against the proxy's
/// in-memory caches :
/// - basic-auth verification cache : 30 s scan, evict expired entries.
///   Bound on a password-spray scenario where attackers never produce a
///   successful login that would naturally evict their entry (PERF-8).
/// - per-IP rate-limit buckets : 60 s scan, 5 min idle TTL. Without
///   this, a port scan or high-cardinality crawler accumulates one
///   bucket per distinct IP forever.
/// - bot challenge stash : default cadence inside the proxy helper.
///
/// The `JoinHandle`s the underlying `spawn_*` helpers return are
/// intentionally dropped here : the tracker owns the tasks (they live
/// attached to the runtime until shutdown drain), and dropping a tokio
/// `JoinHandle` does NOT abort the task. Mirrors the pre-extraction
/// pattern of binding to `_basic_auth_prune` etc. at every call site.
///
/// `task_tracker` is the per-role tracker (worker has its own local
/// tracker because it is between `rt.block_on` blocks at the call site ;
/// single uses its main `single_task_tracker`). Caller MUST be inside an
/// active tokio runtime context.
pub fn spawn_data_plane_pruners(proxy: &LoricaProxy, task_tracker: &TaskTracker) {
    let _basic_auth =
        proxy.spawn_basic_auth_cache_prune(task_tracker, Duration::from_secs(30));
    let _rate_limit = proxy.spawn_rate_limit_prune(
        task_tracker,
        Duration::from_secs(60),
        Duration::from_secs(5 * 60),
    );
    let _bot_stash = proxy.spawn_bot_stash_prune(task_tracker);
}
