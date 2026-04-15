// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! GeoIP live-reload plumbing for the proxy supervisor.
//!
//! `lorica-geoip::GeoIpResolver` hot-swaps its in-memory `.mmdb`
//! reader atomically via `ArcSwapOption`, but the `reload_proxy_config`
//! path in `lorica::reload` only sees `ConfigStore` and `ProxyConfig` —
//! it has no handle on the resolver. This module exposes a process-wide
//! `OnceLock<Arc<GeoIpResolver>>` that the single-process / worker
//! startup code registers once with [`set_handle`]; `reload.rs` then
//! reads the handle via [`handle`] to call `load_from_path` /
//! `unload` when `GlobalSettings.geoip_db_path` changes.
//!
//! A single OnceLock is safe because a given Lorica process only
//! owns one `GeoIpResolver` (worker processes are forked from the
//! supervisor but each one has its own process-wide static — fork
//! COWs the memory space and the worker's `ProxyApp::geoip_resolver`
//! field points at the same `Arc<GeoIpResolver>` we stash here).
//!
//! The handle is optional: a test harness that constructs a
//! `ProxyApp` without calling `set_handle` simply sees
//! `handle()` return `None`, and the reload path short-circuits to
//! a no-op with no panic / no warn spam.

use std::sync::{Arc, OnceLock};

use lorica_geoip::GeoIpResolver;

static GEOIP_RESOLVER_HANDLE: OnceLock<Arc<GeoIpResolver>> = OnceLock::new();

/// Register the process-wide GeoIP resolver handle. Called once from
/// each runtime's startup path (`run_single_process`, `run_worker`)
/// with the same `Arc` that backs `ProxyApp::geoip_resolver`. Second
/// and subsequent calls are silently ignored — the OnceLock is
/// set-once, so a test harness that calls this twice (rare, but
/// possible with nested `#[tokio::test]` runtimes) does not panic.
pub fn set_handle(resolver: Arc<GeoIpResolver>) {
    let _ = GEOIP_RESOLVER_HANDLE.set(resolver);
}

/// Read the process-wide GeoIP resolver handle. Returns `None` before
/// [`set_handle`] has been called (early boot, test harness, etc.).
pub fn handle() -> Option<Arc<GeoIpResolver>> {
    GEOIP_RESOLVER_HANDLE.get().cloned()
}
