// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Per-stage `request_filter` rejection helpers.
//!
//! Story 8.1 AC #4 - the `check_<name>` methods extracted from
//! `request_filter` (AC #5) are split across per-concern submodules
//! so each file holds a coherent slice of the filter chain. The 16
//! helpers land as :
//!
//! - `connection` : process-wide + per-route active-connection caps,
//!   WebSocket upgrade gating, slowloris detection.
//! - `ip` : auto-ban table lookup, WAF IP blocklist, per-route
//!   allow / deny lists.
//! - `rate_limit` : token-bucket (`RateLimit` struct) and legacy
//!   (`rate_limit_rps`) per-IP / per-route throttling.
//! - `auth` : mTLS enforcement (495 / 496) and forward-auth sub-
//!   request dispatch (Allow / Deny / FailClosed).
//! - `waf` : header-phase + body-phase WAF evaluation, including the
//!   shmem / per-process auto-ban escalation.
//! - `geoip` : country resolution + per-route allowlist / denylist.
//! - `route_directive` : maintenance mode + `return_status` (direct
//!   response or `Location:` redirect).
//!
//! All four expose `check_<name>` methods on `LoricaProxy` via
//! separate `impl LoricaProxy` blocks ; the inherent impl is split
//! across files but stays a single inherent type at the type-system
//! level. The top-level `request_filter` reads as a flat sequence
//! of `if let Some(d) = self.check_X(...)? { return ... }` calls,
//! one per helper.

pub mod auth;
pub mod connection;
pub mod geoip;
pub mod ip;
pub mod rate_limit;
pub mod route_directive;
pub mod waf;
