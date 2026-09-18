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

//! The node-wide ceiling on bytes held for WAF body inspection
//! (Story 10.6 AC #7).
//!
//! The per-route `waf_body_scan_max_bytes` shapes one request; it is
//! not a guarantee, because the node's real exposure is that value
//! times the number of inspectable requests in flight. At the API's 64
//! MiB ceiling and 500 concurrent requests that is 32 GB. This budget
//! is the number that actually bounds the node.
//!
//! The mechanism is [`crate::byte_budget`], shared with traffic
//! capture. Two things are specific here:
//!
//! - The ceiling comes from the `waf_body_scan_max_inflight_bytes`
//!   global setting, so it moves with a configuration reload
//!   ([`set_ceiling_from_settings`], called while a snapshot is built).
//! - Over budget, the request is ALLOWED THROUGH in both WAF modes. It
//!   is not buffered, not scanned, and not rejected. See
//!   [`waf_body_budget`] for why that direction and not the other.

use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::byte_budget::ByteBudget;

/// Bytes every in-flight WAF scan buffer on this process may hold at
/// once, before an operator says otherwise: 256 MiB.
///
/// Mirrors `lorica_config`'s default for
/// `waf_body_scan_max_inflight_bytes`. Duplicated rather than imported
/// because this static is built before any settings row is read, on the
/// very first request a process serves, and a node whose store is
/// unreadable must still run under a bound.
pub const WAF_BODY_SCAN_DEFAULT_INFLIGHT_BYTES: usize = 268_435_456;

/// The process-wide budget every inspected body reserves from.
static WAF_BODY_BUDGET: Lazy<Arc<ByteBudget>> = Lazy::new(|| {
    ByteBudget::publishing(
        WAF_BODY_SCAN_DEFAULT_INFLIGHT_BYTES,
        lorica_api::metrics::set_waf_body_scan_inflight_bytes,
    )
});

/// The budget the proxy pipeline reserves WAF scan buffers from.
///
/// WHY IT FAILS OPEN. A request that cannot fit under this budget is
/// forwarded unscanned, in Blocking mode as well as Detection, with one
/// `WafEvent` and one `lorica_waf_body_scans_total{outcome="skipped_budget"}`
/// increment. Failing closed would be worse than the gap it closes: the
/// budget is shared by every route on the node, so any client able to
/// keep it saturated - a handful of slow large uploads is enough -
/// would turn it into a fleet-wide 413 storm against traffic that has
/// nothing wrong with it. A scan gap that is counted, evented and
/// alarmable is recoverable; a self-inflicted outage on every route at
/// once is not. The operator's lever is the setting itself, and the
/// counter is what tells them to pull it.
///
/// Tests that need to exercise the ceiling build their own
/// [`ByteBudget`] instead, so they neither observe nor disturb the
/// accounting of a concurrently running test.
pub fn waf_body_budget() -> &'static Arc<ByteBudget> {
    &WAF_BODY_BUDGET
}

/// Turn the stored setting into a ceiling this process can hold.
///
/// `0` is not a valid ceiling (it would skip every scan on the node) so
/// it falls back to [`WAF_BODY_SCAN_DEFAULT_INFLIGHT_BYTES`], matching
/// how the rest of the reload path treats an unset numeric setting. The
/// write boundary already refuses it; this is the runtime's own floor.
/// A value past `usize` on a 32-bit target saturates rather than
/// wrapping into a tiny ceiling.
pub fn resolve_ceiling(bytes: u64) -> usize {
    if bytes == 0 {
        WAF_BODY_SCAN_DEFAULT_INFLIGHT_BYTES
    } else {
        usize::try_from(bytes).unwrap_or(usize::MAX)
    }
}

/// Point the process-wide budget at the reloaded setting.
///
/// Called while a `ProxyConfig` snapshot is built, next to the capture
/// budget's own reload hook, so the value a request reserves against is
/// the one the live configuration carries. Reservations already taken
/// are untouched; see [`ByteBudget::set_ceiling`].
pub fn set_ceiling_from_settings(bytes: u64) {
    waf_body_budget().set_ceiling(resolve_ceiling(bytes));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_setting_falls_back_to_the_default_rather_than_skipping_every_scan() {
        assert_eq!(resolve_ceiling(0), WAF_BODY_SCAN_DEFAULT_INFLIGHT_BYTES);
        assert_eq!(resolve_ceiling(33_554_432), 33_554_432);
        // Saturates instead of wrapping into a ceiling of nearly zero.
        assert_eq!(resolve_ceiling(u64::MAX), usize::MAX);
    }

    #[test]
    fn the_node_budget_starts_bounded_before_any_setting_is_read() {
        // Never zero, never unbounded: the first request a process
        // serves runs under a ceiling even if the store never answered.
        assert!(waf_body_budget().ceiling() > 0);
    }
}
