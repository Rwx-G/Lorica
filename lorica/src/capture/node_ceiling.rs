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

//! The node-wide ceiling on bytes held for capture.
//!
//! A capture rule is a diagnostic an operator can enable on a node that
//! also terminates production TLS, so it must not be usable as a
//! memory-exhaustion primitive: without a ceiling, `rule count x
//! request rate x body cap` is unbounded. One counter covers every rule
//! and every in-flight request on the process, and a request that
//! cannot fit under it records nothing instead of allocating anyway.
//!
//! The mechanism itself is [`crate::byte_budget`], shared with WAF body
//! inspection, which buffers request bodies for its own reasons and
//! needs the same guarantee. This module is the capture instance of it:
//! the constant, the static, and the gauge it publishes. See that
//! module for why the counter is a process-wide static and why the
//! release is a `Drop` impl.

use std::sync::Arc;

use once_cell::sync::Lazy;

use crate::byte_budget::ByteBudget;

/// Bytes every in-flight capture on this process may hold at once,
/// across all rules: 64 MiB.
///
/// Sized to be irrelevant next to the node's working set (the HTTP
/// response cache alone is allowed 128 MiB) while still bounding the
/// worst case at a fixed number that does not scale with traffic.
///
/// A compile-time constant, unlike the WAF body-scan budget: capture is
/// off by default and an operator who turns it on is asking for a
/// diagnostic, not sizing a production memory envelope.
pub const CAPTURE_MAX_INFLIGHT_BYTES: usize = 64 * 1024 * 1024;

/// A budget over capture buffers.
///
/// An alias rather than a type of its own: the rule is
/// [`ByteBudget`]'s, and capture keeps its own vocabulary at the call
/// sites that admit a request.
pub type CaptureBudget = ByteBudget;

/// Bytes one request holds against a [`CaptureBudget`].
pub type CaptureReservation = crate::byte_budget::ByteReservation;

/// The process-wide budget every request reserves from.
static NODE_BUDGET: Lazy<Arc<CaptureBudget>> = Lazy::new(|| {
    ByteBudget::publishing(
        CAPTURE_MAX_INFLIGHT_BYTES,
        lorica_api::metrics::set_capture_inflight_bytes,
    )
});

/// The budget the proxy pipeline uses.
///
/// Tests that need to exercise the ceiling build their own
/// [`CaptureBudget`] instead, so they neither observe nor disturb the
/// accounting of a concurrently running test.
pub fn node_budget() -> &'static Arc<CaptureBudget> {
    &NODE_BUDGET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_budget_runs_under_the_documented_ceiling() {
        // The behaviour of the type is covered in `byte_budget`; what
        // belongs here is that the capture instance was wired to the
        // constant this module documents and not to something else.
        assert_eq!(node_budget().ceiling(), CAPTURE_MAX_INFLIGHT_BYTES);
    }
}
