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

//! Transport limits for cluster endpoints.
//!
//! Story 9.1 AC #3 made `RpcLimits` per-endpoint precisely because the
//! crate defaults are same-host UDS tuning; this is the WAN profile
//! every cluster endpoint (listener and dialer) is built with.

use std::time::Duration;

use lorica_command::RpcLimits;

/// Largest frame either side may send. The epic sizes a full
/// configuration push and a certificate bundle at about 1 MiB; 4 MiB
/// leaves headroom without turning a length prefix into a memory
/// grenade (the reader grows its buffer as bytes arrive, but a peer
/// that actually sends this much is still held for the frame).
pub const CLUSTER_MAX_MESSAGE_SIZE: u64 = 4 * 1024 * 1024;

/// Queue capacity per direction. Small on purpose: cluster traffic
/// is control traffic (one handshake, periodic heartbeats, occasional
/// pushes), and the per-connection decoded-frame ceiling is
/// `(outbound + inbound) * max_message_size` = 256 MiB worst case at
/// these values, further bounded by the listener's session cap.
pub const CLUSTER_QUEUE_CAP: usize = 32;

/// The WAN-tuned limits for every `RpcEndpoint<ClusterFrame>`.
///
/// `frame_read_timeout` (30 s) must stay above the dialer's default
/// heartbeat interval so an idle-but-healthy session is never cut
/// mid-frame; it bounds the time to receive one frame's body, not the
/// idle gap between frames.
pub fn cluster_rpc_limits() -> RpcLimits {
    RpcLimits {
        max_message_size: CLUSTER_MAX_MESSAGE_SIZE,
        outbound_queue_cap: CLUSTER_QUEUE_CAP,
        inbound_queue_cap: CLUSTER_QUEUE_CAP,
        slow_enqueue_warn: Duration::from_millis(50),
        default_request_timeout: Duration::from_secs(10),
        frame_read_timeout: Duration::from_secs(30),
        max_inflight: 256,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_limits_differ_from_the_uds_defaults() {
        let l = cluster_rpc_limits();
        let d = RpcLimits::default();
        assert!(l.max_message_size > d.max_message_size);
        assert!(l.outbound_queue_cap < d.outbound_queue_cap);
        assert!(l.inbound_queue_cap < d.inbound_queue_cap);
        assert_eq!(l.frame_read_timeout, Duration::from_secs(30));
    }
}
