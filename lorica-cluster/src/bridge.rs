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

//! The confused-deputy guard between the cluster plane and the worker
//! plane (Story 9.2 AC #6, enforcement half).
//!
//! The worker `Command` message is one flat type that includes
//! `SHUTDOWN` and `BAN_IP` with no plane discriminator. If the cluster
//! plane FORWARDED rather than strictly translated, any enrolled
//! follower could shut down the control plane's workers or poison its
//! ban list. So:
//!
//! - EVERY inbound cluster request routes through
//!   [`translate_cluster_request`]; there is no other dispatch path.
//! - The whitelist below is the complete set of things the cluster
//!   plane may do. In Story 9.2 it contains ONLY in-plane session
//!   traffic; Stories 9.4/9.6 add explicit entries for configuration
//!   apply and telemetry fan-in.
//! - Nothing here ever passes a peer-supplied `CommandType` (or any
//!   other worker-plane value) through to `lorica-command`. A future
//!   entry that needs a worker-plane effect must CONSTRUCT the worker
//!   command itself from validated fields.
//! - Anything not on the whitelist, including an empty body (which is
//!   what deliberately mis-sent worker-`Envelope` bytes decode to,
//!   see [`crate::frame`]), is a [`BridgeOutcome::ProtocolViolation`]:
//!   the caller drops the connection and increments its violation
//!   counter.

use crate::messages::{cluster_request, ClusterRequest};

/// The in-plane actions the whitelist admits (Story 9.2 set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InPlaneAction {
    /// A liveness probe carrying the sender's clock (unix ms).
    Heartbeat {
        /// The probe's `timestamp_ms`, echoed in the ack.
        timestamp_ms: u64,
    },
}

/// Outcome of routing one inbound cluster request through the
/// whitelist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The request is on the whitelist; handle it in-plane.
    InPlane(InPlaneAction),
    /// The request is not on the whitelist (unknown, empty, or
    /// wrong-phase body): drop the connection.
    ProtocolViolation,
}

/// Route one inbound cluster request through the whitelist.
///
/// This is the single dispatch point for established sessions. A
/// [`Hello`] here is a violation too: the opener is consumed by the
/// handshake before a session reaches steady state, so a second one
/// is a peer speaking out of phase.
///
/// [`Hello`]: crate::messages::Hello
pub fn translate_cluster_request(request: &ClusterRequest) -> BridgeOutcome {
    match &request.body {
        // ---- The whitelist. Every entry is a reviewed decision. ----
        Some(cluster_request::Body::Heartbeat(hb)) => BridgeOutcome::InPlane(
            InPlaneAction::Heartbeat {
                timestamp_ms: hb.timestamp_ms,
            },
        ),
        // ---- Everything else is a violation. ----
        Some(cluster_request::Body::Hello(_)) | None => BridgeOutcome::ProtocolViolation,
    }
}

#[cfg(test)]
mod tests {
    use lorica_command::messages::{envelope, Command, CommandType, Envelope};
    use prost::Message;

    use super::*;
    use crate::messages::{cluster_request, ClusterFrame, Heartbeat, Hello};
    use lorica_command::{Frame, FrameKind};

    #[test]
    fn heartbeat_is_whitelisted() {
        let req = ClusterRequest {
            sequence: 1,
            body: Some(cluster_request::Body::Heartbeat(Heartbeat {
                timestamp_ms: 123,
            })),
        };
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat { timestamp_ms: 123 })
        );
    }

    #[test]
    fn out_of_phase_hello_and_empty_bodies_are_violations() {
        let hello = ClusterRequest {
            sequence: 2,
            body: Some(cluster_request::Body::Hello(Hello::default())),
        };
        assert_eq!(
            translate_cluster_request(&hello),
            BridgeOutcome::ProtocolViolation
        );
        let empty = ClusterRequest {
            sequence: 3,
            body: None,
        };
        assert_eq!(
            translate_cluster_request(&empty),
            BridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn worker_shutdown_bytes_end_in_a_connection_drop() {
        // A malicious peer deliberately encodes a worker Envelope
        // (SHUTDOWN, the worst case) on the cluster connection. Tag
        // disjointness makes it decode to an EMPTY cluster frame; the
        // endpoint reader drops empty frames, and even if a decoded
        // request with no recognisable body reached dispatch, the
        // bridge answers ProtocolViolation. Either way no Command
        // materialises.
        let env = Envelope {
            kind: Some(envelope::Kind::Command(Command::new(
                CommandType::Shutdown,
                7,
            ))),
        };
        let bytes = env.encode_to_vec();

        let as_cluster = ClusterFrame::decode(bytes.as_slice()).expect("prost decode is tolerant");
        match as_cluster.into_kind() {
            // The expected path: nothing materialises, the reader
            // drops the frame before dispatch.
            FrameKind::Empty => {}
            // If prost ever surfaced a request here, the bridge must
            // still refuse it.
            FrameKind::Request(req) => {
                assert_eq!(
                    translate_cluster_request(&req),
                    BridgeOutcome::ProtocolViolation
                );
            }
            FrameKind::Response(_) => {
                panic!("worker bytes must never materialise as a cluster response")
            }
        }
    }
}
