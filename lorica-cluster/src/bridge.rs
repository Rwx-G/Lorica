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
//! - A request whose `body_kind` names a method this build does not
//!   implement (a NEWER peer) is [`BridgeOutcome::Unsupported`]: the
//!   caller answers `UNSUPPORTED_METHOD` and keeps the connection, so
//!   a rolling upgrade never turns a legitimate peer into a "hostile"
//!   one (AC #4).
//! - Anything else, including an empty body with no `body_kind`
//!   (which is what deliberately mis-sent worker-`Envelope` bytes
//!   decode to, see [`crate::frame`]) and an out-of-phase `Hello`, is
//!   a [`BridgeOutcome::ProtocolViolation`]: the caller drops the
//!   connection and increments its violation counter.

use crate::messages::{cluster_request, ClusterRequest};

/// The in-plane actions the whitelist admits (Story 9.2 session
/// traffic, Story 9.3 lifecycle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InPlaneAction {
    /// A liveness probe carrying the sender's clock (unix ms).
    Heartbeat {
        /// The probe's `timestamp_ms`, echoed in the ack.
        timestamp_ms: u64,
    },
    /// The node asks for a new certificate on a new public key
    /// (Story 9.3 AC #12). Identity comes from the session, never
    /// from this payload.
    Renew {
        /// The new `SubjectPublicKeyInfo`, DER.
        public_key_der: Vec<u8>,
    },
    /// The node is leaving the fleet (Story 9.3 AC #13).
    Leave,
}

/// Outcome of routing one inbound cluster request through the
/// whitelist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeOutcome {
    /// The request is on the whitelist; handle it in-plane.
    InPlane(InPlaneAction),
    /// Well-formed request for a method this build does not know:
    /// refuse with `UNSUPPORTED_METHOD`, keep the connection.
    Unsupported {
        /// The peer's `body_kind`, for the diagnostic.
        body_kind: u32,
    },
    /// The request is not on the whitelist (empty, malformed, or
    /// wrong-phase body): drop the connection.
    ProtocolViolation,
}

/// Route one inbound cluster request through the whitelist.
///
/// This is the single dispatch point for established sessions. A
/// [`Hello`] here is a violation too: the opener is consumed by the
/// handshake before a session reaches steady state, so a second one
/// is a peer speaking out of phase. A `body_kind` that names one of
/// OUR methods while the body is missing is malformed, not "newer",
/// and is a violation as well.
///
/// [`Hello`]: crate::messages::Hello
pub fn translate_cluster_request(request: &ClusterRequest) -> BridgeOutcome {
    // The scalar discriminator and the populated body must agree
    // (`messages.rs`); a peer that makes them disagree is choosing
    // which reading applies, the classic type-confusion shape.
    if !request.body_kind_matches() {
        return BridgeOutcome::ProtocolViolation;
    }
    match &request.body {
        // ---- The whitelist. Every entry is a reviewed decision. ----
        Some(cluster_request::Body::Heartbeat(hb)) => BridgeOutcome::InPlane(
            InPlaneAction::Heartbeat {
                timestamp_ms: hb.timestamp_ms,
            },
        ),
        Some(cluster_request::Body::Renew(renew)) => BridgeOutcome::InPlane(InPlaneAction::Renew {
            public_key_der: renew.public_key_der.clone(),
        }),
        Some(cluster_request::Body::Leave(_)) => BridgeOutcome::InPlane(InPlaneAction::Leave),
        // ---- Newer peer: known shape, unknown method. ----
        None if request.body_kind != 0
            && !ClusterRequest::is_known_body_kind(request.body_kind) =>
        {
            BridgeOutcome::Unsupported {
                body_kind: request.body_kind,
            }
        }
        // ---- Everything else is a violation. An Enroll on the
        // ---- operational plane is a peer using the wrong listener.
        Some(cluster_request::Body::Hello(_))
        | Some(cluster_request::Body::Enroll(_))
        | None => BridgeOutcome::ProtocolViolation,
    }
}

#[cfg(test)]
mod tests {
    use lorica_command::messages::{envelope, Command, CommandType, Envelope};
    use prost::Message;

    use super::*;
    use crate::messages::{ClusterFrame, Heartbeat, Hello, BODY_KIND_HELLO};
    use lorica_command::{Frame, FrameKind};

    #[test]
    fn mismatched_body_kind_is_a_violation_even_for_whitelisted_bodies() {
        let mut req = ClusterRequest::heartbeat(Heartbeat { timestamp_ms: 1 });
        req.body_kind = 25;
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::ProtocolViolation
        );
        req.body_kind = BODY_KIND_HELLO;
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn lifecycle_requests_are_whitelisted_and_enroll_is_not() {
        let renew = ClusterRequest::renew(crate::messages::Renew {
            public_key_der: vec![1, 2, 3],
        });
        assert_eq!(
            translate_cluster_request(&renew),
            BridgeOutcome::InPlane(InPlaneAction::Renew {
                public_key_der: vec![1, 2, 3]
            })
        );
        assert_eq!(
            translate_cluster_request(&ClusterRequest::leave()),
            BridgeOutcome::InPlane(InPlaneAction::Leave)
        );
        let enroll = ClusterRequest::enroll(crate::messages::Enroll::default());
        assert_eq!(
            translate_cluster_request(&enroll),
            BridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn heartbeat_is_whitelisted() {
        let req = ClusterRequest::heartbeat(Heartbeat { timestamp_ms: 123 });
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat { timestamp_ms: 123 })
        );
    }

    #[test]
    fn out_of_phase_hello_and_empty_bodies_are_violations() {
        let hello = ClusterRequest::hello(Hello::default());
        assert_eq!(
            translate_cluster_request(&hello),
            BridgeOutcome::ProtocolViolation
        );
        let empty = ClusterRequest::default();
        assert_eq!(
            translate_cluster_request(&empty),
            BridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn unknown_body_kind_is_unsupported_not_a_violation() {
        // A peer from a newer release sends a tag-25 body (Story 9.4
        // range). This build decodes it as an unknown field, body =
        // None, but the scalar discriminator says "known shape".
        let newer = ClusterRequest {
            sequence: 4,
            body_kind: 25,
            body: None,
        };
        assert_eq!(
            translate_cluster_request(&newer),
            BridgeOutcome::Unsupported { body_kind: 25 }
        );
        // The same scalar naming one of OUR kinds with no body is
        // malformed, not newer.
        let malformed = ClusterRequest {
            sequence: 5,
            body_kind: BODY_KIND_HELLO,
            body: None,
        };
        assert_eq!(
            translate_cluster_request(&malformed),
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
        // bridge answers ProtocolViolation (body_kind is 0: a worker
        // Envelope has no field 3 inside a field-101 message). Either
        // way no Command materialises.
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
