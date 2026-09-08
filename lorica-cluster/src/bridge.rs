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
//!   plane may do. In Story 9.2 it contained ONLY in-plane session
//!   traffic; Story 9.4 adds the convergence pull, and Story 9.6 will
//!   add telemetry fan-in.
//! - Story 9.4 makes the plane BIDIRECTIONAL: the control plane pushes
//!   configuration to a follower, so the follower has a whitelist of
//!   its own, [`translate_control_plane_request`]. The two tables are
//!   disjoint by construction. A follower that sends a `ConfigPrepare`
//!   to the control plane is trying to push configuration UPWARDS and
//!   is a violation; a control plane that sends a `Renew` or a
//!   `ConfigPull` DOWNWARDS is equally out of role.
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

use crate::messages::{cluster_request, config_hash_is_valid, ClusterRequest};
use crate::replication::{AppliedConfig, ConfigPayload};

/// The in-plane actions the control-plane whitelist admits (Story 9.2
/// session traffic, Story 9.3 lifecycle, Story 9.4 convergence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InPlaneAction {
    /// A liveness probe carrying the sender's clock (unix ms) and what
    /// the follower currently runs (Story 9.4 AC #6/#7).
    Heartbeat {
        /// The probe's `timestamp_ms`, echoed in the ack.
        timestamp_ms: u64,
        /// The configuration the follower reports as applied.
        applied: AppliedConfig,
    },
    /// The follower asks for the current generation because what it
    /// runs may be stale (Story 9.4 AC #7).
    ConfigPull {
        /// The configuration the follower reports as applied.
        applied: AppliedConfig,
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

/// The actions a FOLLOWER accepts from its control plane (Story 9.4
/// D5). All three are configuration pushes; nothing else exists in
/// this direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowerAction {
    /// Stage this generation without applying it.
    Prepare(ConfigPayload),
    /// Apply the staged generation.
    Commit {
        /// The generation to apply; it must match the staged one.
        generation: u64,
    },
    /// Drop the staged generation (another follower rejected it).
    Abort {
        /// The staged generation to drop.
        generation: u64,
    },
}

/// Outcome of routing one control-plane-initiated request through the
/// follower's whitelist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowerBridgeOutcome {
    /// The request is on the follower's whitelist; serve it.
    Serve(FollowerAction),
    /// Well-formed request for a method this build does not know (a
    /// NEWER control plane): refuse with `UNSUPPORTED_METHOD`, keep the
    /// session.
    Unsupported {
        /// The control plane's `body_kind`, for the diagnostic.
        body_kind: u32,
    },
    /// The control plane sent something no control plane may send:
    /// drop the session.
    ProtocolViolation,
}

/// Route one inbound cluster request through the CONTROL PLANE's
/// whitelist.
///
/// This is the single dispatch point for established sessions on the
/// control plane. A [`Hello`] here is a violation too: the opener is
/// consumed by the handshake before a session reaches steady state, so
/// a second one is a peer speaking out of phase. A `body_kind` that
/// names one of OUR methods while the body is missing is malformed, not
/// "newer", and is a violation as well. A configuration PUSH
/// (`ConfigPrepare` / `ConfigCommit` / `ConfigAbort`) arriving here is a
/// follower trying to configure its control plane: a violation.
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
        Some(cluster_request::Body::Heartbeat(hb)) => {
            // The hash rides straight into a log line, a registry entry
            // and a drift comparison: bound its shape here, at the
            // decode boundary, or nowhere.
            if !config_hash_is_valid(&hb.applied_hash) {
                return BridgeOutcome::ProtocolViolation;
            }
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat {
                timestamp_ms: hb.timestamp_ms,
                applied: AppliedConfig {
                    generation: hb.applied_generation,
                    hash: hb.applied_hash.clone(),
                    break_glass: hb.break_glass,
                },
            })
        }
        Some(cluster_request::Body::ConfigPull(pull)) => {
            if !config_hash_is_valid(&pull.applied_hash) {
                return BridgeOutcome::ProtocolViolation;
            }
            BridgeOutcome::InPlane(InPlaneAction::ConfigPull {
                applied: AppliedConfig {
                    generation: pull.applied_generation,
                    hash: pull.applied_hash.clone(),
                    break_glass: false,
                },
            })
        }
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
        // ---- operational plane is a peer using the wrong listener;
        // ---- a configuration push is a follower acting as if it
        // ---- owned the fleet's configuration.
        Some(cluster_request::Body::Hello(_))
        | Some(cluster_request::Body::Enroll(_))
        | Some(cluster_request::Body::ConfigPrepare(_))
        | Some(cluster_request::Body::ConfigCommit(_))
        | Some(cluster_request::Body::ConfigAbort(_))
        | None => BridgeOutcome::ProtocolViolation,
    }
}

/// Route one control-plane-initiated request through the FOLLOWER's
/// whitelist (Story 9.4 D5).
///
/// The follower serves exactly three methods, all configuration pushes.
/// Every other body is a control plane out of role: a `Hello` or a
/// `Heartbeat` (the follower is the one that opens and probes), an
/// `Enroll` (wrong listener entirely), a `Renew` or a `Leave` (those
/// travel upwards), or a `ConfigPull` (the follower is the puller). An
/// unknown `body_kind` means the control plane is NEWER: refused
/// without dropping the session, so a control-plane upgrade never
/// disconnects the fleet.
pub fn translate_control_plane_request(request: &ClusterRequest) -> FollowerBridgeOutcome {
    if !request.body_kind_matches() {
        return FollowerBridgeOutcome::ProtocolViolation;
    }
    match &request.body {
        Some(cluster_request::Body::ConfigPrepare(prepare)) => {
            if !config_hash_is_valid(&prepare.hash) {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::Prepare(ConfigPayload {
                generation: prepare.generation,
                hash: prepare.hash.clone(),
                blob: prepare.blob.clone(),
            }))
        }
        Some(cluster_request::Body::ConfigCommit(commit)) => {
            FollowerBridgeOutcome::Serve(FollowerAction::Commit {
                generation: commit.generation,
            })
        }
        Some(cluster_request::Body::ConfigAbort(abort)) => {
            FollowerBridgeOutcome::Serve(FollowerAction::Abort {
                generation: abort.generation,
            })
        }
        None if request.body_kind != 0
            && !ClusterRequest::is_known_body_kind(request.body_kind) =>
        {
            FollowerBridgeOutcome::Unsupported {
                body_kind: request.body_kind,
            }
        }
        Some(cluster_request::Body::Hello(_))
        | Some(cluster_request::Body::Heartbeat(_))
        | Some(cluster_request::Body::Enroll(_))
        | Some(cluster_request::Body::Renew(_))
        | Some(cluster_request::Body::Leave(_))
        | Some(cluster_request::Body::ConfigPull(_))
        | None => FollowerBridgeOutcome::ProtocolViolation,
    }
}

#[cfg(test)]
mod tests {
    use lorica_command::messages::{envelope, Command, CommandType, Envelope};
    use prost::Message;

    use super::*;
    use crate::messages::{
        ClusterFrame, ConfigPrepare, ConfigPull, Heartbeat, Hello, BODY_KIND_HELLO,
    };
    use lorica_command::{Frame, FrameKind};

    fn heartbeat(timestamp_ms: u64) -> Heartbeat {
        Heartbeat {
            timestamp_ms,
            applied_generation: 0,
            applied_hash: String::new(),
            break_glass: false,
        }
    }

    #[test]
    fn mismatched_body_kind_is_a_violation_even_for_whitelisted_bodies() {
        let mut req = ClusterRequest::heartbeat(heartbeat(1));
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
    fn heartbeat_is_whitelisted_and_carries_the_applied_configuration() {
        let req = ClusterRequest::heartbeat(Heartbeat {
            timestamp_ms: 123,
            applied_generation: 4,
            applied_hash: "abcdef".to_string(),
            break_glass: true,
        });
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::InPlane(InPlaneAction::Heartbeat {
                timestamp_ms: 123,
                applied: AppliedConfig {
                    generation: 4,
                    hash: "abcdef".to_string(),
                    break_glass: true,
                },
            })
        );
    }

    #[test]
    fn a_convergence_pull_is_whitelisted_on_the_control_plane() {
        let req = ClusterRequest::config_pull(ConfigPull {
            applied_generation: 2,
            applied_hash: "beef".to_string(),
        });
        assert_eq!(
            translate_cluster_request(&req),
            BridgeOutcome::InPlane(InPlaneAction::ConfigPull {
                applied: AppliedConfig {
                    generation: 2,
                    hash: "beef".to_string(),
                    break_glass: false,
                },
            })
        );
    }

    #[test]
    fn a_malformed_hash_is_refused_at_the_decode_boundary_in_both_directions() {
        // Uppercase, non-hex and over-long hashes never reach a log
        // line, a registry entry or a comparison.
        let too_long = "a".repeat(65);
        for hash in ["ZZ", "AB", too_long.as_str()] {
            let heartbeat = ClusterRequest::heartbeat(Heartbeat {
                timestamp_ms: 1,
                applied_generation: 1,
                applied_hash: hash.to_string(),
                break_glass: false,
            });
            assert_eq!(
                translate_cluster_request(&heartbeat),
                BridgeOutcome::ProtocolViolation,
                "heartbeat hash {hash}"
            );
            let pull = ClusterRequest::config_pull(ConfigPull {
                applied_generation: 1,
                applied_hash: hash.to_string(),
            });
            assert_eq!(
                translate_cluster_request(&pull),
                BridgeOutcome::ProtocolViolation,
                "pull hash {hash}"
            );
            let prepare = ClusterRequest::config_prepare(ConfigPrepare {
                generation: 1,
                hash: hash.to_string(),
                blob: vec![1],
            });
            assert_eq!(
                translate_control_plane_request(&prepare),
                FollowerBridgeOutcome::ProtocolViolation,
                "prepare hash {hash}"
            );
        }
    }

    #[test]
    fn a_follower_cannot_push_configuration_to_the_control_plane() {
        // The whole point of two tables: a Prepare travels DOWNWARDS
        // only. An enrolled follower that sends one is trying to
        // configure the fleet from a leaf.
        for pushed in [
            ClusterRequest::config_prepare(ConfigPrepare {
                generation: 9,
                hash: "ab".to_string(),
                blob: vec![1, 2, 3],
            }),
            ClusterRequest::config_commit(9),
            ClusterRequest::config_abort(9),
        ] {
            assert_eq!(
                translate_cluster_request(&pushed),
                BridgeOutcome::ProtocolViolation
            );
        }
    }

    #[test]
    fn the_follower_serves_only_the_three_configuration_pushes() {
        let prepare = ClusterRequest::config_prepare(ConfigPrepare {
            generation: 9,
            hash: "ab".to_string(),
            blob: vec![1, 2, 3],
        });
        assert_eq!(
            translate_control_plane_request(&prepare),
            FollowerBridgeOutcome::Serve(FollowerAction::Prepare(ConfigPayload {
                generation: 9,
                hash: "ab".to_string(),
                blob: vec![1, 2, 3],
            }))
        );
        assert_eq!(
            translate_control_plane_request(&ClusterRequest::config_commit(9)),
            FollowerBridgeOutcome::Serve(FollowerAction::Commit { generation: 9 })
        );
        assert_eq!(
            translate_control_plane_request(&ClusterRequest::config_abort(9)),
            FollowerBridgeOutcome::Serve(FollowerAction::Abort { generation: 9 })
        );
    }

    #[test]
    fn the_control_plane_cannot_send_lifecycle_or_session_traffic_to_a_follower() {
        for out_of_role in [
            ClusterRequest::hello(Hello::default()),
            ClusterRequest::heartbeat(heartbeat(1)),
            ClusterRequest::enroll(crate::messages::Enroll::default()),
            ClusterRequest::renew(crate::messages::Renew {
                public_key_der: vec![1, 2, 3],
            }),
            ClusterRequest::leave(),
            ClusterRequest::config_pull(ConfigPull::default()),
            ClusterRequest::default(),
        ] {
            assert_eq!(
                translate_control_plane_request(&out_of_role),
                FollowerBridgeOutcome::ProtocolViolation,
                "body_kind {}",
                out_of_role.body_kind
            );
        }
        // A forged discriminator is a violation on this side too.
        let mut forged = ClusterRequest::config_commit(1);
        forged.body_kind = BODY_KIND_HELLO;
        assert_eq!(
            translate_control_plane_request(&forged),
            FollowerBridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn a_newer_control_plane_is_unsupported_not_hostile() {
        // Body tag 30 is inside the reserved 24-39 range: a control
        // plane from a later release. Refuse the method, keep the
        // session, so a control-plane upgrade never disconnects the
        // fleet.
        let newer = ClusterRequest {
            sequence: 3,
            body_kind: 30,
            body: None,
        };
        assert_eq!(
            translate_control_plane_request(&newer),
            FollowerBridgeOutcome::Unsupported { body_kind: 30 }
        );
        // One of OUR kinds with no body is malformed, not newer.
        let malformed = ClusterRequest {
            sequence: 4,
            body_kind: crate::messages::BODY_KIND_CONFIG_COMMIT,
            body: None,
        };
        assert_eq!(
            translate_control_plane_request(&malformed),
            FollowerBridgeOutcome::ProtocolViolation
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
