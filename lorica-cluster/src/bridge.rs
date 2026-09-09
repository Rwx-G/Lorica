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
//! - Story 9.5 adds a second directed pair on the same principle, and
//!   it is the one where direction matters most: `CertPush` carries
//!   PRIVATE KEYS downwards, so a follower sending one is offering key
//!   material to its control plane and is a violation; `CertPull` goes
//!   upwards only, so a control plane sending one is out of role. Both
//!   are validated here, at the decode boundary, against the single
//!   [`cert_bundle_defect`] rule.
//! - Story 9.5 also adds the HTTP-01 challenge pair,
//!   `ChallengePublish` and `ChallengeRetract`, both downwards only. A
//!   follower that publishes a challenge to its control plane is
//!   choosing what the fleet answers a certificate authority, which is
//!   a violation for the same reason a follower may not push
//!   configuration. They are validated against the single
//!   [`challenge_defect`] rule.
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

use crate::certs::{cert_bundle_defect, CertBundle, MAX_CERT_BUNDLES, MAX_CERT_PULL_IDS};
use crate::challenge::challenge_defect;
use crate::messages::{
    ban_duration_is_valid, ban_reason_is_valid, ban_target_is_valid, cert_id_is_valid,
    challenge_token_is_valid, cluster_request, config_hash_is_valid, sla_pull_defect,
    telemetry_audit_row_defect, ClusterRequest, NodeResources, SlaPull, TelemetryPush,
    MAX_TELEMETRY_AUDIT, MAX_TELEMETRY_BANS, MAX_TELEMETRY_ROWS,
};
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
        /// What the node reports it is using (Story 9.7 AC #3), or
        /// `None` from a node that installs no sampler.
        resources: Option<NodeResources>,
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
    /// A batch of telemetry the follower drained from its own store
    /// (Story 9.6 AC #5).
    ///
    /// Carries no node identity: the control plane stamps every row
    /// with the `node_id` the session proves (decision D2). A
    /// `node_id` in the payload would let a compromised follower file
    /// rows under another node's name.
    TelemetryPush {
        /// The batch, already length-checked at this boundary.
        batch: Box<TelemetryPush>,
    },
    /// The follower asks for certificate material it counted as
    /// missing (Story 9.5 AC #8).
    CertPull {
        /// The ids the follower named. A REQUEST, never an
        /// authorization input: the control plane resolves entitlement
        /// itself and may answer with fewer bundles, or none.
        cert_ids: Vec<String>,
    },
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
/// D5, Story 9.5 AC #6/#7): three configuration pushes, one
/// certificate push, and the HTTP-01 challenge pair. Nothing else
/// exists in this direction.
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
    /// Install certificate material the control plane pushed
    /// (Story 9.5 AC #7). Independent of any staged generation: it
    /// applies immediately and does not participate in the two-phase
    /// round.
    InstallCerts(Vec<CertBundle>),
    /// Serve an HTTP-01 challenge token so the certificate authority
    /// can validate `identifier` against this node (Story 9.5 AC #6).
    PublishChallenge {
        /// The per-SAN hostname being validated.
        identifier: String,
        /// The challenge token, base64url.
        token: String,
        /// What the node answers for that token.
        key_authorization: String,
    },
    /// Stop serving a token. The token alone identifies the entry.
    RetractChallenge {
        /// The token to stop serving.
        token: String,
    },
    /// Apply an operator-issued fleet-wide ban (Story 9.6 AC #10).
    ///
    /// Only ever operator-issued: automatic per-node auto-ban is not
    /// replicated, because one node's reflex to its own traffic would
    /// become a fleet-wide outage for that client.
    ApplyBan {
        /// The address to ban.
        client_ip: String,
        /// How long the ban lasts, in seconds.
        duration_s: u64,
        /// Reason recorded on this node.
        reason: String,
    },
    /// Compute this node's SLA figures for the control plane, which
    /// serves them to an operator (Story 9.7 AC #5). A read: nothing
    /// on this node changes.
    SlaPull(SlaPull),
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
/// A certificate PUSH (`CertPush`) arriving here is a follower
/// offering private keys to its control plane: a violation, and the
/// direction that matters most on this plane (Story 9.5). A
/// `ChallengePublish` or `ChallengeRetract` is the same class: a
/// follower choosing what the fleet answers a certificate authority.
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
                // Clamped rather than refused: a gauge reading past
                // 100 is a wrong number on a dashboard, not a protocol
                // violation, and dropping the session over it would
                // let a buggy peer take itself offline.
                resources: hb.resources.clone().map(|r| NodeResources {
                    cpu_percent: r.cpu_percent.min(100),
                    ..r
                }),
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
        Some(cluster_request::Body::TelemetryPush(push)) => {
            // Peer-supplied and unbounded on the wire: bound the row
            // counts here so a follower cannot make the control plane
            // allocate a batch before its ingest quota (AC #8) even
            // gets a chance to shed it.
            if push.access.len() > MAX_TELEMETRY_ROWS
                || push.waf.len() > MAX_TELEMETRY_ROWS
                || push.bans.len() > MAX_TELEMETRY_BANS
                || push.audit.len() > MAX_TELEMETRY_AUDIT
            {
                return BridgeOutcome::ProtocolViolation;
            }
            // Audit rows are exempt from load shedding, which makes
            // bounding their CONTENT here the only thing standing
            // between a follower and unbounded growth in a table
            // retention deletes by a field that same follower chose.
            if push
                .audit
                .iter()
                .any(|r| telemetry_audit_row_defect(r).is_some())
            {
                return BridgeOutcome::ProtocolViolation;
            }
            BridgeOutcome::InPlane(InPlaneAction::TelemetryPush {
                batch: Box::new(push.clone()),
            })
        }
        Some(cluster_request::Body::CertPull(pull)) => {
            // The list is peer-supplied: bound its length and every id
            // in it here, or a follower could make the control plane
            // allocate and log arbitrary strings just by asking.
            if pull.cert_ids.len() > MAX_CERT_PULL_IDS
                || !pull.cert_ids.iter().all(|id| cert_id_is_valid(id))
            {
                return BridgeOutcome::ProtocolViolation;
            }
            BridgeOutcome::InPlane(InPlaneAction::CertPull {
                cert_ids: pull.cert_ids.clone(),
            })
        }
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
        | Some(cluster_request::Body::CertPush(_))
        | Some(cluster_request::Body::ChallengePublish(_))
        | Some(cluster_request::Body::ChallengeRetract(_))
        | Some(cluster_request::Body::BanPush(_))
        | Some(cluster_request::Body::SlaPull(_))
        | None => BridgeOutcome::ProtocolViolation,
    }
}

/// Route one control-plane-initiated request through the FOLLOWER's
/// whitelist (Story 9.4 D5).
///
/// The follower serves exactly eight methods: three configuration
/// pushes, one certificate push, the HTTP-01 challenge pair, the
/// fleet-wide ban and the SLA read. Every
/// other body is a control plane out of role: a `Hello` or a
/// `Heartbeat` (the follower is the one that opens and probes), an
/// `Enroll` (wrong listener entirely), a `Renew` or a `Leave` (those
/// travel upwards), a `ConfigPull` or a `CertPull` (the follower is
/// the puller in both). An unknown `body_kind` means the control plane
/// is NEWER: refused without dropping the session, so a control-plane
/// upgrade never disconnects the fleet.
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
        Some(cluster_request::Body::CertPush(push)) => {
            if push.bundles.len() > MAX_CERT_BUNDLES {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            let bundles: Vec<CertBundle> = push
                .bundles
                .iter()
                .cloned()
                .map(CertBundle::from_material)
                .collect();
            if bundles.iter().any(|b| cert_bundle_defect(b).is_some()) {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::InstallCerts(bundles))
        }
        Some(cluster_request::Body::ChallengePublish(publish)) => {
            // The token becomes a path segment the data plane serves
            // and the key authorization becomes a response body: both
            // are bounded here, at the decode boundary, or nowhere.
            if challenge_defect(
                &publish.identifier,
                &publish.token,
                &publish.key_authorization,
            )
            .is_some()
            {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::PublishChallenge {
                identifier: publish.identifier.clone(),
                token: publish.token.clone(),
                key_authorization: publish.key_authorization.clone(),
            })
        }
        Some(cluster_request::Body::ChallengeRetract(retract)) => {
            if !challenge_token_is_valid(&retract.token) {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::RetractChallenge {
                token: retract.token.clone(),
            })
        }
        Some(cluster_request::Body::BanPush(ban)) => {
            // The address becomes a key in the data-plane ban map and
            // the reason reaches a log line and the API: bound both
            // here rather than trusting a control plane to be sane.
            if !ban_target_is_valid(&ban.client_ip)
                || !ban_reason_is_valid(&ban.reason)
                || !ban_duration_is_valid(ban.duration_s)
            {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::ApplyBan {
                client_ip: ban.client_ip.clone(),
                duration_s: ban.duration_s,
                reason: ban.reason.clone(),
            })
        }
        Some(cluster_request::Body::SlaPull(pull)) => {
            if sla_pull_defect(pull).is_some() {
                return FollowerBridgeOutcome::ProtocolViolation;
            }
            FollowerBridgeOutcome::Serve(FollowerAction::SlaPull(pull.clone()))
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
        | Some(cluster_request::Body::CertPull(_))
        | Some(cluster_request::Body::TelemetryPush(_))
        | None => FollowerBridgeOutcome::ProtocolViolation,
    }
}

#[cfg(test)]
mod tests {
    use lorica_command::messages::{envelope, Command, CommandType, Envelope};
    use prost::Message;

    use super::*;
    use crate::messages::{
        CertMaterial, CertPull, CertPush, ChallengePublish, ClusterFrame, ConfigPrepare,
        ConfigPull, Heartbeat, Hello, BODY_KIND_HELLO, MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES,
        MAX_CHALLENGE_TOKEN_BYTES, MAX_CONFIG_HASH_BYTES,
    };

    const IDENTIFIER: &str = "edge.example.com";
    const TOKEN: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";
    const KEY_AUTH: &str = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0.9jg46WB3rR_AHD-EBXd";

    fn publication() -> ChallengePublish {
        ChallengePublish {
            identifier: IDENTIFIER.to_string(),
            token: TOKEN.to_string(),
            key_authorization: KEY_AUTH.to_string(),
        }
    }
    use lorica_command::{Frame, FrameKind};

    /// A well-formed bundle in wire form.
    fn material(cert_id: &str) -> CertMaterial {
        CertMaterial {
            cert_id: cert_id.to_string(),
            domain: "edge.example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----".to_string(),
            key_digest: format!("sha256:{}", "a".repeat(MAX_CONFIG_HASH_BYTES)),
        }
    }

    fn heartbeat(timestamp_ms: u64) -> Heartbeat {
        Heartbeat {
            timestamp_ms,
            applied_generation: 0,
            applied_hash: String::new(),
            break_glass: false,
            resources: None,
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
            resources: None,
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
                resources: None,
            })
        );
    }

    #[test]
    fn an_out_of_range_cpu_reading_is_clamped_rather_than_refused() {
        let req = ClusterRequest::heartbeat(Heartbeat {
            timestamp_ms: 1,
            applied_generation: 0,
            applied_hash: String::new(),
            break_glass: false,
            resources: Some(NodeResources {
                cpu_percent: 4_000_000,
                memory_used_bytes: 7,
                memory_total_bytes: 9,
                disk_used_bytes: 1,
                disk_total_bytes: 2,
            }),
        });
        let BridgeOutcome::InPlane(InPlaneAction::Heartbeat { resources, .. }) =
            translate_cluster_request(&req)
        else {
            panic!("a heartbeat is whitelisted whatever its gauges say");
        };
        let resources = resources.expect("the reading is kept, not dropped");
        assert_eq!(resources.cpu_percent, 100);
        assert_eq!(resources.memory_used_bytes, 7, "the rest passes through");
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
                resources: None,
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
    fn the_follower_serves_the_three_configuration_pushes() {
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
    fn a_certificate_pull_is_whitelisted_on_the_control_plane_only() {
        let pull = ClusterRequest::cert_pull(CertPull {
            cert_ids: vec!["cert-1".to_string(), "cert-2".to_string()],
        });
        assert_eq!(
            translate_cluster_request(&pull),
            BridgeOutcome::InPlane(InPlaneAction::CertPull {
                cert_ids: vec!["cert-1".to_string(), "cert-2".to_string()],
            })
        );
        // The mirror image: a control plane asking a follower for keys
        // is out of role, and the follower drops the session.
        assert_eq!(
            translate_control_plane_request(&pull),
            FollowerBridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn a_certificate_push_is_whitelisted_on_the_follower_only() {
        let push = ClusterRequest::cert_push(CertPush {
            bundles: vec![material("cert-1")],
        });
        assert_eq!(
            translate_control_plane_request(&push),
            FollowerBridgeOutcome::Serve(FollowerAction::InstallCerts(vec![
                CertBundle::from_material(material("cert-1"))
            ]))
        );
        // A follower pushing PRIVATE KEYS at its control plane is the
        // violation this table exists for.
        assert_eq!(
            translate_cluster_request(&push),
            BridgeOutcome::ProtocolViolation
        );
    }

    #[test]
    fn a_malformed_certificate_batch_never_reaches_a_handler() {
        // Over the cap.
        let oversized = ClusterRequest::cert_push(CertPush {
            bundles: (0..=MAX_CERT_BUNDLES)
                .map(|i| material(&format!("cert-{i}")))
                .collect(),
        });
        assert_eq!(
            translate_control_plane_request(&oversized),
            FollowerBridgeOutcome::ProtocolViolation
        );
        // One defect anywhere in the batch refuses the whole batch:
        // an injected id or domain, a chain or key that is not there,
        // and a digest that cannot be checked against the blob.
        let mut injected = material("cert-1");
        injected.cert_id = "cert\n1".to_string();
        let mut no_key = material("cert-2");
        no_key.key_pem = String::new();
        let mut bad_digest = material("cert-3");
        bad_digest.key_digest = "sha256:zz".to_string();
        for bad in [injected, no_key, bad_digest] {
            let push = ClusterRequest::cert_push(CertPush {
                bundles: vec![material("cert-0"), bad.clone()],
            });
            assert_eq!(
                translate_control_plane_request(&push),
                FollowerBridgeOutcome::ProtocolViolation,
                "cert {}",
                bad.cert_id
            );
        }
    }

    #[test]
    fn a_malformed_certificate_pull_never_reaches_a_handler() {
        let oversized = ClusterRequest::cert_pull(CertPull {
            cert_ids: vec!["cert-1".to_string(); MAX_CERT_PULL_IDS + 1],
        });
        assert_eq!(
            translate_cluster_request(&oversized),
            BridgeOutcome::ProtocolViolation
        );
        for bad_id in ["", "cert\n1", &"c".repeat(65)] {
            let pull = ClusterRequest::cert_pull(CertPull {
                cert_ids: vec!["cert-0".to_string(), bad_id.to_string()],
            });
            assert_eq!(
                translate_cluster_request(&pull),
                BridgeOutcome::ProtocolViolation,
                "id {bad_id:?}"
            );
        }
    }

    #[test]
    fn the_challenge_pair_is_whitelisted_on_the_follower_only() {
        let publish = ClusterRequest::challenge_publish(publication());
        assert_eq!(
            translate_control_plane_request(&publish),
            FollowerBridgeOutcome::Serve(FollowerAction::PublishChallenge {
                identifier: IDENTIFIER.to_string(),
                token: TOKEN.to_string(),
                key_authorization: KEY_AUTH.to_string(),
            })
        );
        let retract = ClusterRequest::challenge_retract(TOKEN);
        assert_eq!(
            translate_control_plane_request(&retract),
            FollowerBridgeOutcome::Serve(FollowerAction::RetractChallenge {
                token: TOKEN.to_string(),
            })
        );
        // Upwards, both are a follower choosing what the fleet answers
        // a certificate authority.
        for upward in [publish, retract] {
            assert_eq!(
                translate_cluster_request(&upward),
                BridgeOutcome::ProtocolViolation,
                "body_kind {}",
                upward.body_kind
            );
        }
    }

    #[test]
    fn a_malformed_challenge_never_reaches_a_handler() {
        let long_token = "a".repeat(MAX_CHALLENGE_TOKEN_BYTES + 1);
        let long_auth = "a".repeat(MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES + 1);
        // An injected identifier, a token that is a path-traversal
        // shape or unbounded, and a key authorization carrying a header
        // break: a node would serve every one of these to an
        // unauthenticated caller.
        for (identifier, token, key_authorization) in [
            ("", TOKEN, KEY_AUTH),
            ("edge.example.com\nforged", TOKEN, KEY_AUTH),
            (IDENTIFIER, "../../etc/passwd", KEY_AUTH),
            (IDENTIFIER, "", KEY_AUTH),
            (IDENTIFIER, long_token.as_str(), KEY_AUTH),
            (IDENTIFIER, TOKEN, ""),
            (IDENTIFIER, TOKEN, "auth\r\nInjected: 1"),
            (IDENTIFIER, TOKEN, long_auth.as_str()),
        ] {
            let publish = ClusterRequest::challenge_publish(ChallengePublish {
                identifier: identifier.to_string(),
                token: token.to_string(),
                key_authorization: key_authorization.to_string(),
            });
            assert_eq!(
                translate_control_plane_request(&publish),
                FollowerBridgeOutcome::ProtocolViolation,
                "{identifier:?} {token:?} {key_authorization:?}"
            );
        }
        for bad_token in ["", "tok/en", "../x"] {
            assert_eq!(
                translate_control_plane_request(&ClusterRequest::challenge_retract(bad_token)),
                FollowerBridgeOutcome::ProtocolViolation,
                "{bad_token:?}"
            );
        }
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
