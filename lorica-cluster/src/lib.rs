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

//! Lorica cluster plane (Epic 9): authenticated, encrypted transport
//! between a control-plane node and its followers.
//!
//! Story 9.2 lays the foundations in this crate:
//!
//! - a DISJOINT protobuf message set ([`messages`], AC #6) riding the
//!   worker plane's pipelined `RpcEndpoint` via a [`Frame`] impl, with
//!   WAN-tuned transport [`limits`];
//! - protocol version RANGE negotiation ([`version`], AC #4) and the
//!   schema-ordering check (AC #5) in the [`handshake`];
//! - the cluster CA and EKU-split leaf issuance ([`ca`], AC #8);
//! - the three TLS 1.3-only configs and the arc-swappable acceptor
//!   ([`tls`], AC #2's crypto half, Story 9.3's revocation seam);
//! - the pre-authentication budgets and per-source gate ([`preauth`],
//!   AC #3), the two [`listener`]s, convergence [`admission`]
//!   (AC #10), the follower [`dialer`] (AC #9), the confused-deputy
//!   [`bridge`] (AC #6) and the [`session`] contract later stories
//!   consume.
//!
//! Story 9.3 adds the fleet layer: join [`token`]s, the redemption
//! and lifecycle hooks in [`enroll`], the in-memory [`roster`] with
//! its session registry and kill switches, bare-public-key issuance
//! and CRL minting in [`ca`], and the SPKI-pinning joiner config in
//! [`tls`].
//!
//! Story 9.4 makes the plane BIDIRECTIONAL and adds configuration
//! [`replication`]: the two-phase Prepare/Commit/Abort messages and the
//! convergence pull in [`messages`], a second whitelist in [`bridge`]
//! for what a control plane may ask of a follower, the
//! [`Replicator`] that runs one round over the live sessions, and a
//! [`dialer`] that now SERVES its incoming half instead of dropping it.
//!
//! Story 9.5 adds certificate distribution in [`certs`], on the tags
//! the protocol already reserved for it. It is deliberately NOT the
//! replication path: a push is per node and best effort, so a slow
//! follower cannot block fleet renewals the way it could block a
//! configuration round. A push travels downwards only and a pull
//! upwards only, each a protocol violation in the other direction, and
//! the pull reuses the `Active` gate the configuration pull already
//! has, so no key material reaches a node awaiting activation.
//!
//! Story 9.5 also adds the HTTP-01 [`challenge`] fan-out, which is the
//! opposite trade-off on purpose: a certificate push is best effort
//! because the pull path recovers it, while a challenge publication has
//! no second chance, so the fan-out reports PER NODE and the ACME
//! solver refuses the order unless every recipient took the token. The
//! transport reports; it does not decide.
//!
//! # API stability rule
//!
//! `#[non_exhaustive]` marks types that evolve WITH THE WIRE and are
//! matched by peers of other builds ([`ClusterStatus`]); configuration
//! and outcome types stay exhaustive so the in-workspace consumers get
//! a compile error, not a silent default, when a field or variant is
//! added. Configs are built through `new()` constructors carrying the
//! documented defaults and then adjusted field by field.
//!
//! [`Frame`]: lorica_command::Frame

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod admission;
pub mod bridge;
pub mod ca;
pub mod certs;
pub mod challenge;
pub mod dialer;
pub mod enroll;
pub mod frame;
pub mod handshake;
pub mod limits;
pub mod listener;
pub mod messages;
pub mod preauth;
pub mod replication;
pub mod roster;
pub mod session;
pub mod telemetry;
pub mod tls;
pub mod token;
pub mod version;

pub use admission::{AdmissionDecision, AdmissionGate, AdmissionPermit, DEFAULT_QUEUE_WAIT};
pub use bridge::{
    translate_cluster_request, translate_control_plane_request, BridgeOutcome, FollowerAction,
    FollowerBridgeOutcome, InPlaneAction,
};
pub use ca::{CaError, ClusterCa, IssuedLeaf, RevokedEntry};
pub use certs::{
    cert_bundle_defect, safe_cert_id, CertBundle, CertDistributor, CertInstallReport,
    CertPushReport, MAX_CERT_BUNDLES, MAX_CERT_PULL_IDS,
};
pub use challenge::{challenge_defect, ChallengeFanout, ChallengeMiss, ChallengeReport};
pub use dialer::{
    resolve_and_connect, split_host_port, ClusterConnection, Dialer, DialerConfig, DialerError,
    DialerHandle, DialerStats, FollowerHandler, SessionHandle, BACKOFF_CAP_CEILING,
};
pub use enroll::{
    join, EnrollGrant, EnrollRefusal, EnrollRequest, EnrollmentHandler, JoinError, JoinParams,
    NoopSessionHandler, RefuseAllEnrollments, RenewGrant, RenewRequest, SessionHandler,
};
pub use handshake::{
    client_handshake, display_field_is_valid, evaluate_hello, node_name_is_valid, serve_hello,
    HandshakeConfig, HandshakeError, MAX_NODE_NAME_BYTES,
};
pub use limits::{cluster_rpc_limits, CLUSTER_MAX_MESSAGE_SIZE, CLUSTER_QUEUE_CAP};
pub use listener::{
    EnrollmentHandle, EnrollmentListener, EnrollmentStats, FleetHooks, OperationalConfig,
    OperationalHandle, OperationalListener, OperationalStats, TokenLiveness, DEFAULT_MAX_SESSIONS,
    DEFAULT_OPENER_TIMEOUT,
};
pub use messages::{
    cert_digest_is_valid, cert_domain_is_valid, cert_id_is_valid,
    challenge_key_authorization_is_valid, challenge_token_is_valid, config_hash_is_valid,
    telemetry_audit_row_defect, BanPush, BanPushAck, CertMaterial, CertPull, CertPullAck, CertPush,
    CertPushAck, CertRefusal, ChallengePublish, ChallengePublishAck, ChallengeRetract,
    ChallengeRetractAck, ClusterFrame, ClusterRequest, ClusterResponse, ClusterStatus, ConfigAbort,
    ConfigAbortAck, ConfigCommit, ConfigCommitAck, ConfigPrepare, ConfigPrepareAck, ConfigPull,
    ConfigPullAck, Enroll, EnrollAck, Heartbeat, HeartbeatAck, Hello, HelloAck, Leave, LeaveAck,
    NodeResources, Renew, RenewAck, TelemetryAccessRow, TelemetryAuditRow, TelemetryBan,
    TelemetryPush, TelemetryPushAck, TelemetryWafRow, BODY_KIND_BAN_PUSH, BODY_KIND_CERT_PULL,
    BODY_KIND_CERT_PUSH, BODY_KIND_CHALLENGE_PUBLISH, BODY_KIND_CHALLENGE_RETRACT,
    BODY_KIND_CONFIG_ABORT, BODY_KIND_CONFIG_COMMIT, BODY_KIND_CONFIG_PREPARE,
    BODY_KIND_CONFIG_PULL, BODY_KIND_ENROLL, BODY_KIND_HEARTBEAT, BODY_KIND_HELLO, BODY_KIND_LEAVE,
    BODY_KIND_RENEW, BODY_KIND_TELEMETRY_PUSH, CERT_DIGEST_PREFIX, MAX_AUDIT_FIELD_BYTES,
    MAX_CERT_DOMAIN_BYTES, MAX_CERT_ID_BYTES, MAX_CHALLENGE_KEY_AUTHORIZATION_BYTES,
    MAX_CHALLENGE_TOKEN_BYTES, MAX_CONFIG_HASH_BYTES, MAX_TELEMETRY_AUDIT, MAX_TELEMETRY_BANS,
    MAX_TELEMETRY_ROWS,
};
pub use preauth::{source_key, AttemptWindow, PreAuthBudgets, SourceGate, SourceKey, SourceSlot};
pub use replication::{
    safe_reason, AcceptedConfig, AppliedConfig, ConfigPayload, ConfigVersion, ReplicationReport,
    Replicator, DEFAULT_PER_NODE_DEADLINE, DEFAULT_QUARANTINE_THRESHOLD, MAX_HONOURED_BREAK_GLASS,
    MAX_REJECTION_REASON_BYTES,
};
pub use roster::{
    ControlPlane, LiveSession, LiveSessionSnapshot, NodeIdentity, NodeState, RefreshGuard, Roster,
    SessionGuard, SessionRegistry, MAX_SESSIONS_PER_NODE_PER_WINDOW, SESSION_RATE_WINDOW,
};
pub use session::SessionContext;
pub use telemetry::{
    storage_verdict, IngestQuota, IngestVerdict, DEFAULT_BYTES_PER_WINDOW, DEFAULT_ROWS_PER_WINDOW,
    DEFAULT_STORAGE_CAP_BYTES, QUOTA_RETRY_AFTER_S, QUOTA_WINDOW,
};
pub use tls::{
    client_config, enrollment_server_config, join_client_config, leaf_spki_sha256,
    negotiated_cluster_alpn, operational_server_config, operational_server_config_with_crl,
    peer_fingerprint, ClusterTlsError, SwappableAcceptor, CLUSTER_ALPN,
};
pub use token::{MintError, MintedToken, ParsedToken, TokenFormatError};
pub use version::{negotiate, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION};

/// The TLS stack this crate's configs are built for, re-exported so
/// callers build connectors and acceptors against the same rustls
/// without pinning it themselves.
pub use tokio_rustls;

/// Re-exported for the same reason as [`tokio_rustls`]: the shared
/// configuration-version slot
/// ([`listener::OperationalConfig::config_version`]) is an
/// `Arc<ArcSwap<ConfigVersion>>`, and a caller must be able to name
/// that type without pinning `arc-swap` itself.
pub use arc_swap;
