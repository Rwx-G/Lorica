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
pub mod dialer;
pub mod enroll;
pub mod frame;
pub mod handshake;
pub mod limits;
pub mod listener;
pub mod messages;
pub mod preauth;
pub mod roster;
pub mod session;
pub mod tls;
pub mod token;
pub mod version;

pub use admission::{AdmissionDecision, AdmissionGate, AdmissionPermit, DEFAULT_QUEUE_WAIT};
pub use bridge::{translate_cluster_request, BridgeOutcome, InPlaneAction};
pub use ca::{CaError, ClusterCa, IssuedLeaf, RevokedEntry};
pub use enroll::{
    join, EnrollGrant, EnrollRefusal, EnrollRequest, EnrollmentHandler, JoinError, JoinParams,
    NoopSessionHandler, RefuseAllEnrollments, RenewGrant, RenewRequest, SessionHandler,
};
pub use dialer::{
    split_host_port, ClusterConnection, Dialer, DialerConfig, DialerError, DialerHandle,
    DialerStats, SessionHandle, BACKOFF_CAP_CEILING,
};
pub use handshake::{
    client_handshake, display_field_is_valid, evaluate_hello, node_name_is_valid, serve_hello,
    HandshakeConfig, HandshakeError, MAX_NODE_NAME_BYTES,
};
pub use limits::{cluster_rpc_limits, CLUSTER_MAX_MESSAGE_SIZE, CLUSTER_QUEUE_CAP};
pub use listener::{
    EnrollmentHandle, EnrollmentListener, EnrollmentStats, FleetHooks, OperationalConfig,
    OperationalHandle, OperationalListener, OperationalStats, TokenLiveness,
    DEFAULT_MAX_SESSIONS, DEFAULT_OPENER_TIMEOUT,
};
pub use messages::{
    ClusterFrame, ClusterRequest, ClusterResponse, ClusterStatus, Enroll, EnrollAck, Heartbeat,
    HeartbeatAck, Hello, HelloAck, Leave, LeaveAck, Renew, RenewAck, BODY_KIND_ENROLL,
    BODY_KIND_HEARTBEAT, BODY_KIND_HELLO, BODY_KIND_LEAVE, BODY_KIND_RENEW,
};
pub use preauth::{source_key, PreAuthBudgets, SourceGate, SourceKey, SourceSlot};
pub use roster::{
    ControlPlane, LiveSessionSnapshot, NodeIdentity, NodeState, Roster, SessionGuard,
    SessionRegistry,
};
pub use session::SessionContext;
pub use tls::{
    client_config, enrollment_server_config, join_client_config, leaf_spki_sha256,
    negotiated_cluster_alpn, operational_server_config, operational_server_config_with_crl,
    peer_fingerprint, ClusterTlsError, SwappableAcceptor, CLUSTER_ALPN,
};
pub use token::{MintedToken, ParsedToken, TokenFormatError};
pub use version::{negotiate, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION};

/// The TLS stack this crate's configs are built for, re-exported so
/// callers build connectors and acceptors against the same rustls
/// without pinning it themselves.
pub use tokio_rustls;
