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
//! - the two [`listener`]s with pre-authentication budgets (AC #3),
//!   convergence [`admission`] (AC #10), the follower [`dialer`]
//!   (AC #9) and the confused-deputy [`bridge`] (AC #6).
//!
//! Enrollment (join tokens, issuance over the wire) is Story 9.3.
//!
//! [`Frame`]: lorica_command::Frame

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod admission;
pub mod bridge;
pub mod ca;
pub mod dialer;
pub mod frame;
pub mod handshake;
pub mod limits;
pub mod listener;
pub mod messages;
pub mod tls;
pub mod version;

pub use admission::{AdmissionDecision, AdmissionGate, AdmissionPermit, DEFAULT_QUEUE_WAIT};
pub use bridge::{translate_cluster_request, BridgeOutcome, InPlaneAction};
pub use ca::{CaError, ClusterCa};
pub use dialer::{
    ClusterConnection, Dialer, DialerConfig, DialerHandle, DialerStats, SessionHandle,
    BACKOFF_CAP_CEILING,
};
pub use handshake::{
    client_handshake, evaluate_hello, node_name_is_valid, serve_hello, HandshakeConfig,
    HandshakeError, MAX_NODE_NAME_BYTES,
};
pub use limits::{cluster_rpc_limits, CLUSTER_MAX_MESSAGE_SIZE, CLUSTER_QUEUE_CAP};
pub use listener::{
    EnrollmentHandle, EnrollmentListener, EnrollmentStats, OperationalConfig, OperationalHandle,
    OperationalListener, OperationalStats, PreAuthBudgets, SessionContext, TokenLiveness,
};
pub use messages::{
    ClusterFrame, ClusterRequest, ClusterResponse, ClusterStatus, BODY_KIND_HEARTBEAT,
    BODY_KIND_HELLO,
};
pub use tls::{
    client_config, enrollment_server_config, negotiated_cluster_alpn, operational_server_config,
    ClusterTlsError, SwappableAcceptor, CLUSTER_ALPN,
};
pub use version::{negotiate, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION};
