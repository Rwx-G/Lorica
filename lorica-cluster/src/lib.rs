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
//!   worker plane's pipelined `RpcEndpoint` via a [`Frame`] impl;
//! - protocol version RANGE negotiation ([`version`], AC #4) and the
//!   schema-ordering check (AC #5) in the [`handshake`];
//! - the cluster CA and EKU-split leaf issuance ([`ca`], AC #8);
//! - the three TLS configs and the arc-swappable acceptor ([`tls`],
//!   AC #2's crypto half, Story 9.3's revocation seam).
//!
//! Listeners, dialer, budgets and metrics build on these in the same
//! story; enrollment (join tokens, issuance over the wire) is Story
//! 9.3.
//!
//! [`Frame`]: lorica_command::Frame

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod ca;
pub mod frame;
pub mod handshake;
pub mod messages;
pub mod tls;
pub mod version;

pub use ca::{CaError, ClusterCa};
pub use handshake::{client_handshake, evaluate_hello, serve_hello, HandshakeConfig, HandshakeError};
pub use messages::{ClusterFrame, ClusterRequest, ClusterResponse, ClusterStatus};
pub use tls::{
    client_config, enrollment_server_config, operational_server_config, ClusterTlsError,
    SwappableAcceptor,
};
pub use version::{negotiate, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION};
