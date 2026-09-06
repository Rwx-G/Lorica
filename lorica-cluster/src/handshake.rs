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

//! Cluster session handshake (Story 9.2 AC #4/#5), spoken over an
//! established [`RpcEndpoint<ClusterFrame>`] AFTER mutual TLS has
//! verified the client certificate on the operational path.
//!
//! The client opens with [`Hello`] (protocol range + schema version);
//! the server negotiates the highest common protocol version and
//! checks the schema ordering. Refusals carry a DISTINCT
//! [`ClusterStatus`] on the authenticated operational path; callers on
//! the pre-authentication enrollment path must instead answer with
//! [`ClusterStatus::opaque()`] and keep the real diagnostic in the
//! local log (AC #4's reconnaissance note).

use std::time::Duration;

use lorica_command::{ChannelError, IncomingRequest, RpcEndpoint};

use crate::messages::{
    cluster_request, cluster_response, ClusterFrame, ClusterRequest, ClusterResponse,
    ClusterStatus, Hello, HelloAck,
};
use crate::version::{negotiate, PROTOCOL_MIN_COMPATIBLE, PROTOCOL_VERSION};

/// Longest `node_name` a [`Hello`] may carry. The field is display
/// only, but it is peer-supplied: bound it before it can become a
/// per-handshake allocation or a log-injection vector.
pub const MAX_NODE_NAME_BYTES: usize = 64;

/// The local side's handshake inputs.
///
/// Construct with [`HandshakeConfig::new`] (the protocol range comes
/// from this build's [`crate::version`] constants); the fields stay
/// public so tests can simulate other builds.
#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Lowest protocol version this node still speaks.
    pub protocol_min: u32,
    /// Highest protocol version this node speaks.
    pub protocol_max: u32,
    /// This node's database schema version
    /// (`ConfigStore::schema_version()` at boot).
    pub schema_version: u32,
}

impl HandshakeConfig {
    /// This build's protocol range with the node's `schema_version`.
    pub fn new(schema_version: u32) -> Self {
        Self {
            protocol_min: PROTOCOL_MIN_COMPATIBLE,
            protocol_max: PROTOCOL_VERSION,
            schema_version,
        }
    }
}

/// Errors surfaced to the DIALING side of a handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    /// Transport failure (timeout, closed connection, oversize frame).
    #[error("cluster handshake transport failure: {0}")]
    Transport(#[from] ChannelError),
    /// The control plane refused the session with this status.
    #[error("cluster handshake refused: {0:?}")]
    Refused(ClusterStatus),
    /// The admission gate is full (AC #10); retry after this many
    /// seconds. Split from [`HandshakeError::Refused`] so the dialer
    /// can honour the server-provided delay.
    #[error("cluster admission full; retry after {retry_after_s}s")]
    RetryLater {
        /// Server-provided delay before the next attempt.
        retry_after_s: u32,
    },
    /// The peer answered with something other than a HelloAck.
    #[error("cluster handshake protocol violation: unexpected response body")]
    ProtocolViolation,
}

/// Whether a peer-supplied `node_name` is acceptable: within
/// [`MAX_NODE_NAME_BYTES`] and free of control characters.
pub fn node_name_is_valid(node_name: &str) -> bool {
    node_name.len() <= MAX_NODE_NAME_BYTES && !node_name.chars().any(char::is_control)
}

/// Server-side evaluation of a peer's [`Hello`] - pure, so every
/// refusal path is unit-testable without sockets.
///
/// Returns the [`HelloAck`] to send, or the DISTINCT refusal status
/// for the operational path (enrollment callers map it through
/// [`ClusterStatus::opaque`] before the wire). An oversized or
/// control-character `node_name` is a protocol violation.
pub fn evaluate_hello(
    local: &HandshakeConfig,
    fleet_size_hint: u32,
    hello: &Hello,
) -> Result<HelloAck, ClusterStatus> {
    if !node_name_is_valid(&hello.node_name) {
        return Err(ClusterStatus::ProtocolViolation);
    }
    let Some(negotiated_version) = negotiate(
        local.protocol_min,
        local.protocol_max,
        hello.protocol_min,
        hello.protocol_max,
    ) else {
        return Err(ClusterStatus::IncompatibleVersion);
    };
    // AC #5: a follower BELOW the control plane's schema cannot apply
    // configuration written by the newer schema; refuse with the
    // distinct diagnostic. A follower AHEAD of the control plane is
    // fine (its store reads older rows), which is what makes rolling
    // upgrades order-able: upgrade followers first.
    if hello.schema_version < local.schema_version {
        return Err(ClusterStatus::SchemaTooOld);
    }
    Ok(HelloAck {
        negotiated_version,
        schema_version: local.schema_version,
        fleet_size_hint,
    })
}

/// Serve one incoming request AS the handshake opener: the first
/// request on an operational session must be a [`Hello`]. Replies with
/// the ack or the distinct refusal, and returns the outcome so the
/// caller can keep or drop the session.
///
/// Anything other than a `Hello` as the opener, or a `Hello` whose
/// `body_kind` disagrees with its body, is a protocol violation: the
/// caller must drop the connection (AC #6 handling).
pub async fn serve_hello(
    incoming: IncomingRequest<ClusterFrame>,
    local: &HandshakeConfig,
    fleet_size_hint: u32,
) -> Result<Result<HelloAck, ClusterStatus>, ChannelError> {
    let hello = match &incoming.request().body {
        Some(cluster_request::Body::Hello(hello)) if incoming.request().body_kind_matches() => {
            hello.clone()
        }
        _ => {
            incoming
                .reply_frame(ClusterResponse::refusal(ClusterStatus::ProtocolViolation))
                .await?;
            return Ok(Err(ClusterStatus::ProtocolViolation));
        }
    };

    match evaluate_hello(local, fleet_size_hint, &hello) {
        Ok(ack) => {
            incoming
                .reply_frame(ClusterResponse::ok(cluster_response::Body::HelloAck(
                    ack.clone(),
                )))
                .await?;
            Ok(Ok(ack))
        }
        Err(status) => {
            incoming.reply_frame(ClusterResponse::refusal(status)).await?;
            Ok(Err(status))
        }
    }
}

/// Client (dialer) side: send [`Hello`] and await the ack.
///
/// `node_name` is display-only (identity is the client certificate).
pub async fn client_handshake(
    endpoint: &RpcEndpoint<ClusterFrame>,
    local: &HandshakeConfig,
    node_name: &str,
    timeout: Duration,
) -> Result<HelloAck, HandshakeError> {
    let request = ClusterRequest::hello(Hello {
        protocol_min: local.protocol_min,
        protocol_max: local.protocol_max,
        schema_version: local.schema_version,
        node_name: node_name.to_string(),
    });
    let response = endpoint.request(request, timeout).await?;
    match response.cluster_status() {
        ClusterStatus::Ok => match response.body {
            Some(cluster_response::Body::HelloAck(ack)) => Ok(ack),
            _ => Err(HandshakeError::ProtocolViolation),
        },
        ClusterStatus::RetryLater => Err(HandshakeError::RetryLater {
            retry_after_s: response.retry_after_s,
        }),
        refused => Err(HandshakeError::Refused(refused)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> HandshakeConfig {
        HandshakeConfig::new(49)
    }

    fn hello(min: u32, max: u32, schema: u32) -> Hello {
        Hello {
            protocol_min: min,
            protocol_max: max,
            schema_version: schema,
            node_name: "node".to_string(),
        }
    }

    #[test]
    fn matching_peer_is_admitted() {
        let ack = evaluate_hello(&local(), 5, &hello(1, 1, 49)).expect("admitted");
        assert_eq!(ack.negotiated_version, 1);
        assert_eq!(ack.schema_version, 49);
        assert_eq!(ack.fleet_size_hint, 5);
    }

    #[test]
    fn newer_follower_schema_is_admitted() {
        // Rolling upgrade order: followers upgrade first, so a
        // follower one schema AHEAD must be admitted.
        assert!(evaluate_hello(&local(), 0, &hello(1, 1, 50)).is_ok());
    }

    #[test]
    fn older_follower_schema_gets_the_distinct_diagnostic() {
        assert_eq!(
            evaluate_hello(&local(), 0, &hello(1, 1, 48)),
            Err(ClusterStatus::SchemaTooOld)
        );
    }

    #[test]
    fn disjoint_protocol_ranges_are_refused() {
        assert_eq!(
            evaluate_hello(&local(), 0, &hello(7, 9, 49)),
            Err(ClusterStatus::IncompatibleVersion)
        );
    }

    #[test]
    fn oversized_or_control_character_node_names_are_violations() {
        let mut long = hello(1, 1, 49);
        long.node_name = "n".repeat(MAX_NODE_NAME_BYTES + 1);
        assert_eq!(
            evaluate_hello(&local(), 0, &long),
            Err(ClusterStatus::ProtocolViolation)
        );
        let mut injected = hello(1, 1, 49);
        injected.node_name = "edge\n[forged log line]".to_string();
        assert_eq!(
            evaluate_hello(&local(), 0, &injected),
            Err(ClusterStatus::ProtocolViolation)
        );
        // Exactly at the bound is fine, and so is an empty name.
        let mut max = hello(1, 1, 49);
        max.node_name = "n".repeat(MAX_NODE_NAME_BYTES);
        assert!(evaluate_hello(&local(), 0, &max).is_ok());
        let mut empty = hello(1, 1, 49);
        empty.node_name.clear();
        assert!(evaluate_hello(&local(), 0, &empty).is_ok());
    }
}
