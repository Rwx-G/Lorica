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

//! Protobuf message types for the cluster-plane protocol.
//!
//! Defined using prost derive macros to avoid requiring protoc at build
//! time. See `proto/cluster.proto` for the canonical schema
//! documentation, including the tag-disjointness argument against the
//! worker plane's `lorica.command` package (Story 9.2 AC #6) and the
//! tag ranges reserved for Stories 9.4/9.5/9.6.

/// Response status for a [`ClusterResponse`].
///
/// `Unspecified` doubles as the OPAQUE refusal for pre-authentication
/// paths (Story 9.2 AC #4): an unauthenticated peer must not learn
/// build or protocol facts from refusal shapes. Callers on the
/// enrollment listener map every refusal through
/// [`ClusterStatus::opaque`] before it reaches the wire and log the
/// real cause locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum ClusterStatus {
    /// Opaque refusal (and proto3 default for unknown values).
    Unspecified = 0,
    /// Session admitted / request served.
    Ok = 1,
    /// Admission control queue is full (AC #10); retry after
    /// `retry_after_s`.
    RetryLater = 2,
    /// No overlap between the peers' protocol version ranges (AC #4).
    IncompatibleVersion = 3,
    /// The follower's schema version is below the control plane's
    /// (AC #5); configuration apply is refused with this distinct
    /// diagnostic.
    SchemaTooOld = 4,
    /// The peer sent a malformed or wrong-plane frame (AC #6).
    ProtocolViolation = 5,
}

impl ClusterStatus {
    /// Decode from the wire representation; unknown values collapse to
    /// [`ClusterStatus::Unspecified`].
    pub fn from_i32(v: i32) -> Self {
        match v {
            1 => Self::Ok,
            2 => Self::RetryLater,
            3 => Self::IncompatibleVersion,
            4 => Self::SchemaTooOld,
            5 => Self::ProtocolViolation,
            _ => Self::Unspecified,
        }
    }

    /// The status an unauthenticated (enrollment-path) peer sees for
    /// ANY refusal: [`ClusterStatus::Unspecified`]. The real cause is
    /// for the local log only.
    pub fn opaque() -> Self {
        Self::Unspecified
    }
}

/// First request on every operational connection, sent AFTER mutual
/// TLS has verified the client certificate (AC #4).
#[derive(Clone, PartialEq, prost::Message)]
pub struct Hello {
    /// Lowest protocol version the sender still speaks (AC #4).
    #[prost(uint32, tag = "1")]
    pub protocol_min: u32,
    /// Highest protocol version the sender speaks.
    #[prost(uint32, tag = "2")]
    pub protocol_max: u32,
    /// The sender's database schema version (AC #5).
    #[prost(uint32, tag = "3")]
    pub schema_version: u32,
    /// Display name only. Node IDENTITY is the peer-certificate
    /// fingerprint recorded at enrollment (Story 9.3 AC #8); never an
    /// authorization input, never a metric label (AC #12).
    #[prost(string, tag = "4")]
    pub node_name: ::prost::alloc::string::String,
}

/// Control-plane answer to a [`Hello`] when the session is admitted.
#[derive(Clone, PartialEq, prost::Message)]
pub struct HelloAck {
    /// Highest protocol version both sides speak.
    #[prost(uint32, tag = "1")]
    pub negotiated_version: u32,
    /// The control plane's schema version.
    #[prost(uint32, tag = "2")]
    pub schema_version: u32,
    /// Approximate fleet size so the follower can scale its reconnect
    /// backoff cap (AC #9) without knowing the roster.
    #[prost(uint32, tag = "3")]
    pub fleet_size_hint: u32,
}

/// Liveness probe, either direction.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Heartbeat {
    /// Sender's clock, unix milliseconds.
    #[prost(uint64, tag = "1")]
    pub timestamp_ms: u64,
}

/// Answer to a [`Heartbeat`].
#[derive(Clone, PartialEq, prost::Message)]
pub struct HeartbeatAck {
    /// Echo of the probe's `timestamp_ms`.
    #[prost(uint64, tag = "1")]
    pub timestamp_ms: u64,
    /// Refreshed backoff-cap input (AC #9).
    #[prost(uint32, tag = "2")]
    pub fleet_size_hint: u32,
}

/// A request from either side of the cluster plane.
///
/// Body tags: 10-19 session control (this story), 20-39 RESERVED for
/// configuration replication (Story 9.4), 40-59 RESERVED for telemetry
/// fan-in (Story 9.6), 60-79 RESERVED for certificate distribution
/// (Story 9.5).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterRequest {
    /// Monotonic per direction, managed by `RpcEndpoint`.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// Typed request body.
    #[prost(oneof = "cluster_request::Body", tags = "10, 11")]
    pub body: ::core::option::Option<cluster_request::Body>,
}

/// Typed body variants for [`ClusterRequest`].
pub mod cluster_request {
    use super::{Heartbeat, Hello};

    /// Request payloads (see the tag-range note on `ClusterRequest`).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        /// Session opener (post-TLS on the operational path).
        #[prost(message, tag = "10")]
        Hello(Hello),
        /// Liveness probe.
        #[prost(message, tag = "11")]
        Heartbeat(Heartbeat),
    }
}

/// A response matched to a [`ClusterRequest`] by `sequence`.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterResponse {
    /// Sequence of the request being answered.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// [`ClusterStatus`] as its wire integer.
    #[prost(int32, tag = "2")]
    pub status: i32,
    /// Only meaningful with [`ClusterStatus::RetryLater`] (AC #10).
    #[prost(uint32, tag = "3")]
    pub retry_after_s: u32,
    /// Typed response body; `None` on refusals.
    #[prost(oneof = "cluster_response::Body", tags = "10, 11")]
    pub body: ::core::option::Option<cluster_response::Body>,
}

/// Typed body variants for [`ClusterResponse`].
pub mod cluster_response {
    use super::{HeartbeatAck, HelloAck};

    /// Response payloads (tag ranges mirror `cluster_request::Body`).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        /// Session admitted.
        #[prost(message, tag = "10")]
        HelloAck(HelloAck),
        /// Liveness answer.
        #[prost(message, tag = "11")]
        HeartbeatAck(HeartbeatAck),
    }
}

impl ClusterResponse {
    /// An admitted-or-served response carrying `body`.
    pub fn ok(sequence: u64, body: cluster_response::Body) -> Self {
        Self {
            sequence,
            status: ClusterStatus::Ok as i32,
            retry_after_s: 0,
            body: Some(body),
        }
    }

    /// A refusal with `status` and no body. Enrollment-path callers
    /// must pass [`ClusterStatus::opaque()`] here (AC #4).
    pub fn refusal(sequence: u64, status: ClusterStatus) -> Self {
        Self {
            sequence,
            status: status as i32,
            retry_after_s: 0,
            body: None,
        }
    }

    /// The AC #10 admission-control answer.
    pub fn retry_later(sequence: u64, retry_after_s: u32) -> Self {
        Self {
            sequence,
            status: ClusterStatus::RetryLater as i32,
            retry_after_s,
            body: None,
        }
    }

    /// Decoded [`ClusterStatus`] of this response.
    pub fn cluster_status(&self) -> ClusterStatus {
        ClusterStatus::from_i32(self.status)
    }
}

/// Top-level cluster frame.
///
/// The oneof tags are 101/102, deliberately DISJOINT from the worker
/// plane's `Envelope` (tags 1/2): bytes of one frame type decode to an
/// empty frame (`kind = None`) on the other plane, never to a valid
/// message (Story 9.2 AC #6, type-level half; the bridge whitelist is
/// the enforced half).
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterFrame {
    /// Request or response.
    #[prost(oneof = "cluster_frame::Kind", tags = "101, 102")]
    pub kind: ::core::option::Option<cluster_frame::Kind>,
}

/// Kind variants for [`ClusterFrame`].
pub mod cluster_frame {
    use super::{ClusterRequest, ClusterResponse};

    /// Request or response (tags 101/102; see the disjointness note).
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// A request from the peer.
        #[prost(message, tag = "101")]
        Request(ClusterRequest),
        /// A response to one of our requests.
        #[prost(message, tag = "102")]
        Response(ClusterResponse),
    }
}
