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
#[non_exhaustive]
pub enum ClusterStatus {
    /// Opaque refusal (and proto3 default for unknown values). Note
    /// that an OLDER peer also sees any status it does not know as
    /// this value, so it cannot tell a newer status from a deliberate
    /// opaque refusal; acceptable, and documented in the .proto.
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
    /// The request had a well-formed shape but a `body_kind` this
    /// build does not implement: the peer is NEWER, the request is
    /// refused, the connection stays up (rolling-upgrade tolerance).
    UnsupportedMethod = 6,
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
            6 => Self::UnsupportedMethod,
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

/// `body_kind` value of a [`Hello`] request (its oneof tag).
pub const BODY_KIND_HELLO: u32 = 10;
/// `body_kind` value of a [`Heartbeat`] request (its oneof tag).
pub const BODY_KIND_HEARTBEAT: u32 = 11;

/// A request from either side of the cluster plane.
///
/// Body tags: 10-19 session control (this story), 20-39 RESERVED for
/// configuration replication (Story 9.4), 40-59 RESERVED for telemetry
/// fan-in (Story 9.6), 60-79 RESERVED for certificate distribution
/// (Story 9.5).
///
/// `body_kind` duplicates the body's oneof tag as a scalar so a
/// receiver that does NOT know the body (an older build talking to a
/// newer peer) can still tell "a method I do not implement" (answer
/// `UNSUPPORTED_METHOD`, keep the connection) from "no body at all"
/// (protocol violation, drop). prost decodes an unknown oneof tag as an
/// unknown field, leaving `body = None`; without the scalar the two
/// cases are indistinguishable and the wire format would freeze at
/// this release.
///
/// # Invariant
///
/// When a body IS present, `body_kind` MUST equal that body's oneof
/// tag. The constructors guarantee it on the sending side; every
/// decode boundary (the handshake opener and the bridge) checks it
/// with [`ClusterRequest::body_kind_matches`] and treats a mismatch as
/// a `PROTOCOL_VIOLATION`, so the scalar can never be used to make the
/// two readings of one request disagree.
#[derive(Clone, PartialEq, prost::Message)]
pub struct ClusterRequest {
    /// Monotonic per direction, managed by `RpcEndpoint`.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// The body's oneof tag, set by the constructors; `0` means the
    /// sender put no body at all.
    #[prost(uint32, tag = "3")]
    pub body_kind: u32,
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

    impl Body {
        /// The oneof tag of this body, for `ClusterRequest::body_kind`.
        pub fn kind(&self) -> u32 {
            match self {
                Body::Hello(_) => super::BODY_KIND_HELLO,
                Body::Heartbeat(_) => super::BODY_KIND_HEARTBEAT,
            }
        }
    }
}

impl ClusterRequest {
    /// A request carrying `body`, with `body_kind` set to match. The
    /// sequence is stamped by `RpcEndpoint` on send.
    pub fn with_body(body: cluster_request::Body) -> Self {
        Self {
            sequence: 0,
            body_kind: body.kind(),
            body: Some(body),
        }
    }

    /// A session opener.
    pub fn hello(hello: Hello) -> Self {
        Self::with_body(cluster_request::Body::Hello(hello))
    }

    /// A liveness probe.
    pub fn heartbeat(heartbeat: Heartbeat) -> Self {
        Self::with_body(cluster_request::Body::Heartbeat(heartbeat))
    }

    /// Whether `body_kind` names a method THIS build implements.
    pub fn is_known_body_kind(body_kind: u32) -> bool {
        matches!(body_kind, BODY_KIND_HELLO | BODY_KIND_HEARTBEAT)
    }

    /// The invariant every decode boundary enforces: a present body's
    /// oneof tag equals `body_kind`. An absent body always passes
    /// (the scalar alone then decides between "unknown method" and
    /// "no body at all").
    pub fn body_kind_matches(&self) -> bool {
        match &self.body {
            Some(body) => self.body_kind == body.kind(),
            None => true,
        }
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
    /// An admitted-or-served response carrying `body`. The sequence is
    /// stamped by `RpcEndpoint::reply_frame` from the request being
    /// answered; constructors never take one.
    pub fn ok(body: cluster_response::Body) -> Self {
        Self {
            sequence: 0,
            status: ClusterStatus::Ok as i32,
            retry_after_s: 0,
            body: Some(body),
        }
    }

    /// A refusal with `status` and no body. Enrollment-path callers
    /// must pass [`ClusterStatus::opaque()`] here (AC #4).
    pub fn refusal(status: ClusterStatus) -> Self {
        Self {
            sequence: 0,
            status: status as i32,
            retry_after_s: 0,
            body: None,
        }
    }

    /// The AC #10 admission-control answer.
    pub fn retry_later(retry_after_s: u32) -> Self {
        Self {
            sequence: 0,
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use prost::Message;

    use super::*;

    /// The published wire contract. The Rust types are hand-written
    /// prost derives (no protoc at build time); this test is the drift
    /// gate between the two.
    const PROTO: &str = include_str!("../proto/cluster.proto");

    /// `(block, field) -> tag` for every message field (oneof members
    /// included, attributed to their enclosing message) and enum
    /// value declared in the .proto.
    fn proto_tags() -> HashMap<(String, String), u32> {
        let mut out = HashMap::new();
        let mut block: Option<String> = None;
        let mut depth: usize = 0;
        for raw in PROTO.lines() {
            let line = raw.split("//").next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if depth == 0 {
                if let Some(rest) = line
                    .strip_prefix("message ")
                    .or_else(|| line.strip_prefix("enum "))
                {
                    block = Some(rest.trim_end_matches('{').trim().to_string());
                }
            }
            if let (Some(b), Some((lhs, rhs))) = (&block, line.split_once('=')) {
                if line.ends_with(';') {
                    let name = lhs.split_whitespace().last().expect("field name").to_string();
                    let tag: u32 = rhs
                        .trim()
                        .trim_end_matches(';')
                        .trim()
                        .parse()
                        .expect("numeric tag");
                    out.insert((b.clone(), name), tag);
                }
            }
            depth += line.matches('{').count();
            depth = depth.saturating_sub(line.matches('}').count());
            if depth == 0 && line.contains('}') {
                block = None;
            }
        }
        out
    }

    fn varint(bytes: &[u8]) -> (u64, usize) {
        let mut value = 0u64;
        let mut shift = 0u32;
        for (i, byte) in bytes.iter().enumerate() {
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return (value, i + 1);
            }
            shift += 7;
        }
        panic!("truncated varint");
    }

    /// The field numbers present in an encoded message, in wire order.
    fn field_numbers(bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let (key, n) = varint(&bytes[i..]);
            i += n;
            out.push((key >> 3) as u32);
            match key & 7 {
                0 => {
                    let (_, n) = varint(&bytes[i..]);
                    i += n;
                }
                1 => i += 8,
                2 => {
                    let (len, n) = varint(&bytes[i..]);
                    i += n + len as usize;
                }
                5 => i += 4,
                other => panic!("unexpected wire type {other}"),
            }
        }
        out
    }

    #[test]
    fn rust_tags_match_the_published_proto() {
        let tags = proto_tags();
        let tag = |block: &str, field: &str| -> u32 {
            *tags
                .get(&(block.to_string(), field.to_string()))
                .unwrap_or_else(|| panic!("{block}.{field} missing from cluster.proto"))
        };

        // Every scalar is non-zero so prost emits it.
        let hello = Hello {
            protocol_min: 1,
            protocol_max: 1,
            schema_version: 1,
            node_name: "n".to_string(),
        };
        assert_eq!(
            field_numbers(&hello.encode_to_vec()),
            vec![
                tag("Hello", "protocol_min"),
                tag("Hello", "protocol_max"),
                tag("Hello", "schema_version"),
                tag("Hello", "node_name"),
            ]
        );
        let ack = HelloAck {
            negotiated_version: 1,
            schema_version: 1,
            fleet_size_hint: 1,
        };
        assert_eq!(
            field_numbers(&ack.encode_to_vec()),
            vec![
                tag("HelloAck", "negotiated_version"),
                tag("HelloAck", "schema_version"),
                tag("HelloAck", "fleet_size_hint"),
            ]
        );
        assert_eq!(
            field_numbers(&Heartbeat { timestamp_ms: 1 }.encode_to_vec()),
            vec![tag("Heartbeat", "timestamp_ms")]
        );
        assert_eq!(
            field_numbers(
                &HeartbeatAck {
                    timestamp_ms: 1,
                    fleet_size_hint: 1
                }
                .encode_to_vec()
            ),
            vec![
                tag("HeartbeatAck", "timestamp_ms"),
                tag("HeartbeatAck", "fleet_size_hint"),
            ]
        );

        let mut request = ClusterRequest::hello(Hello::default());
        request.sequence = 1;
        assert_eq!(
            field_numbers(&request.encode_to_vec()),
            vec![
                tag("ClusterRequest", "sequence"),
                tag("ClusterRequest", "body_kind"),
                tag("ClusterRequest", "hello"),
            ]
        );
        let mut request = ClusterRequest::heartbeat(Heartbeat::default());
        request.sequence = 1;
        assert_eq!(
            field_numbers(&request.encode_to_vec()),
            vec![
                tag("ClusterRequest", "sequence"),
                tag("ClusterRequest", "body_kind"),
                tag("ClusterRequest", "heartbeat"),
            ]
        );
        // `body_kind` IS the body's tag by definition.
        assert_eq!(BODY_KIND_HELLO, tag("ClusterRequest", "hello"));
        assert_eq!(BODY_KIND_HEARTBEAT, tag("ClusterRequest", "heartbeat"));

        let mut response = ClusterResponse::retry_later(1);
        response.sequence = 1;
        response.body = Some(cluster_response::Body::HelloAck(HelloAck::default()));
        assert_eq!(
            field_numbers(&response.encode_to_vec()),
            vec![
                tag("ClusterResponse", "sequence"),
                tag("ClusterResponse", "status"),
                tag("ClusterResponse", "retry_after_s"),
                tag("ClusterResponse", "hello_ack"),
            ]
        );
        response.body = Some(cluster_response::Body::HeartbeatAck(HeartbeatAck::default()));
        assert_eq!(
            *field_numbers(&response.encode_to_vec()).last().expect("body"),
            tag("ClusterResponse", "heartbeat_ack")
        );

        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Request(ClusterRequest::default())),
        };
        assert_eq!(
            field_numbers(&frame.encode_to_vec()),
            vec![tag("ClusterFrame", "request")]
        );
        let frame = ClusterFrame {
            kind: Some(cluster_frame::Kind::Response(ClusterResponse::default())),
        };
        assert_eq!(
            field_numbers(&frame.encode_to_vec()),
            vec![tag("ClusterFrame", "response")]
        );
    }

    #[test]
    fn status_values_match_the_published_enum() {
        let tags = proto_tags();
        let value = |name: &str| -> i32 {
            *tags
                .get(&("ClusterStatus".to_string(), name.to_string()))
                .unwrap_or_else(|| panic!("ClusterStatus.{name} missing from cluster.proto"))
                as i32
        };
        let pairs = [
            ("CLUSTER_STATUS_UNSPECIFIED", ClusterStatus::Unspecified),
            ("OK", ClusterStatus::Ok),
            ("RETRY_LATER", ClusterStatus::RetryLater),
            ("INCOMPATIBLE_VERSION", ClusterStatus::IncompatibleVersion),
            ("SCHEMA_TOO_OLD", ClusterStatus::SchemaTooOld),
            ("PROTOCOL_VIOLATION", ClusterStatus::ProtocolViolation),
            ("UNSUPPORTED_METHOD", ClusterStatus::UnsupportedMethod),
        ];
        for (name, status) in pairs {
            assert_eq!(status as i32, value(name), "{name}");
            assert_eq!(ClusterStatus::from_i32(status as i32), status, "{name}");
        }
        // Every published value has a Rust arm (and vice versa).
        let published = tags.keys().filter(|(b, _)| b == "ClusterStatus").count();
        assert_eq!(published, pairs.len());
        assert_eq!(ClusterStatus::from_i32(99), ClusterStatus::Unspecified);
    }

    #[test]
    fn body_kind_invariant_holds_for_constructors_and_flags_mismatches() {
        assert!(ClusterRequest::hello(Hello::default()).body_kind_matches());
        assert!(ClusterRequest::heartbeat(Heartbeat::default()).body_kind_matches());
        // No body: the scalar alone is authoritative.
        assert!(ClusterRequest {
            sequence: 0,
            body_kind: 25,
            body: None
        }
        .body_kind_matches());
        let mut forged = ClusterRequest::heartbeat(Heartbeat::default());
        forged.body_kind = BODY_KIND_HELLO;
        assert!(!forged.body_kind_matches());
        // Reserved ranges are unknown to this build.
        for kind in [0, 12, 20, 39, 40, 59, 60, 79] {
            assert!(!ClusterRequest::is_known_body_kind(kind), "{kind}");
        }
    }
}
