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

//! [`lorica_command::Frame`] implementation for [`ClusterFrame`], so
//! the cluster plane rides the same pipelined `RpcEndpoint` transport
//! as the worker plane while speaking a fully disjoint message set
//! (Story 9.2 AC #6).
//!
//! # Disjointness guarantee (and its honest limits)
//!
//! `ClusterFrame`'s oneof uses tags 101/102 while the worker
//! `Envelope` uses 1/2. Under prost's tolerant decoding, worker-plane
//! code fed cluster bytes sees only unknown fields: the decode
//! SUCCEEDS but yields `kind = None`, which `RpcEndpoint`'s reader
//! classifies as `FrameKind::Empty` and drops with a warning - it can
//! never surface as a `Command` (`SHUTDOWN`, `BAN_IP`, ...). The same
//! holds in the other direction. What tag disjointness alone cannot
//! prevent is a MALICIOUS peer deliberately encoding worker-`Envelope`
//! bytes on a cluster connection; that is caught by the bridge, which
//! only translates whitelisted cluster bodies and treats an empty or
//! unknown frame as a protocol violation.

use lorica_command::{Frame, FrameKind};

use crate::messages::{cluster_frame, ClusterFrame, ClusterRequest, ClusterResponse};

impl Frame for ClusterFrame {
    type Request = ClusterRequest;
    type Response = ClusterResponse;

    fn into_kind(self) -> FrameKind<ClusterRequest, ClusterResponse> {
        match self.kind {
            Some(cluster_frame::Kind::Request(req)) => FrameKind::Request(req),
            Some(cluster_frame::Kind::Response(resp)) => FrameKind::Response(resp),
            None => FrameKind::Empty,
        }
    }

    fn from_request(req: ClusterRequest) -> Self {
        Self {
            kind: Some(cluster_frame::Kind::Request(req)),
        }
    }

    fn from_response(resp: ClusterResponse) -> Self {
        Self {
            kind: Some(cluster_frame::Kind::Response(resp)),
        }
    }

    fn request_sequence(req: &ClusterRequest) -> u64 {
        req.sequence
    }

    fn set_request_sequence(req: &mut ClusterRequest, seq: u64) {
        req.sequence = seq;
    }

    fn response_sequence(resp: &ClusterResponse) -> u64 {
        resp.sequence
    }

    fn set_response_sequence(resp: &mut ClusterResponse, seq: u64) {
        resp.sequence = seq;
    }
}

#[cfg(test)]
mod tests {
    use lorica_command::messages::Envelope;
    use prost::Message;

    use super::*;
    use crate::messages::{cluster_request, Hello};

    fn sample_frame() -> ClusterFrame {
        let mut req = ClusterRequest::hello(Hello {
            protocol_min: 1,
            protocol_max: 1,
            schema_version: 49,
            node_name: "edge-node".to_string(),
            build_version: String::new(),
        });
        req.sequence = 42;
        ClusterFrame::from_request(req)
    }

    #[test]
    fn cluster_bytes_never_decode_as_a_worker_command() {
        // Story 9.2 AC #6, type-level half: worker-plane code fed
        // cluster bytes must see an EMPTY envelope (kind = None), never
        // a Command it might dispatch.
        let bytes = sample_frame().encode_to_vec();
        let as_envelope = Envelope::decode(bytes.as_slice()).expect("prost decode is tolerant");
        assert!(
            as_envelope.kind.is_none(),
            "cluster frame bytes must not materialise a worker Command/Response"
        );
    }

    #[test]
    fn worker_bytes_never_decode_as_a_cluster_frame() {
        use lorica_command::messages::{envelope, Command, CommandType};

        // The reverse direction: a worker Envelope (here a SHUTDOWN
        // command, the worst case) must not materialise as a cluster
        // request or response.
        let env = Envelope {
            kind: Some(envelope::Kind::Command(Command::new(
                CommandType::Shutdown,
                7,
            ))),
        };
        let bytes = env.encode_to_vec();
        let as_cluster = ClusterFrame::decode(bytes.as_slice()).expect("prost decode is tolerant");
        assert!(
            as_cluster.kind.is_none(),
            "worker envelope bytes must not materialise a cluster frame"
        );
    }

    #[test]
    fn frame_round_trips_through_the_frame_trait() {
        let frame = sample_frame();
        let bytes = frame.encode_to_vec();
        let decoded = ClusterFrame::decode(bytes.as_slice()).expect("decode");
        match decoded.into_kind() {
            FrameKind::Request(req) => {
                assert_eq!(req.sequence, 42);
                match req.body {
                    Some(cluster_request::Body::Hello(h)) => {
                        assert_eq!(h.schema_version, 49);
                        assert_eq!(h.node_name, "edge-node");
                    }
                    other => panic!("expected Hello body, got {other:?}"),
                }
            }
            _ => panic!("expected a request frame"),
        }
    }

    #[test]
    fn sequence_accessors_are_wired() {
        let mut req = ClusterRequest::default();
        ClusterFrame::set_request_sequence(&mut req, 9);
        assert_eq!(ClusterFrame::request_sequence(&req), 9);
        let mut resp = ClusterResponse::default();
        ClusterFrame::set_response_sequence(&mut resp, 11);
        assert_eq!(ClusterFrame::response_sequence(&resp), 11);
    }
}
