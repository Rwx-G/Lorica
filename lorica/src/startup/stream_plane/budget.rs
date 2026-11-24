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

//! The node-side budget: the demand each binding declares, the
//! failure a refusal is reported with, and what bounds the node's UDP
//! session ceiling.

use lorica_config::models::Stream;
use lorica_stream::budget::CeilingBound;
use lorica_stream::{BindFailureKind, BindKey, BudgetViolation, StreamDemand};

use super::{StreamPlane, WorkerLink};

/// The budget demand of binding `key`: [`StreamDemand::of`] its stream,
/// the one demand function the API's write check also builds on (Story
/// 12.3 D-p), with the protocol and ports of the binding as bound. A
/// binding whose stream is gone declares nothing beyond its sockets.
pub(super) fn demand_of(key: &BindKey, stream: Option<&Stream>) -> StreamDemand {
    let listen_sockets = u64::from(key.port_last.saturating_sub(key.port_first)) + 1;
    match stream {
        Some(stream) => StreamDemand {
            protocol: key.protocol,
            listen_sockets,
            ..StreamDemand::of(stream)
        },
        None => StreamDemand {
            stream_id: key.stream_id.clone(),
            name: String::new(),
            protocol: key.protocol,
            listen_sockets,
            held: None,
            source_addresses: Vec::new(),
        },
    }
}

/// The failure kind a node-side budget refusal is reported with.
pub(super) fn budget_failure_kind(violation: &BudgetViolation) -> BindFailureKind {
    match violation {
        BudgetViolation::SourcePorts { .. } => BindFailureKind::SourcePorts,
        BudgetViolation::ListenSocketCap { .. }
        | BudgetViolation::WorkerFds { .. }
        | BudgetViolation::SupervisorFds { .. } => BindFailureKind::FdBudget,
    }
}

impl<L: WorkerLink> StreamPlane<L> {
    /// What bounds the node's UDP session ceiling for the streams of
    /// `streams` this plane holds, with the source ports read at the last
    /// pass: the `stream_udp_ceiling_reached` alert names it (Story 12.9
    /// D-h).
    pub(crate) fn ceiling_bound(&self, streams: &[Stream]) -> CeilingBound {
        let demands: Vec<StreamDemand> = streams
            .iter()
            .filter(|s| self.held.contains_key(&s.id))
            .map(StreamDemand::of)
            .collect();
        self.budget
            .session_ceiling(&demands, self.usable_source_ports)
            .bound_by
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use lorica_stream::reconcile::desired_bindings;
    use lorica_stream::BindState;

    use super::*;
    use crate::startup::stream_plane::caps::lock_caps;
    use crate::startup::stream_plane::test_support::{
        bindable, free_ports, free_udp_port, plane, tcp, udp, FakeLink, DEFAULT_RANGE_USABLE_PORTS,
        PASS, STANDALONE,
    };
    use crate::startup::stream_plane::{PassSettings, PlaneEvent, Trigger};

    #[tokio::test]
    async fn the_listen_socket_cap_refuses_the_binding_past_it() {
        let (w0, _) = FakeLink::new(&[]);
        let (mut plane, _) = plane(vec![w0]);
        let first = free_ports(2);
        let streams = vec![tcp("a", first), tcp("b", first + 1)];
        let pass = PassSettings {
            listen_socket_cap: 1,
            ..PASS
        };

        let events = plane
            .bind_desired(&streams, &[], STANDALONE, pass, Trigger::Change)
            .await;

        assert!(matches!(events[0], PlaneEvent::Bound { .. }));
        match &events[1] {
            PlaneEvent::BindFailed {
                kind: BindFailureKind::FdBudget,
                os_error,
                ..
            } => assert!(os_error.contains("stream_listen_socket_cap"), "{os_error}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(bindable(first + 1));
    }

    #[tokio::test]
    async fn the_node_refuses_a_udp_binding_past_its_source_ports() {
        let (w0, _) = FakeLink::new(&[]);
        let (plane, states) = plane(vec![w0]);
        let mut plane = plane.with_source_ports(Box::new(|| Some(1_000)));
        let s = udp("u1", free_udp_port());

        let events = plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::SourcePorts,
                os_error,
                ..
            }] => assert!(os_error.contains("1000 usable"), "{os_error}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(states.get("u1"), Some(BindState::Failed(_))));
        assert!(!plane.has_retryable_failure(), "retried on change only");
        assert_eq!(lock_caps(&plane.caps).memfds(), 0, "no region created");

        // A port range the node cannot read leaves the fds alone to
        // decide.
        let mut plane = plane.with_source_ports(Box::new(|| None));
        let events = plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert!(
            matches!(events.as_slice(), [PlaneEvent::Bound { .. }]),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn a_node_past_its_ceiling_rebinds_what_raises_nothing_and_refuses_raises() {
        let (w0, _) = FakeLink::new(&[]);
        let (plane, states) = plane(vec![w0]);
        let usable = Arc::new(std::sync::atomic::AtomicU64::new(
            DEFAULT_RANGE_USABLE_PORTS,
        ));
        let reading = Arc::clone(&usable);
        let mut plane = plane.with_source_ports(Box::new(move || {
            Some(reading.load(std::sync::atomic::Ordering::Relaxed))
        }));
        let mut streams = vec![udp("u1", free_udp_port()), udp("u2", free_udp_port())];
        plane
            .bind_desired(&streams, &[], STANDALONE, PASS, Trigger::Change)
            .await;
        assert!(matches!(states.get("u1"), Some(BindState::Bound { .. })));
        assert!(matches!(states.get("u2"), Some(BindState::Bound { .. })));

        // The range narrows under the two bound streams: 8,192 sessions
        // committed on 5,000 ports. Nothing is unbound.
        usable.store(5_000, std::sync::atomic::Ordering::Relaxed);
        let rebind = |streams: &mut Vec<Stream>, max_sessions: u32| {
            let moved = &mut streams[0];
            let port = free_udp_port();
            moved.port_first = port;
            moved.port_last = port;
            moved.udp.as_mut().unwrap().max_sessions = max_sessions;
        };

        // A move to another port at the same share raises nothing.
        rebind(&mut streams, 4096);
        plane.release_stale(&streams, STANDALONE, PASS).await;
        let events = plane
            .bind_desired(&streams, &[], STANDALONE, PASS, Trigger::Change)
            .await;
        assert!(
            matches!(events.as_slice(), [PlaneEvent::Bound { .. }]),
            "{events:?}"
        );

        // A move that also raises the share is checked, and refused.
        rebind(&mut streams, 4097);
        plane.release_stale(&streams, STANDALONE, PASS).await;
        let events = plane
            .bind_desired(&streams, &[], STANDALONE, PASS, Trigger::Change)
            .await;
        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::SourcePorts,
                ..
            }] => {}
            other => panic!("unexpected {other:?}"),
        }

        // Lowered back, the retry compares with what the node counted
        // for the stream's last binding, not with nothing.
        streams[0].udp.as_mut().unwrap().max_sessions = 2048;
        let events = plane
            .bind_desired(&streams, &[], STANDALONE, PASS, Trigger::Change)
            .await;
        assert!(
            matches!(events.as_slice(), [PlaneEvent::Bound { .. }]),
            "{events:?}"
        );

        // A stream the node never held is all new demand.
        streams.push(udp("u3", free_udp_port()));
        let events = plane
            .bind_desired(&streams, &[], STANDALONE, PASS, Trigger::Change)
            .await;
        match events.as_slice() {
            [PlaneEvent::BindFailed {
                kind: BindFailureKind::SourcePorts,
                ..
            }] => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_tcp_binding_declares_what_its_connections_hold() {
        let mut s = tcp("s1", 5432);
        s.max_connections = 100;
        let key = desired_bindings(std::slice::from_ref(&s), STANDALONE)
            .into_iter()
            .next()
            .expect("a desired binding");
        let demand = demand_of(&key, Some(&s));
        assert_eq!(
            demand,
            StreamDemand::of(&s),
            "the driver's demand is the one the API's write check builds"
        );
        assert_eq!(demand.held, lorica_stream::tcp::held_fds(&s));
        assert!(demand.held.is_some(), "a TCP stream declares its fds");
        assert_eq!(
            demand_of(&key, None).held,
            None,
            "a binding whose stream is gone declares nothing"
        );
    }
}
