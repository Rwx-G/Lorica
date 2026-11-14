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

//! The pure reconcile diff of Story 12.2 D-d: which bindings to release
//! and which to bind, given the streams the store holds, this node's role
//! and the bindings the supervisor holds.
//!
//! A binding is keyed by its [`BindKey`] (stream id, protocol, listen
//! address, port range). Any other field change (name, group, selector
//! still matching, backends) is not a rebind: the workers pick it up on
//! `refresh`, and established connections keep the snapshot they were
//! accepted with.
//!
//! **UDP overlaps are refused here, not by the kernel.** A same-user
//! `SO_REUSEPORT` UDP socket joins or shadows an existing group on an
//! overlapping address without error (verified in Lot A, the test
//! `udp_reuseport_groups_of_one_user_are_not_refused_by_the_kernel` in
//! `lorica-worker`). So a UDP binding that overlaps, by protocol, port
//! and [`listen_addresses_conflict`], one this node keeps or one this
//! pass already chose to bind is never asked for: it comes back in
//! [`Actions::refused`]. TCP needs no such check: without `SO_REUSEPORT`
//! the kernel refuses an overlapping listener with `EADDRINUSE`, and that
//! OS error is what the operator sees.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;

use lorica_config::listen_ports::listen_addresses_conflict;
use lorica_config::models::{
    binds_here, binds_here_when_enabled, NodeRole, Stream, StreamProtocol,
};

use crate::state::BindFailureKind;

/// What makes a binding: changing any of it is a rebind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindKey {
    /// The stream's id.
    pub stream_id: String,
    /// TCP or UDP.
    pub protocol: StreamProtocol,
    /// The one address the stream listens on.
    pub listen_address: IpAddr,
    /// First port of the range.
    pub port_first: u16,
    /// Last port of the range, `port_first` for a single port.
    pub port_last: u16,
}

impl BindKey {
    /// The bind key of `stream`.
    pub fn of(stream: &Stream) -> Self {
        BindKey {
            stream_id: stream.id.clone(),
            protocol: stream.protocol,
            listen_address: stream.listen_address,
            port_first: stream.port_first,
            port_last: stream.port_last,
        }
    }

    /// The ports of the binding.
    pub fn ports(&self) -> RangeInclusive<u16> {
        self.port_first..=self.port_last
    }

    /// The first port on which `self` and `other` would hold the same
    /// traffic: same protocol, intersecting port ranges and conflicting
    /// listen addresses.
    pub fn overlap_port(&self, other: &BindKey) -> Option<u16> {
        if self.protocol != other.protocol
            || !listen_addresses_conflict(self.listen_address, other.listen_address)
        {
            return None;
        }
        let first = self.port_first.max(other.port_first);
        let last = self.port_last.min(other.port_last);
        (first <= last).then_some(first)
    }
}

/// A binding the supervisor holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundBinding {
    /// What it was bound for.
    pub key: BindKey,
    /// The supervisor's generation number of the binding.
    pub bind_gen: u64,
}

/// Why a binding is released, the cause the `stream.release` audit row
/// carries (D-h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseCause {
    /// The stream is gone from the store.
    Deleted,
    /// The stream is disabled.
    Disabled,
    /// The stream's bind key changed; a new binding replaces this one.
    Rebind,
    /// The stream no longer targets this node.
    NodeDeselected,
    /// The process is stopping (the stop path, never [`diff`]).
    Shutdown,
}

impl ReleaseCause {
    /// The audit spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseCause::Deleted => "deleted",
            ReleaseCause::Disabled => "disabled",
            ReleaseCause::Rebind => "rebind",
            ReleaseCause::NodeDeselected => "node_deselected",
            ReleaseCause::Shutdown => "shutdown",
        }
    }
}

/// A binding to release, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detach {
    /// The binding.
    pub binding: BoundBinding,
    /// Why.
    pub cause: ReleaseCause,
}

/// A UDP binding refused because it overlaps another UDP binding of this
/// node, which the kernel would not refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpOverlap {
    /// The refused binding.
    pub key: BindKey,
    /// The stream whose binding it overlaps.
    pub other_stream_id: String,
    /// The first port both would hold.
    pub port: u16,
}

impl UdpOverlap {
    /// How the refusal is reported on the stream: as the kernel reports
    /// the same overlap for TCP, so the 10 s retry of `address_in_use`
    /// binds it once the other stream lets go.
    pub fn kind(&self) -> BindFailureKind {
        BindFailureKind::AddressInUse
    }
}

impl std::fmt::Display for UdpOverlap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP {} port {} overlaps the binding of stream {} on this node",
            self.key.listen_address, self.port, self.other_stream_id
        )
    }
}

/// What one reconcile pass does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Actions {
    /// Bindings to release, before the configuration commit reaches the
    /// workers.
    pub detach: Vec<Detach>,
    /// Bindings to bind and attach, after it.
    pub bind: Vec<BindKey>,
    /// Desired UDP bindings not asked for, see the module doc.
    pub refused: Vec<UdpOverlap>,
}

impl Actions {
    /// Whether the pass changes nothing.
    pub fn is_empty(&self) -> bool {
        self.detach.is_empty() && self.bind.is_empty() && self.refused.is_empty()
    }
}

/// The bindings a node in `role` wants: every stream it binds by
/// [`binds_here`], in stream id order.
pub fn desired_bindings(streams: &[Stream], role: NodeRole<'_>) -> Vec<BindKey> {
    let mut keys: Vec<BindKey> = streams
        .iter()
        .filter(|s| binds_here(s, role))
        .map(BindKey::of)
        .collect();
    keys.sort();
    keys.dedup_by(|a, b| a.stream_id == b.stream_id);
    keys
}

fn release_cause(stream: Option<&Stream>, role: NodeRole<'_>) -> ReleaseCause {
    match stream {
        None => ReleaseCause::Deleted,
        Some(s) if !s.enabled => ReleaseCause::Disabled,
        Some(s) if !binds_here_when_enabled(s, role) => ReleaseCause::NodeDeselected,
        Some(_) => ReleaseCause::Rebind,
    }
}

/// Diff the streams a node in `role` binds against the bindings it holds.
///
/// A held binding whose stream still wants the same [`BindKey`] is kept.
/// Every other held binding is detached with its [`ReleaseCause`]. Every
/// wanted key not kept is bound, in stream id order, except a UDP one
/// that overlaps a kept UDP binding or one bound earlier in this pass,
/// which is refused. Bindings being detached do not count: their ports
/// are free once the pass applies.
pub fn diff(streams: &[Stream], role: NodeRole<'_>, bound: &[BoundBinding]) -> Actions {
    let by_id: BTreeMap<&str, &Stream> = streams.iter().map(|s| (s.id.as_str(), s)).collect();
    let desired: BTreeMap<String, BindKey> = desired_bindings(streams, role)
        .into_iter()
        .map(|k| (k.stream_id.clone(), k))
        .collect();

    let mut held: Vec<&BoundBinding> = bound.iter().collect();
    held.sort_by(|a, b| a.key.cmp(&b.key).then(a.bind_gen.cmp(&b.bind_gen)));

    let mut actions = Actions::default();
    let mut kept: Vec<&BindKey> = Vec::new();
    let mut kept_ids: BTreeSet<&str> = BTreeSet::new();
    for b in held {
        let id = b.key.stream_id.as_str();
        if desired.get(id) == Some(&b.key) && kept_ids.insert(id) {
            kept.push(&b.key);
            continue;
        }
        actions.detach.push(Detach {
            binding: b.clone(),
            cause: release_cause(by_id.get(id).copied(), role),
        });
    }

    let mut claimed: Vec<BindKey> = kept
        .iter()
        .filter(|k| k.protocol == StreamProtocol::Udp)
        .map(|k| (*k).clone())
        .collect();
    for (id, key) in desired {
        if kept_ids.contains(id.as_str()) {
            continue;
        }
        if key.protocol == StreamProtocol::Udp {
            if let Some((other, port)) = claimed
                .iter()
                .find_map(|c| key.overlap_port(c).map(|p| (c, p)))
            {
                actions.refused.push(UdpOverlap {
                    other_stream_id: other.stream_id.clone(),
                    port,
                    key,
                });
                continue;
            }
            claimed.push(key.clone());
        }
        actions.bind.push(key);
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn stream(id: &str, protocol: StreamProtocol, addr: &str, first: u16, last: u16) -> Stream {
        let at: DateTime<Utc> = DateTime::parse_from_rfc3339("2026-11-14T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        Stream {
            id: id.into(),
            name: id.into(),
            group_name: String::new(),
            protocol,
            enabled: true,
            listen_address: addr.parse().unwrap(),
            port_first: first,
            port_last: last,
            node_selector: Vec::new(),
            created_at: at,
            updated_at: at,
        }
    }

    fn tcp(id: &str, port: u16) -> Stream {
        stream(id, StreamProtocol::Tcp, "0.0.0.0", port, port)
    }

    fn udp(id: &str, addr: &str, first: u16, last: u16) -> Stream {
        stream(id, StreamProtocol::Udp, addr, first, last)
    }

    fn held(s: &Stream, bind_gen: u64) -> BoundBinding {
        BoundBinding {
            key: BindKey::of(s),
            bind_gen,
        }
    }

    const STANDALONE: NodeRole<'static> = NodeRole::Standalone;

    #[test]
    fn a_new_stream_is_bound() {
        let s = tcp("a", 5432);
        let actions = diff(std::slice::from_ref(&s), STANDALONE, &[]);
        assert_eq!(actions.bind, vec![BindKey::of(&s)]);
        assert!(actions.detach.is_empty() && actions.refused.is_empty());
    }

    #[test]
    fn an_edit_outside_the_bind_key_is_no_action() {
        let before = tcp("a", 5432);
        let mut after = before.clone();
        after.name = "renamed".into();
        after.group_name = "db".into();
        after.updated_at = Utc::now();
        // Backends live in `stream_backends`, not on the stream: a
        // backend-only edit leaves every stream row as it was.
        assert!(diff(
            std::slice::from_ref(&before),
            STANDALONE,
            &[held(&before, 1)]
        )
        .is_empty());
        assert!(diff(&[after], STANDALONE, &[held(&before, 1)]).is_empty());
    }

    #[test]
    fn a_port_change_is_detach_then_bind() {
        let before = tcp("a", 5432);
        let mut after = before.clone();
        after.port_first = 5433;
        after.port_last = 5433;
        let actions = diff(
            std::slice::from_ref(&after),
            STANDALONE,
            &[held(&before, 7)],
        );
        assert_eq!(
            actions.detach,
            vec![Detach {
                binding: held(&before, 7),
                cause: ReleaseCause::Rebind
            }]
        );
        assert_eq!(actions.bind, vec![BindKey::of(&after)]);
    }

    #[test]
    fn an_address_or_protocol_change_is_a_rebind() {
        let before = tcp("a", 53);
        let mut moved = before.clone();
        moved.listen_address = "127.0.0.1".parse().unwrap();
        let mut udp_now = before.clone();
        udp_now.protocol = StreamProtocol::Udp;
        for after in [moved, udp_now] {
            let actions = diff(
                std::slice::from_ref(&after),
                STANDALONE,
                &[held(&before, 1)],
            );
            assert_eq!(actions.detach[0].cause, ReleaseCause::Rebind);
            assert_eq!(actions.bind, vec![BindKey::of(&after)]);
        }
    }

    #[test]
    fn disabled_deleted_and_deselected_are_detached_with_their_cause() {
        let s = tcp("a", 5432);
        let mut disabled = s.clone();
        disabled.enabled = false;
        let actions = diff(&[disabled], STANDALONE, &[held(&s, 1)]);
        assert_eq!(actions.detach[0].cause, ReleaseCause::Disabled);
        assert!(actions.bind.is_empty());

        let actions = diff(&[], STANDALONE, &[held(&s, 1)]);
        assert_eq!(actions.detach[0].cause, ReleaseCause::Deleted);

        let mut pinned = s.clone();
        pinned.node_selector = vec!["edge02".into()];
        let follower = NodeRole::Follower {
            node_name: "edge01",
        };
        let actions = diff(std::slice::from_ref(&pinned), follower, &[held(&s, 1)]);
        assert_eq!(actions.detach[0].cause, ReleaseCause::NodeDeselected);
        // The control plane binds only fleet-wide streams (12.1 D-8).
        let actions = diff(&[pinned], NodeRole::ControlPlane, &[held(&s, 1)]);
        assert_eq!(actions.detach[0].cause, ReleaseCause::NodeDeselected);
    }

    #[test]
    fn a_duplicate_held_binding_is_released() {
        let s = tcp("a", 5432);
        let actions = diff(
            std::slice::from_ref(&s),
            STANDALONE,
            &[held(&s, 1), held(&s, 2)],
        );
        assert_eq!(actions.detach.len(), 1);
        assert_eq!(actions.detach[0].binding.bind_gen, 2);
        assert!(actions.bind.is_empty());
    }

    #[test]
    fn udp_overlapping_a_kept_dual_stack_group_is_refused() {
        let wildcard6 = udp("a", "::", 53, 53);
        for addr in ["0.0.0.0", "127.0.0.1", "::", "::1"] {
            let other = udp("b", addr, 53, 53);
            let actions = diff(
                &[wildcard6.clone(), other.clone()],
                STANDALONE,
                &[held(&wildcard6, 1)],
            );
            assert!(actions.bind.is_empty(), "{addr} was asked for");
            assert_eq!(
                actions.refused,
                vec![UdpOverlap {
                    key: BindKey::of(&other),
                    other_stream_id: "a".into(),
                    port: 53,
                }],
                "{addr}"
            );
            assert_eq!(actions.refused[0].kind(), BindFailureKind::AddressInUse);
        }
    }

    #[test]
    fn udp_overlap_follows_the_address_rule_and_the_port_intersection() {
        let v4_any = udp("a", "0.0.0.0", 1000, 1010);
        let cases = [
            (udp("b", "127.0.0.1", 1005, 1005), Some(1005)),
            (udp("b", "127.0.0.1", 990, 1000), Some(1000)),
            (udp("b", "127.0.0.1", 1011, 1020), None),
            // A specific IPv6 literal binds `IPV6_V6ONLY` on: no overlap
            // with an IPv4 group.
            (udp("b", "::1", 1000, 1010), None),
            // TCP is the kernel's to refuse.
            (
                stream("b", StreamProtocol::Tcp, "0.0.0.0", 1000, 1000),
                None,
            ),
        ];
        for (other, overlap) in cases {
            let actions = diff(
                &[v4_any.clone(), other.clone()],
                STANDALONE,
                &[held(&v4_any, 1)],
            );
            match overlap {
                Some(port) => {
                    assert_eq!(actions.refused.len(), 1, "{other:?}");
                    assert_eq!(actions.refused[0].port, port);
                    assert!(actions.bind.is_empty());
                }
                None => {
                    assert!(actions.refused.is_empty(), "{other:?}");
                    assert_eq!(actions.bind, vec![BindKey::of(&other)]);
                }
            }
        }
    }

    #[test]
    fn two_new_overlapping_udp_bindings_bind_the_first_in_id_order() {
        let a = udp("a", "127.0.0.1", 53, 53);
        let b = udp("b", "0.0.0.0", 53, 53);
        let actions = diff(&[b.clone(), a.clone()], STANDALONE, &[]);
        assert_eq!(actions.bind, vec![BindKey::of(&a)]);
        assert_eq!(actions.refused.len(), 1);
        assert_eq!(actions.refused[0].key, BindKey::of(&b));
        assert_eq!(actions.refused[0].other_stream_id, "a");
        // Stable across passes while `a` fails to bind and stays desired.
        assert_eq!(diff(&[b, a], STANDALONE, &[]), actions);
    }

    #[test]
    fn a_binding_released_in_the_same_pass_frees_its_ports() {
        let old = udp("a", "0.0.0.0", 53, 53);
        let mut moved = old.clone();
        moved.port_first = 54;
        moved.port_last = 54;
        let newcomer = udp("b", "127.0.0.1", 53, 53);
        let actions = diff(
            &[moved.clone(), newcomer.clone()],
            STANDALONE,
            &[held(&old, 1)],
        );
        assert_eq!(actions.detach.len(), 1);
        assert_eq!(
            actions.bind,
            vec![BindKey::of(&moved), BindKey::of(&newcomer)]
        );
        assert!(actions.refused.is_empty());
    }

    #[test]
    fn a_kept_binding_wins_over_a_newcomer_whatever_the_id_order() {
        let kept = udp("z", "0.0.0.0", 53, 53);
        let newcomer = udp("a", "0.0.0.0", 53, 53);
        let actions = diff(
            &[kept.clone(), newcomer.clone()],
            STANDALONE,
            &[held(&kept, 3)],
        );
        assert!(actions.detach.is_empty());
        assert!(actions.bind.is_empty());
        assert_eq!(actions.refused[0].key, BindKey::of(&newcomer));
        assert_eq!(actions.refused[0].other_stream_id, "z");
    }
}
