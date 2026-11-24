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

//! The stream sockets a hot upgrade hands over (Story 12.2 D-j,
//! Story 12.11 D-e): what the outgoing plane hands out, and what the
//! incoming one adopts or closes.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use lorica_config::models::StreamProtocol;
use lorica_stream::BindKey;
use lorica_worker::stream_sockets::BoundPort;
use tracing::warn;

use super::{StreamPlane, WorkerLink};
use crate::startup::hot_upgrade::{StreamTcpFd, StreamUdpFd};

impl<L: WorkerLink> StreamPlane<L> {
    /// Adopt the TCP stream listeners a hot upgrade handed over (D-j).
    /// The next pass takes each one a desired binding matches instead of
    /// binding its port, and closes the rest.
    pub(crate) fn adopt_inherited(&mut self, listeners: Vec<(StreamTcpFd, OwnedFd)>) {
        for (entry, fd) in listeners {
            // The old generation's numbers name its own bindings; this
            // supervisor never reuses one.
            self.next_gen = self.next_gen.max(entry.bind_gen.saturating_add(1));
            self.inherited.push((entry.stream_id, entry.addr, fd));
        }
    }

    /// Adopt the UDP slot sockets a hot upgrade handed over (Story 12.11
    /// D-e). The next pass takes a binding's whole group, slot `k` going
    /// to worker `k`, when it has exactly one slot per worker on every
    /// port; otherwise it closes them and binds a fresh group.
    pub(crate) fn adopt_inherited_udp(&mut self, sockets: Vec<(StreamUdpFd, OwnedFd)>) {
        for (entry, fd) in sockets {
            self.next_gen = self.next_gen.max(entry.bind_gen.saturating_add(1));
            self.inherited_udp.push((entry, fd));
        }
    }

    /// The TCP listeners a hot upgrade hands to the next supervisor
    /// (D-j). The descriptors stay owned here.
    pub(crate) fn tcp_handoff_fds(&self) -> Vec<StreamTcpFd> {
        self.held
            .values()
            .filter(|b| b.key.protocol == StreamProtocol::Tcp)
            .flat_map(|b| {
                b.ports.iter().filter_map(move |port| {
                    port.sockets.first().map(|fd| StreamTcpFd {
                        stream_id: b.key.stream_id.clone(),
                        bind_gen: b.bind_gen,
                        addr: port.addr,
                        fd: fd.as_raw_fd(),
                    })
                })
            })
            .collect()
    }

    /// The UDP slot sockets a hot upgrade hands to the next supervisor
    /// (Story 12.11 D-e): every slot of every port of each held group,
    /// slot `k` being worker `k`'s. The descriptors stay owned here.
    pub(crate) fn udp_handoff_fds(&self) -> Vec<StreamUdpFd> {
        self.held
            .values()
            .filter(|b| b.key.protocol == StreamProtocol::Udp)
            .flat_map(|b| {
                b.ports.iter().flat_map(move |port| {
                    port.sockets
                        .iter()
                        .enumerate()
                        .map(move |(slot, fd)| StreamUdpFd {
                            stream_id: b.key.stream_id.clone(),
                            bind_gen: b.bind_gen,
                            slot: u32::try_from(slot).unwrap_or(u32::MAX),
                            addr: port.addr,
                            fd: fd.as_raw_fd(),
                        })
                })
            })
            .collect()
    }

    /// The inherited sockets of `key`, if they cover it: see
    /// [`Self::take_inherited_tcp`] and [`Self::take_inherited_udp`].
    pub(super) fn take_inherited(&mut self, key: &BindKey) -> Option<Vec<BoundPort>> {
        match key.protocol {
            StreamProtocol::Tcp => self.take_inherited_tcp(key),
            StreamProtocol::Udp => self.take_inherited_udp(key),
        }
    }

    /// The inherited UDP group of `key`, slot `k` of each port being
    /// worker `k`'s socket, if it has exactly one slot per worker on
    /// every port (Story 12.11 D-e). The sockets inherited for `key` are
    /// taken either way: a group that does not match is closed and the
    /// caller binds a fresh one, which then shares the port with the old
    /// generation's group until that one is gone.
    fn take_inherited_udp(&mut self, key: &BindKey) -> Option<Vec<BoundPort>> {
        let matches = |(entry, _): &(StreamUdpFd, OwnedFd)| {
            entry.stream_id == key.stream_id
                && entry.addr.ip() == key.listen_address
                && key.ports().contains(&entry.addr.port())
        };
        if !self.inherited_udp.iter().any(matches) {
            return None;
        }
        let (taken, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.inherited_udp)
            .into_iter()
            .partition(matches);
        self.inherited_udp = kept;
        let received = taken.len();
        let mut groups: BTreeMap<SocketAddr, BTreeMap<u32, OwnedFd>> = BTreeMap::new();
        for (entry, fd) in taken {
            groups.entry(entry.addr).or_default().insert(entry.slot, fd);
        }
        let slots = || 0..self.worker_count;
        let whole = groups.len() == key.ports().len()
            && groups.values().all(|g| g.keys().copied().eq(slots()))
            && received == groups.values().map(BTreeMap::len).sum::<usize>();
        if !whole {
            warn!(
                stream_id = %key.stream_id,
                received,
                ports = groups.len(),
                workers = self.worker_count,
                "inherited UDP group does not match this node's workers; closed, a fresh group is bound"
            );
            return None;
        }
        Some(
            groups
                .into_iter()
                .map(|(addr, group)| BoundPort {
                    addr,
                    sockets: group.into_values().collect(),
                })
                .collect(),
        )
    }

    /// The inherited listeners that cover exactly the ports of `key`, if
    /// every port has one.
    fn take_inherited_tcp(&mut self, key: &BindKey) -> Option<Vec<BoundPort>> {
        let matches = |(stream_id, addr, _): &(String, SocketAddr, OwnedFd)| {
            *stream_id == key.stream_id
                && addr.ip() == key.listen_address
                && key.ports().contains(&addr.port())
        };
        let ports: BTreeSet<u16> = self
            .inherited
            .iter()
            .filter(|e| matches(e))
            .map(|(_, addr, _)| addr.port())
            .collect();
        let covered = ports.len() == key.ports().len()
            && self.inherited.iter().filter(|e| matches(e)).count() == ports.len();
        if !covered {
            return None;
        }
        let (taken, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.inherited)
            .into_iter()
            .partition(matches);
        self.inherited = kept;
        let mut bound: Vec<BoundPort> = taken
            .into_iter()
            .map(|(_, addr, fd)| BoundPort {
                addr,
                sockets: vec![fd],
            })
            .collect();
        bound.sort_by_key(|p| p.addr.port());
        Some(bound)
    }
}

#[cfg(test)]
mod tests {
    use lorica_stream::BindState;

    use super::*;
    use crate::startup::stream_plane::test_support::{
        bindable, free_ports, free_udp_port, plane, seen, tcp, udp, FakeLink, Seen, PASS,
        STANDALONE,
    };
    use crate::startup::stream_plane::{PlaneEvent, Trigger};

    /// The device and inode of socket `fd`: one kernel socket whatever
    /// descriptor names it.
    fn socket_identity(fd: &OwnedFd) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let file = std::fs::File::from(fd.try_clone().unwrap());
        let meta = file.metadata().unwrap();
        (meta.dev(), meta.ino())
    }

    #[tokio::test]
    async fn a_udp_group_is_handed_over_and_adopted_slot_by_slot() {
        let port = free_udp_port();
        let s = udp("u1", port);
        let (mut old, _) = plane(vec![FakeLink::new(&[]).0, FakeLink::new(&[]).0]);
        old.bind_desired(
            std::slice::from_ref(&s),
            &[],
            STANDALONE,
            PASS,
            Trigger::Change,
        )
        .await;

        let mut handed = old.udp_handoff_fds();
        handed.sort_by_key(|h| h.slot);
        assert_eq!(
            handed.iter().map(|h| h.slot).collect::<Vec<_>>(),
            vec![0, 1],
            "every slot of the group"
        );
        assert!(handed
            .iter()
            .all(|h| h.stream_id == "u1" && h.addr.port() == port));
        // What the new supervisor receives: its own descriptors of the
        // same sockets.
        let received: Vec<(StreamUdpFd, OwnedFd)> = handed
            .iter()
            .map(|h| {
                // SAFETY: the old plane owns `h.fd` and outlives this
                // borrow; the clone is a new descriptor of its own.
                let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(h.fd) };
                (h.clone(), borrowed.try_clone_to_owned().unwrap())
            })
            .collect();
        let identities: Vec<(u64, u64)> =
            received.iter().map(|(_, fd)| socket_identity(fd)).collect();

        let (mut new, states) = plane(vec![FakeLink::new(&[]).0, FakeLink::new(&[]).0]);
        new.adopt_inherited_udp(received);
        let events = new
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        let bind_gen = handed[0].bind_gen + 1;
        assert!(
            matches!(events.as_slice(), [PlaneEvent::Bound { bind_gen: g, .. }] if *g == bind_gen),
            "{events:?}"
        );
        assert!(matches!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                ..
            })
        ));
        for (worker, identity) in identities.iter().enumerate() {
            let link = new.workers[&u32::try_from(worker).unwrap()]
                .link
                .as_ref()
                .unwrap();
            let held = link.held("u1", bind_gen);
            assert_eq!(held.len(), 1);
            assert_eq!(
                socket_identity(&held[0]),
                *identity,
                "worker {worker} serves the old generation's slot {worker}"
            );
        }
    }

    #[tokio::test]
    async fn a_udp_group_that_does_not_match_the_workers_is_closed_and_rebound() {
        let port = free_udp_port();
        let s = udp("u1", port);
        let (mut old, _) = plane(vec![FakeLink::new(&[]).0]);
        old.bind_desired(
            std::slice::from_ref(&s),
            &[],
            STANDALONE,
            PASS,
            Trigger::Change,
        )
        .await;
        let handed = old.udp_handoff_fds();
        assert_eq!(handed.len(), 1, "a one-worker group");
        let received: Vec<(StreamUdpFd, OwnedFd)> = handed
            .iter()
            .map(|h| {
                // SAFETY: as in the adoption test above.
                let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(h.fd) };
                (h.clone(), borrowed.try_clone_to_owned().unwrap())
            })
            .collect();
        let inherited = socket_identity(&received[0].1);

        // Two workers on the new side: the group cannot be kept whole.
        let (mut new, states) = plane(vec![FakeLink::new(&[]).0, FakeLink::new(&[]).0]);
        new.adopt_inherited_udp(received);
        new.bind_desired(
            std::slice::from_ref(&s),
            &[],
            STANDALONE,
            PASS,
            Trigger::Change,
        )
        .await;

        assert!(matches!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                ..
            })
        ));
        assert!(
            new.inherited_udp.is_empty(),
            "nothing inherited is left open"
        );
        let bind_gen = handed[0].bind_gen + 1;
        for worker in 0..2u32 {
            let held = new.workers[&worker]
                .link
                .as_ref()
                .unwrap()
                .held("u1", bind_gen);
            assert_eq!(held.len(), 1);
            assert_ne!(socket_identity(&held[0]), inherited, "a fresh group");
        }
    }

    #[tokio::test]
    async fn an_inherited_listener_is_adopted_and_an_unwanted_one_closed() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(2);
        let (wanted, unwanted) = (first, first + 1);
        // No SO_REUSEPORT: binding the port again would fail, so a bound
        // state proves the inherited socket was taken.
        let inherited = |id: &str, port: u16| {
            let addr: SocketAddr = ([127, 0, 0, 1], port).into();
            let fd = lorica_worker::stream_sockets::bind_tcp_stream_listener(addr).unwrap();
            (
                StreamTcpFd {
                    stream_id: id.into(),
                    bind_gen: 41,
                    addr,
                    fd: fd.as_raw_fd(),
                },
                fd,
            )
        };
        plane.adopt_inherited(vec![inherited("s1", wanted), inherited("gone", unwanted)]);
        let s = tcp("s1", wanted);

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
            matches!(events.as_slice(), [PlaneEvent::Bound { bind_gen: 42, .. }]),
            "{events:?}"
        );
        assert!(matches!(states.get("s1"), Some(BindState::Bound { .. })));
        assert!(matches!(
            seen(&seen0).as_slice(),
            [Seen::Caps { .. }, Seen::Attach { .. }, ..]
        ));
        assert!(!bindable(wanted));
        assert!(
            bindable(unwanted),
            "an inherited socket no stream wants is closed"
        );
    }
}
