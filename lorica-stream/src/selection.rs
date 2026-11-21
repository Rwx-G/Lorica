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

//! Backend selection as both engines run it (Story 12.3 D-e, D-f, D-m;
//! Story 12.5 E9: UDP reuses TCP's, it does not copy it): which links
//! are candidates, the backup rule, the selector's pick, the local check
//! of the chosen backend's addresses with its exclusion transition, and
//! the rotation among those addresses and the stream's source addresses.
//!
//! What stays per protocol is what really differs: TCP resolves a name
//! within the connect deadline and filters links by the matched rule,
//! UDP reads the resolver cache only; TCP binds one source address, UDP
//! tries them in order.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::{backend_address_port, HealthStatus, LifecycleState, Stream};
use tracing::warn;

use crate::counters::{StreamCounters, StreamStats};
use crate::local::{BoundPorts, LocalRefusal, NodeLocality};
use crate::resolver::{LocalExclusions, ResolverCache};
use crate::seams::{BackendSelector, Candidate, SelectionRequest};
use crate::table::{LinkedBackend, StreamTable};

/// One candidate of a selection: a link, the addresses its backend has
/// now, and the port a connection or session to it uses.
pub(crate) struct Eligible<'a> {
    pub(crate) link: &'a LinkedBackend,
    pub(crate) addresses: Arc<[IpAddr]>,
    pub(crate) port: u16,
}

impl<'a> Eligible<'a> {
    /// `link` at `addresses`, on its backend's own port or, for a
    /// portless backend of a range stream, on `listen_port`.
    pub(crate) fn new(
        link: &'a LinkedBackend,
        addresses: Arc<[IpAddr]>,
        listen_port: u16,
    ) -> Eligible<'a> {
        let port = backend_address_port(&link.backend.address)
            .ok()
            .flatten()
            .unwrap_or(listen_port);
        Eligible {
            link,
            addresses,
            port,
        }
    }
}

/// Whether `link` may be a candidate: not passed over yet in this
/// connection or session, not down, in the normal lifecycle.
pub(crate) fn is_candidate(link: &LinkedBackend, excluded: &HashSet<String>) -> bool {
    let backend = &link.backend;
    !excluded.contains(&backend.id)
        && backend.health_status != HealthStatus::Down
        && backend.lifecycle_state == LifecycleState::Normal
}

/// Keep the primaries, or the backups when no primary is left (12.3 D-f).
pub(crate) fn primaries_or_backups(eligible: &mut Vec<Eligible<'_>>) {
    let has_primary = eligible.iter().any(|e| !e.link.backup);
    eligible.retain(|e| e.link.backup != has_primary);
}

/// The selector's pick among `eligible`, which is not empty. The ring
/// address of a candidate is its first address on its port.
pub(crate) fn choose(
    selector: &dyn BackendSelector,
    stream: &Stream,
    eligible: &[Eligible<'_>],
    client: IpAddr,
    accepted_at: std::time::Instant,
) -> usize {
    let candidates: Vec<Candidate<'_>> = eligible
        .iter()
        .map(|e| Candidate {
            backend: &e.link.backend,
            ring_address: SocketAddr::new(e.addresses[0], e.port),
        })
        .collect();
    selector
        .select(&SelectionRequest {
            stream,
            candidates: &candidates,
            client,
            accepted_at,
        })
        .min(candidates.len() - 1)
}

/// Rotating counters: per stream for source addresses, one for the
/// address choice within a backend.
#[derive(Debug, Default)]
pub(crate) struct Rotation {
    sources: Mutex<HashMap<String, usize>>,
    addresses: AtomicUsize,
}

impl Rotation {
    fn next_source(&self, stream_id: &str) -> usize {
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        // The stream's id is copied on its first turn only.
        if let Some(n) = sources.get_mut(stream_id) {
            let current = *n;
            *n = n.wrapping_add(1);
            return current;
        }
        sources.insert(stream_id.to_string(), 1);
        0
    }

    fn next_address(&self) -> usize {
        self.addresses.fetch_add(1, Ordering::Relaxed)
    }

    /// Forget the source turns of the streams `table` no longer holds.
    pub(crate) fn retain(&self, table: &StreamTable) {
        self.sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|id, _| table.stream(id).is_some());
    }

    /// The first of `destinations` the stream has a source address of
    /// the same family for, and those source addresses starting from the
    /// stream's next in turn (12.3 D-f). Empty sources when the stream
    /// sets none; `None` when no destination has a source of its family.
    pub(crate) fn sources(
        &self,
        stream: &Stream,
        destinations: &[SocketAddr],
    ) -> Option<(SocketAddr, Vec<IpAddr>)> {
        if stream.source_addresses.is_empty() {
            return destinations.first().map(|d| (*d, Vec::new()));
        }
        destinations.iter().find_map(|destination| {
            let mut family: Vec<IpAddr> = stream
                .source_addresses
                .iter()
                .copied()
                .filter(|s| s.is_ipv4() == destination.is_ipv4())
                .collect();
            if family.is_empty() {
                return None;
            }
            let start = self.next_source(&stream.id) % family.len();
            family.rotate_left(start);
            Some((*destination, family))
        })
    }
}

/// What the local check of a chosen backend reads (12.3 D-m): the
/// node's interfaces and reserved ports, the process's exclusion
/// register and counters, and the address rotation.
pub(crate) struct LocalCheck<'a> {
    pub(crate) resolver: &'a ResolverCache,
    pub(crate) reserved: Option<&'a ReservedPorts>,
    pub(crate) exclusions: &'a LocalExclusions,
    pub(crate) counters: &'a StreamCounters,
    pub(crate) rotation: &'a Rotation,
}

impl LocalCheck<'_> {
    /// The destinations of `chosen` the local check lets through, in
    /// rotating order; `None` when it refuses them all, which excludes
    /// the backend from this connection or session and is reported once
    /// per transition (IV4).
    pub(crate) fn destinations(
        &self,
        stream: &Stream,
        bound: &BoundPorts,
        stats: &StreamStats,
        chosen: &Eligible<'_>,
    ) -> Option<Vec<SocketAddr>> {
        let interfaces = self.resolver.interfaces();
        let node = NodeLocality {
            interfaces: &interfaces,
            reserved: self.reserved,
            bound,
        };
        let backend = &chosen.link.backend;
        let count = chosen.addresses.len();
        let offset = self.rotation.next_address();
        let mut refusal: Option<LocalRefusal> = None;
        let allowed: Vec<SocketAddr> = (0..count)
            .map(|i| SocketAddr::new(chosen.addresses[(offset + i) % count], chosen.port))
            .filter(
                |destination| match node.check(*destination, stream.allow_local_backend) {
                    Ok(()) => true,
                    Err(r) => {
                        refusal = Some(r);
                        false
                    }
                },
            )
            .collect();
        if allowed.is_empty() {
            stats.local_destination_refused();
            if self.exclusions.set(&stream.id, &backend.id, true) {
                self.counters.backend(&backend.id).dns_local_excluded();
                warn!(stream_id = %stream.id, stream = %stream.name,
                      backend_id = %backend.id, backend = %backend.name,
                      addresses = ?chosen.addresses,
                      rule = refusal.map_or("", |r| r.as_str()),
                      "stream backend resolves to a refused local address: excluded from the stream");
            }
            return None;
        }
        self.exclusions.set(&stream.id, &backend.id, false);
        Some(allowed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::StreamProtocol;

    fn stream(sources: &[&str]) -> Stream {
        let mut s = Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().unwrap(),
            5432,
            5432,
            Utc::now(),
        );
        s.source_addresses = sources.iter().map(|a| a.parse().unwrap()).collect();
        s
    }

    fn at(address: &str) -> SocketAddr {
        address.parse().unwrap()
    }

    #[test]
    fn sources_of_the_destination_family_rotate_per_stream() {
        let rotation = Rotation::default();
        let s = stream(&["192.0.2.1", "2001:db8::1", "192.0.2.2", "192.0.2.3"]);
        let v4 = [at("198.51.100.1:5432")];
        let firsts: Vec<IpAddr> = (0..4)
            .map(|_| rotation.sources(&s, &v4).unwrap().1[0])
            .collect();
        let ip = |a: &str| a.parse::<IpAddr>().unwrap();
        assert_eq!(
            firsts,
            [
                ip("192.0.2.1"),
                ip("192.0.2.2"),
                ip("192.0.2.3"),
                ip("192.0.2.1")
            ]
        );
        let (_, ordered) = rotation.sources(&s, &v4).unwrap();
        assert_eq!(
            ordered,
            [ip("192.0.2.2"), ip("192.0.2.3"), ip("192.0.2.1")],
            "the bind tries the others in turn after the first"
        );
    }

    #[test]
    fn a_destination_without_a_source_of_its_family_is_passed_over() {
        let rotation = Rotation::default();
        let s = stream(&["2001:db8::1"]);
        assert_eq!(rotation.sources(&s, &[at("198.51.100.1:5432")]), None);
        let mixed = [at("198.51.100.1:5432"), at("[2001:db8::9]:5432")];
        assert_eq!(
            rotation.sources(&s, &mixed),
            Some((mixed[1], vec!["2001:db8::1".parse().unwrap()]))
        );
        let unset = stream(&[]);
        assert_eq!(
            rotation.sources(&unset, &mixed),
            Some((mixed[0], Vec::new()))
        );
    }
}
