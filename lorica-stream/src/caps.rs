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

//! The stream-caps regions of UDP streams on both sides of the control
//! channel (Story 12.5 D-d).
//!
//! - [`NodeCapsRegions`], in the supervisor (or the single-process
//!   driver): one region per UDP stream on the node, created from its
//!   `udp.max_sessions` and the worker count, replaced with the next
//!   `caps_gen` when a size change moves the table sizes, kept while a
//!   retired region still counts sessions, and the one place a dead
//!   worker's sessions are released before its respawn replay.
//! - [`CapsRegistry`], in a worker: what the `caps` messages handed it,
//!   by stream id, which the UDP engine reads at each session creation.
//!
//! One region per stream, not per binding, so caps stay exact across a
//! rebind's drain. A session keeps the region it was counted in through
//! its permit, so replacing a region never moves a live session.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::OwnedFd;
use std::sync::{Arc, PoisonError, RwLock};

use lorica_shmem::{layout_for, StreamCapsError, StreamCapsRegion, WorkerCaps};
use lorica_worker::stream_ctl::StreamCtlMsg;

/// A worker's view of one UDP stream's regions: the current one, through
/// which it admits new sessions under its slot, and the retired ones
/// still counting sessions.
#[derive(Debug, Clone)]
pub struct StreamCaps {
    current: WorkerCaps,
    retired: Vec<Arc<StreamCapsRegion>>,
}

impl StreamCaps {
    /// The region new sessions are admitted in, under this worker's slot.
    pub fn current(&self) -> &WorkerCaps {
        &self.current
    }

    /// Sessions the stream still holds on the node in its retired
    /// regions.
    pub fn retired_sessions(&self) -> u64 {
        self.retired
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.total()))
    }

    /// The stream cap the current region admits against: `max_sessions`
    /// less what the retired regions still count, so the stream's total
    /// across its regions stays exact while one drains.
    pub fn stream_cap_left(&self, max_sessions: u64) -> u64 {
        max_sessions.saturating_sub(self.retired_sessions())
    }
}

/// A worker's regions by stream id, filled by the `caps` messages the
/// stream runtime adopts. Cloning shares it.
#[derive(Debug, Clone, Default)]
pub struct CapsRegistry(Arc<RwLock<HashMap<String, StreamCaps>>>);

impl CapsRegistry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Make `caps` the current region of `stream_id`. The region it
    /// replaces is kept as retired while it counts sessions; one of the
    /// same `caps_gen` (a replay) is simply replaced.
    pub fn adopt(&self, stream_id: &str, caps: WorkerCaps) {
        let caps_gen = caps.region().caps_gen();
        let mut streams = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let entry = match streams.remove(stream_id) {
            None => StreamCaps {
                current: caps,
                retired: Vec::new(),
            },
            Some(previous) => {
                let mut retired = previous.retired;
                if previous.current.region().caps_gen() != caps_gen {
                    retired.push(Arc::clone(previous.current.region()));
                }
                retired.retain(|r| r.caps_gen() != caps_gen && r.total() > 0);
                StreamCaps {
                    current: caps,
                    retired,
                }
            }
        };
        streams.insert(stream_id.to_string(), entry);
    }

    /// The regions of `stream_id`, `None` until its first `caps`.
    pub fn get(&self, stream_id: &str) -> Option<StreamCaps> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(stream_id)
            .cloned()
    }

    /// Forget the streams `keep` refuses (no longer in the table), and
    /// every retired region that counts no session any more. Sessions
    /// still hold their own region through their permits.
    pub fn retain(&self, mut keep: impl FnMut(&str) -> bool) {
        let mut streams = self.0.write().unwrap_or_else(PoisonError::into_inner);
        streams.retain(|id, caps| {
            caps.retired.retain(|r| r.total() > 0);
            keep(id)
        });
    }

    /// Streams with a region.
    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Whether no stream has a region.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One UDP stream's regions in the supervisor.
#[derive(Debug)]
struct NodeStreamCaps {
    current: Arc<StreamCapsRegion>,
    /// The current region's memfd, kept to send it again: to a respawned
    /// worker, and to the first `attach` of a later binding. One per UDP
    /// stream, which the budget counts in the supervisor's fds.
    fd: OwnedFd,
    retired: Vec<Arc<StreamCapsRegion>>,
}

/// The supervisor's regions, one per UDP stream on the node.
#[derive(Debug)]
pub struct NodeCapsRegions {
    workers: u32,
    streams: BTreeMap<String, NodeStreamCaps>,
    /// Regions of streams no longer on the node, by stream, kept mapped
    /// while they count sessions so a dead worker's can still be
    /// released.
    orphans: BTreeMap<String, Vec<Arc<StreamCapsRegion>>>,
}

impl NodeCapsRegions {
    /// No region yet, on a node of `workers` worker slots (1 in
    /// single-process mode).
    pub fn new(workers: u32) -> Self {
        NodeCapsRegions {
            workers,
            streams: BTreeMap::new(),
            orphans: BTreeMap::new(),
        }
    }

    /// Give `stream_id` a region sized for `max_sessions`. Creates the
    /// first one, or a replacement with the next `caps_gen` when the
    /// table sizes move (the old one then counts its sessions down as
    /// retired); a change within the same sizes needs nothing, since the
    /// limits are read from the stream at each admission. Returns the
    /// `caps_gen` to send to every worker, `None` when nothing changed.
    ///
    /// A stream that comes back while a region [`NodeCapsRegions::retire`]
    /// kept still counts sessions (disabled then enabled within its
    /// drain) continues that region's `caps_gen` and counts it as
    /// retired, so a worker adopts the new region beside the old one
    /// rather than in its place, and the stream's total stays exact.
    ///
    /// # Errors
    ///
    /// The region's [`StreamCapsError`]; the stream keeps the region it
    /// had.
    pub fn ensure(
        &mut self,
        stream_id: &str,
        max_sessions: u64,
    ) -> Result<Option<u64>, StreamCapsError> {
        let caps_gen = match self.streams.get(stream_id) {
            None => self
                .orphans
                .get(stream_id)
                .and_then(|regions| regions.iter().map(|r| r.caps_gen()).max())
                .map_or(1, |last| last + 1),
            Some(held) => {
                let wanted = layout_for(max_sessions, self.workers)?;
                let layout = held.current.layout();
                if (wanted.rate_slots, wanted.shard_slots)
                    == (layout.rate_slots, layout.shard_slots)
                {
                    return Ok(None);
                }
                held.current.caps_gen() + 1
            }
        };
        let (region, fd) = StreamCapsRegion::create(max_sessions, self.workers, caps_gen)?;
        let region = Arc::new(region);
        match self.streams.get_mut(stream_id) {
            Some(held) => {
                let previous = std::mem::replace(&mut held.current, region);
                held.retired.push(previous);
                held.fd = fd;
            }
            None => {
                self.streams.insert(
                    stream_id.to_string(),
                    NodeStreamCaps {
                        current: region,
                        fd,
                        retired: self.orphans.remove(stream_id).unwrap_or_default(),
                    },
                );
            }
        }
        Ok(Some(caps_gen))
    }

    /// Whether `stream_id` has a region.
    pub fn holds(&self, stream_id: &str) -> bool {
        self.streams.contains_key(stream_id)
    }

    /// The streams with a region, in id order.
    pub fn stream_ids(&self) -> impl Iterator<Item = &str> {
        self.streams.keys().map(String::as_str)
    }

    /// The `caps` message handing worker `slot` the current region of
    /// `stream_id`, `None` when the stream has none.
    ///
    /// # Errors
    ///
    /// The memfd could not be duplicated for the message.
    pub fn caps_message(
        &self,
        stream_id: &str,
        seq: u64,
        slot: u32,
    ) -> io::Result<Option<StreamCtlMsg>> {
        let Some(held) = self.streams.get(stream_id) else {
            return Ok(None);
        };
        Ok(Some(StreamCtlMsg::Caps {
            seq,
            stream_id: stream_id.to_string(),
            caps_gen: held.current.caps_gen(),
            slot,
            region: held.fd.try_clone()?,
        }))
    }

    /// The stream left the node: close its memfd and keep its regions
    /// only while they count sessions.
    pub fn retire(&mut self, stream_id: &str) {
        if let Some(held) = self.streams.remove(stream_id) {
            let orphans = self.orphans.entry(stream_id.to_string()).or_default();
            orphans.push(held.current);
            orphans.extend(held.retired);
        }
    }

    /// Release what dead worker `slot` held in every live region: its
    /// shards emptied, its sessions subtracted from each total. Before
    /// the respawn replay, while no process writes that slot. Returns
    /// the sessions released.
    pub fn release_worker(&self, slot: u32) -> u64 {
        self.regions().fold(0u64, |acc, r| {
            acc.saturating_add(r.release_worker(slot).unwrap_or(0))
        })
    }

    /// The periodic pass: evict the settled rate cells of every live
    /// region, and drop the retired ones that count no session.
    pub fn tick(&mut self, now_ns: u64) {
        for region in self.regions() {
            region.evict_rates(now_ns);
        }
        for held in self.streams.values_mut() {
            held.retired.retain(|r| r.total() > 0);
        }
        self.orphans.retain(|_, regions| {
            regions.retain(|r| r.total() > 0);
            !regions.is_empty()
        });
    }

    /// Sessions `stream_id` holds on the node, exact, over its live
    /// regions.
    pub fn sessions(&self, stream_id: &str) -> u64 {
        self.streams.get(stream_id).map_or(0, |held| {
            held.retired
                .iter()
                .fold(held.current.total(), |acc, r| acc.saturating_add(r.total()))
        })
    }

    /// Memfds the supervisor holds, one per UDP stream with a region.
    pub fn memfds(&self) -> usize {
        self.streams.len()
    }

    fn regions(&self) -> impl Iterator<Item = &Arc<StreamCapsRegion>> {
        self.streams
            .values()
            .flat_map(|held| std::iter::once(&held.current).chain(held.retired.iter()))
            .chain(self.orphans.values().flatten())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_shmem::SourceKey;
    use std::net::IpAddr;

    fn source(n: u8) -> SourceKey {
        SourceKey::of(IpAddr::from([192, 0, 2, n]))
    }

    fn worker_view(regions: &NodeCapsRegions, stream_id: &str, slot: u32) -> WorkerCaps {
        let Some(StreamCtlMsg::Caps { region, slot, .. }) =
            regions.caps_message(stream_id, 1, slot).unwrap()
        else {
            panic!("a caps message");
        };
        Arc::new(StreamCapsRegion::open(region).unwrap())
            .worker(slot)
            .unwrap()
    }

    #[test]
    fn a_size_change_replaces_the_region_and_the_old_one_drains() {
        let mut node = NodeCapsRegions::new(2);
        assert_eq!(node.ensure("dns", 4096).unwrap(), Some(1));
        assert_eq!(node.ensure("dns", 4000).unwrap(), None, "same table sizes");
        assert_eq!(node.memfds(), 1);

        let registry = CapsRegistry::new();
        registry.adopt("dns", worker_view(&node, "dns", 0));
        let permit = registry
            .get("dns")
            .unwrap()
            .current()
            .admit_session(source(1), 256, 4096)
            .unwrap();
        assert_eq!(node.sessions("dns"), 1);

        assert_eq!(node.ensure("dns", 16_384).unwrap(), Some(2));
        registry.adopt("dns", worker_view(&node, "dns", 0));
        let caps = registry.get("dns").unwrap();
        assert_eq!(caps.current().region().caps_gen(), 2);
        assert_eq!(caps.retired_sessions(), 1);
        assert_eq!(caps.stream_cap_left(16_384), 16_383);
        assert_eq!(node.sessions("dns"), 1, "the retired region still counts");

        drop(permit);
        node.tick(lorica_shmem::now_ns());
        assert_eq!(node.sessions("dns"), 0);
        registry.retain(|_| true);
        assert_eq!(registry.get("dns").unwrap().retired_sessions(), 0);
    }

    #[test]
    fn a_dead_workers_sessions_are_released_in_every_live_region() {
        let mut node = NodeCapsRegions::new(2);
        node.ensure("a", 64).unwrap();
        node.ensure("b", 64).unwrap();
        let dead_a = worker_view(&node, "a", 1);
        let dead_b = worker_view(&node, "b", 1);
        let alive = worker_view(&node, "a", 0);
        // The dead worker's permits are never dropped: its process is gone.
        let leaked: Vec<_> = (0..3)
            .map(|n| dead_a.admit_session(source(n), 8, 64).unwrap())
            .chain(std::iter::once(
                dead_b.admit_session(source(9), 8, 64).unwrap(),
            ))
            .collect();
        let _kept = alive.admit_session(source(1), 8, 64).unwrap();
        node.retire("b");
        assert_eq!(node.memfds(), 1);
        assert_eq!(node.release_worker(1), 4);
        assert_eq!(node.sessions("a"), 1, "the live worker's session stays");
        assert_eq!(dead_a.region().source_sessions(source(0)), 0);
        std::mem::forget(leaked);
    }

    #[test]
    fn a_stream_back_while_its_retired_region_counts_continues_its_caps_gen() {
        let mut node = NodeCapsRegions::new(1);
        node.ensure("dns", 64).unwrap();
        let registry = CapsRegistry::new();
        registry.adopt("dns", worker_view(&node, "dns", 0));
        let permit = registry
            .get("dns")
            .unwrap()
            .current()
            .admit_session(source(1), 8, 64)
            .unwrap();
        node.retire("dns");
        assert!(!node.holds("dns"));

        assert_eq!(node.ensure("dns", 64).unwrap(), Some(2));
        assert_eq!(node.sessions("dns"), 1, "the old region still counts");
        registry.adopt("dns", worker_view(&node, "dns", 0));
        let caps = registry.get("dns").unwrap();
        assert_eq!(caps.retired_sessions(), 1);
        assert_eq!(caps.stream_cap_left(64), 63);

        drop(permit);
        node.tick(lorica_shmem::now_ns());
        assert_eq!(node.sessions("dns"), 0);
        node.retire("dns");
        node.tick(lorica_shmem::now_ns());
        assert_eq!(
            node.ensure("dns", 64).unwrap(),
            Some(1),
            "nothing left to count beside"
        );
    }

    #[test]
    fn a_replayed_caps_gen_replaces_and_a_gone_stream_is_forgotten() {
        let mut node = NodeCapsRegions::new(1);
        node.ensure("dns", 64).unwrap();
        let registry = CapsRegistry::new();
        registry.adopt("dns", worker_view(&node, "dns", 0));
        registry.adopt("dns", worker_view(&node, "dns", 0));
        assert_eq!(registry.get("dns").unwrap().retired_sessions(), 0);
        assert!(node.caps_message("absent", 1, 0).unwrap().is_none());
        registry.retain(|id| id != "dns");
        assert!(registry.is_empty());
    }
}
