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

//! The caps regions: one per stream on the node, sized, replaced,
//! retired, handed to the workers, and released for a dead worker.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard, PoisonError};

use lorica_config::models::{Stream, StreamBackend};
use lorica_stream::caps::admitted_cap;
use lorica_stream::NodeCapsRegions;
use lorica_worker::stream_ctl::StreamCtlMsg;
use tracing::{info, warn};

use super::{StreamPlane, WorkerLink};

/// The caps regions a plane and its handle share. Never held across an
/// await.
pub(super) type SharedCaps = Arc<StdMutex<NodeCapsRegions>>;

pub(super) fn lock_caps(caps: &SharedCaps) -> MutexGuard<'_, NodeCapsRegions> {
    // A panic while holding the lock leaves counts no worse than a dead
    // worker does, which the regions are built to survive.
    caps.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(super) fn release_worker_sessions(caps: &SharedCaps, worker: u32) -> u64 {
    let released = lock_caps(caps).release_worker(worker);
    if released > 0 {
        info!(
            worker_id = worker,
            released,
            "connections and sessions of a dead worker released from the stream caps regions"
        );
    }
    released
}

/// The backend links the region of `stream_id` is sized for: its links
/// with a `max_active`, the only ones the engines count in the region's
/// backend shards (Story 12.6 D-h). A link gaining or losing its cap
/// past the region's floor replaces the region, as a size change does;
/// uncapped links never move it.
pub(super) fn capped_links(links: &[StreamBackend], stream_id: &str) -> u64 {
    let capped = links
        .iter()
        .filter(|link| link.stream_id == stream_id && link.max_active.is_some())
        .count();
    u64::try_from(capped).unwrap_or(u64::MAX)
}

impl<L: WorkerLink> StreamPlane<L> {
    /// Release what dead worker `worker` held in every caps region: its
    /// session shards emptied and its sessions subtracted from each
    /// stream's total (D-d). Called when the worker is found dead and
    /// again first thing in its respawn's replay, while no process
    /// writes its slot (the respawn is sent no region before this);
    /// the second call finds nothing left. Returns the sessions
    /// released.
    pub(crate) fn release_worker(&self, worker: u32) -> u64 {
        release_worker_sessions(&self.caps, worker)
    }

    /// Retire the caps region of every stream with no binding wanted on
    /// this node any more (deleted, disabled, deselected): its memfd
    /// closes, and the region stays mapped while its connections or
    /// sessions drain. Held bindings that are no longer wanted were
    /// detached earlier in the pass. A stream that changes protocol keeps
    /// its region, replaced when its new cap moves the table sizes.
    pub(super) fn retire_caps(&mut self, desired: &BTreeSet<&str>) {
        let mut caps = lock_caps(&self.caps);
        let gone: Vec<String> = caps
            .stream_ids()
            .filter(|id| !desired.contains(id))
            .map(str::to_string)
            .collect();
        for id in gone {
            caps.retire(&id);
        }
    }

    /// Replace the region of every held binding whose stream's
    /// [`admitted_cap`] or [`capped_links`] moved its table sizes, and
    /// hand the new one to every worker; connections and sessions counted
    /// in the old one stay counted there until they end (D-d).
    pub(super) async fn resize_caps(&mut self, streams: &[Stream], links: &[StreamBackend]) {
        let mut replaced: Vec<String> = Vec::new();
        for b in self.held.values() {
            let id = &b.key.stream_id;
            let Some(cap) = streams.iter().find(|s| s.id == *id).and_then(admitted_cap) else {
                continue;
            };
            let capped = capped_links(links, id);
            match lock_caps(&self.caps).ensure(id, cap, capped) {
                Ok(Some(caps_gen)) => {
                    info!(stream_id = %id, caps_gen, cap, capped_links = capped,
                          "stream caps region replaced");
                    replaced.push(id.clone());
                }
                Ok(None) => {}
                Err(e) => warn!(stream_id = %id, error = %e,
                                "stream caps region not replaced; the stream keeps its current one"),
            }
        }
        if replaced.is_empty() {
            return;
        }
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for worker in self.workers.keys().copied().collect::<Vec<_>>() {
            for id in &replaced {
                if let Some(msg) = self.caps_message(id, worker) {
                    per_worker.entry(worker).or_default().push(msg);
                }
            }
        }
        self.send_all(per_worker).await;
        for id in &replaced {
            if let Some(b) = self.held.get(id) {
                self.states.set_bound(id, b.serving(), self.worker_count);
            }
        }
    }

    /// The `caps` message handing `worker` the current region of
    /// `stream_id`, or `None`, logged, when there is none to send.
    pub(super) fn caps_message(&mut self, stream_id: &str, worker: u32) -> Option<StreamCtlMsg> {
        let seq = self.seq();
        match lock_caps(&self.caps).caps_message(stream_id, seq, worker) {
            Ok(Some(msg)) => Some(msg),
            Ok(None) => {
                warn!(%stream_id, worker_id = worker,
                      "no stream caps region; this worker will not serve the binding");
                None
            }
            Err(e) => {
                warn!(%stream_id, worker_id = worker, error = %e,
                      "stream caps region not duplicated; this worker will not serve the binding");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use lorica_stream::BindState;

    use super::*;
    use crate::startup::stream_plane::test_support::{
        free_ports, free_udp_port, plane, seen, tcp, udp, FakeLink, Reply, Seen, PASS, STANDALONE,
    };
    use crate::startup::stream_plane::Trigger;

    /// The view of the worker in `slot` of `stream_id`'s current region,
    /// as a worker maps it from its `caps`.
    fn worker_caps(
        plane: &StreamPlane<FakeLink>,
        stream_id: &str,
        slot: u32,
    ) -> lorica_shmem::WorkerCaps {
        let Some(StreamCtlMsg::Caps { region, .. }) = lock_caps(&plane.caps)
            .caps_message(stream_id, 0, slot)
            .unwrap()
        else {
            panic!("a caps message for {stream_id}");
        };
        Arc::new(lorica_shmem::StreamCapsRegion::open(region).unwrap())
            .worker(slot)
            .unwrap()
    }

    fn client(n: u8) -> lorica_shmem::SourceKey {
        lorica_shmem::SourceKey::of(std::net::IpAddr::from([192, 0, 2, n]))
    }

    /// A UDP session's admission: the stream part, then the source part
    /// with no pending share.
    fn session(
        caps: &lorica_shmem::WorkerCaps,
        source: lorica_shmem::SourceKey,
        source_cap: u64,
        stream_cap: u64,
    ) -> Result<lorica_shmem::StreamPermit, lorica_shmem::AdmitRefusal> {
        caps.admit_stream(stream_cap, false, 0)?
            .admit_source(source, source_cap, u64::MAX)
    }

    #[tokio::test]
    async fn a_worker_that_refuses_the_caps_region_does_not_count_as_serving() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[Reply::Refuse]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let s = udp("u1", free_udp_port());

        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        assert_eq!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 1,
                workers: 2
            }),
            "it holds the sockets but admits no session"
        );
    }

    #[tokio::test]
    async fn a_respawned_worker_is_released_then_sent_its_caps_then_its_attach() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let port = free_udp_port();
        let s = udp("u1", port);
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        // Worker 1 holds three sessions when it dies: its permits are
        // never dropped, its process is gone. Worker 0 holds one.
        let dead = worker_caps(&plane, "u1", 1);
        let leaked: Vec<_> = (1..=3)
            .map(|n| session(&dead, client(n), 8, 4096).unwrap())
            .collect();
        let _live = session(&worker_caps(&plane, "u1", 0), client(9), 8, 4096).unwrap();
        assert_eq!(lock_caps(&plane.caps).sessions("u1"), 4);

        let (respawned, seen1) = FakeLink::new(&[]);
        plane.replay_worker(1, respawned, PASS).await;

        assert_eq!(
            seen(&seen1),
            vec![
                Seen::Caps {
                    stream_id: "u1".into(),
                    caps_gen: 1,
                    slot: 1,
                    total: 1,
                },
                Seen::Attach {
                    stream_id: "u1".into(),
                    bind_gen: 1,
                    addrs: vec![([127, 0, 0, 1], port).into()],
                },
                Seen::Refresh { drain_ms: 30_000 },
            ],
            "released before the region is handed to the respawn, which gets it before its socket"
        );
        assert_eq!(lock_caps(&plane.caps).sessions("u1"), 1);
        assert_eq!(dead.region().source_sessions(client(1)), 0);
        assert_eq!(plane.release_worker(1), 0, "a second release finds nothing");
        assert_eq!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                workers: 2
            })
        );
        std::mem::forget(leaked);
    }

    #[tokio::test]
    async fn a_size_change_sends_a_new_caps_and_keeps_the_old_region_until_it_drains() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let mut s = udp("u1", free_udp_port());
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        let permit = session(&worker_caps(&plane, "u1", 0), client(1), 8, 4096).unwrap();
        let before = seen(&seen0).len();

        if let Some(udp) = s.udp.as_mut() {
            udp.max_sessions = 16_384;
        }
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        for (slot, log) in [(0u32, &seen0), (1, &seen1)] {
            assert_eq!(
                seen(log)[before..],
                [
                    Seen::Caps {
                        stream_id: "u1".into(),
                        caps_gen: 2,
                        slot,
                        total: 0,
                    },
                    Seen::Refresh { drain_ms: 30_000 },
                ],
                "a new region, no rebind"
            );
        }
        assert_eq!(
            lock_caps(&plane.caps).sessions("u1"),
            1,
            "the old region still counts"
        );
        assert_eq!(lock_caps(&plane.caps).memfds(), 1, "one memfd per stream");
        assert!(matches!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                ..
            })
        ));

        // Within the same table sizes: nothing to send.
        if let Some(udp) = s.udp.as_mut() {
            udp.max_sessions = 16_000;
        }
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert!(!seen(&seen0)
            .iter()
            .any(|s| matches!(s, Seen::Caps { caps_gen: 3, .. })));

        drop(permit);
        lock_caps(&plane.caps).tick(lorica_shmem::now_ns());
        assert_eq!(lock_caps(&plane.caps).sessions("u1"), 0);
    }

    /// The backend cells per worker of `stream_id`'s current region, as a
    /// worker maps it from its `caps`.
    fn backend_slots(plane: &StreamPlane<FakeLink>, stream_id: &str) -> u64 {
        let Some(StreamCtlMsg::Caps { region, .. }) = lock_caps(&plane.caps)
            .caps_message(stream_id, 0, 0)
            .unwrap()
        else {
            panic!("a caps message for {stream_id}");
        };
        lorica_shmem::StreamCapsRegion::open(region)
            .unwrap()
            .layout()
            .backend_slots
    }

    /// `count` links of `stream_id`, the first `capped` of them with a
    /// `max_active`.
    fn links(stream_id: &str, count: usize, capped: usize) -> Vec<StreamBackend> {
        (0..count)
            .map(|i| StreamBackend {
                max_active: (i < capped).then_some(4),
                ..StreamBackend::primary(stream_id, &format!("b-{i}"))
            })
            .collect()
    }

    #[tokio::test]
    async fn a_region_is_sized_for_the_capped_links_and_replaced_when_they_cross_its_floor() {
        use lorica_shmem::stream_caps::{BACKEND_SLOTS_PER_LINK, MIN_BACKEND_SLOTS};

        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, _) = plane(vec![w0]);
        let s = tcp("t1", free_ports(1));
        let at_floor = usize::try_from(MIN_BACKEND_SLOTS / BACKEND_SLOTS_PER_LINK).unwrap();
        let past_floor = at_floor + 1;

        // Uncapped links are never counted, so they never size a region.
        let uncapped = links("t1", past_floor * 2, 0);
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &uncapped,
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert_eq!(backend_slots(&plane, "t1"), MIN_BACKEND_SLOTS);

        // Capped links within the floor move nothing.
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &links("t1", past_floor * 2, at_floor),
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        let caps_sent = |log: &Arc<StdMutex<Vec<Seen>>>| {
            seen(log)
                .iter()
                .filter(|s| matches!(s, Seen::Caps { .. }))
                .count()
        };
        assert_eq!(caps_sent(&seen0), 1, "the first region only");

        // One capped link past the floor: the next region, sent ahead of
        // the refresh, with the cells for it.
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &links("t1", past_floor * 2, past_floor),
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert_eq!(
            backend_slots(&plane, "t1"),
            (u64::try_from(past_floor).unwrap() * BACKEND_SLOTS_PER_LINK).next_power_of_two()
        );
        assert!(seen(&seen0).contains(&Seen::Caps {
            stream_id: "t1".into(),
            caps_gen: 2,
            slot: 0,
            total: 0,
        }));

        // The caps lifted again: back to the floor, in a third region.
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &uncapped,
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert_eq!(backend_slots(&plane, "t1"), MIN_BACKEND_SLOTS);
        assert_eq!(caps_sent(&seen0), 3);
    }

    #[test]
    fn only_the_links_of_the_stream_with_a_cap_are_counted() {
        let mut all = links("t1", 5, 3);
        all.extend(links("t2", 4, 4));
        assert_eq!(capped_links(&all, "t1"), 3);
        assert_eq!(capped_links(&all, "t2"), 4);
        assert_eq!(capped_links(&all, "t3"), 0);
    }
}
