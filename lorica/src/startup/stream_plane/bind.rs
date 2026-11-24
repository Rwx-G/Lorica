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

//! The reconcile passes: detach what is no longer desired, bind and
//! attach what is new, refresh every worker, replay a respawned one.

use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::OwnedFd;
use std::time::Instant;

use lorica_config::models::{NodeRole, Stream, StreamBackend, StreamProtocol};
use lorica_stream::caps::admitted_cap;
use lorica_stream::reconcile::desired_bindings;
use lorica_stream::{
    diff, BindFailureKind, BindKey, BoundBinding, Detach, ReleaseCause, StreamDemand,
};
use lorica_worker::fd_passing::StreamProto;
use lorica_worker::stream_ctl::{check_stream_id, chunk_sockets, StreamCtlMsg, StreamSocket};
use lorica_worker::stream_sockets::bind_range;
use tracing::{info, warn};

use super::budget::{budget_failure_kind, demand_of};
use super::caps::{capped_links, lock_caps};
use super::exchange::{Pending, WorkerSlot};
use super::{
    DrainingBinding, HeldBinding, PassSettings, PlaneEvent, StreamPlane, Trigger, WorkerLink,
};

/// Whether a failure may clear without a configuration change.
fn retryable(kind: BindFailureKind) -> bool {
    matches!(
        kind,
        BindFailureKind::AddressInUse | BindFailureKind::AddressNotAvailable
    )
}

fn proto_of(protocol: StreamProtocol) -> StreamProto {
    match protocol {
        StreamProtocol::Tcp => StreamProto::Tcp,
        StreamProtocol::Udp => StreamProto::Udp,
    }
}

impl<L: WorkerLink> StreamPlane<L> {
    fn bound_list(&self) -> Vec<BoundBinding> {
        self.held.values().map(HeldBinding::bound).collect()
    }

    /// Whether a failure the retry tick would retry is held.
    pub(crate) fn has_retryable_failure(&self) -> bool {
        self.failures.values().any(|kind| retryable(*kind))
    }

    /// D-d step 1, before the workers commit: detach every binding no
    /// longer desired or whose bind key changed.
    pub(crate) async fn release_stale(
        &mut self,
        streams: &[Stream],
        role: NodeRole<'_>,
        pass: PassSettings,
    ) -> Vec<PlaneEvent> {
        if self.quiesced {
            return Vec::new();
        }
        let actions = diff(streams, role, &self.bound_list());
        self.detach(actions.detach, pass).await
    }

    /// D-d step 3, after the workers commit: detach what step 1 could
    /// not see, bind and attach every desired binding not held yet, and
    /// on a [`Trigger::Change`] refresh every worker. `links` are the
    /// stored stream-to-backend links, which size each caps region.
    pub(crate) async fn bind_desired(
        &mut self,
        streams: &[Stream],
        links: &[StreamBackend],
        role: NodeRole<'_>,
        pass: PassSettings,
        trigger: Trigger,
    ) -> Vec<PlaneEvent> {
        if self.quiesced {
            return Vec::new();
        }
        let actions = diff(streams, role, &self.bound_list());
        let mut events = self.detach(actions.detach, pass).await;
        self.usable_source_ports = (self.source_ports)();
        let now = Instant::now();
        self.draining.retain(|d| d.until > now);

        let desired_keys = desired_bindings(streams, role);
        let desired: BTreeSet<&str> = desired_keys.iter().map(|k| k.stream_id.as_str()).collect();
        self.retire_caps(&desired);
        self.rebinding.retain(|id, _| desired.contains(id.as_str()));
        for id in self.states.snapshot().into_keys() {
            if !desired.contains(id.as_str()) && !self.held.contains_key(&id) {
                self.states.remove(&id);
                self.failures.remove(&id);
            }
        }
        self.resize_caps(streams, links).await;

        let names: BTreeMap<&str, &str> = streams
            .iter()
            .map(|s| (s.id.as_str(), s.name.as_str()))
            .collect();
        for refused in actions.refused {
            let name = names
                .get(refused.key.stream_id.as_str())
                .copied()
                .unwrap_or("");
            self.fail(
                &refused.key,
                name,
                refused.kind(),
                refused.to_string(),
                refused.port,
                &mut events,
            );
        }

        for key in actions.bind {
            let skip = trigger == Trigger::RetryTick
                && self
                    .failures
                    .get(&key.stream_id)
                    .is_some_and(|kind| !retryable(*kind));
            if skip || self.waits_for_drain(&key) {
                continue;
            }
            let name = names.get(key.stream_id.as_str()).copied().unwrap_or("");
            self.bind_one(key, name, streams, links, pass, &mut events)
                .await;
        }

        // Inherited listeners serve the first pass only: whatever it did
        // not adopt belongs to no desired binding.
        for (stream_id, addr, _fd) in self.inherited.drain(..) {
            info!(%stream_id, %addr, "inherited stream listener not adopted; closed");
        }
        for (entry, _fd) in self.inherited_udp.drain(..) {
            info!(stream_id = %entry.stream_id, addr = %entry.addr, slot = entry.slot,
                  "inherited UDP slot socket not adopted; closed");
        }

        if trigger == Trigger::Change {
            self.refresh_all(pass).await;
        }
        events
    }

    /// Send `refresh` to every worker: each reloads its stream table and
    /// drains what the new one no longer holds. Binds and detaches
    /// nothing.
    pub(crate) async fn refresh_all(&mut self, pass: PassSettings) {
        if self.quiesced {
            return;
        }
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for id in self.workers.keys().copied().collect::<Vec<_>>() {
            let seq = self.seq();
            per_worker.insert(
                id,
                vec![StreamCtlMsg::Refresh {
                    seq,
                    drain_ms: pass.drain_ms(),
                }],
            );
        }
        self.send_all(per_worker).await;
    }

    /// Whether `key` must wait for a draining UDP binding over its ports
    /// to let them go (D-m). It then stays pending, its own state
    /// untouched, and is retried as an `address_in_use` failure would
    /// be, without the alert: waiting for a drain is not a failure.
    fn waits_for_drain(&mut self, key: &BindKey) -> bool {
        let Some((draining, port)) = self
            .draining
            .iter()
            .find_map(|d| key.overlap_port(&d.key).map(|port| (d, port)))
        else {
            return false;
        };
        info!(
            stream_id = %key.stream_id,
            port,
            draining_stream_id = %draining.key.stream_id,
            draining_bind_gen = draining.bind_gen,
            "UDP binding waits for a draining binding to release its port"
        );
        if self.states.get(&key.stream_id).is_none() {
            self.states.set_pending(&key.stream_id);
        }
        self.failures
            .insert(key.stream_id.clone(), BindFailureKind::AddressInUse);
        true
    }

    /// What `worker` is sent for binding `stream_id`: the stream's
    /// `caps`, then its `attach` messages; nothing when either cannot be
    /// built, so the worker never holds sockets it cannot serve.
    fn binding_messages(&mut self, stream_id: &str, worker: u32) -> Vec<StreamCtlMsg> {
        let Some(caps) = self.caps_message(stream_id, worker) else {
            return Vec::new();
        };
        let attaches = self.attach_messages(stream_id, worker);
        if attaches.is_empty() {
            return Vec::new();
        }
        std::iter::once(caps).chain(attaches).collect()
    }

    /// A worker came back after a crash: release what its predecessor
    /// held in the caps regions, take its new channel and replay every
    /// live binding (each one's `caps` ahead of its `attach`), then a
    /// `refresh` (D-a, Story 12.5 D-d).
    pub(crate) async fn replay_worker(&mut self, worker: u32, link: L, pass: PassSettings) {
        self.release_worker(worker);
        if self.quiesced {
            return;
        }
        self.workers.insert(worker, WorkerSlot::new(link));
        let mut msgs = Vec::new();
        let ids: Vec<String> = self.held.keys().cloned().collect();
        for id in ids {
            let binding = self.binding_messages(&id, worker);
            if let Some(b) = self.held.get_mut(&id) {
                b.acked.remove(&worker);
                b.caps_refused.remove(&worker);
            }
            msgs.extend(binding);
        }
        let seq = self.seq();
        msgs.push(StreamCtlMsg::Refresh {
            seq,
            drain_ms: pass.drain_ms(),
        });
        self.send_all(BTreeMap::from([(worker, msgs)])).await;
        for b in self.held.values() {
            self.states
                .set_bound(&b.key.stream_id, b.serving(), self.worker_count);
        }
    }

    async fn detach(&mut self, detaches: Vec<Detach>, pass: PassSettings) -> Vec<PlaneEvent> {
        let mut events = Vec::new();
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        let workers: Vec<u32> = self.workers.keys().copied().collect();
        for d in detaches {
            let id = d.binding.key.stream_id.clone();
            let held_here = self
                .held
                .get(&id)
                .is_some_and(|b| b.bind_gen == d.binding.bind_gen);
            if !held_here {
                continue;
            }
            // The supervisor's copies close first; the port is free once
            // the last worker closes its copy on `detach`, which for UDP
            // is when the binding's sessions have drained (D-m).
            if d.binding.key.protocol == StreamProtocol::Udp {
                self.draining.push(DrainingBinding {
                    key: d.binding.key.clone(),
                    bind_gen: d.binding.bind_gen,
                    until: Instant::now() + pass.drain + self.drain_margin,
                });
            }
            if let Some(held) = self.held.remove(&id) {
                if d.cause == ReleaseCause::Rebind {
                    self.rebinding.insert(id.clone(), held.demand.clone());
                }
            }
            for slot in self.workers.values_mut() {
                slot.outstanding.retain(|_, p| {
                    *p != Pending::Attach {
                        stream_id: id.clone(),
                        bind_gen: d.binding.bind_gen,
                    }
                });
            }
            for worker in &workers {
                let seq = self.seq();
                per_worker
                    .entry(*worker)
                    .or_default()
                    .push(StreamCtlMsg::Detach {
                        seq,
                        stream_id: id.clone(),
                        bind_gen: d.binding.bind_gen,
                        drain_ms: pass.drain_ms(),
                    });
            }
            if d.cause == ReleaseCause::Rebind {
                self.states.set_pending(&id);
            } else {
                self.states.remove(&id);
            }
            events.push(PlaneEvent::Released {
                key: d.binding.key,
                bind_gen: d.binding.bind_gen,
                cause: d.cause,
            });
        }
        self.send_all(per_worker).await;
        events
    }

    fn fail(
        &mut self,
        key: &BindKey,
        name: &str,
        kind: BindFailureKind,
        os_error: String,
        port: u16,
        events: &mut Vec<PlaneEvent>,
    ) {
        let entered = self.states.set_failed(
            &key.stream_id,
            kind,
            os_error.clone(),
            port,
            chrono::Utc::now(),
        );
        self.failures.insert(key.stream_id.clone(), kind);
        if entered {
            events.push(PlaneEvent::BindFailed {
                key: key.clone(),
                name: name.to_string(),
                kind,
                os_error,
                port,
            });
        }
    }

    async fn bind_one(
        &mut self,
        key: BindKey,
        name: &str,
        streams: &[Stream],
        links: &[StreamBackend],
        pass: PassSettings,
        events: &mut Vec<PlaneEvent>,
    ) {
        let id = key.stream_id.clone();
        if self.states.get(&id).is_none() {
            self.states.set_pending(&id);
        }
        // An id the channel cannot carry could never be attached: say so
        // on the stream rather than drop it.
        if let Err(reason) = check_stream_id(&id) {
            self.fail(
                &key,
                name,
                BindFailureKind::Other,
                format!("the stream id cannot be sent to the workers: {reason}"),
                key.port_first,
                events,
            );
            return;
        }
        if let Some((port, listener)) = self.reserved.clash_in(key.port_first, key.port_last) {
            self.fail(
                &key,
                name,
                BindFailureKind::ReservedPort,
                format!("port {port} is {}", listener.phrase()),
                port,
                events,
            );
            return;
        }
        let stream_of = |id: &str| streams.iter().find(|s| s.id == id);
        let others: Vec<StreamDemand> = self
            .held
            .values()
            .map(|b| demand_of(&b.key, stream_of(&b.key.stream_id)))
            .collect();
        let demand = demand_of(&key, stream_of(&key.stream_id));
        // The node's backstop of the API's write check, by the same rule
        // (Story 12.5 D-e): a rebind is judged against what the node
        // counted for the stream's last binding, with `U` as read at the
        // start of this pass.
        if let Err(violation) = self.budget.check_change(
            &demand,
            self.rebinding.get(&id),
            &others,
            self.worker_count,
            pass.listen_socket_cap,
            self.usable_source_ports,
        ) {
            self.fail(
                &key,
                name,
                budget_failure_kind(&violation),
                violation.to_string(),
                key.port_first,
                events,
            );
            return;
        }
        let ensured = match stream_of(&key.stream_id).and_then(admitted_cap) {
            None => Err("the UDP stream carries no udp settings".to_string()),
            Some(cap) => lock_caps(&self.caps)
                .ensure(&id, cap, capped_links(links, &id))
                .map_err(|e| format!("the stream caps region could not be created: {e}")),
        };
        if let Err(reason) = ensured {
            self.fail(
                &key,
                name,
                BindFailureKind::Other,
                reason,
                key.port_first,
                events,
            );
            return;
        }
        let ports = match self.take_inherited(&key) {
            Some(ports) => ports,
            None => match bind_range(
                proto_of(key.protocol),
                key.listen_address,
                key.ports(),
                self.worker_count as usize,
            ) {
                Ok(ports) => ports,
                Err(e) => {
                    self.fail(
                        &key,
                        name,
                        e.kind,
                        e.source.to_string(),
                        e.addr.port(),
                        events,
                    );
                    return;
                }
            },
        };

        let bind_gen = self.next_gen;
        self.next_gen += 1;
        self.rebinding.remove(&id);
        self.held.insert(
            id.clone(),
            HeldBinding {
                key: key.clone(),
                bind_gen,
                ports,
                chunks: 0,
                acked: BTreeMap::new(),
                caps_refused: BTreeSet::new(),
                demand,
            },
        );
        let mut per_worker: BTreeMap<u32, Vec<StreamCtlMsg>> = BTreeMap::new();
        for worker in self.workers.keys().copied().collect::<Vec<_>>() {
            let msgs = self.binding_messages(&id, worker);
            per_worker.insert(worker, msgs);
        }
        self.send_all(per_worker).await;

        self.failures.remove(&id);
        let (serving, bind_gen) = match self.held.get(&id) {
            Some(b) => (b.serving(), b.bind_gen),
            None => return,
        };
        self.states.set_bound(&id, serving, self.worker_count);
        events.push(PlaneEvent::Bound {
            key,
            bind_gen,
            workers_serving: serving,
            workers: self.worker_count,
        });
    }

    /// The `attach` messages of binding `stream_id` for `worker`: a dup
    /// of each TCP listener, or the worker's own slot socket of each UDP
    /// port, chunked by [`chunk_sockets`].
    fn attach_messages(&mut self, stream_id: &str, worker: u32) -> Vec<StreamCtlMsg> {
        let Some(b) = self.held.get(stream_id) else {
            return Vec::new();
        };
        let slot = match b.key.protocol {
            StreamProtocol::Tcp => 0,
            StreamProtocol::Udp => worker as usize,
        };
        let mut sockets = Vec::with_capacity(b.ports.len());
        for port in &b.ports {
            let dup = port.sockets.get(slot).map(OwnedFd::try_clone);
            match dup {
                Some(Ok(fd)) => sockets.push(StreamSocket {
                    proto: proto_of(b.key.protocol),
                    addr: port.addr,
                    fd,
                }),
                Some(Err(e)) => {
                    warn!(%stream_id, worker_id = worker, addr = %port.addr, error = %e,
                          "stream socket not duplicated; this worker will not serve the binding");
                    return Vec::new();
                }
                None => {
                    warn!(%stream_id, worker_id = worker, slot,
                          "no UDP slot socket for this worker; it will not serve the binding");
                    return Vec::new();
                }
            }
        }
        let bind_gen = b.bind_gen;
        let chunks = chunk_sockets(sockets);
        if let Some(b) = self.held.get_mut(stream_id) {
            b.chunks = chunks.len();
        }
        chunks
            .into_iter()
            .map(|sockets| StreamCtlMsg::Attach {
                seq: self.seq(),
                stream_id: stream_id.to_string(),
                bind_gen,
                sockets,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    use lorica_stream::BindState;
    use lorica_worker::stream_ctl;

    use super::*;
    use crate::startup::stream_plane::caps::lock_caps;
    use crate::startup::stream_plane::test_support::{
        bindable, free_ports, free_udp_port, plane, reserved, seen, stream, tcp, udp, FakeLink,
        Seen, PASS, STANDALONE,
    };

    #[tokio::test]
    async fn a_new_stream_is_bound_attached_to_every_worker_then_refreshed() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let port = free_ports(1);
        let s = tcp("s1", port);

        let events = plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        assert_eq!(
            events,
            vec![PlaneEvent::Bound {
                key: BindKey::of(&s),
                bind_gen: 1,
                workers_serving: 2,
                workers: 2,
            }]
        );
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        for (slot, log) in [&seen0, &seen1].into_iter().enumerate() {
            assert_eq!(
                seen(log),
                vec![
                    // A TCP stream's region precedes its attach, as a UDP
                    // one's does (Story 12.6 D-e).
                    Seen::Caps {
                        stream_id: "s1".into(),
                        caps_gen: 1,
                        slot: u32::try_from(slot).unwrap(),
                        total: 0,
                    },
                    Seen::Attach {
                        stream_id: "s1".into(),
                        bind_gen: 1,
                        addrs: vec![addr],
                    },
                    Seen::Refresh { drain_ms: 30_000 },
                ]
            );
        }
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 2,
                workers: 2
            })
        );
        assert!(TcpStream::connect(addr).is_ok(), "the port listens");
        assert_eq!(plane.tcp_handoff_fds().len(), 1);
    }

    #[tokio::test]
    async fn deleting_a_stream_detaches_it_everywhere_and_frees_the_port() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let port = free_ports(1);
        let s = tcp("s1", port);
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        assert!(!bindable(port));

        let events = plane.release_stale(&[], STANDALONE, PASS).await;

        assert_eq!(
            events,
            vec![PlaneEvent::Released {
                key: BindKey::of(&s),
                bind_gen: 1,
                cause: ReleaseCause::Deleted,
            }]
        );
        assert_eq!(
            seen(&seen0).last(),
            Some(&Seen::Detach {
                stream_id: "s1".into(),
                drain_ms: 30_000
            })
        );
        assert!(bindable(port), "the port is free once every holder let go");
        assert!(states.get("s1").is_none());
    }

    #[tokio::test]
    async fn a_port_change_rebinds_under_a_new_generation() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(2);
        let before = tcp("s1", first);
        plane
            .bind_desired(
                std::slice::from_ref(&before),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        let after = tcp("s1", first + 1);

        let mut events = plane
            .release_stale(std::slice::from_ref(&after), STANDALONE, PASS)
            .await;
        assert_eq!(states.get("s1"), Some(BindState::Pending));
        events.extend(
            plane
                .bind_desired(
                    std::slice::from_ref(&after),
                    &[],
                    STANDALONE,
                    PASS,
                    Trigger::Change,
                )
                .await,
        );

        assert!(matches!(
            events.as_slice(),
            [
                PlaneEvent::Released {
                    cause: ReleaseCause::Rebind,
                    bind_gen: 1,
                    ..
                },
                PlaneEvent::Bound { bind_gen: 2, .. },
            ]
        ));
        assert!(bindable(first));
        assert!(!bindable(first + 1));
        assert!(seen(&seen0).contains(&Seen::Detach {
            stream_id: "s1".into(),
            drain_ms: 30_000
        }));
    }

    #[tokio::test]
    async fn a_range_with_a_taken_port_binds_nothing_reports_that_port_then_recovers() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let first = free_ports(3);
        let squatter = TcpListener::bind(("127.0.0.1", first + 1)).unwrap();
        let s = stream("s1", StreamProtocol::Tcp, first, first + 2);

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
                kind: BindFailureKind::AddressInUse,
                port,
                os_error,
                ..
            }] => {
                assert_eq!(*port, first + 1);
                assert!(os_error.contains("os error"), "{os_error}");
            }
            other => panic!("unexpected {other:?}"),
        }
        assert!(
            bindable(first),
            "the ports bound before the failure are closed"
        );
        assert!(!seen(&seen0)
            .iter()
            .any(|s| matches!(s, Seen::Attach { .. })));
        assert!(plane.has_retryable_failure());

        // Failing again is not a new entry: no second event.
        let again = plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::RetryTick,
            )
            .await;
        assert!(again.is_empty());
        assert!(matches!(states.get("s1"), Some(BindState::Failed(_))));

        drop(squatter);
        let recovered = plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::RetryTick,
            )
            .await;
        assert!(matches!(recovered.as_slice(), [PlaneEvent::Bound { .. }]));
        assert!(!plane.has_retryable_failure());
    }

    #[tokio::test]
    async fn a_stream_id_the_channel_cannot_carry_is_a_failed_bind() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let port = free_ports(1);
        let id = "x".repeat(stream_ctl::MAX_STREAM_ID_LEN + 1);
        let s = tcp(&id, port);

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
                kind: BindFailureKind::Other,
                os_error,
                ..
            }] => assert!(os_error.contains("stream id"), "{os_error}"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(states.get(&id), Some(BindState::Failed(_))));
        assert!(bindable(port), "nothing was bound for it");
        assert!(!seen(&seen0)
            .iter()
            .any(|s| matches!(s, Seen::Attach { .. })));
    }

    #[tokio::test]
    async fn a_reserved_port_is_refused_and_left_to_the_next_change() {
        let (w0, _) = FakeLink::new(&[]);
        let (mut plane, _) = plane(vec![w0]);
        let s = tcp("s1", reserved().http);

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
                kind: BindFailureKind::ReservedPort,
                os_error,
                port: 8080,
                ..
            }] => assert_eq!(os_error, "port 8080 is a proxy listener port"),
            other => panic!("unexpected {other:?}"),
        }
        assert!(!plane.has_retryable_failure());
    }

    #[tokio::test]
    async fn a_respawned_worker_gets_every_live_binding_replayed() {
        let (w0, _) = FakeLink::new(&[]);
        let (w1, _) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0, w1]);
        let port = free_ports(1);
        let s = tcp("s1", port);
        plane
            .bind_desired(
                std::slice::from_ref(&s),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        let (respawned, seen1) = FakeLink::new(&[]);
        plane.replay_worker(1, respawned, PASS).await;

        assert_eq!(
            seen(&seen1),
            vec![
                Seen::Caps {
                    stream_id: "s1".into(),
                    caps_gen: 1,
                    slot: 1,
                    total: 0,
                },
                Seen::Attach {
                    stream_id: "s1".into(),
                    bind_gen: 1,
                    addrs: vec![([127, 0, 0, 1], port).into()],
                },
                Seen::Refresh { drain_ms: 30_000 },
            ]
        );
        assert_eq!(
            states.get("s1"),
            Some(BindState::Bound {
                workers_serving: 2,
                workers: 2
            })
        );
    }

    #[tokio::test]
    async fn udp_sends_each_worker_its_caps_slot_then_one_slot_socket_per_port() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (w1, seen1) = FakeLink::new(&[]);
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

        for (slot, log) in [(0u32, &seen0), (1, &seen1)] {
            let seen = seen(log);
            assert_eq!(
                seen[0],
                Seen::Caps {
                    stream_id: "u1".into(),
                    caps_gen: 1,
                    slot,
                    total: 0,
                },
                "the region comes before the sockets"
            );
            assert!(matches!(
                &seen[1],
                Seen::Attach { addrs, .. } if addrs.len() == 1
            ));
        }
        assert!(matches!(
            states.get("u1"),
            Some(BindState::Bound {
                workers_serving: 2,
                ..
            })
        ));
        assert_eq!(lock_caps(&plane.caps).memfds(), 1);
        assert!(plane.tcp_handoff_fds().is_empty());
        assert_eq!(plane.udp_handoff_fds().len(), 2, "one per slot");
    }

    #[tokio::test]
    async fn a_udp_rebind_on_the_same_port_waits_for_the_drain_without_an_alert() {
        let (w0, seen0) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        plane.drain_margin = Duration::from_millis(200);
        let pass = PassSettings {
            drain: Duration::ZERO,
            ..PASS
        };
        let port = free_udp_port();
        let before = udp("u1", port);
        plane
            .bind_desired(
                std::slice::from_ref(&before),
                &[],
                STANDALONE,
                pass,
                Trigger::Change,
            )
            .await;
        // A listen-address change that keeps the port.
        let mut after = before.clone();
        after.listen_address = "0.0.0.0".parse().unwrap();

        let mut events = plane
            .release_stale(std::slice::from_ref(&after), STANDALONE, pass)
            .await;
        events.extend(
            plane
                .bind_desired(
                    std::slice::from_ref(&after),
                    &[],
                    STANDALONE,
                    pass,
                    Trigger::Change,
                )
                .await,
        );

        assert!(
            matches!(
                events.as_slice(),
                [PlaneEvent::Released {
                    cause: ReleaseCause::Rebind,
                    ..
                }]
            ),
            "no bind and no failure while the old binding drains: {events:?}"
        );
        assert_eq!(states.get("u1"), Some(BindState::Pending));
        assert!(plane.has_retryable_failure());
        assert_eq!(
            lock_caps(&plane.caps).memfds(),
            1,
            "a rebind keeps the stream's region"
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        let retried = plane
            .bind_desired(
                std::slice::from_ref(&after),
                &[],
                STANDALONE,
                pass,
                Trigger::RetryTick,
            )
            .await;
        assert!(
            matches!(retried.as_slice(), [PlaneEvent::Bound { bind_gen: 2, .. }]),
            "{retried:?}"
        );
        assert!(!plane.has_retryable_failure());
        assert!(matches!(
            seen(&seen0).as_slice(),
            [
                Seen::Caps { caps_gen: 1, .. },
                Seen::Attach { bind_gen: 1, .. },
                Seen::Refresh { .. },
                Seen::Detach { .. },
                Seen::Refresh { .. },
                Seen::Caps { caps_gen: 1, .. },
                Seen::Attach { bind_gen: 2, .. },
            ]
        ));

        // Deleted: the binding drains and the region is retired.
        plane.release_stale(&[], STANDALONE, pass).await;
        plane
            .bind_desired(&[], &[], STANDALONE, pass, Trigger::Change)
            .await;
        assert_eq!(lock_caps(&plane.caps).memfds(), 0);
        assert!(states.get("u1").is_none());
    }

    #[tokio::test]
    async fn a_tcp_binding_never_waits_for_a_draining_udp_one() {
        let (w0, _) = FakeLink::new(&[]);
        let (mut plane, states) = plane(vec![w0]);
        let port = free_ports(1);
        let u = udp("u1", port);
        plane
            .bind_desired(
                std::slice::from_ref(&u),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;
        plane.release_stale(&[], STANDALONE, PASS).await;
        let t = tcp("t1", port);

        plane
            .bind_desired(
                std::slice::from_ref(&t),
                &[],
                STANDALONE,
                PASS,
                Trigger::Change,
            )
            .await;

        assert!(matches!(states.get("t1"), Some(BindState::Bound { .. })));
    }
}
