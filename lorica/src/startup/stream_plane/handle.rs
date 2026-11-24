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

//! The handle every caller drives the plane through: the reload path,
//! the retry tick, the caps tick, the worker monitor, the stop path and
//! the hot upgrade.

use std::sync::Arc;
use std::time::{Duration, Instant};

use lorica_config::models::{Stream, StreamBackend};
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{info, warn};

use super::caps::{lock_caps, release_worker_sessions, SharedCaps};
use super::events::{audit_row, bind_failed_alert};
use super::{
    PassSettings, PlaneEvent, PlaneRole, PlaneWatch, StreamPlane, Trigger, UpgradeDrain,
    WorkerLink, STREAM_BIND_RETRY_INTERVAL, STREAM_CAPS_TICK_INTERVAL,
};
use crate::startup::drain::WORKER_KILL_MARGIN;
use crate::startup::hot_upgrade::StreamHandoffFds;

/// A [`StreamPlane`] shared by the reload path, the retry tick, the
/// worker monitor and the stop path, with what each pass reads (the
/// store, the node's role) and where its events go (the audit chain, the
/// alert channel and, with [`StreamPlaneHandle::with_watch`], the
/// node's stream observability).
pub(crate) struct StreamPlaneHandle<L> {
    plane: Arc<Mutex<StreamPlane<L>>>,
    /// The plane's caps regions, reached without waiting for a pass that
    /// holds the plane on a worker's answer.
    caps: SharedCaps,
    store: Arc<Mutex<ConfigStore>>,
    role: Arc<PlaneRole>,
    audit: Option<lorica_api::server::LogStoreSlot>,
    alerts: lorica_notify::AlertSender,
    watch: Option<Arc<PlaneWatch>>,
}

impl<L> Clone for StreamPlaneHandle<L> {
    fn clone(&self) -> Self {
        StreamPlaneHandle {
            plane: Arc::clone(&self.plane),
            caps: Arc::clone(&self.caps),
            store: Arc::clone(&self.store),
            role: Arc::clone(&self.role),
            audit: self.audit.clone(),
            alerts: self.alerts.clone(),
            watch: self.watch.clone(),
        }
    }
}

impl<L: WorkerLink + 'static> StreamPlaneHandle<L> {
    /// Share `plane`, reading `store` and binding for `role`; `audit` is
    /// where `stream.bind`, `stream.release` and `stream.bind_failed`
    /// rows go, `alerts` where the `stream_bind_failed` alert goes.
    pub(crate) fn new(
        plane: StreamPlane<L>,
        store: Arc<Mutex<ConfigStore>>,
        role: PlaneRole,
        audit: Option<lorica_api::server::LogStoreSlot>,
        alerts: lorica_notify::AlertSender,
    ) -> Self {
        StreamPlaneHandle {
            caps: Arc::clone(&plane.caps),
            plane: Arc::new(Mutex::new(plane)),
            store,
            role: Arc::new(role),
            audit,
            alerts,
            watch: None,
        }
    }

    /// Feed `watch` from every pass and caps tick from now on.
    pub(crate) fn with_watch(mut self, watch: PlaneWatch) -> Self {
        self.watch = Some(Arc::new(watch));
        self
    }

    /// Hand the table as the store holds it now to the watch, if any:
    /// after every pass, so the series and the alert state of a removed
    /// stream go with the change that removed it.
    async fn publish_table(&self) {
        let Some(watch) = &self.watch else {
            return;
        };
        let loaded = {
            let store = self.store.lock().await;
            (
                store.list_streams(),
                store.list_stream_backends(),
                store.list_backends(),
            )
        };
        let (streams, links, backends) = match loaded {
            (Ok(streams), Ok(links), Ok(backends)) => (streams, links, backends),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                warn!(error = %e, "stream plane: configuration unreadable; stream metrics keep the last table");
                return;
            }
        };
        let bound = self.plane.lock().await.ceiling_bound(&streams);
        watch.table_changed(
            lorica_stream::StreamTable::with_backends(streams, &links, backends),
            Some(bound),
        );
    }

    async fn inputs(&self) -> Option<(Vec<Stream>, Vec<StreamBackend>, PassSettings)> {
        let store = self.store.lock().await;
        let streams = store.list_streams();
        let links = store.list_stream_backends();
        let settings = store.get_global_settings();
        match (streams, links, settings) {
            (Ok(streams), Ok(links), Ok(settings)) => {
                Some((streams, links, PassSettings::of(&settings)))
            }
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                warn!(error = %e, "stream plane: configuration unreadable; bindings left as they are");
                None
            }
        }
    }

    /// D-d step 1: before the workers commit a change.
    pub(crate) async fn before_commit(&self) {
        let Some((streams, _, pass)) = self.inputs().await else {
            return;
        };
        let events = self
            .plane
            .lock()
            .await
            .release_stale(&streams, self.role.as_node_role(), pass)
            .await;
        self.record(events).await;
        self.publish_table().await;
    }

    /// D-d step 3: after the workers commit a change, and the first
    /// reconcile at startup.
    pub(crate) async fn after_commit(&self) {
        self.bind_pass(Trigger::Change).await;
    }

    async fn bind_pass(&self, trigger: Trigger) {
        let Some((streams, links, pass)) = self.inputs().await else {
            return;
        };
        let events = self
            .plane
            .lock()
            .await
            .bind_desired(&streams, &links, self.role.as_node_role(), pass, trigger)
            .await;
        self.record(events).await;
        self.publish_table().await;
    }

    /// A backend's health or lifecycle changed (Story 12.3 D-i): every
    /// worker reloads its stream table, so new connections select with
    /// the new health and `close_on_backend_down` streams drain. Not a
    /// configuration change: no binding moves and the reload path is not
    /// woken.
    pub(crate) async fn refresh_tables(&self) {
        let pass = {
            let store = self.store.lock().await;
            match store.get_global_settings() {
                Ok(settings) => PassSettings::of(&settings),
                Err(e) => {
                    warn!(error = %e, "stream plane: settings unreadable; stream tables not refreshed");
                    return;
                }
            }
        };
        self.plane.lock().await.refresh_all(pass).await;
        self.publish_table().await;
    }

    /// The health loop's `on_change` hook: [`Self::refresh_tables`] on a
    /// task of its own, so the loop never waits on a worker's answer.
    pub(crate) fn refresh_hook(&self) -> Arc<dyn Fn() + Send + Sync> {
        let handle = self.clone();
        Arc::new(move || {
            let handle = handle.clone();
            tokio::spawn(async move { handle.refresh_tables().await });
        })
    }

    /// Retry the failures that may have cleared, every
    /// [`STREAM_BIND_RETRY_INTERVAL`], for the life of the process.
    pub(crate) fn spawn_retry_loop(&self) -> tokio::task::JoinHandle<()> {
        let handle = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(STREAM_BIND_RETRY_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await;
            loop {
                tick.tick().await;
                if handle.plane.lock().await.has_retryable_failure() {
                    handle.bind_pass(Trigger::RetryTick).await;
                }
            }
        })
    }

    /// Every [`STREAM_CAPS_TICK_INTERVAL`], for the life of the process:
    /// evict the settled rate cells of every caps region and drop the
    /// retired regions that count no session (D-d), then read the regions
    /// for the watch, if any (Story 12.9).
    pub(crate) fn spawn_caps_tick(&self) -> tokio::task::JoinHandle<()> {
        let caps = Arc::clone(&self.caps);
        let watch = self.watch.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(STREAM_CAPS_TICK_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                lock_caps(&caps).tick(lorica_shmem::now_ns());
                if let Some(watch) = &watch {
                    watch.tick(&caps);
                }
            }
        })
    }

    /// Worker `worker` was found dead: release its UDP sessions from
    /// every caps region now, so its share of each stream's cap is free
    /// for the live workers during the respawn backoff, and whether or
    /// not a respawn follows. See [`StreamPlane::release_worker`].
    pub(crate) fn worker_lost(&self, worker: u32) -> u64 {
        release_worker_sessions(&self.caps, worker)
    }

    /// A worker came back: replay the live bindings to it.
    pub(crate) async fn replay(&self, worker: u32, link: L) {
        let Some((_, _, pass)) = self.inputs().await else {
            return;
        };
        self.plane
            .lock()
            .await
            .replay_worker(worker, link, pass)
            .await;
    }

    /// The stop path: quiesce every worker for `drain`.
    pub(crate) async fn quiesce(&self, drain: Duration) {
        let events = self.plane.lock().await.quiesce(drain).await;
        self.record(events).await;
    }

    /// The stream sockets to hand over on a hot upgrade: the TCP
    /// listeners (D-j) and the UDP slot sockets (Story 12.11 D-e).
    pub(crate) async fn handoff_fds(&self) -> StreamHandoffFds {
        let plane = self.plane.lock().await;
        StreamHandoffFds {
            tcp: plane.tcp_handoff_fds(),
            udp: plane.udp_handoff_fds(),
        }
    }

    /// D-b steps 4 to 6 of a hot upgrade's old side (Story 12.11): quiesce
    /// every worker for `drain` with reason `upgrade`, then `terminate`
    /// them, which SIGTERMs, waits and SIGKILLs past the bound it is
    /// given, `drain` plus [`WORKER_KILL_MARGIN`], and says whether every
    /// worker exited by itself; then read the reports the workers left.
    /// `terminate` blocks, so it runs off the runtime's worker threads:
    /// the supervisor tasks the draining workers call keep being served.
    pub(crate) async fn drain_for_upgrade(
        &self,
        drain: Duration,
        terminate: impl FnOnce(Duration) -> bool + Send + 'static,
    ) -> UpgradeDrain {
        self.plane.lock().await.quiesce_for_upgrade(drain).await;
        let started = Instant::now();
        let bound = drain + WORKER_KILL_MARGIN;
        let clean = match tokio::task::spawn_blocking(move || terminate(bound)).await {
            Ok(clean) => clean,
            Err(e) => {
                warn!(error = %e, "upgrade drain: the worker wait failed; counted as killed");
                false
            }
        };
        let drain_secs = started.elapsed().as_secs_f64();
        let reports = self.plane.lock().await.collect_drain_reports().await;
        UpgradeDrain {
            clean,
            drain_secs,
            reports,
        }
    }

    async fn record(&self, events: Vec<PlaneEvent>) {
        let node = self.role.label();
        for event in events {
            let (action, key, payload) = audit_row(node, &event);
            match &event {
                PlaneEvent::BindFailed {
                    name,
                    kind,
                    os_error,
                    port,
                    ..
                } => {
                    warn!(stream_id = %key.stream_id, kind = kind.as_str(), %os_error,
                          "stream bind failed");
                    self.alerts.send(bind_failed_alert(
                        node,
                        &key.stream_id,
                        name,
                        *kind,
                        os_error,
                        *port,
                    ));
                }
                _ => info!(stream_id = %key.stream_id, action, "stream plane"),
            }
            if let Some(slot) = &self.audit {
                lorica_api::audit::record_with_store(
                    slot.store(),
                    &lorica_api::audit::AuditContext::node("stream-plane"),
                    action,
                    ("stream", &key.stream_id),
                    None,
                    Some(&payload),
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use lorica_stream::BindState;

    use super::*;
    use crate::startup::stream_plane::test_support::{free_ports, plane, reserved, tcp, FakeLink};

    #[tokio::test]
    async fn a_failed_bind_raises_one_alert_per_entry_never_per_retry() {
        let first = free_ports(1);
        let squatter = TcpListener::bind(("127.0.0.1", first)).unwrap();
        let mut s = tcp("6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c3d", first);
        s.name = "pg".into();
        let store = ConfigStore::open_in_memory().expect("test setup: store");
        store.create_stream(&s).expect("test setup: stream");
        let alerts = lorica_notify::AlertSender::new(16);
        let mut received = alerts.subscribe();
        let (w0, _) = FakeLink::new(&[]);
        let (plane, states) = plane(vec![w0]);
        // A follower binds a fleet-wide stream, and the alert names the
        // node by its roster name.
        let handle = StreamPlaneHandle::new(
            plane,
            Arc::new(Mutex::new(store)),
            PlaneRole::Follower("edge01".into()),
            None,
            alerts,
        );

        handle.after_commit().await;
        handle.bind_pass(Trigger::RetryTick).await;
        handle.after_commit().await;

        let alert = received.try_recv().expect("one alert");
        assert_eq!(
            alert.alert_type,
            lorica_notify::events::AlertType::StreamBindFailed
        );
        let detail = |key: &str| alert.details.get(key).map(String::as_str);
        assert_eq!(detail("stream_id"), Some(s.id.as_str()));
        assert_eq!(detail("stream_name"), Some("pg"));
        assert_eq!(detail("node"), Some("edge01"));
        assert_eq!(detail("kind"), Some("address_in_use"));
        assert_eq!(detail("port"), Some(first.to_string().as_str()));
        let os_error = detail("os_error").expect("the OS error");
        assert!(os_error.contains("os error"), "{os_error}");
        assert!(alert.summary.contains("`pg`"), "{}", alert.summary);
        assert!(
            received.try_recv().is_err(),
            "a retry or a change that fails again raises nothing"
        );

        // A recovery then a new failure is a new entry.
        drop(squatter);
        handle.bind_pass(Trigger::RetryTick).await;
        assert!(matches!(states.get(&s.id), Some(BindState::Bound { .. })));
        handle
            .store
            .lock()
            .await
            .update_stream(&Stream {
                port_first: reserved().http,
                port_last: reserved().http,
                ..s.clone()
            })
            .expect("test setup: move onto a reserved port");
        handle.before_commit().await;
        handle.after_commit().await;
        let again = received.try_recv().expect("a second entry alerts again");
        assert_eq!(
            again.details.get("kind").map(String::as_str),
            Some("reserved_port")
        );
    }
}
