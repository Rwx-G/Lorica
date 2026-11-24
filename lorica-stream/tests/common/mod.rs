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

//! The fake seams and fixtures the stream engine tests share: the
//! `lorica-stream` integration tests pull this in with `mod common;`,
//! and the binary's `tests/stream_engine_adapters.rs` with `#[path]`.
//!
//! Every double does the least a test can configure: the selector picks
//! as it is told and records what the engine reports, the breaker admits
//! unless told to deny, hang or probe, the resolver answers the names it
//! holds and hangs on any other, the source gate refuses and places the
//! addresses it is given, and the observer hands everything it hears to
//! the test through [`Observed`].

// Each test crate that includes this module uses a part of it.
#![allow(dead_code)]

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::Utc;
use lorica_config::models::{
    Backend, HealthCheck, HealthStatus, LifecycleState, Stream, StreamBackend, StreamProtocol,
    StreamRefusal,
};
use lorica_shmem::StreamCapsRegion;
use lorica_stream::caps::admitted_cap;
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    Admission, BackendSelector, BreakerGate, CapsRegistry, ConnectOutcome, ConnectionObserver,
    ConnectionRecord, ConnectionTracker, NodeCapsRegions, RefusalRecord, Resolve, ResolveError,
    Resolved, SelectionRequest, SourceGate, StreamTable, StreamTableSource, SuppressedRecord,
};
use lorica_worker::stream_ctl::StreamCtlMsg;
use tokio::sync::mpsc;

/// How long an event the engine owes a test may take before the test
/// calls it lost. It bounds a hang, never a duration: a loaded host
/// delays every event, and no assertion may depend on how much.
pub const EVENT_WAIT: Duration = Duration::from_secs(60);

/// The next value of `rx`, within [`EVENT_WAIT`]; `what` names it in the
/// failure.
pub async fn next<T>(rx: &mut mpsc::UnboundedReceiver<T>, what: &str) -> T {
    tokio::time::timeout(EVENT_WAIT, rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what} in time"))
        .unwrap_or_else(|| panic!("the engine is alive while waiting for {what}"))
}

// ---- backends ------------------------------------------------------------

/// A healthy backend `id` at `address`, named `backend-<id>`, in the
/// normal lifecycle, without active checks or upstream TLS.
pub fn backend(id: &str, address: impl ToString) -> Backend {
    Backend {
        id: id.into(),
        address: address.to_string(),
        name: format!("backend-{id}"),
        group_name: String::new(),
        weight: 1,
        health_status: HealthStatus::Healthy,
        health_check_enabled: false,
        health_check_interval_s: 10,
        health_check_path: None,
        health_check: HealthCheck::default(),
        lifecycle_state: LifecycleState::Normal,
        active_connections: 0,
        tls_upstream: false,
        tls_skip_verify: false,
        tls_sni: None,
        h2_upstream: false,
        managed_by: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// ---- selection -----------------------------------------------------------

/// How a [`Selector`] picks among the candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// The first candidate (backend id order).
    First,
    /// The candidate with the fewest connections or sessions open.
    FewestSessions,
    /// A hash of the client address.
    ClientHash,
}

/// Picks as told, and records the clients it was asked for and the
/// backends the engine reports connected and closed.
pub struct Selector {
    pick: Pick,
    pub clients: Mutex<Vec<IpAddr>>,
    sessions: Mutex<HashMap<String, i64>>,
    pub connected: Mutex<Vec<String>>,
    pub closed: Mutex<Vec<String>>,
}

impl Selector {
    pub fn new(pick: Pick) -> Self {
        Selector {
            pick,
            clients: Mutex::default(),
            sessions: Mutex::default(),
            connected: Mutex::default(),
            closed: Mutex::default(),
        }
    }

    /// A selector that always takes the first candidate.
    pub fn first() -> Self {
        Selector::new(Pick::First)
    }
}

impl BackendSelector for Selector {
    fn select(&self, request: &SelectionRequest<'_>) -> usize {
        self.clients.lock().unwrap().push(request.client);
        match self.pick {
            Pick::First => 0,
            Pick::FewestSessions => {
                let sessions = self.sessions.lock().unwrap();
                (0..request.candidates.len())
                    .min_by_key(|&i| {
                        sessions
                            .get(&request.candidates[i].backend.id)
                            .copied()
                            .unwrap_or(0)
                    })
                    .unwrap()
            }
            Pick::ClientHash => {
                let mut hasher = DefaultHasher::new();
                request.client.to_string().hash(&mut hasher);
                (hasher.finish() % request.candidates.len() as u64) as usize
            }
        }
    }

    fn connected(&self, _stream_id: &str, backend: &Backend, _: SocketAddr, _: Duration) {
        *self
            .sessions
            .lock()
            .unwrap()
            .entry(backend.id.clone())
            .or_default() += 1;
        self.connected.lock().unwrap().push(backend.id.clone());
    }

    fn closed(&self, _stream_id: &str, backend: &Backend, _: SocketAddr) {
        *self
            .sessions
            .lock()
            .unwrap()
            .entry(backend.id.clone())
            .or_default() -= 1;
        self.closed.lock().unwrap().push(backend.id.clone());
    }
}

// ---- the breaker ---------------------------------------------------------

/// Admits every backend but those it is told to deny, hang on or admit
/// as a half-open probe, and records every outcome reported to it as
/// `(backend id, success, was_probe)`.
#[derive(Default)]
pub struct Breaker {
    pub deny: Mutex<HashSet<String>>,
    pub hang: Mutex<HashSet<String>>,
    pub probe: Mutex<HashSet<String>>,
    pub records: Mutex<Vec<(String, bool, bool)>>,
}

impl Breaker {
    /// This breaker, denying `backend_id`.
    pub fn denying(self, backend_id: &str) -> Self {
        self.deny.lock().unwrap().insert(backend_id.into());
        self
    }

    /// This breaker, never answering an admission of `backend_id`.
    pub fn hanging(self, backend_id: &str) -> Self {
        self.hang.lock().unwrap().insert(backend_id.into());
        self
    }

    /// This breaker, half-open for `backend_id`: each admission a probe.
    pub fn probing(self, backend_id: &str) -> Self {
        self.probe.lock().unwrap().insert(backend_id.into());
        self
    }

    /// The outcomes reported for `backend_id`, in order.
    pub fn recorded(&self, backend_id: &str) -> Vec<bool> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _, _)| id == backend_id)
            .map(|(_, success, _)| *success)
            .collect()
    }
}

impl BreakerGate for Breaker {
    fn admit<'a>(&'a self, _stream_id: &'a str, backend: &'a Backend) -> SeamFuture<'a, Admission> {
        let (denied, hangs, probes) = (
            self.deny.lock().unwrap().contains(&backend.id),
            self.hang.lock().unwrap().contains(&backend.id),
            self.probe.lock().unwrap().contains(&backend.id),
        );
        Box::pin(async move {
            if hangs {
                std::future::pending::<()>().await;
            }
            if denied {
                Admission::Deny
            } else if probes {
                Admission::AllowProbe
            } else {
                Admission::Allow
            }
        })
    }

    fn record<'a>(
        &'a self,
        _stream_id: &'a str,
        backend: &'a Backend,
        success: bool,
        was_probe: bool,
    ) -> SeamFuture<'a, ()> {
        self.records
            .lock()
            .unwrap()
            .push((backend.id.clone(), success, was_probe));
        Box::pin(async {})
    }
}

// ---- resolution ----------------------------------------------------------

/// Answers the names it holds, hangs on any other: a backend whose name
/// a test never answered stays unresolved.
#[derive(Default)]
pub struct Dns(Mutex<HashMap<String, Vec<IpAddr>>>);

impl Dns {
    /// This resolver, answering `host` with `addresses`.
    pub fn answering(self, host: &str, addresses: Vec<IpAddr>) -> Self {
        self.answer(host, addresses);
        self
    }

    /// Answer `host` with `addresses` from now on.
    pub fn answer(&self, host: &str, addresses: Vec<IpAddr>) {
        self.0.lock().unwrap().insert(host.into(), addresses);
    }
}

impl Resolve for Dns {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        let answer = self.0.lock().unwrap().get(host).cloned();
        Box::pin(async move {
            match answer {
                Some(addresses) => Ok(Resolved {
                    addresses,
                    ttl: Duration::from_secs(30),
                }),
                None => std::future::pending().await,
            }
        })
    }
}

// ---- the node's source controls ------------------------------------------

/// Refuses the addresses it holds; knows the countries it is told. A
/// default gate refuses nobody and places nobody.
#[derive(Default)]
pub struct Gate {
    pub filtered: Mutex<HashSet<IpAddr>>,
    pub blocked: Mutex<HashSet<IpAddr>>,
    pub countries: Mutex<HashMap<IpAddr, [u8; 2]>>,
}

impl SourceGate for Gate {
    fn global(&self, client: IpAddr) -> Option<StreamRefusal> {
        if self.filtered.lock().unwrap().contains(&client) {
            Some(StreamRefusal::ConnectionFilter)
        } else if self.blocked.lock().unwrap().contains(&client) {
            Some(StreamRefusal::IpBlocklist)
        } else {
            None
        }
    }

    fn country(&self, client: IpAddr) -> Option<[u8; 2]> {
        self.countries.lock().unwrap().get(&client).copied()
    }
}

// ---- the observer --------------------------------------------------------

/// A connect outcome as the observer heard it.
pub type Outcome = (String, StreamProtocol, ConnectOutcome);

/// The observer an engine is built with: it hands each record, refusal,
/// suppressed count and connect outcome to its [`Observed`], and notes
/// the tracker's entry count at each record and refusal once the tracker
/// is known.
pub struct Records {
    ended: mpsc::UnboundedSender<ConnectionRecord>,
    refused: mpsc::UnboundedSender<RefusalRecord>,
    suppressed: mpsc::UnboundedSender<SuppressedRecord>,
    outcomes: Arc<Mutex<Vec<Outcome>>>,
    tracker: Arc<OnceLock<ConnectionTracker>>,
    tracked_at_report: Arc<Mutex<Vec<usize>>>,
}

/// What a [`Records`] observer heard, for the test to read.
pub struct Observed {
    pub records: mpsc::UnboundedReceiver<ConnectionRecord>,
    pub refusals: mpsc::UnboundedReceiver<RefusalRecord>,
    pub suppressed: mpsc::UnboundedReceiver<SuppressedRecord>,
    pub outcomes: Arc<Mutex<Vec<Outcome>>>,
    /// The tracker whose entry count each report notes; set it once the
    /// tracker exists.
    pub tracker: Arc<OnceLock<ConnectionTracker>>,
    /// The tracker's entry count at each record and refusal.
    pub tracked_at_report: Arc<Mutex<Vec<usize>>>,
}

/// An observer and what it hears.
pub fn observer() -> (Arc<Records>, Observed) {
    let (ended, records) = mpsc::unbounded_channel();
    let (refused, refusals) = mpsc::unbounded_channel();
    let (held_back, suppressed) = mpsc::unbounded_channel();
    let outcomes: Arc<Mutex<Vec<Outcome>>> = Arc::default();
    let tracker: Arc<OnceLock<ConnectionTracker>> = Arc::default();
    let tracked_at_report: Arc<Mutex<Vec<usize>>> = Arc::default();
    let observer = Records {
        ended,
        refused,
        suppressed: held_back,
        outcomes: Arc::clone(&outcomes),
        tracker: Arc::clone(&tracker),
        tracked_at_report: Arc::clone(&tracked_at_report),
    };
    let observed = Observed {
        records,
        refusals,
        suppressed,
        outcomes,
        tracker,
        tracked_at_report,
    };
    (Arc::new(observer), observed)
}

impl Records {
    fn note_tracked(&self) {
        if let Some(tracker) = self.tracker.get() {
            self.tracked_at_report.lock().unwrap().push(tracker.len());
        }
    }
}

impl ConnectionObserver for Records {
    fn observe(&self, record: ConnectionRecord) {
        self.note_tracked();
        let _ = self.ended.send(record);
    }

    fn connect_outcome(&self, stream_id: &str, protocol: StreamProtocol, outcome: ConnectOutcome) {
        self.outcomes
            .lock()
            .unwrap()
            .push((stream_id.to_string(), protocol, outcome));
    }

    fn refused(&self, record: RefusalRecord) {
        self.note_tracked();
        let _ = self.refused.send(record);
    }

    fn refusals_suppressed(&self, record: SuppressedRecord) {
        let _ = self.suppressed.send(record);
    }
}

// ---- tables and caps regions ---------------------------------------------

/// A table source the test rewrites between loads.
#[derive(Default)]
pub struct Source(pub Mutex<StreamTable>);

impl Source {
    /// A source of `streams` with `links` and no backend rows.
    pub fn with(streams: Vec<Stream>, links: &[StreamBackend]) -> Arc<Self> {
        let source = Arc::new(Source::default());
        source.set(streams, links);
        source
    }

    /// Load `streams` with `links` and no backend rows from now on.
    pub fn set(&self, streams: Vec<Stream>, links: &[StreamBackend]) {
        *self.0.lock().unwrap() = StreamTable::new(streams, links);
    }
}

impl StreamTableSource for Source {
    fn load(&self) -> Result<StreamTable, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Give `stream` its caps region on `node`, a node of one worker, and
/// hand the worker's side to `caps`, as the supervisor does; a stream
/// that already has one keeps it.
pub fn adopt_region(node: &mut NodeCapsRegions, caps: &CapsRegistry, stream: &Stream) {
    let created = node
        .ensure(&stream.id, admitted_cap(stream).unwrap(), 0)
        .unwrap();
    if created.is_some() {
        let Some(StreamCtlMsg::Caps { region, slot, .. }) =
            node.caps_message(&stream.id, 1, 0).unwrap()
        else {
            panic!("test setup: a caps message");
        };
        let region = Arc::new(StreamCapsRegion::open(region).unwrap());
        caps.adopt(&stream.id, region.worker(slot).unwrap());
    }
}
