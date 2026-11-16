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

//! The binary's side of the stream engines (Story 12.3 D-a, Lot D2):
//! the three seams `lorica-stream` cannot implement itself, over the
//! code HTTP already runs.
//!
//! - [`StreamSelector`]: [`select_index`], HTTP's selection function,
//!   with state of its own: one smooth weighted round-robin state per
//!   stream and rule (Story 12.4 I3), a least-connections count fed by
//!   the engine's connects and
//!   closes, and a latency tracker fed connect latency (D-e). Never
//!   HTTP's instances, so a backend shared by a route and a stream is
//!   balanced for each by its own traffic.
//! - [`StreamBreakerGate`]: the process's [`BreakerEngine`], HTTP's
//!   registry, keyed `stream:<id>` (D-g). The slot is late-bound
//!   because a worker creates its RPC endpoint after its stream runtime;
//!   an empty slot admits, the fail-open policy of an RPC failure.
//! - [`HickoryResolve`]: `hickory-resolver` from the system
//!   configuration with the hosts file, which returns the record TTLs a
//!   TTL-bounded schedule needs (D-n).
//!
//! [`stream_engines`] assembles them into the [`Engines`] a process's
//! stream runtime serves with: a TCP and a UDP engine over one selector
//! and one resolver cache per process, and one counters `Arc` shared by
//! both engines and the runtime handle that snapshots it. The TCP engine
//! terminates and originates TLS with [`stream_tls_parts`]: the process's
//! certificate resolver and public roots (Story 12.4). The stream table
//! carries the client identities of upstream TLS,
//! [`stream_client_identities`].

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::{Resolver, TokioResolver};
use lorica_config::listen_ports::ReservedPorts;
use lorica_config::models::StreamRefusal;
use lorica_config::models::{Backend, Certificate, LoadBalancing, Stream};
use lorica_stream::seams::SeamFuture;
use lorica_stream::{
    Admission, BackendSelector, BreakerGate, Candidate, ClientIdentity, ConnectionObserver,
    Engines, LogObserver, Resolve, ResolveError, Resolved, ResolverCache, SelectionRequest,
    SourceGate, StreamCounters, StreamTable, TcpEngine, TcpEngineParts, TlsParts, UdpEngine,
    UdpEngineParts,
};
use lorica_tls::cert_resolver::{CertResolver, ResolvesServerCertByLocalIp};
use tracing::{info, warn};

use crate::proxy_wiring::lb::{random_seed, select_index, SelectionState};
use crate::proxy_wiring::{
    BackendConnections, BreakerAdmission, BreakerEngine, EwmaTracker, SmoothWrrState,
};

/// The prefix of a stream's circuit-breaker key. A route is keyed by its
/// bare id, so the prefix keeps the two namespaces apart by construction
/// in the one registry they share (D-g).
pub const STREAM_BREAKER_PREFIX: &str = "stream:";

/// The breaker key of `stream_id`: [`STREAM_BREAKER_PREFIX`] and the id.
pub fn stream_breaker_key(stream_id: &str) -> String {
    format!("{STREAM_BREAKER_PREFIX}{stream_id}")
}

/// Per-attempt timeout of the system resolver. With
/// [`RESOLVER_ATTEMPTS`] it keeps a whole lookup inside the resolver
/// cache's `DNS_RESOLVE_TIMEOUT`, so a slow server ends the lookup as
/// hickory's failure rather than the cache's cut.
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(2);

/// Retries after a failed attempt, see [`RESOLVER_TIMEOUT`].
const RESOLVER_ATTEMPTS: usize = 1;

/// The round-robin key of a stream that reads no ClientHello: its links
/// serve no rule, and a rule name is never empty.
const NO_RULE: &str = "";

/// Backend selection for the stream engines, one per process (D-e).
///
/// Round-robin state is kept per (stream, rule) (Story 12.4 I3): the
/// candidates of a TLS stream's connection are the links of the rule it
/// matched, so each rule rotates over its own backends. The rule is read
/// from the last table with [`StreamTable::rule_of`] (a backend serves
/// at most one rule of a stream). Least connections and the latency
/// tracker stay per backend address: a backend's load does not depend
/// on which rule reached it.
pub struct StreamSelector {
    worker_offset: usize,
    /// Stream id, then rule name ([`NO_RULE`] for none), to its state.
    round_robin: parking_lot::Mutex<HashMap<String, HashMap<String, Arc<SmoothWrrState>>>>,
    /// The table of the last [`BackendSelector::table_changed`], which
    /// says which rule a candidate's link serves.
    table: parking_lot::RwLock<Arc<StreamTable>>,
    connections: BackendConnections,
    ewma: EwmaTracker,
}

impl std::fmt::Debug for StreamSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSelector")
            .field("worker_offset", &self.worker_offset)
            .field("streams", &self.round_robin.lock().len())
            .finish_non_exhaustive()
    }
}

impl StreamSelector {
    /// A selector whose round-robin states start at `worker_offset`, the
    /// process id as HTTP's route states do, so workers do not all pick
    /// the same backend first.
    pub fn new(worker_offset: usize) -> Self {
        StreamSelector {
            worker_offset,
            round_robin: parking_lot::Mutex::new(HashMap::new()),
            table: parking_lot::RwLock::new(Arc::new(StreamTable::default())),
            connections: BackendConnections::new(),
            ewma: EwmaTracker::new(),
        }
    }

    /// The round-robin state of the rule the candidates of a connection
    /// of `stream_id` serve, read from the link of the first one:
    /// [`NO_RULE`]'s for a stream without rules, or for a backend the
    /// last table does not link.
    fn round_robin_for(
        &self,
        stream_id: &str,
        candidates: &[Candidate<'_>],
    ) -> Arc<SmoothWrrState> {
        let table = self.table.read();
        let rule = candidates
            .first()
            .and_then(|first| table.rule_of(stream_id, &first.backend.id))
            .unwrap_or(NO_RULE);
        self.round_robin_of(stream_id, rule)
    }

    fn round_robin_of(&self, stream_id: &str, rule: &str) -> Arc<SmoothWrrState> {
        let mut states = self.round_robin.lock();
        if let Some(state) = states.get(stream_id).and_then(|rules| rules.get(rule)) {
            return Arc::clone(state);
        }
        let state = Arc::new(SmoothWrrState::new(self.worker_offset));
        states
            .entry(stream_id.to_string())
            .or_default()
            .insert(rule.to_string(), Arc::clone(&state));
        state
    }

    /// Open stream connections to `backend` in this process, as
    /// `least_conn` reads them.
    pub fn open_connections(&self, backend: &Backend) -> u64 {
        self.connections.get(&backend.address)
    }

    /// The connect-latency score of `backend` in microseconds, `None`
    /// before its first established connection.
    pub fn latency_score(&self, backend: &Backend) -> Option<f64> {
        self.ewma.scores.get(&backend.address).map(|s| *s)
    }

    /// Whether `stream_id` holds round-robin state, for any rule.
    pub fn holds_round_robin(&self, stream_id: &str) -> bool {
        self.round_robin.lock().contains_key(stream_id)
    }

    /// Whether `stream_id` holds round-robin state for `rule` (`None` for
    /// a stream without rules).
    pub fn holds_rule_round_robin(&self, stream_id: &str, rule: Option<&str>) -> bool {
        self.round_robin
            .lock()
            .get(stream_id)
            .is_some_and(|rules| rules.contains_key(rule.unwrap_or(NO_RULE)))
    }
}

impl BackendSelector for StreamSelector {
    fn select(&self, request: &SelectionRequest<'_>) -> usize {
        let candidates: Vec<&Backend> = request.candidates.iter().map(|c| c.backend).collect();
        // The ring is only read by `consistent_hash`: no allocation for
        // the other algorithms.
        let ring: Option<Vec<String>> =
            matches!(request.stream.load_balancing, LoadBalancing::ConsistentHash).then(|| {
                request
                    .candidates
                    .iter()
                    .map(|c| c.ring_address.to_string())
                    .collect()
            });
        let ring_refs: Option<Vec<&str>> = ring
            .as_ref()
            .map(|ring| ring.iter().map(String::as_str).collect());
        let client = request.client.to_string();
        let round_robin = self.round_robin_for(&request.stream.id, request.candidates);
        let index = select_index(
            &request.stream.load_balancing,
            &candidates,
            ring_refs.as_deref(),
            Some(&client),
            random_seed(&request.accepted_at),
            SelectionState {
                wrr: &round_robin,
                ewma: &self.ewma,
                connections: &self.connections,
            },
        );
        index.min(candidates.len().saturating_sub(1))
    }

    fn connected(
        &self,
        _stream_id: &str,
        backend: &Backend,
        _address: SocketAddr,
        connect_latency: Duration,
    ) {
        // Keyed by the configured address, which `select_index` reads.
        self.connections.increment(&backend.address);
        self.ewma
            .record(&backend.address, connect_latency.as_secs_f64() * 1e6);
    }

    fn closed(&self, _stream_id: &str, backend: &Backend, _address: SocketAddr) {
        self.connections.decrement(&backend.address);
    }

    fn table_changed(&self, table: &StreamTable) {
        *self.table.write() = Arc::new(table.clone());
        // A stream's state goes with the stream, a rule's with the rule.
        self.round_robin.lock().retain(|id, rules| {
            let Some(stream) = table.stream(id) else {
                return false;
            };
            rules.retain(|rule, _| rule == NO_RULE || stream.match_rule(rule).is_some());
            !rules.is_empty()
        });
        let addresses: HashSet<&str> = table.backends().map(|b| b.address.as_str()).collect();
        self.ewma
            .scores
            .retain(|address, _| addresses.contains(address.as_str()));
    }
}

/// The circuit breaker of the stream engines (D-g): the process's
/// [`BreakerEngine`], once installed.
#[derive(Default)]
pub struct StreamBreakerGate {
    engine: ArcSwapOption<BreakerEngine>,
}

impl std::fmt::Debug for StreamBreakerGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamBreakerGate")
            .field("installed", &self.engine.load().is_some())
            .finish()
    }
}

impl StreamBreakerGate {
    /// A gate with no engine yet: it admits every attempt until
    /// [`StreamBreakerGate::install`].
    pub fn new() -> Self {
        Self::default()
    }

    /// A gate over `engine` from the start.
    pub fn with_engine(engine: BreakerEngine) -> Self {
        let gate = Self::new();
        gate.install(engine);
        gate
    }

    /// Install the engine the gate asks from now on.
    pub fn install(&self, engine: BreakerEngine) {
        self.engine.store(Some(Arc::new(engine)));
    }
}

impl BreakerGate for StreamBreakerGate {
    fn admit<'a>(&'a self, stream_id: &'a str, backend: &'a Backend) -> SeamFuture<'a, Admission> {
        Box::pin(async move {
            let Some(engine) = self.engine.load_full() else {
                return Admission::Allow;
            };
            match engine
                .admit(&stream_breaker_key(stream_id), &backend.address)
                .await
            {
                BreakerAdmission::Allow => Admission::Allow,
                BreakerAdmission::Probe => Admission::AllowProbe,
                BreakerAdmission::Deny => Admission::Deny,
            }
        })
    }

    fn record<'a>(
        &'a self,
        stream_id: &'a str,
        backend: &'a Backend,
        success: bool,
        was_probe: bool,
    ) -> SeamFuture<'a, ()> {
        Box::pin(async move {
            if let Some(engine) = self.engine.load_full() {
                engine
                    .record(
                        &stream_breaker_key(stream_id),
                        &backend.address,
                        success,
                        was_probe,
                    )
                    .await;
            }
        })
    }
}

/// Backend host-name resolution through `hickory-resolver` (D-n).
pub struct HickoryResolve {
    /// The resolver, or why none could be built: every lookup then
    /// fails with that reason, which the resolver cache counts and logs
    /// as any failure.
    resolver: Result<TokioResolver, String>,
}

impl std::fmt::Debug for HickoryResolve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolve")
            .field("configured", &self.resolver.is_ok())
            .finish()
    }
}

impl HickoryResolve {
    /// A resolver from the system configuration (`/etc/resolv.conf`),
    /// with the hosts file always consulted first. An unreadable
    /// configuration is logged here and leaves a resolver whose every
    /// lookup fails: IP-literal backends never need it.
    pub fn from_system_conf() -> Self {
        let resolver = hickory_resolver::system_conf::read_system_conf()
            .map_err(|e| format!("system resolver configuration unreadable: {e}"))
            .and_then(|(config, opts)| Self::build(config, opts));
        if let Err(reason) = &resolver {
            warn!(%reason, "stream backends named by host cannot be resolved");
        }
        HickoryResolve { resolver }
    }

    /// A resolver over an explicit configuration, with the same
    /// timeouts as the system one; the hosts file setting is the
    /// caller's.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Self {
        HickoryResolve {
            resolver: Self::build_with(config, opts),
        }
    }

    fn build(config: ResolverConfig, mut opts: ResolverOpts) -> Result<TokioResolver, String> {
        opts.use_hosts_file = ResolveHosts::Always;
        Self::build_with(config, opts)
    }

    fn build_with(config: ResolverConfig, mut opts: ResolverOpts) -> Result<TokioResolver, String> {
        opts.timeout = RESOLVER_TIMEOUT;
        opts.attempts = RESOLVER_ATTEMPTS;
        Resolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| format!("resolver not built: {e}"))
    }
}

impl Resolve for HickoryResolve {
    fn lookup<'a>(&'a self, host: &'a str) -> SeamFuture<'a, Result<Resolved, ResolveError>> {
        Box::pin(async move {
            let resolver = self
                .resolver
                .as_ref()
                .map_err(|reason| ResolveError(reason.clone()))?;
            let lookup = resolver
                .lookup_ip(host)
                .await
                .map_err(|e| ResolveError(format!("{host}: {e}")))?;
            let addresses: Vec<IpAddr> = lookup.iter().collect();
            // What is left of the TTL: a cached answer is not fresher
            // than its record says.
            let ttl = lookup
                .valid_until()
                .saturating_duration_since(std::time::Instant::now());
            Ok(Resolved { addresses, ttl })
        })
    }
}

/// The node-wide source controls of the stream engines until Story 12.6
/// Lot D builds the gate over the process's connection filter, IP
/// blocklist, WAF whitelist and GeoIP resolver: none, so a stream applies
/// its own controls (CIDRs, GeoIP list with every country unknown, rates
/// and caps) and nothing of the node's.
struct NodeControlsPending;

impl SourceGate for NodeControlsPending {
    fn global(&self, _client: IpAddr) -> Option<StreamRefusal> {
        None
    }

    fn country(&self, _client: IpAddr) -> Option<[u8; 2]> {
        None
    }
}

/// The [`Engines`] of one process's stream runtime: a [`TcpEngine`] and
/// a [`UdpEngine`] over the same parts (Story 12.5 Interface edit E3):
/// one [`StreamSelector`] seeded with the process id, so least
/// connections counts a backend's TCP connections and UDP sessions
/// together and round-robin state is per stream whatever its protocol;
/// `breaker`; one [`ResolverCache`] over `resolver`, so a host named by
/// a TCP and a UDP stream is resolved once; a debug-logging observer;
/// and the node's `reserved_ports` for the local check (`None` when the
/// process was not told them: the stream listen ports are still
/// refused). Both engines and the runtime share one counters `Arc`.
///
/// `tls` is what the TCP engine terminates and originates TLS with
/// (Story 12.4): [`stream_tls_parts`] over the process's certificate
/// resolver, so every reload of that resolver (a renewal, an upload, a
/// hot swap) reaches the next handshake of a terminating stream.
pub fn stream_engines(
    breaker: Arc<StreamBreakerGate>,
    resolver: Arc<dyn Resolve>,
    reserved_ports: Option<ReservedPorts>,
    tls: TlsParts,
) -> Engines {
    let counters = Arc::new(StreamCounters::new());
    let selector = Arc::new(StreamSelector::new(std::process::id() as usize));
    let resolver = ResolverCache::new(resolver, Arc::clone(&counters));
    let observer = Arc::new(LogObserver);
    let source_gate: Arc<dyn SourceGate> = Arc::new(NodeControlsPending);
    let tcp = TcpEngine::with_tls(
        TcpEngineParts {
            selector: Arc::clone(&selector) as Arc<dyn BackendSelector>,
            breaker: Arc::clone(&breaker) as Arc<dyn BreakerGate>,
            resolver: Arc::clone(&resolver),
            counters: Arc::clone(&counters),
            observer: Arc::clone(&observer) as Arc<dyn ConnectionObserver>,
            reserved_ports,
            source_gate: Arc::clone(&source_gate),
        },
        tls,
    );
    let udp = UdpEngine::new(UdpEngineParts {
        selector,
        breaker,
        resolver,
        counters: Arc::clone(&counters),
        observer,
        reserved_ports,
        source_gate,
    });
    Engines {
        tcp: Some(Arc::new(tcp)),
        udp: Some(Arc::new(udp)),
        counters,
    }
}

/// The TLS parts of a process's TCP engine (Story 12.4): `resolver`, the
/// one instance the HTTPS listener answers from and every certificate
/// reload swaps, and the public roots of upstream TLS, read here, once
/// per process ([`lorica_stream::tls::load_public_roots`], which logs a
/// failure and leaves `None`).
pub fn stream_tls_parts(resolver: Arc<CertResolver>) -> TlsParts {
    TlsParts {
        resolver: resolver as Arc<dyn ResolvesServerCertByLocalIp>,
        public_roots: lorica_stream::tls::load_public_roots(),
    }
}

/// The client identities a stream table carries (Story 12.4 D-i): the
/// stored certificate of every `upstream_tls.client_certificate_id` of
/// `streams`, with its key, as [`ClientIdentity`] values by certificate
/// id. `certificate` reads one row from the store.
///
/// A row without a key (a follower the key has not reached, the rule
/// [`crate::reload::cert_data_for_resolver`] applies to the resolver), a
/// missing row, or one that does not decode is left out, so the stream's
/// upstream TLS ends `no_trust` until it arrives; each is logged by id,
/// never with a PEM. A row that cannot be read fails the load, like any
/// other read of the table.
///
/// # Errors
///
/// The first error `certificate` returns.
pub fn stream_client_identities<E>(
    streams: &[Stream],
    mut certificate: impl FnMut(&str) -> Result<Option<Certificate>, E>,
) -> Result<Vec<(String, ClientIdentity)>, E> {
    let mut ids: Vec<&str> = streams
        .iter()
        .filter_map(|stream| {
            stream
                .upstream_tls
                .as_ref()?
                .client_certificate_id
                .as_deref()
        })
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut identities = Vec::with_capacity(ids.len());
    for id in ids {
        match certificate(id)? {
            None => {
                warn!(certificate_id = %id, "stream client certificate not in the store");
            }
            Some(row) if row.key_pem.is_empty() => {
                info!(certificate_id = %id,
                      "stream client certificate held back: no private key on this node yet");
            }
            Some(row) => match ClientIdentity::from_pem(&row.cert_pem, &row.key_pem) {
                Ok(identity) => identities.push((id.to_string(), identity)),
                Err(reason) => {
                    warn!(certificate_id = %id, %reason,
                          "stream client certificate does not load");
                }
            },
        }
    }
    Ok(identities)
}
