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

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures_util::stream::StreamExt;
use lorica_config::models::{
    Backend, Exchange, HealthCheck, HealthStatus, LifecycleState, MatchAnchor, PROBE_READ_MAX_BYTES,
};
use lorica_config::ConfigStore;
use once_cell::sync::Lazy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::{timeout, timeout_at};
use tracing::{debug, info, warn};

use lorica::proxy_wiring::{BackendConnections, ProxyConfig};
use lorica::reload::reload_proxy_config;

const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Process-wide HTTP client for backend health probes (v1.5.1
/// audit M-10).
///
/// Pre-fix, `http_probe` built a fresh `reqwest::Client` per
/// invocation - one per backend per probe interval (default 5 s).
/// Each build allocated a connection pool, TLS context, resolver
/// state, and forced a fresh TCP handshake (no idle-pool reuse)
/// plus a TLS context setup on every probe ; with 100 backends and
/// a 5 s interval that was 20 client builds / s plus the connection
/// churn. Mirrors the static-client precedent in
/// `proxy_wiring/mirror_rewrite.rs::MIRROR_CLIENT` and
/// `proxy_wiring/forward_auth.rs::FORWARD_AUTH_CLIENT`.
///
/// Certificate verification is off (`http_client::unverified`) because
/// operator backends commonly run with self-signed or wildcard certs
/// that the proxy is not expected to validate (this is a liveness
/// probe, not an end-to-end TLS chain check). The probe target
/// is the operator-configured backend URL ; the trust boundary
/// is the operator's network, not the public internet.
static HEALTH_HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    lorica_tls::http_client::client_builder(lorica_tls::http_client::unverified())
        .timeout(TCP_CONNECT_TIMEOUT)
        .pool_max_idle_per_host(8)
        .build()
        .expect("build health-probe reqwest client (static config is infallible)")
});

/// Default drain timeout before force-closing a Closing backend.
const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Latency threshold above which a backend is considered degraded (ms).
const DEGRADED_THRESHOLD_MS: u128 = 2000;

/// Consecutive probes reporting the same new status required before the health
/// loop commits a backend status flip. Prevents a single transient probe
/// failure (or a brief latency spike) from yanking a backend out of rotation
/// for a full interval. The absolute confirmation time is this value times the
/// operator's `health_check_interval_s`.
const HEALTH_FLIP_THRESHOLD: u32 = 3;

/// How many of the bytes a send/expect probe read the confirmed-Down
/// log line shows (Story 12.7, D-10).
const LOGGED_READ_BYTES: usize = 64;

/// Result of a single health check probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// The probe succeeded within the degraded threshold.
    Healthy,
    /// The probe succeeded but took longer than the degraded threshold.
    Degraded,
    /// The probe failed, for this reason.
    Down(ProbeFailure),
}

impl ProbeResult {
    pub fn to_health_status(&self) -> HealthStatus {
        match self {
            ProbeResult::Healthy => HealthStatus::Healthy,
            ProbeResult::Degraded => HealthStatus::Degraded,
            ProbeResult::Down(_) => HealthStatus::Down,
        }
    }
}

/// Why a probe failed, over every probe kind (Story 12.7, D-10). A
/// closed set: it is the `reason` label of
/// `lorica_backend_health_probe_failures_total`, so a word published
/// anywhere is read from [`strum::VariantArray::VARIANTS`] and spelled
/// by `IntoStaticStr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::VariantArray, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum ProbeFailure {
    /// The TCP connection was refused or failed.
    ConnectFailed,
    /// The TCP connection did not complete before the deadline.
    ConnectTimeout,
    /// The bytes to send could not be written before the deadline.
    SendFailed,
    /// Reading the answer failed (a reset, for one).
    ReadFailed,
    /// No byte was read before the deadline.
    ResponseTimeout,
    /// The backend closed the connection before sending a byte.
    ClosedBeforeMatch,
    /// Bytes were read and none of the expected answers matched them,
    /// by end of stream, full buffer, early mismatch or deadline.
    NoMatch,
    /// The HTTP check got an answer outside 2xx.
    HttpStatus,
    /// The HTTP check got no answer.
    HttpFailed,
}

impl ProbeFailure {
    /// The snake_case word this reason is published as.
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

/// The bytes a probe read, as much of them as the log line shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReadSample {
    /// How many bytes the probe read.
    total: usize,
    /// The first [`LOGGED_READ_BYTES`] of them.
    head: Vec<u8>,
}

impl ReadSample {
    fn of(read: &[u8]) -> Self {
        Self {
            total: read.len(),
            head: read[..read.len().min(LOGGED_READ_BYTES)].to_vec(),
        }
    }
}

/// One probe's result and what it read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeOutcome {
    result: ProbeResult,
    read: ReadSample,
}

impl ProbeOutcome {
    /// The outcome of a probe that reads nothing it reports.
    fn reading_nothing(result: ProbeResult) -> Self {
        Self {
            result,
            read: ReadSample::default(),
        }
    }

    fn down(reason: ProbeFailure, read: &[u8]) -> Self {
        Self {
            result: ProbeResult::Down(reason),
            read: ReadSample::of(read),
        }
    }
}

/// How often the health loop wakes to run a cycle: the drain pass, and
/// the probes of the backends due one.
const HEALTH_LOOP_TICK: Duration = Duration::from_secs(1);

/// The shortest pause between two probes of one backend, whatever its
/// `health_check_interval_s` says.
const MIN_PROBE_INTERVAL: Duration = Duration::from_secs(5);

/// Run TCP health checks and backend drain monitoring in a loop.
///
/// - Health checks: probe each backend, update status (Healthy/Degraded/Down)
/// - Drain checks: transition Closing backends to Closed when connections reach 0 or timeout expires
///
/// A cycle runs every [`HEALTH_LOOP_TICK`] and probes the backends due
/// a probe (`take_due`): each one at its own `health_check_interval_s`,
/// never more often than [`MIN_PROBE_INTERVAL`].
///
/// `on_change` is called once per cycle that persisted a confirmed
/// health flip or a lifecycle transition, beside the `config_reload_tx`
/// signal: the stream plane's table refresh (Story 12.3 D-i), which is
/// not a configuration change and must not wake the reload path.
pub async fn health_check_loop(
    store: Arc<Mutex<ConfigStore>>,
    proxy_config: Arc<ArcSwap<ProxyConfig>>,
    backend_connections: Option<Arc<BackendConnections>>,
    alert_sender: Option<lorica_notify::AlertSender>,
    config_reload_tx: Option<tokio::sync::broadcast::Sender<u64>>,
    on_change: Option<Arc<dyn Fn() + Send + Sync>>,
) {
    let health = HealthLoop {
        store,
        proxy_config,
        backend_connections,
        alert_sender,
        config_reload_tx,
        on_change,
    };
    let mut state = HealthLoopState::default();
    let mut ticks = tokio::time::interval_at(
        tokio::time::Instant::now() + HEALTH_LOOP_TICK,
        HEALTH_LOOP_TICK,
    );
    // A cycle outlasting a tick (a probe waiting out its timeout) must
    // not be followed by a burst of catch-up cycles.
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticks.tick().await;
        run_health_cycle(&health, &mut state, Instant::now()).await;
    }
}

/// What every health cycle reads and notifies, fixed for the loop's
/// life.
struct HealthLoop {
    store: Arc<Mutex<ConfigStore>>,
    proxy_config: Arc<ArcSwap<ProxyConfig>>,
    backend_connections: Option<Arc<BackendConnections>>,
    alert_sender: Option<lorica_notify::AlertSender>,
    config_reload_tx: Option<tokio::sync::broadcast::Sender<u64>>,
    on_change: Option<Arc<dyn Fn() + Send + Sync>>,
}

/// What the health loop carries from one cycle to the next.
#[derive(Default)]
struct HealthLoopState {
    /// When each backend was first seen Closing, for the drain timeout.
    drain_start: HashMap<String, Instant>,
    /// An in-progress health-status flip per backend (candidate status
    /// and consecutive-confirmation count), so a transient probe blip
    /// does not flip the stored status. See `confirm_status_flip` and
    /// `HEALTH_FLIP_THRESHOLD`.
    pending_health: HashMap<String, (HealthStatus, u32)>,
    /// When the last probe of each backend started, which decides when
    /// it is due the next one (`take_due`).
    last_probe: HashMap<String, Instant>,
}

impl HealthLoopState {
    /// Drop everything tracked for a backend absent from `backends`,
    /// so a deleted backend leaves nothing behind.
    fn forget_unlisted(&mut self, backends: &[Backend]) {
        let listed: HashSet<&str> = backends.iter().map(|b| b.id.as_str()).collect();
        self.drain_start
            .retain(|id, _| listed.contains(id.as_str()));
        self.pending_health
            .retain(|id, _| listed.contains(id.as_str()));
        self.last_probe.retain(|id, _| listed.contains(id.as_str()));
    }
}

/// The pause `backend` asks for between two of its probes: its own
/// `health_check_interval_s`, never below [`MIN_PROBE_INTERVAL`].
fn probe_interval(backend: &Backend) -> Duration {
    let own = u64::try_from(backend.health_check_interval_s).unwrap_or(0);
    Duration::from_secs(own).max(MIN_PROBE_INTERVAL)
}

/// The backends of `eligible` due a probe at `now`: never probed yet,
/// or whose last probe started at least their [`probe_interval`]
/// before `now`. Each one returned is recorded as probed at `now`.
///
/// The interval is read from the backend as listed this cycle, so an
/// edited interval acts from the next probe.
fn take_due(
    last_probe: &mut HashMap<String, Instant>,
    eligible: Vec<Backend>,
    now: Instant,
) -> Vec<Backend> {
    let mut due = Vec::new();
    for backend in eligible {
        let is_due = last_probe
            .get(&backend.id)
            .is_none_or(|last| now.saturating_duration_since(*last) >= probe_interval(&backend));
        if is_due {
            last_probe.insert(backend.id.clone(), now);
            due.push(backend);
        }
    }
    due
}

/// One health cycle at `now`: list the backends, close the drained
/// ones, probe the eligible ones due a probe, persist the confirmed
/// flips, and signal the reload when anything was persisted. Returns
/// whether it was.
async fn run_health_cycle(health: &HealthLoop, state: &mut HealthLoopState, now: Instant) -> bool {
    let backends = {
        let store = health.store.lock().await;
        match store.list_backends() {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "failed to list backends for health check");
                return false;
            }
        }
    };
    state.forget_unlisted(&backends);

    let mut changed = close_drained_backends(health, state, &backends).await;

    // --- Phase A: probe the eligible backends due a probe, concurrently ---
    // Clone them so each probe future owns its data; this keeps the
    // spawned `health_check_loop` future free of borrows that the stream
    // combinators cannot prove `Send` across the await points.
    let eligible: Vec<Backend> = backends
        .iter()
        .filter(|b| b.lifecycle_state != LifecycleState::Closing && b.health_check_enabled)
        .cloned()
        .collect();
    let due = take_due(&mut state.last_probe, eligible, now);
    // One slow or timing-out backend must not delay every other backend's
    // probe. Bound concurrency with the operator-tunable
    // `health_max_concurrent_probes` (default 32).
    let max_concurrent = if due.is_empty() {
        1
    } else {
        let store = health.store.lock().await;
        store
            .get_global_settings()
            .map(|s| s.health_max_concurrent_probes.clamp(1, 512) as usize)
            .unwrap_or(32)
    };
    let probe_results: Vec<(Backend, ProbeOutcome)> = futures_util::stream::iter(due)
        .map(|backend| async move {
            let outcome = probe(&backend).await;
            if let ProbeResult::Down(reason) = outcome.result {
                lorica_api::metrics::inc_backend_health_probe_failure(&backend.id, reason.as_str());
            }
            (backend, outcome)
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    // --- Phase B: apply flip hysteresis (sequential) ---
    // `pending_health` is single-threaded loop state, so the decision runs
    // sequentially over the collected probe outcomes. Only confirmed flips
    // (the new status observed HEALTH_FLIP_THRESHOLD times in a row) are
    // carried forward; a transient probe blip is absorbed.
    let mut commits: Vec<HealthFlip> = Vec::new();
    for (backend, outcome) in probe_results {
        if confirm_status_flip(
            &mut state.pending_health,
            &backend.id,
            &backend.health_status,
            &outcome.result.to_health_status(),
            HEALTH_FLIP_THRESHOLD,
        ) {
            commits.push(HealthFlip { backend, outcome });
        }
    }

    changed |= persist_health_flips(health, &commits).await;

    if changed {
        if let Err(e) = reload_proxy_config(&health.store, &health.proxy_config, None).await {
            warn!(error = %e, "failed to reload proxy config after health check");
        }
        // Notify workers to reload their proxy config with updated health statuses
        if let Some(ref tx) = health.config_reload_tx {
            let _ = tx.send(0);
        }
        if let Some(ref on_change) = health.on_change {
            on_change();
        }
    }
    changed
}

/// Phase 0, drain monitoring (sequential): move each `Closing` backend
/// of `backends` to `Closed` once it is drained or its drain timed out,
/// and clear the drain and flip tracking of the others. Returns whether
/// a transition was persisted.
///
/// Writes the lifecycle state alone, so an edit committed since
/// `backends` was listed survives.
async fn close_drained_backends(
    health: &HealthLoop,
    state: &mut HealthLoopState,
    backends: &[Backend],
) -> bool {
    let mut changed = false;
    for backend in backends {
        if backend.lifecycle_state == LifecycleState::Closing {
            let start = state
                .drain_start
                .entry(backend.id.clone())
                .or_insert_with(Instant::now);

            let active = health
                .backend_connections
                .as_ref()
                .map(|bc| bc.get(&backend.address))
                .unwrap_or(0);

            let timed_out = start.elapsed() >= DEFAULT_DRAIN_TIMEOUT;

            if active == 0 || timed_out {
                let reason = if active == 0 {
                    "all connections drained"
                } else {
                    "drain timeout expired"
                };
                info!(
                    backend = %backend.address,
                    active_connections = active,
                    reason = reason,
                    "transitioning backend to Closed"
                );

                let store = health.store.lock().await;
                if let Err(e) = store.set_backend_lifecycle_state(
                    &backend.id,
                    &LifecycleState::Closed,
                    chrono::Utc::now(),
                ) {
                    warn!(
                        backend = %backend.address,
                        error = %e,
                        "failed to transition backend to Closed"
                    );
                } else {
                    changed = true;
                    state.drain_start.remove(&backend.id);
                }
            }
            continue;
        }

        // Clean up drain tracking for non-Closing backends.
        state.drain_start.remove(&backend.id);
        // A backend that is not health-checked keeps no flip streak.
        if !backend.health_check_enabled {
            state.pending_health.remove(&backend.id);
        }
    }
    changed
}

/// A confirmed status flip: the backend as the cycle listed it, and the
/// probe that confirmed the new status.
struct HealthFlip {
    backend: Backend,
    outcome: ProbeOutcome,
}

/// Phase C: persist confirmed flips under a single lock, and send
/// `BackendDown` for each flip to `Down`. Returns whether a flip was
/// persisted.
///
/// Writes the health status alone, so an edit committed since the
/// probed rows were listed survives.
async fn persist_health_flips(health: &HealthLoop, commits: &[HealthFlip]) -> bool {
    if commits.is_empty() {
        return false;
    }
    let mut changed = false;
    let store = health.store.lock().await;
    for HealthFlip { backend, outcome } in commits {
        let new_status = outcome.result.to_health_status();
        debug!(
            backend = %backend.address,
            old = backend.health_status.as_str(),
            new = new_status.as_str(),
            "backend health status changed"
        );

        // Dispatch backend_down notification on a confirmed transition
        // to Down (not on a transient blip - the hysteresis already
        // filtered those out). The check that failed and why; never
        // a payload, never a byte the backend sent.
        if let ProbeResult::Down(reason) = outcome.result {
            if let Some(ref sender) = health.alert_sender {
                let alert = lorica_notify::AlertEvent::new(
                    lorica_notify::events::AlertType::BackendDown,
                    format!("Backend {} is down", backend.address),
                )
                .with_detail("backend_id", backend.id.clone())
                .with_detail("address", backend.address.clone())
                .with_detail("name", backend.name.clone())
                .with_detail("check", check_label(&backend.health_check))
                .with_detail("reason", reason.as_str());
                // A stream operator learns the flip is theirs from the
                // same alert (Story 12.9 D-h).
                let alert = match linked_stream_names(&store, &backend.id) {
                    Some(streams) => alert.with_detail("streams", streams),
                    None => alert,
                };
                sender.send(alert);
            }
        }

        if let Err(e) = store.set_backend_health_status(&backend.id, &new_status) {
            warn!(
                backend = %backend.address,
                error = %e,
                "failed to update backend health status"
            );
        } else {
            changed = true;
            if let ProbeResult::Down(reason) = outcome.result {
                log_confirmed_down(backend, reason, &outcome.read);
            }
        }
    }
    changed
}

/// The most stream names a `backend_down` alert lists before it counts
/// the rest.
const BACKEND_DOWN_STREAMS_LISTED: usize = 20;

/// The `streams` detail of a `backend_down` alert: the names of the
/// streams linked to `backend_id`, sorted, `None` for a backend no
/// stream uses. A store that cannot be read leaves the detail out
/// rather than the alert.
fn linked_stream_names(store: &ConfigStore, backend_id: &str) -> Option<String> {
    let links = store.list_stream_backends().ok()?;
    let streams = store.list_streams().ok()?;
    let mut names: Vec<String> = streams
        .into_iter()
        .filter(|stream| {
            links
                .iter()
                .any(|link| link.stream_id == stream.id && link.backend_id == backend_id)
        })
        .map(|stream| stream.name)
        .collect();
    names.sort_unstable();
    stream_names_detail(&names)
}

/// `names` as one detail: at most [`BACKEND_DOWN_STREAMS_LISTED`],
/// then `and N more`.
fn stream_names_detail(names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let listed = names
        .iter()
        .take(BACKEND_DOWN_STREAMS_LISTED)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let more = names.len().saturating_sub(BACKEND_DOWN_STREAMS_LISTED);
    Some(if more > 0 {
        format!("{listed} and {more} more")
    } else {
        listed
    })
}

/// What a notification names a check by: its template, or its kind.
fn check_label(check: &HealthCheck) -> &'static str {
    check.template_name().unwrap_or_else(|| check.kind())
}

/// The one line a confirmed flip to `Down` logs (Story 12.7, D-10):
/// once per flip, never per probe, so a backend cannot choose the log
/// write rate. The bytes read are shown for `no_match` only, the first
/// [`LOGGED_READ_BYTES`] of them, escaped.
fn log_confirmed_down(backend: &Backend, reason: ProbeFailure, read: &ReadSample) {
    let first_bytes = if reason == ProbeFailure::NoMatch {
        escape_bytes(&read.head)
    } else {
        String::new()
    };
    info!(
        backend_id = %backend.id,
        address = %backend.address,
        kind = backend.health_check.kind(),
        template = backend.health_check.template_name().unwrap_or("-"),
        reason = reason.as_str(),
        bytes_read = read.total,
        first_bytes = %first_bytes,
        "backend marked down by its health check"
    );
}

/// Printable ASCII kept, every other byte (and the backslash, so the
/// escape reads one way) as `\xNN`.
fn escape_bytes(bytes: &[u8]) -> String {
    let mut escaped = String::with_capacity(bytes.len());
    for &byte in bytes {
        if (0x20..0x7f).contains(&byte) && byte != b'\\' {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("\\x{byte:02x}"));
        }
    }
    escaped
}

/// What one active probe of a backend reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProbeTarget {
    /// A GET of this URL; a 2xx answer is healthy.
    Http {
        /// `http://` or `https://` (after `tls_upstream`), the address,
        /// then the check's path.
        url: String,
    },
    /// A TCP connection to this `host:port`.
    TcpConnect {
        /// The backend's address.
        address: String,
    },
    /// A TCP connection to this `host:port`, then `exchange`.
    TcpExchange {
        /// The backend's address.
        address: String,
        /// What to send and what to expect, within one deadline.
        exchange: Exchange,
    },
}

/// The probe `backend`'s typed check asks for (Story 12.1, D-2).
///
/// Read from `health_check` and never from the deprecated
/// `health_check_path`: the store reconciles the two on read, so for a
/// backend with a path set this is the URL the loop built from the path
/// before 1.11.0, byte for byte.
fn probe_for(backend: &Backend) -> ProbeTarget {
    match &backend.health_check {
        HealthCheck::Http { path } => {
            let scheme = if backend.tls_upstream {
                "https"
            } else {
                "http"
            };
            ProbeTarget::Http {
                url: format!("{scheme}://{}{path}", backend.address),
            }
        }
        HealthCheck::TcpConnect => ProbeTarget::TcpConnect {
            address: backend.address.clone(),
        },
        // A payload that does not decode (only a row no write validated
        // holds one) exchanges nothing: probed by TCP connect, never
        // marked down over bytes it could not send.
        HealthCheck::TcpTemplate { .. } | HealthCheck::TcpSendExpect { .. } => {
            match backend.health_check.exchange() {
                Some(exchange) => ProbeTarget::TcpExchange {
                    address: backend.address.clone(),
                    exchange,
                },
                None => ProbeTarget::TcpConnect {
                    address: backend.address.clone(),
                },
            }
        }
    }
}

/// Probe `backend` the way its check asks.
async fn probe(backend: &Backend) -> ProbeOutcome {
    match probe_for(backend) {
        ProbeTarget::Http { url } => ProbeOutcome::reading_nothing(http_probe(&url).await),
        ProbeTarget::TcpConnect { address } => {
            ProbeOutcome::reading_nothing(tcp_probe(&address).await)
        }
        ProbeTarget::TcpExchange { address, exchange } => {
            send_expect_probe(&address, &exchange).await
        }
    }
}

/// Attempt a TCP connection and measure latency.
/// Returns Healthy if connect < DEGRADED_THRESHOLD_MS, Degraded if slower, Down on failure.
async fn tcp_probe(address: &str) -> ProbeResult {
    let start = Instant::now();
    match timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
        Ok(Ok(_stream)) => {
            let elapsed_ms = start.elapsed().as_millis();
            if elapsed_ms > DEGRADED_THRESHOLD_MS {
                debug!(
                    address = %address,
                    latency_ms = elapsed_ms as u64,
                    threshold_ms = DEGRADED_THRESHOLD_MS as u64,
                    "TCP health check slow - marking degraded"
                );
                ProbeResult::Degraded
            } else {
                ProbeResult::Healthy
            }
        }
        Ok(Err(e)) => {
            debug!(address = %address, error = %e, "TCP health check failed");
            ProbeResult::Down(ProbeFailure::ConnectFailed)
        }
        Err(_) => {
            debug!(address = %address, "TCP health check timed out");
            ProbeResult::Down(ProbeFailure::ConnectTimeout)
        }
    }
}

/// Attempt an HTTP GET and check for a 2xx response.
/// Returns Healthy if response is 2xx within the degraded threshold, Degraded if slow, Down on failure.
///
/// Uses the process-wide [`HEALTH_HTTP_CLIENT`] so successive
/// probes against the same backend reuse an idle TCP connection
/// from the pool instead of paying for a fresh handshake +
/// TLS context setup every time (v1.5.1 audit M-10).
async fn http_probe(url: &str) -> ProbeResult {
    let start = Instant::now();

    match HEALTH_HTTP_CLIENT.get(url).send().await {
        Ok(resp) => {
            let elapsed_ms = start.elapsed().as_millis();
            if !resp.status().is_success() {
                debug!(
                    url = %url,
                    status = resp.status().as_u16(),
                    "HTTP health check non-2xx response"
                );
                return ProbeResult::Down(ProbeFailure::HttpStatus);
            }
            if elapsed_ms > DEGRADED_THRESHOLD_MS {
                debug!(
                    url = %url,
                    latency_ms = elapsed_ms as u64,
                    "HTTP health check slow - marking degraded"
                );
                ProbeResult::Degraded
            } else {
                ProbeResult::Healthy
            }
        }
        Err(e) => {
            debug!(url = %url, error = %e, "HTTP health check failed");
            ProbeResult::Down(ProbeFailure::HttpFailed)
        }
    }
}

/// Connect to `address`, send `exchange.send`, and read until one of
/// `exchange.expect` matches or none can (Story 12.7, D-9).
///
/// One deadline covers the whole probe, connect, write and read, so
/// no probe outlives the check's timeout. The read buffer is the
/// longest expected prefix when every alternative is a prefix, and
/// [`PROBE_READ_MAX_BYTES`] otherwise: a backend dribbling bytes is
/// bounded by the deadline, one flooding them by the buffer. Matching
/// is incremental ([`Matcher`]). The connection is dropped once the
/// answer is decided, with no farewell bytes. A match slower than
/// [`DEGRADED_THRESHOLD_MS`] from the start of the connect is
/// `Degraded`.
async fn send_expect_probe(address: &str, exchange: &Exchange) -> ProbeOutcome {
    let start = Instant::now();
    let deadline = tokio::time::Instant::now() + exchange.timeout;
    let mut stream = match timeout_at(deadline, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            debug!(address = %address, error = %e, "send/expect health check connect failed");
            return ProbeOutcome::down(ProbeFailure::ConnectFailed, &[]);
        }
        Err(_) => return ProbeOutcome::down(ProbeFailure::ConnectTimeout, &[]),
    };
    // A short send must leave at once rather than wait for an ACK.
    if let Err(e) = stream.set_nodelay(true) {
        debug!(address = %address, error = %e, "TCP_NODELAY not set on a health probe");
    }
    if let Some(send) = &exchange.send {
        if !matches!(
            timeout_at(deadline, stream.write_all(send)).await,
            Ok(Ok(()))
        ) {
            return ProbeOutcome::down(ProbeFailure::SendFailed, &[]);
        }
    }

    let mut buffer = vec![0u8; read_budget(&exchange.expect)];
    let mut filled = 0;
    let mut matcher = Matcher::new(&exchange.expect);
    loop {
        let finished = match timeout_at(deadline, stream.read(&mut buffer[filled..])).await {
            Err(_) => {
                let reason = if filled == 0 {
                    ProbeFailure::ResponseTimeout
                } else {
                    ProbeFailure::NoMatch
                };
                return ProbeOutcome::down(reason, &buffer[..filled]);
            }
            Ok(Err(e)) => {
                debug!(address = %address, error = %e, "send/expect health check read failed");
                return ProbeOutcome::down(ProbeFailure::ReadFailed, &buffer[..filled]);
            }
            Ok(Ok(0)) => true,
            Ok(Ok(read)) => {
                filled += read;
                filled == buffer.len()
            }
        };
        match matcher.evaluate(&buffer[..filled], finished) {
            Verdict::NeedMore => {}
            Verdict::Match => {
                return ProbeOutcome {
                    result: healthy_after(start),
                    read: ReadSample::of(&buffer[..filled]),
                }
            }
            Verdict::Mismatch => {
                let reason = if filled == 0 {
                    ProbeFailure::ClosedBeforeMatch
                } else {
                    ProbeFailure::NoMatch
                };
                return ProbeOutcome::down(reason, &buffer[..filled]);
            }
        }
    }
}

/// `Healthy`, or `Degraded` when the probe that started at `start` took
/// longer than [`DEGRADED_THRESHOLD_MS`].
fn healthy_after(start: Instant) -> ProbeResult {
    if start.elapsed().as_millis() > DEGRADED_THRESHOLD_MS {
        ProbeResult::Degraded
    } else {
        ProbeResult::Healthy
    }
}

/// The most bytes a probe expecting `expect` reads: the longest
/// alternative when every one is a prefix (no byte past it can change
/// the answer), [`PROBE_READ_MAX_BYTES`] otherwise, and never more.
fn read_budget(expect: &[(MatchAnchor, Cow<'static, [u8]>)]) -> usize {
    let prefixes_only = expect
        .iter()
        .all(|(anchor, _)| *anchor == MatchAnchor::Prefix);
    let budget = if prefixes_only {
        expect
            .iter()
            .map(|(_, bytes)| bytes.len())
            .max()
            .unwrap_or(0)
    } else {
        PROBE_READ_MAX_BYTES
    };
    budget.clamp(1, PROBE_READ_MAX_BYTES)
}

/// What the bytes read so far say about an expected answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// An alternative matched: the probe is healthy.
    Match,
    /// No alternative matches and none can any more.
    Mismatch,
    /// Nothing decided yet: read again.
    NeedMore,
}

/// Literal matching of the bytes a probe reads against its expected
/// alternatives, any one of them (Story 12.7, D-3): `prefix` when the
/// bytes start with it, `contains` when it occurs anywhere in them.
///
/// Incremental, so its cost does not depend on how the bytes arrive:
/// each call is handed the whole buffer read so far and compares only
/// what earlier calls could not have. A prefix alternative compares the
/// new bytes within its length and is dropped at its first difference;
/// a contains alternative tries only the windows that end in a new
/// byte. Every byte is therefore compared at most an alternative's
/// length times per alternative, whatever the read sizes.
struct Matcher<'a> {
    expect: &'a [(MatchAnchor, Cow<'static, [u8]>)],
    /// Per alternative, whether a prefix alternative still agrees with
    /// every byte read. Always `true` for a contains alternative.
    viable: Vec<bool>,
    /// How much of the buffer earlier calls examined.
    scanned: usize,
    /// Every byte comparison made, so a test can bound them.
    #[cfg(test)]
    comparisons: usize,
}

impl<'a> Matcher<'a> {
    fn new(expect: &'a [(MatchAnchor, Cow<'static, [u8]>)]) -> Self {
        Self {
            expect,
            viable: vec![true; expect.len()],
            scanned: 0,
            #[cfg(test)]
            comparisons: 0,
        }
    }

    #[cfg(test)]
    fn count(&mut self, compared: usize) {
        self.comparisons += compared;
    }

    #[cfg(not(test))]
    fn count(&mut self, _compared: usize) {}

    /// The verdict on `read`, the whole buffer read so far (it only ever
    /// grows between calls). `finished` says no byte will follow (end of
    /// stream, or a full buffer), so `NeedMore` becomes `Mismatch`.
    /// `Mismatch` also comes early, before `finished`, once every
    /// alternative is a prefix the bytes have left.
    fn evaluate(&mut self, read: &[u8], finished: bool) -> Verdict {
        let new_from = self.scanned.min(read.len());
        self.scanned = read.len();
        let expect = self.expect;
        for (index, (anchor, bytes)) in expect.iter().enumerate() {
            let len = bytes.len();
            let matched = match anchor {
                MatchAnchor::Prefix => {
                    if !self.viable[index] {
                        continue;
                    }
                    let end = read.len().min(len);
                    if new_from < end {
                        let agrees = read[new_from..end] == bytes[new_from..end];
                        self.count(end - new_from);
                        if !agrees {
                            self.viable[index] = false;
                            continue;
                        }
                    }
                    read.len() >= len
                }
                MatchAnchor::Contains => {
                    if len == 0 {
                        true
                    } else if read.len() < len {
                        false
                    } else {
                        let first = new_from.saturating_sub(len - 1);
                        let last = read.len() - len;
                        let mut found = false;
                        for window in first..=last {
                            self.count(len);
                            if read[window..window + len] == bytes[..] {
                                found = true;
                                break;
                            }
                        }
                        found
                    }
                }
            };
            if matched {
                return Verdict::Match;
            }
        }
        let an_alternative_can_still_match = expect
            .iter()
            .zip(&self.viable)
            .any(|((anchor, _), viable)| *anchor == MatchAnchor::Contains || *viable);
        if finished || !an_alternative_can_still_match {
            Verdict::Mismatch
        } else {
            Verdict::NeedMore
        }
    }
}

/// Apply flip hysteresis for a single backend probe.
///
/// Returns `true` when `new` differs from `current` and has now been observed
/// `threshold` consecutive times, meaning the status flip should be committed.
/// Otherwise it records the in-progress streak in `pending` and returns
/// `false`. A probe whose result matches `current` clears any pending streak.
fn confirm_status_flip(
    pending: &mut HashMap<String, (HealthStatus, u32)>,
    backend_id: &str,
    current: &HealthStatus,
    new: &HealthStatus,
    threshold: u32,
) -> bool {
    if new == current {
        pending.remove(backend_id);
        return false;
    }
    let streak = match pending.get_mut(backend_id) {
        Some((candidate, count)) if candidate == new => {
            *count += 1;
            *count
        }
        _ => {
            pending.insert(backend_id.to_string(), (new.clone(), 1));
            1
        }
    };
    if streak >= threshold {
        pending.remove(backend_id);
        true
    } else {
        false
    }
}

/// Determine probe result from a latency value (for testing).
#[cfg(test)]
fn classify_latency(connected: bool, latency_ms: u128) -> ProbeResult {
    if !connected {
        ProbeResult::Down(ProbeFailure::ConnectFailed)
    } else if latency_ms > DEGRADED_THRESHOLD_MS {
        ProbeResult::Degraded
    } else {
        ProbeResult::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Latency classification ----

    #[test]
    fn test_classify_latency_healthy() {
        assert_eq!(classify_latency(true, 50), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 0), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 1999), ProbeResult::Healthy);
        assert_eq!(classify_latency(true, 2000), ProbeResult::Healthy);
    }

    #[test]
    fn test_classify_latency_degraded() {
        assert_eq!(classify_latency(true, 2001), ProbeResult::Degraded);
        assert_eq!(classify_latency(true, 5000), ProbeResult::Degraded);
    }

    #[test]
    fn test_classify_latency_down() {
        assert!(matches!(classify_latency(false, 0), ProbeResult::Down(_)));
        assert!(matches!(
            classify_latency(false, 3000),
            ProbeResult::Down(_)
        ));
    }

    #[test]
    fn test_probe_result_to_health_status() {
        assert_eq!(
            ProbeResult::Healthy.to_health_status(),
            HealthStatus::Healthy
        );
        assert_eq!(
            ProbeResult::Degraded.to_health_status(),
            HealthStatus::Degraded
        );
        assert_eq!(
            ProbeResult::Down(ProbeFailure::NoMatch).to_health_status(),
            HealthStatus::Down
        );
    }

    #[tokio::test]
    async fn test_tcp_probe_unreachable_address() {
        // Use a non-routable address to guarantee failure
        let result = tcp_probe("192.0.2.1:1").await;
        assert!(matches!(result, ProbeResult::Down(_)), "{result:?}");
    }

    #[tokio::test]
    async fn test_tcp_probe_invalid_address() {
        let result = tcp_probe("not-a-valid-address").await;
        assert_eq!(result, ProbeResult::Down(ProbeFailure::ConnectFailed));
    }

    #[tokio::test]
    async fn test_tcp_probe_refused() {
        // Localhost on a port nothing is listening on
        let result = tcp_probe("127.0.0.1:1").await;
        assert_eq!(result, ProbeResult::Down(ProbeFailure::ConnectFailed));
    }

    // ---- HTTP probe ----

    #[tokio::test]
    async fn test_http_probe_unreachable() {
        let result = http_probe("http://192.0.2.1:1/healthz").await;
        assert_eq!(result, ProbeResult::Down(ProbeFailure::HttpFailed));
    }

    #[tokio::test]
    async fn test_http_probe_invalid_url() {
        let result = http_probe("not-a-url").await;
        assert_eq!(result, ProbeResult::Down(ProbeFailure::HttpFailed));
    }

    // ---- Probe selection ----

    fn backend_checked_by(path: Option<&str>, tls_upstream: bool) -> Backend {
        let mut backend: Backend = serde_json::from_value(serde_json::json!({
            "id": "b-1",
            "address": "192.0.2.10:8080",
            "weight": 100,
            "health_status": "healthy",
            "health_check_enabled": true,
            "health_check_interval_s": 10,
            "lifecycle_state": "normal",
            "active_connections": 0,
            "tls_upstream": tls_upstream,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .expect("test setup: a backend");
        backend.set_health_check(HealthCheck::reconcile(None, path));
        backend
    }

    /// The URL the loop built before 1.11.0 from `health_check_path`,
    /// kept as the reference the typed probe must reproduce.
    fn url_before_1_11_0(backend: &Backend) -> Option<String> {
        let path = backend.health_check_path.as_ref()?;
        let scheme = if backend.tls_upstream {
            "https"
        } else {
            "http"
        };
        Some(format!("{scheme}://{}{path}", backend.address))
    }

    #[test]
    fn a_backend_read_with_a_path_is_probed_at_the_url_the_path_gave_before() {
        for tls_upstream in [false, true] {
            for path in ["/healthz", "/ready?deep=1", "/"] {
                let backend = backend_checked_by(Some(path), tls_upstream);
                let expected = url_before_1_11_0(&backend).expect("a path is set");
                assert_eq!(
                    probe_for(&backend),
                    ProbeTarget::Http { url: expected },
                    "path {path}, tls_upstream {tls_upstream}"
                );
            }
        }
    }

    #[test]
    fn a_backend_with_no_path_is_probed_by_tcp_connect() {
        let backend = backend_checked_by(None, false);
        assert_eq!(url_before_1_11_0(&backend), None);
        assert_eq!(
            probe_for(&backend),
            ProbeTarget::TcpConnect {
                address: "192.0.2.10:8080".to_string()
            }
        );
    }

    #[test]
    fn the_typed_check_decides_the_probe() {
        let mut backend = backend_checked_by(None, false);
        backend.set_health_check(HealthCheck::Http {
            path: "/typed".to_string(),
        });
        assert_eq!(
            probe_for(&backend),
            ProbeTarget::Http {
                url: "http://192.0.2.10:8080/typed".to_string()
            }
        );
        backend.set_health_check(HealthCheck::TcpConnect);
        assert!(matches!(
            probe_for(&backend),
            ProbeTarget::TcpConnect { .. }
        ));
    }

    // ---- Per-backend cadence ----

    fn backend_probed_every(id: &str, interval_s: i32) -> Backend {
        let mut backend = backend_checked_by(None, false);
        backend.id = id.to_string();
        backend.health_check_interval_s = interval_s;
        backend
    }

    /// How many times each backend of `backends` is probed by one cycle
    /// a second over `seconds` seconds, `edit` applied to the listing
    /// before each cycle (at its second).
    fn probes_over(
        seconds: u64,
        backends: &mut [Backend],
        mut edit: impl FnMut(u64, &mut [Backend]),
    ) -> HashMap<String, usize> {
        let start = Instant::now();
        let mut last_probe = HashMap::new();
        let mut probes: HashMap<String, usize> = HashMap::new();
        for second in 0..seconds {
            edit(second, backends);
            let now = start + Duration::from_secs(second);
            for probed in take_due(&mut last_probe, backends.to_vec(), now) {
                *probes.entry(probed.id).or_default() += 1;
            }
        }
        probes
    }

    #[test]
    fn each_backend_is_probed_at_its_own_interval() {
        let mut backends = [
            backend_probed_every("fast", 5),
            backend_probed_every("slow", 15),
        ];
        let probes = probes_over(30, &mut backends, |_, _| {});
        assert_eq!(probes["fast"], 6);
        assert_eq!(probes["slow"], 2);
    }

    #[test]
    fn an_interval_below_the_floor_is_probed_at_the_floor() {
        let mut backends = [backend_probed_every("eager", 1)];
        let probes = probes_over(30, &mut backends, |_, _| {});
        assert_eq!(
            probes["eager"] as u64,
            30 / MIN_PROBE_INTERVAL.as_secs(),
            "one probe per floor interval"
        );
    }

    #[test]
    fn an_interval_edited_between_cycles_acts_from_the_next_probe() {
        // Probed at 0 every 15 s, shortened to 5 s at second 3: the next
        // probe is the first second at least 5 s after the last one.
        let mut backends = [backend_probed_every("edited", 15)];
        let start = Instant::now();
        let mut last_probe = HashMap::new();
        let mut probed_at = Vec::new();
        for second in 0..12u64 {
            if second == 3 {
                backends[0].health_check_interval_s = 5;
            }
            let now = start + Duration::from_secs(second);
            if !take_due(&mut last_probe, backends.to_vec(), now).is_empty() {
                probed_at.push(second);
            }
        }
        assert_eq!(probed_at, vec![0, 5, 10]);

        // Lengthened from 5 s to 30 s after its probe at 0: not due at 5.
        let mut backends = [backend_probed_every("lengthened", 5)];
        let probes = probes_over(30, &mut backends, |second, listed| {
            if second == 1 {
                listed[0].health_check_interval_s = 30;
            }
        });
        assert_eq!(probes["lengthened"], 1);
    }

    #[test]
    fn a_backend_that_leaves_the_list_leaves_no_state() {
        let kept = backend_probed_every("kept", 5);
        let mut state = HealthLoopState::default();
        let now = Instant::now();
        for id in ["kept", "deleted"] {
            state.drain_start.insert(id.to_string(), now);
            state
                .pending_health
                .insert(id.to_string(), (HealthStatus::Down, 1));
            state.last_probe.insert(id.to_string(), now);
        }

        state.forget_unlisted(std::slice::from_ref(&kept));

        for map_keys in [
            state.drain_start.keys().collect::<Vec<_>>(),
            state.pending_health.keys().collect::<Vec<_>>(),
            state.last_probe.keys().collect::<Vec<_>>(),
        ] {
            assert_eq!(map_keys, vec!["kept"]);
        }
    }

    /// An HTTP backend answering every request `200` and counting them.
    async fn serve_200_counting(
        listener: tokio::net::TcpListener,
        served: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut socket, _)) = listener.accept().await {
            served.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        }
    }

    #[tokio::test]
    async fn a_cycle_probes_only_the_backends_due_a_probe() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup: listener");
        let mut backend = backend_checked_by(Some("/healthz"), false);
        backend.address = listener
            .local_addr()
            .expect("test setup: local address")
            .to_string();
        backend.health_check_interval_s = 15;
        let store = store_holding(&backend).await;
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(serve_200_counting(listener, Arc::clone(&served)));

        let health = health_loop_over(&store);
        let mut state = HealthLoopState::default();
        let start = Instant::now();
        for second in 0..30u64 {
            run_health_cycle(&health, &mut state, start + Duration::from_secs(second)).await;
        }
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    // ---- The cycle's writes ----

    fn health_loop_over(store: &Arc<Mutex<ConfigStore>>) -> HealthLoop {
        HealthLoop {
            store: Arc::clone(store),
            proxy_config: Arc::new(ArcSwap::from_pointee(ProxyConfig::default())),
            backend_connections: None,
            alert_sender: None,
            config_reload_tx: None,
            on_change: None,
        }
    }

    async fn store_holding(backend: &Backend) -> Arc<Mutex<ConfigStore>> {
        let store = ConfigStore::open_in_memory().expect("test setup: in-memory store");
        store
            .create_backend(backend)
            .expect("test setup: backend stored");
        Arc::new(Mutex::new(store))
    }

    async fn stored(store: &Arc<Mutex<ConfigStore>>, id: &str) -> Backend {
        store
            .lock()
            .await
            .get_backend(id)
            .expect("test setup: backend read")
            .expect("test setup: backend present")
    }

    /// What an operator changes on a backend while a cycle probes it.
    fn operator_edit(backend: &mut Backend) {
        backend.weight = 7;
        backend.address = "192.0.2.20:9090".to_string();
        backend.set_health_check(HealthCheck::Http {
            path: "/edited".to_string(),
        });
    }

    async fn edit_stored(store: &Arc<Mutex<ConfigStore>>, id: &str) {
        let mut backend = stored(store, id).await;
        operator_edit(&mut backend);
        store
            .lock()
            .await
            .update_backend(&backend)
            .expect("test setup: operator edit stored");
    }

    fn assert_edit_kept(backend: &Backend) {
        let mut expected = backend.clone();
        operator_edit(&mut expected);
        assert_eq!(backend.weight, expected.weight);
        assert_eq!(backend.address, expected.address);
        assert_eq!(backend.health_check, expected.health_check);
        assert_eq!(backend.health_check_path, expected.health_check_path);
    }

    #[tokio::test]
    async fn a_flip_keeps_an_edit_committed_after_the_cycle_listed_the_backend() {
        let backend = backend_checked_by(None, false);
        let store = store_holding(&backend).await;
        let listed = stored(&store, &backend.id).await;
        edit_stored(&store, &backend.id).await;

        let health = health_loop_over(&store);
        assert!(persist_health_flips(&health, &[flip_down(listed)]).await);

        let after = stored(&store, &backend.id).await;
        assert_eq!(after.health_status, HealthStatus::Down);
        assert_edit_kept(&after);
    }

    /// A confirmed flip to `Down` of `backend` as listed.
    fn flip_down(backend: Backend) -> HealthFlip {
        HealthFlip {
            backend,
            outcome: ProbeOutcome::down(ProbeFailure::ConnectFailed, &[]),
        }
    }

    #[tokio::test]
    async fn a_flip_keeps_a_template_chosen_after_the_cycle_listed_the_backend() {
        let backend = backend_checked_by(None, false);
        let store = store_holding(&backend).await;
        let listed = stored(&store, &backend.id).await;
        let mut switched = listed.clone();
        switched.set_health_check(redis_ping(1_000));
        store
            .lock()
            .await
            .update_backend(&switched)
            .expect("test setup: the operator switches the failing check");

        let health = health_loop_over(&store);
        assert!(persist_health_flips(&health, &[flip_down(listed)]).await);

        let after = stored(&store, &backend.id).await;
        assert_eq!(after.health_status, HealthStatus::Down);
        assert_eq!(after.health_check, redis_ping(1_000));
    }

    #[tokio::test]
    async fn closing_a_drained_backend_keeps_an_edit_committed_after_the_cycle_listed_it() {
        let mut backend = backend_checked_by(None, false);
        backend.lifecycle_state = LifecycleState::Closing;
        let store = store_holding(&backend).await;
        let listed = stored(&store, &backend.id).await;
        edit_stored(&store, &backend.id).await;

        let health = health_loop_over(&store);
        let mut state = HealthLoopState::default();
        assert!(close_drained_backends(&health, &mut state, &[listed]).await);

        let after = stored(&store, &backend.id).await;
        assert_eq!(after.lifecycle_state, LifecycleState::Closed);
        assert_edit_kept(&after);
        assert!(state.drain_start.is_empty());
    }

    #[tokio::test]
    async fn a_flip_of_a_backend_deleted_during_the_cycle_persists_nothing() {
        let backend = backend_checked_by(None, false);
        let store = store_holding(&backend).await;
        let listed = stored(&store, &backend.id).await;
        store
            .lock()
            .await
            .delete_backend(&backend.id)
            .expect("test setup: backend deleted");

        let health = health_loop_over(&store);
        assert!(!persist_health_flips(&health, &[flip_down(listed)]).await);
    }

    /// An HTTP backend answering every request `503`, which commits
    /// [`operator_edit`] to the stored backend `id` while it holds the
    /// `edit_on`-th request, before it answers: an edit made while a
    /// cycle is probing.
    async fn serve_503_editing_during_probe(
        listener: tokio::net::TcpListener,
        store: Arc<Mutex<ConfigStore>>,
        id: String,
        edit_on: usize,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut served = 0;
        while let Ok((mut socket, _)) = listener.accept().await {
            served += 1;
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            if served == edit_on {
                edit_stored(&store, &id).await;
            }
            let _ = socket
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await;
        }
    }

    #[tokio::test]
    async fn a_cycle_keeps_an_edit_committed_while_it_probed_and_signals_the_flip_once() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup: listener");
        let mut backend = backend_checked_by(Some("/healthz"), false);
        backend.address = listener
            .local_addr()
            .expect("test setup: local address")
            .to_string();
        let store = store_holding(&backend).await;
        tokio::spawn(serve_503_editing_during_probe(
            listener,
            Arc::clone(&store),
            backend.id.clone(),
            HEALTH_FLIP_THRESHOLD as usize,
        ));

        let signals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let alerts = lorica_notify::AlertSender::new(16);
        let mut alerts_received = alerts.subscribe();
        let mut health = health_loop_over(&store);
        health.alert_sender = Some(alerts);
        health.on_change = Some({
            let signals = Arc::clone(&signals);
            Arc::new(move || {
                signals.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        });
        let mut state = HealthLoopState::default();
        let start = Instant::now();
        let probe_due = |cycle: u32| start + probe_interval(&backend) * cycle;

        for cycle in 1..HEALTH_FLIP_THRESHOLD {
            assert!(
                !run_health_cycle(&health, &mut state, probe_due(cycle)).await,
                "cycle {cycle} is below the flip threshold"
            );
            assert_eq!(
                stored(&store, &backend.id).await.health_status,
                HealthStatus::Healthy
            );
        }
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert!(run_health_cycle(&health, &mut state, probe_due(HEALTH_FLIP_THRESHOLD)).await);
        let after = stored(&store, &backend.id).await;
        assert_eq!(after.health_status, HealthStatus::Down);
        assert_edit_kept(&after);
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 1);
        let alert = alerts_received.try_recv().expect("one BackendDown alert");
        assert_eq!(
            alert.alert_type,
            lorica_notify::events::AlertType::BackendDown
        );
        assert_eq!(alert.details["check"], "http");
        assert_eq!(alert.details["reason"], ProbeFailure::HttpStatus.as_str());
        assert!(alerts_received.try_recv().is_err());
    }

    // ---- Send/expect (Story 12.7) ----

    fn redis_ping(timeout_ms: u32) -> HealthCheck {
        template_check("redis_ping", timeout_ms)
    }

    fn template_check(name: &str, timeout_ms: u32) -> HealthCheck {
        HealthCheck::TcpTemplate {
            template: lorica_config::models::TcpCheckTemplateName::new(name)
                .expect("test setup: a catalogue template"),
            timeout_ms,
        }
    }

    fn template_exchange(name: &str, timeout_ms: u32) -> Exchange {
        template_check(name, timeout_ms)
            .exchange()
            .expect("a template exchanges bytes")
    }

    /// A custom exchange sending nothing and expecting `expect`.
    fn custom_exchange(expect: Vec<(MatchAnchor, &[u8])>, timeout_ms: u32) -> Exchange {
        HealthCheck::TcpSendExpect {
            send: None,
            expect: expect
                .into_iter()
                .map(|(anchor, bytes)| lorica_config::models::Expectation {
                    anchor,
                    bytes: lorica_config::models::Payload::Text(
                        String::from_utf8(bytes.to_vec()).expect("test setup: text bytes"),
                    ),
                })
                .collect(),
            timeout_ms,
        }
        .exchange()
        .expect("a custom check exchanges bytes")
    }

    fn alternatives(
        expect: &[(MatchAnchor, &'static [u8])],
    ) -> Vec<(MatchAnchor, Cow<'static, [u8]>)> {
        expect
            .iter()
            .map(|(anchor, bytes)| (*anchor, Cow::Borrowed(*bytes)))
            .collect()
    }

    const P: MatchAnchor = MatchAnchor::Prefix;
    const C: MatchAnchor = MatchAnchor::Contains;

    /// (alternatives, bytes read, `finished` after them, verdict).
    #[allow(clippy::type_complexity)] // a vector table reads best inline
    fn evaluate_vectors() -> Vec<(Vec<(MatchAnchor, &'static [u8])>, Vec<u8>, bool, Verdict)> {
        vec![
            (
                vec![(P, b"+PONG")],
                b"+PONG\r\n".to_vec(),
                false,
                Verdict::Match,
            ),
            (
                vec![(P, b"+PONG")],
                b"+PO".to_vec(),
                false,
                Verdict::NeedMore,
            ),
            (
                vec![(P, b"+PONG")],
                b"-ERR".to_vec(),
                false,
                Verdict::Mismatch,
            ),
            (
                vec![(P, b"+PONG")],
                b"+PO".to_vec(),
                true,
                Verdict::Mismatch,
            ),
            (
                vec![(P, b"+PONG"), (P, b"-NOAUTH")],
                b"-NOAUTH Authentication required.\r\n".to_vec(),
                false,
                Verdict::Match,
            ),
            (
                vec![(P, b"+PONG"), (P, b"-NOAUTH")],
                b"-LOADING".to_vec(),
                false,
                Verdict::Mismatch,
            ),
            (
                vec![(P, b"S"), (P, b"N")],
                b"N".to_vec(),
                false,
                Verdict::Match,
            ),
            (
                vec![(P, b"S"), (P, b"N")],
                b"E".to_vec(),
                false,
                Verdict::Mismatch,
            ),
            (
                vec![(C, b"ESMTP")],
                b"220 mail.example.com ESMTP ready\r\n".to_vec(),
                false,
                Verdict::Match,
            ),
            (
                vec![(C, b"ESMTP")],
                b"220 mail.example.com ES".to_vec(),
                false,
                Verdict::NeedMore,
            ),
            (
                vec![(C, b"ESMTP")],
                b"220 mail.example.com ES".to_vec(),
                true,
                Verdict::Mismatch,
            ),
            (
                vec![(P, b"+PONG"), (C, b"LOADING")],
                b"-LOADING Redis is loading".to_vec(),
                false,
                Verdict::Match,
            ),
            (
                vec![(P, b"+PONG"), (C, b"zz")],
                b"-ERR".to_vec(),
                false,
                Verdict::NeedMore,
            ),
            (vec![(C, b"x")], Vec::new(), true, Verdict::Mismatch),
            (
                vec![(C, b"zz")],
                vec![b'a'; PROBE_READ_MAX_BYTES],
                true,
                Verdict::Mismatch,
            ),
        ]
    }

    #[test]
    fn evaluate_decides_the_same_whole_or_one_byte_at_a_time() {
        for (expect, read, finished, verdict) in evaluate_vectors() {
            let expect = alternatives(&expect);
            let whole = Matcher::new(&expect).evaluate(&read, finished);
            assert_eq!(whole, verdict, "{read:?} whole");

            let mut matcher = Matcher::new(&expect);
            let mut dribbled = if read.is_empty() {
                matcher.evaluate(&read, finished)
            } else {
                Verdict::NeedMore
            };
            for end in 1..=read.len() {
                dribbled = matcher.evaluate(&read[..end], finished && end == read.len());
                if dribbled != Verdict::NeedMore {
                    break;
                }
            }
            assert_eq!(dribbled, verdict, "{read:?} one byte at a time");
        }
    }

    #[test]
    fn a_contains_alternative_matches_across_a_read_boundary() {
        let expect = alternatives(&[(C, b"ESMTP")]);
        let answer = b"220 mail.example.com ESMTP\r\n";
        let split = answer
            .windows(5)
            .position(|window| window == b"ESMTP")
            .expect("test setup: the word is in the answer")
            + 2;
        let mut matcher = Matcher::new(&expect);
        assert_eq!(matcher.evaluate(&answer[..split], false), Verdict::NeedMore);
        assert_eq!(matcher.evaluate(answer, false), Verdict::Match);
    }

    /// The worst case of D-3: every alternative as long as allowed and
    /// never matching, a full read buffer fed one byte at a time. A
    /// rescan of the whole buffer after each read would be quadratic in
    /// the read size and blow through the bound.
    #[test]
    fn matching_one_byte_at_a_time_stays_within_its_comparison_bound() {
        use lorica_config::models::{EXPECT_MAX_ALTERNATIVES, EXPECT_MAX_BYTES};
        let mut near_miss = vec![b'b'; EXPECT_MAX_BYTES - 1];
        near_miss.push(b'c');
        let read = vec![b'b'; PROBE_READ_MAX_BYTES];
        let bound = PROBE_READ_MAX_BYTES * EXPECT_MAX_BYTES * EXPECT_MAX_ALTERNATIVES;
        for anchor in [P, C] {
            let expect: Vec<(MatchAnchor, Cow<'static, [u8]>)> = (0..EXPECT_MAX_ALTERNATIVES)
                .map(|_| (anchor, Cow::Owned(near_miss.clone())))
                .collect();
            let mut matcher = Matcher::new(&expect);
            let mut verdict = Verdict::NeedMore;
            for end in 1..=read.len() {
                verdict = matcher.evaluate(&read[..end], end == read.len());
                if verdict != Verdict::NeedMore {
                    break;
                }
            }
            assert_eq!(verdict, Verdict::Mismatch, "{anchor:?}");
            assert!(
                matcher.comparisons <= bound,
                "{anchor:?}: {} comparisons, bound {bound}",
                matcher.comparisons
            );
        }
    }

    #[test]
    fn the_read_buffer_is_the_longest_prefix_or_the_cap() {
        assert_eq!(
            read_budget(&alternatives(&[(P, b"+PONG"), (P, b"-NOAUTH")])),
            7
        );
        assert_eq!(
            read_budget(&alternatives(&[(P, b"+PONG"), (C, b"x")])),
            PROBE_READ_MAX_BYTES
        );
    }

    #[test]
    fn a_failure_reason_is_a_unique_snake_case_word() {
        use strum::VariantArray;
        let words: HashSet<&str> = ProbeFailure::VARIANTS.iter().map(|r| r.as_str()).collect();
        assert_eq!(words.len(), ProbeFailure::VARIANTS.len());
        for word in words {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{word}"
            );
        }
        assert_eq!(ProbeFailure::ResponseTimeout.as_str(), "response_timeout");
    }

    #[test]
    fn logged_bytes_keep_printable_ascii_and_escape_the_rest() {
        assert_eq!(
            escape_bytes(b"-LOADING\r\n\x00\xff\\"),
            "-LOADING\\x0d\\x0a\\x00\\xff\\x5c"
        );
    }

    /// What a scripted backend does on each connection once it has read
    /// the probe's request.
    #[derive(Clone)]
    enum Reply {
        Bytes(&'static [u8]),
        After(Duration, &'static [u8]),
        Silent,
        Close,
        Flood,
    }

    /// A loopback backend that reads `request_len` bytes from each
    /// connection, then plays `reply`. Returns its address.
    async fn scripted_backend(request_len: usize, reply: Reply) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup: listener");
        let address = listener
            .local_addr()
            .expect("test setup: local address")
            .to_string();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(play(socket, request_len, reply.clone()));
            }
        });
        address
    }

    async fn play(mut socket: TcpStream, request_len: usize, reply: Reply) {
        let mut request = vec![0u8; request_len];
        if socket.read_exact(&mut request).await.is_err() {
            return;
        }
        match reply {
            Reply::Bytes(bytes) => {
                let _ = socket.write_all(bytes).await;
            }
            Reply::After(delay, bytes) => {
                tokio::time::sleep(delay).await;
                let _ = socket.write_all(bytes).await;
            }
            Reply::Silent => {}
            Reply::Close => return,
            Reply::Flood => {
                let chunk = vec![b'a'; 64 * 1024];
                for _ in 0..16 {
                    if socket.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            }
        }
        // Hold the connection until the probe drops it.
        let _ = socket.read(&mut [0u8; 1]).await;
    }

    #[tokio::test]
    async fn each_template_is_healthy_against_its_canonical_answer() {
        let cases: [(&str, usize, &'static [u8]); 5] = [
            ("redis_ping", 6, b"+PONG\r\n"),
            ("redis_ping", 6, b"-NOAUTH Authentication required.\r\n"),
            ("smtp_banner", 0, b"220 mail.example.com ESMTP\r\n"),
            ("postgresql_ssl_request", 8, b"S"),
            ("postgresql_ssl_request", 8, b"N"),
        ];
        for (name, request_len, answer) in cases {
            let address = scripted_backend(request_len, Reply::Bytes(answer)).await;
            let outcome = send_expect_probe(&address, &template_exchange(name, 2_000)).await;
            assert_eq!(outcome.result, ProbeResult::Healthy, "{name}: {answer:?}");
        }
    }

    #[tokio::test]
    async fn a_wrong_answer_is_no_match() {
        let cases: [(&str, usize, &'static [u8]); 2] = [
            (
                "redis_ping",
                6,
                b"-LOADING Redis is loading the dataset in memory\r\n",
            ),
            (
                "smtp_banner",
                0,
                b"554 mail.example.com no SMTP service here\r\n",
            ),
        ];
        for (name, request_len, answer) in cases {
            let address = scripted_backend(request_len, Reply::Bytes(answer)).await;
            let outcome = send_expect_probe(&address, &template_exchange(name, 2_000)).await;
            assert_eq!(
                outcome.result,
                ProbeResult::Down(ProbeFailure::NoMatch),
                "{name}: {answer:?}"
            );
            assert!(outcome.read.total > 0);
        }
    }

    #[tokio::test]
    async fn a_silent_backend_is_a_response_timeout_at_the_deadline() {
        let address = scripted_backend(6, Reply::Silent).await;
        let start = Instant::now();
        let outcome = send_expect_probe(&address, &template_exchange("redis_ping", 300)).await;
        let elapsed = start.elapsed();
        assert_eq!(
            outcome.result,
            ProbeResult::Down(ProbeFailure::ResponseTimeout)
        );
        assert!(elapsed >= Duration::from_millis(300), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(1_500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn a_backend_that_closes_is_closed_before_match() {
        let address = scripted_backend(6, Reply::Close).await;
        let outcome = send_expect_probe(&address, &template_exchange("redis_ping", 2_000)).await;
        assert_eq!(
            outcome.result,
            ProbeResult::Down(ProbeFailure::ClosedBeforeMatch)
        );
    }

    #[tokio::test]
    async fn a_refused_port_is_connect_failed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup: listener");
        let address = listener
            .local_addr()
            .expect("test setup: local address")
            .to_string();
        drop(listener);
        let outcome = send_expect_probe(&address, &template_exchange("redis_ping", 2_000)).await;
        assert_eq!(
            outcome.result,
            ProbeResult::Down(ProbeFailure::ConnectFailed)
        );
    }

    #[tokio::test]
    async fn a_flood_is_decided_within_the_read_cap() {
        let address = scripted_backend(0, Reply::Flood).await;
        let outcome = send_expect_probe(&address, &custom_exchange(vec![(C, b"zz")], 2_000)).await;
        assert_eq!(outcome.result, ProbeResult::Down(ProbeFailure::NoMatch));
        assert_eq!(outcome.read.total, PROBE_READ_MAX_BYTES);
        assert_eq!(outcome.read.head.len(), LOGGED_READ_BYTES);

        let address = scripted_backend(0, Reply::Flood).await;
        let outcome =
            send_expect_probe(&address, &custom_exchange(vec![(P, b"+PONG")], 2_000)).await;
        assert_eq!(outcome.result, ProbeResult::Down(ProbeFailure::NoMatch));
        assert!(
            outcome.read.total <= "+PONG".len(),
            "{}",
            outcome.read.total
        );
    }

    #[tokio::test]
    async fn a_slow_match_is_degraded() {
        let delay =
            Duration::from_millis(u64::try_from(DEGRADED_THRESHOLD_MS).expect("fits") + 200);
        let address = scripted_backend(6, Reply::After(delay, b"+PONG\r\n")).await;
        let outcome = send_expect_probe(&address, &template_exchange("redis_ping", 5_000)).await;
        assert_eq!(outcome.result, ProbeResult::Degraded);
    }

    #[test]
    fn a_template_or_a_custom_check_is_probed_by_its_exchange() {
        let mut backend = backend_checked_by(None, false);
        backend.set_health_check(redis_ping(1_000));
        assert_eq!(
            probe_for(&backend),
            ProbeTarget::TcpExchange {
                address: backend.address.clone(),
                exchange: template_exchange("redis_ping", 1_000),
            }
        );
        // A stored payload no write validated exchanges nothing: it is
        // probed by TCP connect rather than marked down.
        backend.set_health_check(HealthCheck::TcpSendExpect {
            send: Some(lorica_config::models::Payload::Hex("0".to_string())),
            expect: Vec::new(),
            timeout_ms: 1_000,
        });
        assert!(matches!(
            probe_for(&backend),
            ProbeTarget::TcpConnect { .. }
        ));
    }

    /// A fake Redis on loopback: the first `answered` connections get
    /// `+PONG`, every later one is accepted and never answered, as a
    /// frozen server whose listen backlog still completes handshakes.
    async fn fake_redis(answered: usize) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test setup: listener");
        let address = listener
            .local_addr()
            .expect("test setup: local address")
            .to_string();
        tokio::spawn(async move {
            let mut accepted = 0;
            while let Ok((socket, _)) = listener.accept().await {
                accepted += 1;
                let reply = if accepted <= answered {
                    Reply::Bytes(b"+PONG\r\n")
                } else {
                    Reply::Silent
                };
                tokio::spawn(play(socket, "PING\r\n".len(), reply));
            }
        });
        address
    }

    /// IV1: a Redis backend that stops answering `PING` while its port
    /// stays open is marked down within the configured thresholds.
    #[tokio::test]
    async fn iv1_a_redis_that_stops_answering_ping_is_marked_down() {
        let mut backend = backend_checked_by(None, false);
        backend.id = "iv1-redis-ping".to_string();
        backend.address = fake_redis(1).await;
        backend.set_health_check(redis_ping(1_000));
        let store = store_holding(&backend).await;

        let alerts = lorica_notify::AlertSender::new(16);
        let mut alerts_received = alerts.subscribe();
        let mut health = health_loop_over(&store);
        health.alert_sender = Some(alerts);
        let mut state = HealthLoopState::default();
        let start = Instant::now();
        let probe_due = |cycle: u32| start + probe_interval(&backend) * cycle;
        let failures = || {
            lorica_api::metrics::backend_health_probe_failures_value(
                &backend.id,
                ProbeFailure::ResponseTimeout.as_str(),
            )
        };
        let failures_before = failures();

        // The first probe is answered.
        assert!(!run_health_cycle(&health, &mut state, probe_due(0)).await);
        assert_eq!(failures(), failures_before);

        for cycle in 1..HEALTH_FLIP_THRESHOLD {
            assert!(!run_health_cycle(&health, &mut state, probe_due(cycle)).await);
            assert_eq!(
                stored(&store, &backend.id).await.health_status,
                HealthStatus::Healthy,
                "cycle {cycle} is below the flip threshold"
            );
            assert_eq!(failures(), failures_before + u64::from(cycle));
        }
        assert!(alerts_received.try_recv().is_err());

        assert!(run_health_cycle(&health, &mut state, probe_due(HEALTH_FLIP_THRESHOLD)).await);
        assert_eq!(
            stored(&store, &backend.id).await.health_status,
            HealthStatus::Down
        );
        assert_eq!(
            failures(),
            failures_before + u64::from(HEALTH_FLIP_THRESHOLD)
        );
        let alert = alerts_received.try_recv().expect("one BackendDown alert");
        assert_eq!(
            alert.alert_type,
            lorica_notify::events::AlertType::BackendDown
        );
        assert_eq!(alert.details["check"], "redis_ping");
        assert_eq!(
            alert.details["reason"],
            ProbeFailure::ResponseTimeout.as_str()
        );
        assert!(alerts_received.try_recv().is_err());
    }

    // ---- Flip hysteresis ----

    #[test]
    fn flip_requires_consecutive_confirmations() {
        let mut pending = HashMap::new();
        // Two failures under the threshold of 3 do not flip.
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
        // Third consecutive failure commits the flip and clears the streak.
        assert!(confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
        assert!(pending.is_empty());
    }

    #[test]
    fn flip_streak_resets_when_probe_matches_current() {
        let mut pending = HashMap::new();
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
        // A probe back at the current status clears the pending Down streak.
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Healthy,
            3
        ));
        assert!(pending.is_empty());
        // The next Down therefore starts over: one failure must not flip.
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
    }

    #[test]
    fn flip_streak_resets_when_candidate_changes() {
        let mut pending = HashMap::new();
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            3
        ));
        // Candidate changes Down -> Degraded: streak restarts at 1.
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Degraded,
            3
        ));
        assert!(!confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Degraded,
            3
        ));
        assert!(confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Degraded,
            3
        ));
    }

    #[test]
    fn flip_threshold_of_one_is_immediate() {
        let mut pending = HashMap::new();
        assert!(confirm_status_flip(
            &mut pending,
            "b",
            &HealthStatus::Healthy,
            &HealthStatus::Down,
            1
        ));
    }

    #[test]
    fn the_streams_detail_lists_twenty_names_then_counts_the_rest() {
        assert_eq!(stream_names_detail(&[]), None);
        let few: Vec<String> = vec!["dns".into(), "pg".into()];
        assert_eq!(stream_names_detail(&few).as_deref(), Some("dns, pg"));
        let many: Vec<String> = (0..BACKEND_DOWN_STREAMS_LISTED + 3)
            .map(|i| format!("s{i:02}"))
            .collect();
        let detail = stream_names_detail(&many).expect("a detail");
        assert!(detail.ends_with(" and 3 more"), "{detail}");
        assert_eq!(
            detail.matches(", ").count(),
            BACKEND_DOWN_STREAMS_LISTED - 1,
            "{detail}"
        );
    }

    #[tokio::test]
    async fn the_streams_detail_names_the_streams_linked_to_the_backend() {
        let backend = backend_checked_by(None, false);
        let store = store_holding(&backend).await;
        let store = store.lock().await;
        assert_eq!(linked_stream_names(&store, &backend.id), None);
        const PG: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c02";
        const DNS: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c01";
        const OTHER: &str = "6f1c1a52-5b0e-4f7e-9a51-1a7c5a1b2c03";
        for (id, name, port) in [(PG, "pg", 5432), (DNS, "dns", 53), (OTHER, "other", 6000)] {
            store
                .create_stream(&lorica_config::models::Stream::new(
                    id.into(),
                    name.into(),
                    lorica_config::models::StreamProtocol::Tcp,
                    "127.0.0.1".parse().expect("an address"),
                    port,
                    port,
                    chrono::Utc::now(),
                ))
                .expect("test setup: stream");
        }
        for id in [DNS, PG] {
            store
                .set_stream_backends(id, std::slice::from_ref(&backend.id))
                .expect("test setup: link");
        }
        assert_eq!(
            linked_stream_names(&store, &backend.id).as_deref(),
            Some("dns, pg")
        );
    }
}
