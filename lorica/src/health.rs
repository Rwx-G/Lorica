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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use futures_util::stream::StreamExt;
use lorica_config::models::{Backend, HealthCheck, HealthStatus, LifecycleState};
use lorica_config::ConfigStore;
use once_cell::sync::Lazy;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
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

/// Result of a single TCP health check probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Connection succeeded within the degraded threshold.
    Healthy,
    /// Connection succeeded but took longer than the degraded threshold.
    Degraded,
    /// Connection failed or timed out.
    Down,
}

impl ProbeResult {
    pub fn to_health_status(&self) -> HealthStatus {
        match self {
            ProbeResult::Healthy => HealthStatus::Healthy,
            ProbeResult::Degraded => HealthStatus::Degraded,
            ProbeResult::Down => HealthStatus::Down,
        }
    }
}

/// The pause before the next health-loop cycle: the stored
/// `default_health_check_interval_s`, re-read every cycle so a change
/// acts from the next one without a restart, or `fallback` when the
/// store cannot be read. Never below five seconds.
async fn next_interval(store: &Mutex<ConfigStore>, fallback: u64) -> Duration {
    let stored = store
        .lock()
        .await
        .get_global_settings()
        .map(|settings| u64::try_from(settings.default_health_check_interval_s).unwrap_or(fallback))
        .unwrap_or(fallback);
    Duration::from_secs(stored.max(5))
}

/// Run TCP health checks and backend drain monitoring in a loop.
///
/// - Health checks: probe each backend, update status (Healthy/Degraded/Down)
/// - Drain checks: transition Closing backends to Closed when connections reach 0 or timeout expires
///
/// `default_interval_s` is the pause used when the store cannot be
/// read; otherwise every cycle waits the interval stored at its start.
///
/// `on_change` is called once per cycle that persisted a confirmed
/// health flip or a lifecycle transition, beside the `config_reload_tx`
/// signal: the stream plane's table refresh (Story 12.3 D-i), which is
/// not a configuration change and must not wake the reload path.
pub async fn health_check_loop(
    store: Arc<Mutex<ConfigStore>>,
    proxy_config: Arc<ArcSwap<ProxyConfig>>,
    default_interval_s: u64,
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
    loop {
        tokio::time::sleep(next_interval(&health.store, default_interval_s).await).await;
        run_health_cycle(&health, &mut state).await;
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
}

/// One health cycle: list the backends, close the drained ones, probe
/// the eligible ones, persist the confirmed flips, and signal the
/// reload when anything was persisted. Returns whether it was.
async fn run_health_cycle(health: &HealthLoop, state: &mut HealthLoopState) -> bool {
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

    let mut changed = close_drained_backends(health, state, &backends).await;

    // --- Phase A: probe eligible backends concurrently ---
    // One slow or timing-out backend must not delay every other backend's
    // probe or overrun the loop interval. Bound concurrency with the
    // operator-tunable `health_max_concurrent_probes` (default 32).
    let max_concurrent = {
        let store = health.store.lock().await;
        store
            .get_global_settings()
            .map(|s| s.health_max_concurrent_probes.clamp(1, 512) as usize)
            .unwrap_or(32)
    };
    // Clone the eligible backends so each probe future owns its data; this
    // keeps the spawned `health_check_loop` future free of borrows that the
    // stream combinators cannot prove `Send` across the await points.
    let eligible: Vec<Backend> = backends
        .iter()
        .filter(|b| b.lifecycle_state != LifecycleState::Closing && b.health_check_enabled)
        .cloned()
        .collect();
    let probe_results: Vec<(Backend, HealthStatus)> = futures_util::stream::iter(eligible)
        .map(|backend| async move {
            let probe = match probe_for(&backend) {
                ProbeTarget::Http { url } => http_probe(&url).await,
                ProbeTarget::TcpConnect { address } => tcp_probe(&address).await,
            };
            (backend, probe.to_health_status())
        })
        .buffer_unordered(max_concurrent)
        .collect()
        .await;

    // --- Phase B: apply flip hysteresis (sequential) ---
    // `pending_health` is single-threaded loop state, so the decision runs
    // sequentially over the collected probe outcomes. Only confirmed flips
    // (the new status observed HEALTH_FLIP_THRESHOLD times in a row) are
    // carried forward; a transient probe blip is absorbed.
    let mut commits: Vec<(Backend, HealthStatus)> = Vec::new();
    for (backend, new_status) in probe_results {
        if confirm_status_flip(
            &mut state.pending_health,
            &backend.id,
            &backend.health_status,
            &new_status,
            HEALTH_FLIP_THRESHOLD,
        ) {
            commits.push((backend, new_status));
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

/// Phase C: persist confirmed flips under a single lock, and send
/// `BackendDown` for each flip to `Down`. Returns whether a flip was
/// persisted.
///
/// Writes the health status alone, so an edit committed since the
/// probed rows were listed survives.
async fn persist_health_flips(health: &HealthLoop, commits: &[(Backend, HealthStatus)]) -> bool {
    if commits.is_empty() {
        return false;
    }
    let mut changed = false;
    let store = health.store.lock().await;
    for (backend, new_status) in commits {
        debug!(
            backend = %backend.address,
            old = backend.health_status.as_str(),
            new = new_status.as_str(),
            "backend health status changed"
        );

        // Dispatch backend_down notification on a confirmed transition
        // to Down (not on a transient blip - the hysteresis already
        // filtered those out).
        if *new_status == HealthStatus::Down {
            if let Some(ref sender) = health.alert_sender {
                sender.send(
                    lorica_notify::AlertEvent::new(
                        lorica_notify::events::AlertType::BackendDown,
                        format!("Backend {} is down", backend.address),
                    )
                    .with_detail("backend_id", backend.id.clone())
                    .with_detail("address", backend.address.clone())
                    .with_detail("name", backend.name.clone()),
                );
            }
        }

        if let Err(e) = store.set_backend_health_status(&backend.id, new_status) {
            warn!(
                backend = %backend.address,
                error = %e,
                "failed to update backend health status"
            );
        } else {
            changed = true;
        }
    }
    changed
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
            ProbeResult::Down
        }
        Err(_) => {
            debug!(address = %address, "TCP health check timed out");
            ProbeResult::Down
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
                return ProbeResult::Down;
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
            ProbeResult::Down
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
        ProbeResult::Down
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
        assert_eq!(classify_latency(false, 0), ProbeResult::Down);
        assert_eq!(classify_latency(false, 3000), ProbeResult::Down);
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
        assert_eq!(ProbeResult::Down.to_health_status(), HealthStatus::Down);
    }

    #[tokio::test]
    async fn the_interval_is_read_from_the_store_every_cycle_and_never_below_five_seconds() {
        let store = Mutex::new(ConfigStore::open_in_memory().expect("in-memory store"));
        let mut settings = store.lock().await.get_global_settings().expect("settings");
        settings.default_health_check_interval_s = 30;
        store
            .lock()
            .await
            .update_global_settings(&settings)
            .expect("stored");
        assert_eq!(next_interval(&store, 10).await, Duration::from_secs(30));
        settings.default_health_check_interval_s = 1;
        store
            .lock()
            .await
            .update_global_settings(&settings)
            .expect("stored");
        assert_eq!(next_interval(&store, 10).await, Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_tcp_probe_unreachable_address() {
        // Use a non-routable address to guarantee failure
        let result = tcp_probe("192.0.2.1:1").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_tcp_probe_invalid_address() {
        let result = tcp_probe("not-a-valid-address").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_tcp_probe_refused() {
        // Localhost on a port nothing is listening on
        let result = tcp_probe("127.0.0.1:1").await;
        assert_eq!(result, ProbeResult::Down);
    }

    // ---- HTTP probe ----

    #[tokio::test]
    async fn test_http_probe_unreachable() {
        let result = http_probe("http://192.0.2.1:1/healthz").await;
        assert_eq!(result, ProbeResult::Down);
    }

    #[tokio::test]
    async fn test_http_probe_invalid_url() {
        let result = http_probe("not-a-url").await;
        assert_eq!(result, ProbeResult::Down);
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
        assert!(persist_health_flips(&health, &[(listed, HealthStatus::Down)]).await);

        let after = stored(&store, &backend.id).await;
        assert_eq!(after.health_status, HealthStatus::Down);
        assert_edit_kept(&after);
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
        assert!(!persist_health_flips(&health, &[(listed, HealthStatus::Down)]).await);
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

        for cycle in 1..HEALTH_FLIP_THRESHOLD {
            assert!(
                !run_health_cycle(&health, &mut state).await,
                "cycle {cycle} is below the flip threshold"
            );
            assert_eq!(
                stored(&store, &backend.id).await.health_status,
                HealthStatus::Healthy
            );
        }
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 0);

        assert!(run_health_cycle(&health, &mut state).await);
        let after = stored(&store, &backend.id).await;
        assert_eq!(after.health_status, HealthStatus::Down);
        assert_edit_kept(&after);
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 1);
        let alert = alerts_received.try_recv().expect("one BackendDown alert");
        assert_eq!(
            alert.alert_type,
            lorica_notify::events::AlertType::BackendDown
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
}
