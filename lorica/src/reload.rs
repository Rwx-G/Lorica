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

use std::sync::Arc;

use arc_swap::ArcSwap;
use lorica_config::ConfigStore;
use lorica_tls::cert_resolver::{CertData, CertResolver};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::connection_filter::{ConnectionFilterPolicy, GlobalConnectionFilter};
use crate::proxy_wiring::ProxyConfig;

/// Load all routes, backends, certificates and route-backend links from the store
/// and build a new ProxyConfig, then atomically swap it in.
///
/// When `connection_filter` is provided, its CIDR policy is refreshed in the
/// same transaction as the ProxyConfig swap, so listener-level filtering
/// stays coherent with route/backend state after a settings change.
pub async fn reload_proxy_config(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    connection_filter: Option<&Arc<GlobalConnectionFilter>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    reload_proxy_config_with_mtls(store, proxy_config, connection_filter, None).await
}

/// Result of the Prepare half of the two-phase config reload. Holds
/// both the rebuilt [`ProxyConfig`] and the connection-filter policy
/// so the Commit half can publish them together in the same ArcSwap-
/// adjacent window. See design § 7 WPAR-8.
pub struct PreparedReload {
    pub config: ProxyConfig,
    pub connection_allow_cidrs: Vec<String>,
    pub connection_deny_cidrs: Vec<String>,
    /// Per-source-IP live-connection cap (Story 8.9 AC #5); `None`
    /// disables it. Applied on the connection filter at commit time,
    /// beside the CIDR policy.
    pub connection_limits_per_ip: Option<u32>,
    pub mtls_fingerprint_drift: Option<(Option<String>, Option<String>)>,
}

/// Prepare half of a two-phase config reload (WPAR-8).
///
/// Performs the slow work - SQLite reads, ProxyConfig construction,
/// wrr_state preservation, mTLS fingerprint drift detection - but
/// does **not** ArcSwap the current config or reload the connection
/// filter. The caller stashes the result and commits it later via
/// [`commit_prepared_reload`] so multi-worker deployments can
/// coordinate the swap within microseconds instead of the ~10-50 ms
/// window the slow rebuild takes.
pub async fn build_proxy_config(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    installed_mtls_fingerprint: Option<&parking_lot::Mutex<Option<String>>>,
) -> Result<PreparedReload, Box<dyn std::error::Error + Send + Sync>> {
    let prepared =
        build_proxy_config_inner(store, proxy_config, installed_mtls_fingerprint).await?;
    Ok(prepared)
}

/// Commit half of a two-phase config reload (WPAR-8).
///
/// Atomically publishes the [`PreparedReload`] built by
/// [`build_proxy_config`]. This is the fast path; under normal
/// operation it's a single ArcSwap plus a lockfree connection filter
/// reload, so the divergence window between workers collapses to
/// RTT skew on the UDS channel.
pub fn commit_prepared_reload(
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    connection_filter: Option<&Arc<GlobalConnectionFilter>>,
    prepared: PreparedReload,
) {
    if let Some((installed_fp, current_fp)) = &prepared.mtls_fingerprint_drift {
        warn!(
            installed = ?installed_fp,
            current = ?current_fp,
            "mtls CA bundle changed since startup; restart Lorica to apply (rustls ServerConfig is immutable). Toggling mtls.required or editing allowed_organizations takes effect live."
        );
    }
    proxy_config.store(Arc::new(prepared.config));
    if let Some(filter) = connection_filter {
        let policy = ConnectionFilterPolicy::from_cidrs(
            &prepared.connection_allow_cidrs,
            &prepared.connection_deny_cidrs,
        );
        let allow_count = policy.allow.len();
        let deny_count = policy.deny.len();
        filter.reload(policy);
        filter.set_per_ip_limit(prepared.connection_limits_per_ip);
        info!(
            allow_cidrs = allow_count,
            deny_cidrs = deny_count,
            per_ip_limit = prepared.connection_limits_per_ip.unwrap_or(0),
            "connection filter reloaded"
        );
    }
}

/// Variant of [`reload_proxy_config`] that also compares the current
/// CA fingerprint against the one installed on the listener at startup
/// and logs a warning when they differ. Kept as a separate entry
/// point so existing callers (tests, internal call sites that never
/// see a fingerprint) don't need to track a new argument.
pub async fn reload_proxy_config_with_mtls(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    connection_filter: Option<&Arc<GlobalConnectionFilter>>,
    installed_mtls_fingerprint: Option<&parking_lot::Mutex<Option<String>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let prepared =
        build_proxy_config_inner(store, proxy_config, installed_mtls_fingerprint).await?;
    commit_prepared_reload(proxy_config, connection_filter, prepared);
    apply_per_process_reload_state(store).await;
    Ok(())
}

/// Rebuild the process-wide merged AI-crawler registry (built-in +
/// enabled custom rows) from the current store and atomically swap it
/// in (Story 8.2 AC #8). Called from every config-application path -
/// worker / single-process startup and every reload commit - so a
/// dashboard Custom Crawler edit takes effect on the next request
/// without a process restart. Lenient by construction : a single
/// unreadable or malformed custom row is dropped (logged + counted)
/// while the rest of the registry stays live. Placed next to the
/// per-process resolver hooks so the call site reads uniformly with
/// the GeoIP / ASN / OTel / bot-secret re-application.
pub async fn rebuild_merged_crawlers(store: &Arc<Mutex<ConfigStore>>) {
    let guard = store.lock().await;
    crate::proxy_wiring::ai_bot_merged::rebuild_from_store(&guard);
}

/// Re-apply the full per-process reload state from the current store:
/// the four resolver hooks (OTel exporter, GeoIP / ASN updater task
/// lifecycle, bot HMAC secret) AND the merged AI-crawler registry
/// rebuild. Idempotent ; each step dedups internally so calling this
/// on every reload is cheap when nothing changed.
///
/// This is THE single bundle every reload path must invoke. The
/// AI-crawler registry rebuild used to be wired separately from the
/// resolver hooks, so any reload path that called only the hooks
/// (notably the legacy `CommandType::ConfigReload` worker fallback)
/// refreshed resolvers but silently skipped the registry - the exact
/// missed-rebuild asymmetry Story 8.1 killed for resolver spawns.
/// Folding the rebuild in here makes that class of bug unrepresentable.
///
/// Used by both the supervisor's `config_reload_tx` listener (the
/// supervisor never calls `reload_proxy_config` itself - only workers
/// do, via the two-phase RPC coordinator) AND by every worker reload
/// path. The two-phase RPC `ConfigReloadCommit` handler at
/// `proxy_wiring/worker_rpc.rs::handle_config_reload_commit` calls it ;
/// the legacy `CommandType::ConfigReload` worker handler calls it too
/// (audit M-18 - was previously skipping this sequence, so a
/// fallback-from-two-phase reload left GeoIP / OTel / ASN / bot-secret
/// state frozen even though the proxy config swap completed).
pub async fn apply_per_process_reload_state(store: &Arc<Mutex<ConfigStore>>) {
    apply_otel_settings_from_store(store).await;
    apply_geoip_settings_from_store(store).await;
    apply_asn_settings_from_store(store).await;
    apply_bot_secret_from_store(store).await;
    rebuild_merged_crawlers(store).await;
}

/// Supervisor-only alias for [`apply_per_process_reload_state`].
/// Kept as the public symbol used by the supervisor boot + reload
/// listener for backwards naming clarity ; the body delegates.
pub async fn apply_supervisor_settings_from_store(store: &Arc<Mutex<ConfigStore>>) {
    apply_per_process_reload_state(store).await;
}

/// Supervisor-side reload trigger registered at boot. The
/// auto-update task fires this after a successful `.mmdb` download
/// so the supervisor's config-reload coordinator broadcasts a
/// ConfigReload to every worker. Workers then re-read the freshly
/// landed file from disk via their own `apply_*_settings_from_store`
/// hooks, which keeps the data plane in sync without a manual
/// dashboard save or process restart.
static SUPERVISOR_RELOAD_TRIGGER: once_cell::sync::OnceCell<tokio::sync::watch::Sender<u64>> =
    once_cell::sync::OnceCell::new();

/// Called once at supervisor boot with the same `watch::Sender` that
/// the API uses for `notify_config_changed`. Subsequent calls are
/// silently ignored (the trigger is a process-wide singleton).
pub fn register_supervisor_reload_trigger(tx: tokio::sync::watch::Sender<u64>) {
    let _ = SUPERVISOR_RELOAD_TRIGGER.set(tx);
}

/// Bump the supervisor's reload watch by one. Called from the
/// updater's `on_success` callback. No-op when no trigger has been
/// registered (e.g. single-process mode, test harness).
fn fire_supervisor_reload() {
    if let Some(tx) = SUPERVISOR_RELOAD_TRIGGER.get() {
        tx.send_modify(|seq| *seq = seq.wrapping_add(1));
        info!("supervisor reload broadcast triggered after auto-update download");
    }
}

/// Hot-reload the ASN resolver from `GlobalSettings.asn_db_path`.
/// Same pattern as `apply_geoip_settings_from_store` — parallels
/// are intentional so both DBs follow one operator-visible model.
pub(crate) async fn apply_asn_settings_from_store(store: &Arc<Mutex<ConfigStore>>) {
    use std::sync::OnceLock;

    static LAST_APPLIED: OnceLock<parking_lot::Mutex<Option<String>>> = OnceLock::new();
    let slot = LAST_APPLIED.get_or_init(|| parking_lot::Mutex::new(None));

    let resolver = match crate::geoip::asn_handle() {
        Some(r) => r,
        None => return,
    };

    let s = store.lock().await;
    let settings = match s.get_global_settings() {
        Ok(settings) => settings,
        Err(e) => {
            warn!(error = %e, "apply_asn_settings_from_store: store fetch failed, resolver pinned at last applied state");
            lorica_api::metrics::inc_resolver_apply_failed("asn");
            return;
        }
    };
    drop(s);

    let next = settings
        .asn_db_path
        .as_ref()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());

    {
        let mut last = slot.lock();
        if *last != next {
            match next.as_ref() {
                Some(path) => match resolver.load_from_path(path) {
                    Ok(()) => {
                        info!(path = %path, "ASN database hot-reloaded from settings");
                        *last = next.clone();
                    }
                    Err(e) => {
                        // Same reasoning as the GeoIP path: missing
                        // file is the expected case when the operator
                        // just enabled auto-update with a fresh path.
                        info!(
                            path = %path,
                            error = %e,
                            "ASN database not yet present on disk; auto-update task (if enabled) will download it"
                        );
                    }
                },
                None => {
                    resolver.unload();
                    info!("ASN database unloaded by settings change (asn_db_path cleared)");
                    *last = next.clone();
                }
            }
        }
    }

    apply_auto_update_flip(
        &ASN_UPDATER_HANDLE,
        settings.asn_auto_update_enabled,
        next.clone(),
        lorica_geoip::updater::DEFAULT_ASN_URL_TEMPLATE,
        Arc::clone(&resolver),
        "asn",
        lorica_geoip::updater::spawn_asn_updater,
    );
}

/// Re-apply the bot-protection HMAC secret stored in
/// `GlobalSettings.bot_hmac_secret_hex` to the live process
/// (v1.4.0 Epic 3). Called from every `reload_proxy_config*` so a
/// cert-renewal-triggered `rotate_bot_hmac_secret` persistence
/// takes effect without a proxy restart.
///
/// First-boot contract: if the persisted hex is empty (fresh
/// install before the bot-protection feature has ever been
/// enabled), this helper generates a random 32-byte secret, writes
/// it back to the DB, and installs it in memory. Subsequent
/// reloads read the same hex and install it (idempotent — dedup is
/// by value, not by "already run once").
///
/// Failure modes:
/// - Hex in the DB is malformed / wrong length: `warn!`, generate a
///   fresh one, overwrite. A hand-edited bad row cannot leave the
///   secret slot empty. Outstanding cookies signed with the
///   previous (good) bytes stop validating — acceptable degradation
///   for a corrupt config.
/// - DB write failure: `warn!`, leave the in-memory slot alone.
///   The process serves traffic with whatever secret is installed
///   (or without bot-protection until the next reload succeeds).
pub(crate) async fn apply_bot_secret_from_store(store: &Arc<Mutex<ConfigStore>>) {
    use std::sync::OnceLock;

    static LAST_APPLIED: OnceLock<parking_lot::Mutex<Option<[u8; 32]>>> = OnceLock::new();
    let slot = LAST_APPLIED.get_or_init(|| parking_lot::Mutex::new(None));

    let s = store.lock().await;
    let settings = match s.get_global_settings() {
        Ok(settings) => settings,
        Err(e) => {
            warn!(error = %e, "apply_bot_secret_from_store: store fetch failed, secret pinned at last installed value");
            lorica_api::metrics::inc_resolver_apply_failed("bot_secret");
            return;
        }
    };
    drop(s);

    // Decode persisted hex if present + correctly shaped; otherwise
    // generate a fresh secret and schedule it for persistence.
    let (bytes, persist_back) = match parse_bot_secret_hex(&settings.bot_hmac_secret_hex) {
        Some(b) => (b, false),
        None => {
            if !settings.bot_hmac_secret_hex.trim().is_empty() {
                warn!(
                    "bot_hmac_secret_hex in DB is malformed or wrong length; generating a fresh secret"
                );
            } else {
                info!("bot-protection HMAC secret not set; generating on first boot");
            }
            (lorica_challenge::secret::generate(), true)
        }
    };

    // Dedup: if the decoded (or generated) bytes match the last
    // installed value AND nothing needs persisting, skip the
    // ArcSwap store + the DB write.
    {
        let mut last = slot.lock();
        let changed = match *last {
            Some(prev) => prev != bytes,
            None => true,
        };
        if !changed && !persist_back {
            return;
        }
        *last = Some(bytes);
    }

    lorica_challenge::secret::install(bytes);

    if persist_back {
        let hex = encode_bot_secret_hex(&bytes);
        let s = store.lock().await;
        match s.get_global_settings() {
            Ok(mut cur) => {
                cur.bot_hmac_secret_hex = hex;
                if let Err(e) = s.update_global_settings(&cur) {
                    warn!(
                        error = %e,
                        "failed to persist newly-generated bot HMAC secret; next boot will regenerate"
                    );
                } else {
                    info!("bot-protection HMAC secret persisted to SQLite");
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "failed to read global settings to persist bot HMAC secret"
                );
            }
        }
    }
}

/// Parse a 64-char hex string into a fixed 32-byte secret. Returns
/// `None` on malformed hex or wrong length — callers treat that as
/// "regenerate". Kept module-private because the wire format is an
/// internal contract between `GlobalSettings.bot_hmac_secret_hex`
/// and the in-memory slot.
fn parse_bot_secret_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out[i] = hi << 4 | lo;
    }
    Some(out)
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode 32 raw bytes into a 64-char lowercase hex string. Paired
/// with [`parse_bot_secret_hex`]; round-trip-equal.
fn encode_bot_secret_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Re-apply the GeoIP settings stored in `GlobalSettings` to the live
/// process. Called from each `reload_proxy_config*` so a dashboard
/// edit to `geoip_db_path` takes effect without a restart.
///
/// Semantics:
/// - Path changed to a non-empty value → `load_from_path` on the
///   process-wide resolver (atomic ArcSwap; in-flight lookups on the
///   old DB complete unaffected). Failure keeps the old DB live and
///   emits a `warn!` so the operator sees the problem on the next
///   settings save.
/// - Path cleared → `unload()` so `lookup_country` returns `None`
///   and GeoIP rules stop firing.
/// - Path unchanged from the previous snapshot → no-op (dedup, so
///   unrelated settings edits do not churn the resolver).
///
/// The auto-update task is now hot-reloadable: flipping
/// `geoip_auto_update_enabled` from false to true spawns the updater;
/// flipping back to false aborts the running task. The task's
/// `JoinHandle` is kept in a process-wide OnceLock so the reload hook
/// can reach it.
pub(crate) async fn apply_geoip_settings_from_store(store: &Arc<Mutex<ConfigStore>>) {
    use std::sync::OnceLock;

    static LAST_APPLIED: OnceLock<parking_lot::Mutex<Option<String>>> = OnceLock::new();
    let slot = LAST_APPLIED.get_or_init(|| parking_lot::Mutex::new(None));

    let resolver = match crate::geoip::handle() {
        Some(r) => r,
        // No resolver registered: either the startup path hasn't run
        // yet (early boot) or we are in a test harness. Nothing to
        // do; a later reload call after `set_handle` will pick up
        // the persisted setting.
        None => return,
    };

    let s = store.lock().await;
    let settings = match s.get_global_settings() {
        Ok(settings) => settings,
        Err(e) => {
            warn!(error = %e, "apply_geoip_settings_from_store: store fetch failed, resolver pinned at last applied state");
            lorica_api::metrics::inc_resolver_apply_failed("geoip");
            return;
        }
    };
    drop(s);

    let next = settings
        .geoip_db_path
        .as_ref()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());

    {
        let mut last = slot.lock();
        if *last != next {
            match next.as_ref() {
                Some(path) => match resolver.load_from_path(path) {
                    Ok(()) => {
                        info!(path = %path, "GeoIP database hot-reloaded from settings");
                        *last = next.clone();
                    }
                    Err(e) => {
                        // File missing / unreadable is the EXPECTED case
                        // when auto-update is enabled with a not-yet-
                        // downloaded path: the updater task we spawn
                        // below will fetch and write it. Log at info
                        // level so a fresh-install boot does not look
                        // like a misconfiguration. Do NOT advance the
                        // snapshot - a future save retries the load
                        // once the file exists.
                        info!(
                            path = %path,
                            error = %e,
                            "GeoIP database not yet present on disk; auto-update task (if enabled) will download it"
                        );
                    }
                },
                None => {
                    resolver.unload();
                    info!("GeoIP database unloaded by settings change (geoip_db_path cleared)");
                    *last = next.clone();
                }
            }
        }
    }

    // Auto-update task lifecycle: flip false->true spawns, flip
    // true->false aborts. Path-only changes are ignored - the running
    // updater picks up the new `target_path` on the next tick via
    // `UpdaterConfig` which is built fresh on each spawn. The file
    // existing on disk is NOT a precondition: the whole point of
    // the updater is to populate it.
    apply_auto_update_flip(
        &GEOIP_UPDATER_HANDLE,
        settings.geoip_auto_update_enabled,
        next.clone(),
        lorica_geoip::updater::DEFAULT_URL_TEMPLATE,
        Arc::clone(&resolver),
        "geoip",
        lorica_geoip::updater::spawn_updater,
    );
}

/// Process-wide handle to the running GeoIP auto-update task. `None`
/// when auto-update is off; `Some(_)` while the task is live so the
/// reload hook can abort it on toggle.
static GEOIP_UPDATER_HANDLE: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

/// Same pattern as GEOIP_UPDATER_HANDLE but for the ASN auto-update
/// task.
static ASN_UPDATER_HANDLE: once_cell::sync::Lazy<
    parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
> = once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(None));

/// Generic auto-update flip handler: aborts any running task, then
/// spawns a new one when `enabled && path.is_some()`. The
/// `spawn_fn` closure is the only piece that varies between GeoIP
/// (`spawn_updater`) and ASN (`spawn_asn_updater`).
fn apply_auto_update_flip<R: Send + Sync + 'static>(
    slot: &parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
    enabled: bool,
    path: Option<String>,
    url_template: &'static str,
    resolver: Arc<R>,
    log_tag: &'static str,
    spawn_fn: fn(Arc<R>, lorica_geoip::updater::UpdaterConfig) -> tokio::task::JoinHandle<()>,
) {
    let mut guard = slot.lock();
    let should_run = enabled && path.is_some();
    let is_running = guard.is_some();

    // Only the supervisor process owns the auto-update task. Worker
    // processes read the freshly-downloaded file from disk via their
    // own resolver-reload hook. Running the updater in every worker
    // would stampede the DB-IP feed AND corrupt the on-disk
    // `.tmp` file via the concurrent rename contention. Detect the
    // supervisor by the presence of the registered reload trigger:
    // only `run_supervisor` calls `register_supervisor_reload_trigger`.
    let is_supervisor = SUPERVISOR_RELOAD_TRIGGER.get().is_some();

    if should_run && !is_running && is_supervisor {
        if let Some(p) = path {
            let mut cfg = lorica_geoip::updater::UpdaterConfig::new(p.clone());
            cfg.url_template = url_template.to_string();
            // Wire the supervisor-side reload trigger: after each
            // successful download, bump the config-reload watch so
            // the workers re-read the new file from disk via their
            // own RPC reload path.
            cfg.on_success = Some(std::sync::Arc::new(fire_supervisor_reload));
            let handle = spawn_fn(resolver, cfg);
            *guard = Some(handle);
            info!(
                tag = log_tag,
                path = %p,
                "auto-update task spawned via hot-reload"
            );
        }
    } else if !should_run && is_running {
        if let Some(h) = guard.take() {
            h.abort();
            info!(tag = log_tag, "auto-update task stopped via hot-reload");
        }
    }
}

/// Re-apply the OTel settings stored in `GlobalSettings` to the live
/// process. Called from each `reload_proxy_config*` so a dashboard
/// edit to `otlp_endpoint` / `otlp_protocol` / `otlp_service_name`
/// / `otlp_sampling_ratio` takes effect without a restart.
///
/// Strategy: snapshot the four fields, hash them, and only call
/// `otel::init` (or `otel::shutdown` when the endpoint is cleared)
/// when the snapshot diverges from the last applied value. Without
/// the dedup we would tear down the BatchSpanProcessor on every
/// route edit, which is needlessly expensive.
pub(crate) async fn apply_otel_settings_from_store(store: &Arc<Mutex<ConfigStore>>) {
    use std::sync::OnceLock;

    static LAST_APPLIED: OnceLock<parking_lot::Mutex<Option<OtelSnapshot>>> = OnceLock::new();
    let slot = LAST_APPLIED.get_or_init(|| parking_lot::Mutex::new(None));

    let s = store.lock().await;
    let settings = match s.get_global_settings() {
        Ok(settings) => settings,
        Err(e) => {
            warn!(error = %e, "apply_otel_settings_from_store: store fetch failed, exporter pinned at last applied state");
            lorica_api::metrics::inc_resolver_apply_failed("otel");
            return;
        }
    };
    drop(s);

    let endpoint = settings
        .otlp_endpoint
        .as_ref()
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    let next = endpoint.map(|ep| OtelSnapshot {
        endpoint: ep,
        protocol: settings.otlp_protocol.clone(),
        service_name: settings.otlp_service_name.clone(),
        sampling_ratio: settings.otlp_sampling_ratio,
    });

    let mut last = slot.lock();
    if *last == next {
        return;
    }

    match (last.as_ref(), next.as_ref()) {
        (_, Some(snapshot)) => {
            let cfg = crate::otel::OtelConfig {
                endpoint: snapshot.endpoint.clone(),
                protocol: crate::otel::OtlpProtocol::from_settings(&snapshot.protocol),
                service_name: snapshot.service_name.clone(),
                sampling_ratio: snapshot.sampling_ratio,
            };
            match crate::otel::init(&cfg) {
                Ok(()) => info!(
                    endpoint = %cfg.endpoint,
                    protocol = cfg.protocol.as_str(),
                    service_name = %cfg.service_name,
                    sampling_ratio = cfg.sampling_ratio,
                    "OpenTelemetry tracing reloaded from settings"
                ),
                Err(e) => {
                    warn!(error = %e, "OpenTelemetry reload failed; previous provider stays live")
                }
            }
        }
        (Some(_), None) => {
            // Endpoint cleared: tear down so dashboard "disable"
            // actually stops emitting spans.
            crate::otel::shutdown();
            info!("OpenTelemetry tracing disabled by settings change");
        }
        (None, None) => {}
    }

    *last = next;
}

#[derive(Clone, PartialEq)]
struct OtelSnapshot {
    endpoint: String,
    protocol: String,
    service_name: String,
    sampling_ratio: f64,
}

/// Story 8.10 AC #8. Emit a single operator-facing notice, once per
/// process, listing routes that still carry the legacy `rate_limit_rps`
/// fields without a structured `rate_limit` block. The unified limiter
/// keeps enforcing these via a compatibility shim, so this is advisory
/// only: no database row is written and operators are encouraged (not
/// forced) to migrate to the richer `rate_limit` struct. The
/// `std::sync::Once` guard keeps it to the first config build of the
/// process (`build_proxy_config_inner` also runs on every hot reload).
fn log_legacy_rate_limit_migration_notice(routes: &[lorica_config::models::Route]) {
    static NOTICE: std::sync::Once = std::sync::Once::new();
    NOTICE.call_once(|| {
        let legacy: Vec<&str> = routes
            .iter()
            .filter(|r| r.rate_limit_rps.is_some() && r.rate_limit.is_none())
            .map(|r| r.hostname.as_str())
            .collect();
        if !legacy.is_empty() {
            tracing::warn!(
                count = legacy.len(),
                routes = %legacy.join(", "),
                "routes still use the legacy rate_limit_rps field; they keep working via the \
                 compatibility shim, but migrating them to the structured rate_limit block is \
                 recommended (Story 8.10)"
            );
        }
    });
}

async fn build_proxy_config_inner(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    installed_mtls_fingerprint: Option<&parking_lot::Mutex<Option<String>>>,
) -> Result<PreparedReload, Box<dyn std::error::Error + Send + Sync>> {
    let store = store.lock().await;

    let routes = store.list_routes()?;
    log_legacy_rate_limit_migration_notice(&routes);
    let backends = store.list_backends()?;
    let certificates = store.list_certificates()?;
    let route_backends = store.list_route_backends()?;
    let settings = store.get_global_settings().ok();
    let custom_presets = settings
        .as_ref()
        .map(|s| s.custom_security_presets.clone())
        .unwrap_or_default();
    let max_global_connections = settings
        .as_ref()
        .map(|s| s.max_global_connections.max(0) as u32)
        .unwrap_or(0);
    let flood_threshold_rps = settings
        .as_ref()
        .map(|s| s.flood_threshold_rps.max(0) as u32)
        .unwrap_or(0);
    let flood_strict_rps = settings.as_ref().map(|s| s.flood_strict_rps).unwrap_or(0);
    let header_timeout_s = settings.as_ref().map(|s| s.header_timeout_s).unwrap_or(10);
    let waf_ban_threshold = settings
        .as_ref()
        .map(|s| s.waf_ban_threshold.max(0) as u32)
        .unwrap_or(5);
    let waf_ban_duration_s = settings
        .as_ref()
        .map(|s| s.waf_ban_duration_s.max(0) as u32)
        .unwrap_or(3600);
    let trusted_proxies = settings
        .as_ref()
        .map(|s| s.trusted_proxies.clone())
        .unwrap_or_default();
    let waf_whitelist_ips = settings
        .as_ref()
        .map(|s| s.waf_whitelist_ips.clone())
        .unwrap_or_default();
    let connection_allow_cidrs = settings
        .as_ref()
        .map(|s| s.connection_allow_cidrs.clone())
        .unwrap_or_default();
    let connection_deny_cidrs = settings
        .as_ref()
        .map(|s| s.connection_deny_cidrs.clone())
        .unwrap_or_default();
    let connection_limits_per_ip = settings
        .as_ref()
        .and_then(|s| s.connection_limits_per_ip)
        .filter(|v| *v > 0);
    // Story 8.2 AC #3 / #11. Plumbed at config-load time so the
    // filter-chain helpers read a stable snapshot, no SettingsStore
    // lookup on the hot path.
    let ai_bot_treat_spoofed_as = settings
        .as_ref()
        .map(|s| s.ai_bot_treat_spoofed_as)
        .unwrap_or_default();
    let ai_bot_inject_headers = settings
        .as_ref()
        .map(|s| s.ai_bot_inject_headers)
        .unwrap_or(true);

    let links: Vec<(String, String)> = route_backends
        .into_iter()
        .map(|rb| (rb.route_id, rb.backend_id))
        .collect();

    let mut new_config = ProxyConfig::from_store(
        routes,
        backends,
        certificates,
        links,
        crate::proxy_wiring::ProxyConfigGlobals {
            custom_security_presets: custom_presets,
            max_global_connections,
            flood_threshold_rps,
            flood_strict_rps,
            header_timeout_s,
            waf_ban_threshold,
            waf_ban_duration_s,
            trusted_proxy_cidrs: trusted_proxies,
            waf_whitelist_cidrs: waf_whitelist_ips,
            ai_bot_treat_spoofed_as,
            ai_bot_inject_headers,
            bot_stash_max_entries: settings
                .as_ref()
                .map(|s| s.bot_stash_max_entries)
                .unwrap_or(10_000),
            bot_stash_per_prefix_max: settings
                .as_ref()
                .map(|s| s.bot_stash_per_prefix_max)
                .unwrap_or(100),
            mirror_max_concurrent_per_route: settings
                .as_ref()
                .map(|s| s.mirror_max_concurrent_per_route)
                .unwrap_or(32),
            mirror_max_concurrent_global: settings
                .as_ref()
                .map(|s| s.mirror_max_concurrent_global)
                .unwrap_or(4096),
        },
    );

    // Preserve round-robin counters from the old config to avoid
    // resetting load distribution on every config reload. Entries are
    // now stored as `Arc<RouteEntry>` (shared across hostname +
    // aliases), so we rebuild the inner struct with the preserved
    // wrr_state once per route_id and then replace every Arc slot
    // pointing at that route.
    let old_config = proxy_config.load();
    let mut rebuilt: std::collections::HashMap<String, Arc<crate::proxy_wiring::RouteEntry>> =
        std::collections::HashMap::new();
    for entries in new_config.routes_by_host.values() {
        for entry in entries {
            if rebuilt.contains_key(&entry.route.id) {
                continue;
            }
            if let Some(old_entries) = old_config.routes_by_host.get(&entry.route.hostname) {
                if let Some(old_entry) = old_entries.iter().find(|e| e.route.id == entry.route.id) {
                    let mut new_inner = (**entry).clone();
                    new_inner.wrr_state = Arc::clone(&old_entry.wrr_state);
                    rebuilt.insert(entry.route.id.clone(), Arc::new(new_inner));
                }
            }
        }
    }
    for entries in new_config.routes_by_host.values_mut() {
        for slot in entries.iter_mut() {
            if let Some(new_arc) = rebuilt.get(&slot.route.id) {
                *slot = Arc::clone(new_arc);
            }
        }
    }

    let route_count: usize = new_config.routes_by_host.values().map(|v| v.len()).sum();
    info!(routes = route_count, "proxy configuration reloaded");

    // mTLS CA bundle drift detection: rustls `ServerConfig` is
    // immutable after the listener is built, so any edit to a
    // route's `mtls.ca_cert_pem` at runtime won't take effect until
    // the process is restarted. We detect drift in Prepare so the
    // log lands once per reload (rather than twice if both Prepare
    // and Commit emit it); the actual warn! is deferred to
    // `commit_prepared_reload` so it only fires if the commit
    // succeeds.
    let mtls_fingerprint_drift = if let Some(slot) = installed_mtls_fingerprint {
        let current_routes: Vec<lorica_config::models::Route> = new_config
            .routes_by_host
            .values()
            .flat_map(|v| v.iter().map(|e| (*e.route).clone()))
            .collect();
        let current_fp = crate::mtls::compute_ca_fingerprint(&current_routes);
        let installed_fp = slot.lock().clone();
        if installed_fp != current_fp {
            Some((installed_fp, current_fp))
        } else {
            None
        }
    } else {
        None
    };

    Ok(PreparedReload {
        config: new_config,
        connection_allow_cidrs,
        connection_deny_cidrs,
        connection_limits_per_ip,
        mtls_fingerprint_drift,
    })
}

/// Per-process serialisation guard for `reload_cert_resolver`. The
/// reload involves an SQLite read of the cert table + parallel OCSP
/// fetches with a 10 s per-responder timeout. If two reload calls
/// land back-to-back (e.g. the supervisor's two-phase coordinator
/// fires Commit RPCs for two consecutive generations within the OCSP
/// fetch window), without this guard both futures race ; the LAST
/// one to finish wins the `cert_resolver.reload(cert_data)` arc-swap,
/// which can leave the resolver pinned to the OLDER db state if its
/// OCSP fetches happened to finish second. Audit L-16 ; serialising
/// at the per-process level is the simplest correct fix.
static CERT_RESOLVER_RELOAD_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Process-wide nudge from [`reload_cert_resolver`] to the background
/// `ocsp_refresh_loop` (Story 8.5). Reload now swaps cert bodies with no
/// OCSP staple; firing this after the swap lets the loop staple the
/// fresh certs within a few seconds instead of waiting for its next
/// periodic tick.
static OCSP_REFRESH_NOTIFY: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Handle to the OCSP-refresh nudge. The background loop awaits
/// [`tokio::sync::Notify::notified`] on it alongside its periodic timer.
pub fn ocsp_refresh_notify() -> &'static tokio::sync::Notify {
    &OCSP_REFRESH_NOTIFY
}

/// Reload the TLS certificate resolver from the database.
/// Only loads certificates that are actively referenced by at least one route.
/// Called alongside `reload_proxy_config` when certificates change.
pub async fn reload_cert_resolver(
    store: &Arc<Mutex<ConfigStore>>,
    cert_resolver: &Arc<CertResolver>,
) {
    // Serialise concurrent invocations so two back-to-back commits
    // cannot have their OCSP fetches finish out-of-order and end up
    // arc-swapping the older db state on top of the newer (audit
    // L-16). Lock is per-process ; held for the whole reload
    // (SQLite read + OCSP fetch + arc-swap) so the next caller sees
    // a complete predecessor.
    let _reload_guard = CERT_RESOLVER_RELOAD_LOCK.lock().await;

    let s = store.lock().await;
    let db_certs = match s.list_certificates() {
        Ok(c) => c,
        Err(e) => {
            lorica_api::metrics::inc_cert_resolver_reload("fail");
            warn!(error = %e, "failed to list certificates for resolver reload");
            return;
        }
    };

    // Only load certificates referenced by at least one route
    let active_cert_ids: std::collections::HashSet<String> = match s.list_routes() {
        Ok(routes) => routes
            .iter()
            .filter_map(|r| r.certificate_id.clone())
            .collect(),
        Err(e) => {
            lorica_api::metrics::inc_cert_resolver_reload("fail");
            warn!(error = %e, "failed to list routes for resolver reload");
            return;
        }
    };

    // Build cert bodies only - no OCSP fetch on the reload critical
    // path (Story 8.5 AC #3). Stapling used to run a 10 s-per-responder
    // parallel fetch here, so a slow OCSP responder delayed the TLS
    // listener from serving a freshly installed cert by up to 10 s. The
    // staples are now attached by the background `ocsp_refresh_loop`,
    // nudged via `OCSP_REFRESH_NOTIFY` right after this swap (typically
    // stapled within a few seconds). Drop the store lock before the
    // (now purely CPU) key parsing in `reload`.
    let active_certs: Vec<_> = db_certs
        .iter()
        .filter(|c| active_cert_ids.contains(&c.id))
        .cloned()
        .collect();
    drop(s);

    let cert_data: Vec<CertData> = active_certs
        .iter()
        .map(|c| CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
            ocsp_response: None,
        })
        .collect();

    match cert_resolver.reload(cert_data) {
        Ok(stats) => {
            lorica_api::metrics::inc_cert_resolver_reload("ok");
            if stats.skipped > 0 {
                lorica_api::metrics::inc_certificates_invalid_bundle_by(
                    "reload",
                    stats.skipped as u64,
                );
            }
            info!(
                domains = cert_resolver.domain_count(),
                skipped = stats.skipped,
                total = stats.total,
                "TLS certificate resolver reloaded (OCSP staples deferred to background refresh)"
            );
            // Nudge the background OCSP loop so the fresh certs get
            // stapled promptly instead of at the next periodic tick.
            OCSP_REFRESH_NOTIFY.notify_one();
        }
        Err(e) => {
            lorica_api::metrics::inc_cert_resolver_reload("fail");
            warn!(error = %e, "failed to reload TLS certificate resolver");
        }
    }
}

#[cfg(test)]
mod bot_secret_hex_tests {
    use super::{encode_bot_secret_hex, parse_bot_secret_hex};

    #[test]
    fn round_trip_preserves_bytes() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
            0xc3, 0xd2, 0xe1, 0xf0,
        ];
        let hex = encode_bot_secret_hex(&bytes);
        assert_eq!(hex.len(), 64);
        let decoded = parse_bot_secret_hex(&hex).expect("round-trip must decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn encode_is_lowercase() {
        let bytes = [0xABu8; 32];
        let hex = encode_bot_secret_hex(&bytes);
        assert!(
            hex.chars().all(|c| !c.is_ascii_uppercase()),
            "encoded hex must be lowercase: {hex}"
        );
    }

    #[test]
    fn parse_accepts_uppercase_and_mixed_case_hex() {
        // Operator-hand-edited DB rows might mix case; the decoder
        // must be tolerant there even though the encoder emits lower.
        let upper = "A".repeat(64);
        let decoded = parse_bot_secret_hex(&upper).expect("uppercase must decode");
        assert_eq!(decoded, [0xAAu8; 32]);

        let mixed = "aAbBcCdDeEfF0011".repeat(4);
        assert_eq!(mixed.len(), 64);
        parse_bot_secret_hex(&mixed).expect("mixed-case must decode");
    }

    #[test]
    fn parse_trims_surrounding_whitespace() {
        // Hex copied from the dashboard form field often carries a
        // trailing newline — the helper strips it.
        let hex = format!("  {}\n", "0".repeat(64));
        parse_bot_secret_hex(&hex).expect("trimmed hex must decode");
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(parse_bot_secret_hex("").is_none());
        assert!(parse_bot_secret_hex(&"0".repeat(63)).is_none());
        assert!(parse_bot_secret_hex(&"0".repeat(65)).is_none());
    }

    #[test]
    fn parse_rejects_non_hex_characters() {
        let mut bad = "0".repeat(63);
        bad.push('z');
        assert!(parse_bot_secret_hex(&bad).is_none());
    }
}
