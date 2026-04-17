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
        info!(
            allow_cidrs = allow_count,
            deny_cidrs = deny_count,
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
    apply_otel_settings_from_store(store).await;
    apply_geoip_settings_from_store(store).await;
    apply_asn_settings_from_store(store).await;
    apply_bot_secret_from_store(store).await;
    Ok(())
}

/// Supervisor-only entry point. Re-applies the process-local hooks
/// (OTel exporter, GeoIP / ASN updater task lifecycle, bot HMAC
/// secret) when the dashboard saves a new `GlobalSettings` document.
/// The supervisor's `config_reload_tx` listener does not call
/// [`reload_proxy_config`] (only workers do, via the two-phase RPC
/// coordinator), so without this entry point the supervisor would
/// never re-evaluate `geoip_auto_update_enabled` after boot.
pub async fn apply_supervisor_settings_from_store(store: &Arc<Mutex<ConfigStore>>) {
    apply_otel_settings_from_store(store).await;
    apply_geoip_settings_from_store(store).await;
    apply_asn_settings_from_store(store).await;
    apply_bot_secret_from_store(store).await;
}

/// Supervisor-side reload trigger registered at boot. The
/// auto-update task fires this after a successful `.mmdb` download
/// so the supervisor's config-reload coordinator broadcasts a
/// ConfigReload to every worker. Workers then re-read the freshly
/// landed file from disk via their own `apply_*_settings_from_store`
/// hooks, which keeps the data plane in sync without a manual
/// dashboard save or process restart.
static SUPERVISOR_RELOAD_TRIGGER: once_cell::sync::OnceCell<
    tokio::sync::watch::Sender<u64>,
> = once_cell::sync::OnceCell::new();

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
        Err(_) => return,
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
        Err(_) => return,
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
        Err(_) => return,
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
    spawn_fn: fn(
        Arc<R>,
        lorica_geoip::updater::UpdaterConfig,
    ) -> tokio::task::JoinHandle<()>,
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
        Err(_) => return,
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
                Err(e) => warn!(error = %e, "OpenTelemetry reload failed; previous provider stays live"),
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

async fn build_proxy_config_inner(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    installed_mtls_fingerprint: Option<&parking_lot::Mutex<Option<String>>>,
) -> Result<PreparedReload, Box<dyn std::error::Error + Send + Sync>> {
    let store = store.lock().await;

    let routes = store.list_routes()?;
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
            waf_ban_threshold,
            waf_ban_duration_s,
            trusted_proxy_cidrs: trusted_proxies,
            waf_whitelist_cidrs: waf_whitelist_ips,
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
        mtls_fingerprint_drift,
    })
}

/// Reload the TLS certificate resolver from the database.
/// Only loads certificates that are actively referenced by at least one route.
/// Called alongside `reload_proxy_config` when certificates change.
pub async fn reload_cert_resolver(
    store: &Arc<Mutex<ConfigStore>>,
    cert_resolver: &Arc<CertResolver>,
) {
    let s = store.lock().await;
    let db_certs = match s.list_certificates() {
        Ok(c) => c,
        Err(e) => {
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
            warn!(error = %e, "failed to list routes for resolver reload");
            return;
        }
    };

    // Build CertData with OCSP staple responses fetched in parallel.
    // Drop the store lock before doing network I/O.
    let active_certs: Vec<_> = db_certs
        .iter()
        .filter(|c| active_cert_ids.contains(&c.id))
        .cloned()
        .collect();
    drop(s);

    let ocsp_futures: Vec<_> = active_certs
        .iter()
        .map(|c| lorica_tls::ocsp::try_fetch_ocsp(&c.cert_pem))
        .collect();
    let ocsp_responses = futures_util::future::join_all(ocsp_futures).await;

    let cert_data: Vec<CertData> = active_certs
        .iter()
        .zip(ocsp_responses)
        .map(|(c, ocsp)| CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
            ocsp_response: ocsp,
        })
        .collect();

    match cert_resolver.reload(cert_data) {
        Ok(()) => info!(
            domains = cert_resolver.domain_count(),
            "TLS certificate resolver reloaded"
        ),
        Err(e) => warn!(error = %e, "failed to reload TLS certificate resolver"),
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
