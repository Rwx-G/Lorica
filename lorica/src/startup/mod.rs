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

//! Shared startup helpers for the three process modes (audit H-9).
//!
//! `run_supervisor`, `run_worker`, and `run_single_process` used to
//! duplicate several background-task clusters inline. The v1.5.2
//! worker-mode cert-hotswap bug came from exactly that duplication: a
//! spawn added to one mode was missed in another. Every helper in this
//! module is the single source of truth for one such cluster;
//! mode-specific differences are explicit parameters, never copies.

pub(crate) mod cluster_follower;
pub(crate) mod cluster_plane;
pub(crate) mod hot_upgrade;
pub(crate) mod single;
pub(crate) mod supervisor;
pub(crate) mod telemetry_drain;
pub(crate) mod worker;

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::Datelike;
use lorica_api::middleware::auth::SessionStore;
use lorica_api::middleware::rate_limit::RateLimiter;
use lorica_api::server::AppState;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use lorica::proxy_wiring::{BackendConnections, ProxyConfig};

/// Handles produced by [`start_alerting_stack`] that the calling mode
/// still needs after the shared spawns are done.
pub(crate) struct AlertingStack {
    /// Dispatcher behind a mutex so the supervisor's config-reload
    /// task can rebuild it when notification channels change.
    pub(crate) notify_dispatcher: Arc<Mutex<lorica_notify::NotifyDispatcher>>,
    /// Shared notification history ring, captured before the
    /// dispatcher is wrapped. Single-process mode hands it straight to
    /// `AppState`; supervisor mode re-reads it via
    /// `notify_dispatcher.lock().await.history()` at AppState build.
    pub(crate) notification_history: Arc<parking_lot::Mutex<VecDeque<lorica_notify::AlertEvent>>>,
    /// Active probe scheduler, already loaded via `reload()`.
    pub(crate) probe_scheduler: Arc<lorica_bench::ProbeScheduler>,
    /// SLA collector with its flush task already started.
    pub(crate) sla_collector: Arc<lorica_bench::SlaCollector>,
}

/// Start the alerting + probing + SLA cluster shared by supervisor and
/// single-process modes (audit H-9 dedup).
///
/// Covers: notification dispatcher built from DB configs, the
/// persisted alert-dispatcher bridge, the active probe scheduler
/// (with its initial `reload()`), and the SLA collector with its
/// flush task.
///
/// The `AlertSender` is created at the call site, not here: the
/// supervisor needs it well before this cluster runs (the health-check
/// loop and the WAF UDS listener both clone it first). Single-process
/// mode additionally starts the load-test scheduler right after this
/// cluster; that stays at its single call site.
///
/// Mode notes:
/// - Before extraction the supervisor created the probe scheduler
///   before the SLA collector and single-process mode did the reverse.
///   The two are independent (no shared state besides the store mutex,
///   locked at distinct points), so this helper fixes one order:
///   probe scheduler first, then SLA collector.
/// - The alert-dispatcher `JoinHandle` was discarded at both original
///   call sites (`let _alert_dispatcher = ...`), so it is dropped
///   here; dropping a `JoinHandle` detaches the task.
pub(crate) async fn start_alerting_stack(
    store: &Arc<Mutex<ConfigStore>>,
    alert_sender: &lorica_notify::AlertSender,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
) -> AlertingStack {
    // Create notification dispatcher from DB configs
    let notify_dispatcher = {
        let s = store.lock().await;
        build_notify_dispatcher(&s)
    };
    let notification_history = notify_dispatcher.history();
    let notify_dispatcher = Arc::new(Mutex::new(notify_dispatcher));

    // Bridge: alert_sender (broadcast) -> NotifyDispatcher (async dispatch) + DB persistence
    let _alert_dispatcher =
        spawn_persisted_alert_dispatcher(alert_sender, Arc::clone(&notify_dispatcher), log_store);

    // Start active probe scheduler
    let probe_store = Arc::clone(store);
    let probe_scheduler = Arc::new(lorica_bench::ProbeScheduler::new(
        probe_store,
        Some(Arc::clone(&notify_dispatcher)),
    ));
    probe_scheduler.reload().await;

    // Create SLA collector and start background flush task
    let sla_collector = Arc::new(lorica_bench::SlaCollector::new());
    {
        let s = store.lock().await;
        sla_collector.load_configs(&s);
    }
    sla_collector.start_flush_task(Arc::clone(store), Some(Arc::clone(&notify_dispatcher)));

    AlertingStack {
        notify_dispatcher,
        notification_history,
        probe_scheduler,
        sla_collector,
    }
}

/// Create the load-test engine and start its cron scheduler.
///
/// One helper for both API-serving modes (Epic 8 Story 8.1 asymmetry,
/// fixed in v1.5.11): supervisor mode used to create a `LoadTestEngine`
/// for `AppState` but never called `start_scheduler`, so cron-scheduled
/// load tests silently never ran outside single-process mode. Going
/// through this helper makes "engine without scheduler" unrepresentable
/// at the call sites.
pub(crate) fn start_load_test_engine(
    store: &Arc<Mutex<ConfigStore>>,
) -> Arc<lorica_bench::LoadTestEngine> {
    let engine = Arc::new(lorica_bench::LoadTestEngine::new());
    lorica_bench::scheduler::start_scheduler(Arc::clone(store), Arc::clone(&engine));
    engine
}

/// Run the shared API-server tail: session store, ACME auto-renewal,
/// cert-expiry notifier, then the blocking `start_server` loop
/// (audit H-9 dedup).
///
/// The mode-specific `AppState` is built at the call site, inside the
/// `tokio::spawn` that owns `api_handle` (aborted at shutdown in both
/// modes); everything after the state exists is identical across
/// supervisor and single-process modes and lives here. The ACME
/// renewal + cert-expiry spawns are the exact pair whose absence in
/// worker mode caused the v1.5.2 cert-hotswap bug; keeping them in one
/// place prevents the modes from drifting again.
///
/// Mode notes:
/// - Before extraction the supervisor built the session store before
///   spawning the ACME tasks and single-process mode did the reverse.
///   The steps are independent until `start_server`, so this helper
///   fixes one order: session store + rate limiter first.
/// - Renewal checks every 12 h and renews at 30 days before expiry;
///   the expiry notifier also runs every 12 h. Both alert through
///   `alert_sender`.
pub(crate) async fn run_api_server(
    management_port: u16,
    state: AppState,
    alert_sender: lorica_notify::AlertSender,
    inherited_listener: Option<std::net::TcpListener>,
) {
    let session_store = SessionStore::new(Arc::clone(&state.store))
        .await
        .with_task_tracker(state.task_tracker.clone());
    let rate_limiter = RateLimiter::new();

    // Issuance belongs to the control plane (Story 9.5 AC #3). A
    // follower renews nothing and warns about nothing: the fleet's
    // certificates are issued once, centrally, and pushed down.
    //
    // The guard sits HERE, at the spawn, not inside either task. The
    // expiry notifier runs one check immediately before entering its
    // loop, so a guard placed in the loop would still fire one
    // duplicate fleet-wide alert per node at every boot. The orphan
    // purge joins them because it DELETES certificates, which on a
    // follower is both redundant with the replica apply's own delete
    // pass and capable of racing it.
    //
    // OCSP refresh is deliberately NOT gated: stapling is a serving
    // concern and followers are the nodes terminating client TLS (AC
    // #4). See `spawn_ocsp_refresh_loop`.
    let is_follower = matches!(
        state.cluster,
        lorica_api::cluster::ClusterRuntime::Follower(_)
    );
    if is_follower {
        info!(
            "follower mode: certificate issuance, renewal and expiry alerting are the control plane's job; this node installs what it is sent and keeps stapling its own certs"
        );
    } else {
        // One-shot startup purge of superseded orphan ACME certs (fix
        // 1.5.12). Shared by both modes here so single-process and
        // supervisor cannot drift, exactly like the renewal spawn
        // below.
        purge_superseded_acme_orphans(&state.store).await;

        let _acme_renewal = lorica_api::acme::spawn_renewal_task(
            state.clone(),
            std::time::Duration::from_secs(12 * 3600),
            30,
            Some(alert_sender.clone()),
        );
        let _cert_expiry_check = lorica_api::acme::spawn_cert_expiry_check_task(
            state.clone(),
            std::time::Duration::from_secs(12 * 3600),
            alert_sender,
        );
    }

    if let Err(e) = lorica_api::server::start_server(
        management_port,
        state,
        session_store,
        rate_limiter,
        inherited_listener,
    )
    .await
    {
        error!(error = %e, "API server exited with error");
    }
}

/// Purge superseded orphan ACME certificates left over by the old
/// insert-then-reassign renewal (fix 1.5.12). An orphan is an ACME
/// cert that is unreferenced by any route AND has a sibling for the
/// same identifier set with a later `not_after`. Unique unbound certs
/// are kept (an operator may bind them); the decision lives in the
/// pure `superseded_orphans` selector so it is unit-tested in
/// `lorica-api`.
///
/// Best-effort and non-fatal: a store error is logged and startup
/// continues, since a failed purge never blocks serving traffic.
async fn purge_superseded_acme_orphans(store: &Arc<Mutex<ConfigStore>>) {
    let s = store.lock().await;

    let certs = match s.list_certificates() {
        Ok(certs) => certs,
        Err(e) => {
            warn!(error = %e, "startup orphan purge: failed to list certificates");
            return;
        }
    };
    let bound_ids: std::collections::HashSet<String> = match s.list_routes() {
        Ok(routes) => routes
            .iter()
            .filter_map(|r| r.certificate_id.clone())
            .collect(),
        Err(e) => {
            warn!(error = %e, "startup orphan purge: failed to list routes");
            return;
        }
    };

    let orphan_ids = lorica_api::acme::superseded_orphans(&certs, &bound_ids);
    if orphan_ids.is_empty() {
        return;
    }

    for id in &orphan_ids {
        if let Err(e) = s.delete_certificate(id) {
            warn!(cert_id = %id, error = %e, "startup orphan purge: failed to delete orphan certificate");
        }
    }

    info!(
        count = orphan_ids.len(),
        ids = ?orphan_ids,
        "purged superseded orphan ACME certificates at startup"
    );
}

/// Spawn the hourly retention loop shared by supervisor and
/// single-process modes (audit H-9 dedup): access-log retention, probe
/// result purge (keep 1000), WAF event retention (keep 100 000),
/// expired ACME challenge purge (Story 9.5), and the daily SLA bucket
/// purge.
///
/// A `None` `log_store` (the access-log store failed to open) skips
/// only the jobs that read it. The configuration-store jobs still run:
/// Story 9.5 iteration 1 found the challenge purge silently disabled
/// on any node whose log store was missing, which is exactly the
/// degraded node where stale rows accumulate unnoticed.
///
/// The `JoinHandle` was discarded at both original call sites, so it
/// is not returned. Must be called from within a tokio runtime
/// context.
pub(crate) fn spawn_retention_loop(
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    config_store: Arc<Mutex<ConfigStore>>,
    telemetry: Option<Arc<lorica_api::cluster_telemetry_store::ClusterTelemetryStore>>,
) {
    // The loop runs even with no log store: several of its jobs
    // (expired ACME challenges, probe results, SLA windows) live in
    // the configuration store and must not be hostage to whether this
    // process happens to keep access logs.
    let retention_log_store = log_store;
    let retention_config_store = config_store;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        let mut last_sla_purge_day: u32 = 0;
        loop {
            interval.tick().await;
            let (retention, waf_retention, audit_retention_days) = {
                let s = retention_config_store.lock().await;
                s.get_global_settings()
                    .map(|gs| {
                        (
                            gs.access_log_retention,
                            gs.waf_event_retention,
                            gs.audit_log_retention_days,
                        )
                    })
                    .unwrap_or((100_000, 100_000, 90))
            };
            if let Some(logs) = &retention_log_store {
                if retention > 0 {
                    if let Err(e) = logs.enforce_retention(retention as u64) {
                        tracing::warn!(error = %e, "access log retention cleanup failed");
                    }
                }
            }
            // Fan-in retention (Story 9.6 AC #3): a PER-NODE quota,
            // not a global row cap. A global cap would make the fleet
            // view shallower than each node's own local log and let
            // one noisy edge evict every quiet edge's rows, which is
            // the incident-correlation case fan-in exists for. Only a
            // control plane has this store.
            if let Some(telemetry) = &telemetry {
                let telemetry = Arc::clone(telemetry);
                // The roster decides which node ids still own their
                // rows. A node id absent from the registry (deleted,
                // or superseded by a re-enrolment under a fresh id)
                // owns nothing; a revoked node keeps its rows for a
                // day, because the hours before a revocation are
                // exactly what an operator reviews after one. Without
                // this, retired ids held up to twice their quota
                // forever and counted toward the watermark that sheds
                // the whole fleet (Epic 9 close, architecture review).
                let roster = {
                    let s = retention_config_store.lock().await;
                    s.list_cluster_nodes().unwrap_or_default()
                };
                let pruned = tokio::task::spawn_blocking(move || {
                    let mut total = 0u64;
                    let retired_cutoff = chrono::Utc::now() - chrono::Duration::hours(24);
                    let nodes = telemetry.nodes_with_rows()?;
                    for node_id in &nodes {
                        let owner = roster.iter().find(|n| &n.node_id == node_id);
                        let retired = match owner {
                            None => true,
                            Some(n) => {
                                n.status == lorica_config::models::NodeStatus::Revoked
                                    && n.revoked_at.is_some_and(|at| at < retired_cutoff)
                            }
                        };
                        if retired {
                            let reclaimed = telemetry.forget_node(node_id)?;
                            if reclaimed > 0 {
                                tracing::info!(
                                    node_id,
                                    rows = reclaimed,
                                    "fleet telemetry of a retired node reclaimed"
                                );
                            }
                            total += reclaimed;
                            continue;
                        }
                        for table in [
                            lorica_api::cluster_telemetry_store::TelemetryTable::Access,
                            lorica_api::cluster_telemetry_store::TelemetryTable::Waf,
                        ] {
                            total += telemetry.enforce_node_quota(
                                table,
                                node_id,
                                lorica_api::cluster_telemetry_store::DEFAULT_ROWS_PER_NODE,
                            )?;
                        }
                    }
                    // A node that stops reporting keeps its rows until
                    // the quota reclaims them, but its BANS are live
                    // state: a snapshot nobody refreshed for a day is
                    // not a ban any more.
                    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
                    total += telemetry.prune_stale_bans(&cutoff)?;
                    Ok::<_, String>(total)
                })
                .await;
                match pruned {
                    Ok(Ok(0)) => {}
                    Ok(Ok(rows)) => {
                        tracing::info!(rows, "fleet telemetry retention reclaimed rows");
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "fleet telemetry retention failed");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "fleet telemetry retention task failed");
                    }
                }
            }
            // Expired ACME challenges (Story 9.5 AC #6). Reclaiming the
            // rows is housekeeping, so it rides this loop rather than
            // the request path: the read side already refuses an
            // expired entry, so a late purge costs storage, never
            // correctness. Runs on every node, because every node can
            // hold challenges it served.
            {
                let s = retention_config_store.lock().await;
                match s.purge_expired_acme_challenges(chrono::Utc::now()) {
                    Ok(0) => {}
                    Ok(purged) => {
                        tracing::info!(purged, "expired ACME challenges removed");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "ACME challenge purge failed");
                    }
                }
            }
            // Audit-log retention is day-based and chain-safe: the
            // store writes a retention seal before truncating so
            // /api/v1/audit/verify keeps passing (Story 8.9 AC #9).
            if let Some(logs) = &retention_log_store {
                if audit_retention_days > 0 {
                    let cutoff = (chrono::Utc::now()
                        - chrono::Duration::days(i64::from(audit_retention_days)))
                    .to_rfc3339();
                    match logs.enforce_audit_retention(&cutoff) {
                        Ok(0) => {}
                        Ok(deleted) => {
                            tracing::info!(
                                deleted,
                                "audit log retention: expired rows sealed and removed"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "audit log retention cleanup failed");
                        }
                    }
                }
            }
            {
                let s = retention_config_store.lock().await;
                if let Err(e) = s.purge_probe_results(1000) {
                    tracing::warn!(error = %e, "probe result retention cleanup failed");
                }
            }
            if let Some(logs) = &retention_log_store {
                if waf_retention > 0 {
                    if let Err(e) = logs.enforce_waf_retention(waf_retention as u64) {
                        tracing::warn!(error = %e, "WAF event retention cleanup failed");
                    }
                }
            }
            last_sla_purge_day = run_sla_purge(&retention_config_store, last_sla_purge_day).await;
        }
    });
}

/// Spawn the background OCSP-staple refresh loop (Story 8.5).
///
/// The cert resolver reloads cert bodies only (OCSP fetching was lifted
/// off the reload critical path, so a slow responder no longer delays a
/// freshly installed cert from being served). This loop attaches the
/// staples out-of-band: every 6 hours - or immediately when
/// [`crate::reload::ocsp_refresh_notify`] fires right after a cert
/// install / rotation - it re-reads the route-referenced certs from the
/// store, fetches a fresh staple per cert over the shared
/// `lorica_tls::ocsp` HTTP client, and arc-swaps them into the resolver
/// via [`lorica_tls::cert_resolver::CertResolver::refresh_staples`].
///
/// The `min(nextUpdate - now, 6h)` cadence from the story AC collapses
/// to a flat 6 h for every real-world CA (public OCSP `nextUpdate` is
/// days out, so the `6h` cap always wins); the notify path covers the
/// "staple a freshly installed cert within seconds" requirement. Must be
/// called from within a tokio runtime context; the `JoinHandle` is
/// detached (the loop lives for the whole process, like the resolver).
pub(crate) fn spawn_ocsp_refresh_loop(
    cert_resolver: Arc<lorica_tls::cert_resolver::CertResolver>,
    config_store: Arc<Mutex<ConfigStore>>,
) {
    const OCSP_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

    tokio::spawn(async move {
        // Per-domain instant of the last successful staple, feeding the
        // `cert_resolver_pending_ocsp_seconds` gauge.
        let mut last_ok: std::collections::HashMap<String, std::time::Instant> =
            std::collections::HashMap::new();
        let mut interval = tokio::time::interval(OCSP_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            // First `tick()` fires immediately, so boot certs get stapled
            // right away; thereafter the timer or a post-reload notify
            // wakes the loop, whichever comes first.
            tokio::select! {
                _ = interval.tick() => {}
                _ = lorica::reload::ocsp_refresh_notify().notified() => {}
            }

            // Snapshot the route-referenced certs under the store lock,
            // then drop it before any network I/O.
            let active_certs = {
                let s = config_store.lock().await;
                let certs = match s.list_certificates() {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(error = %e, "OCSP refresh: failed to list certificates");
                        continue;
                    }
                };
                let active_ids: std::collections::HashSet<String> = match s.list_routes() {
                    Ok(routes) => routes
                        .iter()
                        .filter_map(|r| r.certificate_id.clone())
                        .collect(),
                    Err(e) => {
                        warn!(error = %e, "OCSP refresh: failed to list routes");
                        continue;
                    }
                };
                certs
                    .into_iter()
                    .filter(|c| active_ids.contains(&c.id))
                    .collect::<Vec<_>>()
            };

            if active_certs.is_empty() {
                continue;
            }

            let fetches = active_certs
                .iter()
                .map(|c| lorica_tls::ocsp::try_fetch_ocsp(&c.cert_pem));
            let responses = futures_util::future::join_all(fetches).await;

            let now = std::time::Instant::now();
            let mut staples: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();
            let mut ok: u64 = 0;
            let mut fail: u64 = 0;

            for (c, resp) in active_certs.iter().zip(responses) {
                let domains: Vec<String> = std::iter::once(c.domain.to_lowercase())
                    .chain(c.san_domains.iter().map(|s| s.to_lowercase()))
                    .collect();
                match resp {
                    Some(bytes) => {
                        ok += 1;
                        for d in domains {
                            last_ok.insert(d.clone(), now);
                            lorica_api::metrics::set_cert_resolver_pending_ocsp_seconds(&d, 0.0);
                            staples.insert(d, bytes.clone());
                        }
                    }
                    None => {
                        fail += 1;
                        for d in &domains {
                            // Age the gauge only for domains that were
                            // stapled before; a never-stapled domain is
                            // "no staple yet", not "aging".
                            if let Some(t) = last_ok.get(d) {
                                let age = now.duration_since(*t).as_secs_f64();
                                lorica_api::metrics::set_cert_resolver_pending_ocsp_seconds(d, age);
                            }
                        }
                    }
                }
            }

            if !staples.is_empty() {
                let stats = cert_resolver.refresh_staples(&staples);
                info!(
                    refreshed = stats.refreshed,
                    unchanged = stats.unchanged,
                    ok,
                    fail,
                    "OCSP staples refreshed"
                );
            }
            lorica_api::metrics::inc_ocsp_refresh_by("ok", ok);
            lorica_api::metrics::inc_ocsp_refresh_by("fail", fail);
        }
    });
}

/// Spawn the backend health-check loop (audit H-9 dedup).
///
/// Reads `default_health_check_interval_s` from `GlobalSettings`
/// (default 10 s) and spawns `health::health_check_loop`.
///
/// Mode differences are explicit parameters:
/// - `backend_connections`: `Some` in single-process mode (direct
///   drain monitoring); `None` in supervisor mode where drain
///   monitoring is per-worker.
/// - `config_reload_tx`: `Some` in supervisor mode so a health-status
///   flip triggers a worker config reload; `None` in single-process
///   mode (no workers to notify).
///
/// Returns the `JoinHandle` so the caller can abort it at shutdown
/// (both modes keep it bound as `health_handle`).
pub(crate) async fn spawn_health_check_loop(
    store: &Arc<Mutex<ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    backend_connections: Option<Arc<BackendConnections>>,
    alert_sender: lorica_notify::AlertSender,
    config_reload_tx: Option<tokio::sync::broadcast::Sender<u64>>,
) -> tokio::task::JoinHandle<()> {
    let health_store = Arc::clone(store);
    let health_config = Arc::clone(proxy_config);
    let health_interval = {
        let s = store.lock().await;
        s.get_global_settings()
            .map(|gs| gs.default_health_check_interval_s as u64)
            .unwrap_or(10)
    };
    tokio::spawn(async move {
        crate::health::health_check_loop(
            health_store,
            health_config,
            health_interval,
            backend_connections,
            Some(alert_sender),
            config_reload_tx,
        )
        .await;
    })
}

/// Register the process-wide GeoIP / ASN resolver handles, and
/// optionally the rDNS resolver (audit H-9 dedup; all three process
/// modes call this).
///
/// `rdns_log_prefix` controls the rDNS half:
/// - `None` (supervisor): skip rDNS entirely - the supervisor never
///   evaluates bot-protection bypasses, it only keeps the on-disk
///   `.mmdb` files fresh.
/// - `Some(prefix)` (worker passes `"worker: "`, single-process passes
///   `""`): build the resolver from the system resolv.conf and
///   register it. The prefix keeps the original per-mode log lines
///   byte-identical.
///
/// Synchronous on purpose: `RdnsResolver::from_system_conf` latches
/// onto the *current* tokio runtime at construction, so worker mode
/// calls this from inside an `rt.enter()` guard (no async context
/// exists there). A failure to build the rDNS resolver is non-fatal -
/// it just disables the `bot_protection.bypass.rdns` category for this
/// process (other bot-protection categories keep working).
pub(crate) fn init_geo_resolver_handles(
    geoip: &Arc<lorica_geoip::GeoIpResolver>,
    asn: &Arc<lorica_geoip::AsnResolver>,
    rdns_log_prefix: Option<&str>,
) {
    lorica::geoip::set_handle(Arc::clone(geoip));
    lorica::geoip::set_asn_handle(Arc::clone(asn));
    let Some(prefix) = rdns_log_prefix else {
        return;
    };
    match lorica::bot_rdns::RdnsResolver::from_system_conf() {
        Ok(r) => {
            lorica::bot_rdns::set_handle(Arc::new(r));
            info!("{prefix}rDNS resolver initialised from system resolv.conf");
        }
        Err(e) => warn!(
            error = %e,
            "{prefix}rDNS resolver init failed; bot_protection.bypass.rdns will be a silent no-op"
        ),
    }
}

/// Run the SLA data purge if enabled and the schedule matches today.
/// Returns the day-of-month on which the last purge ran (used as guard to run once per day).
async fn run_sla_purge(store: &Arc<Mutex<ConfigStore>>, last_purge_day: u32) -> u32 {
    let today = chrono::Utc::now().day();
    if today == last_purge_day {
        return last_purge_day;
    }
    let s = store.lock().await;
    let gs = match s.get_global_settings() {
        Ok(gs) => gs,
        Err(_) => return last_purge_day,
    };
    if !gs.sla_purge_enabled {
        return last_purge_day;
    }
    let should_run = match gs.sla_purge_schedule.as_str() {
        "daily" => true,
        "first_of_month" => today == 1,
        other => other.parse::<u32>().is_ok_and(|d| d == today),
    };
    if !should_run {
        return last_purge_day;
    }
    let cutoff = chrono::Utc::now() - chrono::Duration::days(gs.sla_purge_retention_days as i64);
    match s.prune_sla_buckets(&cutoff) {
        Ok(n) if n > 0 => {
            tracing::info!(
                count = n,
                retention_days = gs.sla_purge_retention_days,
                "purged old SLA buckets"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "SLA purge failed");
        }
        _ => {}
    }
    today
}

/// Spawn alert dispatcher that also persists events to the log store (SQLite).
fn spawn_persisted_alert_dispatcher(
    alert_sender: &lorica_notify::AlertSender,
    dispatcher: Arc<Mutex<lorica_notify::NotifyDispatcher>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
) -> tokio::task::JoinHandle<()> {
    let mut rx = alert_sender.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    // Dispatch via channels (email, webhook, etc.)
                    let d = dispatcher.lock().await;
                    d.dispatch(&event).await;
                    drop(d);

                    // Persist to log store. Both calls are sync rusqlite under
                    // `parking_lot::Mutex<Connection>` ; running them inline
                    // would block the alert dispatcher's async reactor (audit
                    // H-7). Off-load both to one `spawn_blocking` so the
                    // mutex acquisition + the SELECT COUNT(*) + DELETE pair
                    // happen on the blocking pool, and surface retention
                    // failures via the existing notifier-events-dropped metric
                    // (was a silent `let _ = ...` swallow that left the table
                    // unbounded if DELETE ever failed).
                    if let Some(ref store) = log_store {
                        let store = Arc::clone(store);
                        let event_for_blocking = event.clone();
                        let blocking_outcome = tokio::task::spawn_blocking(move || {
                            let insert = store.insert_notification_event(&event_for_blocking);
                            let retention = store.enforce_notification_retention(500);
                            (insert, retention)
                        })
                        .await;
                        match blocking_outcome {
                            Ok((insert, retention)) => {
                                if let Err(e) = insert {
                                    tracing::warn!(error = %e, "failed to persist notification event");
                                    lorica_api::metrics::inc_notifier_events_dropped(
                                        "persist_failed",
                                        1,
                                    );
                                }
                                if let Err(e) = retention {
                                    tracing::warn!(error = %e, "notification retention enforcement failed");
                                    lorica_api::metrics::inc_notifier_events_dropped(
                                        "retention_failed",
                                        1,
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "notification persistence task join failed");
                                lorica_api::metrics::inc_notifier_events_dropped("join_failed", 1);
                            }
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(
                        dropped = n,
                        "alert dispatcher lagged, some notifications were dropped"
                    );
                    lorica_api::metrics::inc_notifier_events_dropped("lag", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    lorica_api::metrics::inc_notifier_events_dropped("closed", 1);
                    break;
                }
            }
        }
    })
}

/// Build a NotifyDispatcher from database notification configs.
pub(crate) fn build_notify_dispatcher(
    store: &lorica_config::ConfigStore,
) -> lorica_notify::NotifyDispatcher {
    let mut dispatcher = lorica_notify::NotifyDispatcher::new();
    if let Ok(configs) = store.list_notification_configs() {
        for nc in configs {
            let config_json = &nc.config;
            match nc.channel {
                lorica_config::models::NotificationChannel::Email => {
                    if let Ok(email_cfg) =
                        serde_json::from_str::<lorica_notify::channels::EmailConfig>(config_json)
                    {
                        dispatcher.add_email_channel(nc.id, email_cfg, nc.alert_types, nc.enabled);
                    }
                }
                lorica_config::models::NotificationChannel::Webhook => {
                    if let Ok(webhook_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_webhook_channel(
                            nc.id,
                            webhook_cfg,
                            nc.alert_types,
                            nc.enabled,
                        );
                    }
                }
                lorica_config::models::NotificationChannel::Slack => {
                    if let Ok(slack_cfg) =
                        serde_json::from_str::<lorica_notify::channels::WebhookConfig>(config_json)
                    {
                        dispatcher.add_slack_channel(nc.id, slack_cfg, nc.alert_types, nc.enabled);
                    }
                }
            }
        }
    }
    dispatcher
}

/// Try to initialise the OpenTelemetry exporter from persisted
/// `GlobalSettings`. No-op when the `otel` Cargo feature is off, the
/// settings row cannot be read, or `otlp_endpoint` is unset / blank.
///
/// Must be called from inside a Tokio runtime — the OTLP batch
/// exporter spawns a background flush task. `role` is a free-form
/// label (`"supervisor"`, `"worker"`, `"single-process"`) included in
/// the startup log line so multi-process installs can tell which
/// component finished tracing init.
///
/// Errors are logged at `warn!` and swallowed: observability is not
/// a critical path, so a misconfigured endpoint never blocks startup.
pub(crate) async fn try_init_otel_from_settings(
    store: &Arc<Mutex<lorica_config::ConfigStore>>,
    role: &str,
) {
    let s = store.lock().await;
    let gs = match s.get_global_settings() {
        Ok(gs) => gs,
        Err(e) => {
            warn!(error = %e, "failed to read global settings for OTel init");
            return;
        }
    };
    drop(s);

    let Some(endpoint) = gs.otlp_endpoint.as_ref().filter(|e| !e.trim().is_empty()) else {
        return;
    };

    let otel_cfg = lorica::otel::OtelConfig {
        endpoint: endpoint.clone(),
        protocol: lorica::otel::OtlpProtocol::from_settings(&gs.otlp_protocol),
        service_name: gs.otlp_service_name.clone(),
        sampling_ratio: gs.otlp_sampling_ratio,
    };
    match lorica::otel::init(&otel_cfg) {
        Ok(()) => info!(
            role = role,
            endpoint = %otel_cfg.endpoint,
            protocol = otel_cfg.protocol.as_str(),
            service_name = %otel_cfg.service_name,
            sampling_ratio = otel_cfg.sampling_ratio,
            "OpenTelemetry tracing enabled"
        ),
        Err(e) => warn!(
            role = role,
            error = %e,
            "OpenTelemetry init failed; tracing disabled (startup continues)"
        ),
    }
}

/// Restrict private key file permissions to owner-only read.
pub(crate) fn restrict_key_permissions(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        warn!(error = %e, path = %path.display(), "failed to restrict key file permissions");
        return false;
    }
    true
}

/// What [`spawn_cluster_runtime`] hands back to a startup mode.
pub(crate) struct ClusterStartup {
    /// The control plane, when `--cluster-listen` is set.
    pub plane: Option<cluster_plane::ClusterPlane>,
    /// The follower, when this node holds a fleet identity.
    pub follower: Option<cluster_follower::FollowerPlane>,
    /// The role handed to `AppState`.
    pub runtime: lorica_api::cluster::ClusterRuntime,
}

/// Start the fleet role shared by both startup modes (Stories
/// 9.2/9.3): the control-plane listeners and registry, opt-in via
/// `--cluster-listen`, or the follower dialer when this node holds a
/// fleet identity. Registers the Prometheus bridge. A bad bind, a
/// missing CA, or a node that is both is fatal: the operator asked
/// for a role, running without it is the wrong failure mode. The only
/// mode-specific input is the inherited operational socket inside
/// `opts`.
pub(crate) async fn spawn_cluster_runtime(
    opts: cluster_plane::ClusterPlaneOptions,
    store: &Arc<Mutex<ConfigStore>>,
    bans: cluster_follower::BanApplier,
) -> ClusterStartup {
    let drain_logs = opts.log_store.clone();
    let bans_for_drain = bans.clone();
    // Both roles need these; `opts` is consumed by the control-plane
    // path, so take the copies the follower needs first.
    let follower_reload = opts.config_reload.clone();
    let follower_alerts = opts.alert_sender.clone();
    let follower_data_dir = opts.data_dir.clone();
    let follower_log_store = opts.log_store.clone();
    let plane = match cluster_plane::spawn_cluster_plane(opts, store).await {
        Ok(Some(plane)) => {
            lorica_api::metrics::install_cluster_plane_stats(
                Arc::clone(&plane.operational_stats),
                Arc::clone(&plane.enrollment_stats),
            );
            // Story 9.4 AC #14: the per-node applied generation is read
            // from the live sessions at every scrape.
            lorica_api::metrics::install_cluster_registry(Arc::clone(&plane.control.sessions));
            Some(plane)
        }
        Ok(None) => None,
        Err(e) => {
            error!(error = %e, "cluster plane failed to start");
            std::process::exit(1);
        }
    };
    let follower = match cluster_follower::spawn_follower(
        cluster_follower::FollowerOptions {
            is_control_plane: plane.is_some(),
            config_reload: follower_reload,
            alert_sender: follower_alerts,
            bans,
            data_dir: follower_data_dir,
            log_store: follower_log_store,
        },
        store,
    )
    .await
    {
        Ok(follower) => follower,
        Err(e) => {
            error!(error = %e, "cluster follower failed to start");
            std::process::exit(1);
        }
    };
    // Story 9.6 AC #5/#7: the follower's telemetry drain. It rides
    // the same connection the dialer owns and reads the shared log
    // store by cursor, so it starts here, once the follower exists,
    // and only on a node that actually has a control plane to report
    // to.
    if let Some(follower) = &follower {
        let drain = telemetry_drain::spawn_telemetry_drain(
            Arc::clone(&follower.runtime),
            drain_logs,
            Arc::clone(store),
            bans_for_drain,
        );
        follower.watch(drain);
    }
    let runtime = match (&plane, &follower) {
        (Some(plane), _) => {
            // One runtime handle shared by the API and the binary's
            // replication tasks, so the drift bookkeeping the report
            // reads is the same one the alert loop advances.
            lorica_api::cluster::ClusterRuntime::ControlPlane(Arc::clone(&plane.runtime))
        }
        (None, Some(follower)) => {
            lorica_api::cluster::ClusterRuntime::Follower(Arc::clone(&follower.runtime))
        }
        (None, None) => lorica_api::cluster::ClusterRuntime::Standalone,
    };
    ClusterStartup {
        plane,
        follower,
        runtime,
    }
}

/// Inspect `encryption.key` before promoting it to the identity root
/// of a fleet (`lorica cluster init`), then tighten it to 0600.
///
/// Returns `Err` when the file is owned by a different uid than this
/// process (a key someone else controls must not become the fleet
/// root), `Ok(Some(warning))` when the file WAS readable beyond its
/// owner before being tightened (the key may already have leaked and
/// the operator must decide), and `Ok(None)` when it was already
/// private. The process uid is read from `/proc/self`, which the
/// kernel owns by the effective uid, so no libc binding is needed.
pub(crate) fn check_key_file_before_promotion(
    path: &std::path::Path,
) -> Result<Option<String>, String> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        std::fs::metadata(path).map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
    let process_uid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| format!("cannot determine the process uid from /proc/self: {e}"))?;
    if meta.uid() != process_uid {
        return Err(format!(
            "{} is owned by uid {} but this process runs as uid {}; the fleet identity root \
             must be owned by the service user",
            path.display(),
            meta.uid(),
            process_uid
        ));
    }
    let mode = meta.mode() & 0o777;
    let exposure = (mode & 0o077 != 0).then(|| {
        format!(
            "{} was mode {:04o} (readable beyond its owner) before being tightened to 0600; \
             treat the key as possibly exposed and consider `lorica rotate-key` before \
             clustering",
            path.display(),
            mode
        )
    });
    if !restrict_key_permissions(path) {
        return Err(format!("cannot restrict {} to mode 0600", path.display()));
    }
    Ok(exposure)
}

/// Persist the first-run admin password to a 0600 file under the data
/// directory and return its path.
///
/// The bootstrap credential must not reach stdout, because systemd runs
/// the service with `StandardOutput=journal`: the password would then
/// persist in `/var/log/journal`, readable by the `systemd-journal`
/// group long after the one-time login. Writing it to a service-owned
/// file with mode 0600 keeps it off the journal (audit M, CWE-532).
/// `must_change_password=true` still forces rotation on first login,
/// after which the operator deletes the file.
pub(crate) fn persist_initial_password(
    data_dir: &std::path::Path,
    password: &str,
) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = data_dir.join("initial-admin-password");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    // `mode` only applies on creation; force 0600 in case the file
    // pre-existed (a previous run that crashed after writing it).
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    writeln!(file, "{password}")?;
    Ok(path)
}

pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to install SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => {
            warn!("Received SIGTERM");
        }
        _ = sigint.recv() => {
            warn!("Received SIGINT");
        }
    }
}

#[cfg(test)]
mod tests {
    /// Story 9.5 AC #4 / D7 drift gate.
    ///
    /// OCSP stapling is a SERVING concern, not an issuance one: the
    /// loop attaches staples to the resolver the node actually
    /// terminates TLS from. Disabling it on followers would strip
    /// stapling from exactly the nodes serving client traffic, with
    /// no push path to replace it. AC #3 gates the renewal task and
    /// the expiry notifier on `is_follower`; the risk this test
    /// exists for is someone extending that guard by one line.
    ///
    /// The gate is deliberately a source scan rather than a runtime
    /// assertion, because the two call sites are in DIFFERENT
    /// PROCESSES (single-process boot, and each forked worker) and
    /// `supervisor.rs` never calls it at all. There is no single
    /// runtime in which both could be observed.
    #[test]
    fn ocsp_refresh_is_spawned_on_every_role_and_never_gated_on_being_a_follower() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/startup");
        let mut call_sites = Vec::new();

        for file in ["single.rs", "worker.rs"] {
            let src = std::fs::read_to_string(root.join(file))
                .unwrap_or_else(|e| panic!("test setup: {file} reads: {e}"));
            let lines: Vec<&str> = src.lines().collect();
            let calls: Vec<usize> = lines
                .iter()
                .enumerate()
                .filter(|(_, l)| {
                    l.contains("spawn_ocsp_refresh_loop(") && !l.trim_start().starts_with("//")
                })
                .map(|(i, _)| i)
                .collect();
            assert_eq!(
                calls.len(),
                1,
                "{file} must spawn the OCSP refresh loop exactly once; found {} call sites",
                calls.len()
            );

            // Nothing in the enclosing run-up may make this call
            // conditional on the node's cluster role. Twenty lines is
            // well past the top of both call sites' blocks.
            let call = calls[0];
            let from = call.saturating_sub(20);
            for (offset, line) in lines[from..call].iter().enumerate() {
                assert!(
                    !line.contains("is_follower"),
                    "{file}:{}: the OCSP refresh loop must not be gated on the node being a \
                     follower (Story 9.5 AC #4): stapling is a serving concern and a follower \
                     is exactly the node terminating client TLS",
                    from + offset + 1
                );
            }
            call_sites.push(file);
        }

        assert_eq!(call_sites, vec!["single.rs", "worker.rs"]);
    }
}
