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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use lorica_api::logs::LogBuffer;
use lorica_api::server::AppState;
use lorica_api::system::SystemCache;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use lorica::proxy_wiring::{LoricaProxy, ProxyConfig};
use lorica::reload::reload_proxy_config;

use crate::cli::Cli;
use crate::startup;
use crate::startup::{
    persist_initial_password, restrict_key_permissions, shutdown_signal,
    try_init_otel_from_settings,
};

// ---------------------------------------------------------------------------
// Single-process mode (original behavior, no workers)
// ---------------------------------------------------------------------------

pub(crate) fn run_single_process(cli: Cli) {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async move {
        // Ensure data directory exists
        let data_dir = PathBuf::from(&cli.data_dir);
        if let Err(e) = std::fs::create_dir_all(&data_dir) {
            error!(error = %e, path = %data_dir.display(), "failed to create data directory");
            std::process::exit(1);
        }

        // Load or create encryption key for certificate private keys at rest
        let key_path = data_dir.join("encryption.key");
        let encryption_key = match lorica_config::crypto::EncryptionKey::load_or_create(&key_path) {
            Ok(k) => k,
            Err(e) => {
                error!(error = %e, "failed to load/create encryption key");
                std::process::exit(1);
            }
        };
        restrict_key_permissions(&key_path);

        // Open the configuration database
        let db_path = data_dir.join("lorica.db");
        let store = match ConfigStore::open(&db_path, Some(encryption_key)) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to open configuration database");
                std::process::exit(1);
            }
        };
        restrict_key_permissions(&db_path);

        // Ensure an admin user exists (first-run password generation)
        match lorica_api::auth::ensure_admin_user(&store) {
            Ok(Some(password)) => match persist_initial_password(&data_dir, &password) {
                Ok(path) => {
                    println!();
                    println!("  ===================================================");
                    println!("  Initial admin password written to (mode 0600):");
                    println!("    {}", path.display());
                    println!("  Read it with:  sudo cat {}", path.display());
                    println!(
                        "  Login at https://localhost:{}/ (self-signed cert - accept the browser warning)",
                        cli.management_port
                    );
                    println!("  You will be asked to change it on first login,");
                    println!("  after which you can delete that file.");
                    println!("  ===================================================");
                    println!();
                    info!(path = %path.display(), "admin user created (first run); password written to 0600 file");
                }
                Err(e) => {
                    // Last resort: never lose the only copy of the
                    // bootstrap credential. Fall back to stdout (journal)
                    // with a warning so the operator can still log in.
                    warn!(error = %e, "failed to write initial password file; printing to stdout as fallback");
                    println!();
                    println!("  ===================================================");
                    println!("  Initial admin password: {password}");
                    println!(
                        "  Login at https://localhost:{}/ (self-signed cert - accept the browser warning)",
                        cli.management_port
                    );
                    println!("  You will be asked to change it on first login.");
                    println!("  ===================================================");
                    println!();
                }
            },
            Ok(None) => {}
            Err(e) => {
                error!(error = %e, "failed to ensure admin user");
                std::process::exit(1);
            }
        }

        let log_store = match lorica_api::log_store::LogStore::open(&data_dir) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                warn!(error = %e, "failed to open access log database, persistence disabled");
                None
            }
        };

        let store = Arc::new(Mutex::new(store));
        let log_buffer = Arc::new(LogBuffer::new(10_000));
        let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
        let connection_filter =
            Arc::new(lorica::connection_filter::GlobalConnectionFilter::empty());

        if let Err(e) = reload_proxy_config(&store, &proxy_config, Some(&connection_filter)).await {
            error!(error = %e, "failed to load initial proxy configuration");
            std::process::exit(1);
        }

        try_init_otel_from_settings(&store, "single-process").await;

        // Story 9.8: install the log-export sinks (syslog / OTLP
        // logs) from persisted settings. Reloads go through
        // apply_per_process_reload_state; this is the boot-time
        // equivalent, mirroring the OTel init above.
        lorica::reload::apply_log_sinks_from_store(&store).await;

        // Build the CertResolver for SNI-based certificate selection
        let cert_resolver = Arc::new(lorica_tls::cert_resolver::CertResolver::new());
        load_certs_into_resolver(&store, &cert_resolver).await;

        // Create shared WAF engine
        let waf_engine = Arc::new(lorica_waf::WafEngine::new());
        let waf_event_buffer = waf_engine.event_buffer();
        let waf_rule_count = waf_engine.rule_count();

        // Restore WAF state (IP blocklist, disabled + custom rules) from settings
        restore_waf_state(&store, &waf_engine).await;

        // Tracker shared by every background task that must drain on
        // shutdown. The shutdown path below calls `close(); wait().
        // await` on its clone, giving in-flight work a bounded time
        // to complete.
        let single_task_tracker = tokio_util::task::TaskTracker::new();

        // Spawn IP blocklist auto-refresh (every 6 hours, matching Data-Shield update frequency)
        let _blocklist_refresh = lorica_api::waf::spawn_blocklist_refresh(
            Arc::clone(&waf_engine),
            std::time::Duration::from_secs(6 * 3600),
            &single_task_tracker,
        );

        // Create non-blocking alert sender, then the notification
        // dispatcher + alert bridge + probe scheduler + SLA collector
        // cluster shared with supervisor mode (audit H-9, see
        // `startup::start_alerting_stack`). The dispatcher handle is
        // kept: the config-reload listener below rebuilds it when
        // notification channels change (Story 8.1 asymmetry, fixed in
        // v1.5.11: edits used to be ignored until restart in
        // single-process mode while supervisor mode hot-reloaded them).
        let alert_sender = lorica_notify::AlertSender::new(256);
        let startup::AlertingStack {
            notify_dispatcher,
            notification_history,
            probe_scheduler,
            sla_collector,
        } = startup::start_alerting_stack(&store, &alert_sender, log_store.clone()).await;

        // Load-test engine + cron scheduler (shared helper, see
        // `startup::start_load_test_engine`)
        let load_test_engine = startup::start_load_test_engine(&store);

        // Create shared ACME challenge store backed by SQLite for cross-process access
        let acme_challenge_store =
            lorica_api::acme::AcmeChallengeStore::with_db_path(db_path.clone());

        // Start the HTTP proxy service
        let mut lorica_proxy = LoricaProxy::new(
            Arc::clone(&proxy_config),
            Arc::clone(&log_buffer),
            Arc::clone(&active_connections),
            Arc::clone(&sla_collector),
        );
        lorica_proxy.waf_engine = Arc::clone(&waf_engine);
        lorica_proxy.acme_challenge_store = Some(acme_challenge_store.clone());
        lorica_proxy.alert_sender = Some(alert_sender.clone());
        // Hand the proxy a producer handle for the background log
        // writer (batched access-log + WAF-event persistence,
        // backlog #24) instead of a direct LogStore reference. A
        // clone also goes into AppState so the clear endpoints can
        // flush in-flight writes before wiping.
        let log_writer = log_store
            .as_ref()
            .map(|s| lorica_api::log_writer::spawn_log_writer(Arc::clone(s)));
        lorica_proxy.log_writer = log_writer.clone();

        // GeoIP: load the DB from `GlobalSettings.geoip_db_path` so
        // the request_filter can resolve client IPs. If auto-update is
        // enabled, also spawn the periodic refresh task inside the
        // current tokio runtime. Silent no-op when the path is unset
        // (installations without GeoIP pay nothing). The resolver
        // handle is also stashed in the process-wide `lorica::geoip`
        // static so `reload::apply_geoip_settings_from_store` can
        // hot-swap the DB when the dashboard changes the path,
        // without forcing a restart.
        // Handle registration + rDNS init for bot-protection's rdns
        // bypass (v1.4.0 follow-up) are shared across all three modes
        // (audit H-9, see `startup::init_geo_resolver_handles`). A
        // missing / broken resolv.conf is not fatal, it just disables
        // the rDNS bypass category for this process (other
        // bot-protection categories keep working).
        startup::init_geo_resolver_handles(
            &lorica_proxy.geoip_resolver,
            &lorica_proxy.asn_resolver,
            Some(""),
        );
        // Load + auto-update spawn are handled by
        // `apply_supervisor_settings_from_store` further down, after
        // `register_supervisor_reload_trigger`. That call does the
        // initial load via the same hot-reload path that fires on
        // every dashboard save, so boot and runtime behave identically.

        // Periodic prune of expired basic-auth cache entries so a
        // password-spray with no successful logins cannot grow the
        // cache unboundedly until next restart (PERF-8).
        let _basic_auth_prune = lorica_proxy
            .spawn_basic_auth_cache_prune(&single_task_tracker, Duration::from_secs(30));
        // Same lazy-prune for per-IP rate-limit buckets; see worker
        // path comment for rationale.
        let _rate_limit_prune = lorica_proxy.spawn_rate_limit_prune(
            &single_task_tracker,
            Duration::from_secs(60),
            Duration::from_secs(5 * 60),
        );
        let _bot_stash_prune = lorica_proxy.spawn_bot_stash_prune(&single_task_tracker);
        let backend_conns = Arc::clone(&lorica_proxy.backend_connections);
        let health_backend_conns = Arc::clone(&backend_conns);
        let proxy_cache_hits = Arc::clone(&lorica_proxy.cache_hits);
        let proxy_cache_misses = Arc::clone(&lorica_proxy.cache_misses);
        let proxy_ban_list = Arc::clone(&lorica_proxy.ban_list);
        let proxy_ewma_scores = lorica_proxy.ewma_tracker.scores_ref();
        let pool_size = {
            let s = store.lock().await;
            let backend_count = s.list_backends().map(|b| b.len()).unwrap_or(0);
            lorica::proxy_wiring::compute_pool_size(backend_count)
        };
        info!(pool_size, "upstream keepalive pool size");
        let server_conf = Arc::new(lorica_core::server::configuration::ServerConf {
            upstream_crl_file: cli.upstream_crl_file.clone(),
            upstream_keepalive_pool_size: pool_size,
            ..Default::default()
        });
        let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
        proxy_service.set_connection_filter(
            connection_filter.clone() as Arc<dyn lorica_core::listeners::ConnectionFilter>
        );
        let mut tcp_opts = lorica_core::listeners::TcpSocketOptions::default();
        tcp_opts.so_reuseport = Some(true);
        proxy_service.add_tcp_with_settings(&format!("0.0.0.0:{}", cli.http_port), tcp_opts);

        info!(port = cli.http_port, "HTTP proxy listener configured");

        // Add TLS listener with SNI-based cert resolver (always, even with no certs yet).
        // Connections to unknown domains fail TLS handshake; when the first cert is uploaded
        // and the resolver is reloaded, TLS starts working without restart.
        let https_port = cli.https_port;
        // Snapshot the CA fingerprint once at startup and pass the slot
        // to the reload loop further down so it can warn the operator
        // if an `mtls.ca_cert_pem` edit happens at runtime (rustls
        // ServerConfig is immutable; an edit needs a restart).
        let mtls_installed_fingerprint: Arc<parking_lot::Mutex<Option<String>>> =
            Arc::new(parking_lot::Mutex::new(None));
        {
            // Build the optional mTLS verifier from the union of per-route
            // CA bundles. `store` is a `tokio::sync::Mutex`, and we are
            // inside the `rt.block_on(async move { ... })` runtime
            // context — so we must `await` the lock instead of using
            // the blocking_lock which panics from within a runtime.
            let (mtls_verifier, startup_fp) = {
                let routes = store.lock().await.list_routes().unwrap_or_default();
                (
                    lorica::mtls::build_from_routes(&routes),
                    lorica::mtls::compute_ca_fingerprint(&routes),
                )
            };
            *mtls_installed_fingerprint.lock() = startup_fp.clone();
            if let Some(ref fp) = startup_fp {
                info!(fingerprint = %fp, "mTLS enabled at listener: per-route enforcement applies");
            }
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
            if let Some(ref v) = mtls_verifier {
                tls_settings.set_client_cert_verifier(v.clone());
            }
            let mut tls_tcp_opts = lorica_core::listeners::TcpSocketOptions::default();
            tls_tcp_opts.so_reuseport = Some(true);
            proxy_service.add_tls_with_settings(
                &format!("0.0.0.0:{https_port}"),
                Some(tls_tcp_opts),
                tls_settings,
            );
            info!(
                port = https_port,
                domains = cert_resolver.domain_count(),
                "HTTPS proxy listener configured with SNI resolver"
            );
        }

        // Create config reload channel so API mutations can trigger proxy reload
        let (config_reload_tx, mut config_reload_rx) = tokio::sync::watch::channel(0u64);

        // Register with the reload module so the GeoIP / ASN auto-
        // update task can bump the watch after every successful
        // download. Same rationale as the supervisor path: the
        // updater must be spawned in THIS process (we own the
        // resolver that serves requests), and the flag doubles as
        // a "this process owns the updater" marker for
        // `apply_auto_update_flip`.
        lorica::reload::register_supervisor_reload_trigger(config_reload_tx.clone());

        // Fire the hot-reload path once at boot so the resolvers
        // load from disk AND the updater tasks spawn if
        // `*_auto_update_enabled` is persisted true. Must run AFTER
        // `register_supervisor_reload_trigger` above.
        lorica::reload::apply_supervisor_settings_from_store(&store).await;

        // Clone sla_collector before the async move closure captures it
        let reload_sla_collector = Arc::clone(&sla_collector);

        // Clone alert_sender before it's moved into the API spawn block
        let health_alert_sender2 = alert_sender.clone();

        // Start API server
        let api_store = Arc::clone(&store);
        let api_log_buffer = Arc::clone(&log_buffer);
        let api_active_connections = Arc::clone(&active_connections);
        let api_log_store = log_store.clone();
        let management_port = cli.management_port;
        // `single_task_tracker` is already defined above (before the
        // WAF blocklist refresh spawn). Clone it for AppState and the
        // shutdown drain path.
        let api_task_tracker = single_task_tracker.clone();
        let shutdown_task_tracker = single_task_tracker.clone();
        let api_handle = tokio::spawn(async move {
            let state = AppState {
                store: api_store.clone(),
                log_buffer: api_log_buffer,
                system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
                active_connections: api_active_connections,
                started_at: Instant::now(),
                data_dir: PathBuf::from(&cli.data_dir),
                http_port: cli.http_port,
                https_port: cli.https_port,
                config_reload_tx: Some(config_reload_tx),
                // Single-process: the API shares the proxy's in-process
                // handles directly. No supervisor, so the hot-upgrade
                // endpoint stages only and there is no aggregated/refresher
                // path.
                mode: lorica_api::server::Mode::SingleProcess {
                    cache_hits: proxy_cache_hits,
                    cache_misses: proxy_cache_misses,
                    ban_list: proxy_ban_list,
                    ewma_scores: proxy_ewma_scores,
                    backend_connections: backend_conns.clone(),
                    cache_backend: &lorica::proxy_wiring::CACHE_BACKEND,
                },
                waf_event_buffer: Some(waf_event_buffer),
                waf_engine: Some(waf_engine),
                waf_rule_count: Some(waf_rule_count),
                acme_challenge_store: Some(acme_challenge_store),
                pending_dns_challenges: std::sync::Arc::new(dashmap::DashMap::new()),
                sla_collector: Some(Arc::clone(&sla_collector)),
                load_test_engine: Some(Arc::clone(&load_test_engine)),
                notification_history: Some(notification_history),
                log_store: api_log_store,
                log_writer: log_writer.clone(),
                task_tracker: api_task_tracker,
            };

            // Session store + ACME auto-renewal + cert-expiry notifier
            // + server loop, shared with supervisor mode (audit H-9,
            // see `startup::run_api_server`). No inherited listener:
            // single-process binds the management port fresh.
            startup::run_api_server(management_port, state, alert_sender, None).await;
        });

        // Hourly retention loop (access logs, probe results, WAF
        // events, SLA buckets), shared across modes (audit H-9, see
        // `startup::spawn_retention_loop`). No-op when the access-log
        // store failed to open.
        startup::spawn_retention_loop(log_store.clone(), Arc::clone(&store));

        // Background OCSP-staple refresh (Story 8.5). Reload swaps cert
        // bodies with no staple; this loop attaches OCSP responses out
        // of band, nudged immediately after each reload.
        startup::spawn_ocsp_refresh_loop(Arc::clone(&cert_resolver), Arc::clone(&store));

        // Background task: reload proxy config, cert resolver, and probe scheduler when API signals a change
        let reload_store = Arc::clone(&store);
        let reload_config = Arc::clone(&proxy_config);
        let reload_cert_resolver = Arc::clone(&cert_resolver);
        let reload_probe_scheduler = Arc::clone(&probe_scheduler);
        let reload_connection_filter = Arc::clone(&connection_filter);
        let reload_mtls_fp = Arc::clone(&mtls_installed_fingerprint);
        let reload_notify_dispatcher = Arc::clone(&notify_dispatcher);
        let _reload_handle = tokio::spawn(async move {
            while config_reload_rx.changed().await.is_ok() {
                if let Err(e) = lorica::reload::reload_proxy_config_with_mtls(
                    &reload_store,
                    &reload_config,
                    Some(&reload_connection_filter),
                    Some(&*reload_mtls_fp),
                )
                .await
                {
                    tracing::error!(error = %e, "failed to reload proxy configuration");
                }
                lorica::reload::reload_cert_resolver(&reload_store, &reload_cert_resolver).await;
                reload_probe_scheduler.reload().await;
                {
                    let s = reload_store.lock().await;
                    reload_sla_collector.load_configs(&s);
                    // Rebuild notification dispatcher with updated
                    // channel configs, mirroring supervisor mode
                    // (Story 8.1 asymmetry, fixed in v1.5.11).
                    let new_dispatcher = startup::build_notify_dispatcher(&s);
                    let mut d = reload_notify_dispatcher.lock().await;
                    *d = new_dispatcher;
                }
            }
        });

        // Start health check background task. Spawn shared with
        // supervisor mode (audit H-9, see
        // `startup::spawn_health_check_loop`). Single-process mode
        // passes direct backend-connection handles for drain
        // monitoring and has no workers to notify on a status flip.
        let health_handle = startup::spawn_health_check_loop(
            &store,
            &proxy_config,
            Some(health_backend_conns),
            health_alert_sender2,
            None,
        )
        .await;

        // Run the proxy engine in a dedicated thread
        let _proxy_thread = std::thread::spawn(move || {
            let mut server =
                lorica_core::server::Server::new(None).expect("failed to create proxy server");
            server.bootstrap();
            server.add_service(proxy_service);
            server.run_forever();
        });

        // Tell systemd we are accepting. REQUIRED for `Type=notify` or
        // systemd times the unit out and marks the start failed. No-op
        // when `$NOTIFY_SOCKET` is unset (Docker, manual run). MAINPID is
        // self here (single-process has no handover), a no-op for a cold
        // start. Mirrors the supervisor cold path.
        let self_pid = std::process::id() as i32;
        match crate::startup::hot_upgrade::sd_notify_ready(self_pid) {
            Ok(true) => info!(pid = self_pid, "sent sd_notify READY + MAINPID"),
            Ok(false) => info!("NOTIFY_SOCKET unset, skipping sd_notify"),
            Err(e) => warn!(error = %e, "sd_notify failed"),
        }

        // Wait for shutdown signal
        shutdown_signal().await;

        info!("Lorica shutting down gracefully");

        // Drain tracked background tasks before tearing down the API
        // server. Bounded at 10 s so a hung task does not delay exit.
        shutdown_task_tracker.close();
        if tokio::time::timeout(Duration::from_secs(10), shutdown_task_tracker.wait())
            .await
            .is_err()
        {
            warn!("some background tasks did not finish within drain timeout; aborting");
        }
        api_handle.abort();
        health_handle.abort();

        // Flush the OTel batch exporter before the runtime drops so
        // in-flight spans reach the collector on clean shutdown. No-op
        // when the `otel` feature is off or when the endpoint was
        // never configured, so it's always safe to call.
        lorica::otel::shutdown();
    });
}

/// Load every persisted certificate into the SNI resolver at boot. OCSP
/// staples are attached out of band by the background refresh loop, so
/// each `CertData` starts with `ocsp_response: None`. A parse failure on
/// an individual bundle is counted and skipped, never fatal.
async fn load_certs_into_resolver(
    store: &Arc<Mutex<ConfigStore>>,
    cert_resolver: &Arc<lorica_tls::cert_resolver::CertResolver>,
) {
    let s = store.lock().await;
    let db_certs = s.list_certificates().unwrap_or_default();
    if db_certs.is_empty() {
        return;
    }
    let cert_data: Vec<lorica_tls::cert_resolver::CertData> = db_certs
        .iter()
        .map(|c| lorica_tls::cert_resolver::CertData {
            domain: c.domain.clone(),
            san_domains: c.san_domains.clone(),
            cert_pem: c.cert_pem.clone(),
            key_pem: c.key_pem.clone(),
            not_after_epoch: c.not_after.timestamp(),
            ocsp_response: None, // OCSP fetched asynchronously on reload_cert_resolver
        })
        .collect();
    match cert_resolver.reload(cert_data) {
        Ok(stats) => {
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
                "loaded certificates into SNI resolver"
            );
        }
        Err(e) => warn!(error = %e, "failed to load certificates into resolver"),
    }
}

/// Restore WAF runtime state from persisted settings: the IP blocklist
/// (enable flag plus an initial Data-Shield fetch when on), the operator
/// disabled-rule set, and any custom rules. Single-process mode owns the
/// blocklist fetch (workers inherit the enable flag only).
async fn restore_waf_state(store: &Arc<Mutex<ConfigStore>>, waf_engine: &Arc<lorica_waf::WafEngine>) {
    let s = store.lock().await;
    if let Ok(settings) = s.get_global_settings() {
        if settings.ip_blocklist_enabled {
            waf_engine.ip_blocklist().set_enabled(true);
            match lorica_api::waf::fetch_and_load_blocklist(waf_engine.ip_blocklist()).await {
                Ok(count) => info!(count, "IP blocklist loaded at startup"),
                Err(e) => warn!(error = %e, "IP blocklist initial load failed"),
            }
        }
    }
    if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
        if !disabled_ids.is_empty() {
            waf_engine.set_disabled_rules(&disabled_ids);
            info!(count = disabled_ids.len(), "WAF disabled rules restored");
        }
    }
    if let Ok(custom_rules) = s.load_waf_custom_rules() {
        for (id, desc, cat, pattern, severity, _enabled) in &custom_rules {
            let category = cat
                .parse()
                .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
            let _ = waf_engine.add_custom_rule(*id, desc.clone(), category, pattern, *severity);
        }
        if !custom_rules.is_empty() {
            info!(count = custom_rules.len(), "WAF custom rules restored");
        }
    }
}
