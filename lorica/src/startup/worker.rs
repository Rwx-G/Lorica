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
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use lorica::proxy_wiring::{LoricaProxy, ProxyConfig};
use lorica::reload::reload_proxy_config;

use crate::startup;
use crate::startup::stream_plane::StoreStreamTable;
use crate::startup::try_init_otel_from_settings;

// ---------------------------------------------------------------------------
// Worker mode (Unix only): receives FDs from supervisor, runs proxy engine
// ---------------------------------------------------------------------------

pub(crate) fn run_worker(
    id: u32,
    cmd_fd: i32,
    data_dir: &str,
    https_port: u16,
    upstream_crl_file: Option<&str>,
    reserved_ports: Option<lorica_config::listen_ports::ReservedPorts>,
) {
    use lorica_command::{Command, CommandChannel, CommandType, Response};
    use lorica_core::server::Fds;
    use lorica_worker::fd_passing;
    use std::os::fd::{FromRawFd, OwnedFd};

    info!(worker_id = id, cmd_fd = cmd_fd, "worker starting");

    // Receive typed FDs from supervisor via SCM_RIGHTS. Listener entries
    // register with the Fds table; a `Shmem` entry (if present) is
    // adopted via `lorica_shmem::SharedRegion::open_worker`.
    let entries = match fd_passing::recv_worker_fds(cmd_fd) {
        Ok(entries) => entries,
        Err(e) => {
            error!(error = %e, "worker failed to receive FDs");
            std::process::exit(1);
        }
    };

    let mut fds = Fds::new();
    let mut listener_addrs: Vec<String> = Vec::new();
    let mut shmem_region: Option<&'static lorica_shmem::SharedRegion> = None;
    let mut rpc_fd: Option<i32> = None;
    let mut stream_ctl_fd: Option<OwnedFd> = None;
    let mut listener_count = 0usize;
    for entry in entries {
        match entry.kind {
            fd_passing::FdKind::Listener { addr } => {
                fds.add(addr.clone(), entry.fd);
                listener_addrs.push(addr.clone());
                listener_count += 1;
                info!(worker_id = id, addr = %addr, fd = entry.fd, "registered listener FD");
            }
            fd_passing::FdKind::Shmem => {
                match unsafe { lorica_shmem::SharedRegion::open_worker(entry.fd) } {
                    Ok(region) => {
                        shmem_region = Some(region);
                        info!(worker_id = id, fd = entry.fd, "adopted shmem region");
                    }
                    Err(e) => {
                        error!(worker_id = id, error = %e, "worker failed to open shmem region");
                        std::process::exit(1);
                    }
                }
            }
            fd_passing::FdKind::Rpc => {
                rpc_fd = Some(entry.fd);
                info!(worker_id = id, fd = entry.fd, "adopted RPC channel FD");
            }
            fd_passing::FdKind::StreamCtl => {
                // SAFETY: `recv_worker_fds` hands each received FD over
                // with exclusive ownership; nothing else refers to it.
                stream_ctl_fd = Some(unsafe { OwnedFd::from_raw_fd(entry.fd) });
                info!(worker_id = id, fd = entry.fd, "adopted stream control FD");
            }
            fd_passing::FdKind::StreamSocket { proto, addr, .. } => {
                // Stream sockets only travel over the stream control
                // channel; one in the fork bundle is closed, not served.
                // SAFETY: as above, the FD is exclusively ours.
                drop(unsafe { OwnedFd::from_raw_fd(entry.fd) });
                warn!(worker_id = id, %proto, %addr, "closed a stream socket sent in the fork bundle");
            }
        }
    }

    info!(
        worker_id = id,
        listener_count,
        shmem = shmem_region.is_some(),
        rpc = rpc_fd.is_some(),
        stream_ctl = stream_ctl_fd.is_some(),
        "received worker FDs"
    );

    // Open the configuration database with encryption key
    let data_dir = PathBuf::from(data_dir);
    let key_path = data_dir.join("encryption.key");
    let encryption_key = match lorica_config::crypto::EncryptionKey::load_or_create(&key_path) {
        Ok(key) => Some(key),
        Err(e) => {
            error!(
                error = %e,
                path = %key_path.display(),
                "worker: failed to load encryption key - database opens WITHOUT encryption"
            );
            None
        }
    };
    let db_path = data_dir.join("lorica.db");
    let store = match ConfigStore::open(&db_path, encryption_key.clone()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "worker failed to open database");
            std::process::exit(1);
        }
    };

    // The stream runtime (Story 12.2 D-b), started as soon as the store
    // opens so the supervisor's first `attach` is answered well inside
    // its ack timeout. The handle lives as long as the worker: dropping
    // it stops the runtime.
    let Some(stream_ctl_fd) = stream_ctl_fd else {
        error!(worker_id = id, "worker received no stream control FD");
        std::process::exit(1);
    };
    let stream_source = match StoreStreamTable::open(&db_path, encryption_key) {
        Ok(source) => Arc::new(source),
        Err(e) => {
            error!(error = %e, "worker failed to open the stream table");
            std::process::exit(1);
        }
    };
    // The TCP engine (Story 12.3). Its breaker gate admits until the
    // RPC endpoint, created well after this, installs the supervisor's
    // registry below (D-g). No UDP engine until Story 12.5: a datagram
    // is dropped.
    if reserved_ports.is_none() {
        warn!(
            worker_id = id,
            "started without --reserved-ports; stream connects refuse only the stream listen ports"
        );
    }
    let stream_breaker = Arc::new(lorica::stream_engine::StreamBreakerGate::new());
    let stream_runtime = match lorica_stream::StreamRuntime::spawn(
        lorica_stream::ControlTransport::Seqpacket(stream_ctl_fd),
        lorica::stream_engine::tcp_engines(
            Arc::clone(&stream_breaker),
            Arc::new(lorica::stream_engine::HickoryResolve::from_system_conf()),
            reserved_ports,
        ),
        Arc::clone(&stream_source) as Arc<dyn lorica_stream::StreamTableSource>,
    ) {
        Ok(handle) => Arc::new(handle),
        Err(e) => {
            error!(worker_id = id, error = %e, "worker failed to start the stream runtime");
            std::process::exit(1);
        }
    };
    match lorica_worker::stream_sockets::process_fd_limit() {
        Ok(limit) => info!(worker_id = id, fd_limit = limit, "process fd limit"),
        Err(e) => warn!(worker_id = id, error = %e, "process fd limit unreadable"),
    }

    let store = Arc::new(Mutex::new(store));
    let log_buffer = Arc::new(LogBuffer::new(10_000));
    let active_connections = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::default()));
    // Listener-level connection filter with hot-reloadable CIDR policy.
    // The supervisor broadcasts settings changes via the command channel; the
    // filter is refreshed inline with ProxyConfig so listener state never
    // drifts from the rest of the configuration.
    let connection_filter = Arc::new(lorica::connection_filter::GlobalConnectionFilter::empty());

    // Load initial proxy configuration
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        if let Err(e) = reload_proxy_config(&store, &proxy_config, Some(&connection_filter)).await {
            error!(error = %e, "worker failed to load proxy configuration");
            std::process::exit(1);
        }
        // Story 8.2 AC #8 / Epic-8.1 mode parity. A freshly forked,
        // respawned, or hot-upgraded worker lazy-inits the process-wide
        // merged AI-crawler registry with the BUILT-INS ONLY, and
        // `reload_proxy_config` above does not touch that registry. Without
        // this rebuild, operator-defined custom AI-crawler deny rows are
        // silently unenforced on this worker until the next config
        // mutation reaches it. Rebuild once here from the store so the
        // worker enforces existing custom rows from its first request -
        // single-process boot already gets the same rebuild via
        // `apply_supervisor_settings_from_store`. Idempotent and lenient:
        // a malformed custom row is dropped, logged, and counted, never
        // blanking the live registry. Scoped to the registry (rather than
        // the full `apply_per_process_reload_state` bundle) because worker
        // boot already applies OTel above and GeoIP/ASN below through
        // mode-specific code; routing the whole bundle here would re-init
        // OTel and race the not-yet-registered resolver handles.
        lorica::reload::rebuild_merged_crawlers(&store).await;
    });

    // Initialise the OTel exporter in this worker's runtime. Must run
    // *after* fork and *inside* the worker's runtime so the batch
    // processor's background task lives on the right reactor. Each
    // worker thus maintains its own independent exporter; spans emitted
    // on one worker do not block another worker's flush queue. The
    // supervisor has its own init (for API / health spans).
    rt.block_on(try_init_otel_from_settings(&store, "worker"));

    // Story 9.8: install this worker's log-export sinks at boot
    // (access logs and WAF events are produced in the worker
    // process). Reloads refresh them via
    // apply_per_process_reload_state in the two-phase commit handler
    // and the legacy fallback.
    rt.block_on(lorica::reload::apply_log_sinks_from_store(&store));

    // Build CertResolver for TLS termination in worker
    let cert_resolver = Arc::new(lorica_tls::cert_resolver::CertResolver::new());
    rt.block_on(worker_load_certs_into_resolver(&store, &cert_resolver, id));

    // Pre-create metric Arcs so the command thread can read them
    let worker_cache_hits = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let worker_cache_misses = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let worker_ban_list: Arc<lorica_api::ban::BanMap> = Arc::new(dashmap::DashMap::new());
    let worker_ewma = Arc::new(lorica::proxy_wiring::EwmaTracker::new());
    let worker_backend_conns = Arc::new(lorica::proxy_wiring::BackendConnections::new());
    let worker_request_counts: Arc<dashmap::DashMap<(String, u16), std::sync::atomic::AtomicU64>> =
        Arc::new(dashmap::DashMap::new());
    let worker_waf_counts: Arc<dashmap::DashMap<(String, String), std::sync::atomic::AtomicU64>> =
        Arc::new(dashmap::DashMap::new());

    // Create shared WAF engine for worker (must be before command channel setup)
    let waf_engine = Arc::new(lorica_waf::WafEngine::new());
    // Every event must reach the supervisor, which alerts and bans:
    // number them from the first request on.
    waf_engine.enable_forwarding();
    worker_restore_waf_state(&store, &waf_engine);

    // Start the command channel listener in a background thread
    // (the proxy server's run_forever blocks the main thread)
    let cmd_store = Arc::clone(&store);
    let cmd_config = Arc::clone(&proxy_config);
    let cmd_cert_resolver = Arc::clone(&cert_resolver);
    let cmd_waf_engine = Arc::clone(&waf_engine);
    let cmd_cache_hits = Arc::clone(&worker_cache_hits);
    let cmd_cache_misses = Arc::clone(&worker_cache_misses);
    let cmd_active_conns = Arc::clone(&active_connections);
    let cmd_ban_list = Arc::clone(&worker_ban_list);
    let cmd_ewma = worker_ewma.scores_ref();
    let cmd_backend_conns = Arc::clone(&worker_backend_conns);
    let cmd_request_counts = Arc::clone(&worker_request_counts);
    let cmd_waf_counts = Arc::clone(&worker_waf_counts);
    let cmd_connection_filter = Arc::clone(&connection_filter);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("failed to create command channel runtime");
        rt.block_on(async move {
            // SAFETY: cmd_fd is the socketpair file descriptor passed by the
            // supervisor via --cmd-fd CLI arg. It is exclusively owned by this
            // worker process after fork/exec.
            let mut channel = match unsafe { CommandChannel::from_raw_fd(cmd_fd) } {
                Ok(ch) => ch,
                Err(e) => {
                    error!(error = %e, "worker failed to create command channel");
                    return;
                }
            };
            // Worker recv timeout must be longer than supervisor heartbeat interval
            channel.set_timeout(std::time::Duration::from_secs(30));

            info!(worker_id = id, "command channel listener started");

            loop {
                let cmd: Command = match channel.recv().await {
                    Ok(cmd) => cmd,
                    Err(e) => {
                        warn!(worker_id = id, error = %e, "command channel recv error");
                        // Channel closed - supervisor probably shut down
                        break;
                    }
                };

                match cmd.typed_command() {
                    CommandType::ConfigReload => {
                        info!(worker_id = id, seq = cmd.sequence, "applying config reload");
                        // Sync WAF state from persisted settings/DB
                        {
                            let s = cmd_store.lock().await;
                            if let Ok(settings) = s.get_global_settings() {
                                cmd_waf_engine
                                    .ip_blocklist()
                                    .set_enabled(settings.ip_blocklist_enabled);
                            }
                            // Reload disabled rules
                            if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
                                cmd_waf_engine.set_disabled_rules(&disabled_ids);
                            }
                            // Reload custom rules
                            cmd_waf_engine.clear_custom_rules();
                            if let Ok(custom_rules) = s.load_waf_custom_rules() {
                                for (rule_id, desc, cat, pattern, severity, _enabled) in
                                    &custom_rules
                                {
                                    let category = cat
                                        .parse()
                                        .unwrap_or(lorica_waf::RuleCategory::ProtocolViolation);
                                    let _ = cmd_waf_engine.add_custom_rule(
                                        *rule_id,
                                        desc.clone(),
                                        category,
                                        pattern,
                                        *severity,
                                    );
                                }
                            }
                        }
                        match reload_proxy_config(
                            &cmd_store,
                            &cmd_config,
                            Some(&cmd_connection_filter),
                        )
                        .await
                        {
                            Ok(()) => {
                                // Rebuild the cert resolver AFTER the
                                // proxy config is committed so any new
                                // routes referencing a cert are
                                // resolvable on the first subsequent
                                // handshake, and so any TLS-settings
                                // change lands on the same snapshot
                                // the proxy just adopted.
                                lorica::reload::reload_cert_resolver(
                                    &cmd_store,
                                    &cmd_cert_resolver,
                                )
                                .await;
                                // Re-apply the full per-process reload
                                // state (OTel exporter, GeoIP / ASN
                                // updater task lifecycle, bot HMAC
                                // secret, AND the merged AI-crawler
                                // registry rebuild) so the legacy
                                // fallback path converges with the
                                // two-phase RPC commit handler. Audit
                                // M-18 closure : before this, falling
                                // back to the legacy ConfigReload (e.g.
                                // when two-phase Prepare timed out) left
                                // GeoIP / OTel / ASN / bot-secret AND
                                // the AI-crawler registry frozen even
                                // though the proxy config swap completed.
                                lorica::reload::apply_per_process_reload_state(
                                    &cmd_store,
                                )
                                .await;
                                let resp = Response::ok(cmd.sequence);
                                if let Err(e) = channel.send(&resp).await {
                                    warn!(error = %e, "failed to send response");
                                }
                            }
                            Err(e) => {
                                error!(
                                    worker_id = id,
                                    error = %e,
                                    "config reload failed"
                                );
                                let resp = Response::error(cmd.sequence, e.to_string());
                                if let Err(e) = channel.send(&resp).await {
                                    warn!(error = %e, "failed to send error response");
                                }
                            }
                        }
                    }
                    CommandType::Heartbeat => {
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send heartbeat response");
                        }
                    }
                    CommandType::Shutdown => {
                        info!(worker_id = id, "received shutdown command");
                        let resp = Response::ok(cmd.sequence);
                        let _ = channel.send(&resp).await;
                        std::process::exit(0);
                    }
                    CommandType::MetricsRequest => {
                        // Build the snapshot through the SAME shared builder
                        // the pipelined-RPC handler uses, so this legacy
                        // channel report also carries `generic_counters`
                        // (bot_challenge, geoip_block, ai_bot,
                        // cert_resolver_reload, ocsp_refresh, ...). This arm
                        // used to build its own report and omit them, which
                        // silently zeroed every per-worker generic counter
                        // whenever the supervisor pulled metrics over the
                        // legacy channel (which it still does, as the
                        // periodic-pull populator behind the RPC pull-on-
                        // scrape path).
                        let metrics_ctx =
                            lorica::proxy_wiring::worker_rpc::WorkerMetricsCtx::new(
                                Arc::clone(&cmd_ban_list),
                                Arc::clone(&cmd_ewma),
                                Arc::clone(&cmd_backend_conns),
                                Arc::clone(&cmd_request_counts),
                                Arc::clone(&cmd_waf_counts),
                                Arc::clone(&cmd_cache_hits),
                                Arc::clone(&cmd_cache_misses),
                                Arc::clone(&cmd_active_conns),
                            );
                        let report = metrics_ctx.build_report(id);

                        if let Err(e) = channel.send(&report).await {
                            warn!(error = %e, "failed to send metrics report");
                        }
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send metrics response");
                        }
                    }
                    CommandType::BanIp => {
                        let ip = cmd.ban_ip.clone();
                        let duration_s = cmd.ban_duration_s;
                        if apply_ban_ip(&cmd_ban_list, &ip, duration_s, cmd.ban_reason) {
                            info!(
                                worker_id = id,
                                ip = %ip,
                                ban_duration_s = %duration_s,
                                "applied BanIp from supervisor"
                            );
                        }
                        let resp = Response::ok(cmd.sequence);
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send BanIp response");
                        }
                    }
                    CommandType::Unspecified => {
                        warn!(worker_id = id, "received unspecified command");
                    }
                    // Pipelined RPC command variants (Phase 1 framework,
                    // see docs/architecture/worker-shared-state.md § 4).
                    // The legacy CommandChannel used here is request/reply
                    // inline; the pipelined RPC uses RpcEndpoint on a
                    // separate (future) socketpair. Any RPC-typed Command
                    // arriving on this channel is a protocol misuse; reply
                    // with a clear error so the supervisor can log it.
                    CommandType::RateLimitQuery
                    | CommandType::RateLimitDelta
                    | CommandType::VerdictLookup
                    | CommandType::VerdictPush
                    | CommandType::BreakerQuery
                    | CommandType::BreakerReport
                    | CommandType::ConfigReloadPrepare
                    | CommandType::ConfigReloadCommit
                    | CommandType::ConfigReloadAbort => {
                        warn!(
                            worker_id = id,
                            command_type = ?cmd.typed_command(),
                            "RPC-typed command delivered on legacy channel; expected the pipelined RpcEndpoint"
                        );
                        let resp = Response::error(
                            cmd.sequence,
                            "pipelined RPC command on legacy channel",
                        );
                        if let Err(e) = channel.send(&resp).await {
                            warn!(error = %e, "failed to send RPC protocol-error response");
                        }
                    }
                }
            }
        });
    });

    // Create SLA collector and load configs
    let sla_collector = Arc::new(lorica_bench::SlaCollector::new());
    rt.block_on(async {
        let s = store.lock().await;
        sla_collector.load_configs(&s);
    });

    // Worker background tasks: log forwarding + WAF event forwarding via UDS + SLA flush to DB
    let log_fwd_buffer = Arc::clone(&log_buffer);
    let sla_flush_collector = Arc::clone(&sla_collector);
    let sla_flush_store = Arc::clone(&store);
    let log_sock_path = PathBuf::from(&data_dir).join("log.sock");
    let waf_fwd_engine = Arc::clone(&waf_engine);
    let waf_sock_path_worker = PathBuf::from(&data_dir).join("waf.sock");
    // Filled by the proxy's rate-limit stage, drained by the forwarder.
    let rate_limit_bans = Arc::new(lorica::proxy_wiring::RateLimitBanQueue::default());
    let fwd_rate_limit_bans = Arc::clone(&rate_limit_bans);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("worker background runtime");
        rt.block_on(async move {
            sla_flush_collector.start_flush_task(sla_flush_store, None);

            // IP blocklist: initial load + periodic refresh (every 6h)
            if waf_fwd_engine.ip_blocklist().is_enabled() {
                match lorica_api::waf::fetch_and_load_blocklist(waf_fwd_engine.ip_blocklist()).await
                {
                    Ok(count) => tracing::info!(count, "worker: IP blocklist loaded at startup"),
                    Err(e) => {
                        tracing::warn!(error = %e, "worker: IP blocklist initial load failed")
                    }
                }
            }
            let blocklist_engine = Arc::clone(&waf_fwd_engine);
            // Worker mode has no supervisor drain; a local tracker
            // is fine (worker shutdown is orchestrated by the
            // supervisor via SIGTERM + drain-timeout anyway).
            let worker_blocklist_tracker = tokio_util::task::TaskTracker::new();
            lorica_api::waf::spawn_blocklist_refresh(
                blocklist_engine,
                std::time::Duration::from_secs(6 * 3600),
                &worker_blocklist_tracker,
            );

            // Forward WAF events and rate-limit bans to supervisor. A
            // write error reconnects: forwarding is what alerts and
            // auto-bans run on, so it must not stop for the life of the
            // worker. The batch being written when the socket broke is
            // lost, and logged; a ban in it holds on this worker only.
            tokio::spawn(async move {
                let mut cursor = super::waf_forward::WafForwardCursor::new();
                loop {
                    let stream = loop {
                        match tokio::net::UnixStream::connect(&waf_sock_path_worker).await {
                            Ok(s) => break s,
                            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                        }
                    };
                    let mut writer = tokio::io::BufWriter::new(stream);
                    let mut interval = tokio::time::interval(super::waf_forward::FORWARD_INTERVAL);
                    'forward: loop {
                        interval.tick().await;
                        let mut batch = cursor.take_batch(&waf_fwd_engine);
                        batch.bans = fwd_rate_limit_bans.take();
                        if batch.is_empty() {
                            continue;
                        }
                        for line in batch.into_lines() {
                            if let Err(e) =
                                tokio::io::AsyncWriteExt::write_all(&mut writer, line.as_bytes())
                                    .await
                            {
                                tracing::error!(
                                    error = %e,
                                    "worker: WAF event stream to the supervisor broke; \
                                     reconnecting, the batch in flight is lost"
                                );
                                break 'forward;
                            }
                        }
                        if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut writer).await {
                            tracing::error!(
                                error = %e,
                                "worker: WAF event stream to the supervisor broke; \
                                 reconnecting, the batch in flight is lost"
                            );
                            break 'forward;
                        }
                    }
                }
            });

            // Connect to supervisor's log socket (retry until available)
            let stream = loop {
                match tokio::net::UnixStream::connect(&log_sock_path).await {
                    Ok(s) => break s,
                    Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
                }
            };
            let mut writer = tokio::io::BufWriter::new(stream);
            let mut rx = log_fwd_buffer.subscribe();
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            let line = format!("{json}\n");
                            if tokio::io::AsyncWriteExt::write_all(&mut writer, line.as_bytes())
                                .await
                                .is_err()
                            {
                                break;
                            }
                            let _ = tokio::io::AsyncWriteExt::flush(&mut writer).await;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
    });

    // Build the proxy service with pre-created metric Arcs
    let mut lorica_proxy = LoricaProxy::new(
        Arc::clone(&proxy_config),
        Arc::clone(&log_buffer),
        Arc::clone(&active_connections),
        Arc::clone(&sla_collector),
    );
    // Replace the default Arcs with our pre-created ones (shared with command thread)
    lorica_proxy.cache_hits = worker_cache_hits;
    lorica_proxy.cache_misses = worker_cache_misses;
    lorica_proxy.ban_list = worker_ban_list;
    lorica_proxy.ewma_tracker = worker_ewma;
    lorica_proxy.backend_connections = worker_backend_conns;
    lorica_proxy.request_counts = worker_request_counts;
    lorica_proxy.waf_counts = worker_waf_counts;
    lorica_proxy.waf_engine = waf_engine;
    // Worker mode needs the SQLite-backed bot-protection stash so
    // a challenge stashed here is visible to the POST handler on
    // a sibling worker. The in-memory default would stash only
    // locally and a worker-B POST would always fail-closed with
    // 403 "challenge expired or unknown".
    lorica_proxy.bot_engine = Arc::new(lorica::bot::BotEngine::with_sqlite(Arc::clone(&store)));
    lorica_proxy.shmem = shmem_region;
    lorica_proxy.rate_limit_bans = rate_limit_bans;
    // Worker mode: rate-limit engine runs as a local cache synced with
    // the supervisor via the pipelined RPC channel every 100 ms. See
    // `spawn_rate_limit_sync` below and design doc § 6.
    lorica_proxy.rate_limit_buckets = lorica::proxy_wiring::RateLimitEngine::local();
    // GeoIP: load the DB from `GlobalSettings.geoip_db_path` so worker
    // lookups can resolve client IPs to country codes. Each worker
    // keeps its own copy (the DB is small - ~3 MiB for DB-IP Lite
    // Country). The resolver handle is stashed in the per-worker
    // `lorica::geoip` static so the config-reload path can hot-swap
    // the DB on setting change, and a periodic 24-hour reload task
    // below picks up updater-written files on disk. Silent no-op
    // when the path is unset.
    // Handle registration + rDNS init are shared across all three
    // modes (audit H-9, see `startup::init_geo_resolver_handles`).
    // The rDNS resolver (v1.4.0 follow-up) must be built inside the
    // worker's tokio runtime because hickory-resolver's
    // TokioAsyncResolver latches onto the current runtime at
    // construction. `rt.enter()` gives us that context.
    {
        let _rt_guard = rt.enter();
        startup::init_geo_resolver_handles(
            &lorica_proxy.geoip_resolver,
            &lorica_proxy.asn_resolver,
            Some("worker: "),
        );
    }
    {
        let s = store.blocking_lock();
        if let Ok(settings) = s.get_global_settings() {
            if let Some(ref path) = settings.geoip_db_path {
                if !path.trim().is_empty() {
                    match lorica_proxy.geoip_resolver.load_from_path(path) {
                        Ok(()) => info!(path = %path, "worker: GeoIP database loaded"),
                        Err(e) => warn!(
                            path = %path,
                            error = %e,
                            "worker: GeoIP database load failed; lookups will return None"
                        ),
                    }
                }
            }
            if let Some(ref path) = settings.asn_db_path {
                if !path.trim().is_empty() {
                    match lorica_proxy.asn_resolver.load_from_path(path) {
                        Ok(()) => info!(path = %path, "worker: ASN database loaded"),
                        Err(e) => warn!(
                            path = %path,
                            error = %e,
                            "worker: ASN database load failed; lookups will return None"
                        ),
                    }
                }
            }
        }
    }
    // Periodic basic-auth cache prune (PERF-8). Worker mode has no
    // supervisor TaskTracker available here; a local tracker is fine
    // because worker shutdown is orchestrated by the supervisor via
    // SIGTERM and the prune task exits with the runtime.
    let worker_auth_prune_tracker = tokio_util::task::TaskTracker::new();
    // The `spawn_*` helpers below call into
    // `tokio::spawn`, which requires a current runtime. We are
    // between two `rt.block_on(...)` blocks here, so use `rt.enter()`
    // to establish a runtime context for the duration of the setup.
    // The spawned tasks outlive the guard (tokio keeps them attached
    // to the runtime itself).
    let _rt_guard = rt.enter();
    let _basic_auth_prune = lorica_proxy
        .spawn_basic_auth_cache_prune(&worker_auth_prune_tracker, Duration::from_secs(30));
    // Per-IP rate-limit buckets need the same lazy-prune treatment:
    // a scan or high-cardinality traffic pattern would otherwise
    // accumulate one bucket per distinct IP forever. The idle TTL
    // matches the shmem WAF eviction cadence and the supervisor's own
    // prune of the authoritative buckets.
    let _rate_limit_prune = lorica_proxy.spawn_rate_limit_prune(
        &worker_auth_prune_tracker,
        lorica::proxy_wiring::rate_limit::BUCKET_PRUNE_INTERVAL,
        lorica::proxy_wiring::rate_limit::BUCKET_IDLE_TTL,
    );
    let _bot_stash_prune = lorica_proxy.spawn_bot_stash_prune(&worker_auth_prune_tracker);
    // Background OCSP-staple refresh (Story 8.5). Each worker owns its
    // own resolver, so each runs its own loop; the fetches are
    // idempotent. Reload swaps cert bodies with no staple; this loop
    // attaches OCSP responses out of band, nudged after each reload.
    crate::startup::spawn_ocsp_refresh_loop(Arc::clone(&cert_resolver), Arc::clone(&store));
    // Spawn the cross-worker sync task when the supervisor provided
    // an RPC socketpair (production worker mode). The task drains
    // `LocalBucket::take_delta` every 100 ms, pushes the batch via
    // `RateLimitDelta`, and refreshes each bucket with the
    // authoritative snapshot from the reply.
    if let Some(fd) = rpc_fd {
        // SAFETY: fd is a valid socketpair end received via SCM_RIGHTS
        // from the supervisor and exclusively owned by this worker.
        match unsafe { lorica_command::RpcEndpoint::from_raw_fd(fd) } {
            Ok((endpoint, incoming)) => {
                // The endpoint is cloned across five use sites:
                // rate-limit sync loop, verdict cache lookup/push,
                // breaker query/report, config-reload prepare/commit
                // listener, and the incoming stream that receives
                // supervisor-initiated commands. `RpcEndpoint` is
                // `Clone` via `Arc<Inner>` so all five share the
                // same underlying stream and pipelined dispatcher.
                // See design § 4.3.
                lorica_proxy.verdict_cache = lorica::proxy_wiring::VerdictCacheEngine::rpc(
                    endpoint.clone(),
                    Duration::from_millis(500),
                );
                lorica_proxy.circuit_breaker_engine = lorica::proxy_wiring::BreakerEngine::rpc(
                    endpoint.clone(),
                    Duration::from_millis(500),
                );
                // The stream engine's breaker is the same registry,
                // keyed `stream:<id>` (Story 12.3 D-g).
                stream_breaker.install(lorica_proxy.circuit_breaker_engine.clone());
                let _rpc_listener = lorica_proxy.spawn_worker_rpc_listener(
                    &worker_auth_prune_tracker,
                    incoming,
                    Arc::clone(&store),
                    // Pass the connection filter so `ConfigReloadCommit`
                    // publishes ProxyConfig AND filter CIDRs atomically
                    // (audit H-3). Previously `None` left the filter
                    // out of the two-phase semantics.
                    Some(Arc::clone(&connection_filter)),
                    // Pass the cert resolver so `ConfigReloadCommit`
                    // propagates uploaded / ACME-issued certificates
                    // to the worker's TLS stack without a restart
                    // (v1.5.2 fix - was previously only reloaded by
                    // single-process `config_reload_rx` or the dead
                    // legacy `CommandType::ConfigReload` path).
                    Arc::clone(&cert_resolver),
                    id,
                );
                let _sync_handle = lorica_proxy.spawn_rate_limit_sync(
                    &worker_auth_prune_tracker,
                    endpoint,
                    Duration::from_millis(100),
                );
                info!(
                    worker_id = id,
                    "rate-limit sync + RPC listener spawned; verdict cache + breaker engines bound to RPC"
                );
            }
            Err(e) => {
                error!(
                    worker_id = id,
                    error = %e,
                    "failed to create worker RpcEndpoint; rate-limit sync disabled"
                );
                // Streams fall back with HTTP to this process's local
                // breaker rather than to none.
                stream_breaker.install(lorica_proxy.circuit_breaker_engine.clone());
            }
        }
    } else if shmem_region.is_some() {
        // Worker mode without RPC FD: should not happen in current
        // `WorkerManager::spawn_worker` which always sends one. Log
        // loudly so the misconfiguration surfaces.
        warn!(
            worker_id = id,
            "worker started with shmem but no RPC FD; rate-limit sync disabled"
        );
    }
    if rpc_fd.is_none() {
        stream_breaker.install(lorica_proxy.circuit_breaker_engine.clone());
    }
    drop(_rt_guard);
    // Open a LogStore so the worker can persist access logs and WAF
    // events directly (with route_hostname and action stamped). SQLite
    // WAL mode allows concurrent writes from multiple worker processes.
    // Writes go through the per-worker background log writer (backlog
    // #24). A store that will not open is retried here and reported to
    // the supervisor, which alerts: see `startup::log_store_health`.
    let worker_log_store = crate::startup::log_store_health::open_log_store(
        &data_dir,
        crate::startup::log_store_health::LogStoreRole::Worker,
    );
    lorica_proxy.log_store = worker_log_store.clone();
    // The capture self-disable writer. Capture admission happens in
    // this process, so the queue it drains is this process's; without
    // the task a rule that spent its total keeps its stored `enabled`
    // flag and never produces the audit row that says why it stopped.
    // Registered here rather than beside the prunes above because it
    // needs the log store opened just now, and `_rt_guard` is already
    // gone by this point.
    let (_capture_disable, _log_store_retry) = {
        let _rt_guard = rt.enter();
        (
            lorica::capture::spawn_capture_disable_task(
                Arc::clone(lorica::capture::node_budgets()),
                Arc::clone(&store),
                worker_log_store.clone(),
                &worker_auth_prune_tracker,
                lorica::capture::CAPTURE_DISABLE_INTERVAL,
            ),
            crate::startup::log_store_health::spawn_log_store_retry(
                worker_log_store,
                data_dir.clone(),
                crate::startup::log_store_health::LogStoreRole::Worker,
                crate::startup::log_store_health::LOG_STORE_RETRY_INTERVAL,
            ),
        )
    };
    // ACME challenge store backed by SQLite - workers can read challenges set by supervisor
    lorica_proxy.acme_challenge_store = Some(lorica_api::acme::AcmeChallengeStore::with_db_path(
        db_path.clone(),
    ));

    let pool_size = {
        let backend_count = store
            .blocking_lock()
            .list_backends()
            .map(|b| b.len())
            .unwrap_or(0);
        lorica::proxy_wiring::compute_pool_size(backend_count)
    };
    info!(pool_size, "upstream keepalive pool size");
    // One configuration for the proxy service and the `Server` that runs
    // it, so Pingora's shutdown waits are Lorica's (Story 12.2 D-f).
    let lorica_server_conf = || {
        startup::drain::pingora_server_conf(lorica_core::server::configuration::ServerConf {
            upstream_crl_file: upstream_crl_file.map(|s| s.to_string()),
            upstream_keepalive_pool_size: pool_size,
            ..lorica_core::server::configuration::ServerConf::new()
        })
    };
    let server_conf = Arc::new(lorica_server_conf());
    let mut proxy_service = lorica_proxy::http_proxy_service(&server_conf, lorica_proxy);
    // Install the TCP-level pre-filter. Held by Arc inside the listener, so
    // subsequent reloads take effect without rebuilding endpoints.
    proxy_service.set_connection_filter(
        connection_filter.clone() as Arc<dyn lorica_core::listeners::ConnectionFilter>
    );

    // Build the optional mTLS client-cert verifier from the union of
    // per-route CA bundles. This is done once here; rustls
    // ServerConfig is immutable so the union only changes on restart
    // (each route's own bundle is rebuilt with every snapshot).
    // We also snapshot the CA fingerprint so `reload_proxy_config`
    // can warn if an operator edits `mtls.ca_cert_pem` at runtime.
    let (mtls_verifier, mtls_installed_fingerprint) = {
        let routes = store.blocking_lock().list_routes().unwrap_or_default();
        let fp = lorica::mtls::compute_ca_fingerprint(&routes);
        (lorica::mtls::build_from_routes(&routes), fp)
    };
    if let Some(ref fp) = mtls_installed_fingerprint {
        info!(worker_id = id, fingerprint = %fp, "mTLS enabled at listener: per-route enforcement applies");
    }
    // Note: the worker process doesn't drive reload_proxy_config
    // directly (supervisor does via command channel), so no
    // fingerprint slot is wired here - the supervisor side carries
    // the drift-detection responsibility for the entire worker pool.

    // Register listeners - TCP for HTTP, TLS for HTTPS. Both carry their
    // PROXY protocol policy (Story 12.8) whatever the stored mode: the
    // mode is read on every accept, so a settings change applies without
    // re-registering, and with the mode off the endpoint behaves as one
    // registered without a policy.
    let https_suffix = format!(":{https_port}");
    let proxy_protocol = connection_filter.proxy_protocol();
    for addr in &listener_addrs {
        let l4 = lorica_core::listeners::ServerAddress::Tcp(addr.clone(), None);
        if https_port > 0 && addr.ends_with(&https_suffix) {
            let mut tls_settings =
                lorica_core::listeners::tls::TlsSettings::with_resolver(cert_resolver.clone());
            tls_settings.enable_h2();
            if let Some(ref v) = mtls_verifier {
                tls_settings.set_client_cert_verifier(v.clone());
            }
            proxy_service.endpoints().add_endpoint_with_proxy_protocol(
                l4,
                Some(tls_settings),
                proxy_protocol.policy(lorica::connection_filter::HttpListener::Https),
            );
            info!(worker_id = id, addr = %addr, "registered TLS listener");
        } else {
            proxy_service.endpoints().add_endpoint_with_proxy_protocol(
                l4,
                None,
                proxy_protocol.policy(lorica::connection_filter::HttpListener::Http),
            );
            info!(worker_id = id, addr = %addr, "registered TCP listener");
        }
    }

    info!(worker_id = id, "starting proxy engine");

    // OTel graceful shutdown in workers (v1.4.0 story 1.6
    // completion): `Server::run_forever()` is `run() + exit(0)`
    // which drops the post-serve flush entirely. We inline the
    // equivalent - `server.run(RunArgs::default())` drives the
    // graceful-drain loop exactly like `run_forever` would, then
    // we call `otel::shutdown()` before `std::process::exit(0)`.
    // Result: the BatchSpanProcessor drains any in-flight spans
    // AFTER the worker finishes serving and BEFORE the process
    // exits, so a SIGTERM mid-export does not lose the last N
    // seconds of spans.
    let mut server = lorica_core::server::Server::new_with_opt_and_conf(None, lorica_server_conf());
    server.set_listen_fds(fds);
    server.add_service(proxy_service);
    // The drain watcher ends this worker as soon as a stop has no
    // traffic left, long before Pingora's grace (the setting's hard
    // maximum) would: armed by the supervisor's `quiesce`, or by
    // Pingora's graceful-terminate phase with the stored setting when a
    // SIGTERM arrives without one.
    let drain_source = Arc::clone(&stream_source);
    if let Err(e) = startup::drain::arm_worker_drain(
        Arc::clone(&stream_runtime),
        server.watch_execution_phase(),
        Arc::clone(&active_connections),
        move || drain_source.drain_timeout(),
        move |end| {
            info!(
                worker_id = id,
                ?end,
                "drain finished; flushing OTel spans and exiting"
            );
            lorica::otel::shutdown();
            std::process::exit(0);
        },
    ) {
        warn!(worker_id = id, error = %e, "drain watcher not started; Pingora's grace bounds the stop");
    }
    server.run(lorica_core::server::RunArgs::default());
    info!(worker_id = id, "proxy engine drained; flushing OTel spans");
    lorica::otel::shutdown();
    std::process::exit(0);
}

/// Load persisted certificates into the worker's SNI resolver at boot.
/// Mirrors single-process cert loading; OCSP staples are attached later
/// by the reload path, so each `CertData` starts with `ocsp_response: None`.
async fn worker_load_certs_into_resolver(
    store: &Arc<Mutex<ConfigStore>>,
    cert_resolver: &Arc<lorica_tls::cert_resolver::CertResolver>,
    id: u32,
) {
    let db_certs = store.lock().await;
    let certs = db_certs.list_certificates().unwrap_or_default();
    if certs.is_empty() {
        return;
    }
    let cert_data = lorica::reload::cert_data_for_resolver(&certs);
    match cert_resolver.reload(cert_data) {
        Ok(stats) => {
            if stats.skipped > 0 {
                lorica_api::metrics::inc_certificates_invalid_bundle_by(
                    "reload",
                    stats.skipped as u64,
                );
            }
            info!(
                worker_id = id,
                domains = cert_resolver.domain_count(),
                skipped = stats.skipped,
                total = stats.total,
                "worker loaded TLS certificates"
            );
        }
        Err(e) => warn!(error = %e, "worker failed to load certificates into resolver"),
    }
}

/// Apply a `BanIp` the supervisor broadcast to this worker's ban list.
/// Returns `false` for an empty address, which bans nothing.
///
/// The supervisor broadcasts WAF and rate-limit auto-bans and operator
/// bans, each with its reason. A reason this binary does not know (from
/// a newer supervisor) is read as a WAF critical-rule ban rather than
/// mislabelled as something it is not.
pub(crate) fn apply_ban_ip(
    ban_list: &lorica_api::ban::BanMap,
    ip: &str,
    duration_s: u64,
    reason: i32,
) -> bool {
    if ip.is_empty() {
        return false;
    }
    let reason = lorica_api::ban::BanReason::from_i32(reason)
        .unwrap_or(lorica_api::ban::BanReason::WafCriticalRule);
    ban_list.insert(
        ip.to_string(),
        lorica_api::ban::BanRecord {
            banned_at: Instant::now(),
            duration_s,
            reason,
        },
    );
    true
}

/// Restore WAF runtime state for a worker from persisted settings: the IP
/// blocklist enable flag (workers inherit the flag only; single-process /
/// supervisor owns the Data-Shield fetch), the disabled-rule set, and any
/// custom rules. Synchronous - called outside a runtime, so it takes the
/// store's blocking lock.
fn worker_restore_waf_state(
    store: &Arc<Mutex<ConfigStore>>,
    waf_engine: &Arc<lorica_waf::WafEngine>,
) {
    let s = store.blocking_lock();
    if let Ok(settings) = s.get_global_settings() {
        if settings.ip_blocklist_enabled {
            waf_engine.ip_blocklist().set_enabled(true);
            info!("worker: IP blocklist restored as enabled");
        }
    }
    if let Ok(disabled_ids) = s.load_waf_disabled_rules() {
        if !disabled_ids.is_empty() {
            waf_engine.set_disabled_rules(&disabled_ids);
            info!(
                count = disabled_ids.len(),
                "worker: WAF disabled rules restored"
            );
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
            info!(
                count = custom_rules.len(),
                "worker: WAF custom rules restored"
            );
        }
    }
}
