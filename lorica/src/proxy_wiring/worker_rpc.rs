// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Worker-side RPC machinery (backlog #7 step 3).
//!
//! The pipelined RPC listener spawned on each worker and its
//! handlers: two-phase config reload (Prepare / Commit / Abort,
//! WPAR-8) and the metrics snapshot reply (WPAR-7).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::{BackendConnections, LoricaProxy, ProxyConfig};

/// Prepared-but-not-yet-committed proxy config. Held by workers
/// between `ConfigReloadPrepare` and `ConfigReloadCommit`. Carries the
/// full [`crate::reload::PreparedReload`] rather than only the
/// `ProxyConfig` so the Commit side can publish both the ArcSwap and
/// the connection-filter update atomically (audit H-3). See § 7
/// WPAR-8.
pub struct PendingProxyConfig {
    pub generation: u64,
    pub prepared: crate::reload::PreparedReload,
}

impl LoricaProxy {
    /// Spawn the worker-side pipelined RPC listener that handles
    /// supervisor-initiated commands on the shared RPC channel
    /// (`ConfigReloadPrepare`, `ConfigReloadCommit`, `MetricsRequest`).
    ///
    /// Drops silently on supervisor EOF; dies with the runtime when
    /// the worker shuts down.
    ///
    /// The Prepare half reads the DB, rebuilds a fresh `ProxyConfig`,
    /// and stashes it in `self.pending_proxy_config` keyed by the
    /// generation number. The Commit half pops the stash and does
    /// the single-instruction `ArcSwap`, collapsing the divergence
    /// window across workers to the UDS RTT (microseconds). See
    /// design § 7 WPAR-8.
    ///
    /// Generation monotonicity is enforced by
    /// [`lorica_command::GenerationGate`] so a reordered Prepare is
    /// rejected rather than silently overwriting a fresher pending
    /// config.
    ///
    /// `MetricsRequest` (WPAR-7) builds an instant snapshot of the
    /// worker's per-request counters, ban list, EWMA scores, backend
    /// connections, request counts, and WAF counts and replies with
    /// a `Response` carrying a `MetricsReport` payload so /metrics
    /// pull-on-scrape can aggregate concurrently across workers.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_worker_rpc_listener(
        &self,
        tracker: &tokio_util::task::TaskTracker,
        mut incoming: lorica_command::IncomingCommands,
        store: Arc<tokio::sync::Mutex<lorica_config::ConfigStore>>,
        connection_filter: Option<Arc<crate::connection_filter::GlobalConnectionFilter>>,
        cert_resolver: Arc<lorica_tls::cert_resolver::CertResolver>,
        worker_id: u32,
    ) -> tokio::task::JoinHandle<()> {
        let proxy_config = Arc::clone(&self.config);
        let pending = Arc::clone(&self.pending_proxy_config);
        let gate = Arc::new(lorica_command::GenerationGate::new());
        let metrics_ctx = WorkerMetricsCtx {
            ban_list: Arc::clone(&self.ban_list),
            ewma_scores: self.ewma_tracker.scores_ref(),
            backend_connections: Arc::clone(&self.backend_connections),
            request_counts: Arc::clone(&self.request_counts),
            waf_counts: Arc::clone(&self.waf_counts),
            cache_hits: Arc::clone(&self.cache_hits),
            cache_misses: Arc::clone(&self.cache_misses),
            active_connections: Arc::clone(&self.active_connections),
        };
        tracker.spawn(async move {
            tracing::info!(worker_id, "worker RPC listener started");
            while let Some(inc) = incoming.recv().await {
                match inc.command_type() {
                    lorica_command::CommandType::ConfigReloadPrepare => {
                        handle_config_reload_prepare(
                            inc,
                            &store,
                            &proxy_config,
                            &pending,
                            &gate,
                            worker_id,
                        )
                        .await;
                    }
                    lorica_command::CommandType::ConfigReloadCommit => {
                        handle_config_reload_commit(
                            inc,
                            &proxy_config,
                            &pending,
                            connection_filter.as_ref(),
                            &gate,
                            worker_id,
                            &store,
                            &cert_resolver,
                        )
                        .await;
                    }
                    lorica_command::CommandType::ConfigReloadAbort => {
                        handle_config_reload_abort(inc, &pending, worker_id).await;
                    }
                    lorica_command::CommandType::MetricsRequest => {
                        handle_metrics_request(inc, &metrics_ctx, worker_id).await;
                    }
                    other => {
                        tracing::debug!(
                            worker_id,
                            command_type = ?other,
                            "worker RPC: supervisor-initiated command has no handler"
                        );
                        let _ = inc
                            .reply_error("no worker-side handler for this command")
                            .await;
                    }
                }
            }
            tracing::info!(worker_id, "worker RPC listener exiting (supervisor EOF)");
        })
    }
}

/// Handles needed to build a worker-side `MetricsReport` snapshot.
/// Mirrors the per-worker counter Arcs the proxy hot path writes to,
/// clonable via `Arc` so the pipelined-RPC listener task can own its
/// own handle without holding the whole `LoricaProxy`.
///
/// The single [`build_report`](Self::build_report) builder is shared
/// by BOTH `MetricsRequest` responders - the pipelined-RPC handler
/// here and the legacy `CommandChannel` handler in
/// `startup::worker` - so the two snapshots can never diverge. The
/// legacy path previously built its own report and silently omitted
/// `generic_counters`, dropping every per-worker generic counter
/// (bot_challenge, geoip_block, ai_bot, cert_resolver_reload, ...)
/// whenever metrics were pulled over the legacy channel.
#[derive(Clone)]
pub struct WorkerMetricsCtx {
    ban_list: Arc<lorica_api::ban::BanMap>,
    ewma_scores: Arc<dashmap::DashMap<String, f64>>,
    backend_connections: Arc<BackendConnections>,
    request_counts: Arc<DashMap<(String, u16), AtomicU64>>,
    waf_counts: Arc<DashMap<(String, String), AtomicU64>>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    active_connections: Arc<AtomicU64>,
}

impl WorkerMetricsCtx {
    /// Assemble the context from the proxy's per-worker counter Arcs.
    /// Every argument is an `Arc` clone of a slot the proxy hot path
    /// writes to, so [`build_report`](Self::build_report) reads an
    /// instant snapshot.
    // Eight per-worker counter Arcs; grouping them into a sub-struct
    // would only move the same argument list one level down.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ban_list: Arc<lorica_api::ban::BanMap>,
        ewma_scores: Arc<dashmap::DashMap<String, f64>>,
        backend_connections: Arc<BackendConnections>,
        request_counts: Arc<DashMap<(String, u16), AtomicU64>>,
        waf_counts: Arc<DashMap<(String, String), AtomicU64>>,
        cache_hits: Arc<AtomicU64>,
        cache_misses: Arc<AtomicU64>,
        active_connections: Arc<AtomicU64>,
    ) -> Self {
        Self {
            ban_list,
            ewma_scores,
            backend_connections,
            request_counts,
            waf_counts,
            cache_hits,
            cache_misses,
            active_connections,
        }
    }

    /// Build an instant `MetricsReport` snapshot for `worker_id`:
    /// cache hits/misses, active connections, bans, EWMA scores,
    /// backend connections, request counts, WAF counts, AND the
    /// per-worker `generic_counters` (bot_challenge, geoip_block,
    /// ai_bot, cert_resolver_reload, ocsp_refresh, ...). Shared by
    /// both `MetricsRequest` responders so neither can drop a field.
    pub fn build_report(&self, worker_id: u32) -> lorica_command::MetricsReport {
        use lorica_command::{
            BackendConnEntry, BanReportEntry, EwmaReportEntry, MetricsReport, RequestCountEntry,
            WafCountEntry,
        };

        let ban_entries: Vec<BanReportEntry> = self
            .ban_list
            .iter()
            .filter_map(|entry| {
                let (ip, rec) = (entry.key(), entry.value());
                let elapsed = rec.banned_at.elapsed().as_secs();
                if elapsed >= rec.duration_s {
                    return None;
                }
                Some(BanReportEntry {
                    ip: ip.clone(),
                    remaining_seconds: rec.duration_s - elapsed,
                    ban_duration_seconds: rec.duration_s,
                    reason: rec.reason.as_i32(),
                })
            })
            .collect();

        let ewma_entries: Vec<EwmaReportEntry> = self
            .ewma_scores
            .iter()
            .map(|entry| EwmaReportEntry {
                backend_address: entry.key().clone(),
                score_us: *entry.value(),
            })
            .collect();

        let backend_conn_entries: Vec<BackendConnEntry> = self
            .backend_connections
            .snapshot()
            .into_iter()
            .map(|(addr, conns)| BackendConnEntry {
                backend_address: addr,
                connections: conns,
            })
            .collect();

        let request_entries: Vec<RequestCountEntry> = self
            .request_counts
            .iter()
            .map(|entry| {
                let ((route_id, status_code), counter) = (entry.key(), entry.value());
                RequestCountEntry {
                    route_id: route_id.clone(),
                    status_code: *status_code as u32,
                    count: counter.load(Ordering::Relaxed),
                }
            })
            .collect();

        let waf_entries: Vec<WafCountEntry> = self
            .waf_counts
            .iter()
            .map(|entry| {
                let ((category, action), counter) = (entry.key(), entry.value());
                WafCountEntry {
                    category: category.clone(),
                    action: action.clone(),
                    count: counter.load(Ordering::Relaxed),
                }
            })
            .collect();

        let mut report = MetricsReport::new(
            worker_id,
            0, // total_requests not tracked yet
            self.active_connections.load(Ordering::Relaxed),
        );
        report.cache_hits = self.cache_hits.load(Ordering::Relaxed);
        report.cache_misses = self.cache_misses.load(Ordering::Relaxed);
        report.ban_entries = ban_entries;
        report.ewma_entries = ewma_entries;
        report.backend_conn_entries = backend_conn_entries;
        report.request_entries = request_entries;
        report.waf_entries = waf_entries;
        // Cross-worker counter aggregation (v1.4.0 follow-up). Ships
        // every non-typed per-worker counter (bot_challenge,
        // geoip_block, forward_auth_cache, ...) to the supervisor so
        // `/metrics` at the supervisor sees the union across workers.
        // lorica-api exposes the snapshot as `(name, labels, value)`
        // tuples; translate into the lorica-command wire shape here -
        // keeps lorica-api free of the lorica-command dep.
        report.generic_counters = lorica_api::metrics::snapshot_per_worker_counters()
            .into_iter()
            .map(|(name, label_pairs, value)| {
                // Flatten name=value pairs into alternating strings on
                // the wire (`["route_id", "uuid", "mode", "cookie", ...]`).
                // The supervisor re-pairs them at apply time. This keeps
                // the wire format flat while preserving the label-name
                // metadata needed for positional reorder.
                let mut labels: Vec<String> = Vec::with_capacity(label_pairs.len() * 2);
                for (k, v) in label_pairs {
                    labels.push(k);
                    labels.push(v);
                }
                lorica_command::GenericCounterEntry {
                    name,
                    labels,
                    value,
                }
            })
            .collect();

        report
    }
}

/// Worker-side handler for `CommandType::MetricsRequest` on the
/// pipelined RPC channel (WPAR-7). Builds an instant snapshot via the
/// shared [`WorkerMetricsCtx::build_report`] and replies with it as a
/// `Response::MetricsReport` payload so the supervisor's pull-on-
/// scrape coordinator can aggregate across workers within a single
/// 500 ms budget.
async fn handle_metrics_request(
    inc: lorica_command::IncomingCommand,
    ctx: &WorkerMetricsCtx,
    worker_id: u32,
) {
    let report = ctx.build_report(worker_id);
    let _ = inc
        .reply(lorica_command::Response::ok_with(
            0,
            lorica_command::response::Payload::MetricsReport(report),
        ))
        .await;
}

/// Worker-side handler for `ConfigReloadPrepare`. Reads the DB and
/// builds a fresh `ProxyConfig`, then stashes it in the pending slot.
/// Generation must strictly exceed the gate watermark; replies Ok on
/// success, Error on build failure or generation regression.
async fn handle_config_reload_prepare(
    inc: lorica_command::IncomingCommand,
    store: &Arc<tokio::sync::Mutex<lorica_config::ConfigStore>>,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    gate: &Arc<lorica_command::GenerationGate>,
    worker_id: u32,
) {
    let prepare = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadPrepare(p)) => p,
        _ => {
            let _ = inc
                .reply_error("malformed ConfigReloadPrepare payload")
                .await;
            return;
        }
    };
    if let Err(e) = gate.observe(prepare.generation) {
        tracing::warn!(
            worker_id,
            generation = prepare.generation,
            error = %e,
            "ConfigReloadPrepare rejected: stale generation"
        );
        let _ = inc.reply_error(format!("stale generation: {e}")).await;
        return;
    }
    match crate::reload::build_proxy_config(store, proxy_config, None).await {
        Ok(prepared) => {
            *pending.lock() = Some(PendingProxyConfig {
                generation: prepare.generation,
                prepared,
            });
            tracing::info!(
                worker_id,
                generation = prepare.generation,
                "ConfigReloadPrepare: pending config built and stashed (with connection-filter CIDRs)"
            );
            let _ = inc.reply(lorica_command::Response::ok(0)).await;
        }
        Err(e) => {
            tracing::error!(
                worker_id,
                generation = prepare.generation,
                error = %e,
                "ConfigReloadPrepare failed to build new ProxyConfig"
            );
            let _ = inc
                .reply_error(format!("Prepare failed to build config: {e}"))
                .await;
        }
    }
}

/// Worker-side handler for `ConfigReloadAbort`. Drops the pending
/// slot if its generation matches. A mismatch or an empty slot is a
/// silent no-op (Ok reply) - Abort is advisory; the worker is free
/// to already have moved on. Closes audit M-7 orphan.
async fn handle_config_reload_abort(
    inc: lorica_command::IncomingCommand,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    worker_id: u32,
) {
    let abort = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadAbort(a)) => a,
        _ => {
            let _ = inc.reply_error("malformed ConfigReloadAbort payload").await;
            return;
        }
    };
    let dropped = {
        let mut slot = pending.lock();
        match *slot {
            Some(ref p) if p.generation == abort.generation => {
                *slot = None;
                true
            }
            _ => false,
        }
    };
    if dropped {
        tracing::info!(
            worker_id,
            generation = abort.generation,
            "ConfigReloadAbort: pending config dropped"
        );
    } else {
        tracing::debug!(
            worker_id,
            generation = abort.generation,
            "ConfigReloadAbort: no matching pending (already committed or already dropped)"
        );
    }
    let _ = inc.reply(lorica_command::Response::ok(0)).await;
}

/// Worker-side handler for `ConfigReloadCommit`. Pops the pending
/// slot, verifies the generation, and atomically ArcSwaps. A commit
/// with no pending entry or a mismatched generation replies Error so
/// the supervisor's coordinator can decide whether to retry.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_config_reload_commit(
    inc: lorica_command::IncomingCommand,
    proxy_config: &Arc<ArcSwap<ProxyConfig>>,
    pending: &Arc<parking_lot::Mutex<Option<PendingProxyConfig>>>,
    connection_filter: Option<&Arc<crate::connection_filter::GlobalConnectionFilter>>,
    gate: &Arc<lorica_command::GenerationGate>,
    worker_id: u32,
    store: &Arc<tokio::sync::Mutex<lorica_config::ConfigStore>>,
    cert_resolver: &Arc<lorica_tls::cert_resolver::CertResolver>,
) {
    let commit = match inc.command().payload.clone() {
        Some(lorica_command::command::Payload::ConfigReloadCommit(c)) => c,
        _ => {
            let _ = inc
                .reply_error("malformed ConfigReloadCommit payload")
                .await;
            return;
        }
    };
    if let Err(e) = gate.observe_commit(commit.generation) {
        tracing::warn!(
            worker_id,
            generation = commit.generation,
            error = %e,
            "ConfigReloadCommit rejected: stale generation"
        );
        let _ = inc.reply_error(format!("stale commit: {e}")).await;
        return;
    }
    // Pop the prepared snapshot atomically. It carries the ProxyConfig
    // AND the connection-filter CIDRs AND any mTLS fingerprint drift,
    // so the single `commit_prepared_reload` call below publishes them
    // together - no partial-state window between ArcSwap and filter
    // reload (audit H-3).
    let prepared = {
        let mut slot = pending.lock();
        match slot.take() {
            Some(p) if p.generation == commit.generation => Some(p.prepared),
            Some(p) => {
                let pending_gen = p.generation;
                // Put it back: a late commit for an older generation
                // should not clobber a fresher pending.
                *slot = Some(p);
                tracing::warn!(
                    worker_id,
                    pending_generation = pending_gen,
                    commit_generation = commit.generation,
                    "ConfigReloadCommit generation mismatch"
                );
                None
            }
            None => None,
        }
    };
    match prepared {
        Some(prepared) => {
            crate::reload::commit_prepared_reload(proxy_config, connection_filter, prepared);
            tracing::info!(
                worker_id,
                generation = commit.generation,
                "ConfigReloadCommit: pending config swapped in"
            );
            // Apply the per-process resolver hooks so the worker's
            // GeoIP / ASN / OTel / bot-HMAC state stays in sync with
            // the supervisor on every commit. Without these calls,
            // the pipelined RPC reload would only swap the proxy
            // config, leaving stale resolver state until a process
            // restart - which is the issue that caused
            // freshly-downloaded `.mmdb` files to never become
            // visible to worker lookups.
            // The single per-process reload bundle: OTel / GeoIP / ASN
            // / bot-HMAC resolver hooks AND the merged AI-crawler
            // registry rebuild (Story 8.2 AC #8). Calling the one
            // bundle means the registry rebuild can never be forgotten
            // on a reload path the way it was when it was wired
            // separately.
            crate::reload::apply_per_process_reload_state(store).await;
            // Reply BEFORE the cert resolver reload. The supervisor
            // coordinator's `CONFIG_RELOAD_COMMIT_TIMEOUT` is 500 ms,
            // and `reload_cert_resolver` does OCSP fetches with a
            // 10 s per-responder timeout (see `try_fetch_ocsp`). A
            // slow OCSP responder would otherwise blow the deadline,
            // trigger the legacy-broadcast fallback, and duplicate
            // the reload work on a second command channel. Replying
            // first keeps the two-phase semantics atomic at the
            // ProxyConfig + connection-filter level (what the 500 ms
            // deadline actually protects) while letting the TLS
            // resolver update best-effort in the background of the
            // same handler. Single-process mode already has this
            // exact window (see `main.rs:3868-3878` : sequential
            // `reload_proxy_config_with_mtls` then
            // `reload_cert_resolver`) - worker mode now matches.
            let _ = inc.reply(lorica_command::Response::ok(0)).await;
            // Reload the TLS cert resolver so uploaded / ACME-issued
            // certificates become visible on the worker without a
            // restart. Previously only the supervisor's single-process
            // reload path called `reload_cert_resolver`, so in worker
            // mode the cert set was frozen at worker boot (v1.5.2 fix).
            // Kept last because of the OCSP latency risk documented
            // above.
            crate::reload::reload_cert_resolver(store, cert_resolver).await;
        }
        None => {
            let _ = inc
                .reply_error(format!(
                    "no matching pending for generation {}",
                    commit.generation
                ))
                .await;
        }
    }
}
