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

//! The follower's telemetry drain (Story 9.6 AC #5, #6, #7).
//!
//! # There is no queue in front of the request path
//!
//! Decision D5. AC #7 requires the follower SUPERVISOR to read the
//! shared log store rather than add a worker-to-supervisor RPC per
//! request. Take that seriously and AC #5's ring buffer becomes
//! redundant on the two high-volume paths: `access-log.db` already IS
//! a bounded, drop-on-overflow buffer written off the hot path by
//! `log_writer`'s OS thread, shared across every worker process under
//! WAL, with its own drop counter
//! (`lorica_log_write_dropped_total{kind}`).
//!
//! So this task walks that store by rowid cursor. The request path is
//! not touched at all, which satisfies the epic's one hard invariant
//! by construction rather than by a bound someone has to reason
//! about. A second in-process buffer would have duplicated an
//! existing bound, added a second drop counter for the same event,
//! and still not solved worker mode.
//!
//! # Execution model (AC #6)
//!
//! A tokio task, not `log_writer`'s OS thread. That thread is
//! deliberately runtime-free so it behaves identically in all three
//! process modes; sending on `RpcEndpoint` needs tokio, and the
//! supervisor's cluster connection is a tokio construct. Under D5 the
//! question mostly dissolves anyway: the drain's input is a SQLite
//! cursor, so nothing crosses the runtime boundary.
//!
//! # Never queue against a missing control plane
//!
//! `ClusterConnection`'s own contract says consumers must treat "no
//! session" as unreachable and NOT queue. This task holds a cursor,
//! not a backlog: with the control plane down it simply stops
//! advancing, and the rows wait in the store where local retention
//! bounds them. That is also why the outbound RPC queue is never
//! reached from a request task, which matters because that queue
//! awaits rather than drops.

use std::sync::Arc;
use std::time::Duration;

use lorica_api::cluster::runtime::FollowerRuntime;
use lorica_api::log_store::LogStore;
use lorica_cluster::{
    ClusterRequest, TelemetryAccessRow, TelemetryAuditRow, TelemetryPush, TelemetryWafRow,
    MAX_TELEMETRY_AUDIT, MAX_TELEMETRY_ROWS,
};
use lorica_config::{ConfigStore, TelemetryCursor};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::startup::cluster_follower::BanApplier;

/// How often the drain looks for new rows when it is caught up.
///
/// Fan-in is for correlating an incident minutes later, not for live
/// tailing, so a short interval buys nothing and costs a wakeup per
/// node per interval on the control plane. When there IS a backlog
/// the tick is not the limit: see [`MAX_BATCHES_PER_TICK`].
const DRAIN_INTERVAL: Duration = Duration::from_secs(10);

/// Batches one tick may ship before yielding until the next one.
///
/// Without this the drain shipped at most one batch per tick, so its
/// ceiling was `MAX_TELEMETRY_ROWS / DRAIN_INTERVAL` = about 51 rows
/// a second, far below the traffic the fan-in envelope claims to
/// support. A node above that never caught up: the backlog grew
/// until local retention evicted rows the cursor had not reached,
/// which is silent, permanent loss rather than lag.
///
/// So a tick keeps shipping while batches come back full, and stops
/// at this many. The bound is what keeps a huge backlog from
/// monopolising the control plane's ingest for one node: 20 batches
/// is about 1 000 rows a second sustained, an order of magnitude
/// above the documented envelope, and the loop also stops early on
/// any partial acceptance so a quota shedding this node ends the
/// burst immediately.
const MAX_BATCHES_PER_TICK: usize = 20;

/// Bound on one push exchange.
const PUSH_DEADLINE: Duration = Duration::from_secs(15);

/// Spawn the follower's telemetry drain.
///
/// Does nothing useful until the dialer has a session; every tick
/// with no session is a cheap no-op that leaves the cursor where it
/// is.
pub(crate) fn spawn_telemetry_drain(
    runtime: Arc<FollowerRuntime>,
    log_store: Option<Arc<LogStore>>,
    config_store: Arc<Mutex<ConfigStore>>,
    bans: BanApplier,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // A node that has never drained starts at the PRESENT rather
        // than replaying everything local retention holds. Up to
        // 100 000 rows per kind arriving in one burst is not a useful
        // first impression of a node, and the history it would carry
        // predates the fleet knowing about this node at all.
        if let Some(logs) = &log_store {
            if let Err(reason) = seed_cursors(&config_store, Arc::clone(logs)).await {
                warn!(%reason, "could not seed the telemetry cursors; the drain starts from zero");
            }
        }
        let mut interval = tokio::time::interval(DRAIN_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            for _ in 0..MAX_BATCHES_PER_TICK {
                match drain_once(&runtime, log_store.as_ref(), &config_store, &bans).await {
                    // A short batch means the backlog is gone; wait
                    // for the next tick rather than spinning.
                    Ok(DrainOutcome::CaughtUp) => break,
                    Ok(DrainOutcome::MoreWaiting) => continue,
                    Err(reason) => {
                        // Never fatal: a drain that cannot run is a
                        // visibility loss, and the session it rides
                        // carries configuration that matters more.
                        debug!(%reason, "telemetry drain tick did not complete");
                        break;
                    }
                }
            }
        }
    })
}

/// Point both cursors at the newest local row, once, when this node
/// has never pushed.
async fn seed_cursors(
    config_store: &Arc<Mutex<ConfigStore>>,
    logs: Arc<LogStore>,
) -> Result<(), String> {
    let (newest_access, newest_waf, newest_audit) = tokio::task::spawn_blocking(move || {
        Ok::<_, String>((
            logs.newest_access_id()?,
            logs.newest_waf_id()?,
            logs.newest_local_audit_id()?,
        ))
    })
    .await
    .map_err(|e| format!("the cursor seed task failed: {e}"))??;
    cursor_write(config_store, move |store| {
        for (kind, newest) in [
            (TelemetryCursor::Access, newest_access),
            (TelemetryCursor::Waf, newest_waf),
            // Audit seeds the same way: a node joining an existing
            // fleet ships what it records from now on, not its whole
            // pre-cluster history. Those rows are still on the node and
            // still verifiable there; chaining them into the aggregate
            // would say they were fanned in when they were not.
            (TelemetryCursor::Audit, newest_audit),
        ] {
            let current = store
                .telemetry_cursor(kind)
                .map_err(|e| format!("could not read a telemetry cursor: {e}"))?;
            if current == 0 && newest > 0 {
                store
                    .advance_telemetry_cursor(kind, newest)
                    .map_err(|e| format!("could not seed a telemetry cursor: {e}"))?;
            }
        }
        Ok(())
    })
    .await
}

/// Run a synchronous closure against the configuration store off the
/// executor, holding the async lock only across the handoff.
///
/// The store is `rusqlite`, so every call into it is blocking; doing
/// it inline while holding the `tokio::sync::Mutex` guard would park
/// a worker thread for as long as SQLite takes, up to its five-second
/// busy timeout.
async fn cursor_write<F>(config_store: &Arc<Mutex<ConfigStore>>, f: F) -> Result<(), String>
where
    F: FnOnce(&ConfigStore) -> Result<(), String> + Send + 'static,
{
    let guard = Arc::clone(config_store).lock_owned().await;
    tokio::task::spawn_blocking(move || f(&guard))
        .await
        .map_err(|e| format!("the cursor task failed: {e}"))?
}

/// Whether a drain pass left anything behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainOutcome {
    /// The batch was short, or the control plane asked this node to
    /// back off: stop until the next tick.
    CaughtUp,
    /// The batch was full and fully accepted, so there is very likely
    /// more waiting: go again inside this tick.
    MoreWaiting,
}

/// One drain pass: read, push, advance.
async fn drain_once(
    runtime: &FollowerRuntime,
    logs: Option<&Arc<LogStore>>,
    config_store: &Arc<Mutex<ConfigStore>>,
    bans: &BanApplier,
) -> Result<DrainOutcome, String> {
    // No session: the control plane is unreachable right now, so
    // nothing is queued and the cursor stays put.
    let Some(session) = runtime.connection.current() else {
        return Ok(DrainOutcome::CaughtUp);
    };

    let (access_cursor, waf_cursor, audit_cursor) = {
        let guard = Arc::clone(config_store).lock_owned().await;
        tokio::task::spawn_blocking(move || {
            Ok::<_, String>((
                guard
                    .telemetry_cursor(TelemetryCursor::Access)
                    .map_err(|e| e.to_string())?,
                guard
                    .telemetry_cursor(TelemetryCursor::Waf)
                    .map_err(|e| e.to_string())?,
                guard
                    .telemetry_cursor(TelemetryCursor::Audit)
                    .map_err(|e| e.to_string())?,
            ))
        })
        .await
        .map_err(|e| format!("the cursor read task failed: {e}"))??
    };

    // Off the executor. Both stores open with `busy_timeout=5000`,
    // so a contended read can park a worker thread for five seconds,
    // and this task shares its runtime with the liveness publisher,
    // the drift watch and the replication watch. Every other caller
    // of these stores in this codebase offloads the same way; the one
    // module written to honour that discipline should not be the one
    // that breaks it.
    let (access, waf, audit) = match logs {
        Some(logs) => {
            let logs = Arc::clone(logs);
            tokio::task::spawn_blocking(move || {
                Ok::<_, String>((
                    logs.access_rows_after(access_cursor, MAX_TELEMETRY_ROWS)?,
                    logs.waf_rows_after(waf_cursor, MAX_TELEMETRY_ROWS)?,
                    logs.audit_rows_after(audit_cursor, MAX_TELEMETRY_AUDIT)?,
                ))
            })
            .await
            .map_err(|e| format!("the telemetry read task failed: {e}"))??
        }
        None => (Vec::new(), Vec::new(), Vec::new()),
    };
    let ban_snapshot = bans.snapshot().await;

    // Nothing new and nothing banned: do not spend a round trip.
    if access.is_empty() && waf.is_empty() && audit.is_empty() && ban_snapshot.is_empty() {
        return Ok(DrainOutcome::CaughtUp);
    }
    // A full batch on either kind means there is very likely more
    // behind it, which is what lets one tick ship more than one.
    let batch_was_full = access.len() >= MAX_TELEMETRY_ROWS
        || waf.len() >= MAX_TELEMETRY_ROWS
        || audit.len() >= MAX_TELEMETRY_AUDIT;

    let next_access = access
        .last()
        .map(|(id, _)| *id as u64)
        .unwrap_or(access_cursor);
    let next_waf = waf.last().map(|(id, _)| *id as u64).unwrap_or(waf_cursor);
    let next_audit = audit
        .last()
        .map(|(id, _)| *id as u64)
        .unwrap_or(audit_cursor);

    let batch = TelemetryPush {
        access: access
            .into_iter()
            .map(|(_, row)| TelemetryAccessRow {
                timestamp: row.timestamp,
                method: row.method,
                path: row.path,
                host: row.host,
                status: row.status,
                latency_ms: row.latency_ms,
                backend: row.backend,
                error: row.error,
                client_ip: row.client_ip,
                is_xff: row.is_xff,
                xff_proxy_ip: row.xff_proxy_ip,
                source: row.source,
                request_id: row.request_id,
            })
            .collect(),
        waf: waf
            .into_iter()
            .map(|(_, row)| TelemetryWafRow {
                rule_id: row.rule_id,
                description: row.description,
                category: row.category,
                severity: row.severity,
                matched_field: row.matched_field,
                matched_value: row.matched_value,
                timestamp: row.timestamp,
                client_ip: row.client_ip,
                route_hostname: row.route_hostname,
                action: row.action,
            })
            .collect(),
        bans: ban_snapshot,
        audit: audit
            .into_iter()
            .map(|(_, row)| TelemetryAuditRow {
                // `0` is the local-row sentinel elsewhere in this
                // feature, so it is the one value this must never
                // silently fall back to. The ids come from a SQLite
                // `AUTOINCREMENT` rowid and are always positive, which
                // is why this saturates rather than erroring: a
                // negative id here would mean the row did not come from
                // that column at all.
                origin_id: u64::try_from(row.origin_id).unwrap_or(u64::MAX),
                timestamp: row.timestamp,
                operator_username: row.operator_username,
                operator_role: row.operator_role,
                action: row.action,
                target_type: row.target_type,
                target_id: row.target_id,
                before_payload_hash: row.before_payload_hash,
                after_payload_hash: row.after_payload_hash,
                ip: row.ip,
                user_agent: row.user_agent,
                // Both hashes ride unchanged. Recomputing either would
                // make the aggregated copy agree with itself and with
                // nothing the node published, which is the one thing
                // that gives it any value.
                prev_chain_hash: row.prev_chain_hash,
                chain_hash: row.chain_hash,
            })
            .collect(),
        audit_cursor: next_audit,
        access_cursor: next_access,
        waf_cursor: next_waf,
        // The local writer already counts what it dropped; this field
        // carries it so the control plane can show the gap beside the
        // rows that did arrive.
        dropped_since_last: 0,
    };
    let sent_access = batch.access.len();
    let sent_waf = batch.waf.len();
    let sent_audit = batch.audit.len();

    let response = tokio::time::timeout(
        PUSH_DEADLINE,
        session
            .endpoint
            .request(ClusterRequest::telemetry_push(batch), PUSH_DEADLINE),
    )
    .await
    .map_err(|_| "the telemetry push timed out".to_string())?
    .map_err(|e| format!("the telemetry push failed: {e}"))?;

    let ack = match response.body {
        Some(lorica_cluster::messages::cluster_response::Body::TelemetryPushAck(ack)) => ack,
        _ => {
            return Err("the control plane refused the telemetry batch".to_string());
        }
    };

    // Advance each cursor only past what was ACCEPTED of ITS class. A
    // quota that shed part of the batch must not silently lose those
    // rows: leaving that cursor behind means the next tick offers them
    // again.
    //
    // The three classes advance independently, not on one conjunction
    // (Epic 9 close, architecture review). Gated together, a class the
    // peer did not acknowledge would freeze the other two as well: a
    // control plane one release behind this node drops a class it
    // does not know at decode, answers zero for it, and access, WAF and
    // audit would all re-send the same batch every tick, forever,
    // while the control plane believed it had accepted everything it
    // understood. A class the peer did not take blocks only itself.
    //
    // Audit rows are exempt from shedding, so a short audit count is
    // never a quota decision: it means the control plane could not
    // store them. That cursor stays put and the rows are offered again,
    // which is what the fan-in insert's idempotency is for.
    let access_ok = ack.accepted_access as usize == sent_access;
    let waf_ok = ack.accepted_waf as usize == sent_waf;
    let audit_ok = ack.accepted_audit as usize == sent_audit;
    let advances: Vec<(TelemetryCursor, u64)> = [
        (TelemetryCursor::Access, access_ok, ack.access_cursor),
        (TelemetryCursor::Waf, waf_ok, ack.waf_cursor),
        (TelemetryCursor::Audit, audit_ok, ack.audit_cursor),
    ]
    .into_iter()
    .filter(|(_, ok, _)| *ok)
    .map(|(cursor, _, to)| (cursor, to))
    .collect();
    if !advances.is_empty() {
        cursor_write(config_store, move |store| {
            for (cursor, to) in advances {
                store
                    .advance_telemetry_cursor(cursor, to)
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        })
        .await?;
    }
    let accepted_all = access_ok && waf_ok && audit_ok;
    if accepted_all {
        debug!(
            access = sent_access,
            waf = sent_waf,
            audit = sent_audit,
            "telemetry delivered to the control plane"
        );
    } else {
        info!(
            sent_access,
            sent_waf,
            sent_audit,
            accepted_access = ack.accepted_access,
            accepted_waf = ack.accepted_waf,
            accepted_audit = ack.accepted_audit,
            retry_after_s = ack.retry_after_s,
            "the control plane accepted part of the telemetry batch; the cursor of each short \
             class stays put so nothing is lost, and the rest is offered again"
        );
    }

    if ack.retry_after_s > 0 {
        // Told to back off: sleep past the window rather than
        // hammering a control plane that is already shedding, and end
        // the burst.
        tokio::time::sleep(Duration::from_secs(u64::from(ack.retry_after_s))).await;
        return Ok(DrainOutcome::CaughtUp);
    }
    Ok(if batch_was_full && accepted_all {
        DrainOutcome::MoreWaiting
    } else {
        DrainOutcome::CaughtUp
    })
}
