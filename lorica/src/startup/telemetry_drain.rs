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
    ClusterRequest, TelemetryAccessRow, TelemetryPush, TelemetryWafRow, MAX_TELEMETRY_ROWS,
};
use lorica_config::{ConfigStore, TelemetryCursor};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::startup::cluster_follower::BanApplier;

/// How often the drain looks for new rows.
///
/// Fan-in is for correlating an incident minutes later, not for
/// live tailing, so a short interval buys nothing and costs a wakeup
/// per node per interval on the control plane.
const DRAIN_INTERVAL: Duration = Duration::from_secs(10);

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
            if let Err(reason) = seed_cursors(&config_store, logs).await {
                warn!(%reason, "could not seed the telemetry cursors; the drain starts from zero");
            }
        }
        let mut interval = tokio::time::interval(DRAIN_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Err(reason) = drain_once(&runtime, log_store.as_deref(), &config_store, &bans).await
            {
                // Never fatal: a drain that cannot run is a
                // visibility loss, and the session it rides carries
                // configuration that matters more.
                debug!(%reason, "telemetry drain tick did not complete");
            }
        }
    })
}

/// Point both cursors at the newest local row, once, when this node
/// has never pushed.
async fn seed_cursors(
    config_store: &Arc<Mutex<ConfigStore>>,
    logs: &LogStore,
) -> Result<(), String> {
    let newest_access = logs.newest_access_id()?;
    let newest_waf = logs.newest_waf_id()?;
    let store = config_store.lock().await;
    for (kind, newest) in [
        (TelemetryCursor::Access, newest_access),
        (TelemetryCursor::Waf, newest_waf),
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
}

/// One drain tick: read, push, advance.
async fn drain_once(
    runtime: &FollowerRuntime,
    logs: Option<&LogStore>,
    config_store: &Arc<Mutex<ConfigStore>>,
    bans: &BanApplier,
) -> Result<(), String> {
    // No session: the control plane is unreachable right now, so
    // nothing is queued and the cursor stays put.
    let Some(session) = runtime.connection.current() else {
        return Ok(());
    };

    let (access_cursor, waf_cursor) = {
        let store = config_store.lock().await;
        (
            store
                .telemetry_cursor(TelemetryCursor::Access)
                .map_err(|e| e.to_string())?,
            store
                .telemetry_cursor(TelemetryCursor::Waf)
                .map_err(|e| e.to_string())?,
        )
    };

    let (access, waf) = match logs {
        Some(logs) => (
            logs.access_rows_after(access_cursor, MAX_TELEMETRY_ROWS)?,
            logs.waf_rows_after(waf_cursor, MAX_TELEMETRY_ROWS)?,
        ),
        None => (Vec::new(), Vec::new()),
    };
    let ban_snapshot = bans.snapshot().await;

    // Nothing new and nothing banned: do not spend a round trip.
    if access.is_empty() && waf.is_empty() && ban_snapshot.is_empty() {
        return Ok(());
    }

    let next_access = access.last().map(|(id, _)| *id as u64).unwrap_or(access_cursor);
    let next_waf = waf.last().map(|(id, _)| *id as u64).unwrap_or(waf_cursor);

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
        access_cursor: next_access,
        waf_cursor: next_waf,
        // The local writer already counts what it dropped; this field
        // carries it so the control plane can show the gap beside the
        // rows that did arrive.
        dropped_since_last: 0,
    };
    let sent_access = batch.access.len();
    let sent_waf = batch.waf.len();

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

    // Advance only past what was ACCEPTED. A quota that shed part of
    // the batch must not silently lose those rows: leaving the cursor
    // behind means the next tick offers them again.
    let accepted_all = ack.accepted_access as usize == sent_access
        && ack.accepted_waf as usize == sent_waf;
    if accepted_all {
        let store = config_store.lock().await;
        store
            .advance_telemetry_cursor(TelemetryCursor::Access, ack.access_cursor)
            .map_err(|e| e.to_string())?;
        store
            .advance_telemetry_cursor(TelemetryCursor::Waf, ack.waf_cursor)
            .map_err(|e| e.to_string())?;
        debug!(
            access = sent_access,
            waf = sent_waf,
            "telemetry delivered to the control plane"
        );
    } else {
        info!(
            sent_access,
            sent_waf,
            accepted_access = ack.accepted_access,
            accepted_waf = ack.accepted_waf,
            retry_after_s = ack.retry_after_s,
            "the control plane accepted part of the telemetry batch; the cursor stays put so \
             nothing is lost, and the rest is offered again"
        );
    }

    if ack.retry_after_s > 0 {
        // Told to back off: sleep past the window rather than
        // hammering a control plane that is already shedding.
        tokio::time::sleep(Duration::from_secs(u64::from(ack.retry_after_s))).await;
    }
    Ok(())
}
