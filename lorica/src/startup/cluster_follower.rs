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

//! Follower side of the cluster plane (Story 9.3): when this node
//! holds a fleet identity (it ran `lorica cluster join`), dial the
//! control plane for the life of the process, renew the node
//! certificate at two thirds of its lifetime over the established
//! session (AC #12), and stop when `POST /api/v1/cluster/leave` wipes
//! the identity.
//!
//! Renewals are jittered: the lead is drawn once per process between
//! 25 and 30 days before expiry, so a batch of nodes enrolled together
//! spreads its renewals over days instead of hitting the control
//! plane's signing path in the same ten minutes. After a successful
//! renewal the dialer reconnects immediately on the new certificate,
//! which is what lets the control plane retire the superseded one.
//!
//! Story 9.4 adds the receiving end of configuration replication: the
//! [`ReplicaHandler`] below serves the control plane's
//! Prepare/Commit/Abort on the session's incoming half, pulls when a
//! `HelloAck` or a `HeartbeatAck` says this node is behind, and holds
//! the break-glass window that suspends all of it.
//!
//! Shared by both startup modes: the follower runtime lives in the
//! supervisor (or the single process); workers never dial.

use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_api::cluster::FollowerRuntime;
use lorica_api::db::db_blocking;
use lorica_api::error::ApiError;
use lorica_cluster::enroll::BoxFuture;
use lorica_cluster::messages::{cluster_response, ConfigPull, Renew};
use lorica_cluster::{
    AppliedConfig, ClusterRequest, ConfigPayload, ConfigVersion, Dialer, DialerConfig,
    DialerHandle, FollowerHandler, SessionHandle,
};
use lorica_config::canonical::CanonicalConfig;
use lorica_config::models::ClusterIdentity;
use lorica_config::store::ConfigStore;
use lorica_notify::events::{AlertEvent, AlertType};
use lorica_notify::AlertSender;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::startup::cluster_plane::{
    RENEWAL_CHECK_INTERVAL, RENEWAL_LEAD_MAX_DAYS, RENEWAL_LEAD_MIN_DAYS,
    RENEWAL_RETRY_AFTER_REFUSAL,
};

/// Bound on one renewal exchange.
const RENEWAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Bound on one convergence pull exchange. Larger than a renewal: the
/// answer carries the whole canonical blob, which the 4 MiB frame cap
/// bounds but a slow WAN link still takes time to deliver.
const PULL_TIMEOUT: Duration = Duration::from_secs(30);

/// Inputs for [`spawn_follower`].
pub(crate) struct FollowerOptions {
    /// Whether this process also runs a control plane (`--cluster-listen`).
    /// A node cannot be both; the control-plane path refuses first,
    /// this is the belt to its braces.
    pub is_control_plane: bool,
    /// The proxy's configuration-reload signal, bumped after every
    /// applied replica so the data plane serves the new generation
    /// (Story 9.4 AC #4).
    pub config_reload: watch::Sender<u64>,
    /// The alert dispatcher (`ClusterConfigRefused`).
    pub alert_sender: AlertSender,
}

/// Live handles for a running follower.
pub(crate) struct FollowerPlane {
    /// The handle the management API reads (status, leave).
    pub runtime: Arc<FollowerRuntime>,
    /// The dialer, shared with the leave watcher and the renewal task
    /// (both need to reach it after spawn).
    dialer: Arc<std::sync::Mutex<Option<DialerHandle>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl FollowerPlane {
    /// Stop dialing and the background tasks.
    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
        if let Some(dialer) = self
            .dialer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            dialer.shutdown();
        }
    }
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::Internal(e.to_string())
}

/// A generation staged by `ConfigPrepare` and not yet applied.
struct StagedConfig {
    generation: u64,
    hash: String,
    config: CanonicalConfig,
}

/// The follower's half of configuration replication (Story 9.4
/// AC #4/#5/#7/#11): it stages what the control plane pushes, applies
/// it in one transaction, publishes what it now runs, and refuses
/// everything while a break-glass window is open.
///
/// # Why break-glass refuses a Prepare instead of ignoring it
///
/// The control plane already skips break-glass nodes: it reads the
/// flag from the last `Hello` or `Heartbeat`, so a push during a
/// window only happens when the operator opened it inside the last
/// heartbeat interval. Refusing aborts that ONE round fleet-wide and
/// says why; the next round skips this node. Staging it and applying
/// anyway would wipe the edits the operator opened the window to make,
/// which is the failure AC #11 exists to prevent.
///
/// It holds the pieces it shares with [`FollowerRuntime`] directly
/// rather than the runtime itself: the runtime needs the dialer's
/// connection slot and the dialer needs this handler, so one of the
/// two has to own the shared state instead of the other object.
struct ReplicaHandler {
    /// This node's server-assigned id, for the metric label.
    node_id: String,
    /// What this node runs, the same slot the API reads.
    applied: Arc<StdMutex<AppliedConfig>>,
    /// The break-glass window, read-only here; the API writes it.
    break_glass: watch::Receiver<Option<DateTime<Utc>>>,
    store: Arc<Mutex<ConfigStore>>,
    /// This node's `cluster_nodes.name` on the control plane: what
    /// `node_selector` targeting is matched against (D11).
    node_name: String,
    /// Bumped after every applied generation so the proxy, the cert
    /// resolver and the probe scheduler pick it up.
    config_reload: watch::Sender<u64>,
    alert_sender: AlertSender,
    staged: StdMutex<Option<StagedConfig>>,
    /// `(generation, phase)` pairs already alerted on, so a generation
    /// this node cannot take raises one alert instead of one per
    /// heartbeat. Bounded by the number of generations this process
    /// refuses, which an operator fixing the configuration ends; a node
    /// refusing thousands of distinct generations has a louder problem
    /// than this map.
    alerted: StdMutex<HashSet<(u64, String)>>,
}

impl ReplicaHandler {
    /// Whether an operator's break-glass window is open right now.
    fn break_glass_active(&self) -> bool {
        (*self.break_glass.borrow()).is_some_and(|until| until > Utc::now())
    }

    /// What this node currently runs.
    fn applied(&self) -> AppliedConfig {
        self.applied
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Decode and validate a payload, then hold it until the Commit.
    /// A second Prepare replaces the first: the control plane runs one
    /// round at a time, so an unclaimed staged generation is the
    /// remains of a round that never reached this node's Commit.
    async fn stage(&self, payload: ConfigPayload) -> Result<(), String> {
        if self.break_glass_active() {
            return Err(
                "node is in a break-glass window; local configuration edits are in progress"
                    .to_string(),
            );
        }
        let generation = payload.generation;
        // A generation strictly BELOW what this node runs is a
        // rollback, and applying a replica deletes every row the blob
        // omits. A control plane restored from an older backup would
        // otherwise have the whole fleet delete the routes, backends,
        // certificates and rules added since that backup, each node
        // doing it to itself. Refusing is recoverable: the operator
        // raises the generation past the fleet's maximum and changes
        // the configuration again.
        let applied_now = self.applied();
        if generation < applied_now.generation {
            return Err(format!(
                "refusing to roll back from generation {} to {generation}",
                applied_now.generation
            ));
        }
        let hash = payload.hash.clone();
        let staged_hash = hash.clone();
        // The inner `Result` is the SEMANTIC verdict the control plane
        // aborts the round on; the outer one is the store failing.
        let config = db_blocking(&self.store, move |store| {
            Ok::<_, ApiError>(
                store
                    .prepare_replica(&payload.blob, &hash)
                    .map_err(|e| e.to_string()),
            )
        })
        .await
        .map_err(|e| e.to_string())??;
        *self.staged.lock().unwrap_or_else(|p| p.into_inner()) = Some(StagedConfig {
            generation,
            hash: staged_hash,
            config,
        });
        Ok(())
    }

    /// Apply the staged generation in one transaction, persist what is
    /// now applied, and signal the local reload.
    async fn apply_staged(&self, generation: u64) -> Result<AppliedConfig, String> {
        // Re-checked here, not only in `stage`: an operator can open a
        // window in the gap between the Prepare and the Commit, and
        // applying then would wipe the edits the window was opened to
        // make.
        if self.break_glass_active() {
            return Err(
                "a break-glass window opened after the configuration was staged".to_string(),
            );
        }
        let staged = self
            .staged
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .ok_or_else(|| "no staged configuration".to_string())?;
        if staged.generation != generation {
            return Err(format!(
                "staged generation {} does not match the commit's {generation}",
                staged.generation
            ));
        }
        let node_name = self.node_name.clone();
        let hash = staged.hash.clone();
        let applied_hash = staged.hash.clone();
        // The apply is one transaction; the marker write that follows
        // is not part of it, so the two failures are reported
        // differently. The apply failing means this node still serves
        // the previous generation. The MARKER failing means it already
        // serves the new one and merely under-reports, so calling that
        // a refusal would tell an operator the opposite of what
        // happened. Re-applying on the next pull is harmless: every
        // write is an upsert keyed on the blob's ids.
        let outcome = db_blocking(&self.store, move |store| {
            let outcome = match store.apply_replica(&staged.config, &node_name) {
                Ok(outcome) => outcome,
                Err(e) => return Ok::<_, ApiError>(Err(e.to_string())),
            };
            let recorded = store.set_cluster_applied_config(generation, &hash);
            Ok(Ok((outcome, recorded.err())))
        })
        .await
        .map_err(|e| e.to_string())??;
        let (outcome, marker_error) = outcome;
        if let Some(e) = marker_error {
            warn!(
                generation,
                error = %e,
                "the configuration was applied but the applied-generation marker could not be \
                 written; this node serves the new generation and re-applies it on its next pull"
            );
        }

        let applied = AppliedConfig {
            generation,
            hash: applied_hash,
            break_glass: self.break_glass_active(),
        };
        *self.applied.lock().unwrap_or_else(|p| p.into_inner()) = applied.clone();
        lorica_api::metrics::set_cluster_config_generation(&self.node_id, generation);
        // The store is the source of truth for every reload path and
        // the transaction above committed, so bumping the counter is
        // all the local data plane needs.
        self.config_reload
            .send_modify(|seq| *seq = seq.wrapping_add(1));
        info!(
            generation,
            routes = outcome.routes,
            routes_not_for_this_node = outcome.routes_skipped_by_selector,
            backends = outcome.backends,
            certificates = outcome.certificates,
            certificates_without_key = outcome.certificates_without_key,
            "applied a replicated configuration"
        );
        if outcome.certificates_without_key > 0 {
            warn!(
                count = outcome.certificates_without_key,
                "replicated certificates arrived without their private key; the TLS resolver \
                 skips them until the key is distributed"
            );
        }
        Ok(applied)
    }

    /// One convergence pull (AC #7): ask for the current generation,
    /// then run the same stage/apply a push would.
    async fn pull_and_apply(&self, session: SessionHandle) {
        if self.break_glass_active() {
            return;
        }
        let applied = self.applied();
        let response = match tokio::time::timeout(
            PULL_TIMEOUT,
            session.endpoint.request(
                ClusterRequest::config_pull(ConfigPull {
                    applied_generation: applied.generation,
                    applied_hash: applied.hash.clone(),
                }),
                PULL_TIMEOUT,
            ),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                warn!(error = %e, "configuration pull failed; retrying on the next heartbeat");
                return;
            }
            Err(_) => {
                warn!("configuration pull timed out; retrying on the next heartbeat");
                return;
            }
        };
        let Some(cluster_response::Body::ConfigPullAck(ack)) = response.body else {
            warn!(
                status = ?response.cluster_status(),
                "control plane refused the configuration pull"
            );
            return;
        };
        if ack.up_to_date {
            info!("control plane reports this node is already up to date");
            return;
        }
        let generation = ack.generation;
        let payload = ConfigPayload {
            generation,
            hash: ack.hash,
            blob: ack.blob,
        };
        // Through the trait methods, so a pull and a push refuse, log
        // and alert identically.
        if self.on_prepare(payload).await.is_err() {
            return;
        }
        let _ = self.on_commit(generation).await;
    }

    /// Raise `ClusterConfigRefused` (AC #1): a generation this node
    /// could not take, whether it was pushed or pulled.
    /// Operator-visible, because a follower stuck on an old
    /// configuration is a silent failure otherwise.
    ///
    /// At most one alert per `(generation, phase)`. Without that, a
    /// node that cannot take the current generation refuses it again
    /// on every heartbeat pull, forever, and the dispatcher's global
    /// per-channel budget is shared with certificate-expiry and
    /// backend-down alerts: the refusal would drown the alerts an
    /// operator actually needs. The journal still records every
    /// attempt.
    fn refused(&self, generation: u64, reason: &str, phase: &str) {
        // Peer-supplied: this string reaches a journal line and a
        // notification channel, so it is bounded and control
        // characters are dropped, exactly as the control plane bounds
        // what a follower tells IT.
        let reason = &lorica_cluster::safe_reason(reason);
        let first_time = self
            .alerted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert((generation, phase.to_string()));
        if !first_time {
            warn!(
                generation,
                phase,
                %reason,
                "refused a replicated configuration again; the alert is suppressed"
            );
            return;
        }
        error!(
            generation,
            phase,
            %reason,
            "refused a replicated configuration; this node stays on its previous generation"
        );
        self.alert_sender.send(
            AlertEvent::new(
                AlertType::ClusterConfigRefused,
                format!(
                    "node {} refused configuration generation {generation} at {phase}: {reason}",
                    self.node_name
                ),
            )
            .with_detail("node_id", self.node_id.clone())
            .with_detail("node_name", self.node_name.clone())
            .with_detail("generation", generation.to_string())
            .with_detail("phase", phase.to_string())
            .with_detail("reason", reason.to_string()),
        );
    }
}

impl FollowerHandler for ReplicaHandler {
    fn applied_config(&self) -> AppliedConfig {
        let mut applied = self.applied();
        applied.break_glass = self.break_glass_active();
        applied
    }

    fn on_prepare(&self, payload: ConfigPayload) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            let generation = payload.generation;
            let staged = self.stage(payload).await;
            // A break-glass refusal is the operator's own doing and is
            // already bannered; only a blob this node cannot take is
            // worth an alert (AC #1).
            if let Err(reason) = &staged {
                if !self.break_glass_active() {
                    self.refused(generation, reason, "prepare");
                }
            }
            staged
        })
    }

    fn on_commit(&self, generation: u64) -> BoxFuture<'_, Result<AppliedConfig, String>> {
        Box::pin(async move {
            let applied = self.apply_staged(generation).await;
            if let Err(reason) = &applied {
                self.refused(generation, reason, "apply");
            }
            applied
        })
    }

    fn on_abort(&self, generation: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let mut staged = self.staged.lock().unwrap_or_else(|p| p.into_inner());
            if staged.as_ref().is_some_and(|s| s.generation == generation) {
                *staged = None;
            }
        })
    }

    fn on_behind(&self, session: SessionHandle, current: ConfigVersion) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            info!(
                current_generation = current.generation,
                "pulling the control plane's configuration"
            );
            self.pull_and_apply(session).await;
        })
    }
}

/// This process's renewal lead, drawn once (the jitter).
fn renewal_lead() -> chrono::Duration {
    let span = (RENEWAL_LEAD_MAX_DAYS - RENEWAL_LEAD_MIN_DAYS) as u64 * 86_400;
    let offset = rand::random::<u64>() % (span + 1);
    chrono::Duration::days(RENEWAL_LEAD_MIN_DAYS) + chrono::Duration::seconds(offset as i64)
}

/// Start the follower runtime when a fleet identity exists.
/// `Ok(None)` on a node that never joined.
pub(crate) async fn spawn_follower(
    opts: FollowerOptions,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<Option<FollowerPlane>, String> {
    let (identity, schema_version, applied_config, break_glass_until) = {
        let store = store.lock().await;
        let identity = store
            .get_cluster_identity()
            .map_err(|e| format!("follower: failed to read the fleet identity: {e}"))?;
        let schema = store
            .schema_version()
            .map_err(|e| format!("follower: failed to read the schema version: {e}"))?;
        let (generation, hash) = store
            .cluster_applied_config()
            .map_err(|e| format!("follower: failed to read the applied configuration: {e}"))?;
        // A break-glass window must survive a restart (Story 9.4
        // AC #11): a process that forgot it would silently reconcile
        // away the edits the operator opened the window to make.
        let break_glass = store
            .cluster_break_glass_until()
            .map_err(|e| format!("follower: failed to read the break-glass window: {e}"))?
            .filter(|until| *until > Utc::now());
        (identity, schema, (generation, hash), break_glass)
    };
    let Some(identity) = identity else {
        return Ok(None);
    };
    if opts.is_control_plane {
        return Err(
            "follower: this node holds a fleet identity and --cluster-listen was passed; a \
             node cannot be both. Run `lorica cluster leave` first"
                .to_string(),
        );
    }

    let (break_glass_tx, break_glass_rx) = watch::channel(break_glass_until);
    let applied = Arc::new(StdMutex::new(AppliedConfig {
        generation: applied_config.0,
        hash: applied_config.1,
        break_glass: break_glass_until.is_some(),
    }));
    lorica_api::metrics::set_cluster_config_generation(&identity.node_id, applied_config.0);
    let replica = Arc::new(ReplicaHandler {
        node_id: identity.node_id.clone(),
        applied: Arc::clone(&applied),
        break_glass: break_glass_rx,
        store: Arc::clone(store),
        node_name: identity.node_name.clone(),
        config_reload: opts.config_reload,
        alert_sender: opts.alert_sender,
        staged: StdMutex::new(None),
        alerted: StdMutex::new(HashSet::new()),
    });

    let mut config = DialerConfig::new(
        &identity.control_plane,
        &identity.server_name,
        &identity.ca_pem,
        &identity.cert_pem,
        &identity.key_pem,
        u32::try_from(schema_version).unwrap_or(u32::MAX),
    )
    .with_node_name(&identity.node_name)
    .with_follower(replica as Arc<dyn FollowerHandler>);
    config.handshake = config
        .handshake
        .with_build_version(env!("CARGO_PKG_VERSION"));
    let dialer = Dialer::spawn(config).map_err(|e| format!("follower: dialer: {e}"))?;
    let connection = dialer.connection();
    let (left_tx, mut left_rx) = watch::channel(false);
    let runtime = Arc::new(FollowerRuntime {
        node_id: identity.node_id.clone(),
        node_name: identity.node_name.clone(),
        control_plane: identity.control_plane.clone(),
        connection: connection.clone(),
        left: left_tx,
        applied,
        break_glass: break_glass_tx,
    });
    let dialer = Arc::new(std::sync::Mutex::new(Some(dialer)));

    // Leave watcher: the API wiped the identity; stop dialing so the
    // control plane sees the node go and no reconnect presents a
    // certificate this node no longer owns.
    let leave_dialer = Arc::clone(&dialer);
    let leave_task = tokio::spawn(async move {
        while !*left_rx.borrow() {
            if left_rx.changed().await.is_err() {
                return;
            }
        }
        if let Some(dialer) = leave_dialer
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            dialer.shutdown();
        }
        warn!("follower: left the fleet; cluster session closed");
    });

    // Renewal task (AC #12), jittered per process.
    let lead = renewal_lead();
    let renew_dialer = Arc::clone(&dialer);
    let renew_store = Arc::clone(store);
    let renew_connection = connection;
    let renewal_task = tokio::spawn(async move {
        let mut hold_until: Option<tokio::time::Instant> = None;
        loop {
            tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;
            // A refused renewal (the control plane's cooldown, or a
            // node no longer active) is not retried every check: that
            // would burn the per-session refusal budget on the control
            // plane for nothing.
            if hold_until.is_some_and(|until| tokio::time::Instant::now() < until) {
                continue;
            }
            let current = db_blocking(&renew_store, |store| {
                store.get_cluster_identity().map_err(internal)
            })
            .await;
            let Ok(Some(current)) = current else {
                continue;
            };
            if Utc::now() + lead < current.cert_not_after {
                continue;
            }
            let Some(session) = renew_connection.current() else {
                warn!("follower: certificate renewal due but the control plane is unreachable; will retry");
                continue;
            };
            match renew_once(&session.endpoint, &current, &renew_store).await {
                Ok((cert_pem, key_pem, not_after)) => {
                    let outcome = renew_dialer
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .as_ref()
                        .map(|d| d.update_identity(&cert_pem, &key_pem).map(|()| d.reconnect()));
                    match outcome {
                        Some(Ok(())) => info!(
                            not_after = %not_after.to_rfc3339(),
                            "follower: node certificate renewed; reconnecting on it now"
                        ),
                        Some(Err(e)) => error!(error = %e, "follower: renewed identity rejected by the dialer"),
                        None => {}
                    }
                }
                Err(e) => {
                    hold_until = Some(tokio::time::Instant::now() + RENEWAL_RETRY_AFTER_REFUSAL);
                    warn!(
                        error = %e,
                        retry_in_s = RENEWAL_RETRY_AFTER_REFUSAL.as_secs(),
                        "follower: certificate renewal failed; will retry"
                    );
                }
            }
        }
    });

    warn!(
        node_id = %identity.node_id,
        node_name = %identity.node_name,
        control_plane = %identity.control_plane,
        cert_not_after = %identity.cert_not_after.to_rfc3339(),
        renewal_lead_days = lead.num_days(),
        applied_generation = applied_config.0,
        "follower mode: dialing the control plane"
    );
    if let Some(until) = break_glass_until {
        warn!(
            until = %until.to_rfc3339(),
            "follower: a break-glass window is still open; this node refuses replicated \
             configuration and keeps its local edits until the window ends"
        );
    }
    Ok(Some(FollowerPlane {
        runtime,
        dialer,
        tasks: vec![leave_task, renewal_task],
    }))
}

/// One renewal exchange: fresh keypair, `Renew` over the session,
/// persist the granted certificate with the new key.
async fn renew_once(
    endpoint: &lorica_command::RpcEndpoint<lorica_cluster::ClusterFrame>,
    current: &ClusterIdentity,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<(String, String, DateTime<Utc>), String> {
    let (spki_der, key_pem) =
        lorica_cluster::ca::generate_node_keypair().map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(
        RENEWAL_TIMEOUT,
        endpoint.request(
            ClusterRequest::renew(Renew {
                public_key_der: spki_der,
            }),
            RENEWAL_TIMEOUT,
        ),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| e.to_string())?;
    let Some(cluster_response::Body::RenewAck(ack)) = response.body else {
        return Err(format!(
            "control plane refused the renewal ({:?})",
            response.cluster_status()
        ));
    };
    let not_after = DateTime::parse_from_rfc3339(&ack.cert_not_after)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| format!("bad notAfter in the renewal: {e}"))?;
    let renewed = ClusterIdentity {
        cert_pem: ack.cert_pem.clone(),
        key_pem: key_pem.clone(),
        cert_not_after: not_after,
        ..current.clone()
    };
    db_blocking(store, move |store| {
        store.set_cluster_identity(&renewed).map_err(internal)
    })
    .await
    .map_err(|e| e.to_string())?;
    Ok((ack.cert_pem, key_pem, not_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_lead_stays_inside_the_jitter_band() {
        for _ in 0..100 {
            let lead = renewal_lead();
            assert!(lead >= chrono::Duration::days(RENEWAL_LEAD_MIN_DAYS));
            assert!(lead <= chrono::Duration::days(RENEWAL_LEAD_MAX_DAYS));
        }
    }
}
